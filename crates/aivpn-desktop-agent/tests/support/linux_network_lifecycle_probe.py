"""Прежние сокеты и общий DNS после обрыва сети в отдельном guest."""
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import threading
import time

import vertical_probe as v
import lifecycle_probe as l
from linux_multi_profile_probe import cli


HELD = r'''
import json,socket,sys
kind=int(sys.argv[1])
with socket.socket(socket.AF_INET,kind) as s:
    s.settimeout(3)
    s.connect(('198.18.0.53',9999))
    print(json.dumps({'opened':True,'port':s.getsockname()[1]}),flush=True)
    for line in sys.stdin:
        label=line.strip()
        if label=='close':break
        payload=label.encode()
        try:
            if kind==socket.SOCK_STREAM:s.sendall(payload)
            else:assert s.send(payload)==len(payload)
            data=s.recv(2048)
            result={'echo':data==payload}
        except OSError as error:
            result={'echo':False,'error':type(error).__name__,'errno':error.errno}
        print(json.dumps({'label':label,'port':s.getsockname()[1],**result}),flush=True)
'''

TUN_CAPTURE = r'''
import json,socket,sys,select,struct,time
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as s:
    s.bind((sys.argv[1],0))
    print('CAPTURE_READY',flush=True)
    deadline=time.monotonic()+220
    count=0
    while time.monotonic()<deadline:
        ready=select.select([s,sys.stdin],[],[],1)[0]
        if sys.stdin in ready:break
        if s not in ready:continue
        data,meta=s.recvfrom(65535)
        start=0 if data and data[0]>>4==4 else 14
        if len(data)<start+24 or data[start]>>4!=4:continue
        transport=start+(data[start]&15)*4
        if len(data)<transport+4 or data[start+9] not in (6,17):continue
        sp,dp=struct.unpack_from('!HH',data,transport)
        if 9999 not in (sp,dp):continue
        row={'interface':sys.argv[1],'time':time.time(),'packet_type':meta[2],
             'source':socket.inet_ntoa(data[start+12:start+16]),
             'destination':socket.inet_ntoa(data[start+16:start+20]),
             'source_port':sp,'destination_port':dp,'protocol':data[start+9],'bytes':len(data)-start}
        if data[start+9]==6 and len(data)>=transport+20:
            row.update(flags=data[transport+13],seq=struct.unpack_from('!I',data,transport+4)[0],ack=struct.unpack_from('!I',data,transport+8)[0])
        print(json.dumps(row),flush=True)
        count+=1
        if count>=256:raise RuntimeError('capture bound')
'''


def result_line(process, timeout=7):
    assert select.select([process.stdout], [], [], timeout)[0], 'Нет ответа обычного приложения'
    line = process.stdout.readline()
    if not line:
        raise AssertionError('Приложение завершилось: ' + process.stderr.read()[-1200:])
    return json.loads(line)


def stop_tun_captures(processes):
    for process in processes:
        if process.poll() is None:
            process.stdin.write('stop\n')
            process.stdin.flush()
            process.wait(timeout=3)
        assert process.returncode == 0, process.stderr.read()[-1000:]


def restore_wan():
    v.lab.command(['ip', 'link', 'set', 'wan0', 'up'])
    for family, local, gateway in [('-4', '192.0.2.2/24', '192.0.2.1'),
                                    ('-6', '2001:db8:2::2/64', '2001:db8:2::1')]:
        v.lab.command(['ip', family, 'addr', 'replace', local, 'dev', 'wan0', 'nodad'])
        v.lab.command(['ip', family, 'route', 'replace', 'default', 'via', gateway, 'dev', 'wan0'])


def main():
    server, server_log, endpoint, echoes, reader, capture = v.prepare_environment(
        ['python3', '/lab/dns_endpoint.py'])
    service = stream = listener = None
    clients = []
    tun_captures = []
    profile = None
    original = b'nameserver 192.0.2.1\noptions timeout:1 attempts:1\n'
    rows = []
    try:
        home = Path('/home/cli-fixture')
        home.mkdir(mode=0o700, parents=True)
        os.chown(home, 1000, 1000)
        for family in ['-4', '-6']:
            v.lab.command(['ip', family, 'rule', 'del', 'pref', '100', 'fwmark', '0xa1', 'lookup', '200'])
        Path('/etc/resolv.conf').unlink(missing_ok=True)
        Path('/etc/resolv.conf').write_bytes(original)
        Path('/etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
        Path('/var/lib/aivpn-app-routing').mkdir(mode=0o700)
        runtime = Path('/run/aivpn-app-routing')
        runtime.mkdir(mode=0o755)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(runtime / 'control.sock'))
        os.chmod(runtime / 'control.sock', 0o666)
        listener.listen(32)
        fd = listener.fileno()
        stream = Path('/run/routing-service.log').open('wb')
        launch = "import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3,inheritable=True); os.close(fd) if fd!=3 else None; os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1'); os.execve('/usr/libexec/aivpn/aivpn',['aivpn','__routing-service','--dns-provider','file','--dns-upstream','198.18.0.53:53'],os.environ)"
        service = subprocess.Popen(['/usr/bin/python3', '-c', launch, str(fd)], pass_fds=(fd,), stdout=stream, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 25
        while True:
            assert service.poll() is None, 'Служба завершилась при запуске'
            try:
                cli(['status'])
                break
            except (AssertionError, subprocess.TimeoutExpired):
                if time.monotonic() > deadline:
                    raise
                time.sleep(.1)
        profile = cli(['register', 'network-lifecycle-cli'])['profile']
        cli(['dns', 'set', profile, '--acknowledge-outage'], uid=0)
        policy = {'version': 1, 'id': 'network-app-split', 'generation': 1, 'platform': 'linux',
                  'owner': {'kind': 'linux_user', 'uid': 1000}, 'default_action': {'route': 'system'},
                  'dns': {'kind': 'shared_vpn', 'profile': profile, 'acknowledge_outage': True},
                  'rules': [{'id': 'selected', 'application': {'kind': 'executable', 'path': '/usr/bin/binding-a'},
                             'destination': None, 'inherit_children': True, 'action': {'route': 'vpn', 'profile': profile}}]}
        policy_file = Path('/run/network-policy.json')
        policy_file.write_text(json.dumps(policy))
        policy_file.chmod(0o644)
        cli(['apply', str(policy_file)])
        connection = Path('/run/network-connection.json')
        connection.write_bytes(Path('/run/vertical-connection.json').read_bytes())
        os.chown(connection, 1000, 1000)
        connection.chmod(0o600)

        def ready(timeout=25):
            deadline = time.monotonic() + timeout
            previous = None
            while True:
                record = next(p for p in cli(['profiles'])['profiles'] if p['id'] == profile)
                state = record['session_active'], record['ready_ipv4'], record.get('session_id')
                if state != previous:
                    print('NETWORK_PROFILE_STATE ' + json.dumps(record), flush=True)
                    previous = state
                if record['ready_ipv4']:
                    return record
                assert service.poll() is None, 'Служба завершилась до восстановления'
                assert record['session_active'], 'Сеанс завершился: ' + json.dumps(record)
                if time.monotonic() > deadline:
                    raise TimeoutError('Профиль не восстановился: ' + json.dumps(record))
                time.sleep(.2)

        cli(['start', profile, '--connection-file', str(connection)])
        first = ready()
        for namespace, interface in [(None, 'aivpn-app0'), ('binding-peer', 'vertical-server')]:
            prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
            process = subprocess.Popen([*prefix, 'python3', '-u', '-c', TUN_CAPTURE, interface],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tun_captures.append(process)
            assert select.select([process.stdout], [], [], 5)[0], 'Захват TUN не запустился'
            assert process.stdout.readline().strip() == 'CAPTURE_READY'
            def drain(process):
                for line in process.stdout:
                    print('NETWORK_TUN_PACKET ' + line.rstrip(), flush=True)
            threading.Thread(target=drain, args=(process,), daemon=True).start()
        for name, image, expected in [('selected', '/usr/bin/binding-a', '10.77.0.2'),
                                      ('system', '/usr/bin/binding-b', '192.0.2.2')]:
            for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                process = l.ordinary(image, HELD, [str(kind)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                client = {'name': name, 'kind': kind, 'process': process, 'expected': expected}
                clients.append(client)
                opened = result_line(process)
                assert opened.get('opened') and opened['port'] > 0, opened
                client['port'] = opened['port']

        def exchange(client, phase):
            label = f"network-{phase}-{client['name']}-{client['kind']}"
            process = client['process']
            process.stdin.write(label + '\n')
            process.stdin.flush()
            result = result_line(process)
            deadline = time.monotonic() + 2
            while not any(e.get('label') == label for e in echoes) and time.monotonic() < deadline:
                time.sleep(.01)
            seen = [e for e in echoes if e.get('label') == label]
            passed = (result['echo'] and result['port'] == client['port'] and bool(seen)
                      and all(e['peer'] == client['expected'] for e in seen))
            row = {'case': label, 'pass': passed, 'port': client['port'], 'server_echo': seen, 'result': result}
            rows.append(row)
            print('VERTICAL_CASE ' + json.dumps(row), flush=True)
            if phase == 'before':
                assert passed, row

        for client in clients:
            exchange(client, 'before')
        started = time.monotonic()
        print('NETWORK_LINK_DOWN ' + json.dumps({'seconds': 55}), flush=True)
        v.lab.command(['ip', 'link', 'set', 'wan0', 'down'])
        try:
            time.sleep(55)
        finally:
            # В guest нет сетевого менеджера, который возвращает default после link down.
            restore_wan()
        second = ready(timeout=110)
        deadline = time.monotonic() + 15
        while second['session_id'] == first['session_id'] and time.monotonic() < deadline:
            time.sleep(.2)
            second = ready()
        assert second['session_id'] != first['session_id'], 'Сеанс не сменился после обрыва'
        recovery_seconds = time.monotonic() - started
        assert second['ipv4'] == first['ipv4'], 'Сервер изменил адрес, сценарий прежних сокетов неприменим'
        for client in clients:
            exchange(client, 'after')

        fresh = l.ordinary('/usr/bin/binding-a', v.lab.CLIENT.replace('s.settimeout(.5)', 's.settimeout(3)'),
                           ['network-fresh-selected', '198.18.0.53', str(socket.AF_INET), str(socket.SOCK_STREAM), '0'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = fresh.communicate(timeout=7)
        assert fresh.returncode == 0, err
        result = json.loads(out)
        time.sleep(.1)
        seen = [e for e in echoes if e.get('label') == 'network-fresh-selected']
        passed = result['echo'] and bool(seen) and all(e['peer'] == '10.77.0.2' for e in seen)
        rows.append({'case': 'network-fresh-selected', 'pass': passed, 'result': result, 'server_echo': seen})
        print('VERTICAL_CASE ' + json.dumps(rows[-1]), flush=True)
        fresh_port = result['source'][1]
        dns_before = len([e for e in echoes if e.get('dns')])
        name = 'network-' + str(time.time_ns()) + '.lab.test'
        query = l.ordinary('/usr/bin/binding-b', 'import socket,sys,json; print(json.dumps(socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_STREAM)))',
                           [name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = query.communicate(timeout=8)
        assert query.returncode == 0, err
        answers = json.loads(out)
        assert answers and all(a[4][0] == '198.51.100.77' for a in answers), answers
        time.sleep(.1)
        dns = [e for e in echoes if e.get('dns')][dns_before:]
        assert dns and all(e['peer'] == '10.77.0.2' for e in dns), dns
        print('VERTICAL_CASE ' + json.dumps({'case': 'network-fresh-shared-dns', 'pass': True, 'server_rows': dns}), flush=True)

        for client in clients:
            client['process'].stdin.write('close\n')
            client['process'].stdin.flush()
            client['process'].wait(timeout=5)
            assert client['process'].returncode == 0
        time.sleep(.3)
        assert all(thread.is_alive() for thread in capture.threads), 'Захват трафика прекратился до проверки'
        wan_mac = bytes.fromhex(Path('/sys/class/net/wan0/address').read_text().strip().replace(':', ''))
        selected = {(6 if c['kind'] == socket.SOCK_STREAM else 17, c['port'])
                    for c in clients if c['name'] == 'selected'} | {(6, fresh_port)}
        system = {(6 if c['kind'] == socket.SOCK_STREAM else 17, c['port'])
                  for c in clients if c['name'] == 'system'}
        leaked = []
        direct_system = set()
        outer = 0
        for _, data in capture.raw:
            if len(data) < 42 or data[6:12] != wan_mac or data[12:14] != b'\x08\x00':
                continue
            start = 14 + (data[14] & 15) * 4
            if start < 34 or len(data) < start + 4:
                continue
            protocol = data[23]
            if protocol not in [6, 17]:
                continue
            source, destination = struct.unpack_from('!HH', data, start)
            if protocol == 17 and destination == 443:
                outer += 1
            if destination != 9999:
                continue
            key = protocol, source
            if key in selected:
                leaked.append({'protocol': protocol, 'source_port': source, 'bytes': len(data)})
            if key in system:
                direct_system.add(key)
        assert not leaked, leaked
        assert direct_system == system and outer > 0, (direct_system, system, outer)
        stop_tun_captures(tun_captures)
        cli(['stop', profile])
        cli(['remove', '--generation', '1'])
        cli(['dns', 'clear'], uid=0)
        assert Path('/etc/resolv.conf').read_bytes() == original, 'DNS не восстановлен'
        service.terminate()
        service.wait(timeout=15)
        assert service.returncode == 0
        assert all(row['pass'] for row in rows), [row for row in rows if not row['pass']]
        print('VERTICAL_SUMMARY ' + json.dumps({'pass': True, 'network_recovery': True, 'same_four_sockets': True,
              'session_changed': True, 'fresh_dns_vpn': True, 'fresh_tcp_vpn': True, 'outage_seconds': 55,
              'recovery_seconds_including_outage': recovery_seconds, 'selected_original_packets': leaked,
              'system_original_flows': len(direct_system), 'outer_udp_packets': outer, 'rows': len(rows) + 1,
              'original_dns_restored': True, 'native_cli': True, 'public_active': False}), flush=True)
    finally:
        restore_wan()
        for client in clients:
            process = client['process']
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
        stop_tun_captures(tun_captures)
        if service and service.poll() is None:
            service.terminate()
            try:
                service.wait(timeout=10)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait(timeout=3)
        if stream:
            stream.close()
        log = Path('/run/routing-service.log')
        if log.exists():
            tail = log.read_text(errors='replace')[-5000:]
            tail = re.sub(r'aivpn://\S+|[A-Za-z0-9+/=_-]{32,}', '[REDACTED]', tail)
            print('SERVICE_LOG_TAIL ' + json.dumps(tail), flush=True)
        if listener:
            listener.close()
        for process in [server, endpoint]:
            process.terminate()
            process.wait(timeout=5)
        server_log.close()
        reader.join(timeout=2)
        capture.close()
        print('VERTICAL_CLEANED', flush=True)


if __name__ == '__main__':
    main()
