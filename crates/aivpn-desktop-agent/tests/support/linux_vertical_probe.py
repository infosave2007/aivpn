"""Ранний encrypted numeric путь в отдельном no-NIC guest, без Control receipt."""
import base64
import json
import hashlib
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import binding_probe as lab


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output)


class OuterCapture(lab.Capture):
    @staticmethod
    def decode(data, meta):
        event = lab.Capture.decode(data, meta)
        if event is not None:
            return event
        if len(data) >= 42 and data[12:14] == b'\x08\x00' and data[23] == 17:
            start = 14 + (data[14] & 15) * 4
            source, destination = struct.unpack_from('!HH', data, start)
            if 443 in (source, destination):
                return {'interface': meta[0], 'packet_type': meta[2],
                        'source': socket.inet_ntoa(data[26:30]), 'destination': socket.inet_ntoa(data[30:34]),
                        'source_port': source, 'destination_port': destination, 'protocol': 17,
                        'outer': True, 'bytes': len(data)}
        return None

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=2)
            assert not thread.is_alive()
        for sock in self.sockets:sock.close()
        pcap=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for stamp,data in self.raw:
            pcap.extend(struct.pack('<IIII',int(stamp),int((stamp%1)*1000000),len(data),len(data)))
            pcap.extend(data)
        for offset in range(0,len(pcap),1536):
            print('VERTICAL_PCAP_CHUNK '+str(offset)+' '+base64.b64encode(pcap[offset:offset+1536]).decode(),flush=True)
        print('VERTICAL_PCAP_END '+json.dumps({'bytes':len(pcap),'sha256':hashlib.sha256(pcap).hexdigest()}),flush=True)


def line_until(process, prefix, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if not line:
            raise RuntimeError('Процесс завершился до ' + prefix)
        print('VERTICAL_PROCESS ' + line.rstrip(), flush=True)
        if line.startswith(prefix):
            return json.loads(line[len(prefix):])
    raise TimeoutError(prefix)


def prepare_environment(endpoint_command=None, network_config=None):
    lab.require_guest()
    assert 'aivpn.vertical-path=1' in Path('/proc/cmdline').read_text().split()
    lab.prepare_network()
    # Собственный ext4 образ получает владельца root до запуска обычных приложений.
    lab.command(['chown','-R','0:0','/usr/bin'])
    for family in ['-4', '-6']:
        lab.command(['ip', family, 'route', 'del', 'table', '200', 'default'])
        lab.command(['ip', family, 'route', 'add', 'unreachable', 'default', 'table', '200', 'metric', '32767'])
    lab.command(['ip', 'addr', 'del', '10.77.0.2/24', 'dev', 'vpn0'])
    lab.command(['ip', '-n', 'binding-peer', 'addr', 'del', '10.77.0.1/24', 'dev', 'vpn_s'])
    server_config = {
        'listen_addr': '192.0.2.1:443', 'server_ip': '192.0.2.1:443',
        'key_file': '/run/vertical-server.key', 'clients_db': '/run/vertical-clients.json',
        'audit_log': '/run/vertical-audit.jsonl', 'mask_dir': '/lab/masks',
        'tun_name': 'vertical-server', 'network_config': {'server_vpn_ip': '10.77.0.1', 'prefix_len': 24, 'mtu': 1280, **(network_config or {})},
        'enable_nat': True, 'kernel_downlink': False, 'log_level': 'info',
    }
    private_json('/run/vertical-server.json', server_config)
    with os.fdopen(os.open('/run/vertical-server.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as key_file:
        key_file.write(os.urandom(32))
    # stdout CLI содержит ключ и никогда не попадает в отчет или serial.
    created = subprocess.run(['/usr/bin/aivpn-server', '--config', '/run/vertical-server.json', '--add-client', 'vertical'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    found = re.search(rb'aivpn://([A-Za-z0-9_-]+)', created.stdout + created.stderr)
    assert found, 'Сервер не выдал private connection key'
    payload = found[1]
    connection = json.loads(base64.urlsafe_b64decode(payload + b'=' * (-len(payload) % 4)))
    private_json('/run/vertical-connection.json', connection)
    del created, payload, found, connection
    server_log = os.fdopen(os.open('/run/vertical-server.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
    server = subprocess.Popen(['ip', 'netns', 'exec', 'binding-peer', '/usr/bin/aivpn-server', '--config', '/run/vertical-server.json'],
                              stdout=server_log, stderr=subprocess.STDOUT)
    endpoint = subprocess.Popen(['ip', 'netns', 'exec', 'binding-peer', *(endpoint_command or ['python3','/lab/binding_probe.py','--server'])],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert endpoint.stdout.readline().strip() == 'ENDPOINT_READY'
    echoes = []
    reader = threading.Thread(target=lambda: [echoes.append(json.loads(line)) for line in endpoint.stdout], daemon=True)
    reader.start()
    capture = OuterCapture()
    return server, server_log, endpoint, echoes, reader, capture


def run():
    server, server_log, endpoint, echoes, reader, capture = prepare_environment()
    loader = subprocess.Popen(['/usr/bin/snapshot-tests', '--ignored', '--exact', 'snapshot_writer_child', '--nocapture'],
                              env={**os.environ, 'AIVPN_SNAPSHOT_CHILD': '1', 'SNAPSHOT_VARIANT': 'basic', 'VERTICAL_CAPTURE_CHECK': '1'},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    captured = line_until(loader, 'SNAPSHOT_CAPTURE_READY ')
    assert captured['links'] == 6 and captured['network_links'] == 0
    for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
        bootstrap = 'import os,sys\nos.setgroups([]);os.setgid(1000);os.setuid(1000);os.execv(sys.argv[1],sys.argv[1:])'
        result = json.loads(lab.command(['/usr/bin/python3', '-c', bootstrap, '/usr/bin/binding-unknown', '-c', lab.CLIENT, f'capture-{kind}', '198.18.0.53', '2', str(kind), '0'], timeout=5))
        assert result['echo'], result
        print('CAPTURE_SYSTEM ' + json.dumps({'kind':kind,'pass':result['echo']}),flush=True)
    loader.stdin.write('capture-go\n');loader.stdin.flush()
    metadata = line_until(loader, 'SNAPSHOT_READY ')
    assert metadata['core_before'] == metadata['core_after'] == captured['core']
    maps = lab.Maps(metadata)
    raw = bytearray(struct.pack('=IIIIQ4s16s4xQQ', 0xa1, 0, 0, socket.if_nametoindex('vpn0'), 1,
                               socket.inet_aton('10.77.0.2'), bytes(16), maps.netns, os.stat('/sys/class/net/vpn0').st_ino))
    maps.update('profiles', struct.pack('=I', metadata['profile']), bytes(raw))
    service = subprocess.Popen(['/usr/bin/vertical-service'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    owned = line_until(service, 'TUN ')
    restricted = line_until(service, 'RESTRICTED ')
    assert restricted['pid'] != restricted['parent'] and not restricted['creds_are_child_proof']
    transport = line_until(service, 'TRANSPORT ')
    assert transport['before_send'] and transport['unbound']
    try:
        assignment = line_until(service, 'ASSIGNMENT ')
    except Exception:
        for line in Path('/run/vertical-server.log').read_text(errors='replace').splitlines():
            if re.search(r'error|fail|listen|tun|session|ratchet|mask', line, re.I):
                line = re.sub(r'aivpn://\S+|[A-Za-z0-9+/=_-]{32,}', '[REDACTED]', line)
                print('SERVER_DIAGNOSTIC ' + line, flush=True)
        print('OUTER_DIAGNOSTIC ' + json.dumps(capture.events[:12]), flush=True)
        capture.close()
        raise
    interface = owned['name']
    address = assignment['client_ip']
    lab.command(['ip', 'link', 'set', interface, 'mtu', str(assignment['mtu']), 'up'])
    lab.command(['ip', 'addr', 'add', address + '/32', 'dev', interface])
    lab.command(['ip', '-4', 'route', 'add', 'table', '200', 'default', 'dev', interface, 'metric', '1'])
    for executable in ['iptables-nft', 'ip6tables-nft']:
        prefix = [executable, '-t', 'mangle']
        lab.command(prefix + ['-N', 'VERTICAL'])
        lab.command(prefix + ['-A', 'OUTPUT', '-j', 'VERTICAL'])
        lab.command(prefix + ['-A', 'VERTICAL', '-m', 'bpf', '--object-pinned', metadata['pins'] + '/programs/match_block', '-j', 'DROP'])
        lab.command(prefix + ['-A', 'VERTICAL', '-m', 'bpf', '--object-pinned', metadata['pins'] + '/programs/match_vpn', '-j', 'MARK', '--set-mark', '0xa1'])
    lab.command(['nft', '-f', '-'], input=f'table inet vertical_nat {{ chain post {{ type nat hook postrouting priority srcnat; policy accept; meta mark 0xa1 oifname "{interface}" snat ip to {address}; }}\n}}\n')
    maps.update('profiles', struct.pack('=I', metadata['profile']), struct.pack('=IIIIQ4s16s4xQQ',
                0xa1, 1, 0, owned['ifindex'], 1, socket.inet_aton(address), bytes(16), owned['netns'], owned['device']))
    maps.update('interface_profiles', struct.pack('=QII', owned['netns'], owned['ifindex'], 0), struct.pack('=I', metadata['profile']))
    service.stdin.write('ready\n'); service.stdin.flush()
    service_output = threading.Thread(target=lambda: [print('WORKER_LIVE ' + line.rstrip(), flush=True) for line in service.stdout], daemon=True)
    service_output.start()
    rows = []
    # Настоящий обычный exec selected программы после capture, без helper socket.
    client_code = lab.CLIENT.replace('s.settimeout(.5)', 's.settimeout(8)')
    for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
        for label, executable, expected in [('selected', '/usr/bin/binding-a', address), ('system', '/usr/bin/binding-unknown', '192.0.2.2')]:
            label = f'{label}-{kind}'
            start = time.monotonic()
            bootstrap = 'import os,sys\nos.setgroups([]);os.setgid(1000);os.setuid(1000);os.execv(sys.argv[1],sys.argv[1:])'
            output = lab.command(['/usr/bin/python3', '-c', bootstrap, executable, '-c', client_code, label, '198.18.0.53', '2', str(kind), '0'], timeout=12)
            result = json.loads(output)
            time.sleep(.2)
            observed = [entry for entry in echoes if entry['label'] == label]
            row = {'case': label, 'result': result, 'server_echo': observed, 'seconds': time.monotonic()-start,
                   'pass': result['echo'] and bool(observed) and all(entry['peer'] == expected for entry in observed)}
            rows.append(row)
            print('VERTICAL_CASE ' + json.dumps(row), flush=True)
    selected_ports = {row['result']['source'][1] for row in rows if row['case'].startswith('selected')}
    forbidden = [event for event in capture.events if event['interface'] == 'wan0' and event.get('destination_port') == 9999 and event.get('source_port') in selected_ports]
    outer = [event for event in capture.events if event.get('outer')]
    system_udp_port = next(row['result']['source'][1] for row in rows if row['case'] == 'system-2')
    system_udp = [event for event in capture.events if event['interface'] == 'wan0' and event['protocol'] == 17 and event.get('source_port') == system_udp_port and event.get('destination_port') == 9999]
    assert system_udp, 'Короткий SYSTEM UDP должен присутствовать в независимом capture'
    print('VERTICAL_SUMMARY ' + json.dumps({'pass': all(row['pass'] for row in rows) and bool(outer) and not forbidden,
          'rows': len(rows), 'short_system_udp_packets':len(system_udp), 'outer_packets': len(outer), 'forbidden_selected': forbidden,
          'status': 'INTERNAL_GUARDED_FIXTURE', 'public_active': False}), flush=True)
    if not all(row['pass'] for row in rows):
        for line in Path('/run/vertical-server.log').read_text(errors='replace').splitlines():
            if re.search(r'error|fail|listen|tun|session|ratchet|mask', line, re.I):
                print('SERVER_DIAGNOSTIC '+re.sub(r'aivpn://\S+|[A-Za-z0-9+/=_-]{32,}', '[REDACTED]', line),flush=True)
        for command in [['ip','-s','link','show',interface], ['ip','-n','binding-peer','-s','link','show'],
                        ['ip','-n','binding-peer','route','show'], ['ip','route','get','198.18.0.53','mark','0xa1'],
                        ['iptables-nft','-t','mangle','-nvL','VERTICAL'], ['nft','list','table','inet','vertical_nat']]:
            print('PATH_DIAGNOSTIC ' + json.dumps({'command':command,'output':lab.command(command)}),flush=True)
    service.terminate();service.wait(timeout=5)
    try:os.kill(restricted['pid'], 9)
    except ProcessLookupError:pass
    maps.close()
    for executable in ['iptables-nft', 'ip6tables-nft']:
        for args in [['-D','OUTPUT','-j','VERTICAL'],['-F','VERTICAL'],['-X','VERTICAL']]:
            lab.command([executable,'-t','mangle']+args)
    lab.command(['nft','delete','table','inet','vertical_nat'])
    loader.stdin.write('cleanup\n');loader.stdin.flush()
    print(loader.communicate(timeout=20)[0],flush=True)
    server.terminate();server.wait(timeout=5);server_log.close()
    endpoint.terminate();endpoint.wait(timeout=5);reader.join(timeout=2)
    capture.close()
    lab.command(['ip','netns','del','binding-peer'])
    import shutil
    for path in Path('/run').glob('vertical-*'):
        if path.is_dir():shutil.rmtree(path)
        else:path.unlink()
    assert not list(Path('/run').glob('vertical-*'))
    print('VERTICAL_CLEANED',flush=True)
    assert all(row['pass'] for row in rows) and outer and not forbidden


if __name__ == '__main__':
    try:
        run()
    except subprocess.CalledProcessError as error:
        if error.cmd[0] != '/usr/bin/aivpn-server':
            print('COMMAND_ERROR ' + str(error.output), flush=True)
        raise
