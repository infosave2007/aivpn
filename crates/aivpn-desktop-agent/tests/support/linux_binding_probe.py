"""Пакетная регрессия только для отдельного no-NIC guest."""

import base64
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time


def require_guest():
    assert os.geteuid() == 0
    assert 'aivpn.app-routing-lab=1' in Path('/proc/cmdline').read_text().split()
    assert Path('/lab/.app-routing-guest').read_text() == 'aivpn-offline-routing-lab\n'


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kwargs)


def endpoint():
    sockets = []
    for family, addresses in [(socket.AF_INET, ['198.18.0.53', '198.18.0.54','192.0.2.1']),
                              (socket.AF_INET6, ['2001:db8:53::53', '2001:db8:53::54','2001:db8:2::1'])]:
        for address in addresses:
            for kind in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
                sock = socket.socket(family, kind)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, 9999))
                if kind == socket.SOCK_STREAM:
                    sock.listen()
                sockets.append(sock)
    print('ENDPOINT_READY', flush=True)
    while True:
        for sock in select.select(sockets, [], [])[0]:
            if sock.type == socket.SOCK_DGRAM:
                data, peer = sock.recvfrom(2048)
                sock.sendto(data, peer)
            else:
                connection, peer = sock.accept()
                def stream(connection,peer):
                    with connection:
                        while data:=connection.recv(2048):
                            connection.sendall(data)
                            print(json.dumps({'label':data.decode(),'peer':peer[0],'port':peer[1]}),flush=True)
                threading.Thread(target=stream,args=(connection,peer),daemon=True).start()
                continue
            print(json.dumps({'label': data.decode(), 'peer': peer[0], 'port': peer[1]}), flush=True)


def prepare_network():
    os.chmod('/', 0o755)
    command(['modprobe', '-a', 'virtio_blk', 'ext4', 'nf_conntrack', 'nft_compat', 'xt_bpf', 'xt_mark'])
    command(['mount', '/dev/vda', '/usr/bin'])
    command(['mount', '-t', 'bpf', 'bpf', '/sys/fs/bpf'])
    command(['ip', 'link', 'set', 'lo', 'up'])
    command(['ip', 'netns', 'add', 'binding-peer'])
    command(['ip', '-n', 'binding-peer', 'link', 'set', 'lo', 'up'])
    for local, remote, address, peer, address6, peer6 in [
        ('wan0', 'wan_s', '192.0.2.2', '192.0.2.1', '2001:db8:2::2', '2001:db8:2::1'),
        ('vpn0', 'vpn_s', '10.77.0.2', '10.77.0.1', '2001:db8:77::2', '2001:db8:77::1'),
    ]:
        command(['ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', remote])
        command(['ip', 'link', 'set', remote, 'netns', 'binding-peer'])
        command(['ip', 'addr', 'add', address + '/24', 'dev', local])
        command(['ip', '-6', 'addr', 'add', address6 + '/64', 'dev', local, 'nodad'])
        command(['ip', 'link', 'set', local, 'up'])
        command(['ip', '-n', 'binding-peer', 'addr', 'add', peer + '/24', 'dev', remote])
        command(['ip', '-n', 'binding-peer', '-6', 'addr', 'add', peer6 + '/64', 'dev', remote, 'nodad'])
        command(['ip', '-n', 'binding-peer', 'link', 'set', remote, 'up'])
    for address in ['198.18.0.53/32', '198.18.0.54/32', '2001:db8:53::53/128', '2001:db8:53::54/128']:
        command(['ip', '-n', 'binding-peer', 'addr', 'add', address, 'dev', 'lo', 'nodad'])
    for family, wan, vpn in [('-4', '192.0.2.1', '10.77.0.1'), ('-6', '2001:db8:2::1', '2001:db8:77::1')]:
        command(['ip', family, 'route', 'add', 'default', 'via', wan, 'dev', 'wan0'])
        command(['ip', family, 'route', 'add', 'table', '200', 'default', 'via', vpn, 'dev', 'vpn0'])
        command(['ip', family, 'rule', 'add', 'pref', '100', 'fwmark', '0xa1', 'lookup', '200'])
    for path in Path('/proc/sys/net/ipv4/conf').glob('*/rp_filter'):
        path.write_text('0')
    for name in ['a', 'b', 'unknown']:
        shutil.copyfile('/usr/bin/python3', '/usr/bin/binding-' + name)
        os.chmod('/usr/bin/binding-' + name, 0o755)
    os.link('/usr/bin/binding-a', '/usr/bin/binding-a-alias')


class Capture:
    def __init__(self):
        self.events = []
        self.raw = []
        self.stop = threading.Event()
        self.sockets = []
        self.threads = []
        for interface in ['wan0', 'vpn0']:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((interface, 0))
            sock.settimeout(.1)
            self.sockets.append(sock)
            thread = threading.Thread(target=self.read, args=(sock,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def read(self, sock):
        while not self.stop.is_set():
            try:
                data, meta = sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError as error:
                if error.errno != errno.ENETDOWN:
                    raise
                self.stop.wait(.05)
                continue
            # В PCAP нужны все кадры, включая DNS. Фильтр относится только к событиям сценария.
            self.raw.append((time.time(), data))
            event = self.decode(data, meta)
            if event is not None:
                self.events.append(event)

    @staticmethod
    def decode(data, meta):
        if len(data) < 14:
            return None
        if data[12:14] == b'\x08\x00':
            if len(data) < 34 or data[14] >> 4 != 4 or data[14] & 15 < 5:
                return None
            family, protocol, start = socket.AF_INET, data[23], 14 + (data[14] & 15) * 4
            source, destination = data[26:30], data[30:34]
        elif data[12:14] == b'\x86\xdd':
            if len(data) < 54 or data[14] >> 4 != 6:
                return None
            family, protocol, start = socket.AF_INET6, data[20], 54
            source, destination = data[22:38], data[38:54]
        else:
            return None
        if family==socket.AF_INET6:
            for _ in range(3):
                if protocol not in [0,43,60] or len(data)<start+8:break
                protocol,next_start=data[start],start+(data[start+1]+1)*8
                start=next_start
            if protocol==58 and len(data)>=start+8:
                return {'interface':meta[0],'packet_type':meta[2],'source':socket.inet_ntop(family,source),'destination':socket.inet_ntop(family,destination),'source_port':0,'destination_port':0,'protocol':58,'tcp_flags':None,'icmp_type':data[start],'bytes':len(data)}
        if protocol not in [6, 17] or len(data) < start + (20 if protocol == 6 else 8):
            return None
        sport, dport = struct.unpack_from('!HH', data, start)
        if 9999 not in [sport, dport]:
            return None
        return {'interface': meta[0], 'packet_type': meta[2],
            'source': socket.inet_ntop(family, source), 'destination': socket.inet_ntop(family, destination),
            'source_port': sport, 'destination_port': dport, 'protocol': protocol,
            'tcp_flags': data[start + 13] if protocol == 6 else None, 'bytes': len(data)}

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=2)
            assert not thread.is_alive()
        for sock in self.sockets:
            sock.close()
        pcap = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        for stamp, data in self.raw:
            pcap += struct.pack('<IIII', int(stamp), int((stamp % 1) * 1000000), len(data), len(data)) + data
        print('BINDING_PCAP ' + base64.b64encode(pcap).decode(), flush=True)


class Maps:
    # Raw-map публикация нужна только fixture, пока backend не подключен.
    def __init__(self, metadata):
        self.bpf = ctypes.CDLL('libbpf.so.1', use_errno=True)
        self.bpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
        self.bpf.bpf_obj_get.restype = ctypes.c_int
        self.bpf.bpf_map_get_info_by_fd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.bpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong]
        self.bpf.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
        self.fds, self.shapes = {}, {}
        for name, shape in {
            'file_bindings': [1, 8, 4, 4096], 'applications': [1, 24, 4, 16384],
            'profiles': [1, 4, 64, 256], 'interface_profiles': [1, 16, 4, 256],
            'mark_profiles': [1, 16, 4, 512], 'policies': [1, 8, 14376, 256],
            'inode_tokens': [28, 4, 8, 0], 'file_counter': [2, 4, 8, 1], 'path_key': [2, 4, 16, 1],
        }.items():
            fd = self.bpf.bpf_obj_get((metadata['pins'] + '/maps/' + name).encode())
            assert fd >= 0
            info, length = ctypes.create_string_buffer(256), ctypes.c_uint(256)
            assert self.bpf.bpf_map_get_info_by_fd(fd, info, ctypes.byref(length)) == 0
            words = struct.unpack_from('=6I', info.raw)
            actual = [words[0], words[2], words[3], words[4]]
            assert actual == shape, (name, actual, shape)
            self.fds[name], self.shapes[name] = fd, actual
        for row in metadata['bindings']:
            self.update('file_bindings', struct.pack('=Q', row['cookie']), struct.pack('=I', row['slot']))
            for kind in ['physical', 'logical']:
                self.marker(row, kind)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            self.netns = struct.unpack('=Q', sock.getsockopt(socket.SOL_SOCKET, 71, 8))[0]
        slot, index = metadata['profile'], socket.if_nametoindex('vpn0')
        device = os.stat('/sys/class/net/vpn0').st_ino
        self.update('profiles', struct.pack('=I', slot), struct.pack('=IIIIQ4s16s4xQQ',
            0xa1, 1, 1, index, 1, socket.inet_aton('10.77.0.2'),
            socket.inet_pton(socket.AF_INET6, '2001:db8:77::2'), self.netns, device))
        for name, value in [('interface_profiles', index), ('mark_profiles', 0xa1)]:
            self.update(name, struct.pack('=QII', self.netns, value, 0), struct.pack('=I', slot))

    def update(self, name, key, value):
        k, v = ctypes.create_string_buffer(key), ctypes.create_string_buffer(value)
        assert self.bpf.bpf_map_update_elem(self.fds[name], k, v, 0) == 0, (name, ctypes.get_errno())

    def marker(self, row, kind, remove=False):
        key = struct.pack('=QQQ', *row[kind])
        if remove:
            assert self.bpf.bpf_map_delete_elem(self.fds['applications'], ctypes.create_string_buffer(key)) == 0
        else:
            self.update('applications', key, struct.pack('=I', row['slot']))

    def close(self):
        for fd in self.fds.values():
            os.close(fd)


def firewall(pins, remove=False):
    for executable in ['iptables-nft', 'ip6tables-nft']:
        prefix = [executable, '-t', 'mangle']
        if remove:
            for args in [['-D', 'OUTPUT', '-j', 'BINDING'], ['-F', 'BINDING'], ['-X', 'BINDING']]:
                command(prefix + args)
        else:
            command(prefix + ['-N', 'BINDING'])
            command(prefix + ['-A', 'OUTPUT', '-j', 'BINDING'])
            command(prefix + ['-A', 'BINDING', '-m', 'bpf', '--object-pinned', pins + '/programs/match_block', '-j', 'DROP'])
            command(prefix + ['-A', 'BINDING', '-m', 'bpf', '--object-pinned', pins + '/programs/match_vpn', '-j', 'MARK', '--set-mark', '0xa1'])
    if remove:
        command(['nft', 'delete', 'table', 'inet', 'binding_nat'])
    else:
        command(['nft', '-f', '-'], input='table inet binding_nat { chain post { type nat hook postrouting priority srcnat; policy accept; meta mark 0xa1 oifname "vpn0" snat ip to 10.77.0.2; meta mark 0xa1 oifname "vpn0" snat ip6 to 2001:db8:77::2; }\n}\n')


CLIENT = '''import socket,json,sys
family=int(sys.argv[3]);kind=int(sys.argv[4]);s=socket.socket(family,kind);s.settimeout(.5)
s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',int(sys.argv[5])))
sent=False;echo=False;error=None
try:
 if kind==socket.SOCK_STREAM:
  s.connect((sys.argv[2],9999));s.sendall(sys.argv[1].encode())
 else:s.sendto(sys.argv[1].encode(),(sys.argv[2],9999))
 sent=True;echo=s.recv(2048)==sys.argv[1].encode()
except OSError as e:error=str(e)
print(json.dumps({'sent':sent,'echo':echo,'error':error,'source':s.getsockname()}))
'''
ANCESTOR = '''import subprocess,sys
subprocess.run(['/usr/bin/binding-unknown','-c',sys.argv[1],*sys.argv[2:]],check=True)
'''


def identity(uid, bind):
    def enter():
        if bind:
            libc = ctypes.CDLL(None, use_errno=True)
            assert libc.unshare(0x20000) == 0
            assert libc.mount(None, b'/', None, (1 << 18) | (1 << 14), None) == 0
            assert libc.mount(b'/usr/bin/binding-b', b'/usr/bin/binding-a', None, 4096, None) == 0
            assert os.stat('/usr/bin/binding-a').st_ino == os.stat('/usr/bin/binding-b').st_ino
            assert os.stat('/usr/bin/binding-a').st_ino != os.stat('/usr/bin/binding-a-alias').st_ino
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return enter


class Matrix:
    def __init__(self, capture, echoes, captured_bootstrap=False):
        self.capture, self.echoes, self.checks = capture, echoes, []
        self.captured_bootstrap=captured_bootstrap

    def probe(self, case, path, expected, **options):
        for family in [socket.AF_INET, socket.AF_INET6]:
            for kind in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
                self.run_case(case, path, expected, family, kind, **options)

    def observations(self, port, label):
        seen = [p for p in self.capture.events if port in [p['source_port'], p['destination_port']]]
        outgoing = [p for p in seen if p['destination_port'] == 9999 and p['packet_type'] == 4]
        reply = [p for p in self.echoes if p['label'] == label]
        return seen, outgoing, reply

    @staticmethod
    def decision(result, outgoing, reply, family):
        evidence = (bool(result['echo']), bool(outgoing), bool(reply))
        if evidence == (False, False, False):
            return 'BLOCK'
        if evidence != (True, True, True):
            return 'FIXTURE_UNCERTAIN'
        sources = ['2001:db8:77::2', '2001:db8:2::2'] if family == socket.AF_INET6 else ['10.77.0.2', '192.0.2.2']
        interfaces = {p['interface'] for p in outgoing}
        for action, interface, source in zip(['VPN', 'SYSTEM'], ['vpn0', 'wan0'], sources):
            if interfaces == {interface} and reply[0]['peer'] == source:
                return action
        return 'FIXTURE_UNCERTAIN'

    def run_case(self, case, path, expected, family, kind, uid=1000, outside=False, bind=False, ancestor=False, prefix=False, launch_errno=None):
        port = 24000 + len(self.checks)
        label = f'BINDING-{case}-{family}-{kind}'
        target = ('2001:db8:53::' if family == socket.AF_INET6 else '198.18.0.') + ('54' if outside else '53')
        if prefix:target='2001:db8:2::1' if family==socket.AF_INET6 else '192.0.2.1'
        args = [path, '-c', ANCESTOR, CLIENT] if ancestor else [path, '-c', CLIENT]
        if self.captured_bootstrap:
            bootstrap='import os,sys,json\nuid=int(sys.argv[1]);os.setgroups([]);os.setgid(uid);os.setuid(uid)\ntry:os.execv(sys.argv[2],sys.argv[2:])\nexcept OSError as e:print(json.dumps({"sent":False,"echo":False,"error":str(e),"source":None,"launch_errno":e.errno}))'
            args=['/usr/bin/python3','-c',bootstrap,str(uid),*args]
        output = command(args + [label, target, str(family), str(kind), str(port)],
                         preexec_fn=identity(0 if self.captured_bootstrap else uid, bind), timeout=5)
        result = json.loads(output)
        assert result.get('launch_errno')==launch_errno, 'Неожиданный результат exec: '+repr(result)
        time.sleep(.1)
        seen, outgoing, reply = self.observations(port, label)
        actual = self.decision(result, outgoing, reply, family)
        if kind == socket.SOCK_STREAM and actual in ['SYSTEM', 'VPN']:
            assert outgoing[0]['tcp_flags'] == 2, 'Не наблюдался первый TCP SYN'
        row = {'case': case, 'label': label, 'uid': uid, 'family': family, 'kind': kind,
               'target': target, 'client_port': port, 'expected': expected, 'actual': actual,
               'pass': actual == expected, 'client': result, 'packets': seen, 'endpoint': reply}
        self.checks.append(row)
        print('BINDING_CASE ' + json.dumps(row), flush=True)
        assert actual != 'FIXTURE_UNCERTAIN', 'Ошибка пакетного стенда'


def run():
    prepare_network()
    server = subprocess.Popen(['ip', 'netns', 'exec', 'binding-peer', 'python3', __file__, '--server'],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert server.stdout.readline().strip() == 'ENDPOINT_READY'
    echoes = []
    def read_echo():
        for line in server.stdout:
            echoes.append(json.loads(line))
    reader = threading.Thread(target=read_echo, daemon=True)
    reader.start()
    capture = Capture()
    loader = subprocess.Popen([os.environ['AIVPN_BINDING_FIXTURE'], '--ignored', '--exact', 'binding_writer_child', '--nocapture'],
        env={**os.environ, 'AIVPN_BINDING_CHILD': '1'}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    while True:
        line = loader.stdout.readline()
        print('FIXTURE ' + line.rstrip(), flush=True)
        if line.startswith('BINDING_READY '):
            metadata = json.loads(line.split(' ', 1)[1])
            break
        assert line and loader.poll() is None, 'Ошибка KernelWriter fixture'
    maps = Maps(metadata)
    firewall(metadata['pins'])
    def publish(mode):
        loader.stdin.write(mode + '\n')
        loader.stdin.flush()
        assert loader.stdout.readline().strip() == 'PUBLISHED'
    publish('publish')
    matrix = Matrix(capture, echoes)
    a, b = '/usr/bin/binding-a', '/usr/bin/binding-b'
    matrix.probe('original-a', a, 'VPN')
    matrix.probe('ordinary-known-b', b, 'SYSTEM')
    matrix.probe('b-own-policy', b, 'VPN', uid=1001)
    matrix.probe('confirmed-hardlink-a', a + '-alias', 'VPN')
    matrix.probe('original-a-child-no-inherit', a, 'SYSTEM', ancestor=True)
    matrix.probe('logical-known-b-replacement', a, 'BLOCK', bind=True)
    matrix.probe('logical-replacement-other-owner', a, 'SYSTEM', bind=True, uid=1002)
    matrix.probe('logical-replacement-b-own-policy', a, 'VPN', bind=True, uid=1001)
    matrix.probe('logical-replacement-outside-cidr', a, 'SYSTEM', bind=True, outside=True)
    matrix.probe('logical-replacement-child-no-inherit', a, 'SYSTEM', bind=True, ancestor=True)
    assert os.stat(a).st_ino == os.stat(a + '-alias').st_ino
    os.rename(a, a + '-old')
    os.link(b, a)
    matrix.probe('known-b-replaces-selected-a', a, 'BLOCK')
    matrix.probe('physical-replacement-b-own-policy', a, 'VPN', uid=1001)
    maps.marker(metadata['bindings'][0], 'logical', remove=True)
    matrix.probe('physical-only-known-b-replacement', a, 'BLOCK')
    matrix.probe('physical-replacement-outside-cidr', a, 'SYSTEM', outside=True)
    matrix.probe('physical-replacement-child-no-inherit', a, 'SYSTEM', ancestor=True)
    maps.marker(metadata['bindings'][0], 'logical')
    os.unlink(a)
    os.link('/usr/bin/binding-unknown', a)
    matrix.probe('unknown-replaces-selected-a', a, 'BLOCK')
    matrix.probe('unknown-replacement-other-owner', a, 'SYSTEM', uid=1002)
    matrix.probe('unknown-replacement-outside-cidr', a, 'SYSTEM', outside=True)
    os.unlink(a)
    os.link(a + '-old', a)
    publish('inherit')
    matrix.probe('original-a-child-inherit', a, 'VPN', ancestor=True)
    matrix.probe('logical-replacement-child-inherit', a, 'BLOCK', bind=True, ancestor=True)
    matrix.probe('logical-ancestor-outside-cidr', a, 'SYSTEM', bind=True, ancestor=True, outside=True)
    os.unlink(a)
    os.link(b, a)
    maps.marker(metadata['bindings'][0], 'logical', remove=True)
    matrix.probe('physical-replacement-child-inherit', a, 'BLOCK', ancestor=True)
    maps.close()
    firewall(metadata['pins'], remove=True)
    loader.stdin.write('cleanup\n')
    loader.stdin.flush()
    output = loader.communicate(timeout=15)[0]
    print(output, flush=True)
    assert loader.returncode == 0 and 'BINDING_CLEANED' in output
    server.terminate()
    server.wait(timeout=5)
    reader.join(timeout=2)
    capture.close()
    command(['ip', 'netns', 'del', 'binding-peer'])
    cleanup = {'pins_absent': not Path(metadata['pins']).exists(),
        'retainers_absent': not Path('/sys/fs/bpf/aivpn_app_retainers/73737373737373737373737373737373').exists(),
        'writer_state_absent': not Path('/lab/binding-state').exists(), 'loader_exit': loader.returncode,
        'endpoint_exit': server.returncode, 'parent_mount_unchanged': os.stat(a + '-alias').st_ino == os.stat(a + '-old').st_ino}
    print('BINDING_SUMMARY ' + json.dumps({'metadata': metadata, 'map_shapes': maps.shapes,
        'network_namespace': maps.netns, 'checks': matrix.checks, 'cleanup': cleanup}), flush=True)
    assert all(cleanup[key] for key in ['pins_absent', 'retainers_absent', 'writer_state_absent', 'parent_mount_unchanged'])
    assert all(row['pass'] for row in matrix.checks), 'Регрессия scoped path mismatch'


if __name__ == '__main__':
    require_guest()
    if '--server' in sys.argv:
        endpoint()
    else:
        run()
