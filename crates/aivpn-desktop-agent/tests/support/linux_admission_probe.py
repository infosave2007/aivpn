"""Реальная очередь первого пакета, root swap и независимые endpoints в своем guest."""
import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
import binding_probe as lab


class PacketBarrier:
    def __init__(self):
        self.lib = ctypes.CDLL('libnetfilter_queue.so.1', use_errno=True)
        self.lib.nfq_open.restype = ctypes.c_void_p
        self.lib.nfq_create_queue.restype = ctypes.c_void_p
        self.lib.nfq_get_msg_packet_hdr.restype = ctypes.c_void_p
        self.callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_void_p, ctypes.c_void_p)
        for name, args in {
            'nfq_bind_pf': [ctypes.c_void_p, ctypes.c_ushort],
            'nfq_create_queue': [ctypes.c_void_p, ctypes.c_ushort, self.callback_type, ctypes.c_void_p],
            'nfq_set_mode': [ctypes.c_void_p, ctypes.c_ubyte, ctypes.c_uint],
            'nfq_fd': [ctypes.c_void_p],
            'nfq_handle_packet': [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int],
            'nfq_get_msg_packet_hdr': [ctypes.c_void_p],
            'nfq_set_verdict': [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p],
            'nfq_destroy_queue': [ctypes.c_void_p], 'nfq_close': [ctypes.c_void_p],
        }.items():
            getattr(self.lib, name).argtypes = args
        self.handle = self.lib.nfq_open()
        assert self.handle
        assert self.lib.nfq_bind_pf(self.handle, socket.AF_INET) == 0
        assert self.lib.nfq_bind_pf(self.handle, socket.AF_INET6) == 0
        self.ids = []
        self.callback = self.callback_type(self.receive)
        self.queue = self.lib.nfq_create_queue(self.handle, 75, self.callback, None)
        assert self.queue and self.lib.nfq_set_mode(self.queue, 2, 65535) == 0
        self.socket = socket.fromfd(self.lib.nfq_fd(self.handle), socket.AF_NETLINK, socket.SOCK_RAW)
        self.socket.settimeout(3)

    def receive(self, _queue, _message, data, _context):
        header = self.lib.nfq_get_msg_packet_hdr(data)
        self.ids.append(struct.unpack('!I', ctypes.string_at(header, 4))[0])
        return 0

    def wait(self):
        data = self.socket.recv(131072)
        assert self.lib.nfq_handle_packet(self.handle, data, len(data)) >= 0
        assert self.ids

    def release(self):
        for packet in self.ids:
            assert self.lib.nfq_set_verdict(self.queue, packet, 1, 0, None) >= 0
        self.ids.clear()

    def close(self):
        self.socket.close()
        self.lib.nfq_destroy_queue(self.queue)
        self.lib.nfq_close(self.handle)


BOOTSTRAP = '''import os,sys
os.setgroups([]);os.setgid(1000);os.setuid(1000);os.execv(sys.argv[1],sys.argv[1:])
'''

CLIENT = '''import socket,json,sys,struct
family=int(sys.argv[1]);kind=int(sys.argv[2]);address=sys.argv[3];port=27901
protocol=int(sys.argv[4]);s=socket.socket(family,kind,protocol);s.settimeout(1.2)
s.bind(('::' if family==10 else '0.0.0.0',port));connected=False
def cookie():return struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,57,8))[0]
print(json.dumps({'ready':True,'cookie':cookie()}),flush=True)
for label in sys.stdin:
 label=label.strip()
 if label=='close':break
 if label=='retry' and kind==1 and not connected:
  s.close();s=socket.socket(family,kind,protocol);s.settimeout(1.2);port=27902;s.bind(('::' if family==10 else '0.0.0.0',port))
 sent=False;echo=False;error=None;payload=(label+'-admission-evidence').encode()
 try:
  if kind==1:
   if not connected:s.connect((address,9999));connected=True
   s.sendall(payload)
  else:s.sendto(payload,(address,9999))
  sent=True;echo=s.recv(2048)==payload
 except OSError as e:error=str(e)
 print(json.dumps({'label':label,'sent':sent,'echo':echo,'error':error,'source':s.getsockname(),'cookie':cookie()}),flush=True)
s.close()
'''


def tokens(metadata, port):
    bpf = ctypes.CDLL('libbpf.so.1', use_errno=True)
    result = []
    for name in ['routing_system', 'routing_overrides']:
        fd = bpf.bpf_obj_get((metadata['pins'] + '/maps/' + name).encode())
        assert fd >= 0
        info, size = ctypes.create_string_buffer(256), ctypes.c_uint(256)
        assert bpf.bpf_map_get_info_by_fd(fd, info, ctypes.byref(size)) == 0
        assert struct.unpack_from('=2I', info.raw, 8) == (40, 184)
        previous = None
        for _ in range(512):
            key = ctypes.create_string_buffer(40)
            if bpf.bpf_map_get_next_key(fd, previous, key) != 0:
                break
            value = ctypes.create_string_buffer(184)
            if struct.unpack_from('=I', key.raw, 28)[0] == 9999:
                assert bpf.bpf_map_lookup_elem(fd, key, value) == 0
                action = struct.unpack_from('=I', value.raw, 8)[0]
                generation, network, device, tag, cookie, epoch, ident, _, admission, sequence = struct.unpack_from('=10Q', value.raw, 32)
                result.append({'map':name,'cookie':cookie,'epoch':epoch,'id':ident,'binding_tag':tag,
                               'admission':admission & 3,'generation':generation,'action':action,
                               'network_generation':network,'device':device,'sequence':sequence,
                               'kind':struct.unpack_from('=I', value.raw, 176)[0]})
            previous = key
        else:
            raise AssertionError('Превышен предел чтения кеша fixture')
        os.close(fd)
    return result


def exact_token(copies, tag, admission):
    # Кеши могут держать две ссылки на один payload после смены действия.
    fields = ['cookie', 'epoch', 'id', 'binding_tag', 'admission', 'generation',
              'action', 'network_generation', 'device', 'kind']
    return bool(copies) and len({tuple(row[name] for name in fields) for row in copies}) == 1 and all(
        row['binding_tag'] == tag and row['admission'] == admission for row in copies)


def admission_links(metadata):
    bpf = ctypes.CDLL('libbpf.so.1', use_errno=True)
    programs = {}
    for name in ['ensure_local_dispatch', 'prepare_packet_dispatch', 'guard_final_output']:
        fd = bpf.bpf_obj_get((metadata['pins']+'/programs/'+name).encode())
        assert fd >= 0
        info, size = ctypes.create_string_buffer(256), ctypes.c_uint(256)
        assert bpf.bpf_prog_get_info_by_fd(fd, info, ctypes.byref(size)) == 0
        programs[struct.unpack_from('=I',info.raw,4)[0]] = name
        os.close(fd)
    rows = []
    for path in sorted((Path(metadata['pins'])/'links').iterdir()):
        fd = bpf.bpf_obj_get(str(path).encode())
        assert fd >= 0
        info, size = ctypes.create_string_buffer(256), ctypes.c_uint(256)
        assert bpf.bpf_link_get_info_by_fd(fd, info, ctypes.byref(size)) == 0
        kind, ident, program = struct.unpack_from('=3I',info.raw)
        if program in programs:
            row = {'pin':str(path),'type':kind,'id':ident,'program_id':program,'program':programs[program]}
            if kind == 10:
                row.update(zip(['family','hook','priority','flags'],struct.unpack_from('=IIiI',info.raw,16)))
            else:
                row.update(zip(['attach_type','target_object','target_btf_id'],struct.unpack_from('=3I',info.raw,16)))
            rows.append(row)
        os.close(fd)
    anchors = [r for r in rows if r['program']=='ensure_local_dispatch']
    assert {(r['family'],r['hook'],r['priority'],r['flags']) for r in anchors} == {(2,3,0,0),(10,3,0,0)}
    finals = [r for r in rows if r['program']=='guard_final_output']
    assert {(r['family'],r['hook'],r['priority']) for r in finals} == {(2,4,2147483646),(10,4,2147483646)}
    dispatch = [r for r in rows if r['program']=='prepare_packet_dispatch']
    assert len(dispatch)==1 and dispatch[0]['type']==2 and dispatch[0]['target_btf_id']>0
    print('ADMISSION_LINKS '+json.dumps(rows),flush=True)


def evict_cookie(metadata, cookie):
    bpf = ctypes.CDLL('libbpf.so.1', use_errno=True)
    removed = []
    for name in ['routing_system', 'routing_overrides']:
        fd = bpf.bpf_obj_get((metadata['pins'] + '/maps/' + name).encode())
        assert fd >= 0
        previous, keys = None, []
        for _ in range(512):
            key = ctypes.create_string_buffer(40)
            if bpf.bpf_map_get_next_key(fd, previous, key):
                break
            if struct.unpack_from('=Q', key.raw)[0] == cookie:
                keys.append(key)
            previous = key
        else:
            raise AssertionError('Превышен предел eviction fixture')
        for key in keys:
            assert bpf.bpf_map_delete_elem(fd, key) == 0
            removed.append(name)
        os.close(fd)
    assert removed
    assert not [t for t in tokens(metadata, 27901) if t['cookie'] == cookie]
    return removed


def start_single_tcp():
    source = CLIENT.replace('s.settimeout(1.2)', 's.settimeout(30)')
    client = subprocess.Popen(['/usr/bin/python3','-c',BOOTSTRAP,'/usr/bin/binding-a','-c',
                               source,'2','1','198.18.0.53','0'], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    ready = json.loads(client.stdout.readline())
    assert ready['ready']
    return client, ready


def post_barrier():
    barrier = PacketBarrier()
    lab.command(['nft','-f','-'], input='table inet admission_barrier { chain post { type filter hook postrouting priority 200; policy accept; tcp sport 27901 queue num 75; }\n}\n')
    return barrier


def single_tcp_result(client, ready, metadata, capture, echoes, expected, case, removed=None):
    result = json.loads(client.stdout.readline())
    time.sleep(.1)
    copies = [t for t in tokens(metadata, 27901) if t['cookie'] == ready['cookie']]
    _, outgoing, reply = lab.Matrix(capture, echoes).observations(27901, 'first-admission-evidence')
    tag = 0 if case == 'preserved' else metadata['binding_tag']
    allowed = (result['cookie'] == ready['cookie'] and result['echo'] and
               lab.Matrix.decision(result, outgoing, reply, 2) == expected and
               outgoing[0]['tcp_flags'] == 2 and exact_token(copies, tag, 1))
    if case == 'preserved':
        allowed = allowed and all(t['epoch'] == 0 for t in copies)
    row = {'case':case,'uid':1000,'new_connect_calls':1,'extra_send_before_connect_reply':0,
           'ready':ready,'client':result,'tokens':copies,'packets':outgoing,'endpoint':reply,
           'evicted':removed,'expected':expected,'pass':bool(allowed)}
    print('ADMISSION_CASE '+json.dumps(row),flush=True)
    client.stdin.write('close\n'); client.stdin.flush(); client.communicate(timeout=5)
    assert client.returncode == 0
    return row


def eviction_retry(metadata, capture, echoes):
    client, ready = start_single_tcp()
    barrier = post_barrier()
    client.stdin.write('first\n'); client.stdin.flush()
    barrier.wait()
    prepared = [t for t in tokens(metadata, 27901) if t['cookie'] == ready['cookie']]
    assert exact_token(prepared, metadata['binding_tag'], 0)
    removed = evict_cookie(metadata, ready['cookie'])
    barrier.release()
    time.sleep(.15)
    assert not [p for p in capture.events if p['source_port'] == 27901 and p['packet_type'] == 4]
    lab.command(['nft','delete','table','inet','admission_barrier'])
    barrier.close()
    return single_tcp_result(client, ready, metadata, capture, echoes,
                             os.environ['ADMISSION_BEFORE'], 'tcp-eviction-retry', removed)


def matrix_transition(matrix, loader, metadata, capture):
    before, after = os.environ['ADMISSION_BEFORE'], os.environ['ADMISSION_AFTER']
    scenario = os.environ.get('ADMISSION_SCENARIO', 'delayed')
    kind, family = int(os.environ['ADMISSION_KIND']), int(os.environ['ADMISSION_FAMILY'])
    protocol = int(os.environ.get('ADMISSION_PROTOCOL', 0))
    address = '198.18.0.53' if family == 2 else '2001:db8:53::53'
    matrix.run_case('before-control', '/usr/bin/binding-a', before, family, kind)
    client = subprocess.Popen(['/usr/bin/python3','-c',BOOTSTRAP,'/usr/bin/binding-a','-c',
                               CLIENT,str(family),str(kind),address,str(protocol)],
                              stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    ready = json.loads(client.stdout.readline()); assert ready['ready']
    barrier = None
    first = None
    if before != 'BLOCK' and scenario == 'delayed':
        barrier = PacketBarrier()
        lab.command(['nft','-f','-'],input='table inet admission_barrier { chain out { type filter hook output priority 0; policy accept; meta l4proto { tcp, udp } th sport 27901 queue num 75; }\n}\n')
    client.stdin.write('first\n'); client.stdin.flush()
    if barrier:
        barrier.wait()
    else:
        first = json.loads(client.stdout.readline())
        assert first['echo'] == (before != 'BLOCK'), first
    prepared = [t for t in tokens(metadata, 27901) if t['cookie'] == ready['cookie']]
    if not protocol and before != 'BLOCK':
        assert len(prepared) == 1 and prepared[0]['binding_tag'] == metadata['binding_tag']
        assert prepared[0]['admission'] == (1 if scenario == 'accepted' else 0), prepared
    start = len(capture.events)
    command = 'refresh' if before == after else 'policy:' + after
    loader.stdin.write(command+'\n'); loader.stdin.flush()
    swapped = loader_line(loader, 'SNAPSHOT_SWAPPED ')
    assert swapped['binding_tag'] != metadata['binding_tag']
    if barrier:
        barrier.release()
        lab.command(['nft','delete','table','inet','admission_barrier'])
        first = json.loads(client.stdout.readline())
        barrier.close()
    time.sleep(.1)
    first_packets = [p for p in capture.events[start:] if p['source_port']==27901 and p['packet_type']==4]
    if scenario == 'accepted':
        expected = before
    else:
        expected = after
        if after == 'BLOCK':
            assert not first_packets, first_packets
    client.stdin.write('retry\n'); client.stdin.flush()
    retry = json.loads(client.stdout.readline())
    time.sleep(.1)
    port = retry['source'][1]
    packet_rows = [p for p in capture.events if p['source_port']==port and p['packet_type']==4]
    source = ('192.0.2.2' if family==2 else '2001:db8:2::2') if expected=='SYSTEM' else ('10.77.0.2' if family==2 else '2001:db8:77::2')
    exact = [t for t in tokens(metadata,port) if t['cookie']==retry['cookie']]
    tag = metadata['binding_tag'] if scenario=='accepted' else swapped['binding_tag']
    allowed = retry['echo'] and packet_rows and all(p['source']==source for p in packet_rows)
    if expected == 'BLOCK':
        allowed = not retry['echo'] and not [p for p in capture.events[start:] if p['source_port'] in [27901,27902] and p['packet_type']==4]
    elif not protocol:
        allowed = allowed and exact_token(exact, tag, 1)
    row = {'case':'transition','before':before,'after':after,'scenario':scenario,'family':family,'kind':kind,
           'protocol':protocol,'prepared':prepared,'swapped':swapped,'first':first,'first_packets':first_packets[:1],
           'retry':retry,'tokens':exact,'packets':packet_rows,'expected':expected,'pass':bool(allowed)}
    print('ADMISSION_CASE '+json.dumps(row),flush=True)
    client.stdin.write('close\n');client.stdin.flush();client.communicate(timeout=5)
    assert client.returncode==0
    return row


def loader_line(loader, prefix):
    while True:
        line = loader.stdout.readline()
        print('FIXTURE ' + line.rstrip(), flush=True)
        assert line, 'Writer завершился до ответа'
        if line.startswith(prefix):
            return json.loads(line.split(' ', 1)[1])


def run():
    lab.require_guest()
    lab.prepare_network()
    lab.command(['modprobe', '-a', 'nfnetlink_queue', 'nft_queue'])
    server = subprocess.Popen(['ip', 'netns', 'exec', 'binding-peer', 'python3',
                               '/lab/binding_probe.py', '--server'], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
    assert server.stdout.readline().strip() == 'ENDPOINT_READY'
    echoes = []
    reader = threading.Thread(target=lambda: echoes.extend(json.loads(x) for x in server.stdout), daemon=True)
    reader.start()
    capture = lab.Capture()
    scenario = os.environ.get('ADMISSION_SCENARIO', 'delayed')
    preserved = None
    if scenario == 'preserved':
        client, ready = start_single_tcp()
        barrier = post_barrier()
        client.stdin.write('first\n'); client.stdin.flush()
        barrier.wait()
        preserved = client, ready, barrier
    legacy = scenario == 'legacy'
    loader = subprocess.Popen([os.environ['AIVPN_BINDING_FIXTURE'], '--ignored', '--exact',
                               'legacy_capture_writer_child' if legacy else 'snapshot_writer_child', '--nocapture'], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              env={**os.environ, 'AIVPN_SNAPSHOT_CHILD': '1', 'CAPTURE_LEGACY':'1'})
    metadata = loader_line(loader, 'BINDING_READY ' if legacy else 'SNAPSHOT_READY ')
    if not legacy:
        admission_links(metadata)
    maps = lab.Maps(metadata)
    lab.firewall(metadata['pins'])
    matrix = lab.Matrix(capture, echoes, captured_bootstrap=True)
    variant = os.environ['SNAPSHOT_VARIANT']
    if legacy:
        loader.stdin.write('publish\n'); loader.stdin.flush()
        assert loader.stdout.readline().strip() == 'PUBLISHED'
        for kind in [1, 2]:
            matrix.run_case('legacy-system', '/usr/bin/binding-b', 'SYSTEM', 2, kind)
            matrix.run_case('legacy-vpn', '/usr/bin/binding-a', 'VPN', 2, kind)
        row = {'case':'legacy-smoke','pass':all(x['pass'] for x in matrix.checks)}
    elif preserved:
        client, ready, barrier = preserved
        barrier.release()
        lab.command(['nft','delete','table','inet','admission_barrier'])
        barrier.close()
        row = single_tcp_result(client, ready, metadata, capture, echoes, 'SYSTEM', 'preserved')
    elif scenario == 'eviction':
        row = eviction_retry(metadata, capture, echoes)
    elif variant == 'admission-matrix':
        row = matrix_transition(matrix, loader, metadata, capture)
    else:
        actor = '/usr/bin/binding-b' if variant == 'admission-system-block' else '/usr/bin/binding-a'
        before = 'SYSTEM' if variant == 'admission-system-block' else 'VPN'
        kind = int(os.environ.get('ADMISSION_KIND', socket.SOCK_DGRAM))
        family = int(os.environ.get('ADMISSION_FAMILY', socket.AF_INET))
        if os.environ.get('ADMISSION_MINIMAL') == '1':
            matrix.run_case('before-control', actor, before, family, kind)
        else:
            matrix.probe('before-control', actor, before)
        barrier = PacketBarrier()
        lab.command(['nft', '-f', '-'], input='table inet admission_barrier { chain out { type filter hook output priority 0; policy accept; meta l4proto { tcp, udp } th sport 27901 queue num 75; }\n}\n')
        kind = int(os.environ.get('ADMISSION_KIND', socket.SOCK_DGRAM))
        family = int(os.environ.get('ADMISSION_FAMILY', socket.AF_INET))
        address = '198.18.0.53' if family == socket.AF_INET else '2001:db8:53::53'
        client = subprocess.Popen(['/usr/bin/python3', '-c', BOOTSTRAP, actor, '-c',
                                   lab.CLIENT.replace('s.settimeout(.5)', 's.settimeout(2)'),
                                   'delayed-first', address, str(family), str(kind), '27901'],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        barrier.wait()
        first_count = len(capture.events)
        assert not [e for e in capture.events if e['source_port'] == 27901]
        os.rename('/usr/bin/binding-a', '/usr/bin/binding-a-old')
        os.link('/usr/bin/binding-b', '/usr/bin/binding-a')
        loader.stdin.write('refresh\n'); loader.stdin.flush()
        swapped = loader_line(loader, 'SNAPSHOT_SWAPPED ')
        barrier.release()
        lab.command(['nft', 'delete', 'table', 'inet', 'admission_barrier'])
        output = client.communicate(timeout=5)[0]
        time.sleep(.2)
        packets = [e for e in capture.events[first_count:] if e['source_port'] == 27901 and e['packet_type'] == 4]
        row = {'case': 'prepare-before-swap-final-after', 'variant': variant, 'family': family,
               'kind': kind, 'client': json.loads(output), 'swapped': swapped, 'first': packets[:1],
               'packets': len(packets), 'expected': 'BLOCK', 'pass': not packets}
        print('ADMISSION_CASE ' + json.dumps(row), flush=True)
        barrier.close()
        expected = 'BLOCK' if before == 'SYSTEM' else 'VPN'
        if os.environ.get('ADMISSION_MINIMAL') == '1':
            matrix.run_case('after-block-control', '/usr/bin/binding-a', expected, family, kind)
        else:
            matrix.probe('after-block-control', '/usr/bin/binding-a', expected)
    maps.close()
    lab.firewall(metadata['pins'], remove=True)
    loader.stdin.write('cleanup\n'); loader.stdin.flush()
    output = loader.communicate(timeout=20)[0]; print(output, flush=True)
    assert loader.returncode == 0 and ('CLEANED' if legacy else 'SNAPSHOT_CLEANED') in output
    server.terminate(); server.wait(timeout=5); reader.join(timeout=2)
    capture.close()
    lab.command(['ip', 'netns', 'del', 'binding-peer'])
    assert not Path('/lab/snapshot-state').exists()
    assert row['pass'] and all(x['pass'] for x in matrix.checks), 'Старый prepared token допустил первый пакет'


if __name__ == '__main__':
    try:
        run()
    except subprocess.CalledProcessError as error:
        print(error.output, flush=True)
        raise
