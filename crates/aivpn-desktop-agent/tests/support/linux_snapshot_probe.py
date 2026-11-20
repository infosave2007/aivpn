"""Фиксированный root устанавливается до всех клиентских сокетов этой fixture."""
import json
import os
from pathlib import Path
import subprocess
import threading
import socket
import ctypes
import struct
import time
import binding_probe as lab


a,b,h='/usr/bin/binding-a','/usr/bin/binding-b','/usr/bin/binding-a-alias'


def capture_diagnostics(metadata):
    bpf=ctypes.CDLL('libbpf.so.1',use_errno=True)
    rows=[]
    for path in sorted(Path(metadata['pins']+'/maps').iterdir()):
        fd=bpf.bpf_obj_get(str(path).encode())
        if fd<0:continue
        info=ctypes.create_string_buffer(256);length=ctypes.c_uint(256)
        assert bpf.bpf_map_get_info_by_fd(fd,info,ctypes.byref(length))==0
        words=struct.unpack_from('=6I',info.raw)
        row={'map':path.name,'kind':words[0],'key':words[2],'value':words[3],'capacity':words[4],'flags':words[5],
             'fdinfo':Path(f'/proc/self/fdinfo/{fd}').read_text()}
        if path.name=='processes':
            pidfd=os.pidfd_open(os.getpid());key=ctypes.c_int(pidfd);value=ctypes.create_string_buffer(words[3])
            row['current_lookup']=bpf.bpf_map_lookup_elem(fd,ctypes.byref(key),value)
            row['current_errno']=ctypes.get_errno()
            if row['current_lookup']==0:row['current_prefix']=value.raw[:160].hex()
            os.close(pidfd)
        if path.name=='capture_debug':
            key=ctypes.c_uint(0);value=ctypes.create_string_buffer(words[3])
            assert bpf.bpf_map_lookup_elem(fd,ctypes.byref(key),value)==0
            row['counts']=list(struct.unpack('=16Q',value.raw))
        rows.append(row);os.close(fd)
    print('CAPTURE_INVENTORY '+json.dumps({'maps':rows,'optmem_max':Path('/proc/sys/net/core/optmem_max').read_text().strip()}),flush=True)


def probe_failed_root(matrix):
    matrix.probe('fail-closed-selected',a,'BLOCK')
    matrix.probe('fail-closed-unrelated','/usr/bin/binding-unknown','BLOCK')


def probe_full(matrix):
    for kind in [socket.SOCK_DGRAM,socket.SOCK_STREAM]:
        matrix.run_case('all256-last-rule',a,'VPN',socket.AF_INET,kind)
        matrix.run_case('all256-first-rule',a,'VPN',socket.AF_INET,kind,outside=True)
    os.rename(a,a+'-old');os.link(b,a)
    for kind in [socket.SOCK_DGRAM,socket.SOCK_STREAM]:matrix.run_case('all256-negative-last',a,'BLOCK',socket.AF_INET,kind)


def probe_leads(matrix):
    matrix.probe('selected-script-shebang','/usr/bin/selected-script','VPN')
    matrix.probe('self-exec-launcher','/usr/bin/selected-launcher','VPN')
    try:
        matrix.probe('real-appimage','/usr/bin/selected.AppImage','VPN')
    except subprocess.CalledProcessError as error:
        row={'case':'real-appimage-launch-error','pass':False,'output':error.output,'exit':error.returncode}
        matrix.checks.append(row);print('APPIMAGE_LAUNCH_ERROR '+json.dumps(row),flush=True)
    matrix.probe('ordinary-interpreter','/usr/bin/python3','SYSTEM')


def probe_modeled_history(matrix):
    matrix.probe('MODELED_HISTORY-b-added-to-selector-a',b,'VPN')
    matrix.probe('MODELED_HISTORY-a-original',a,'VPN')
    os.rename(a,a+'-old');os.link(b,a)
    matrix.probe('MODELED_HISTORY-positive-a-cannot-hide-link-negative',a,'BLOCK')


def probe_not_ready(matrix):
    matrix.probe('profile-not-ready',a,'BLOCK')
    matrix.probe('unrelated-still-system','/usr/bin/binding-unknown','SYSTEM')


def probe_precedence(matrix):
    matrix.probe('explicit-self-before-parent',a,'SYSTEM',ancestor=True)
    matrix.probe('selected-parent-direct',a,'VPN')


def probe_boundary(matrix):
    lab.ANCESTOR="import subprocess,sys,os\nsubprocess.run(['/usr/bin/binding-unknown','-c',sys.argv[1],*sys.argv[2:]],check=True,preexec_fn=lambda:os.setuid(1000))\n"
    matrix.probe('owner-boundary',a,'SYSTEM',ancestor=True,uid=0)
    matrix.probe('machine-direct',a,'VPN',uid=0)


def probe_loopback(matrix):
    for family in [socket.AF_INET,socket.AF_INET6]:
        for kind in [socket.SOCK_DGRAM,socket.SOCK_STREAM]:
            address='127.0.0.1' if family==socket.AF_INET else '::1'
            listener=socket.socket(family,kind);listener.bind((address,9999))
            if kind==socket.SOCK_STREAM:listener.listen()
            def echo():
                if kind==socket.SOCK_DGRAM:
                    data,peer=listener.recvfrom(2048);listener.sendto(data,peer)
                else:
                    connection,_=listener.accept()
                    with connection:connection.sendall(connection.recv(2048))
            worker=threading.Thread(target=echo,daemon=True);worker.start()
            output=lab.command([a,'-c',lab.CLIENT,'loopback',address,str(family),str(kind),str(24500+family+kind)],preexec_fn=lab.identity(1000,False),timeout=5)
            row={'case':'loopback','family':family,'kind':kind,'client':json.loads(output)};row['pass']=row['client']['echo'];matrix.checks.append(row)
            worker.join(timeout=2);listener.close()
            print('SNAPSHOT_LOOPBACK '+json.dumps(row),flush=True)


def probe_machine(matrix):
    matrix.probe('machine-overrides-uid',a,'BLOCK')
    matrix.probe('machine-unrelated',b,'SYSTEM')


def probe_basic(matrix):
    matrix.probe('u1-selector-a',a,'VPN')
    matrix.probe('u1-hardlink-h',h,'VPN')
    matrix.probe('u2-selector-h',h,'BLOCK',uid=1001)
    matrix.probe('u2-hardlink-a',a,'BLOCK',uid=1001)
    matrix.probe('unrelated-program','/usr/bin/binding-unknown','SYSTEM')
    matrix.probe('outside-cidr',a,'SYSTEM',outside=True)
    matrix.probe('direct-known-b',b,'SYSTEM')
    matrix.probe('known-b-own-selector',b,'VPN',outside=True)
    matrix.probe('inherited-a',a,'VPN',ancestor=True)
    matrix.probe('no-inherit-h',h,'SYSTEM',ancestor=True,uid=1001)
    matrix.probe('mount-replacement',a,'BLOCK',bind=True)
    matrix.probe('mount-other-owner',a,'SYSTEM',bind=True,uid=1002)
    matrix.probe('replacement-other-cidr',a,'VPN',bind=True,outside=True)
    os.rename(a,a+'-old');os.link(b,a)
    matrix.probe('known-b-replaces-a-fixed-root',a,'BLOCK')
    matrix.probe('replacement-other-owner',a,'SYSTEM',uid=1002)
    matrix.probe('replacement-b-positive-cidr',a,'VPN',outside=True)
    matrix.probe('replacement-ancestor',a,'BLOCK',ancestor=True)


def probe_capture(matrix):
    complete=os.environ.get('CAPTURE_MASK')=='3'
    matrix.probe('CAPTURE_FAULT_INJECTED-known-b',b,'SYSTEM' if complete else 'BLOCK')
    matrix.probe('CAPTURE_FAULT_INJECTED-known-parent-b',b,'SYSTEM' if complete else 'BLOCK',ancestor=True)
    matrix.probe('CAPTURE_FAULT_INJECTED-other-owner',b,'SYSTEM',uid=1002)
    matrix.probe('CAPTURE_FAULT_INJECTED-no-inherited-cidr',b,'SYSTEM',ancestor=True,outside=True)
    matrix.probe('complete-selected-a-control',a,'VPN')
    matrix.probe('complete-unrelated-control','/usr/bin/binding-unknown','SYSTEM')
    matrix.probe('CAPTURE_FAULT_INJECTED-bind-replacement',a,'BLOCK',bind=True)


PROBES={'capture':probe_capture,'capture-owner':probe_capture,'modeled-owner-precedence':probe_machine,'failed-root':probe_failed_root,'full':probe_full,'leads':probe_leads,'modeled-history':probe_modeled_history,'not-ready':probe_not_ready,'precedence':probe_precedence,'boundary':probe_boundary,'loopback':probe_loopback,'machine':probe_machine}

def variant_not_ready():
    return os.environ.get('SNAPSHOT_VARIANT')=='not-ready'


def run():
    lab.require_guest()
    assert 'aivpn.binding-snapshot=1' in Path('/proc/cmdline').read_text().split()
    lab.prepare_network()
    import shutil
    shutil.copyfile('/usr/bin/binding-a','/usr/bin/binding-link')
    os.chmod('/usr/bin/binding-link',0o755)
    lab.command(['mount','--bind','/usr/bin/binding-a','/usr/bin/binding-link'])
    os.symlink('/usr/bin/binding-a','/usr/bin/selected-link')
    Path('/usr/bin/selected-script').write_text('#!/usr/bin/python3\nimport sys\nsource=sys.argv[2]\nsys.argv=[sys.argv[0],*sys.argv[3:]]\nexec(source)\n')
    os.chmod('/usr/bin/selected-script',0o755)
    variant=os.environ.get('SNAPSHOT_VARIANT','basic')
    if variant.startswith('exec-'):
        import exec_probe
        exec_probe.prepare(variant)
    server = subprocess.Popen(['ip','netns','exec','binding-peer','python3','/lab/binding_probe.py','--server'], stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    assert server.stdout.readline().strip() == 'ENDPOINT_READY'
    echoes = []
    def read():
        for line in server.stdout:
            echoes.append(json.loads(line))
    reader = threading.Thread(target=read,daemon=True)
    reader.start()
    capture = lab.Capture()
    if variant in ['exec-resources','exec-resource-inspect']:exec_probe.resource_begin()
    legacy=os.environ.get('CAPTURE_LEGACY')=='1'
    child='legacy_capture_writer_child' if legacy else 'snapshot_writer_child'
    loader = subprocess.Popen([os.environ['AIVPN_BINDING_FIXTURE'],'--ignored','--exact',child,'--nocapture'],env={**os.environ,'AIVPN_SNAPSHOT_CHILD':'1'},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    while True:
        line = loader.stdout.readline()
        print('FIXTURE '+line.rstrip(),flush=True)
        if line.startswith('BINDING_READY ' if legacy else 'SNAPSHOT_READY '):
            metadata=json.loads(line.split(' ',1)[1]);break
        assert line,'Ошибка Snapshot writer'
    try:
        maps=lab.Maps(metadata)
    except OSError:
        capture_diagnostics(metadata)
        raise
    capture_diagnostics(metadata)
    if variant_not_ready():
        raw=ctypes.create_string_buffer(64);key=ctypes.c_uint(metadata['profile'])
        assert maps.bpf.bpf_map_lookup_elem(maps.fds['profiles'],ctypes.byref(key),raw)==0
        value=bytearray(raw.raw);value[4:12]=bytes(8);maps.update('profiles',struct.pack('=I',metadata['profile']),bytes(value))
    lab.firewall(metadata['pins'])
    if legacy:
        loader.stdin.write('inherit\n');loader.stdin.flush()
        assert loader.stdout.readline().strip()=='PUBLISHED'
    matrix=lab.Matrix(capture,echoes,captured_bootstrap=os.environ.get('CAPTURE_FIXTURE_BOOTSTRAP')=='1')
    matrix.metadata=metadata
    matrix.endpoint_process=server
    variant=os.environ.get('SNAPSHOT_VARIANT','basic')
    if variant.startswith('exec-'):
        exec_probe.run(variant,matrix)
    elif variant.startswith('malformed-') or variant=='missing-root':
        probe_failed_root(matrix)
    else:
        PROBES.get(variant,probe_basic)(matrix)
    maps.close()
    lab.firewall(metadata['pins'],remove=True)
    loader.stdin.write('cleanup\n');loader.stdin.flush()
    output=loader.communicate(timeout=20)[0];print(output,flush=True)
    assert loader.returncode==0 and ('BINDING_CLEANED' if legacy else 'SNAPSHOT_CLEANED') in output
    server.terminate();server.wait(timeout=5);reader.join(timeout=2)
    capture.close()
    lab.command(['ip','netns','del','binding-peer'])
    lab.command(['umount','/usr/bin/binding-link'])
    if legacy:
        assert not Path('/sys/fs/bpf/aivpn_app_retainers/73737373737373737373737373737373').exists()
        assert not Path('/lab/binding-state').exists()
    cleanup={'pins_absent':not Path(metadata['pins']).exists(),'retentions_absent':not Path('/sys/fs/bpf/aivpn_app_group_retainers/75757575757575757575757575757575').exists(),'state_absent':not Path('/lab/snapshot-state').exists()}
    if variant in ['exec-resources','exec-resource-inspect']:exec_probe.resource_end()
    print('SNAPSHOT_SUMMARY '+json.dumps({'metadata':metadata,'checks':matrix.checks,'cleanup':cleanup}),flush=True)
    assert all(cleanup.values())
    assert all(row['pass'] for row in matrix.checks),'Неверный маршрут фиксированного Snapshot'

if __name__=='__main__':
    if os.environ.get('CAPTURE_TRACE')=='1':
        import trace
        tracer=trace.Trace(count=True,trace=False)
        try:tracer.runfunc(run)
        finally:
            rows=[(Path(path).name,line,hits) for (path,line),hits in tracer.results().counts.items() if Path(path).name in ['exec_probe.py','snapshot_probe.py','binding_probe.py']]
            print('EXEC_TRACE '+json.dumps(rows),flush=True)
    else:run()
