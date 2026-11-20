"""Конечные exec/fork сценарии, только после установки capture в no-NIC guest."""
import json
import os
import ctypes
import struct
import subprocess
import time
import shutil
import socket
from pathlib import Path
import binding_probe as lab

A='/usr/bin/binding-a'
B='/usr/bin/binding-b'
U='/usr/bin/binding-unknown'
PY='/usr/bin/python3'
SCRIPT='/usr/bin/selected-script'
LAUNCH='/usr/bin/selected-launcher'
APP='/usr/bin/selected.AppImage'


def rule(path,route,inherit=True):
    action={'route':route.lower()}
    if route=='VPN':action['profile']='@PROFILE@'
    return {'id':path.rsplit('/',1)[-1],'application':{'kind':'executable','path':path},
            'destination':None,'inherit_children':inherit,'action':action}


def any_rules(action):
    return [{'id':'any-'+str(i),'application':{'kind':'any'},'destination':cidr,'inherit_children':False,'action':{'route':action,**({'profile':'@PROFILE@'} if action=='vpn' else {})}} for i,cidr in enumerate(['192.0.2.0/24','2001:db8:2::/64'])]+[rule(A,'VPN')]


def prepare(variant):
    lab.require_guest()
    cidr=[{'id':'cidr-only','application':{'kind':'any'},'destination':None,'inherit_children':False,'action':{'route':'system'}}]
    rows={
        'exec-priority':[rule(SCRIPT,'VPN',False),rule(LAUNCH,'VPN'),rule(APP,'VPN'),rule(PY,'SYSTEM')],
        'exec-child-vpn':[rule(LAUNCH,'SYSTEM'),rule(PY,'VPN')],
        'exec-noinherit':[rule(A,'VPN',False),rule(SCRIPT,'VPN',False),rule(LAUNCH,'VPN',False),rule(APP,'VPN',False)],
        'exec-fault-cidr':cidr,'exec-overflow-cidr':cidr,'exec-overflow-noinherit':[rule(A,'VPN',False)],
    }.get(variant,[rule(A,'VPN'),rule(B,'SYSTEM')])
    if variant=='exec-lifetime':
        for name,body in [('enoexec','ordinary text\n'),('missing-interpreter','#!/does-not-exist\n')]:
            path='/usr/bin/exec-'+name;Path(path).write_text(body);os.chmod(path,0o755)
        rows.append(rule('/usr/bin/exec-missing-interpreter','VPN'))
    if variant=='exec-owner':
        shutil.copyfile(U,'/usr/bin/exec-setuid');os.chown('/usr/bin/exec-setuid',0,2000);os.chmod('/usr/bin/exec-setuid',0o6755)
    if variant.startswith('exec-fault-any-'):rows=any_rules(variant.rsplit('-',1)[-1])
    Path('/lab/exec-policy.json').write_text(json.dumps({'machine':variant in ['exec-owner','exec-overflow-owner','exec-fault-childrepair','exec-fault-rename'],'rules':rows}))


def client_script(matrix,case,path,expected,source,**kwargs):
    original=lab.CLIENT
    try:
        lab.CLIENT=source.replace('@CLIENT@',repr(original))
        matrix.probe(case,path,expected,**kwargs)
    finally:lab.CLIENT=original


def ancestor_script(matrix,case,path,expected,source,**kwargs):
    original=lab.ANCESTOR
    try:
        lab.ANCESTOR=source
        matrix.probe(case,path,expected,ancestor=True,**kwargs)
    finally:lab.ANCESTOR=original


def chain(matrix,case,depth,expected,leaf=U,nearest=None,uid=1000,leaf_owner=None):
    body='''import os,sys
n=int(sys.argv[1]);leaf=sys.argv[2];near=sys.argv[3];code=sys.argv[4];client=sys.argv[5];args=sys.argv[6:]
if n:
 pid=os.fork()
 if not pid:
  path=leaf if n==1 else (near if n==2 and near else '/usr/bin/binding-unknown')
  os.execv(path,[path,'-c',code,str(n-1),leaf,near,code,client,*args])
 _,status=os.waitpid(pid,0);os._exit(os.waitstatus_to_exitcode(status))
sys.argv=['-c',*args];exec(client)
'''
    if leaf_owner is not None:body=body.replace("sys.argv=['-c',*args];exec(client)","os.setuid("+str(leaf_owner)+");sys.argv=['-c',*args];exec(client)")
    source='import os,sys\ncode='+repr(body)+'\nos.execv(sys.executable,[sys.executable,"-c",code,'+repr(str(depth))+','+repr(leaf)+','+repr(nearest or '')+',code,@CLIENT@,*sys.argv[1:]])\n'
    # Исходный selected A уже является корнем; следующий same-inode exec не создает fork.
    client_script(matrix,case,A,expected,source,uid=uid)


def lifetime(matrix):
    source='''import os,sys
for path in ['/does-not-exist','/usr/bin/exec-enoexec','/usr/bin/exec-missing-interpreter']:
 try:os.execv(path,[path])
 except OSError:pass
os.execv('/usr/bin/python3',['/usr/bin/python3','-c',@CLIENT@,*sys.argv[1:]])
'''
    client_script(matrix,'failed-enoent-enoexec-interpreter-then-success',U,'SYSTEM',source)
    source='''import ctypes,os,sys
libc=ctypes.CDLL(None,use_errno=True);argv=(ctypes.c_char_p*2)(b'/usr/bin/binding-a',None);env=(ctypes.c_char_p*1)(None)
result=libc.syscall(322,-100,b'/usr/bin/binding-a',argv,env,0x10000)
if result!=0:raise RuntimeError('AT_EXECVE_CHECK unsupported errno='+str(ctypes.get_errno()))
exec(@CLIENT@)
'''
    client_script(matrix,'AT_EXECVE_CHECK-does-not-publish-selected-source',U,'SYSTEM',source)
    source='''import os,sys,threading,time
args=['/usr/bin/binding-unknown','-c',@CLIENT@,*sys.argv[1:]]
threading.Thread(target=lambda:os.execv(args[0],args)).start()
time.sleep(30)
'''
    client_script(matrix,'nonleader-thread-exec',A,'VPN',source)
    source='''import os,sys,time
pid=os.fork()
if pid:os._exit(0)
time.sleep(.04)
os.execv('/usr/bin/binding-unknown',['/usr/bin/binding-unknown','-c',sys.argv[1],*sys.argv[2:]])
'''
    ancestor_script(matrix,'parent-exit-reparent-keeps-snapshot',A,'VPN',source)
    source=source.replace('if pid:os._exit(0)',"if pid:os.execv('/usr/bin/binding-b',['/usr/bin/binding-b','-c','import os;os._exit(0)'])")
    ancestor_script(matrix,'parent-exec-keeps-snapshot',A,'VPN',source)
    client_script(matrix,'repeated-exec-without-fork',A,'VPN',"import os,sys\nos.execv('/usr/bin/selected-launcher',['/usr/bin/selected-launcher','-c',@CLIENT@,*sys.argv[1:]])\n")


def owner(matrix):
    source='''import os,sys,subprocess
code="import os,sys;os.setresuid(1000,0,0);os.setresuid(0,0,0);client=sys.argv[1];sys.argv=sys.argv[1:];exec(client)"
subprocess.run(['/usr/bin/binding-unknown','-c',code,sys.argv[1],*sys.argv[2:]],check=True)
'''
    # После двух переходов в child нет промежуточного socket или exec.
    ancestor_script(matrix,'uid-away-back-observed-before-socket',A,'SYSTEM',source,uid=0)
    source='''import os,sys,subprocess
code="import os,sys;os.setuid(1000);client=sys.argv[1];sys.argv=sys.argv[1:];exec(client)"
subprocess.run(['/usr/bin/binding-unknown','-c',code,sys.argv[1],*sys.argv[2:]],check=True)
'''
    ancestor_script(matrix,'different-uid-boundary',A,'SYSTEM',source,uid=0)
    matrix.probe('owner-known-self-vpn',A,'VPN',uid=0)
    matrix.probe('owner-known-self-system',B,'SYSTEM',uid=0)
    checked=lab.CLIENT.replace("'source':s.getsockname()","'source':s.getsockname(),'ruid':os.getuid(),'euid':os.geteuid(),'rgid':os.getgid(),'egid':os.getegid()")
    checked="import os\nassert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(1000,0,1000,2000)\n"+checked
    source="import os,sys\nos.execv('/usr/bin/exec-setuid',['/usr/bin/exec-setuid','-c',"+repr(checked)+",*sys.argv[1:]])\n"
    client_script(matrix,'setuid-exec-effective-ids-change-real-owner-stable',A,'VPN',source)


def sockets(matrix):
    continuation='''import os,socket,json,sys
s=socket.socket(fileno=int(sys.argv[1]));sys.argv=sys.argv[1:];s.settimeout(.5)
sent=False;echo=False;error=None
try:
 s.sendall(sys.argv[1].encode());sent=True;echo=s.recv(2048)==sys.argv[1].encode()
except OSError as e:error=str(e)
print(json.dumps({'sent':sent,'echo':echo,'error':error,'source':s.getsockname()}))
'''
    for before,after,expected in [(A,B,'VPN'),(B,A,'SYSTEM')]:
        source='''import os,sys,socket
family=int(sys.argv[3]);kind=int(sys.argv[4]);s=socket.socket(family,kind);s.settimeout(.5)
s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',int(sys.argv[5])));s.connect((sys.argv[2],9999))
s.sendall((sys.argv[1]+'-warmup').encode());assert s.recv(2048)==(sys.argv[1]+'-warmup').encode()
os.set_inheritable(s.fileno(),True)
os.execv(@AFTER@,[@AFTER@,'-c',@CONT@,str(s.fileno()),*sys.argv[1:]])
'''.replace('@AFTER@',repr(after)).replace('@CONT@',repr(continuation))
        client_script(matrix,'admitted-socket-across-exec-'+expected,before,expected,source)
        client_script(matrix,'new-socket-after-exec-'+expected,before,'SYSTEM' if expected=='VPN' else 'VPN',
                      'import os,sys\nos.execv('+repr(after)+',['+repr(after)+',"-c",@CLIENT@,*sys.argv[1:]])\n')
    receiver='''import array,socket,sys
control=socket.socket(fileno=int(sys.argv[1]));_,anc,_,_=control.recvmsg(1,socket.CMSG_SPACE(4))
fds=array.array('i');fds.frombytes(anc[0][2][:4]);sys.argv[1]=str(fds[0]);exec(@CONT@)
'''.replace('@CONT@',repr(continuation))
    source='''import array,os,socket,subprocess,sys
family=int(sys.argv[3]);kind=int(sys.argv[4]);s=socket.socket(family,kind);s.settimeout(.5)
s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',int(sys.argv[5])));s.connect((sys.argv[2],9999))
left,right=socket.socketpair();p=subprocess.Popen(['/usr/bin/binding-b','-c',@RECV@,str(right.fileno()),*sys.argv[1:]],pass_fds=[right.fileno()])
left.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[s.fileno()]))]);assert p.wait()==0
'''.replace('@RECV@',repr(receiver))
    client_script(matrix,'SCM_RIGHTS-keeps-creator-before-admission',A,'VPN',source)
    for family in [2,10]:
        source='''import os,sys,socket
s=socket.socket(int(sys.argv[3]),socket.SOCK_STREAM,262);s.settimeout(.5)
s.bind(('::' if int(sys.argv[3])==10 else '0.0.0.0',int(sys.argv[5])));s.connect((sys.argv[2],9999))
s.sendall((sys.argv[1]+'-warmup').encode());assert s.recv(2048)==(sys.argv[1]+'-warmup').encode()
os.set_inheritable(s.fileno(),True);os.execv('/usr/bin/binding-b',['/usr/bin/binding-b','-c',@CONT@,str(s.fileno()),*sys.argv[1:]])
'''.replace('@CONT@',repr(continuation))
        original=lab.CLIENT
        try:
            lab.CLIENT=source
            matrix.run_case('MPTCP-keeps-creator-across-exec',A,'VPN',family,1)
        finally:lab.CLIENT=original
    accepted(matrix)


def accepted(matrix):
    continuation='''import socket,sys,json
s=socket.socket(fileno=int(sys.argv[1]));label=sys.argv[2];peer=json.loads(sys.argv[3]);kind=int(sys.argv[4]);s.settimeout(1)
if kind==2:s.sendto(label.encode(),tuple(peer))
else:s.sendall(label.encode())
assert s.recv(2048)==b'ACK'
print(json.dumps({'sent':True,'echo':True,'source':s.getsockname()}))
'''
    server='''import os,socket,sys,json
family=int(sys.argv[1]);kind=int(sys.argv[2]);protocol=int(sys.argv[3]);label=sys.argv[4]
s=socket.socket(family,kind,protocol);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('::' if family==10 else '0.0.0.0',9999));s.settimeout(2)
if kind==1:s.listen()
print('READY',flush=True)
if kind==1:s,peer=s.accept();assert s.recv(2048)==b'HELLO'
else:data,peer=s.recvfrom(2048);assert data==b'HELLO'
os.set_inheritable(s.fileno(),True)
os.execv('/usr/bin/binding-a',['/usr/bin/binding-a','-c',@CONT@,str(s.fileno()),label,json.dumps(peer),str(kind)])
'''.replace('@CONT@',repr(continuation))
    peer='''import socket,sys,json
s=socket.socket(int(sys.argv[1]),int(sys.argv[2]));s.settimeout(2);s.bind((sys.argv[3],int(sys.argv[5])))
s.connect((sys.argv[4],9999));s.sendall(b'HELLO');data=s.recv(2048);s.sendall(b'ACK')
print(json.dumps({'label':data.decode(),'peer':s.getpeername()[0],'port':s.getsockname()[1]}))
'''
    for family in [2,10]:
        for kind,protocol in [(2,0),(1,0),(1,262)]:
            accepted_case(matrix,family,kind,protocol,server,peer)


def accepted_evidence(outgoing,endpoint,label,local,result):
    return bool(outgoing) and {p['interface'] for p in outgoing}=={'wan0'} and {p['source'] for p in outgoing}=={local} and endpoint['label']==label and result['echo']


def accepted_case(matrix,family,kind,protocol,server,peer):
    case='accepted-'+{(2,0):'UDP',(1,0):'TCP',(1,262):'MPTCP'}[(kind,protocol)]+'-across-exec'
    port=24000+len(matrix.checks);label=f'{case}-{family}'
    process=subprocess.Popen([B,'-c',server,str(family),str(kind),str(protocol),label],preexec_fn=lab.identity(1000,False),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert process.stdout.readline().strip()=='READY'
    remote='2001:db8:53::53' if family==10 else '198.18.0.53';local='2001:db8:2::2' if family==10 else '192.0.2.2'
    endpoint=json.loads(lab.command(['ip','netns','exec','binding-peer',PY,'-c',peer,str(family),str(kind),remote,local,str(port)],timeout=5))
    output,error=process.communicate(timeout=5);assert process.returncode==0,error
    result=json.loads(output);time.sleep(.1)
    seen=[p for p in matrix.capture.events if port in [p['source_port'],p['destination_port']]]
    outgoing=[p for p in seen if p['source_port']==9999 and p['packet_type']==4]
    passed=accepted_evidence(outgoing,endpoint,label,local,result)
    if kind==1:assert outgoing[0]['tcp_flags']==18,'Нужен первый SYN ACK принятого соединения'
    row={'case':case,'family':family,'kind':kind,'protocol':protocol,'expected':'SYSTEM','actual':'SYSTEM' if passed else 'FAIL','pass':passed,'client':result,'endpoint':endpoint,'packets':seen}
    matrix.checks.append(row);print('BINDING_CASE '+json.dumps(row),flush=True)

def fault_config(matrix,kind,path=None,uid=1000):
    bpf=ctypes.CDLL('libbpf.so.1',use_errno=True)
    fd=bpf.bpf_obj_get((matrix.metadata['pins']+'/maps/capture_fault').encode())
    assert fd>=0,'Нужен явно собранный private fault overlay'
    zero=ctypes.c_uint(0);previous=ctypes.create_string_buffer(32)
    assert bpf.bpf_map_lookup_elem(fd,ctypes.byref(zero),previous)==0
    old=struct.unpack('=IIQQII',previous.raw)
    if old[0]:
        print('PRIVATE_FAULT_HITS '+json.dumps({'kind':old[0],'uid':old[1],'file':old[2],'exec':old[3],'hits':old[4]}),flush=True)
        assert old[4]>0,'Fault site не исполнялся'
    cookie=0
    if path:
        inode_map=bpf.bpf_obj_get((matrix.metadata['pins']+'/maps/inode_tokens').encode())
        file=os.open(path,os.O_RDONLY);key=ctypes.c_int(file);value=ctypes.c_uint64()
        assert bpf.bpf_map_lookup_elem(inode_map,ctypes.byref(key),ctypes.byref(value))==0
        cookie=value.value;os.close(file);os.close(inode_map)
    key=ctypes.c_uint(0);value=ctypes.create_string_buffer(struct.pack('=IIQQII',kind,uid,cookie,0,0,0))
    assert bpf.bpf_map_update_elem(fd,ctypes.byref(key),value,0)==0
    os.close(fd)


def faults(matrix,variant):
    if variant=='exec-fault-rename':return renamed_image(matrix)
    if variant=='exec-fault-childrepair':return child_repair(matrix)
    if variant=='exec-fault-sameinode':return same_inode_fault(matrix)
    if variant.startswith('exec-fault-any-'):return any_fault(matrix,variant)
    if variant in ['exec-fault-cidr','exec-fault-invalid','exec-fault-missing-rule']:return storage_policy_fault(matrix,variant)
    capture_faults(matrix)


def renamed_image(matrix):
    script='/usr/bin/unselected-interpreter-script'
    Path(script).write_text('#!'+A+'\nimport sys\nsys.argv=sys.argv[2:]\nexec(sys.argv[0])\n');os.chmod(script,0o755)
    os.rename(A,A+'-original');os.link(B,A)
    body="""import os,socket,sys,ctypes
s=socket.socket(int(sys.argv[3]),int(sys.argv[4]));s.bind(('::' if int(sys.argv[3])==10 else '0.0.0.0',int(sys.argv[5])))
os.rename('/usr/bin/binding-a','/usr/bin/renamed-interpreter')
bpf=ctypes.CDLL('libbpf.so.1');fd=bpf.bpf_obj_get((@PINS@+'/maps/capture_fault').encode());key=ctypes.c_uint(0);value=ctypes.create_string_buffer(32)
assert fd>=0 and bpf.bpf_map_lookup_elem(fd,ctypes.byref(key),value)==0
assert int.from_bytes(value.raw[24:28],'little')>0
value=ctypes.create_string_buffer(32);assert bpf.bpf_map_update_elem(fd,ctypes.byref(key),value,0)==0;os.close(fd)
@CLIENT@
""".replace('@PINS@',repr(matrix.metadata['pins'])).replace('@CLIENT@',lab.CLIENT.replace('s=socket.socket(family,kind)','s=s').replace("s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',int(sys.argv[5])))",''))
    original=lab.CLIENT
    try:
        for family in [2,10]:
            for kind in [2,1]:
                fault_config(matrix,12,A,uid=0);lab.CLIENT=body
                matrix.run_case('PRIVATE_FAULT-original-physical-negative-survives-rename',script,'BLOCK',family,kind,uid=0)
                os.rename('/usr/bin/renamed-interpreter',A)
    finally:lab.CLIENT=original
    os.unlink(A);os.rename(A+'-original',A)
    matrix.probe('PRIVATE_FAULT-rename-direct-system-control',B,'SYSTEM',uid=0)


def same_inode_fault(matrix):
    continuation=lab.CLIENT.replace('s=socket.socket(family,kind)','s=socket.socket(fileno=int(os.environ["CAPTURE_OLD_FD"]))').replace("s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',int(sys.argv[5])))",'')
    source='''import os,socket,sys
s=socket.socket(int(sys.argv[3]),int(sys.argv[4]));s.bind(('::' if int(sys.argv[3])==10 else '0.0.0.0',int(sys.argv[5])))
os.set_inheritable(s.fileno(),True);os.environ['CAPTURE_OLD_FD']=str(s.fileno())
os.execv('/usr/bin/binding-a',['/usr/bin/binding-a','-c',@CONT@,*sys.argv[1:]])
'''.replace('@CONT@',repr('import os\n'+continuation))
    original=lab.CLIENT
    try:
        for family in [2,10]:
            for kind in [2,1]:
                fault_config(matrix,10,A);lab.CLIENT=source
                matrix.run_case('PRIVATE_FAULT-same-inode-reexec-cannot-repair-old-socket',A,'BLOCK',family,kind)
                fault_config(matrix,10,A);lab.CLIENT="import os,sys\nos.execv('/usr/bin/binding-a',['/usr/bin/binding-a','-c',"+repr(original)+",*sys.argv[1:]])\n"
                matrix.run_case('PRIVATE_FAULT-same-inode-reexec-new-socket-complete',A,'VPN',family,kind)
    finally:lab.CLIENT=original
    fault_config(matrix,0);return


def any_fault(matrix,variant):
    action=variant.rsplit('-',1)[-1].upper();fault_config(matrix,1,A)
    for ancestor in [False,True]:
        matrix.probe('PRIVATE_FAULT-unknown-'+('parent' if ancestor else 'self')+'-earlyAny',A,action,prefix=True,ancestor=ancestor)
        matrix.probe('PRIVATE_FAULT-unknown-outside-earlyAny',A,'BLOCK',ancestor=ancestor)
    fault_config(matrix,0);return


def storage_policy_fault(matrix,variant):
    for kind in [3,4]:
        fault_config(matrix,kind)
        matrix.probe('PRIVATE_FAULT-storage-no-confirmed-app-'+str(kind),A,'SYSTEM' if variant=='exec-fault-cidr' else 'BLOCK')
    fault_config(matrix,0);return


def capture_faults(matrix):
    for kind in [1,2]:
        fault_config(matrix,kind,A)
        matrix.probe('PRIVATE_FAULT-source-or-scratch-'+str(kind),A,'BLOCK')
        matrix.probe('PRIVATE_FAULT-known-SYSTEM-control-'+str(kind),B,'SYSTEM')
        matrix.probe('PRIVATE_FAULT-other-owner-control-'+str(kind),A,'SYSTEM',uid=1002)
    for kind in [3,4]:
        fault_config(matrix,kind)
        matrix.probe('PRIVATE_FAULT-required-storage-ENOMEM-'+str(kind),A,'BLOCK',launch_errno=12)
        matrix.probe('PRIVATE_FAULT-unrelated-may-also-ENOMEM-'+str(kind),U,'BLOCK',launch_errno=12)
        matrix.probe('PRIVATE_FAULT-no-owner-policy-'+str(kind),A,'SYSTEM',uid=1002)
    for kind in [6,7,8,9]:
        fault_config(matrix,kind)
        for family in [2,10]:
            matrix.run_case('PRIVATE_FAULT-pair-publication-'+str(kind),A,'BLOCK',family,2)
    fault_config(matrix,0)
    matrix.probe('PRIVATE_FAULT-disabled-known-control',A,'VPN')


def child_repair(matrix):
    script='/usr/bin/original-image-script'
    Path(script).write_text('#!'+A+'\nimport sys\nsys.argv=sys.argv[2:]\nexec(sys.argv[0])\n');os.chmod(script,0o755)
    inspect="""import ctypes,os,socket,sys,struct
bpf=ctypes.CDLL('libbpf.so.1',use_errno=True)
def value(name,size,key):
 fd=bpf.bpf_obj_get((@PINS@+'/maps/'+name).encode());key=ctypes.c_int(key);data=ctypes.create_string_buffer(size)
 assert fd>=0 and bpf.bpf_map_lookup_elem(fd,ctypes.byref(key),data)==0
 os.close(fd);return data.raw
def task():
 fd=os.pidfd_open(os.getpid());data=value('processes',5952,fd);os.close(fd);return data
""".replace('@PINS@',repr(matrix.metadata['pins']))
    client="""s=socket.socket(int(sys.argv[3]),int(sys.argv[4]))
assert struct.unpack_from('=I',task(),84)[0]==3
assert struct.unpack_from('=I',value('socket_states',5968,s.fileno()),84)[0]==0
"""+lab.CLIENT.replace('s=socket.socket(family,kind)','s=s')
    source=inspect+"""before=task();pid=os.fork()
if not pid:
 exec(@CLIENT@);os._exit(0)
_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==0
assert task()==before
""".replace('@CLIENT@',repr(client.replace("'source':s.getsockname()","'source':s.getsockname(),'original_image_complete':True,'socket_copy_partial':True").replace("}))","}),flush=True)")))
    fault_config(matrix,11,A,uid=0)
    client_script(matrix,'PRIVATE_FAULT-child-socket-repair-from-original-image',script,'VPN',source,uid=0)
    fault_config(matrix,14,A,uid=0)
    matrix.probe('PRIVATE_FAULT-original-image-missing-stays-unknown',script,'BLOCK',uid=0)
    fault_config(matrix,0)


RESOURCE_GROUP=Path('/sys/fs/cgroup/exec-capture-measure')


def resource_sample(stage):
    stats={key:int(value) for key,value in (line.split() for line in (RESOURCE_GROUP/'memory.stat').read_text().splitlines())}
    row={'stage':stage,'kernel':stats['kernel'],'slab':stats['slab'],'anon':stats['anon'],'file':stats['file'],
         'current':int((RESOURCE_GROUP/'memory.current').read_text()),'total_peak':int((RESOURCE_GROUP/'memory.peak').read_text()),'fds':len(list(Path('/proc/self/fd').iterdir()))}
    print('EXEC_RESOURCE '+json.dumps(row),flush=True);return row


def resource_begin():
    Path('/sys/fs/cgroup/cgroup.subtree_control').write_text('+memory')
    RESOURCE_GROUP.mkdir();(RESOURCE_GROUP/'memory.max').write_text(str(1024**3));(RESOURCE_GROUP/'cgroup.procs').write_text(str(os.getpid()))
    time.sleep(2.2)
    resource_sample('before-load')


def resources(matrix):
    resource_sample('after-load')
    matrix.run_case('resource-nd-actors-warmup',A,'VPN',10,2)
    baseline=json.loads(lab.command(['/usr/bin/exec-reap',matrix.metadata['pins']]))
    print('EXEC_REAP_BASELINE '+json.dumps(baseline),flush=True)
    if os.environ.get('SNAPSHOT_VARIANT')=='exec-resource-inspect':
        matrix.probe('resource-control-inspect',A,'VPN')
        matrix.endpoint_process.terminate();matrix.endpoint_process.wait(timeout=5)
        print('EXEC_REAP_NEW_CONTROLS '+lab.command(['/usr/bin/exec-reap',matrix.metadata['pins']]).strip(),flush=True)
        print('EXEC_CONTROL_FRAMES '+json.dumps([p for p in matrix.capture.events if p['protocol']==58]),flush=True)
        return
    protocols=[(2,2),(2,1),(10,2),(10,1)]
    for i in range(100):
        family,kind=protocols[i%4]
        matrix.run_case('sequential-chain-'+str(i),A,'VPN',family,kind,ancestor=True)
        if i%25==24:resource_sample('sequential-'+str(i+1))
    concurrent_resources(matrix,protocols)
    resource_sample('after-exit-reap-processes')
    matrix.endpoint_process.terminate();matrix.endpoint_process.wait(timeout=5)
    print('EXEC_REAP '+lab.command(['/usr/bin/exec-reap',matrix.metadata['pins']]).strip(),flush=True)
    # Штатный TCP tuple TTL равен 120s. Не подменяем время или kernel callbacks.
    for _ in range(3):time.sleep(41)
    reaped=json.loads(lab.command(['/usr/bin/exec-reap',matrix.metadata['pins']]))
    print('EXEC_REAP '+json.dumps(reaped),flush=True);assert reaped['remaining_client_flows']==0
    resource_controls(matrix,baseline,reaped)
    samples=[]
    for i in range(4):
        time.sleep(2.2);samples.append(resource_sample('post-reap-plateau-'+str(i)))
    assert len({row['fds'] for row in samples})==1
    assert max(row['kernel'] for row in samples)-min(row['kernel'] for row in samples)<=2*1024**2


def resource_controls(matrix,baseline,reaped):
    cookies=set(baseline['kernel_icmp6_control_cookies'])
    assert len(cookies)==2,cookies
    assert set(reaped['kernel_icmp6_control_cookies'])<=cookies
    frames=[p for p in matrix.capture.events if p['protocol']==58 and p['icmp_type'] in [133,135,136]]
    destinations={socket.inet_pton(socket.AF_INET6,p['destination']).hex() for p in frames}
    retained=reaped['routing_system']['retained_keys']
    assert len(retained)<=16
    for key in retained:
        assert key['cookie'] in cookies and key['family']==6 and key['protocol']==58 and key['port']==0,key
        assert key['destination'] in destinations,key
    print('EXEC_CONTROL_PROOF '+json.dumps({'warmup_cookies':sorted(cookies),'retained':retained,'frames':frames}),flush=True)


def concurrent_resources(matrix,protocols):
    pending=[]
    for i in range(32):
        family,kind=protocols[i%4];port=24000+len(matrix.checks)+i;label='concurrent-chain-'+str(i)
        target='2001:db8:53::53' if family==10 else '198.18.0.53'
        process=subprocess.Popen([A,'-c',lab.ANCESTOR,lab.CLIENT,label,target,str(family),str(kind),str(port)],preexec_fn=lab.identity(1000,False),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        pending.append((process,family,kind,port,label))
    resource_sample('concurrent-32-started')
    for process,family,kind,port,label in pending:
        output,error=process.communicate(timeout=10);assert process.returncode==0,error
        result=json.loads(output);time.sleep(.02);seen,outgoing,reply=matrix.observations(port,label)
        actual=matrix.decision(result,outgoing,reply,family)
        if kind==1:assert outgoing[0]['tcp_flags']==2
        row={'case':label,'family':family,'kind':kind,'expected':'VPN','actual':actual,'pass':actual=='VPN','client':result,'endpoint':reply,'packets':seen}
        matrix.checks.append(row);print('BINDING_CASE '+json.dumps(row),flush=True)


def resource_end():
    time.sleep(2.2);resource_sample('after-owned-image-cleanup')
    Path('/sys/fs/cgroup/cgroup.procs').write_text(str(os.getpid()));RESOURCE_GROUP.rmdir()
    print('EXEC_RESOURCE_CGROUP_REMOVED',flush=True)


def priority(matrix):
    matrix.probe('source-script-before-explicit-interpreter',SCRIPT,'VPN')
    matrix.probe('launcher-vpn-explicit-child-system',LAUNCH,'SYSTEM')
    matrix.probe('AppImage-explicit-payload-system',APP,'SYSTEM')


def noinherit(matrix):
    matrix.probe('shebang-same-attempt-inherit-false',SCRIPT,'VPN')
    matrix.probe('samepid-exec-inherit-false',LAUNCH,'SYSTEM')
    matrix.probe('fork-exec-inherit-false',A,'SYSTEM',ancestor=True)
    matrix.probe('AppImage-payload-inherit-false',APP,'SYSTEM')


def history(matrix):
    for depth in [3,32,33]:chain(matrix,f'ordinary-fork-exec-depth-{depth}',depth,'VPN' if depth<=32 else 'BLOCK')
    chain(matrix,'overflow-known-self-vpn',33,'VPN',leaf=A)
    chain(matrix,'overflow-known-self-system',33,'SYSTEM',leaf=B)
    chain(matrix,'overflow-nearest-vpn',33,'VPN',nearest=A)
    chain(matrix,'overflow-nearest-system',33,'SYSTEM',nearest=B)
    chain(matrix,'nearest-system-before-farther-vpn',3,'SYSTEM',nearest=B)


def run(variant,matrix):
    handlers={'exec-priority':priority,'exec-child-vpn':lambda m:m.probe('launcher-system-explicit-child-vpn',LAUNCH,'VPN'),
        'exec-noinherit':noinherit,'exec-history':history,'exec-lifetime':lifetime,'exec-owner':owner,'exec-sockets':sockets,
        'exec-resources':resources,'exec-resource-inspect':resources,
        'exec-overflow-cidr':lambda m:chain(m,variant,33,'SYSTEM'),'exec-overflow-noinherit':lambda m:chain(m,variant,33,'SYSTEM'),
        'exec-overflow-owner':lambda m:chain(m,variant,33,'SYSTEM',uid=0,leaf_owner=1000)}
    if variant.startswith('exec-fault'):faults(matrix,variant)
    else:handlers[variant](matrix)
