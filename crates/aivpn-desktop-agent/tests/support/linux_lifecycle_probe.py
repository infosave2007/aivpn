"""Рабочие отказы и восстановление реального Control в изолированном guest."""
import os,json,socket,signal,subprocess,threading,time,shutil,queue,ctypes,struct
from pathlib import Path
import vertical_probe as v
lab=v.lab
BOOTSTRAP='import os,sys\nos.setgroups([]);os.setgid(int(sys.argv[1]));os.setuid(int(sys.argv[1]));os.execv(sys.argv[2],sys.argv[2:])'

def ordinary(path,code,args,uid=1000,**kw):
    return subprocess.Popen(['/usr/bin/python3','-c',BOOTSTRAP,str(uid),path,'-c',code,*args],**kw)

def worker_dead(pid):
    status=Path(f'/proc/{pid}/stat')
    return not status.exists() or status.read_text().split()[2]=='Z'

def wait_dead(pid):
    end=time.monotonic()+6
    while time.monotonic()<end and not worker_dead(pid):time.sleep(.05)
    assert worker_dead(pid),pid

def start_incoming_system_udp(timeout=3):
    listener=ordinary('/usr/bin/binding-unknown','import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(float(sys.argv[1])); s.bind(("127.0.0.1",0)); print(s.getsockname()[1],flush=True); data,peer=s.recvfrom(128); s.sendto(data,peer)',[str(timeout)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        return listener,int(listener.stdout.readline())
    except BaseException:
        if listener.poll() is None:listener.kill();listener.wait(timeout=3)
        raise

def incoming_system_udp(preexisting=None):
    """Ответ UDP-слушателя, в том числе открытого до установки правил."""
    listener,port=preexisting if preexisting is not None else start_incoming_system_udp()
    client=None
    try:
        client=ordinary('/usr/bin/binding-unknown','import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"incoming-system",("127.0.0.1",int(sys.argv[1]))); assert s.recv(128)==b"incoming-system"',[str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        _,error=client.communicate(timeout=4);assert client.returncode==0,error
        _,error=listener.communicate(timeout=4);assert listener.returncode==0,error
        print('INCOMING_SYSTEM_UDP '+json.dumps({'reply':True,'preexisting':preexisting is not None}),flush=True)
    finally:
        for process in [client,listener]:
            if process is not None and process.poll() is None:process.kill();process.wait(timeout=3)

class Service:
    count=0
    core=None
    final=None
    last_publication=None
    def __init__(self):
        self.events=queue.Queue();self.lines=[]
        environment=os.environ.copy()
        if Service.count==0:environment['VERTICAL_FAIL_SPAWN']='1'
        Service.count+=1
        self.process=subprocess.Popen(['/usr/bin/vertical-product'],env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        def drain():
            for line in self.process.stdout:
                self.lines.append(line);print('LIFECYCLE_SERVICE '+line.rstrip(),flush=True)
                if line.startswith('PRODUCT_'):
                    parts=line.strip().split(' ',1);self.events.put((parts[0],json.loads(parts[1]) if len(parts)>1 else None))
            self.events.put(('EXIT',self.process.poll()))
        self.reader=threading.Thread(target=drain,daemon=True);self.reader.start()
        self.control=self.wait('PRODUCT_CONTROL')
        proof=installation_proof()
        if Service.core is None:Service.core,Service.final=proof['core'],proof['final']
        assert proof=={'core':Service.core,'final':Service.final}
        if Service.last_publication is not None:assert self.control['publication']==Service.last_publication
        print('INSTALLATION_REUSED '+json.dumps(proof),flush=True)
        if Service.count==1:assert self.wait('PRODUCT_SPAWN_REJECTED')=={'session_active':False,'ready_ipv4':False,'worker_homes':0}
        self.restricted=self.wait('PRODUCT_RESTRICTED')
    def wait(self,name,timeout=45):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            key,value=self.events.get(timeout=max(.01,end-time.monotonic()))
            if key==name:return value
            assert key!='EXIT',(name,value)
        raise TimeoutError(name)
    def ready(self):
        transport=self.wait('PRODUCT_TRANSPORT');ready=self.wait('PRODUCT_READY')
        assert ready['status']=='guarded' and not ready['public_active'] and transport['kernel_registered']
        Service.last_publication=ready['publication']
        return transport,ready
    def finish(self,worker=False):
        if worker:os.kill(self.restricted['pid'],signal.SIGKILL)
        else:self.process.kill()
        self.process.wait(timeout=8);self.reader.join(timeout=3);wait_dead(self.restricted['pid'])


def installation_proof():
    bpf=ctypes.CDLL('libbpf.so.1',use_errno=True);bpf.bpf_obj_get.argtypes=[ctypes.c_char_p]
    result={}
    for key,name in [('core','core_inventory'),('final','inventory')]:
        fd=bpf.bpf_obj_get(('/sys/fs/bpf/aivpn_app_routes/'+'76'*16+'/'+name).encode());assert fd>=0
        info=ctypes.create_string_buffer(512);length=ctypes.c_uint(512);assert bpf.bpf_obj_get_info_by_fd(fd,info,ctypes.byref(length))==0
        words=struct.unpack_from('=6I',info.raw);assert [words[0],*words[2:6]]==[2,4,32,1,0]
        zero=ctypes.c_uint(0);value=ctypes.create_string_buffer(32);assert bpf.bpf_map_lookup_elem(fd,ctypes.byref(zero),value)==0
        assert 'frozen:\t1' in Path(f'/proc/self/fdinfo/{fd}').read_text();result[key]=value.raw.hex();os.close(fd)
    return result


def cache_rows(name):
    bpf=ctypes.CDLL('libbpf.so.1',use_errno=True);bpf.bpf_obj_get.argtypes=[ctypes.c_char_p]
    fd=bpf.bpf_obj_get(('/sys/fs/bpf/aivpn_app_routes/'+'76'*16+'/maps/'+name).encode());assert fd>=0
    info=ctypes.create_string_buffer(512);size=ctypes.c_uint(512)
    assert bpf.bpf_obj_get_info_by_fd(fd,info,ctypes.byref(size))==0
    words=struct.unpack_from('=6I',info.raw);key_size=words[2];assert key_size in [40,64]
    previous=None;keys=[]
    for _ in range(2048):
        key=ctypes.create_string_buffer(key_size)
        result=bpf.bpf_map_get_next_key(fd,previous,key)
        if result:assert ctypes.get_errno()==2;break
        keys.append(key.raw);previous=key
    else:raise AssertionError('bounded cache inventory')
    os.close(fd);return keys


def run():
    server,server_log,endpoint,echoes,reader,capture=v.prepare_environment()
    for family in ['-4','-6']:lab.command(['ip',family,'rule','del','pref','100','fwmark','0xa1','lookup','200'])
    # Отдельный системный VPN и чужие младшие mark bits принадлежат fixture.
    lab.command(['ip','addr','add','192.0.3.2/24','dev','vpn0'])
    lab.command(['ip','-n','binding-peer','addr','add','192.0.3.1/24','dev','vpn_s'])
    lab.command(['ip','route','add','table','42002','default','via','192.0.3.1','dev','vpn0'])
    lab.command(['ip','rule','add','pref','200','uidrange','1000-1000','lookup','42002'])
    lab.command(['ip','rule','add','pref','199','fwmark','0x1234/0xffff','lookup','42002'])
    lab.command(['iptables-nft','-t','mangle','-A','OUTPUT','-m','owner','--uid-owner','1000','-j','MARK','--set-xmark','0x1234/0xffff'])
    lab.command(['nft','-f','-'],input='add table inet vertical_foreign\nadd chain inet vertical_foreign post { type filter hook postrouting priority 300; policy accept; }\nadd rule inet vertical_foreign post meta mark & 0xffff == 0x1234 counter comment "foreign_low_bits"\nadd rule inet vertical_foreign post meta mark & 0xffffffff == 0xa1011234 counter comment "selected_masked_mark"\n')
    rows=[];services=[];selected_ports=set();publications=[];cookies=[]
    def probe(label,selected=True,kind=2,expected='10.77.0.2',uid=1000,peer='198.18.0.53',port=0):
        code=lab.CLIENT.replace('s.settimeout(.5)','s.settimeout(2)')
        if peer=='192.0.2.1':code=code.replace('9999','443')
        process=ordinary('/usr/bin/binding-a' if selected else '/usr/bin/binding-unknown',code,[label,peer,'2',str(kind),str(port)],uid,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        out,err=process.communicate(timeout=5);assert process.returncode==0,err
        result=json.loads(out);time.sleep(.05)
        observed=[entry for entry in echoes if entry['label']==label]
        passed=(not result['echo'] and not observed) if expected is None else (result['echo'] and observed and all(entry['peer']==expected for entry in observed))
        row={'case':label,'result':result,'server_echo':observed,'pass':bool(passed)};rows.append(row)
        if selected and peer=='198.18.0.53':selected_ports.add(result['source'][1])
        print('VERTICAL_CASE '+json.dumps(row),flush=True)
        if not passed:
            print('FOREIGN_ROUTE '+lab.command(['ip','-j','route','get','198.18.0.53','uid',str(uid),'mark','0x1234']),flush=True)
            print('FOREIGN_FILTER '+lab.command(['iptables-nft','-t','mangle','-L','OUTPUT','-v','-n']),flush=True)
        assert passed,row
    def start():
        service=Service();services.append(service);transport,ready=service.ready();cookies.append(transport['cookie']);publications.append(ready['publication']);return service
    live=None
    preexisting=start_incoming_system_udp(timeout=30)
    try:
        first=start()
        incoming_system_udp(preexisting)
        for kind in [1,2]:
            probe('initial-selected-'+str(kind),kind=kind)
            probe('initial-system-'+str(kind),False,kind,'192.0.3.2')
        incoming_system_udp()
        for uid,port in [(1000,29991),(65532,29992)]:probe('same-peer-'+str(uid),expected=None,uid=uid,peer='192.0.2.1',port=port)
        live_code='''import socket,sys,json,struct
s=socket.socket();s.settimeout(3);s.connect(('198.18.0.53',9999))
print(json.dumps({'cookie':struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,57,8))[0],'port':s.getsockname()[1]}),flush=True)
for line in sys.stdin:
 data=line.strip().encode();s.sendall(data);print(json.dumps({'echo':s.recv(2048)==data}),flush=True)
'''
        live=ordinary('/usr/bin/binding-unknown',live_code,[],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        live_info=json.loads(live.stdout.readline())
        def ongoing(label):
            live.stdin.write(label+'\n');live.stdin.flush();assert json.loads(live.stdout.readline())['echo']
        ongoing('live-before-failures')
        time.sleep(1.5)
        before={'overrides':len(cache_rows('routing_overrides')),'system':len(cache_rows('routing_system')),'tuples':len(cache_rows('tcp_routes'))}
        assert live_info['cookie'] in [struct.unpack_from('=Q',key)[0] for key in cache_rows('routing_system')]
        first.finish(worker=True)
        for kind in [1,2]:probe('worker-dead-selected-'+str(kind),kind=kind,expected=None)
        probe('worker-dead-system',False,expected='192.0.3.2');ongoing('live-worker-dead')
        second=start();probe('worker-replacement');ongoing('live-worker-replaced')
        second.finish()
        for kind in [1,2]:probe('writer-dead-selected-'+str(kind),kind=kind,expected=None)
        probe('writer-dead-system',False,expected='192.0.3.2');ongoing('live-writer-dead')
        third=start();probe('writer-recovered');ongoing('live-writer-recovered');third.finish()
        server.terminate();server.wait(timeout=5)
        database=Path('/run/vertical-clients.json');content=json.loads(database.read_text());assert len(content['clients'])==1
        content['clients'][0]['vpn_ip']='10.77.0.3';database.write_text(json.dumps(content));os.chmod(database,0o600);del content
        fourth=Service();services.append(fourth)
        fourth.wait('PRODUCT_TRANSPORT');fourth.wait('PRODUCT_RECONNECTING',timeout=20)
        probe('server-down-selected',expected=None);probe('server-down-system',False,expected='192.0.3.2');ongoing('live-server-down')
        server=subprocess.Popen(['ip','netns','exec','binding-peer','/usr/bin/aivpn-server','--config','/run/vertical-server.json'],stdout=server_log,stderr=subprocess.STDOUT)
        transport,ready=fourth.ready();cookies.append(transport['cookie']);publications.append(ready['publication'])
        for kind in [1,2]:probe('assignment-changed-'+str(kind),kind=kind,expected='10.77.0.3')
        ongoing('live-assignment-changed')
        time.sleep(1.5);live.stdin.close();live.wait(timeout=5);live=None;time.sleep(1.5)
        after={'overrides':len(cache_rows('routing_overrides')),'system':len(cache_rows('routing_system')),'tuples':len(cache_rows('tcp_routes'))}
        assert live_info['cookie'] not in [struct.unpack_from('=Q',key)[0] for key in cache_rows('routing_system')]
        assert after['overrides']==0,after
        forbidden=[event for event in capture.events if event.get('destination_port')==9999 and event.get('source_port') in selected_ports and event['interface'] in ['wan0','vpn0']]
        assert not forbidden
        assert not [event for event in capture.events if event.get('destination_port')==443 and event.get('source_port') in [29991,29992]]
        assert len(set(cookies))==len(cookies)
        mark_state=json.loads(lab.command(['nft','-j','list','table','inet','vertical_foreign']))
        marked={row['rule']['comment']:next(expr['counter']['packets'] for expr in row['rule']['expr'] if 'counter' in expr) for row in mark_state['nftables'] if 'rule' in row}
        assert all(marked.get(name,0)>0 for name in ['foreign_low_bits','selected_masked_mark']),marked
        summary={'foreign_vpn_source':'192.0.3.2','preserved_mark_counters':marked,'pass':True,'rows':len(rows),'outer_packets':len([event for event in capture.events if event.get('outer')]),'forbidden_selected':forbidden,'same_peer_uids_denied':[1000,65532],'status':'guarded','public_active':False,'publications':publications,'transport_cookies':cookies,'live_system_survived':True,'cache_before':before,'cache_after':after,'core_unchanged':True,'final_attachments_unchanged':True,'exact_retry_reused_root':True,'spawn_failure_cleanup':True,'kernel_registration':True,'worker_kill':True,'writer_kill_reopen':True,'service_eof':True,'shared_backoff_reconnect':True,'assignment_changed':'10.77.0.3'}
        print('VERTICAL_SUMMARY '+json.dumps(summary),flush=True)
    finally:
        if preexisting[0].poll() is None:preexisting[0].kill();preexisting[0].wait(timeout=3)
        if live is not None:live.kill();live.wait(timeout=3)
        for service in services:
            if service.process.poll() is None:service.finish()
        if server.poll() is None:server.terminate();server.wait(timeout=5)
        server_log.close();endpoint.terminate();endpoint.wait(timeout=5);reader.join(timeout=2);capture.close()
        for pattern in ['vertical-*','aivpn-worker-*']:
            for path in Path('/run').glob(pattern):
                if path.is_dir():shutil.rmtree(path)
                else:path.unlink()
        assert not list(Path('/run').glob('vertical-*')) and not list(Path('/run').glob('aivpn-worker-*'))
        print('VERTICAL_CLEANED',flush=True)

if __name__=='__main__':run()
