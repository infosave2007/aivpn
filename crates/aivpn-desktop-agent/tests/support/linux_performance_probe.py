"""Короткое чередующееся сравнение двух настоящих клиентских путей."""
import os,json,subprocess,signal,time,threading,queue,statistics,re,shutil
from pathlib import Path
import vertical_probe as v
import lifecycle_probe as life
lab=v.lab
ECHO='''import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('198.18.0.53',9999));s.listen()
def handle(c):
 with c:
  try:
   while data:=c.recv(65536):c.sendall(data)
  except ConnectionError:pass
print('ENDPOINT_READY',flush=True)
while True:
 c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
'''
BENCH='''import socket,time,json,math
s=socket.socket();s.settimeout(10);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);s.connect(('198.18.0.53',9999))
def exchange(data):
 s.sendall(data);got=bytearray()
 while len(got)<len(data):
  part=s.recv(len(data)-len(got));assert part;got.extend(part)
 assert got==data
for _ in range(4):exchange(b'warmup')
latencies=[]
for _ in range(32):
 start=time.perf_counter();exchange(b'L'*64);latencies.append((time.perf_counter()-start)*1000)
start=time.perf_counter();size=512*1024
for _ in range(size//32768):exchange(b'x'*32768)
elapsed=time.perf_counter()-start
print(json.dumps({'bytes':size,'seconds':elapsed,'mib_per_second':size/elapsed/1024/1024,'p95_ms':sorted(latencies)[math.ceil(len(latencies)*.95)-1]}),flush=True)
'''
def ticks(pids):
    return sum(sum(map(int,Path(f'/proc/{pid}/stat').read_text().split()[13:15])) for pid in pids)

def run():
    server,server_log,endpoint,echoes,reader,capture=v.prepare_environment(['/usr/bin/python3','-c',ECHO])
    for family in ['-4','-6']:lab.command(['ip',family,'rule','del','pref','100','fwmark','0xa1','lookup','200'])
    connection=json.loads(Path('/run/vertical-connection.json').read_text())
    v.private_json('/run/vertical-legacy.json',{'server_addr':connection['s'],'server_public_key':connection['k'],'server_signing_public_key':connection['sk'],'preshared_key':connection['p'],'network_config':connection['n'],'tun_name':'vertical-legacy','include_routes':['198.18.0.53/32'],'full_tunnel':False})
    del connection
    rows=[];current=None;legacy=None
    try:
        for round in range(2):
            for mode in ['product','legacy']:
                if mode=='product':
                    current=life.Service();current.ready();pids=[current.process.pid,current.restricted['pid']];lines=current.lines
                    command=lambda:life.ordinary('/usr/bin/binding-a',BENCH,[],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                else:
                    home=Path('/run/vertical-legacy-home');home.mkdir(mode=0o700,exist_ok=True)
                    legacy=subprocess.Popen(['/usr/bin/aivpn-client','--config','/run/vertical-legacy.json','--admin-listen','127.0.0.1:44391'],env={'HOME':str(home),'PATH':'/usr/bin:/bin','RUST_LOG':'info'},stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
                    lines=[];ready=queue.Queue()
                    def drain():
                        for line in legacy.stdout:
                            lines.append(line)
                            if line.startswith('AIVPN-STATUS connected'):ready.put(True)
                        ready.put(False)
                    thread=threading.Thread(target=drain,daemon=True);thread.start()
                    try:assert ready.get(timeout=25)
                    except Exception:
                        for line in lines[-35:]:print('LEGACY_DIAGNOSTIC '+re.sub(r'aivpn://\S+|[A-Za-z0-9+/=_-]{32,}','[REDACTED]',line.rstrip()),flush=True)
                        raise
                    pids=[legacy.pid];command=lambda:subprocess.Popen(['/usr/bin/python3','-c',BENCH],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                time.sleep(.3)
                before=ticks(pids);server_before=ticks([server.pid]);start=time.monotonic()
                process=command();out,err=process.communicate(timeout=25);assert process.returncode==0,err
                elapsed=time.monotonic()-start;cpu=ticks(pids)-before;server_cpu=ticks([server.pid])-server_before
                result=json.loads(out);mask=[line.split('Маска сеанса: ',1)[1].strip() for line in lines if 'Маска сеанса: ' in line];assert mask,mode
                row={'mode':mode,'round':round,'mask':mask[-1],'cpu_ticks':cpu,'server_cpu_ticks':server_cpu,'clock_ticks':os.sysconf('SC_CLK_TCK'),'window_seconds':elapsed,**result}
                row['cpu_ms_per_mib']=cpu/os.sysconf('SC_CLK_TCK')*1000/(row['bytes']/1024/1024)
                rows.append(row);print('PERFORMANCE_ROW '+json.dumps(row),flush=True)
                if current is not None:current.finish();current=None
                if legacy is not None:legacy.send_signal(signal.SIGINT);legacy.wait(timeout=8);thread.join(timeout=2);legacy=None;shutil.rmtree(home)
                time.sleep(.2)
        assert len(set(row['mask'] for row in rows))==1,rows
        totals={mode:{key:statistics.median(row[key] for row in rows if row['mode']==mode) for key in ['mib_per_second','p95_ms','cpu_ms_per_mib']} for mode in ['product','legacy']}
        print('PERFORMANCE_SUMMARY '+json.dumps({'same_mask':rows[0]['mask'],'bytes_per_run':512*1024,'order':[row['mode'] for row in rows],'medians':totals,'rows':rows,'debug_build':True,'short_sample':True,'pcap_first_packets':256}),flush=True)
        print('VERTICAL_SUMMARY '+json.dumps({'pass':True,'rows':4,'outer_packets':len([event for event in capture.events if event.get('outer')]),'performance':totals,'public_active':False}),flush=True)
    finally:
        if current is not None:current.finish()
        if legacy is not None:legacy.kill();legacy.wait(timeout=5)
        server.terminate();server.wait(timeout=5);server_log.close();endpoint.terminate();endpoint.wait(timeout=5);reader.join(timeout=2);capture.raw=capture.raw[:256];capture.close()
        for pattern in ['vertical-*','aivpn-worker-*']:
            for path in Path('/run').glob(pattern):
                if path.is_dir():shutil.rmtree(path)
                else:path.unlink()
        assert not list(Path('/run').glob('vertical-*'))
        print('VERTICAL_CLEANED',flush=True)

if __name__=='__main__':run()
