"""Настоящий Control/backend/worker в собственном no-NIC guest."""
import os,json,socket,subprocess,threading,time,shutil
from pathlib import Path
import vertical_probe as v
lab=v.lab

def run():
    server,server_log,endpoint,echoes,reader,capture=v.prepare_environment()
    for family in ['-4','-6']:
        lab.command(['ip',family,'rule','del','pref','100','fwmark','0xa1','lookup','200'])
    service=subprocess.Popen(['/usr/bin/vertical-product'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    control=v.line_until(service,'PRODUCT_CONTROL ')
    restricted=v.line_until(service,'PRODUCT_RESTRICTED ')
    transport=v.line_until(service,'PRODUCT_TRANSPORT ')
    try:
        ready=v.line_until(service,'PRODUCT_READY ')
    except Exception:
        print('OUTER_DIAGNOSTIC '+json.dumps(capture.events[:16]),flush=True)
        capture.close()
        raise
    assert ready['status']=='guarded' and transport['kernel_registered']
    output=threading.Thread(target=lambda:[print('PRODUCT_LIVE '+line.rstrip(),flush=True) for line in service.stdout],daemon=True);output.start()
    rows=[]
    bootstrap='import os,sys\nos.setgroups([]);os.setgid(1000);os.setuid(1000);os.execv(sys.argv[1],sys.argv[1:])'
    for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
        for label,path,expected in [('selected','/usr/bin/binding-a','10.77.0.2'),('system','/usr/bin/binding-unknown','192.0.2.2')]:
            label=f'{label}-{kind}';start=time.monotonic()
            result=json.loads(lab.command(['/usr/bin/python3','-c',bootstrap,path,'-c',lab.CLIENT.replace('s.settimeout(.5)','s.settimeout(5)'),label,'198.18.0.53','2',str(kind),'0'],timeout=8))
            time.sleep(.1);observed=[entry for entry in echoes if entry['label']==label]
            row={'case':label,'result':result,'server_echo':observed,'seconds':time.monotonic()-start,'pass':result['echo'] and bool(observed) and all(entry['peer']==expected for entry in observed)}
            rows.append(row);print('VERTICAL_CASE '+json.dumps(row),flush=True)
    negative_code=lab.CLIENT.replace('9999','443')
    negative=json.loads(lab.command(['/usr/bin/python3','-c',bootstrap,'/usr/bin/binding-a','-c',negative_code,'same-peer','192.0.2.1','2','2','29991'],timeout=5))
    assert not negative['sent'] and not negative['echo'],negative
    assert not [event for event in capture.events if event.get('source_port')==29991 and event.get('destination_port')==443]
    ports={row['result']['source'][1] for row in rows if row['case'].startswith('selected')}
    forbidden=[event for event in capture.events if event['interface']=='wan0' and event.get('destination_port')==9999 and event.get('source_port') in ports]
    system_udp=next(row['result']['source'][1] for row in rows if row['case']=='system-2')
    assert any(event.get('source_port')==system_udp and event.get('destination_port')==9999 for event in capture.events)
    outer=[event for event in capture.events if event.get('outer')]
    print('VERTICAL_SUMMARY '+json.dumps({'pass':all(row['pass'] for row in rows) and bool(outer) and not forbidden,'rows':len(rows),'outer_packets':len(outer),'forbidden_selected':forbidden,'same_peer_denied':True,'status':ready['status'],'public_active':False,'publication':ready['publication']}),flush=True)
    service.terminate();service.wait(timeout=5)
    for _ in range(50):
        if not Path(f"/proc/{restricted['pid']}").exists():break
        time.sleep(.1)
    server.terminate();server.wait(timeout=5);server_log.close();endpoint.terminate();endpoint.wait(timeout=5);reader.join(timeout=2)
    capture.close()
    # Все удаления относятся к этому единственному namespace внутри уничтожаемого guest.
    for path in Path('/run').glob('vertical-*'):
        if path.is_dir():shutil.rmtree(path)
        else:path.unlink()
    for path in Path('/run').glob('aivpn-worker-*'):shutil.rmtree(path)
    assert not list(Path('/run').glob('vertical-*'))
    print('VERTICAL_CLEANED',flush=True)
    assert all(row['pass'] for row in rows) and outer and not forbidden

if __name__=='__main__':run()
