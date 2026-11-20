"""IPv6 обычного приложения через текущую службу и сервер в отдельном guest."""
import json,os,socket,subprocess,time
from pathlib import Path
import vertical_probe as v
import lifecycle_probe as l
from linux_multi_profile_probe import cli

def main():
    server,server_log,endpoint,echoes,reader,capture=v.prepare_environment(
        ['python3','/lab/dns_endpoint.py'], {'ipv6_enabled':True,'ipv6_prefix':'fd77:cafe::/64'})
    service=None;stream=None;listener=None
    original=b'nameserver 192.0.2.1\noptions timeout:1 attempts:1\n'
    try:
        home=Path('/home/cli-fixture');home.mkdir(mode=0o700,parents=True);os.chown(home,1000,1000)
        for family in ['-4','-6']:v.lab.command(['ip',family,'rule','del','pref','100','fwmark','0xa1','lookup','200'])
        Path('/etc/resolv.conf').unlink(missing_ok=True);Path('/etc/resolv.conf').write_bytes(original)
        Path('/etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
        Path('/var/lib/aivpn-app-routing').mkdir(mode=0o700)
        runtime=Path('/run/aivpn-app-routing');runtime.mkdir(mode=0o755)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(runtime/'control.sock'));os.chmod(runtime/'control.sock',0o666);listener.listen(32)
        fd=listener.fileno();stream=Path('/run/routing-service.log').open('wb')
        launch="import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3,inheritable=True); os.close(fd) if fd!=3 else None; os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1'); os.execve('/usr/libexec/aivpn/aivpn',['aivpn','__routing-service','--dns-provider','file','--dns-upstream','198.18.0.53:53'],os.environ)"
        service=subprocess.Popen(['/usr/bin/python3','-c',launch,str(fd)],pass_fds=(fd,),stdout=stream,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+25
        while True:
            if service.poll() is not None:raise RuntimeError('Service startup '+Path('/run/routing-service.log').read_text()[-2000:])
            try:cli(['status']);break
            except (AssertionError,subprocess.TimeoutExpired):
                if time.monotonic()>deadline:raise
                time.sleep(.1)
        profile=cli(['register','ipv6-cli'])['profile']
        cli(['dns','set',profile,'--acknowledge-outage'],uid=0)
        policy={'version':1,'id':'ipv6-app-split','generation':1,'platform':'linux','owner':{'kind':'linux_user','uid':1000},'default_action':{'route':'system'},'dns':{'kind':'shared_vpn','profile':profile,'acknowledge_outage':True},'rules':[{'id':'selected','application':{'kind':'executable','path':'/usr/bin/binding-a'},'destination':None,'inherit_children':True,'action':{'route':'vpn','profile':profile}}]}
        policy_file=Path('/run/ipv6-policy.json');policy_file.write_text(json.dumps(policy));policy_file.chmod(0o644)
        cli(['apply',str(policy_file)])
        connection=Path('/run/ipv6-connection.json');connection.write_bytes(Path('/run/vertical-connection.json').read_bytes());os.chown(connection,1000,1000);connection.chmod(0o600)
        def ready():
            deadline=time.monotonic()+20
            while True:
                record=next(p for p in cli(['profiles'])['profiles'] if p['id']==profile)
                if record['ready_ipv4'] and record['ready_ipv6']:return record
                assert service.poll() is None,'Service exited while assigning IPv6'
                if time.monotonic()>deadline:raise TimeoutError('Dual stack not ready '+Path('/run/routing-service.log').read_text()[-2000:])
                time.sleep(.05)
        cli(['start',profile,'--connection-file',str(connection)]);first=ready()
        assert first['ipv6']=='fd77:cafe::a4d:2',first
        rows=[]
        def probe(label,image,expected,family,kind):
            target='2001:db8:53::53' if family==socket.AF_INET6 else '198.18.0.53'
            proc=l.ordinary(image,v.lab.CLIENT.replace('s.settimeout(.5)','s.settimeout(2)'),[label,target,str(family),str(kind),'0'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            out,err=proc.communicate(timeout=5);assert proc.returncode==0,err
            result=json.loads(out);time.sleep(.05);seen=[row for row in echoes if row.get('label')==label]
            row={'case':label,'result':result,'server_echo':seen,'pass':result['echo'] and bool(seen) and all(record['peer']==expected for record in seen)}
            rows.append(row);print('VERTICAL_CASE '+json.dumps(row),flush=True);assert row['pass'],row
        for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
            probe('ipv6-selected-'+str(kind),'/usr/bin/binding-a',first['ipv6'],socket.AF_INET6,kind)
            probe('ipv6-system-'+str(kind),'/usr/bin/binding-b','2001:db8:2::2',socket.AF_INET6,kind)
        probe('ipv4-after-ipv6','/usr/bin/binding-a','10.77.0.2',socket.AF_INET,socket.SOCK_STREAM)
        cli(['stop',profile]);cli(['start',profile,'--connection-file',str(connection)]);second=ready();assert second['session_id']!=first['session_id']
        probe('ipv6-after-restart','/usr/bin/binding-a',second['ipv6'],socket.AF_INET6,socket.SOCK_DGRAM)
        cli(['stop',profile]);cli(['remove','--generation','1']);cli(['dns','clear'],uid=0)
        assert Path('/etc/resolv.conf').read_bytes()==original,'DNS not restored'
        service.terminate();service.wait(timeout=15);assert service.returncode==0
        print('VERTICAL_SUMMARY '+json.dumps({'pass':True,'dual_stack':True,'rows':len(rows),'native_cli':True,'ipv6_tcp_udp':True,'system_ipv6_preserved':True,'restart':True,'original_dns_restored':True,'public_active':False}),flush=True)
    finally:
        if service and service.poll() is None:
            service.terminate()
            try:service.wait(timeout=10)
            except subprocess.TimeoutExpired:service.kill();service.wait()
        if stream:stream.close()
        if Path('/run/routing-service.log').exists():print('SERVICE_LOG_TAIL '+json.dumps(Path('/run/routing-service.log').read_text()[-3500:]),flush=True)
        if listener:listener.close()
        server.terminate();server.wait(timeout=5);server_log.close();endpoint.terminate();endpoint.wait(timeout=5);reader.join(timeout=2);capture.close()
        print('VERTICAL_CLEANED',flush=True)

if __name__=='__main__':main()
