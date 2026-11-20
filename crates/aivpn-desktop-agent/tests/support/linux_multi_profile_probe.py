"""Два пользователя и два независимых профиля через штатные CLI, Control и worker."""
import base64,json,os,shutil,socket,struct,subprocess,time
from pathlib import Path
import vertical_probe as v
import lifecycle_probe as l

CTL=['/usr/libexec/aivpn/aivpn','app-routing']

def cli(arguments,uid=1000,success=True):
    result=subprocess.run([*CTL,*arguments],user=uid,group=uid,extra_groups=[],capture_output=True,text=True,timeout=15,env=os.environ|{'HOME':('/home/cli-fixture' if uid==1000 else '/home/cli-fixture-'+str(uid))})
    if success:
        assert result.returncode==0,{'operation':arguments[0],'code':result.returncode,'error':result.stderr[-1200:]}
        return json.loads(result.stdout)
    assert result.returncode!=0 and not result.stdout,{'operation':arguments[0],'code':result.returncode}
    return result.stderr

def main():
    server,server_log,endpoint,echoes,reader,capture=v.prepare_environment(['python3','/lab/dns_endpoint.py'])
    service=None;stream=None;listener=None
    original=b'nameserver 192.0.2.1\noptions timeout:1 attempts:1\n'
    try:
        server.terminate();server.wait(timeout=5)
        added=subprocess.run(['/usr/bin/aivpn-server','--config','/run/vertical-server.json','--add-client','vertical-second'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        import re
        match=re.search(rb'aivpn://([A-Za-z0-9_-]+)',added.stdout+added.stderr)
        assert match,'Missing private second connection'
        encoded=match[1];second=json.loads(base64.urlsafe_b64decode(encoded+b'='*(-len(encoded)%4)))
        second_file=Path('/run/second-connection.json');second_file.write_text(json.dumps(second));second_file.chmod(0o600);os.chown(second_file,1001,1001)
        expected_second=second['i'];del added,match,encoded,second
        assert expected_second!='10.77.0.2'
        server=subprocess.Popen(['ip','netns','exec','binding-peer','/usr/bin/aivpn-server','--config','/run/vertical-server.json'],stdout=server_log,stderr=subprocess.STDOUT)
        home=Path('/home/cli-fixture');home.mkdir(mode=0o700,parents=True);os.chown(home,1000,1000)
        second_home=Path('/home/cli-fixture-1001');second_home.mkdir(mode=0o700);os.chown(second_home,1001,1001)
        for family in ['-4','-6']:
            v.lab.command(['ip',family,'rule','del','pref','100','fwmark','0xa1','lookup','200'])
        Path('/etc/resolv.conf').unlink(missing_ok=True)
        Path('/etc/resolv.conf').write_bytes(original)
        Path('/etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
        root=Path('/var/lib/aivpn-app-routing');root.mkdir(mode=0o700)
        runtime=Path('/run/aivpn-app-routing');runtime.mkdir(mode=0o755)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind(str(runtime/'control.sock'));os.chmod(runtime/'control.sock',0o666);listener.listen(32)
        fd=listener.fileno()
        stream=Path('/run/routing-service.log').open('wb')
        launch="import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3,inheritable=True); os.close(fd) if fd!=3 else None; os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1'); os.execve('/usr/libexec/aivpn/aivpn',['aivpn','__routing-service','--dns-provider','file','--dns-upstream','198.18.0.53:53'],os.environ)"
        service=subprocess.Popen(['/usr/bin/python3','-c',launch,str(fd)],pass_fds=(fd,),stdout=stream,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+25
        while True:
            if service.poll() is not None:raise RuntimeError('Service startup '+Path('/run/routing-service.log').read_text()[-2000:])
            try:status=cli(['status']);break
            except (AssertionError,subprocess.TimeoutExpired):
                if time.monotonic()>deadline:raise
                time.sleep(.1)
        assert status['kind']=='status' and status['backend'] in ['guarded','protection_unverified'],status
        registered=cli(['register','ordinary-cli'])
        profile=registered['profile'];assert isinstance(profile,str)
        assert cli(['register','ordinary-cli'])['profile']==profile
        cli(['dns','set',profile,'--acknowledge-outage'],uid=0)
        policy={'version':1,'id':'cli-app-split','generation':1,'platform':'linux','owner':{'kind':'linux_user','uid':1000},
            'default_action':{'route':'system'},'dns':{'kind':'shared_vpn','profile':profile,'acknowledge_outage':True},
            'rules':[{'id':'selected','application':{'kind':'executable','path':'/usr/bin/binding-a'},'destination':None,'inherit_children':True,'action':{'route':'vpn','profile':profile}}]}
        policy_file=Path('/run/cli-policy.json');policy_file.write_text(json.dumps(policy));policy_file.chmod(0o644)
        cli(['check',str(policy_file)])
        cli(['apply',str(policy_file)])
        assert cli(['get'])['document']==policy
        connection=Path('/run/cli-connection.json');document=json.loads(Path('/run/vertical-connection.json').read_text());document['s']='bootstrap-vpn.lab.test:'+document['s'].rsplit(':',1)[1];connection.write_text(json.dumps(document));os.chown(connection,1000,1000);connection.chmod(0o600)
        profile2=cli(['register','second-owner'],uid=1001)['profile']
        policy2=json.loads(json.dumps(policy));policy2.update(id='cli-second-owner',owner={'kind':'linux_user','uid':1001})
        policy2['rules'][0].update(id='selected-second',application={'kind':'executable','path':'/usr/bin/binding-b'},action={'route':'vpn','profile':profile2})
        policy_file2=Path('/run/cli-policy2.json');policy_file2.write_text(json.dumps(policy2));policy_file2.chmod(0o644)
        cli(['apply',str(policy_file2)],uid=1001)
        cli(['start',profile,'--connection-file',str(connection)])
        def ready(user,ident):
            deadline=time.monotonic()+20
            while True:
                current=cli(['profiles'],uid=user)['profiles'];record=next(r for r in current if r['id']==ident)
                if record['ready_ipv4']:return record
                assert service.poll() is None,'Service exited while assigning profiles'
                if time.monotonic()>deadline:raise TimeoutError('Profile not ready '+Path('/run/routing-service.log').read_text()[-1600:])
                time.sleep(.05)
        first=ready(1000,profile)
        cli(['start',profile2,'--connection-file',str(second_file)],uid=1001)
        other=ready(1001,profile2)
        assert first['ipv4']!=other['ipv4'] and first['session_id']!=other['session_id']
        rows=[]
        def probe(label,uid,path,expected,kind=1):
            proc=l.ordinary(path,v.lab.CLIENT.replace('s.settimeout(.5)','s.settimeout(2)'),[label,'198.18.0.53','2',str(kind),'0'],uid=uid,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            out,err=proc.communicate(timeout=5);assert proc.returncode==0,err
            value=json.loads(out);time.sleep(.05);observed=[r for r in echoes if r.get('label')==label]
            row={'case':label,'result':value,'server_echo':observed,'pass':value['echo'] and bool(observed) and all(r['peer']==expected for r in observed)}
            rows.append(row);print('VERTICAL_CASE '+json.dumps(row),flush=True);assert row['pass'],row
        def dns(label,user=1000):
            baseline=len(echoes)
            code="import socket,json,sys; print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET)})))"
            proc=l.ordinary('/usr/bin/binding-a' if user==1000 else '/usr/bin/binding-b',code,[label+'.lab.test.'],uid=user,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            out,err=proc.communicate(timeout=6);assert proc.returncode==0,err
            assert json.loads(out)==['198.51.100.77'],out
            seen=[r for r in echoes[baseline:] if r.get('dns') and not r.get('bootstrap')]
            assert seen and all(r['peer']=='10.77.0.2' for r in seen),seen
        for kind in [1,2]:
            probe('first-'+str(kind),1000,'/usr/bin/binding-a','10.77.0.2',kind)
            probe('second-'+str(kind),1001,'/usr/bin/binding-b',expected_second,kind)
        probe('foreign-same-image',1001,'/usr/bin/binding-a','192.0.2.2')
        dns('two-profiles-first');dns('two-profiles-second',1001)
        denied=cli(['stop',profile2],uid=1000,success=False)
        assert 'NotFound' in denied or 'AccessDenied' in denied,denied
        cli(['stop',profile2],uid=1001)
        assert ready(1000,profile)['session_id']==first['session_id']
        probe('first-after-second-stop',1000,'/usr/bin/binding-a','10.77.0.2');dns('dns-after-other-stop')
        cli(['start',profile2,'--connection-file',str(second_file)],uid=1001);other2=ready(1001,profile2)
        assert other2['session_id']!=other['session_id']
        cli(['stop',profile])
        assert ready(1001,profile2)['session_id']==other2['session_id']
        probe('second-after-first-stop',1001,'/usr/bin/binding-b',expected_second)
        cli(['start',profile,'--connection-file',str(connection)]);first2=ready(1000,profile)
        assert first2['session_id']!=first['session_id']
        probe('first-restarted',1000,'/usr/bin/binding-a','10.77.0.2');dns('dns-after-selected-restart')
        for user,ident,ip in [(1000,profile,'10.77.0.2'),(1001,profile2,expected_second)]:
            statistics=json.loads(cli(['session',ident,'statistics'],uid=user)['output'])
            assert statistics['ip']==ip and statistics['received']>0 and statistics['sent']>0
        print('ADMIN_CASE '+json.dumps({'foreign_denied':True,'two_owners':True,'two_profiles':True,'separate_addresses':True,'other_stop_preserved_session':True}),flush=True)
        cli(['stop',profile2],uid=1001)
        cli(['remove','--generation','1'],uid=1001)
        cli(['stop',profile])
        assert not cli(['profiles'])['profiles'][0]['session_active']
        cli(['remove','--generation','1'])
        cli(['dns','clear'],uid=0)
        assert Path('/etc/resolv.conf').read_bytes()==original,'DNS not restored'
        service.terminate();service.wait(timeout=15);assert service.returncode==0
        print('VERTICAL_SUMMARY '+json.dumps({'pass':True,'rows':len(rows),'native_cli':True,'two_owners':True,'two_profiles':True,'both_tcp_udp':True,'per_profile_stop_restart':True,'common_dns_target_preserved':True,'original_dns_restored':True,'service_exit':0,'public_active':False}),flush=True)
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
