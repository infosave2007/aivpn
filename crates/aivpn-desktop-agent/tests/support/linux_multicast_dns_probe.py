"""Один новый NSS-запрос через самостоятельный resolved и восстановление настроек."""
import base64,ctypes,hashlib,json,os,shutil,socket,struct,subprocess,time
from pathlib import Path
import vertical_probe as v
import lifecycle_probe as l

original_decode=v.OuterCapture.decode
def decode(data,meta):
    prior=original_decode(data,meta)
    if prior is not None:return prior
    if len(data)<42:return None
    if data[12:14]==b'\x08\x00':protocol,start=data[23],14+(data[14]&15)*4
    elif data[12:14]==b'\x86\xdd' and len(data)>=62:protocol,start=data[20],54
    else:return None
    if protocol!=17 or len(data)<start+8:return None
    sport,dport=struct.unpack_from('!HH',data,start)
    if dport not in [53,5353,5355]:return None
    payload=data[start+8:]
    return {'interface':meta[0],'packet_type':meta[2],'protocol':17,'family':4 if data[12:14]==b'\x08\x00' else 6,'source_port':sport,'destination_port':dport,'private_mdns':b'private-mdns-' in payload,'private_llmnr':b'private-llmnr-' in payload,'restored_mdns':b'restored-mdns-' in payload,'restored_llmnr':b'restored-llmnr-' in payload}
v.OuterCapture.decode=staticmethod(decode)

def main():
    server,log,endpoint,echoes,reader,capture=v.prepare_environment(['python3','/lab/dns_endpoint.py'])
    for family in ['-4','-6']:v.lab.command(['ip',family,'rule','del','pref','100','fwmark','0xa1','lookup','200'])
    os.environ.update(VERTICAL_SYSTEM_DNS='1',VERTICAL_RESTORE_SYSTEM_DNS='1',VERTICAL_SYSTEM_DNS_PROVIDER='auto')
    os.environ.pop('VERTICAL_DNS_PROBE',None);os.environ.pop('VERTICAL_DNS_GUARD',None)
    processes=[];service=None
    def run(args):
        p=subprocess.run(args,capture_output=True,text=True,timeout=12)
        assert p.returncode==0,{'command':args,'returncode':p.returncode,'stderr':p.stderr[-1000:]}
        return p.stdout
    def start(name,args):
        f=open('/run/standalone-'+name+'.log','wb');p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT);processes.append((name,p,f));time.sleep(.25)
        assert p.poll() is None,{'daemon':name,'exit':p.returncode}
    def property(name):
        return json.loads(run(['busctl','--system','--json=short','get-property','org.freedesktop.resolve1',link,'org.freedesktop.resolve1.Link',name]))
    try:
        for path in ['/run/dbus','/run/systemd']:Path(path).mkdir(parents=True,exist_ok=True)
        Path('/etc/resolv.conf').unlink(missing_ok=True)
        original=b'nameserver 127.0.0.53\noptions timeout:2 attempts:1\n'
        Path('/etc/resolv.conf').write_bytes(original)
        Path('/etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: resolve [!UNAVAIL=return] files dns\n')
        Path('/etc/systemd/resolved.conf').write_text('[Resolve]\nDNSOverTLS=no\nLLMNR=yes\nMulticastDNS=yes\n')
        start('udev',['/usr/lib/systemd/systemd-udevd']);run(['udevadm','trigger','--action=add','--subsystem-match=net']);run(['udevadm','settle','--timeout=3'])
        start('dbus',['dbus-daemon','--system','--nofork','--nopidfile']);start('resolved',['/usr/lib/systemd/systemd-resolved'])
        index=socket.if_nametoindex('wan0')
        run(['resolvectl','mdns','wan0','yes']);run(['resolvectl','llmnr','wan0','yes'])
        run(['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','SetLinkDNS','ia(iay)',str(index),'1','2','4','198','18','0','53'])
        run(['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','SetLinkDomains','ia(sb)',str(index),'1','lab.test','true'])
        link=json.loads(run(['busctl','--system','--json=short','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','GetLink','i',str(index)]))['data'][0]
        Path('/etc/resolv.conf').unlink()
        Path('/etc/resolv.conf').symlink_to('../run/systemd/resolve/stub-resolv.conf')
        original=Path('/etc/resolv.conf').read_bytes()
        assert Path('/etc/resolv.conf').is_symlink()
        baseline={name:property(name) for name in ['DNSEx','Domains','DefaultRoute','DNSOverTLS','LLMNR','MulticastDNS']}
        print('RESOLVED_BASELINE '+json.dumps(baseline),flush=True)
        run(['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','SetLinkDNSEx','ia(iayqs)',str(index),'1','2','4','198','18','0','53','53',''])
        normalized=property('DNSEx');print('RESOLVED_PORT_NORMALIZATION '+json.dumps({'input_port':53,'actual':normalized}),flush=True)
        run(['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','SetLinkDNS','ia(iay)',str(index),'1','2','4','198','18','0','53'])
        receipt=json.loads(Path('/lab/product-receipt.json').read_text())
        for path,expected in receipt.items():assert hashlib.sha256(Path('/'+path).read_bytes()).hexdigest()==expected['sha256']
        print('PRODUCT_RECEIPT '+json.dumps(receipt),flush=True)
        l.Service.count=1;service=l.Service();service.ready()
        applied={name:property(name) for name in baseline}
        assert '127' in json.dumps(applied['DNSEx']) and applied['DNSEx']!=baseline['DNSEx']
        capture.raw.clear();capture.events.clear();start_count=len(echoes)
        name='standalone-'+str(os.getpid())+'.lab.test'
        code='import socket,json,sys; answers=sorted(set(v[4][0] for v in socket.getaddrinfo(sys.argv[1],80,socket.AF_INET))); assert answers==["198.51.100.77"],answers; print(json.dumps({"query":sys.argv[1],"answers":answers}))'
        probe=l.ordinary('/usr/bin/binding-unknown',code,[name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        out,err=probe.communicate(timeout=6);assert probe.returncode==0,{'exit':probe.returncode,'error':err}
        received=[x for x in echoes[start_count:] if x.get('dns')]
        assert received and all(x['peer']=='10.77.0.2' for x in received),received
        events=list(capture.events)
        forbidden=[x for x in events if x.get('interface')=='wan0' and x.get('destination_port')==53]
        assert not forbidden,forbidden
        def multicast_query(label, family=socket.AF_INET):
            code='import socket,json,sys\ntry:\n socket.getaddrinfo(sys.argv[1],None,int(sys.argv[2]))\nexcept socket.gaierror:\n pass\nprint(json.dumps({"finished":True}))'
            child=l.ordinary('/usr/bin/binding-a',code,[label,str(family)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:out,err=child.communicate(timeout=8)
            except subprocess.TimeoutExpired:child.kill();out,err=child.communicate(timeout=2)
            return {'exit':child.returncode,'stderr':err[-200:]}
        queries=[multicast_query('private-'+kind+'-'+str(os.getpid())+'-'+str(family)+('.local' if kind=='mdns' else ''),family) for family in [socket.AF_INET,socket.AF_INET6] for kind in ['mdns','llmnr']]
        time.sleep(.2)
        leaked=[x for x in capture.events if x.get('interface')=='wan0' and x.get('packet_type')==4 and (x.get('private_mdns') or x.get('private_llmnr'))]
        print('MULTICAST_PROTECTED '+json.dumps({'queries':queries,'physical_packets':leaked}),flush=True)
        records=list(capture.raw);pcap=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for stamp,packet in records:pcap.extend(struct.pack('<IIII',int(stamp),int((stamp%1)*1000000),len(packet),len(packet))+packet)
        for offset in range(0,len(pcap),3072):print('VERTICAL_PCAP_CHUNK '+str(offset)+' '+base64.b64encode(pcap[offset:offset+3072]).decode(),flush=True)
        print('VERTICAL_PCAP_END '+json.dumps({'bytes':len(pcap),'sha256':hashlib.sha256(pcap).hexdigest()}),flush=True)
        service.finish(worker=True)
        assert service.process.returncode==0 and any('PRODUCT_DNS_RESTORED ' in line for line in service.lines)
        controls=[multicast_query('restored-'+kind+'-'+str(os.getpid())+'-'+str(family)+('.local' if kind=='mdns' else ''),family) for family in [socket.AF_INET,socket.AF_INET6] for kind in ['mdns','llmnr']]
        time.sleep(.2)
        restored_packets=[x for x in capture.events if x.get('interface')=='wan0' and x.get('packet_type')==4 and (x.get('restored_mdns') or x.get('restored_llmnr'))]
        print('MULTICAST_FINDING '+json.dumps({'protected_physical_packets':leaked,'restored_positive_packets':restored_packets,'restored_controls':controls,'actual_selected_application_nss':True}),flush=True)
        assert restored_packets,'Multicast positive control absent'
        assert not leaked,'Protected application name leaked through the shared resolver multicast path'
        restored={name:property(name) for name in baseline};assert restored==baseline,(restored,baseline)
        assert Path('/etc/resolv.conf').read_bytes()==original
        print('VERTICAL_SUMMARY '+json.dumps({'pass':True,'rows':1,'provider':'standalone-resolved-auto','nss':json.loads(out),'observed_dns':received,'physical_dns_packets':len(forbidden),'protected_multicast_packets':len(leaked),'restored_multicast_packets':len(restored_packets),'snapshot_restored':True,'resolv_conf_unchanged':True,'public_active':False}),flush=True)
    finally:
        if 'link' in locals():
            print('RESOLVED_FINAL '+json.dumps({name:property(name) for name in ['DNSEx','Domains','DefaultRoute','DNSOverTLS','LLMNR','MulticastDNS']}),flush=True)
        if service is not None and service.process.poll() is None:service.finish(worker=True)
        for name,p,f in reversed(processes):
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
            f.close()
            print('STANDALONE_DAEMON '+json.dumps({'name':name,'log':Path('/run/standalone-'+name+'.log').read_text(errors='replace')[-1200:]}),flush=True)
        server.terminate();server.wait(timeout=5);log.close();endpoint.terminate();endpoint.wait(timeout=5);reader.join(timeout=2);capture.close()
        print('VERTICAL_CLEANED',flush=True)

if __name__=='__main__':main()
