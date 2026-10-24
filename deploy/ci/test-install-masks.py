import hashlib, io, os, pathlib, subprocess, tarfile, tempfile
source=(pathlib.Path(__file__).resolve().parents[2] / 'deploy/install-server.sh').read_text()
start=source.index('seed_masks() {')
function=source[start:source.index('\n}\n',start)+3]
verify_start=source.index('verify_release_signature() {')
function=source[verify_start:source.index('\n}\n',verify_start)+3]+'\n'+function
with tempfile.TemporaryDirectory() as t:
    root=pathlib.Path(t); fixture=root/'fixture'; fixture.mkdir()
    archive=fixture/'masks.tar.gz'
    key=root/'key.pem'
    subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,capture_output=True)
    public=subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'],check=True,capture_output=True).stdout
    import base64
    release_key=base64.b64encode(public).decode()
    def tar(valid=True):
        if not valid:
            archive.write_bytes(b'invalid');return
        with tarfile.open(archive,'w:gz') as tf:
            data=b'{"id":"test"}'
            entry=tarfile.TarInfo('mask.json');entry.size=len(data)
            tf.addfile(entry,io.BytesIO(data))
    def run(label, checksum, valid, expected, signature=True, public_key=None):
        tar(valid)
        sums=fixture/'masks.tar.gz.SHA256SUMS'
        if checksum is None:
            sums.unlink(missing_ok=True)
        else:
            digest=hashlib.sha256(archive.read_bytes()).hexdigest() if checksum else '0'*64
            sums.write_text(f'{digest}  masks.tar.gz\n')
        sig=fixture/'masks.tar.gz.sig'
        subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(key),'-in',str(archive),'-out',str(sig)],check=True,capture_output=True)
        if not signature:
            sig.write_bytes(b'invalid signature')
        target=root/label
        script='''set -euo pipefail
emit_marker() { :; }
curl() {
    local out='' arg
    while [ "$#" -gt 0 ]; do
        if [ "$1" = '-o' ]; then out="$2"; shift 2; else arg="$1"; shift; fi
    done
    cp "$FIXTURE/${arg##*/}" "$out"
}
'''+function+'\nseed_masks\n'
        env=os.environ|{'RELEASE_PUBLIC_KEY':release_key if public_key is None else public_key,'FIXTURE':str(fixture),'MASK_DIR':str(target),'MASKS_DIR_OVERRIDE':'','BUNDLED_MASKS_DIR':'','MASKS_URL':'https://fixture/masks.tar.gz','BINARY_BASE_URL':'https://fixture'}
        result=subprocess.run(['bash','-c',script],env=env,capture_output=True)
        assert (result.returncode==0)==expected, (label,result.stderr.decode())
        assert (target/'mask.json').exists()==expected,label
        print(label,'PASS')
    run('missing-checksum',None,True,False)
    run('wrong-checksum',False,True,False)
    run('invalid-archive',True,False,False)
    run('valid-archive',True,True,True)
    run('invalid-signature',True,True,False,signature=False)
    run('missing-public-key',True,True,False,public_key='')
