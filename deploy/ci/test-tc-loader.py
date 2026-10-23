#!/usr/bin/env python3
"""Проверяет argv реального TC loader; вместо tc/bpftool используются локальные заглушки."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='aivpn-tc-loader-') as temp:
    work = Path(temp)
    tracing = work / 'tracing.rs'
    tracing.write_text('''#[macro_export] macro_rules! debug { ($($arg:tt)*) => {{ let _ = format_args!($($arg)*); }} }
#[macro_export] macro_rules! warn { ($($arg:tt)*) => {{ let _ = format_args!($($arg)*); }} }
''')
    library = work / 'libtracing.rlib'
    subprocess.run(['rustc', '--crate-name', 'tracing', '--crate-type', 'rlib',
                    str(tracing), '-o', str(library)], check=True)
    src = work / 'loader.rs'
    src.write_text((root / 'crates/aivpn-server/src/tc_loader.rs').read_text() + '''
#[test]
fn bpftool_receives_one_argument_per_byte() {
    let mut loader = TcQosLoader { iface: "fixture".into(), prog_path: "fixture".into(), attached: true };
    let rule = TcQosRule { vpn_ip: 0x0a000002, rate_up_bps: 0, rate_down_bps: 10000, dscp: 46 };
    assert!(loader.update_rule(&rule), "update должен передать 4 байта key и 32 байта value");
    assert!(loader.delete_rule(rule.vpn_ip), "delete должен передать 4 байта key");
    loader.attached = false;
}
#[test]
fn detach_preserves_foreign_qdisc() {
    let mut loader = TcQosLoader { iface: "fixture".into(), prog_path: "fixture".into(), attached: true };
    loader.detach();
    let calls = std::fs::read_to_string(std::env::var("TC_LOG").unwrap()).unwrap();
    assert!(!calls.contains("qdisc del"), "Нельзя удалять общий clsact с чужими filters");
    assert!(calls.contains("filter del dev fixture egress pref 47741 handle 1 bpf"));
}
#[test]
fn attach_accepts_existing_qdisc_and_does_not_attach_twice() {
    let mut loader = TcQosLoader::new("fixture", Path::new(file!()));
    assert!(loader.attach(), "File exists от qdisc не означает ошибку filter");
    assert!(loader.attach());
    let calls = std::fs::read_to_string(std::env::var("TC_LOG").unwrap()).unwrap();
    assert_eq!(calls.lines().filter(|line| line.starts_with("filter add")).count(), 1);
}
''')
    tool = work / 'bpftool'
    tool.write_text('''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
assert a[:1] == ['map']
assert a[3] == '/sys/fs/bpf/tc/globals/aivpn_qos_rules', a
assert a[4:10] == ['key', 'hex', '0a', '00', '00', '02'], a
if a[1] == 'update':
    assert a[10:12] == ['value', 'hex'], a
    value = bytes(int(x, 16) for x in a[12:])
    assert len(value) == 32, len(value)
    assert int.from_bytes(value[8:16], sys.byteorder) >= 1500
    assert value[24] == 46 and value[28:32] == bytes(4)
else:
    assert a[1] == 'delete' and len(a) == 10, a
''')
    tool.chmod(0o700)
    (work / 'tc').write_text('''#!/usr/bin/env python3
import os, sys
with open(os.environ['TC_LOG'], 'a') as log:
    log.write(' '.join(sys.argv[1:]) + '\\n')
if sys.argv[1:3] == ['qdisc', 'add']:
    print('RTNETLINK answers: File exists', file=sys.stderr)
    raise SystemExit(2)
''')
    (work / 'tc').chmod(0o700)
    binary = work / 'loader-test'
    subprocess.run(['rustc', '--edition=2021', '--test', str(src), '--extern',
                    f'tracing={library}', '-o', str(binary)], check=True)
    subprocess.run([str(binary)], env=os.environ | {
        'PATH': str(work) + os.pathsep + os.environ['PATH'],
        'TC_LOG': str(work / 'tc.log')}, check=True)
