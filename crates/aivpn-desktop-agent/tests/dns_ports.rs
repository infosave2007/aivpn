#![cfg(target_os = "linux")]

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn dns_guard_covers_multicast_names_without_blocking_loopback_or_other_ports() {
    use std::os::unix::fs::DirBuilderExt;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory =
        std::env::temp_dir().join(format!("aivpn-dns-guard-ports-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let temporary = Temporary(directory);
    let binary = temporary.0.join("memory");
    let compiled = std::process::Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(root.join("tests/support/dns_ports.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = std::process::Command::new("timeout")
        .arg("10")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("DNS_PORT_GUARD_PASS"));
}
