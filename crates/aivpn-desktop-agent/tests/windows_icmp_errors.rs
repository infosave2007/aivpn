#![cfg(target_os = "linux")]

#[test]
fn windows_network_control_errors_and_profile_fragments_preserve_the_application_flow() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = std::env::temp_dir().join(format!(
        "aivpn-icmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let executable = directory.join("icmp-errors");
    let compiled = std::process::Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-g",
        ])
        .arg("-I")
        .arg(root.join("native/windows"))
        .arg(root.join("native/windows/packet.c"))
        .arg(root.join("native/windows/reassembly.c"))
        .arg(root.join("tests/support/windows_icmp_errors.c"))
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = std::process::Command::new("timeout")
        .args(["--kill-after=1", "20"])
        .arg(executable)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
