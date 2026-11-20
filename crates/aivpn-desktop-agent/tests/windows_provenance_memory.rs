#![cfg(target_os = "linux")]

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn short_file_paths_preserve_proof_capacity_and_release_their_byte_budget() {
    use std::os::unix::fs::DirBuilderExt;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory =
        std::env::temp_dir().join(format!("aivpn-provenance-memory-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let temporary = Temporary(directory);
    let binary = temporary.0.join("memory");
    let compiled = std::process::Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(root.join("tests/support/windows_provenance_memory.c"))
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("WINDOWS_PROVENANCE_MEMORY_PASS"));
}
