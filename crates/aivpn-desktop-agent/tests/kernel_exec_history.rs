#![cfg(all(target_os = "linux", feature = "linux-kernel"))]

#[test]
fn bounded_history_preserves_fork_generations_and_owner_epochs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = std::env::temp_dir().join(format!("aivpn-exec-history-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("history");
    let compile = std::process::Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("native/linux"))
        .arg(root.join("tests/support/exec_history.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let output = std::process::Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("EXEC_HISTORY_PASS"));
}
