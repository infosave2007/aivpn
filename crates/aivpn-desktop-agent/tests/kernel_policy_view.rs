#![cfg(all(target_os = "linux", feature = "linux-kernel"))]
#[test]
fn generic_and_windows_equality_keep_wire_and_accessor_parity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let temporary = std::env::temp_dir().join(format!("aivpn-policy-view-{}", std::process::id()));
    std::fs::create_dir(&temporary).unwrap();
    let binary = temporary.join("policy-view");
    let compile = std::process::Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("native/linux"))
        .arg(root.join("tests/support/kernel_policy_view.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let result = std::process::Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(temporary).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("DEFAULT_WINDOWS_EQUALITY_AND_VIEW_PASS")
    );
}
