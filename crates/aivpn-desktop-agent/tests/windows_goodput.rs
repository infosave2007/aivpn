#![cfg(target_os = "linux")]

#[test]
fn benchmark_download_is_limited_by_the_sender() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/windows_goodput_server_test.py");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=1", "15", "python3"])
        .arg(script)
        .env("PYTHONNOUSERSITE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
