#![cfg(target_os = "linux")]

#[test]
fn packet_capture_keeps_dns_outside_the_scenario_event_filter() {
    let test = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/linux_capture_regression.py");
    let output = std::process::Command::new("python3")
        .arg(test)
        .output()
        .expect("Для проверки стендового захвата нужен python3");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
