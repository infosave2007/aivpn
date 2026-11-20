#![cfg(target_os = "windows")]

#[test]
#[ignore = "Требуется изолированный Windows-стенд с активным профилем app-split и отдельным SYSTEM endpoint"]
fn repeated_system_icmp_survives_new_api_handles_with_active_app_split() {
    use std::process::Command;
    let control = std::env::var_os("AIVPN_NATIVE_APP_CONTROL")
        .expect("Стенд должен указать установленный app-control");
    let destination = std::env::var("AIVPN_NATIVE_SYSTEM_ENDPOINT")
        .expect("Стенд должен указать числовой SYSTEM endpoint");
    let _: std::net::IpAddr = destination.parse().unwrap();
    let profiles = Command::new(control).arg("profiles").output().unwrap();
    assert!(profiles.status.success());
    let profiles: serde_json::Value = serde_json::from_slice(&profiles.stdout).unwrap();
    assert!(profiles["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|profile| {
            profile["ready_ipv4"].as_bool() == Some(true)
                || profile["ready_ipv6"].as_bool() == Some(true)
        }));
    let ping = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .join("PING.EXE");
    for count in [1, 1, 2, 1] {
        let output = Command::new(&ping)
            .args(["-n", &count.to_string(), "-w", "1500", &destination])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ICMP после создания нового handle: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
