use std::process::Command;

#[test]
fn explicit_cli_mode_preserves_version_without_connecting() {
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .args(["cli", "--version"])
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    assert!(String::from_utf8_lossy(&result.stdout).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn explicit_cli_mode_preserves_the_existing_help() {
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .args(["cli", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    let help = String::from_utf8_lossy(&result.stdout);
    assert!(help.contains("--split-enabled"));
    assert!(help.contains("--server"));
}

#[test]
fn capabilities_report_the_compiled_routing_support() {
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .arg("--capabilities")
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        value["app_routing"]["compiled"],
        cfg!(feature = "desktop-service")
    );
    assert_eq!(value["app_routing"]["readiness_checked"], false);
    assert_eq!(value["platform"], std::env::consts::OS);
    assert_eq!(
        value["app_routing"]["readiness_command"],
        serde_json::json!(["app-routing", "status"])
    );
}

#[test]
fn routing_control_is_available_only_in_the_full_build() {
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .args(["app-routing", "--help"])
        .output()
        .unwrap();
    if cfg!(feature = "desktop-service") {
        assert!(result.status.success(), "{:?}", result);
        assert!(String::from_utf8_lossy(&result.stdout).contains("split"));
    } else {
        assert_eq!(result.status.code(), Some(69), "{:?}", result);
    }
}

#[cfg(feature = "desktop-service")]
#[test]
fn service_help_does_not_start_the_service_or_client_runtime() {
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .args(["__routing-service", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    assert!(String::from_utf8_lossy(&result.stdout).contains("--state-directory"));
}

#[cfg(all(feature = "desktop-service", target_os = "linux"))]
#[test]
fn worker_without_an_authorized_channel_fails_without_aborting() {
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .arg("__packet-worker")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1), "{:?}", result);
    assert!(result.stdout.is_empty());
}

#[cfg(all(feature = "desktop-service", target_os = "linux"))]
#[test]
fn legacy_control_alias_routes_to_control_without_an_extra_binary() {
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let scratch =
        Scratch(std::env::temp_dir().join(format!("aivpn-control-alias-{}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let alias = scratch.0.join("aivpn-app-control");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_aivpn-client"), &alias).unwrap();
    let result = Command::new(alias).arg("--help").output().unwrap();
    assert!(result.status.success(), "{:?}", result);
    let help = String::from_utf8_lossy(&result.stdout);
    assert!(help.contains("decommission"), "{help}");
    assert!(help.contains("apply"), "{help}");
}

#[cfg(target_os = "linux")]
#[test]
fn network_helper_does_not_reinterpret_a_second_role() {
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .args(["__network-helper", "cli", "--version"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(64), "{:?}", result);
    assert!(result.stdout.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn cached_helper_role_rejects_the_legacy_stdin_batch() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .arg("__network-helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(b"ip link set dev eth0 mtu 9000\n");
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(64), "{:?}", result);
    assert!(result.stdout.is_empty());
}

#[cfg(all(feature = "desktop-service", target_os = "linux"))]
#[test]
fn ordinary_client_does_not_require_a_libbpf_runtime_package() {
    let output = Command::new("readelf")
        .args(["--dynamic", env!("CARGO_BIN_EXE_aivpn-client")])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let dependencies = String::from_utf8_lossy(&output.stdout);
    assert!(
        !dependencies.contains("Shared library: [libbpf.so"),
        "{dependencies}"
    );
}
