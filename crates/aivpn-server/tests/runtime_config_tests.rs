use std::path::Path;
use std::process::{Command, Output};

use base64::Engine;
use serde_json::{json, Value};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aivpn-server"));
    command
        .env_clear()
        .env("PATH", "/nonexistent-aivpn-test-path");
    command
}

fn endpoint(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let key = stdout
        .split_whitespace()
        .find_map(|part| part.strip_prefix("aivpn://"))
        .expect("ключ подключения");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .unwrap();
    let value: Value = serde_json::from_slice(&decoded).unwrap();
    value["s"].as_str().unwrap().to_string()
}

fn key_files(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let key = root.join("server.key");
    let signing = root.join("signing.key");
    std::fs::write(&key, [17u8; 32]).unwrap();
    std::fs::write(&signing, [18u8; 32]).unwrap();
    (key, signing)
}

#[test]
fn file_and_env_startup_apply_paths_before_database_and_key_reads() {
    let root = tempfile::tempdir().unwrap();
    let (key, signing) = key_files(root.path());
    let file_config = root.path().join("file-server.json");
    let file_db = root.path().join("file-clients.json");
    let masks = root.path().join("masks");
    std::fs::write(
        &file_config,
        serde_json::to_vec(&json!({
            "clients_db":file_db, "key_file":key, "mask_signing_key":signing,
            "mask_dir":masks, "public_endpoint":"vpn.example:8443",
            "listen_addr":"[::]:9443", "tun_mtu":1280
        }))
        .unwrap(),
    )
    .unwrap();
    let file_endpoint = endpoint(
        command()
            .arg("--config")
            .arg(&file_config)
            .arg("--add-client")
            .arg("file-client")
            .output()
            .unwrap(),
    );
    assert!(file_db.is_file());
    assert_eq!(file_endpoint, "vpn.example:8443");

    let env_config = root.path().join("env-server.json");
    let env_db = root.path().join("env-clients.json");
    std::fs::write(&env_config, b"{}").unwrap();
    let env_endpoint = endpoint(
        command()
            .env("AIVPN_CONFIG", &env_config)
            .env("AIVPN_CLIENTS_DB", &env_db)
            .env("AIVPN_KEY_FILE", &key)
            .env("AIVPN_MASK_SIGNING_KEY", &signing)
            .env("AIVPN_MASK_DIR", &masks)
            .env("AIVPN_PUBLIC_ENDPOINT", "vpn.example:8443")
            .env("AIVPN_LISTEN_ADDR", "[::]:9443")
            .env("AIVPN_TUN_MTU", "1280")
            .arg("--add-client")
            .arg("env-client")
            .output()
            .unwrap(),
    );
    assert!(env_db.is_file());
    assert_eq!(env_endpoint, file_endpoint);
}

#[test]
fn startup_reports_env_field_without_echoing_its_value() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("server.json");
    std::fs::write(&config, b"{}").unwrap();
    let output = command()
        .env("AIVPN_CONFIG_PATH", &config)
        .env("AIVPN_POOL__PEERS", "do-not-print-token")
        .arg("--list-clients")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("pool.peers"));
    assert!(!stderr.contains("do-not-print-token"));
}

#[test]
fn authenticated_ingress_startup_reports_invalid_env_without_its_value() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("server.json");
    std::fs::write(&config, b"{}").unwrap();
    let output = command()
        .env("AIVPN_CONFIG", config)
        .env(
            "AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT",
            "fixture-invalid-auth-rate",
        )
        .arg("--list-clients")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("per_ip_authenticated_pps_limit"));
    assert!(!stderr.contains("fixture-invalid-auth-rate"));
}

#[cfg(unix)]
#[test]
fn authenticated_ingress_cli_overrides_invalid_lower_env_and_file() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    let (_, signing) = key_files(root.path());
    let config = root.path().join("server.json");
    std::fs::write(&config, br#"{"per_ip_authenticated_pps_limit":false}"#).unwrap();
    let output = command()
        .env("AIVPN_CONFIG", config)
        .env("AIVPN_MASK_SIGNING_KEY", signing)
        .env("AIVPN_CLIENTS_DB", root.path().join("clients.json"))
        .env(
            "AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT",
            OsString::from_vec(vec![255]),
        )
        .args([
            "--list-clients",
            "--per-ip-authenticated-pps-limit",
            "100000",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn authenticated_ingress_non_utf8_env_reports_the_variable() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("server.json");
    std::fs::write(&config, b"{}").unwrap();
    let output = command()
        .env("AIVPN_CONFIG", config)
        .env(
            "AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT",
            OsString::from_vec(vec![255]),
        )
        .arg("--list-clients")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT"));
    assert!(!stderr.contains("panicked"));
}

#[cfg(target_os = "linux")]
#[test]
fn config_can_be_read_from_a_mount_without_writable_sibling_paths() {
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    let (_, signing) = key_files(root.path());
    let path = root.path().join("server.json");
    std::fs::write(&path, b"{}").unwrap();
    let config = std::fs::File::open(&path).unwrap();
    let readonly_path = format!("/proc/{}/fd/{}", std::process::id(), config.as_raw_fd());
    let output = command()
        .arg("--config")
        .arg(readonly_path)
        .arg("--clients-db")
        .arg(root.path().join("clients.json"))
        .env("AIVPN_MASK_SIGNING_KEY", signing)
        .arg("--list-clients")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.path().join("server.json.live.lock").exists());
}

#[cfg(unix)]
#[test]
fn startup_ignores_unrelated_non_utf8_env_and_explains_relevant_value() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    let (_, signing) = key_files(root.path());
    let config = root.path().join("server.json");
    std::fs::write(&config, b"{}").unwrap();
    let output = command()
        .env("UNRELATED_BINARY_VALUE", OsString::from_vec(vec![255]))
        .env("AIVPN_CONFIG", &config)
        .env("AIVPN_MASK_SIGNING_KEY", &signing)
        .env("AIVPN_CLIENTS_DB", root.path().join("clients.json"))
        .arg("--list-clients")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = command()
        .env("AIVPN_LOG_LEVEL", OsString::from_vec(vec![255]))
        .env("AIVPN_CONFIG", config)
        .arg("--list-clients")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("AIVPN_LOG_LEVEL"));
    assert!(!stderr.contains("panicked"));
}
