//! C3 — "Install server via SSH" wizard support for the Linux iced GUI.
//!
//! Mirrors the "shell out to `aivpn-client`" architecture the rest of this
//! crate uses (`vpn_manager::find_client_binary`, `admin.rs`) — the GUI never
//! links `aivpn-common`'s SSH client directly. All three `aivpn-client
//! ssh-install {script,probe,run}` subcommands are driven as subprocesses;
//! see `crates/aivpn-client/src/ssh_install_cmd.rs` for the exact CLI
//! contract this module implements against (flag names, the `##AIVPN {...}`
//! marker JSON shape, and exit-code semantics).
//!
//! `run`'s stdout is streamed line-by-line into the iced event loop via
//! [`install_subscription`], using the same `iced::stream::channel` +
//! `tokio::process::Command` + `BufReader::lines()` pattern the VPN-connect
//! worker subscription in `app.rs::subscription` already uses.

use iced::Subscription;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::app::Message;
use crate::vpn_manager::find_client_binary;

/// Env var name the password is passed through to `aivpn-client ssh-install
/// run --password-env` — never argv (`/proc/<pid>/cmdline` is world-readable
/// on Linux). A fixed name is fine here: it only needs to be unique within
/// the child process's own environment, which `install_subscription` owns
/// entirely at spawn time (each install spawns its own child).
pub const PASSWORD_ENV_VAR: &str = "AIVPN_GUI_SSH_INSTALL_PASSWORD";
/// Same rationale, for `--key-file`'s optional `--key-passphrase-env`.
pub const KEY_PASSPHRASE_ENV_VAR: &str = "AIVPN_GUI_SSH_INSTALL_KEY_PASSPHRASE";

/// Mirrors `ssh_install_cmd::InstallModeArg` (systemd vs docker install
/// mode), duplicated rather than shared since this crate has no dependency
/// on `aivpn-client` as a library, only as a subprocess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallModeOpt {
    Systemd,
    Docker,
}

impl InstallModeOpt {
    fn as_flag(self) -> &'static str {
        match self {
            InstallModeOpt::Systemd => "systemd",
            InstallModeOpt::Docker => "docker",
        }
    }
}

/// Mirrors `ssh_install_cmd::RunArgs`' `--binary-file`/`--binary-url` pair
/// (mutually exclusive, `Default` = pass neither so the remote script
/// downloads its own built-in default from GitHub Releases).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinarySourceOpt {
    Default,
    Url(String),
    LocalFile(String),
}

/// Exactly one of the two `ssh-install run` auth methods this wizard offers
/// (`--password-env` / `--key-file`). `--password-stdin` isn't exposed here —
/// piping a password over the GUI's own stdin has no natural UI equivalent,
/// and `--password-env` already keeps the value out of argv.
#[derive(Debug, Clone)]
pub enum InstallAuth {
    Password(String),
    KeyFile {
        path: String,
        passphrase: Option<String>,
    },
}

/// Everything `ssh-install run` needs, already resolved from the wizard's
/// form state — no further user IO required. The TOFU-confirmed
/// `fingerprint` lives here (rather than being threaded separately) since
/// [`build_run_args`] needs it to build a directly runnable argv.
#[derive(Debug, Clone)]
pub struct InstallTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub fingerprint: String,
    pub auth: InstallAuth,
    pub binary: BinarySourceOpt,
    pub mode: InstallModeOpt,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    /// `true` => pass no `--device-pubkey`/`--no-device-pubkey` flag at all,
    /// so `aivpn-client ssh-install run` looks up
    /// `~/.config/aivpn/device.key` itself (see `local_device_pubkey_b64` in
    /// `ssh_install_cmd.rs`) and binds the created admin client to this
    /// machine automatically. `false` => pass `--no-device-pubkey`
    /// explicitly, so the created client is never device-bound.
    pub bind_device: bool,
}

/// Pure argv builder for `aivpn-client ssh-install run <these args>` — no
/// `ssh-install`/`run` subcommand tokens (the caller prepends those) and no
/// secret VALUES (only the fixed env-var NAMES that [`install_subscription`]
/// also sets via `Command::env` ever appear here). Unit-tested below against
/// the exact flag names `ssh_install_cmd.rs::RunArgs` expects.
pub fn build_run_args(target: &InstallTarget) -> Vec<String> {
    let mut args = vec![
        "--host".to_string(),
        target.host.clone(),
        "--port".to_string(),
        target.port.to_string(),
        "--user".to_string(),
        target.user.clone(),
        "--fingerprint".to_string(),
        target.fingerprint.clone(),
    ];
    match &target.auth {
        InstallAuth::Password(_) => {
            args.push("--password-env".to_string());
            args.push(PASSWORD_ENV_VAR.to_string());
        }
        InstallAuth::KeyFile { path, passphrase } => {
            args.push("--key-file".to_string());
            args.push(path.clone());
            if passphrase.is_some() {
                args.push("--key-passphrase-env".to_string());
                args.push(KEY_PASSPHRASE_ENV_VAR.to_string());
            }
        }
    }
    match &target.binary {
        BinarySourceOpt::Default => {}
        BinarySourceOpt::Url(url) => {
            if !url.is_empty() {
                args.push("--binary-url".to_string());
                args.push(url.clone());
            }
        }
        BinarySourceOpt::LocalFile(path) => {
            if !path.is_empty() {
                args.push("--binary-file".to_string());
                args.push(path.clone());
            }
        }
    }
    if let Some(ip) = &target.server_ip {
        if !ip.is_empty() {
            args.push("--server-ip".to_string());
            args.push(ip.clone());
        }
    }
    if let Some(port) = target.server_port {
        args.push("--server-port".to_string());
        args.push(port.to_string());
    }
    args.push("--mode".to_string());
    args.push(target.mode.as_flag().to_string());
    if !target.bind_device {
        args.push("--no-device-pubkey".to_string());
    }
    args
}

/// One line of `ssh-install run`'s stdout, already classified — see the
/// module doc comment / `ssh_install_cmd.rs`'s streaming contract for the
/// exact `##AIVPN {...}` shape this parses.
#[derive(Debug, Clone, PartialEq)]
pub enum InstallLine {
    Raw(String),
    Marker {
        step: String,
        status: String,
        code: Option<String>,
        msg: Option<String>,
        connection_key: Option<String>,
    },
}

/// Parses one stdout line from `ssh-install run` into `Raw` or `Marker`.
/// Never fails — any line that isn't a well-formed `##AIVPN {...}` marker
/// (including a malformed one, or one missing `step`) is treated as `Raw`,
/// same as a human reading the log would want either way.
pub fn parse_install_line(line: &str) -> InstallLine {
    let Some(json_str) = line.trim().strip_prefix("##AIVPN ") else {
        return InstallLine::Raw(line.to_string());
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return InstallLine::Raw(line.to_string());
    };
    let Some(step) = v.get("step").and_then(|x| x.as_str()) else {
        return InstallLine::Raw(line.to_string());
    };
    let status = v
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("info")
        .to_string();
    let code = v
        .get("code")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let msg = v.get("msg").and_then(|x| x.as_str()).map(|s| s.to_string());
    let connection_key = v
        .get("connection_key")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    InstallLine::Marker {
        step: step.to_string(),
        status,
        code,
        msg,
        connection_key,
    }
}

/// Human-readable label for a known installer `step` id (see the
/// `deploy/install-server.sh` marker list this mirrors, and
/// `crates/aivpn-client/src/ssh_install_cmd.rs`'s own client-side steps),
/// in both UI languages. Falls back to the raw step id verbatim for anything
/// unrecognized, so a future installer-script step never renders blank.
pub fn describe_step(step: &str, lang: &str) -> String {
    let ru = lang == "ru";
    let s: &str = match step {
        "ssh_connect" => {
            if ru {
                "Подключение по SSH"
            } else {
                "SSH connect"
            }
        }
        "upload" => {
            if ru {
                "Загрузка файлов"
            } else {
                "Upload"
            }
        }
        "start" => {
            if ru {
                "Установка запущена"
            } else {
                "Install starting"
            }
        }
        "detect_env" => {
            if ru {
                "Определение окружения"
            } else {
                "Detecting environment"
            }
        }
        "port_check" => {
            if ru {
                "Проверка порта"
            } else {
                "Port check"
            }
        }
        "install_deps" => {
            if ru {
                "Установка зависимостей"
            } else {
                "Installing dependencies"
            }
        }
        "tun_device" => {
            if ru {
                "Проверка устройства TUN"
            } else {
                "TUN device"
            }
        }
        "create_dirs" => {
            if ru {
                "Создание каталогов"
            } else {
                "Creating directories"
            }
        }
        "fetch_binary" => {
            if ru {
                "Загрузка бинарника сервера"
            } else {
                "Fetching server binary"
            }
        }
        "verify_binary" => {
            if ru {
                "Проверка бинарника"
            } else {
                "Verifying binary"
            }
        }
        "install_binary" => {
            if ru {
                "Установка бинарника"
            } else {
                "Installing binary"
            }
        }
        "seed_config" => {
            if ru {
                "Конфигурация сервера"
            } else {
                "Seeding config"
            }
        }
        "gen_key" => {
            if ru {
                "Генерация ключей"
            } else {
                "Generating keys"
            }
        }
        "seed_masks" => {
            if ru {
                "Установка масок трафика"
            } else {
                "Seeding masks"
            }
        }
        "install_systemd_unit" => {
            if ru {
                "Установка systemd-юнита"
            } else {
                "Installing systemd unit"
            }
        }
        "ip_forward" => {
            if ru {
                "Включение IP forwarding"
            } else {
                "Enabling IP forwarding"
            }
        }
        "firewall" => {
            if ru {
                "Настройка firewall"
            } else {
                "Configuring firewall"
            }
        }
        "start_service" => {
            if ru {
                "Запуск сервиса"
            } else {
                "Starting service"
            }
        }
        "create_admin_client" => {
            if ru {
                "Создание admin-клиента"
            } else {
                "Creating admin client"
            }
        }
        "health_check" => {
            if ru {
                "Проверка работоспособности"
            } else {
                "Health check"
            }
        }
        "done" => {
            if ru {
                "Готово"
            } else {
                "Done"
            }
        }
        "client_done" => {
            if ru {
                "Установка завершена"
            } else {
                "Install finished"
            }
        }
        "device_pubkey" => {
            if ru {
                "Привязка устройства"
            } else {
                "Device binding"
            }
        }
        other => other,
    };
    s.to_string()
}

/// Runs `aivpn-client ssh-install script [--sha256-only]` twice, returning
/// `(sha256_hex, script_text)` — two cheap local subprocess calls rather
/// than pulling in a `sha2` crate just to re-hash what the CLI already
/// hashes for us. Resolves the binary itself (no `binary` parameter), same
/// as every other IO helper in `admin.rs` (`list_clients`, `pool_nodes`, …).
pub async fn fetch_script() -> Result<(String, String), String> {
    let binary = find_client_binary()?;

    let sha_out = tokio::process::Command::new(&binary)
        .args(["ssh-install", "script", "--sha256-only"])
        .output()
        .await
        .map_err(|e| format!("Failed to run aivpn-client: {e}"))?;
    if !sha_out.status.success() {
        return Err(format!(
            "ssh-install script --sha256-only failed: {}",
            String::from_utf8_lossy(&sha_out.stderr).trim()
        ));
    }
    let sha256 = String::from_utf8_lossy(&sha_out.stdout).trim().to_string();

    let script_out = tokio::process::Command::new(&binary)
        .args(["ssh-install", "script"])
        .output()
        .await
        .map_err(|e| format!("Failed to run aivpn-client: {e}"))?;
    if !script_out.status.success() {
        return Err(format!(
            "ssh-install script failed: {}",
            String::from_utf8_lossy(&script_out.stderr).trim()
        ));
    }
    let script = String::from_utf8_lossy(&script_out.stdout).to_string();
    Ok((sha256, script))
}

/// Runs `aivpn-client ssh-install probe --host H --port P --user U` (TOFU
/// step 1) and parses its one-line `{"fingerprint":"SHA256:.."}` stdout.
pub async fn probe(host: String, port: u16, user: String) -> Result<String, String> {
    let binary = find_client_binary()?;
    let out = tokio::process::Command::new(&binary)
        .args([
            "ssh-install",
            "probe",
            "--host",
            &host,
            "--port",
            &port.to_string(),
            "--user",
            &user,
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to run aivpn-client: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Probe failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("Malformed probe response: {e}"))?;
    v.get("fingerprint")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Probe response missing 'fingerprint'".to_string())
}

/// Spawns `aivpn-client ssh-install run <target's args>` and streams its
/// stdout/stderr into the iced event loop: one `Message::InstallWizardLine`
/// per line (via [`parse_install_line`]), followed by exactly one
/// `Message::InstallWizardFinished(exit_code)` when the process exits, or a
/// `Message::InstallWizardSpawnError` if it never got that far. Modeled
/// directly on the VPN-connect worker subscription in
/// `app.rs::App::subscription` (`iced::stream::channel` +
/// `tokio::process::Command` + `BufReader::lines()` read in a
/// `tokio::select!` loop) — the password/passphrase are injected via
/// `Command::env`, never argv, matching [`build_run_args`]'s contract.
pub fn install_subscription(target: InstallTarget) -> Subscription<Message> {
    let stream = iced::stream::channel(64, move |mut sender| async move {
        let binary = match find_client_binary() {
            Ok(b) => b,
            Err(e) => {
                let _ = sender.try_send(Message::InstallWizardSpawnError(e));
                return;
            }
        };

        let mut cmd = tokio::process::Command::new(&binary);
        // Don't leave an install running detached if the GUI exits mid-run.
        cmd.kill_on_drop(true);
        cmd.arg("ssh-install").arg("run");
        for a in build_run_args(&target) {
            cmd.arg(a);
        }
        match &target.auth {
            InstallAuth::Password(pw) => {
                cmd.env(PASSWORD_ENV_VAR, pw);
            }
            InstallAuth::KeyFile { passphrase, .. } => {
                if let Some(p) = passphrase {
                    cmd.env(KEY_PASSPHRASE_ENV_VAR, p);
                }
            }
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = sender.try_send(Message::InstallWizardSpawnError(format!(
                    "Failed to launch aivpn-client: {e}"
                )));
                return;
            }
        };
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
            let _ = child.start_kill();
            let _ = sender.try_send(Message::InstallWizardSpawnError(
                "stdout/stderr pipe unavailable".to_string(),
            ));
            return;
        };
        let mut out = BufReader::new(stdout).lines();
        let mut err = BufReader::new(stderr).lines();

        loop {
            tokio::select! {
                line = out.next_line() => match line {
                    Ok(Some(l)) => {
                        let _ = sender.try_send(Message::InstallWizardLine(parse_install_line(&l)));
                    }
                    _ => break,
                },
                line = err.next_line() => match line {
                    Ok(Some(l)) => {
                        let _ = sender.try_send(Message::InstallWizardLine(InstallLine::Raw(
                            format!("[err] {l}"),
                        )));
                    }
                    _ => break,
                },
            }
        }

        let code = match child.wait().await {
            Ok(status) => status.code().unwrap_or(-1),
            Err(_) => -1,
        };
        let _ = sender.try_send(Message::InstallWizardFinished(code));
    });
    Subscription::run_with_id("aivpn_install_wizard", stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_target() -> InstallTarget {
        InstallTarget {
            host: "vps.example.com".to_string(),
            port: 22,
            user: "root".to_string(),
            fingerprint: "SHA256:abc".to_string(),
            auth: InstallAuth::Password("hunter2".to_string()),
            binary: BinarySourceOpt::Default,
            mode: InstallModeOpt::Systemd,
            server_ip: None,
            server_port: None,
            bind_device: true,
        }
    }

    // --- build_run_args ---------------------------------------------------

    #[test]
    fn build_run_args_password_auth_minimal() {
        let args = build_run_args(&base_target());
        assert_eq!(
            args,
            vec![
                "--host",
                "vps.example.com",
                "--port",
                "22",
                "--user",
                "root",
                "--fingerprint",
                "SHA256:abc",
                "--password-env",
                PASSWORD_ENV_VAR,
                "--mode",
                "systemd",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn build_run_args_never_contains_password_value() {
        let args = build_run_args(&base_target());
        assert!(!args.iter().any(|a| a == "hunter2"));
    }

    #[test]
    fn build_run_args_key_file_no_passphrase() {
        let mut target = base_target();
        target.auth = InstallAuth::KeyFile {
            path: "/home/u/.ssh/id_ed25519".to_string(),
            passphrase: None,
        };
        let args = build_run_args(&target);
        assert!(args.contains(&"--key-file".to_string()));
        assert!(args.contains(&"/home/u/.ssh/id_ed25519".to_string()));
        assert!(!args.contains(&"--key-passphrase-env".to_string()));
        assert!(!args.contains(&"--password-env".to_string()));
    }

    #[test]
    fn build_run_args_key_file_with_passphrase_uses_fixed_env_var_name_not_value() {
        let mut target = base_target();
        target.auth = InstallAuth::KeyFile {
            path: "/home/u/.ssh/id_ed25519".to_string(),
            passphrase: Some("p4ss".to_string()),
        };
        let args = build_run_args(&target);
        let idx = args
            .iter()
            .position(|a| a == "--key-passphrase-env")
            .expect("--key-passphrase-env must be present");
        assert_eq!(args[idx + 1], KEY_PASSPHRASE_ENV_VAR);
        assert!(!args.iter().any(|a| a == "p4ss"));
    }

    #[test]
    fn build_run_args_docker_mode_server_ip_port() {
        let mut target = base_target();
        target.mode = InstallModeOpt::Docker;
        target.server_ip = Some("1.2.3.4".to_string());
        target.server_port = Some(18444);
        let args = build_run_args(&target);
        let mode_idx = args.iter().position(|a| a == "--mode").unwrap();
        assert_eq!(args[mode_idx + 1], "docker");
        assert!(args.contains(&"--server-ip".to_string()));
        assert!(args.contains(&"1.2.3.4".to_string()));
        assert!(args.contains(&"--server-port".to_string()));
        assert!(args.contains(&"18444".to_string()));
    }

    #[test]
    fn build_run_args_empty_server_ip_is_omitted() {
        let mut target = base_target();
        target.server_ip = Some(String::new());
        let args = build_run_args(&target);
        assert!(!args.contains(&"--server-ip".to_string()));
    }

    #[test]
    fn build_run_args_bind_device_false_adds_no_device_pubkey() {
        let mut target = base_target();
        target.bind_device = false;
        let args = build_run_args(&target);
        assert!(args.contains(&"--no-device-pubkey".to_string()));
    }

    #[test]
    fn build_run_args_bind_device_true_omits_all_device_flags() {
        // base_target() has bind_device: true — matches the ssh_install_cmd.rs
        // contract: omitting BOTH --device-pubkey and --no-device-pubkey lets
        // `aivpn-client ssh-install run` fall back to the local device key.
        let args = build_run_args(&base_target());
        assert!(!args.iter().any(|a| a.contains("device-pubkey")));
    }

    #[test]
    fn build_run_args_binary_url() {
        let mut target = base_target();
        target.binary = BinarySourceOpt::Url("https://example.com/aivpn-server".to_string());
        let args = build_run_args(&target);
        let idx = args
            .iter()
            .position(|a| a == "--binary-url")
            .expect("--binary-url must be present");
        assert_eq!(args[idx + 1], "https://example.com/aivpn-server");
        assert!(!args.contains(&"--binary-file".to_string()));
    }

    #[test]
    fn build_run_args_binary_local_file() {
        let mut target = base_target();
        target.binary = BinarySourceOpt::LocalFile("/tmp/aivpn-server".to_string());
        let args = build_run_args(&target);
        let idx = args
            .iter()
            .position(|a| a == "--binary-file")
            .expect("--binary-file must be present");
        assert_eq!(args[idx + 1], "/tmp/aivpn-server");
        assert!(!args.contains(&"--binary-url".to_string()));
    }

    #[test]
    fn build_run_args_binary_default_omits_both_flags() {
        // base_target() has binary: Default — matches the ssh_install_cmd.rs
        // contract: omitting both --binary-file and --binary-url lets the
        // remote script download its own built-in default.
        let args = build_run_args(&base_target());
        assert!(!args.iter().any(|a| a.contains("binary-")));
    }

    // --- parse_install_line -------------------------------------------------

    #[test]
    fn parse_install_line_raw() {
        let line = "Installing packages via apt-get...";
        assert_eq!(parse_install_line(line), InstallLine::Raw(line.to_string()));
    }

    #[test]
    fn parse_install_line_marker_full_fields() {
        let line = r#"##AIVPN {"step":"done","status":"ok","code":null,"msg":null,"connection_key":"aivpn://x"}"#;
        let parsed = parse_install_line(line);
        assert_eq!(
            parsed,
            InstallLine::Marker {
                step: "done".to_string(),
                status: "ok".to_string(),
                code: None,
                msg: None,
                connection_key: Some("aivpn://x".to_string()),
            }
        );
    }

    #[test]
    fn parse_install_line_marker_with_code_and_msg() {
        let line = r#"##AIVPN {"step":"port_check","status":"info","code":"port_busy","msg":"port 51820 in use","connection_key":null}"#;
        match parse_install_line(line) {
            InstallLine::Marker {
                step,
                status,
                code,
                msg,
                connection_key,
            } => {
                assert_eq!(step, "port_check");
                assert_eq!(status, "info");
                assert_eq!(code.as_deref(), Some("port_busy"));
                assert_eq!(msg.as_deref(), Some("port 51820 in use"));
                assert_eq!(connection_key, None);
            }
            other => panic!("expected Marker, got {other:?}"),
        }
    }

    #[test]
    fn parse_install_line_malformed_marker_falls_back_to_raw() {
        let line = "##AIVPN {not valid json";
        assert_eq!(parse_install_line(line), InstallLine::Raw(line.to_string()));
    }

    #[test]
    fn parse_install_line_missing_step_falls_back_to_raw() {
        let line = r#"##AIVPN {"status":"ok"}"#;
        assert_eq!(parse_install_line(line), InstallLine::Raw(line.to_string()));
    }

    #[test]
    fn parse_install_line_client_done_exit_code() {
        let line = r#"##AIVPN {"step":"client_done","status":"error","code":"exit_3","msg":null,"connection_key":null}"#;
        match parse_install_line(line) {
            InstallLine::Marker {
                step, status, code, ..
            } => {
                assert_eq!(step, "client_done");
                assert_eq!(status, "error");
                assert_eq!(code.as_deref(), Some("exit_3"));
            }
            other => panic!("expected Marker, got {other:?}"),
        }
    }

    // --- describe_step -------------------------------------------------------

    #[test]
    fn describe_step_known_and_unknown() {
        assert_eq!(describe_step("done", "en"), "Done");
        assert_eq!(describe_step("done", "ru"), "Готово");
        assert_eq!(describe_step("some_future_step", "en"), "some_future_step");
    }
}
