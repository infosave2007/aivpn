//! SSH server-install wizard — host-clean subprocess-bridge logic (C3).
//!
//! Same architecture as `admin.rs`'s module doc: the Windows GUI never links
//! the Rust client/protocol core — it drives `aivpn-client.exe` as a
//! subprocess, this time via its `ssh-install {script,probe,run}`
//! subcommands (see `crates/aivpn-client/src/ssh_install_cmd.rs`, the single
//! source of truth for every flag and every `##AIVPN {...}` marker shape
//! used below — nothing here should ever "invent" a flag or a step name
//! that file doesn't already document).
//!
//! Unlike `admin.rs` (one call -> one `AdminResponse`), an install is a
//! *stream*: `ssh-install run` prints one line per remote-install step over
//! several seconds to minutes, so the bridge here is `mpsc::Sender<
//! InstallLine>` fed continuously from a background thread that reads the
//! child process's stdout line-by-line, rather than a single reply sent
//! once the process exits.
//!
//! Every type and pure function in this module (`InstallLine`,
//! `parse_install_line`, `build_run_args`) is deliberately free of `egui`/
//! `eframe` types and of blocking IO, so it compiles and unit-tests on any
//! host — the same "host-clean" split `admin.rs` uses for its view models
//! and `event_to_line`/`build_install_params` mirror in
//! `ssh_install_cmd.rs`. The IO-performing drivers (`fetch_script`,
//! `probe`, `spawn_install`) are validated against a live/VM SSH server,
//! same as `ssh_install_cmd.rs` itself and `admin.rs`'s `mgmt_call`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;

/// Env var `spawn_install` sets (via `Command::env`, never argv — see
/// `ssh_install_cmd.rs`'s `--password-env` doc comment) to carry the SSH
/// password through to `aivpn-client ssh-install run --password-env`.
pub const SSH_PASSWORD_ENV_VAR: &str = "AIVPN_INSTALL_WIZARD_SSH_PASSWORD";
/// Same, for a private key's passphrase via `--key-passphrase-env`.
pub const SSH_KEY_PASSPHRASE_ENV_VAR: &str = "AIVPN_INSTALL_WIZARD_KEY_PASSPHRASE";

// ── Target / auth / mode ────────────────────────────────────────────────

/// Which of `ssh-install run`'s mutually-exclusive auth methods to use.
/// The actual secret (password, or a key's passphrase) is never stored
/// here — it's passed separately and only transiently to `spawn_install`,
/// so it isn't held any longer than necessary in UI-owned state (mirrors
/// why `ssh_install_cmd.rs` reads secrets from env/stdin/file rather than
/// accepting them as plain CLI args).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallAuth {
    /// `--password-env AIVPN_INSTALL_WIZARD_SSH_PASSWORD`.
    Password,
    /// `--key-file PATH [--key-passphrase-env AIVPN_INSTALL_WIZARD_KEY_PASSPHRASE]`.
    KeyFile { path: PathBuf, has_passphrase: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InstallModeChoice {
    #[default]
    Systemd,
    Docker,
}

impl InstallModeChoice {
    fn as_flag(self) -> &'static str {
        match self {
            InstallModeChoice::Systemd => "systemd",
            InstallModeChoice::Docker => "docker",
        }
    }
}

/// Which `aivpn-server` binary the remote install script should run — maps
/// 1:1 onto `ssh_install_cmd.rs`'s mutually-exclusive `--binary-file` /
/// `--binary-url` flags (`RunArgs`). Previously the wizard always left this
/// at `Default` with no UI to change it (see the removed comment this
/// replaces); now exposed so the wizard matches the CLI's full flag surface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BinarySource {
    /// Neither flag passed — the remote script fetches its own built-in
    /// default build (GitHub Releases).
    #[default]
    Default,
    /// `--binary-url URL` — remote script downloads from this URL instead
    /// of GitHub Releases. A blank/whitespace-only URL is treated the same
    /// as `Default` (mirrors `InstallTarget::server_ip`'s blank handling).
    Url(String),
    /// `--binary-file PATH` — upload this local file instead of letting
    /// the remote script download anything.
    LocalFile(PathBuf),
}

/// Everything `build_run_args` needs to build the argv for `ssh-install
/// run` — the wizard's UI state maps onto this 1:1.
#[derive(Debug, Clone)]
pub struct InstallTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Host key fingerprint already shown to and accepted by the user
    /// (TOFU step 1 — the output of [`probe`] below). `ssh-install run`
    /// hard-fails on any mismatch against what the host actually presents.
    pub fingerprint: String,
    pub auth: InstallAuth,
    pub mode: InstallModeChoice,
    /// Which `aivpn-server` binary the remote script should use — see
    /// [`BinarySource`].
    pub binary_source: BinarySource,
    /// `--server-ip`, or `None`/empty to omit (remote script's own default).
    pub server_ip: Option<String>,
    /// `--server-port`, or `None` to omit.
    pub server_port: Option<u16>,
    /// "Bind this device" toggle: `true` -> pass neither `--device-pubkey`
    /// nor `--no-device-pubkey`, so `ssh-install run` defaults to this
    /// machine's own local device key
    /// (`ssh_install_cmd.rs::local_device_pubkey_b64`, reading
    /// `~/.config/aivpn/device.key`) if one exists. `false` -> always pass
    /// `--no-device-pubkey`, installing without device binding.
    pub bind_device: bool,
}

// ── build_run_args — pure, unit-tested ──────────────────────────────────

/// Builds the argv (excluding the `aivpn-client` binary itself) for
/// `ssh-install run`, per the exact flag contract in `ssh_install_cmd.rs`'s
/// `RunArgs`. Pure — no IO, no env reads — so it's fully unit-testable.
pub fn build_run_args(target: &InstallTarget) -> Vec<String> {
    let mut args = vec!["ssh-install".to_string(), "run".to_string()];

    args.push("--host".to_string());
    args.push(target.host.clone());
    args.push("--port".to_string());
    args.push(target.port.to_string());
    args.push("--user".to_string());
    args.push(target.user.clone());
    args.push("--fingerprint".to_string());
    args.push(target.fingerprint.clone());

    match &target.auth {
        InstallAuth::Password => {
            args.push("--password-env".to_string());
            args.push(SSH_PASSWORD_ENV_VAR.to_string());
        }
        InstallAuth::KeyFile {
            path,
            has_passphrase,
        } => {
            args.push("--key-file".to_string());
            args.push(path.to_string_lossy().into_owned());
            if *has_passphrase {
                args.push("--key-passphrase-env".to_string());
                args.push(SSH_KEY_PASSPHRASE_ENV_VAR.to_string());
            }
        }
    }

    match &target.binary_source {
        BinarySource::Default => {}
        BinarySource::Url(url) => {
            let url = url.trim();
            if !url.is_empty() {
                args.push("--binary-url".to_string());
                args.push(url.to_string());
            }
        }
        BinarySource::LocalFile(path) => {
            args.push("--binary-file".to_string());
            args.push(path.to_string_lossy().into_owned());
        }
    }

    if let Some(ip) = target.server_ip.as_deref() {
        let ip = ip.trim();
        if !ip.is_empty() {
            args.push("--server-ip".to_string());
            args.push(ip.to_string());
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
    // bind_device == true: pass neither --device-pubkey nor
    // --no-device-pubkey — see InstallTarget::bind_device's doc comment.

    args
}

// ── Streamed install-line parsing — pure, unit-tested ───────────────────

/// One line of `ssh-install run`'s stdout, already classified. Mirrors the
/// distinction `ssh_install_cmd.rs`'s module doc draws between raw
/// pass-through lines and `##AIVPN {...}` marker lines (both remote-script
/// markers, reprinted verbatim, and the CLI's own client-side lifecycle
/// markers) — see that file's doc comment for the full field/step list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallLine {
    /// A plain stdout line with no `##AIVPN ` prefix (or one that has the
    /// prefix but doesn't parse as JSON — treated as raw rather than
    /// dropped, so nothing the remote script prints is ever silently lost).
    Raw(String),
    Marker {
        step: String,
        status: String,
        code: Option<String>,
        msg: Option<String>,
        connection_key: Option<String>,
    },
}

const MARKER_PREFIX: &str = "##AIVPN ";

/// Parses one line of `ssh-install run` stdout into an [`InstallLine`].
/// Never fails — an unparseable `##AIVPN `-prefixed line falls back to
/// [`InstallLine::Raw`] rather than being dropped.
pub fn parse_install_line(line: &str) -> InstallLine {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if let Some(json_str) = trimmed.strip_prefix(MARKER_PREFIX) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
            let step = v
                .get("step")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let status = v
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
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
            return InstallLine::Marker {
                step,
                status,
                code,
                msg,
                connection_key,
            };
        }
    }
    InstallLine::Raw(trimmed.to_string())
}

/// Synthetic terminal line `spawn_install` always sends once the child
/// process itself has exited (in addition to, not instead of, whatever
/// `##AIVPN` markers the process printed along the way) — so the UI has an
/// unambiguous "the subprocess is done" signal even in the pathological
/// case where the process exits with no output at all (binary missing,
/// crash before the first line). Uses the `gui_process` step name, which
/// is deliberately outside the step vocabulary `ssh_install_cmd.rs`
/// documents, so it can never collide with a real remote or CLI marker.
fn gui_process_exit_line(exit_code: i32, msg: Option<&str>) -> InstallLine {
    InstallLine::Marker {
        step: "gui_process".to_string(),
        status: if exit_code == 0 { "ok" } else { "error" }.to_string(),
        code: Some(format!("exit_{exit_code}")),
        msg: msg.map(|s| s.to_string()),
        connection_key: None,
    }
}

/// G-C1: whether a just-parsed marker's `connection_key` should be
/// auto-imported into the key store immediately, replacing the old design
/// where the finished-install screen required a manual "Import profile"
/// click. `true` only when all three hold: the marker actually carries a
/// key (by construction only the terminal `done`/`client_done` marker ever
/// does — see `parse_install_line_client_done_success_with_connection_key`
/// below), its `status` is `"ok"` (defense-in-depth: never auto-add a key
/// from an error-status line even in a hypothetical malformed marker that
/// carries both), and nothing has been imported yet this run (so a
/// duplicate/replayed marker — or the main loop observing the same
/// `InstallLine` twice — can't add the same profile a second time).
pub fn should_auto_import(
    status: &str,
    connection_key: &Option<String>,
    already_imported: bool,
) -> bool {
    !already_imported && status == "ok" && connection_key.is_some()
}

// ── IO drivers — validated against a live/VM SSH server, not unit-tested ──

#[cfg(windows)]
fn no_console_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn no_console_window(_cmd: &mut Command) {}

fn run_capture(client_binary: &Path, args: &[&str]) -> Result<(bool, String, String), String> {
    let mut cmd = Command::new(client_binary);
    cmd.args(args);
    no_console_window(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("Failed to run aivpn-client: {e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Runs `ssh-install script` and `ssh-install script --sha256-only`,
/// returning `(sha256_hex, script_text)` — lets the wizard's "Show script"
/// review step display exactly what will run on the remote host, plus its
/// hash, before the user confirms.
pub fn fetch_script(client_binary: &Path) -> Result<(String, String), String> {
    let (ok, sha_out, sha_err) =
        run_capture(client_binary, &["ssh-install", "script", "--sha256-only"])?;
    if !ok {
        let e = sha_err.trim();
        return Err(if e.is_empty() {
            "ssh-install script --sha256-only failed".to_string()
        } else {
            e.to_string()
        });
    }
    let (ok, script_out, script_err) = run_capture(client_binary, &["ssh-install", "script"])?;
    if !ok {
        let e = script_err.trim();
        return Err(if e.is_empty() {
            "ssh-install script failed".to_string()
        } else {
            e.to_string()
        });
    }
    Ok((sha_out.trim().to_string(), script_out))
}

/// Runs `ssh-install probe --host H --port P --user U` (TOFU step 1) and
/// returns the host key fingerprint (`SHA256:...`) for the caller to show
/// the user before proceeding to [`spawn_install`].
pub fn probe(client_binary: &Path, host: &str, port: u16, user: &str) -> Result<String, String> {
    let port_str = port.to_string();
    let (ok, stdout, stderr) = run_capture(
        client_binary,
        &[
            "ssh-install",
            "probe",
            "--host",
            host,
            "--port",
            &port_str,
            "--user",
            user,
        ],
    )?;
    if !ok {
        let e = stderr.trim();
        return Err(if e.is_empty() {
            "ssh-install probe failed".to_string()
        } else {
            e.to_string()
        });
    }
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|e| format!("Bad probe response: {e}"))?;
    v.get("fingerprint")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Probe response did not include a fingerprint".to_string())
}

/// Runs `ssh-install run` on a background thread, streaming every stdout
/// line (parsed via [`parse_install_line`]) to `tx` as it arrives, and
/// finally a [`gui_process_exit_line`] once the child exits. Safe to call
/// from the egui update loop — never blocks the caller.
///
/// `secret` is the auth secret matching `target.auth` — the SSH password
/// for [`InstallAuth::Password`], or the private key's passphrase for
/// [`InstallAuth::KeyFile`] with `has_passphrase: true` (otherwise
/// ignored). Set via `Command::env`, never argv (see the module doc
/// comment and `ssh_install_cmd.rs`).
pub fn spawn_install(
    client_binary: PathBuf,
    target: InstallTarget,
    secret: Option<String>,
    tx: Sender<InstallLine>,
) {
    std::thread::spawn(move || {
        let args = build_run_args(&target);

        let mut cmd = Command::new(&client_binary);
        cmd.args(&args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        no_console_window(&mut cmd);

        match &target.auth {
            InstallAuth::Password => {
                if let Some(secret) = &secret {
                    cmd.env(SSH_PASSWORD_ENV_VAR, secret);
                }
            }
            InstallAuth::KeyFile { has_passphrase, .. } => {
                if *has_passphrase {
                    if let Some(secret) = &secret {
                        cmd.env(SSH_KEY_PASSPHRASE_ENV_VAR, secret);
                    }
                }
            }
        }

        let mut child: Child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(gui_process_exit_line(
                    1,
                    Some(&format!("Failed to run aivpn-client: {e}")),
                ));
                return;
            }
        };

        // BUG FIX (review): stderr was `Stdio::piped()` but never read. A
        // child that writes more than the OS pipe buffer (~64KB) to stderr
        // (verbose SSH transport errors, tracing output) blocked forever on
        // a full pipe nobody drained — stdout then never reached EOF, the
        // loop below never ended, and the wizard sat on "Installing…"
        // forever with no terminal marker. Drain stderr on its own thread,
        // forwarding non-empty lines to the UI log as Raw lines (stderr is
        // the CLI's log/error channel, never a `##AIVPN` marker stream — so
        // no marker parsing here, a terminal state can only come from
        // stdout or the synthetic `gui_process` line). If the receiver is
        // gone, keep draining without sending so the child can still exit.
        let stderr_drain = child.stderr.take().map(|stderr| {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    let Ok(l) = line else { break };
                    let trimmed = l.trim_end_matches(['\r', '\n']);
                    if trimmed.trim().is_empty() {
                        continue;
                    }
                    // Send failure = wizard closed; keep reading (drain)
                    // so the child never blocks on a full stderr pipe.
                    let _ = tx.send(InstallLine::Raw(trimmed.to_string()));
                }
            })
        });

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        if tx.send(parse_install_line(&l)).is_err() {
                            // Receiver gone (GUI closed the wizard) — stop
                            // reading, but still let the child be reaped
                            // below rather than leaking a zombie process.
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        let status = child.wait();
        // Join AFTER wait() (child exit closes its stderr, ending the drain
        // thread at EOF) and BEFORE the terminal marker below, so no stray
        // stderr line ever arrives after `gui_process`.
        if let Some(h) = stderr_drain {
            let _ = h.join();
        }
        let exit_code = status.as_ref().ok().and_then(|s| s.code()).unwrap_or(-1);
        let ok = matches!(&status, Ok(s) if s.success());
        let msg = match &status {
            Ok(_) => None,
            Err(e) => Some(format!("Failed to wait on aivpn-client: {e}")),
        };
        let _ = tx.send(gui_process_exit_line(
            if ok { 0 } else { exit_code },
            msg.as_deref(),
        ));
    });
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
            auth: InstallAuth::Password,
            mode: InstallModeChoice::Systemd,
            binary_source: BinarySource::Default,
            server_ip: None,
            server_port: None,
            bind_device: true,
        }
    }

    // --- build_run_args -----------------------------------------------------

    #[test]
    fn build_run_args_password_auth_defaults() {
        let target = base_target();
        let args = build_run_args(&target);
        assert_eq!(
            args,
            vec![
                "ssh-install",
                "run",
                "--host",
                "vps.example.com",
                "--port",
                "22",
                "--user",
                "root",
                "--fingerprint",
                "SHA256:abc",
                "--password-env",
                SSH_PASSWORD_ENV_VAR,
                "--mode",
                "systemd",
            ]
        );
    }

    #[test]
    fn build_run_args_bind_device_false_adds_no_device_pubkey() {
        let mut target = base_target();
        target.bind_device = false;
        let args = build_run_args(&target);
        assert!(args.iter().any(|a| a == "--no-device-pubkey"));
    }

    #[test]
    fn build_run_args_bind_device_true_omits_both_device_flags() {
        let target = base_target();
        let args = build_run_args(&target);
        assert!(!args.iter().any(|a| a == "--no-device-pubkey"));
        assert!(!args.iter().any(|a| a == "--device-pubkey"));
    }

    #[test]
    fn build_run_args_key_file_auth_without_passphrase() {
        let mut target = base_target();
        target.auth = InstallAuth::KeyFile {
            path: PathBuf::from("/home/u/.ssh/id_ed25519"),
            has_passphrase: false,
        };
        let args = build_run_args(&target);
        let idx = args.iter().position(|a| a == "--key-file").unwrap();
        assert_eq!(args[idx + 1], "/home/u/.ssh/id_ed25519");
        assert!(!args.iter().any(|a| a == "--key-passphrase-env"));
        assert!(!args.iter().any(|a| a == "--password-env"));
    }

    #[test]
    fn build_run_args_key_file_auth_with_passphrase() {
        let mut target = base_target();
        target.auth = InstallAuth::KeyFile {
            path: PathBuf::from("/home/u/.ssh/id_ed25519"),
            has_passphrase: true,
        };
        let args = build_run_args(&target);
        let idx = args
            .iter()
            .position(|a| a == "--key-passphrase-env")
            .unwrap();
        assert_eq!(args[idx + 1], SSH_KEY_PASSPHRASE_ENV_VAR);
    }

    #[test]
    fn build_run_args_server_ip_and_port_included_when_set() {
        let mut target = base_target();
        target.server_ip = Some("1.2.3.4".to_string());
        target.server_port = Some(18444);
        let args = build_run_args(&target);
        let ip_idx = args.iter().position(|a| a == "--server-ip").unwrap();
        assert_eq!(args[ip_idx + 1], "1.2.3.4");
        let port_idx = args.iter().position(|a| a == "--server-port").unwrap();
        assert_eq!(args[port_idx + 1], "18444");
    }

    #[test]
    fn build_run_args_blank_server_ip_is_omitted() {
        let mut target = base_target();
        target.server_ip = Some("   ".to_string());
        let args = build_run_args(&target);
        assert!(!args.iter().any(|a| a == "--server-ip"));
    }

    #[test]
    fn build_run_args_docker_mode() {
        let mut target = base_target();
        target.mode = InstallModeChoice::Docker;
        let args = build_run_args(&target);
        let idx = args.iter().position(|a| a == "--mode").unwrap();
        assert_eq!(args[idx + 1], "docker");
    }

    #[test]
    fn build_run_args_default_binary_source_omits_both_flags() {
        // BinarySource::Default (the wizard's own default) lets the remote
        // script fetch its own built-in GitHub-Releases build.
        let args = build_run_args(&base_target());
        assert!(!args.iter().any(|a| a == "--binary-file"));
        assert!(!args.iter().any(|a| a == "--binary-url"));
    }

    #[test]
    fn build_run_args_binary_url_included_when_set() {
        let mut target = base_target();
        target.binary_source = BinarySource::Url("https://example.com/aivpn-server".to_string());
        let args = build_run_args(&target);
        let idx = args.iter().position(|a| a == "--binary-url").unwrap();
        assert_eq!(args[idx + 1], "https://example.com/aivpn-server");
        assert!(!args.iter().any(|a| a == "--binary-file"));
    }

    #[test]
    fn build_run_args_blank_binary_url_is_omitted() {
        let mut target = base_target();
        target.binary_source = BinarySource::Url("   ".to_string());
        let args = build_run_args(&target);
        assert!(!args.iter().any(|a| a == "--binary-url"));
    }

    #[test]
    fn build_run_args_binary_file_included_when_set() {
        let mut target = base_target();
        target.binary_source = BinarySource::LocalFile(PathBuf::from("/local/aivpn-server"));
        let args = build_run_args(&target);
        let idx = args.iter().position(|a| a == "--binary-file").unwrap();
        assert_eq!(args[idx + 1], "/local/aivpn-server");
        assert!(!args.iter().any(|a| a == "--binary-url"));
    }

    // --- parse_install_line --------------------------------------------------

    #[test]
    fn parse_install_line_raw_line_passthrough() {
        let line = parse_install_line("Installing packages via apt-get...");
        assert_eq!(
            line,
            InstallLine::Raw("Installing packages via apt-get...".to_string())
        );
    }

    #[test]
    fn parse_install_line_strips_trailing_crlf() {
        let line = parse_install_line("some output\r\n");
        assert_eq!(line, InstallLine::Raw("some output".to_string()));
    }

    #[test]
    fn parse_install_line_marker_with_all_fields() {
        let raw = r#"##AIVPN {"step":"done","status":"ok","code":null,"msg":null,"connection_key":"aivpn://x"}"#;
        let line = parse_install_line(raw);
        assert_eq!(
            line,
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
    fn parse_install_line_marker_port_busy() {
        let raw = r#"##AIVPN {"step":"port_check","status":"info","code":"port_busy","msg":"port 51820 in use","connection_key":null}"#;
        let line = parse_install_line(raw);
        match line {
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
            _ => panic!("expected Marker"),
        }
    }

    #[test]
    fn parse_install_line_malformed_json_falls_back_to_raw() {
        let raw = "##AIVPN {not valid json";
        let line = parse_install_line(raw);
        assert_eq!(line, InstallLine::Raw(raw.to_string()));
    }

    #[test]
    fn parse_install_line_health_check_error_with_code_and_msg() {
        let raw = r#"##AIVPN {"step":"health_check","status":"error","code":"timeout","msg":"server did not come up","connection_key":null}"#;
        let line = parse_install_line(raw);
        match line {
            InstallLine::Marker {
                step, status, code, ..
            } => {
                assert_eq!(step, "health_check");
                assert_eq!(status, "error");
                assert_eq!(code.as_deref(), Some("timeout"));
            }
            _ => panic!("expected Marker"),
        }
    }

    #[test]
    fn parse_install_line_client_done_success_with_connection_key() {
        let raw = r#"##AIVPN {"step":"client_done","status":"ok","code":"exit_0","msg":null,"connection_key":"aivpn://server.example.com:51820?k=abc"}"#;
        let line = parse_install_line(raw);
        match line {
            InstallLine::Marker {
                step,
                status,
                code,
                connection_key,
                ..
            } => {
                assert_eq!(step, "client_done");
                assert_eq!(status, "ok");
                assert_eq!(code.as_deref(), Some("exit_0"));
                assert_eq!(
                    connection_key.as_deref(),
                    Some("aivpn://server.example.com:51820?k=abc")
                );
            }
            _ => panic!("expected Marker"),
        }
    }

    // --- gui_process_exit_line ------------------------------------------------

    #[test]
    fn gui_process_exit_line_zero_is_ok() {
        let line = gui_process_exit_line(0, None);
        match line {
            InstallLine::Marker {
                step, status, code, ..
            } => {
                assert_eq!(step, "gui_process");
                assert_eq!(status, "ok");
                assert_eq!(code.as_deref(), Some("exit_0"));
            }
            _ => panic!("expected Marker"),
        }
    }

    #[test]
    fn gui_process_exit_line_nonzero_is_error_with_msg() {
        let line = gui_process_exit_line(3, Some("boom"));
        match line {
            InstallLine::Marker {
                step,
                status,
                code,
                msg,
                ..
            } => {
                assert_eq!(step, "gui_process");
                assert_eq!(status, "error");
                assert_eq!(code.as_deref(), Some("exit_3"));
                assert_eq!(msg.as_deref(), Some("boom"));
            }
            _ => panic!("expected Marker"),
        }
    }

    // --- spawn_install stderr drain (deadlock regression) ---------------------

    /// Regression test for the undrained-stderr deadlock: a child that
    /// writes far more than the OS pipe buffer (~64KB) to stderr used to
    /// block forever mid-write (nobody read that pipe), so stdout never
    /// reached EOF and `spawn_install`'s thread never sent the terminal
    /// `gui_process` marker. With the drain thread, the child runs to
    /// completion and the marker arrives. Unix-only: builds the fake
    /// "client binary" as a shell script.
    #[cfg(unix)]
    #[test]
    fn spawn_install_survives_stderr_flood_and_reports_exit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "aivpn-win-test-stderr-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-client.sh");
        // ~1MB of stderr (16k lines x 64 chars), one stdout marker, exit 0.
        std::fs::write(
            &script,
            "#!/bin/sh\n\
             i=0\n\
             while [ $i -lt 16000 ]; do\n\
               echo 'stderr noise line 0123456789 0123456789 0123456789 xx' 1>&2\n\
               i=$((i+1))\n\
             done\n\
             echo '##AIVPN {\"step\":\"done\",\"status\":\"ok\",\"connection_key\":null}'\n\
             exit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let target = base_target();
        let (tx, rx) = std::sync::mpsc::channel();
        spawn_install(script.clone(), target, None, tx);

        // The whole run should finish quickly; poll with a hard deadline so
        // a regression fails the test instead of hanging the harness.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut saw_done_marker = false;
        let mut saw_gui_process_ok = false;
        let mut stderr_lines = 0usize;
        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(InstallLine::Marker { step, status, .. }) => {
                    if step == "done" {
                        saw_done_marker = true;
                    }
                    if step == "gui_process" {
                        assert_eq!(status, "ok");
                        saw_gui_process_ok = true;
                        break;
                    }
                }
                Ok(InstallLine::Raw(_)) => stderr_lines += 1,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "spawn_install deadlocked: stderr flood was never drained"
                    );
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("sender dropped without a gui_process terminal marker");
                }
            }
        }
        assert!(saw_done_marker, "stdout marker line was lost");
        assert!(saw_gui_process_ok);
        assert!(
            stderr_lines > 0,
            "stderr lines should be forwarded to the install log"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- should_auto_import (G-C1) --------------------------------------------

    #[test]
    fn should_auto_import_true_for_ok_marker_with_key_first_time() {
        let key = Some("aivpn://server.example.com:51820?k=abc".to_string());
        assert!(should_auto_import("ok", &key, false));
    }

    #[test]
    fn should_auto_import_false_when_already_imported() {
        let key = Some("aivpn://server.example.com:51820?k=abc".to_string());
        assert!(!should_auto_import("ok", &key, true));
    }

    #[test]
    fn should_auto_import_false_without_a_key() {
        assert!(!should_auto_import("ok", &None, false));
    }

    #[test]
    fn should_auto_import_false_for_non_ok_status_even_with_a_key() {
        // Defense-in-depth: the CLI never actually attaches a key to a
        // non-"ok" marker, but the gate must not trust that blindly.
        let key = Some("aivpn://server.example.com:51820?k=abc".to_string());
        assert!(!should_auto_import("error", &key, false));
        assert!(!should_auto_import("info", &key, false));
    }
}
