//! Wave C2b-CLI — desktop CLI bridge to `aivpn_common::ssh_install`'s
//! pure-Rust SSH installer client. Adds the `aivpn-client ssh-install
//! {script,probe,run}` subcommands, gated behind the `ssh-install` feature
//! (see `crate::ssh_install`'s own doc comment / Cargo.toml — it pulls in
//! `russh`/`russh-sftp` and must not bloat the default build).
//!
//! ## `run` stdout streaming contract (for GUI subprocess callers)
//!
//! `aivpn-client ssh-install run` is meant to be spawned as a child process
//! by a GUI (desktop admin panel) that reads its stdout line-by-line:
//!
//! - Every [`ssh_install::InstallEvent::Line`] — i.e. every raw line of the
//!   remote `install-server.sh`'s stdout — is printed **verbatim**. This
//!   includes the remote script's own `##AIVPN {...}` marker lines, which
//!   pass through untouched. [`ssh_install::InstallEvent::Marker`] is the
//!   *same* line, already parsed by [`ssh_install::parse_marker_line`] — it
//!   is intentionally **not** re-printed here, or every remote marker would
//!   appear twice on stdout.
//! - Client-side lifecycle events that have no remote-script equivalent are
//!   surfaced as additional `##AIVPN {...}` marker lines, parseable by the
//!   very same [`ssh_install::parse_marker_line`] the remote markers use:
//!   - [`ssh_install::InstallEvent::Connected`] ->
//!     `{"step":"ssh_connect","status":"ok","msg":"<fingerprint>"}`
//!   - [`ssh_install::InstallEvent::Uploading`] ->
//!     `{"step":"upload","status":"ok","msg":"<what>"}`
//!   - [`ssh_install::InstallEvent::Finished`] ->
//!     `{"step":"client_done","status":"ok"|"error","code":"exit_<N>","connection_key":...}`
//!   - a connect/auth/fingerprint-mismatch failure (never reaches the remote
//!     script at all) ->
//!     `{"step":"ssh_connect","status":"error","code":"...","msg":"..."}`
//!   - no `--device-pubkey` given, `--no-device-pubkey` not passed, and no
//!     local device key exists to default to ->
//!     `{"step":"device_pubkey","status":"info","code":"no_local_device_key"}`
//!     (printed once, before the SSH connection is even attempted; the
//!     install then proceeds without `--device-pubkey`)
//!
//! The process exit code mirrors the remote installer's own exit code
//! (`Finished.exit_code`) when the SSH session made it that far; otherwise
//! (connect/auth/fingerprint failure) it's `1`.

use std::io::Read as _;
use std::path::PathBuf;

use base64::Engine as _;

use crate::ssh_install::{
    self, BinarySource, InstallEvent, InstallMode, InstallParams, SshAuth, SshTarget,
};

#[derive(clap::Subcommand, Debug)]
pub enum SshInstallAction {
    /// Print the embedded install-server.sh (or, with --unit, its systemd
    /// unit template) — lets a caller show the user exactly what will run
    /// before they confirm an install ("paranoid mode" review).
    Script {
        /// Print only the SHA256 (hex) of install-server.sh, nothing else.
        #[arg(long, conflicts_with = "unit")]
        sha256_only: bool,
        /// Print the systemd unit template instead of the installer script.
        #[arg(long)]
        unit: bool,
    },
    /// Connect just far enough to read the remote host's SSH key fingerprint
    /// (TOFU step 1) — no authentication is attempted. On success, prints
    /// exactly one line: `{"fingerprint":"SHA256:..."}`.
    Probe {
        /// Remote host to probe.
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long, default_value = "root")]
        user: String,
    },
    /// Run the remote aivpn-server installer over SSH (TOFU step 2 — pass
    /// the fingerprint the caller already showed the user and got
    /// confirmation for, normally the output of `ssh-install probe`).
    /// Streams progress on stdout — see the module doc comment for the
    /// exact contract.
    Run(RunArgs),
}

#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("auth_method")
        .required(true)
        .multiple(false)
        .args(["password_env", "password_stdin", "key_file"])
))]
pub struct RunArgs {
    /// Remote host to install onto.
    #[arg(long)]
    pub host: String,
    #[arg(long, default_value_t = 22)]
    pub port: u16,
    #[arg(long, default_value = "root")]
    pub user: String,
    /// Host key fingerprint (SHA256:...) already confirmed by the user
    /// (normally the output of `ssh-install probe`). Any mismatch against
    /// the key actually presented is a hard error — never auto-accepted.
    #[arg(long)]
    pub fingerprint: String,

    /// Read the SSH password from this environment variable. Exactly one of
    /// --password-env / --password-stdin / --key-file is required — the
    /// password is never accepted directly as a CLI argument, since argv is
    /// visible to every local user via /proc/<pid>/cmdline.
    #[arg(long, value_name = "VAR")]
    pub password_env: Option<String>,
    /// Read the SSH password as the first line of stdin (trimmed).
    #[arg(long)]
    pub password_stdin: bool,
    /// PEM-encoded private key file to authenticate with (OpenSSH or PKCS#8).
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,
    /// Environment variable holding the private key's passphrase, if any.
    /// Only meaningful together with --key-file.
    #[arg(long, value_name = "VAR", requires = "key_file")]
    pub key_passphrase_env: Option<String>,

    /// Upload this local aivpn-server binary instead of letting the remote
    /// script download one.
    #[arg(long, value_name = "PATH", conflicts_with = "binary_url")]
    pub binary_file: Option<PathBuf>,
    /// Have the remote script download the aivpn-server binary from this URL
    /// instead of its own built-in default (GitHub Releases).
    #[arg(long, value_name = "URL")]
    pub binary_url: Option<String>,

    /// Value passed through to install-server.sh --server-ip.
    #[arg(long)]
    pub server_ip: Option<String>,
    /// Value passed through to install-server.sh --port.
    #[arg(long)]
    pub server_port: Option<u16>,
    /// Install mode: systemd (default) or docker.
    #[arg(long, value_enum, default_value = "systemd")]
    pub mode: InstallModeArg,
    /// Base64-encoded X25519 device public key to bind the created client to
    /// (see `aivpn-server add --device-pubkey`). Defaults to this machine's
    /// own local device key (~/.config/aivpn/device.key) if one already
    /// exists; pass --no-device-pubkey to skip that lookup entirely and
    /// install without device binding.
    #[arg(long, value_name = "B64", conflicts_with = "no_device_pubkey")]
    pub device_pubkey: Option<String>,
    /// Never pass --device-pubkey, even if a local device key exists.
    #[arg(long, default_value_t = false)]
    pub no_device_pubkey: bool,
    /// Extra argv token forwarded verbatim to install-server.sh. May be
    /// repeated.
    #[arg(long = "extra-arg")]
    pub extra_args: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum InstallModeArg {
    Systemd,
    Docker,
}

// --- pure helpers (unit-tested below) --------------------------------------

/// Which single auth method [`RunArgs`]' `--password-env` /
/// `--password-stdin` / `--key-file` flags select — the flags themselves are
/// mutually exclusive and required via the `auth_method` clap group above,
/// so in practice exactly one of these is ever produced from real CLI input.
/// Kept separate from the actual env-var/stdin/file reads (which are IO, and
/// live in [`run`]) so the *selection* logic is pure and unit-testable.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthMethodChoice {
    PasswordEnv(String),
    PasswordStdin,
    KeyFile(PathBuf, Option<String>),
}

/// Pure selection logic mirroring the `auth_method` clap group: exactly one
/// of `password_env` / `password_stdin` / `key_file` must be set. Normally
/// unreachable in practice (clap itself rejects zero or multiple before this
/// runs), but kept as an explicit, testable invariant check rather than an
/// `unreachable!()` so a future change to the clap group can't silently
/// reintroduce an ambiguous state.
pub fn resolve_auth_choice(args: &RunArgs) -> Result<AuthMethodChoice, String> {
    let selected = [
        args.password_env.is_some(),
        args.password_stdin,
        args.key_file.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if selected == 0 {
        return Err(
            "exactly one of --password-env, --password-stdin, --key-file is required".to_string(),
        );
    }
    if selected > 1 {
        return Err(
            "--password-env, --password-stdin, --key-file are mutually exclusive".to_string(),
        );
    }
    if let Some(var) = &args.password_env {
        return Ok(AuthMethodChoice::PasswordEnv(var.clone()));
    }
    if args.password_stdin {
        return Ok(AuthMethodChoice::PasswordStdin);
    }
    if let Some(path) = &args.key_file {
        return Ok(AuthMethodChoice::KeyFile(
            path.clone(),
            args.key_passphrase_env.clone(),
        ));
    }
    unreachable!("selected == 1 but none of the three branches matched")
}

/// Already-resolved inputs for [`build_install_params`] — every env-var /
/// stdin / file read that [`RunArgs`] implies has already happened by the
/// time this is constructed, so the mapping into [`InstallParams`] itself
/// stays pure and IO-free.
pub struct ResolvedRunInputs {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub fingerprint: String,
    pub password: Option<String>,
    pub key_pem: Option<String>,
    pub key_passphrase: Option<String>,
    pub binary_file: Option<PathBuf>,
    pub binary_url: Option<String>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub mode: InstallModeArg,
    pub device_pubkey_b64: Option<String>,
    pub extra_args: Vec<String>,
}

/// Pure mapping from already-resolved CLI inputs to [`InstallParams`]. Split
/// out from [`run`] so the argument-to-params logic is unit-testable without
/// touching the environment, stdin, or the filesystem.
pub fn build_install_params(inputs: ResolvedRunInputs) -> Result<InstallParams, String> {
    let auth = match (inputs.password, inputs.key_pem) {
        (Some(password), None) => SshAuth::Password(password),
        (None, Some(pem)) => SshAuth::PrivateKey {
            pem,
            passphrase: inputs.key_passphrase,
        },
        (None, None) => {
            return Err(
                "internal error: no auth method resolved (expected exactly one of \
                 --password-env/--password-stdin/--key-file)"
                    .to_string(),
            )
        }
        (Some(_), Some(_)) => {
            return Err("internal error: more than one auth method resolved".to_string())
        }
    };

    let binary = match (inputs.binary_file, inputs.binary_url) {
        (Some(path), None) => BinarySource::LocalFile(path),
        (None, Some(url)) => BinarySource::Url(url),
        (None, None) => BinarySource::Default,
        (Some(_), Some(_)) => {
            return Err("--binary-file and --binary-url are mutually exclusive".to_string())
        }
    };

    let mode = match inputs.mode {
        InstallModeArg::Systemd => InstallMode::Systemd,
        InstallModeArg::Docker => InstallMode::Docker,
    };

    Ok(InstallParams {
        target: SshTarget {
            host: inputs.host,
            port: inputs.port,
            user: inputs.user,
        },
        auth,
        expected_fingerprint: inputs.fingerprint,
        binary,
        server_ip: inputs.server_ip,
        server_port: inputs.server_port,
        mode,
        device_pubkey_b64: inputs.device_pubkey_b64,
        extra_args: inputs.extra_args,
    })
}

/// Builds one `##AIVPN {...}` client-side marker line, using serde_json for
/// every field so caller-influenced strings (fingerprints, upload
/// descriptions, error messages) can never corrupt the JSON. Round-trips
/// through [`ssh_install::parse_marker_line`] by construction (same shape as
/// [`AivpnMarker`]).
fn client_marker_line(
    step: &str,
    status: &str,
    code: Option<&str>,
    msg: Option<&str>,
    connection_key: Option<&str>,
) -> String {
    let value = serde_json::json!({
        "step": step,
        "status": status,
        "code": code,
        "msg": msg,
        "connection_key": connection_key,
    });
    format!("##AIVPN {value}")
}

/// Maps a single [`InstallEvent`] to the line printed to stdout by `run`, or
/// `None` when that event type is never printed on its own. Pure — no IO —
/// see the module doc comment for the full streaming contract this
/// implements.
pub fn event_to_line(ev: &InstallEvent) -> Option<String> {
    match ev {
        InstallEvent::Connected { fingerprint } => Some(client_marker_line(
            "ssh_connect",
            "ok",
            None,
            Some(fingerprint),
            None,
        )),
        InstallEvent::Uploading { what } => {
            Some(client_marker_line("upload", "ok", None, Some(what), None))
        }
        InstallEvent::Line(line) => Some(line.clone()),
        // The remote script's own marker was already reprinted verbatim via
        // `Line` above (`run_install` reports both for every marker line) —
        // printing it again here would duplicate every ##AIVPN line on
        // stdout.
        InstallEvent::Marker(_) => None,
        InstallEvent::Finished {
            exit_code,
            connection_key,
        } => {
            let status = if *exit_code == 0 { "ok" } else { "error" };
            Some(client_marker_line(
                "client_done",
                status,
                Some(&format!("exit_{exit_code}")),
                None,
                connection_key.as_deref(),
            ))
        }
    }
}

/// `##AIVPN {"step":"device_pubkey","status":"info","code":"no_local_device_key"}`
/// — printed once when `--device-pubkey` wasn't given, `--no-device-pubkey`
/// wasn't passed, and no local device key exists to default to.
fn no_local_device_key_marker_line() -> String {
    client_marker_line(
        "device_pubkey",
        "info",
        Some("no_local_device_key"),
        None,
        None,
    )
}

/// `##AIVPN {"step":"ssh_connect","status":"error",...}` for a connect/auth/
/// fingerprint-mismatch failure that never reaches the remote script at all.
fn connect_error_marker_line(err: &ssh_install::SshInstallError) -> String {
    let code = match err {
        ssh_install::SshInstallError::HostKeyMismatch { .. } => "fingerprint_mismatch",
        ssh_install::SshInstallError::AuthFailed => "auth_failed",
        _ => "connect_failed",
    };
    let msg = err.to_string();
    client_marker_line("ssh_connect", "error", Some(code), Some(&msg), None)
}

/// Reads the local device X25519 keypair from `~/.config/aivpn/device.key`
/// (same file/format `load_or_generate_static_keypair` in
/// `crates/aivpn-client/src/client.rs:3933` uses for VPN device binding) and
/// returns its public key, base64 (STANDARD) encoded. Deliberately does
/// **not** generate a new key if none exists — unlike the VPN connect path,
/// `ssh-install run` must never have the side effect of creating a device
/// key just because `--device-pubkey`/`--no-device-pubkey` were both
/// omitted; a missing key here just means the install proceeds without
/// device binding (see [`no_local_device_key_marker_line`]).
pub fn local_device_pubkey_b64() -> Option<String> {
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(home_var)?;
    let path = std::path::Path::new(&home)
        .join(".config")
        .join("aivpn")
        .join("device.key");
    let bytes = std::fs::read(&path).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let kp = aivpn_common::crypto::KeyPair::from_private_key(arr);
    Some(base64::engine::general_purpose::STANDARD.encode(kp.public_key_bytes()))
}

// --- command drivers (IO — not unit-tested; validated against a live/VM SSH
// server, same as `ssh_install` itself) --------------------------------------

/// Runs the given [`SshInstallAction`], printing to stdout/stderr per the
/// module doc comment, and returns the process exit code.
pub async fn run(action: SshInstallAction) -> i32 {
    match action {
        SshInstallAction::Script { sha256_only, unit } => {
            if sha256_only {
                println!("{}", ssh_install::installer_script_sha256_hex());
            } else if unit {
                println!("{}", ssh_install::systemd_unit());
            } else {
                println!("{}", ssh_install::installer_script());
            }
            0
        }
        SshInstallAction::Probe { host, port, user } => {
            let target = SshTarget { host, port, user };
            match ssh_install::probe_host_fingerprint(&target).await {
                Ok(fingerprint) => {
                    println!("{}", serde_json::json!({ "fingerprint": fingerprint }));
                    0
                }
                Err(e) => {
                    eprintln!("ssh-install probe failed: {e}");
                    1
                }
            }
        }
        SshInstallAction::Run(args) => run_install_cmd(args).await,
    }
}

async fn run_install_cmd(args: RunArgs) -> i32 {
    let auth_choice = match resolve_auth_choice(&args) {
        Ok(choice) => choice,
        Err(e) => {
            eprintln!("ssh-install run: {e}");
            return 1;
        }
    };

    let (password, key_pem, key_passphrase) = match auth_choice {
        AuthMethodChoice::PasswordEnv(var) => match std::env::var(&var) {
            Ok(v) => (Some(v), None, None),
            Err(_) => {
                eprintln!("ssh-install run: environment variable {var} is not set");
                return 1;
            }
        },
        AuthMethodChoice::PasswordStdin => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("ssh-install run: failed to read password from stdin: {e}");
                return 1;
            }
            let password = buf.lines().next().unwrap_or("").trim().to_string();
            (Some(password), None, None)
        }
        AuthMethodChoice::KeyFile(path, passphrase_env) => {
            let pem = match std::fs::read_to_string(&path) {
                Ok(pem) => pem,
                Err(e) => {
                    eprintln!(
                        "ssh-install run: failed to read --key-file {}: {e}",
                        path.display()
                    );
                    return 1;
                }
            };
            let passphrase = match passphrase_env {
                Some(var) => match std::env::var(&var) {
                    Ok(v) => Some(v),
                    Err(_) => {
                        eprintln!(
                            "ssh-install run: environment variable {var} (--key-passphrase-env) is not set"
                        );
                        return 1;
                    }
                },
                None => None,
            };
            (None, Some(pem), passphrase)
        }
    };

    let device_pubkey_b64 = if args.no_device_pubkey {
        None
    } else if let Some(explicit) = args.device_pubkey.clone() {
        Some(explicit)
    } else {
        match local_device_pubkey_b64() {
            Some(pubkey) => Some(pubkey),
            None => {
                println!("{}", no_local_device_key_marker_line());
                None
            }
        }
    };

    let inputs = ResolvedRunInputs {
        host: args.host,
        port: args.port,
        user: args.user,
        fingerprint: args.fingerprint,
        password,
        key_pem,
        key_passphrase,
        binary_file: args.binary_file,
        binary_url: args.binary_url,
        server_ip: args.server_ip,
        server_port: args.server_port,
        mode: args.mode,
        device_pubkey_b64,
        extra_args: args.extra_args,
    };

    let params = match build_install_params(inputs) {
        Ok(params) => params,
        Err(e) => {
            eprintln!("ssh-install run: {e}");
            return 1;
        }
    };

    match ssh_install::run_install(params, |ev| {
        if let Some(line) = event_to_line(&ev) {
            println!("{line}");
        }
    })
    .await
    {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("ssh-install run failed: {e}");
            println!("{}", connect_error_marker_line(&e));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> RunArgs {
        RunArgs {
            host: "vps.example.com".to_string(),
            port: 22,
            user: "root".to_string(),
            fingerprint: "SHA256:abc".to_string(),
            password_env: None,
            password_stdin: false,
            key_file: None,
            key_passphrase_env: None,
            binary_file: None,
            binary_url: None,
            server_ip: None,
            server_port: None,
            mode: InstallModeArg::Systemd,
            device_pubkey: None,
            no_device_pubkey: false,
            extra_args: Vec::new(),
        }
    }

    fn base_inputs() -> ResolvedRunInputs {
        ResolvedRunInputs {
            host: "vps.example.com".to_string(),
            port: 22,
            user: "root".to_string(),
            fingerprint: "SHA256:abc".to_string(),
            password: None,
            key_pem: None,
            key_passphrase: None,
            binary_file: None,
            binary_url: None,
            server_ip: None,
            server_port: None,
            mode: InstallModeArg::Systemd,
            device_pubkey_b64: None,
            extra_args: Vec::new(),
        }
    }

    // --- resolve_auth_choice -------------------------------------------------

    #[test]
    fn resolve_auth_choice_password_env() {
        let mut args = base_args();
        args.password_env = Some("AIVPN_SSH_PASSWORD".to_string());
        assert_eq!(
            resolve_auth_choice(&args),
            Ok(AuthMethodChoice::PasswordEnv(
                "AIVPN_SSH_PASSWORD".to_string()
            ))
        );
    }

    #[test]
    fn resolve_auth_choice_password_stdin() {
        let mut args = base_args();
        args.password_stdin = true;
        assert_eq!(
            resolve_auth_choice(&args),
            Ok(AuthMethodChoice::PasswordStdin)
        );
    }

    #[test]
    fn resolve_auth_choice_key_file_with_passphrase() {
        let mut args = base_args();
        args.key_file = Some(PathBuf::from("/tmp/id_ed25519"));
        args.key_passphrase_env = Some("AIVPN_KEY_PASS".to_string());
        assert_eq!(
            resolve_auth_choice(&args),
            Ok(AuthMethodChoice::KeyFile(
                PathBuf::from("/tmp/id_ed25519"),
                Some("AIVPN_KEY_PASS".to_string())
            ))
        );
    }

    #[test]
    fn resolve_auth_choice_none_selected_is_error() {
        let args = base_args();
        assert!(resolve_auth_choice(&args).is_err());
    }

    #[test]
    fn resolve_auth_choice_multiple_selected_is_error() {
        let mut args = base_args();
        args.password_env = Some("VAR".to_string());
        args.password_stdin = true;
        assert!(resolve_auth_choice(&args).is_err());
    }

    // --- build_install_params -------------------------------------------------

    #[test]
    fn build_install_params_password_auth_defaults() {
        let mut inputs = base_inputs();
        inputs.password = Some("hunter2".to_string());
        let params = build_install_params(inputs).expect("should build");

        assert_eq!(params.target.host, "vps.example.com");
        assert_eq!(params.target.port, 22);
        assert_eq!(params.target.user, "root");
        assert_eq!(params.expected_fingerprint, "SHA256:abc");
        assert!(matches!(params.auth, SshAuth::Password(ref p) if p == "hunter2"));
        assert!(matches!(params.binary, BinarySource::Default));
        assert_eq!(params.mode, InstallMode::Systemd);
        assert_eq!(params.device_pubkey_b64, None);
        assert!(params.extra_args.is_empty());
    }

    #[test]
    fn build_install_params_key_pem_auth_with_passphrase() {
        let mut inputs = base_inputs();
        inputs.key_pem = Some("-----BEGIN KEY-----".to_string());
        inputs.key_passphrase = Some("p4ss".to_string());
        let params = build_install_params(inputs).expect("should build");

        match params.auth {
            SshAuth::PrivateKey { pem, passphrase } => {
                assert_eq!(pem, "-----BEGIN KEY-----");
                assert_eq!(passphrase.as_deref(), Some("p4ss"));
            }
            _ => panic!("expected PrivateKey auth"),
        }
    }

    #[test]
    fn build_install_params_no_auth_resolved_is_error() {
        let inputs = base_inputs();
        assert!(build_install_params(inputs).is_err());
    }

    #[test]
    fn build_install_params_binary_file_and_url() {
        let mut inputs = base_inputs();
        inputs.password = Some("x".to_string());
        inputs.binary_file = Some(PathBuf::from("/local/aivpn-server"));
        let params = build_install_params(inputs).expect("should build");
        assert!(
            matches!(params.binary, BinarySource::LocalFile(ref p) if p == std::path::Path::new("/local/aivpn-server"))
        );

        let mut inputs = base_inputs();
        inputs.password = Some("x".to_string());
        inputs.binary_url = Some("https://example.com/bin".to_string());
        let params = build_install_params(inputs).expect("should build");
        assert!(
            matches!(params.binary, BinarySource::Url(ref u) if u == "https://example.com/bin")
        );
    }

    #[test]
    fn build_install_params_binary_file_and_url_both_set_is_error() {
        let mut inputs = base_inputs();
        inputs.password = Some("x".to_string());
        inputs.binary_file = Some(PathBuf::from("/local/aivpn-server"));
        inputs.binary_url = Some("https://example.com/bin".to_string());
        assert!(build_install_params(inputs).is_err());
    }

    #[test]
    fn build_install_params_docker_mode_server_ip_port_device_pubkey_extra_args() {
        let mut inputs = base_inputs();
        inputs.password = Some("x".to_string());
        inputs.mode = InstallModeArg::Docker;
        inputs.server_ip = Some("1.2.3.4".to_string());
        inputs.server_port = Some(18444);
        inputs.device_pubkey_b64 = Some("QUJDRA==".to_string());
        inputs.extra_args = vec!["--foo".to_string(), "bar".to_string()];
        let params = build_install_params(inputs).expect("should build");

        assert_eq!(params.mode, InstallMode::Docker);
        assert_eq!(params.server_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(params.server_port, Some(18444));
        assert_eq!(params.device_pubkey_b64.as_deref(), Some("QUJDRA=="));
        assert_eq!(
            params.extra_args,
            vec!["--foo".to_string(), "bar".to_string()]
        );
    }

    // --- event_to_line --------------------------------------------------------

    #[test]
    fn event_to_line_line_passes_through_verbatim() {
        let ev = InstallEvent::Line("Installing packages via apt-get...".to_string());
        assert_eq!(
            event_to_line(&ev),
            Some("Installing packages via apt-get...".to_string())
        );
    }

    #[test]
    fn event_to_line_line_of_a_remote_marker_also_passes_through_verbatim() {
        // run_install reports the remote ##AIVPN line via BOTH Line and
        // Marker — Line must still print it so the GUI sees every remote
        // marker exactly once (via Line), never zero or two times.
        let raw = r#"##AIVPN {"step":"done","status":"ok","connection_key":"aivpn://x"}"#;
        let ev = InstallEvent::Line(raw.to_string());
        assert_eq!(event_to_line(&ev), Some(raw.to_string()));
    }

    #[test]
    fn event_to_line_marker_is_none() {
        let marker = ssh_install::AivpnMarker {
            step: "done".to_string(),
            status: "ok".to_string(),
            code: None,
            msg: None,
            connection_key: Some("aivpn://x".to_string()),
            raw: serde_json::json!({}),
        };
        assert_eq!(event_to_line(&InstallEvent::Marker(marker)), None);
    }

    #[test]
    fn event_to_line_connected_is_a_parseable_marker() {
        let ev = InstallEvent::Connected {
            fingerprint: "SHA256:abc".to_string(),
        };
        let line = event_to_line(&ev).expect("Connected must print a line");
        let marker = ssh_install::parse_marker_line(&line).expect("must parse as a marker");
        assert_eq!(marker.step, "ssh_connect");
        assert_eq!(marker.status, "ok");
        assert_eq!(marker.msg.as_deref(), Some("SHA256:abc"));
    }

    #[test]
    fn event_to_line_uploading_is_a_parseable_marker() {
        let ev = InstallEvent::Uploading {
            what: "masks/".to_string(),
        };
        let line = event_to_line(&ev).expect("Uploading must print a line");
        let marker = ssh_install::parse_marker_line(&line).expect("must parse as a marker");
        assert_eq!(marker.step, "upload");
        assert_eq!(marker.status, "ok");
        assert_eq!(marker.msg.as_deref(), Some("masks/"));
    }

    #[test]
    fn event_to_line_finished_ok_is_a_parseable_marker() {
        let ev = InstallEvent::Finished {
            exit_code: 0,
            connection_key: Some("aivpn://x".to_string()),
        };
        let line = event_to_line(&ev).expect("Finished must print a line");
        let marker = ssh_install::parse_marker_line(&line).expect("must parse as a marker");
        assert_eq!(marker.step, "client_done");
        assert_eq!(marker.status, "ok");
        assert_eq!(marker.code.as_deref(), Some("exit_0"));
        assert_eq!(marker.connection_key.as_deref(), Some("aivpn://x"));
    }

    #[test]
    fn event_to_line_finished_error_is_a_parseable_marker() {
        let ev = InstallEvent::Finished {
            exit_code: 3,
            connection_key: None,
        };
        let line = event_to_line(&ev).expect("Finished must print a line");
        let marker = ssh_install::parse_marker_line(&line).expect("must parse as a marker");
        assert_eq!(marker.step, "client_done");
        assert_eq!(marker.status, "error");
        assert_eq!(marker.code.as_deref(), Some("exit_3"));
        assert_eq!(marker.connection_key, None);
    }

    // --- client_marker_line / info / error markers ----------------------------

    #[test]
    fn no_local_device_key_marker_line_is_parseable() {
        let line = no_local_device_key_marker_line();
        let marker = ssh_install::parse_marker_line(&line).expect("must parse as a marker");
        assert_eq!(marker.step, "device_pubkey");
        assert_eq!(marker.status, "info");
        assert_eq!(marker.code.as_deref(), Some("no_local_device_key"));
    }

    #[test]
    fn connect_error_marker_line_host_key_mismatch_is_parseable() {
        let err = ssh_install::SshInstallError::HostKeyMismatch {
            expected: "SHA256:aaa".to_string(),
            got: "SHA256:bbb".to_string(),
        };
        let line = connect_error_marker_line(&err);
        let marker = ssh_install::parse_marker_line(&line).expect("must parse as a marker");
        assert_eq!(marker.step, "ssh_connect");
        assert_eq!(marker.status, "error");
        assert_eq!(marker.code.as_deref(), Some("fingerprint_mismatch"));
        assert!(marker.msg.is_some());
    }

    #[test]
    fn connect_error_marker_line_auth_failed_is_parseable() {
        let err = ssh_install::SshInstallError::AuthFailed;
        let line = connect_error_marker_line(&err);
        let marker = ssh_install::parse_marker_line(&line).expect("must parse as a marker");
        assert_eq!(marker.code.as_deref(), Some("auth_failed"));
    }

    // --- local_device_pubkey_b64 ------------------------------------------------

    #[test]
    fn local_device_pubkey_b64_reads_existing_key() {
        let _guard = crate::TEST_HOME_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let old = std::env::var_os(home_var);

        let tmp_home = std::env::temp_dir().join(format!(
            "aivpn_ssh_install_cmd_test_home_{}_{}",
            std::process::id(),
            base_args().host.len() // cheap unique-ish suffix source
        ));
        let cfg_dir = tmp_home.join(".config").join("aivpn");
        std::fs::create_dir_all(&cfg_dir).expect("create tmp config dir");
        let key_bytes = [7u8; 32];
        std::fs::write(cfg_dir.join("device.key"), key_bytes).expect("write tmp device.key");
        std::env::set_var(home_var, &tmp_home);

        let expected_kp = aivpn_common::crypto::KeyPair::from_private_key(key_bytes);
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_kp.public_key_bytes());

        let result = local_device_pubkey_b64();

        match old {
            Some(v) => std::env::set_var(home_var, v),
            None => std::env::remove_var(home_var),
        }
        std::fs::remove_dir_all(&tmp_home).ok();

        assert_eq!(result, Some(expected_b64));
    }

    #[test]
    fn local_device_pubkey_b64_none_when_key_missing() {
        let _guard = crate::TEST_HOME_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let old = std::env::var_os(home_var);

        let tmp_home = std::env::temp_dir().join(format!(
            "aivpn_ssh_install_cmd_test_nohome_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp_home).ok();
        std::env::set_var(home_var, &tmp_home);

        let result = local_device_pubkey_b64();

        match old {
            Some(v) => std::env::set_var(home_var, v),
            None => std::env::remove_var(home_var),
        }
        std::fs::remove_dir_all(&tmp_home).ok();

        assert_eq!(result, None);
    }
}
