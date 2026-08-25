//! Wave C2a/C2b — pure-Rust SSH client for the in-app aivpn-server installer,
//! plus the embedded installer bundle and high-level orchestration on top of
//! it.
//!
//! Lets a caller (desktop client, or a mobile FFI core — this module lives
//! in `aivpn-common` specifically so both can use it) connect to a remote
//! VPS over SSH (password or private key), verify the host key via TOFU
//! (the caller decides accept/reject given the SHA256 fingerprint — we
//! never auto-accept), upload the installer bundle over SFTP, and run
//! `install-server.sh` remotely while streaming its stdout line-by-line.
//! `install-server.sh` emits progress as `##AIVPN {json}` marker lines on
//! stdout; [`parse_marker_line`] turns those into structured [`AivpnMarker`]
//! events for the UI.
//!
//! [`bundle`] embeds `deploy/install-server.sh`, its systemd unit template,
//! and the shipped `assets/masks/*.json` profiles into the binary at
//! compile time, so a caller never needs a full repo checkout alongside it
//! to drive an install. [`run_install`] ties everything together: connect
//! (with a mandatory, pre-confirmed TOFU fingerprint check), upload the
//! bundle, run the script, and report structured [`InstallEvent`]s.
//!
//! Gated behind the `ssh-install` feature so the default `aivpn-common`
//! build (and every dependent that doesn't opt in — including the mobile
//! FFI cores) never pull in `russh`/`russh-sftp`.
//!
//! Live SSH connect/auth/upload/exec paths require a real SSH server and are
//! NOT unit-tested here — they're validated against a QEMU VM stand
//! separately. Only the pure, IO-free helpers ([`parse_marker_line`], the
//! fingerprint formatter, the embedded bundle contents, and
//! [`build_install_argv`]'s shell-quoting) are unit-tested in this module.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::RngCore;
use russh::client;
use russh::keys::ssh_key;
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileAttributes;
use tokio::io::AsyncWriteExt;

/// SSH connection target.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
}

/// Supported authentication methods.
pub enum SshAuth {
    Password(String),
    PrivateKey {
        /// PEM-encoded Ed25519 or ECDSA private key (OpenSSH or PKCS#8
        /// format). RSA keys are deliberately unsupported until the
        /// upstream implementation has a constant-time private-key path.
        pem: String,
        passphrase: Option<String>,
    },
}

/// Server host key, surfaced to the caller for TOFU accept/reject decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    /// OpenSSH-style `SHA256:<base64>` fingerprint.
    pub fingerprint_sha256: String,
    /// Wire algorithm name, e.g. `ssh-ed25519`.
    pub key_type: String,
}

/// Errors surfaced by the SSH-install client.
#[derive(Debug, thiserror::Error)]
pub enum SshInstallError {
    #[error("ssh protocol error: {0}")]
    Ssh(#[from] russh::Error),
    #[error("ssh key error: {0}")]
    Key(#[from] russh::keys::Error),
    #[error("sftp error: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ssh authentication failed for the given credentials")]
    AuthFailed,
    /// The host key presented during [`connect`] didn't match the
    /// caller-supplied, already-confirmed [`InstallParams::expected_fingerprint`].
    /// Surfaced instead of [`SshInstallError::Ssh`]'s generic `UnknownKey` so
    /// callers can show a specific "this is not the host you confirmed"
    /// message rather than a generic protocol error.
    #[error("ssh host key mismatch: expected {expected}, got {got}")]
    HostKeyMismatch { expected: String, got: String },
    /// [`install_params_from_json`] input is malformed — either not valid
    /// JSON, missing a required field, or an unrecognized `auth.type` /
    /// `binary.type` / `mode` tag. `serde_json::Error`'s own message already
    /// names the offending field/variant, so it's surfaced as-is rather than
    /// wrapped further.
    #[error("invalid install params json: {0}")]
    Json(#[from] serde_json::Error),
    /// The remote command's channel closed without ever reporting an exit
    /// status — the TCP connection dropped mid-command or the remote process
    /// was killed by a signal. Surfaced as a hard error so an interrupted
    /// install is never mistaken for a successful one (it used to be
    /// silently treated as exit code 0).
    #[error("remote command ended without an exit status ({0})")]
    Interrupted(String),
    /// [`run_install`] exceeded its overall time budget
    /// ([`INSTALL_OVERALL_TIMEOUT`]) — almost always a remote step hung while
    /// sshd stayed responsive (apt waiting on a dpkg lock, a stalled
    /// download), which transport keepalives can't catch. The value is the
    /// budget in seconds.
    #[error("install timed out after {0}s overall")]
    Timeout(u64),
}

pub type Result<T> = std::result::Result<T, SshInstallError>;

/// Keepalive cadence for the SSH transport once authenticated. Together with
/// russh's default `keepalive_max` (3) this declares the peer dead after ~2
/// minutes of silence — what catches a half-open TCP connection (dead NAT,
/// suspended VPS) while a remote command is running, instead of waiting on
/// `channel.wait()` forever.
const SSH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Transport-level inactivity backstop. Guards the phases keepalives don't
/// cover (pre-auth handshake, authentication) and a peer that goes fully
/// silent. Deliberately generous: apt/curl inside the installer can legally
/// stay silent for minutes while downloading (the install script redirects
/// apt output away), and russh resets this timer on any received data.
const SSH_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(300);

/// Overall time budget for one [`run_install`] call (connect + upload +
/// remote installer run). The transport timeouts above only fire when the
/// server stops answering entirely; a remote step that hangs forever while
/// sshd stays responsive (apt stuck on a dpkg lock, a stalled download) is
/// indistinguishable from a slow-but-healthy install at the transport level,
/// so it needs this outer bound. 30 minutes comfortably covers a slow-VPS
/// install (package install + binary download, docker mode included).
const INSTALL_OVERALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Builds the `russh` client config used by [`connect`]. Split out into a
/// pure function so the timeout/keepalive policy is unit-testable without a
/// live SSH server.
fn ssh_client_config() -> client::Config {
    client::Config {
        keepalive_interval: Some(SSH_KEEPALIVE_INTERVAL),
        inactivity_timeout: Some(SSH_INACTIVITY_TIMEOUT),
        ..client::Config::default()
    }
}

/// Formats a public key's SHA256 fingerprint the same way OpenSSH does
/// (`SHA256:<base64, no padding>`). Pure — no IO, safe to unit-test with a
/// fixed key vector.
pub fn format_fingerprint_sha256(public_key: &ssh_key::PublicKey) -> String {
    format!("{}", public_key.fingerprint(ssh_key::HashAlg::Sha256))
}

fn host_key_of(public_key: &ssh_key::PublicKey) -> HostKey {
    HostKey {
        fingerprint_sha256: format_fingerprint_sha256(public_key),
        key_type: public_key.algorithm().to_string(),
    }
}

/// `russh::client::Handler` that hands the server host key to a
/// caller-supplied TOFU callback. Returning `false` from the callback makes
/// the underlying `russh::client::connect()` call fail with
/// `russh::Error::UnknownKey` — we never auto-accept an unverified key.
struct TofuHandler {
    verify: Option<Box<dyn FnOnce(&HostKey) -> bool + Send>>,
}

impl client::Handler for TofuHandler {
    type Error = SshInstallError;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let host_key = host_key_of(server_public_key);
        // `check_server_key` is only ever invoked once per connection (during
        // the initial key exchange), so `take()` always finds `Some` here.
        let verify = self.verify.take();
        Ok(verify.map(|f| f(&host_key)).unwrap_or(false))
    }
}

/// An authenticated SSH session with an SFTP subsystem ready for use.
pub struct SshSession {
    handle: client::Handle<TofuHandler>,
    sftp: SftpSession,
}

/// Connects to `target`, verifies the host key via `verify` (TOFU — the
/// callback decides accept/reject given the fingerprint; a `false` return
/// aborts the connection), authenticates via `auth`, and opens an SFTP
/// subsystem ready for [`SshSession::upload_file`] / [`SshSession::upload_dir`].
pub async fn connect(
    target: &SshTarget,
    auth: &SshAuth,
    verify: impl FnOnce(&HostKey) -> bool + Send + 'static,
) -> Result<SshSession> {
    let config = Arc::new(ssh_client_config());
    let handler = TofuHandler {
        verify: Some(Box::new(verify)),
    };
    let mut handle = client::connect(config, (target.host.as_str(), target.port), handler).await?;

    let authenticated = match auth {
        SshAuth::Password(password) => handle
            .authenticate_password(target.user.clone(), password.clone())
            .await?
            .success(),
        SshAuth::PrivateKey { pem, passphrase } => {
            let key_pair = russh::keys::decode_secret_key(pem, passphrase.as_deref())?;
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg);
            handle
                .authenticate_publickey(target.user.clone(), key)
                .await?
                .success()
        }
    };
    if !authenticated {
        return Err(SshInstallError::AuthFailed);
    }

    let sftp_channel = handle.channel_open_session().await?;
    sftp_channel.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(sftp_channel.into_stream()).await?;

    Ok(SshSession { handle, sftp })
}

/// Only the permission bits are touched — uid/gid/size/atime/mtime are left
/// untouched so `set_metadata` doesn't fail (or silently attempt a chown) for
/// a non-root SSH login user.
fn permissions_only(mode: u32) -> FileAttributes {
    FileAttributes {
        size: None,
        uid: None,
        user: None,
        gid: None,
        group: None,
        permissions: Some(mode),
        atime: None,
        mtime: None,
    }
}

#[cfg(unix)]
fn local_file_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn local_file_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

impl SshSession {
    /// Uploads `local_bytes` to `remote_path` over SFTP and chmods it to `mode`.
    pub async fn upload_file(
        &self,
        local_bytes: &[u8],
        remote_path: &str,
        mode: u32,
    ) -> Result<()> {
        let mut file = self.sftp.create(remote_path).await?;
        file.write_all(local_bytes).await?;
        file.flush().await?;
        drop(file);
        self.sftp
            .set_metadata(remote_path, permissions_only(mode))
            .await?;
        Ok(())
    }

    /// Recursively uploads `local_dir` to `remote_dir` over SFTP, preserving
    /// unix permission bits where available (0o644 default elsewhere).
    /// Symlinks are skipped.
    pub fn upload_dir<'a>(
        &'a self,
        local_dir: &'a Path,
        remote_dir: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // Best-effort: the temp install dir is expected to be freshly
            // created, but tolerate it already existing.
            let _ = self.sftp.create_dir(remote_dir).await;

            let mut entries = tokio::fs::read_dir(local_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let file_type = entry.file_type().await?;
                let child_name = entry.file_name().to_string_lossy().into_owned();
                let remote_child = format!("{}/{}", remote_dir.trim_end_matches('/'), child_name);

                if file_type.is_dir() {
                    self.upload_dir(&entry.path(), &remote_child).await?;
                } else if file_type.is_file() {
                    let bytes = tokio::fs::read(entry.path()).await?;
                    let meta = tokio::fs::metadata(entry.path()).await?;
                    let mode = local_file_mode(&meta);
                    self.upload_file(&bytes, &remote_child, mode).await?;
                }
                // Symlinks are intentionally not followed/uploaded.
            }
            Ok(())
        })
    }

    /// Best-effort remote directory creation — tolerates the directory
    /// already existing (upgrade re-runs, or a caller that created it via
    /// [`upload_dir`] already). Used by [`run_install`] to lay out the
    /// `masks/`/`systemd/` subdirectories before uploading embedded bundle
    /// contents (which, unlike [`upload_dir`], have no local directory to
    /// walk).
    async fn ensure_remote_dir(&self, remote_dir: &str) -> Result<()> {
        let _ = self.sftp.create_dir(remote_dir).await;
        Ok(())
    }

    /// Runs `cmd` remotely, calling `on_line` for each complete line of
    /// stdout as it streams in (so the UI can show live progress and
    /// `##AIVPN` markers). Returns the remote process's exit code.
    pub async fn run_streaming(&self, cmd: &str, mut on_line: impl FnMut(&str)) -> Result<i32> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, cmd.as_bytes().to_vec()).await?;

        let mut exit_code: Option<u32> = None;
        let mut exit_signal: Option<String> = None;
        let mut line_buf = String::new();
        let mut err_buf = String::new();

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    line_buf.push_str(&String::from_utf8_lossy(&data));
                    while let Some(pos) = line_buf.find('\n') {
                        let line: String = line_buf.drain(..=pos).collect();
                        on_line(line.trim_end_matches(['\r', '\n']));
                    }
                }
                // stderr (SSH_EXTENDED_DATA_STDERR). Surfaced through the
                // same line callback so failures that only write to stderr
                // ("sudo: a password is required", apt/curl/systemctl
                // errors) are visible to the caller/UI instead of being
                // silently dropped. Buffered separately from stdout so a
                // partial stdout line is never spliced mid-line with stderr.
                ChannelMsg::ExtendedData { data, .. } => {
                    err_buf.push_str(&String::from_utf8_lossy(&data));
                    while let Some(pos) = err_buf.find('\n') {
                        let line: String = err_buf.drain(..=pos).collect();
                        on_line(line.trim_end_matches(['\r', '\n']));
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status);
                }
                // The remote process was killed by a signal (OOM-kill,
                // manual kill, ...). sshd sends `exit-signal` INSTEAD of
                // `exit-status` in that case — record it so the fallthrough
                // below reports a hard error rather than success.
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    exit_signal = Some(format!("killed by signal {:?}", signal_name));
                }
                ChannelMsg::Close | ChannelMsg::Eof => {
                    // Keep draining until the channel actually closes — there
                    // may still be buffered Data messages after Eof.
                    if matches!(msg, ChannelMsg::Close) {
                        break;
                    }
                }
                _ => {}
            }
        }

        if !line_buf.is_empty() {
            on_line(&line_buf);
        }
        if !err_buf.is_empty() {
            on_line(&err_buf);
        }

        match (exit_code, exit_signal) {
            (Some(code), _) => Ok(code as i32),
            // No exit status at all: the process was signal-killed or the
            // connection dropped mid-command. Treating this as success
            // (exit 0) previously made an aborted install report as
            // Finished{exit_code:0} to the UI.
            (None, signal) => {
                Err(SshInstallError::Interrupted(signal.unwrap_or_else(|| {
                    "connection closed before completion".to_string()
                })))
            }
        }
    }

    /// Best-effort removal of the per-run remote install directory. The
    /// session may already be dead (a dropped connection is a common reason
    /// the cleanup runs at all), so failures are logged at debug level and
    /// swallowed — cleanup must never mask the install's real result.
    async fn cleanup_remote_dir(&self, remote_dir: &str) {
        if let Err(err) = self
            .run_streaming(&format!("rm -rf {}", shell_quote(remote_dir)), |_| {})
            .await
        {
            tracing::debug!("ssh-install: remote cleanup of {remote_dir} failed: {err}");
        }
    }
}

const AIVPN_MARKER_PREFIX: &str = "##AIVPN ";

/// A single parsed `##AIVPN {json}` progress/status marker emitted by
/// `install-server.sh` on stdout.
#[derive(Debug, Clone, PartialEq)]
pub struct AivpnMarker {
    pub step: String,
    pub status: String,
    pub code: Option<String>,
    pub msg: Option<String>,
    pub connection_key: Option<String>,
    pub raw: serde_json::Value,
}

/// Parses a single line of installer output. Returns `Some` only for lines
/// starting with `##AIVPN ` whose remainder is valid JSON containing at
/// least `step` and `status` string fields. Any other line (including
/// malformed JSON after the marker prefix) returns `None` — this never
/// panics on untrusted remote output.
pub fn parse_marker_line(line: &str) -> Option<AivpnMarker> {
    let json_part = line.strip_prefix(AIVPN_MARKER_PREFIX)?;
    let raw: serde_json::Value = serde_json::from_str(json_part.trim()).ok()?;
    let obj = raw.as_object()?;

    let step = obj.get("step")?.as_str()?.to_string();
    let status = obj.get("status")?.as_str()?.to_string();
    let code = obj
        .get("code")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let msg = obj
        .get("msg")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let connection_key = obj
        .get("connection_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(AivpnMarker {
        step,
        status,
        code,
        msg,
        connection_key,
        raw,
    })
}

/// The installer bundle embedded into the binary at compile time —
/// `install-server.sh`, its systemd unit template, and the shipped mask
/// profiles (`assets/masks/*.json`). Lets a caller (desktop client, mobile
/// FFI core) drive [`run_install`] against a fresh remote host without
/// needing a full repo checkout alongside the binary; only the server
/// binary itself is fetched over the network (or uploaded from a local
/// file), same as when running `install-server.sh` by hand.
pub mod bundle {
    use sha2::{Digest, Sha256};

    /// The installer script itself (`deploy/install-server.sh`), embedded
    /// verbatim at compile time.
    pub fn installer_script() -> &'static str {
        include_str!("../../../deploy/install-server.sh")
    }

    /// The systemd unit template. `install-server.sh`'s `install_systemd_unit`
    /// step looks for it at `$SCRIPT_DIR/systemd/aivpn-server.service` — i.e.
    /// in a `systemd/` subdirectory next to the script itself — so
    /// [`crate::ssh_install::run_install`] uploads it to
    /// `<remote_dir>/systemd/aivpn-server.service` to match.
    pub fn systemd_unit() -> &'static str {
        include_str!("../../../deploy/systemd/aivpn-server.service")
    }

    /// The `server.json` config template. `install-server.sh`'s `seed_config`
    /// step looks for it at `$SCRIPT_DIR/config/server.json.example` — i.e. in
    /// a `config/` subdirectory next to the script — on a fresh install (when
    /// no `server.json` exists yet), so [`crate::ssh_install::run_install`]
    /// uploads it to `<remote_dir>/config/server.json.example` to match.
    /// Without it a clean install fails at `seed_config` with `template_missing`.
    pub fn config_template() -> &'static str {
        include_str!("../../../deploy/config/server.json.example")
    }

    /// All bundled mask profiles (`assets/masks/*.json`), embedded verbatim
    /// as `(filename, contents)` pairs. [`crate::ssh_install::run_install`]
    /// uploads them into `<remote_dir>/masks/` and passes that directory to
    /// the installer via `--masks-dir`, so a remote install never depends on
    /// `--masks-url`/network reachability just to get a mask set.
    pub fn bundled_masks() -> &'static [(&'static str, &'static [u8])] {
        &[
            (
                "avito_api_v1.json",
                include_bytes!("../../../assets/masks/avito_api_v1.json"),
            ),
            (
                "quic_https_v2.json",
                include_bytes!("../../../assets/masks/quic_https_v2.json"),
            ),
            (
                "sber_salute_v1.json",
                include_bytes!("../../../assets/masks/sber_salute_v1.json"),
            ),
            (
                "telegram_mtproto_v1.json",
                include_bytes!("../../../assets/masks/telegram_mtproto_v1.json"),
            ),
            (
                "vk_video_v1.json",
                include_bytes!("../../../assets/masks/vk_video_v1.json"),
            ),
            (
                "webrtc_sberjazz_v1.json",
                include_bytes!("../../../assets/masks/webrtc_sberjazz_v1.json"),
            ),
            (
                "webrtc_vk_teams_v1.json",
                include_bytes!("../../../assets/masks/webrtc_vk_teams_v1.json"),
            ),
            (
                "webrtc_yandex_telemost_v1.json",
                include_bytes!("../../../assets/masks/webrtc_yandex_telemost_v1.json"),
            ),
            (
                "webrtc_zoom_v3.json",
                include_bytes!("../../../assets/masks/webrtc_zoom_v3.json"),
            ),
            (
                "whatsapp_voip_v1.json",
                include_bytes!("../../../assets/masks/whatsapp_voip_v1.json"),
            ),
            (
                "yandex_alice_v1.json",
                include_bytes!("../../../assets/masks/yandex_alice_v1.json"),
            ),
        ]
    }

    /// SHA256 (hex) of [`installer_script`] — lets a caller show the user
    /// what will run before they confirm, or cross-check against
    /// `install-server.sh --print-sha256` run on a host that already has a
    /// full repo checkout.
    pub fn installer_script_sha256_hex() -> String {
        let mut hasher = Sha256::new();
        hasher.update(installer_script().as_bytes());
        hex::encode(hasher.finalize())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn installer_script_is_embedded_and_looks_right() {
            let script = installer_script();
            assert!(!script.is_empty());
            assert!(script.contains("##AIVPN"));
            assert!(script.contains("emit_marker"));
        }

        #[test]
        fn systemd_unit_is_embedded_and_looks_right() {
            let unit = systemd_unit();
            assert!(unit.contains("[Unit]"));
            assert!(unit.contains("[Service]"));
        }

        #[test]
        fn config_template_is_embedded_and_valid_json() {
            let tmpl = config_template();
            assert!(!tmpl.is_empty());
            serde_json::from_str::<serde_json::Value>(tmpl)
                .expect("bundled server.json.example must be valid JSON");
        }

        #[test]
        fn bundled_masks_all_present_named_and_nonempty() {
            let masks = bundled_masks();
            assert!(masks.len() >= 10);
            for (name, bytes) in masks {
                assert!(name.ends_with(".json"), "unexpected mask filename {name}");
                assert!(!bytes.is_empty(), "{name} embedded as empty");
                // Every bundled mask must be valid JSON.
                serde_json::from_slice::<serde_json::Value>(bytes)
                    .unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"));
            }
        }

        #[test]
        fn installer_script_sha256_hex_is_stable_and_correct_length() {
            let mut hasher = Sha256::new();
            hasher.update(installer_script().as_bytes());
            let expected = hex::encode(hasher.finalize());
            let got = installer_script_sha256_hex();
            assert_eq!(got, expected);
            assert_eq!(got.len(), 64);
        }
    }
}

pub use bundle::{
    bundled_masks, config_template, installer_script, installer_script_sha256_hex, systemd_unit,
};

/// Where `run_install` gets the `aivpn-server` binary from.
pub enum BinarySource {
    /// `install-server.sh --binary-url <url>` — the script downloads it.
    Url(String),
    /// Uploaded from the local filesystem over SFTP before running the
    /// script, then passed as `install-server.sh --binary-file <remote_path>`.
    LocalFile(std::path::PathBuf),
    /// Neither `--binary-url` nor `--binary-file` is passed — the script
    /// falls back to its own default (the project's GitHub Releases).
    Default,
}

/// `install-server.sh --mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    Systemd,
    Docker,
}

impl InstallMode {
    fn as_flag(self) -> &'static str {
        match self {
            InstallMode::Systemd => "systemd",
            InstallMode::Docker => "docker",
        }
    }
}

/// Parameters for a single [`run_install`] call.
pub struct InstallParams {
    pub target: SshTarget,
    pub auth: SshAuth,
    /// The host key fingerprint (`SHA256:...`) the caller already showed the
    /// user and got confirmation for — normally the return value of a prior
    /// [`probe_host_fingerprint`] call. **Required**: [`run_install`] treats
    /// any mismatch against the key actually presented during [`connect`] as
    /// a hard [`SshInstallError::HostKeyMismatch`], never a silent
    /// auto-accept.
    pub expected_fingerprint: String,
    pub binary: BinarySource,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub mode: InstallMode,
    pub device_pubkey_b64: Option<String>,
    pub extra_args: Vec<String>,
}

/// Progress events reported by [`run_install`] via its `on_event` callback.
pub enum InstallEvent {
    /// The SSH connection is up and the host key matched
    /// [`InstallParams::expected_fingerprint`].
    Connected { fingerprint: String },
    /// About to upload `what` (e.g. `"install-server.sh"`, `"masks/"`,
    /// `"aivpn-server binary"`) over SFTP.
    Uploading { what: String },
    /// One raw line of the installer's stdout, as-is (including `##AIVPN`
    /// marker lines — those are also reported separately as [`InstallEvent::Marker`]).
    Line(String),
    /// A `##AIVPN {...}` marker line, already parsed.
    Marker(AivpnMarker),
    /// The installer process exited. `connection_key` is populated from the
    /// last marker that carried one (in practice, the final `step: "done"`
    /// marker, when `--device-pubkey`/`--server-ip` were supplied).
    Finished {
        exit_code: i32,
        connection_key: Option<String>,
    },
}

// --- JSON contract (mobile FFI / CLI) --------------------------------------
//
// [`install_params_from_json`] / [`install_event_to_json`] are the ONLY place
// in the codebase that (de)serializes install params/events to JSON. The iOS
// FFI, Android JNI, and (partially) the CLI all go through these two
// functions rather than hand-rolling their own (de)serialization, so the
// wire format can't drift between callers.

/// `auth` variants accepted by [`install_params_from_json`].
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AuthJson {
    Password {
        password: String,
    },
    /// PEM-encoded private key supplied inline.
    KeyPem {
        pem: String,
        #[serde(default)]
        passphrase: Option<String>,
    },
    /// PEM-encoded private key read from a local file at parse time (the
    /// only variant of the three that touches the filesystem).
    KeyFile {
        path: String,
        #[serde(default)]
        passphrase: Option<String>,
    },
}

/// `binary` variants accepted by [`install_params_from_json`]. Absent from
/// the input entirely maps to [`BinaryJson::Default`].
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BinaryJson {
    Url { url: String },
    File { path: String },
    Default {},
}

/// `mode` values accepted by [`install_params_from_json`]. Absent from the
/// input maps to [`ModeJson::Systemd`].
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModeJson {
    Systemd,
    Docker,
}

/// Wire shape parsed by [`install_params_from_json`] — see that function's
/// doc comment for the full JSON contract.
#[derive(serde::Deserialize)]
struct InstallParamsJson {
    host: String,
    port: u16,
    user: String,
    auth: AuthJson,
    fingerprint: String,
    #[serde(default)]
    binary: Option<BinaryJson>,
    #[serde(default)]
    server_ip: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    mode: Option<ModeJson>,
    #[serde(default)]
    device_pubkey_b64: Option<String>,
    #[serde(default)]
    extra_args: Vec<String>,
}

/// Parses [`InstallParams`] from the JSON contract shared with the iOS FFI /
/// Android JNI layers (and, partially, the CLI):
///
/// ```json
/// {
///   "host": "1.2.3.4", "port": 22, "user": "root",
///   "auth": {"type":"password","password":"..."}
///         | {"type":"key_pem","pem":"...","passphrase":null}
///         | {"type":"key_file","path":"/abs/path","passphrase":null},
///   "fingerprint": "SHA256:...",
///   "binary": {"type":"url","url":"..."}
///           | {"type":"file","path":"..."}
///           | {"type":"default"},
///   "server_ip": null, "server_port": null,
///   "mode": "systemd" | "docker",
///   "device_pubkey_b64": null,
///   "extra_args": []
/// }
/// ```
///
/// `fingerprint` is required (mirrors [`InstallParams::expected_fingerprint`]
/// being non-optional — TOFU confirmation must have already happened
/// out-of-band before this is called). `binary` defaults to `"default"` and
/// `mode` defaults to `"systemd"` when the field is absent; `extra_args`
/// defaults to `[]`. `auth.type: "key_file"` reads `path` off the local
/// filesystem synchronously (`std::fs::read_to_string`) into the same
/// `SshAuth::PrivateKey { pem, .. }` the other two auth variants produce — by
/// the time [`connect`] runs, all three auth variants look identical.
///
/// An unrecognized `auth.type` / `binary.type` / `mode`, missing required
/// field, or malformed JSON all return [`SshInstallError::Json`] (whose
/// message names the offending field/variant, courtesy of `serde_json`).
pub fn install_params_from_json(json: &str) -> Result<InstallParams> {
    let raw: InstallParamsJson = serde_json::from_str(json)?;

    let auth = match raw.auth {
        AuthJson::Password { password } => SshAuth::Password(password),
        AuthJson::KeyPem { pem, passphrase } => SshAuth::PrivateKey { pem, passphrase },
        AuthJson::KeyFile { path, passphrase } => {
            let pem = std::fs::read_to_string(&path)?;
            SshAuth::PrivateKey { pem, passphrase }
        }
    };

    let binary = match raw.binary.unwrap_or(BinaryJson::Default {}) {
        BinaryJson::Url { url } => BinarySource::Url(url),
        BinaryJson::File { path } => BinarySource::LocalFile(std::path::PathBuf::from(path)),
        BinaryJson::Default {} => BinarySource::Default,
    };

    let mode = match raw.mode.unwrap_or(ModeJson::Systemd) {
        ModeJson::Systemd => InstallMode::Systemd,
        ModeJson::Docker => InstallMode::Docker,
    };

    Ok(InstallParams {
        target: SshTarget {
            host: raw.host,
            port: raw.port,
            user: raw.user,
        },
        auth,
        expected_fingerprint: raw.fingerprint,
        binary,
        server_ip: raw.server_ip,
        server_port: raw.server_port,
        mode,
        device_pubkey_b64: raw.device_pubkey_b64,
        extra_args: raw.extra_args,
    })
}

/// Serializes an [`InstallEvent`] into a single-line JSON string, the wire
/// format the iOS FFI / Android JNI layers (and, partially, the CLI) stream
/// back to their callers for [`run_install`] progress. All user-influenced
/// strings (marker fields, raw output lines, ...) go through `serde_json`,
/// never manual string concatenation, so embedded quotes/control
/// characters/unicode in remote output can't corrupt the JSON:
///
/// ```text
/// Connected { fingerprint }            -> {"type":"connected","fingerprint":"..."}
/// Uploading { what }                   -> {"type":"uploading","what":"..."}
/// Line(s)                              -> {"type":"line","line":"..."}
/// Marker(m)                            -> {"type":"marker","step":"...","status":"...","code":null,"msg":null,"connection_key":null}
/// Finished { exit_code, connection_key } -> {"type":"finished","exit_code":0,"connection_key":null}
/// ```
pub fn install_event_to_json(ev: &InstallEvent) -> String {
    let value = match ev {
        InstallEvent::Connected { fingerprint } => serde_json::json!({
            "type": "connected",
            "fingerprint": fingerprint,
        }),
        InstallEvent::Uploading { what } => serde_json::json!({
            "type": "uploading",
            "what": what,
        }),
        InstallEvent::Line(line) => serde_json::json!({
            "type": "line",
            "line": line,
        }),
        InstallEvent::Marker(marker) => serde_json::json!({
            "type": "marker",
            "step": marker.step,
            "status": marker.status,
            "code": marker.code,
            "msg": marker.msg,
            "connection_key": marker.connection_key,
        }),
        InstallEvent::Finished {
            exit_code,
            connection_key,
        } => serde_json::json!({
            "type": "finished",
            "exit_code": exit_code,
            "connection_key": connection_key,
        }),
    };
    // `serde_json::Value::to_string()` never pretty-prints, so this is
    // always a single line — required for line-delimited streaming to a
    // caller.
    value.to_string()
}

/// Connects to `target` with no real intent to authenticate (an empty
/// password — auth is never reached), captures the host key's SHA256
/// fingerprint during key exchange, and aborts the connection immediately.
/// This is TOFU step 1: the caller shows the returned fingerprint to the
/// user for out-of-band confirmation (matching the fingerprint printed by
/// the remote host's `sshd`, e.g. via `ssh-keyscan`/a control-panel
/// console) before calling [`run_install`] with it as
/// [`InstallParams::expected_fingerprint`].
pub async fn probe_host_fingerprint(target: &SshTarget) -> Result<String> {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_for_verify = captured.clone();

    // Key exchange (and thus `check_server_key`) always happens before
    // authentication in the SSH protocol, so returning `false` here means
    // `auth` below is never actually used — a real credential isn't needed
    // (and mustn't be required) just to read the host key.
    let result = connect(target, &SshAuth::Password(String::new()), move |host_key| {
        *captured_for_verify.lock().unwrap() = Some(host_key.fingerprint_sha256.clone());
        false
    })
    .await;

    let fingerprint = captured.lock().unwrap().take();
    match fingerprint {
        Some(fingerprint) => Ok(fingerprint),
        // The callback never ran (or the mutex never got populated) — the
        // connection failed before key exchange (DNS/TCP/handshake error).
        // Surface whatever `connect` returned.
        None => Err(result.err().unwrap_or(SshInstallError::AuthFailed)),
    }
}

/// Generates a short random hex suffix for the per-run remote install
/// directory (`/tmp/aivpn-install-<suffix>`), so concurrent/repeated
/// installs against the same host don't collide.
fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The remote filename an uploaded [`BinarySource::LocalFile`] is placed at,
/// relative to the per-run remote install directory. Shared between
/// [`run_install`] (which uploads there) and [`build_install_argv`] (which
/// must reference the exact same path via `--binary-file`).
const UPLOADED_BINARY_NAME: &str = "aivpn-server-bin";

/// Shell-quotes `s` for safe inclusion as a single argv token in a command
/// line executed via `bash -c "..."` over the SSH channel. Values that are
/// already free of shell metacharacters are returned unquoted (for
/// readability in logs); anything else is wrapped in single quotes, with
/// embedded single quotes escaped using the standard `'\''` technique
/// (close the quote, emit an escaped quote, reopen the quote).
fn shell_quote(s: &str) -> String {
    let is_plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'));
    if is_plain {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Pure builder for `install-server.sh`'s argv, given already-uploaded
/// bundle contents under `remote_dir` (see [`run_install`]). Every value
/// token is shell-quoted via [`shell_quote`] so caller-supplied strings
/// (server IP, extra args, ...) can never break out of their argument no
/// matter what characters they contain. Split out from [`run_install`] so
/// the argv construction — including the quoting — is unit-testable without
/// a live SSH server.
pub fn build_install_argv(params: &InstallParams, remote_dir: &str) -> Vec<String> {
    let script_path = format!("{}/install-server.sh", remote_dir.trim_end_matches('/'));
    let masks_dir = format!("{}/masks", remote_dir.trim_end_matches('/'));

    let mut argv = vec!["bash".to_string(), shell_quote(&script_path)];

    argv.push("--mode".to_string());
    argv.push(shell_quote(params.mode.as_flag()));

    argv.push("--masks-dir".to_string());
    argv.push(shell_quote(&masks_dir));

    match &params.binary {
        BinarySource::Url(url) => {
            argv.push("--binary-url".to_string());
            argv.push(shell_quote(url));
        }
        BinarySource::LocalFile(_) => {
            let remote_binary = format!(
                "{}/{}",
                remote_dir.trim_end_matches('/'),
                UPLOADED_BINARY_NAME
            );
            argv.push("--binary-file".to_string());
            argv.push(shell_quote(&remote_binary));
        }
        BinarySource::Default => {}
    }

    if let Some(ip) = &params.server_ip {
        argv.push("--server-ip".to_string());
        argv.push(shell_quote(ip));
    }
    if let Some(port) = params.server_port {
        argv.push("--port".to_string());
        argv.push(shell_quote(&port.to_string()));
    }
    if let Some(pubkey) = &params.device_pubkey_b64 {
        argv.push("--device-pubkey".to_string());
        argv.push(shell_quote(pubkey));
    }

    for extra in &params.extra_args {
        argv.push(shell_quote(extra));
    }

    if params.target.user != "root" {
        let mut prefixed = vec!["sudo".to_string(), "-n".to_string()];
        prefixed.append(&mut argv);
        prefixed
    } else {
        argv
    }
}

/// Connects to `params.target` (verifying the host key against
/// `params.expected_fingerprint` — any mismatch is a hard error, checked
/// *before* authentication ever runs), uploads the embedded installer
/// bundle plus (optionally) a local server binary into a fresh
/// `/tmp/aivpn-install-<random>` directory over SFTP, then runs
/// `install-server.sh` there via `run_streaming`, reporting progress
/// through `on_event`. Returns the installer's exit code (also delivered as
/// the final [`InstallEvent::Finished`]).
///
/// The whole operation is bounded by [`INSTALL_OVERALL_TIMEOUT`]
/// ([`SshInstallError::Timeout`] on expiry): the transport keepalive/
/// inactivity timeouts configured in [`ssh_client_config`] only fire when the
/// server stops answering entirely, while a remote step that hangs forever
/// with sshd still responsive (apt waiting on a dpkg lock, a stalled
/// download) needs this outer bound. On timeout the in-flight future — and
/// with it the SSH session — is dropped; no remote cleanup is attempted on
/// that path since the session is exactly what's suspected to be wedged.
pub async fn run_install(
    params: InstallParams,
    mut on_event: impl FnMut(InstallEvent),
) -> Result<i32> {
    match tokio::time::timeout(
        INSTALL_OVERALL_TIMEOUT,
        run_install_inner(params, &mut on_event),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(SshInstallError::Timeout(INSTALL_OVERALL_TIMEOUT.as_secs())),
    }
}

/// The body of [`run_install`], split out so the public entry point is a
/// thin overall-timeout wrapper (see its doc comment).
async fn run_install_inner(
    params: InstallParams,
    on_event: &mut impl FnMut(InstallEvent),
) -> Result<i32> {
    let expected_fingerprint = params.expected_fingerprint.clone();
    let mismatch: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mismatch_for_verify = mismatch.clone();
    let expected_for_verify = expected_fingerprint.clone();

    let session = connect(&params.target, &params.auth, move |host_key| {
        if host_key.fingerprint_sha256 == expected_for_verify {
            true
        } else {
            *mismatch_for_verify.lock().unwrap() = Some(host_key.fingerprint_sha256.clone());
            false
        }
    })
    .await;

    let session = match session {
        Ok(session) => session,
        Err(err) => {
            if let Some(got) = mismatch.lock().unwrap().take() {
                return Err(SshInstallError::HostKeyMismatch {
                    expected: expected_fingerprint,
                    got,
                });
            }
            return Err(err);
        }
    };

    on_event(InstallEvent::Connected {
        fingerprint: expected_fingerprint,
    });

    let remote_dir = format!("/tmp/aivpn-install-{}", random_suffix());
    session.ensure_remote_dir(&remote_dir).await?;

    let result = upload_and_run_installer(&session, &params, &remote_dir, on_event).await;

    // Best-effort remote scratch cleanup on EVERY exit path once remote_dir
    // exists: the uploaded bundle (script, masks, and for
    // BinarySource::LocalFile an ~11 MB binary) is no longer needed once the
    // installer script has run — or never ran. Without this every failed
    // upload/exec and every retry leaked a fresh /tmp/aivpn-install-<hex>
    // directory on the target host. The install script copies what it needs
    // to its final locations, so removing the staging dir is safe for any
    // outcome. Failures are ignored: cleanup must never mask the real result.
    session.cleanup_remote_dir(&remote_dir).await;

    let (exit_code, connection_key) = result?;
    on_event(InstallEvent::Finished {
        exit_code,
        connection_key,
    });

    Ok(exit_code)
}

/// Uploads the embedded installer bundle plus (optionally) a local server
/// binary into `remote_dir` and runs `install-server.sh` there via
/// `run_streaming`. Split out from [`run_install_inner`] so the caller can
/// clean up `remote_dir` on every exit path, error included. Returns the
/// installer's exit code and the last connection key seen in a marker.
async fn upload_and_run_installer(
    session: &SshSession,
    params: &InstallParams,
    remote_dir: &str,
    on_event: &mut impl FnMut(InstallEvent),
) -> Result<(i32, Option<String>)> {
    session
        .ensure_remote_dir(&format!("{remote_dir}/systemd"))
        .await?;
    session
        .ensure_remote_dir(&format!("{remote_dir}/masks"))
        .await?;
    session
        .ensure_remote_dir(&format!("{remote_dir}/config"))
        .await?;

    on_event(InstallEvent::Uploading {
        what: "install-server.sh".to_string(),
    });
    session
        .upload_file(
            bundle::installer_script().as_bytes(),
            &format!("{remote_dir}/install-server.sh"),
            0o755,
        )
        .await?;

    on_event(InstallEvent::Uploading {
        what: "systemd/aivpn-server.service".to_string(),
    });
    session
        .upload_file(
            bundle::systemd_unit().as_bytes(),
            &format!("{remote_dir}/systemd/aivpn-server.service"),
            0o644,
        )
        .await?;

    on_event(InstallEvent::Uploading {
        what: "config/server.json.example".to_string(),
    });
    session
        .upload_file(
            bundle::config_template().as_bytes(),
            &format!("{remote_dir}/config/server.json.example"),
            0o644,
        )
        .await?;

    on_event(InstallEvent::Uploading {
        what: "masks/".to_string(),
    });
    for (name, bytes) in bundle::bundled_masks() {
        session
            .upload_file(bytes, &format!("{remote_dir}/masks/{name}"), 0o644)
            .await?;
    }

    if let BinarySource::LocalFile(local_path) = &params.binary {
        on_event(InstallEvent::Uploading {
            what: "aivpn-server binary".to_string(),
        });
        let bytes = tokio::fs::read(local_path).await?;
        session
            .upload_file(
                &bytes,
                &format!("{remote_dir}/{UPLOADED_BINARY_NAME}"),
                0o755,
            )
            .await?;
    }

    let argv = build_install_argv(params, remote_dir);
    let cmd = argv.join(" ");

    let mut connection_key: Option<String> = None;
    let exit_code = session
        .run_streaming(&cmd, |line| {
            on_event(InstallEvent::Line(line.to_string()));
            if let Some(marker) = parse_marker_line(line) {
                if marker.connection_key.is_some() {
                    connection_key = marker.connection_key.clone();
                }
                on_event(InstallEvent::Marker(marker));
            }
        })
        .await?;

    Ok((exit_code, connection_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_marker_line -------------------------------------------------

    #[test]
    fn parse_marker_line_valid_done_marker() {
        let line = r#"##AIVPN {"step":"done","status":"ok","connection_key":"aivpn://x"}"#;
        let marker = parse_marker_line(line).expect("should parse");
        assert_eq!(marker.step, "done");
        assert_eq!(marker.status, "ok");
        assert_eq!(marker.connection_key.as_deref(), Some("aivpn://x"));
        assert_eq!(marker.code, None);
        assert_eq!(marker.msg, None);
    }

    #[test]
    fn parse_marker_line_normal_log_line_is_none() {
        assert_eq!(
            parse_marker_line("Installing packages via apt-get..."),
            None
        );
    }

    #[test]
    fn parse_marker_line_empty_line_is_none() {
        assert_eq!(parse_marker_line(""), None);
    }

    #[test]
    fn parse_marker_line_malformed_json_is_none_not_panic() {
        // Prefix present but the remainder isn't valid JSON at all.
        assert_eq!(parse_marker_line("##AIVPN {not json at all"), None);
        // Valid JSON, but not an object (so `step`/`status` lookups fail cleanly).
        assert_eq!(parse_marker_line("##AIVPN [1,2,3]"), None);
        // Valid JSON object, but missing the required fields.
        assert_eq!(parse_marker_line(r#"##AIVPN {"foo":"bar"}"#), None);
    }

    #[test]
    fn parse_marker_line_port_busy_error_marker() {
        let line = r#"##AIVPN {"step":"listen","status":"error","code":"port_busy","msg":"port 51820 already in use"}"#;
        let marker = parse_marker_line(line).expect("should parse");
        assert_eq!(marker.step, "listen");
        assert_eq!(marker.status, "error");
        assert_eq!(marker.code.as_deref(), Some("port_busy"));
        assert_eq!(marker.msg.as_deref(), Some("port 51820 already in use"));
        assert_eq!(marker.connection_key, None);
    }

    // --- ssh_client_config ---------------------------------------------------

    #[test]
    fn ssh_client_config_bounds_dead_and_silent_peers() {
        let config = ssh_client_config();
        assert_eq!(
            config.keepalive_interval,
            Some(SSH_KEEPALIVE_INTERVAL),
            "keepalive must be enabled so a half-open TCP connection is detected"
        );
        assert_eq!(
            config.inactivity_timeout,
            Some(SSH_INACTIVITY_TIMEOUT),
            "inactivity timeout must backstop a fully silent peer"
        );
        // A dead peer must be declared (keepalive_max exceeded) well before
        // the inactivity backstop fires.
        assert!(config.keepalive_max > 0);
        assert!(
            SSH_KEEPALIVE_INTERVAL * (config.keepalive_max as u32 + 1) < SSH_INACTIVITY_TIMEOUT
        );
    }

    // --- fingerprint formatting ---------------------------------------------

    #[test]
    fn fingerprint_sha256_matches_known_vector() {
        // Known-good vector taken verbatim from the russh test suite
        // (src/keys/mod.rs) — a base64-encoded ssh-ed25519 public key and its
        // documented SHA256 OpenSSH-style fingerprint.
        let key = russh::keys::parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ",
        )
        .expect("known-good test vector must parse");

        assert_eq!(
            format_fingerprint_sha256(&key),
            "SHA256:ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    // --- shell_quote ---------------------------------------------------------

    #[test]
    fn shell_quote_leaves_plain_values_unquoted() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote("vpn.example.com:443"), "vpn.example.com:443");
        assert_eq!(
            shell_quote("/tmp/aivpn-install-abc123"),
            "/tmp/aivpn-install-abc123"
        );
    }

    #[test]
    fn shell_quote_escapes_single_quotes_and_special_chars() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("o'brien"), r"'o'\''brien'");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
        assert_eq!(shell_quote(""), "''");
    }

    // --- build_install_argv ---------------------------------------------------

    fn base_params() -> InstallParams {
        InstallParams {
            target: SshTarget {
                host: "vps.example.com".to_string(),
                port: 22,
                user: "deploy".to_string(),
            },
            auth: SshAuth::Password("unused-in-these-tests".to_string()),
            expected_fingerprint: "SHA256:abc".to_string(),
            binary: BinarySource::Default,
            server_ip: None,
            server_port: None,
            mode: InstallMode::Systemd,
            device_pubkey_b64: None,
            extra_args: Vec::new(),
        }
    }

    #[test]
    fn build_install_argv_default_systemd_nonroot_prefixes_sudo() {
        let params = base_params();
        let argv = build_install_argv(&params, "/tmp/aivpn-install-abc123");

        assert_eq!(argv[0], "sudo");
        assert_eq!(argv[1], "-n");
        assert_eq!(argv[2], "bash");
        assert_eq!(argv[3], "/tmp/aivpn-install-abc123/install-server.sh");
        assert!(argv.windows(2).any(|w| w == ["--mode", "systemd"]));
        assert!(argv
            .windows(2)
            .any(|w| w == ["--masks-dir", "/tmp/aivpn-install-abc123/masks"]));
        // BinarySource::Default passes neither --binary-url nor --binary-file.
        assert!(!argv.contains(&"--binary-url".to_string()));
        assert!(!argv.contains(&"--binary-file".to_string()));
    }

    #[test]
    fn build_install_argv_root_user_has_no_sudo_prefix() {
        let mut params = base_params();
        params.target.user = "root".to_string();
        let argv = build_install_argv(&params, "/tmp/x");
        assert_eq!(argv[0], "bash");
        assert!(!argv.contains(&"sudo".to_string()));
    }

    #[test]
    fn build_install_argv_binary_url_and_docker_mode() {
        let mut params = base_params();
        params.mode = InstallMode::Docker;
        params.binary = BinarySource::Url("https://example.com/releases".to_string());
        let argv = build_install_argv(&params, "/tmp/x");

        assert!(argv
            .windows(2)
            .any(|w| w == ["--binary-url", "https://example.com/releases"]));
        assert!(argv.windows(2).any(|w| w == ["--mode", "docker"]));
        assert!(!argv.contains(&"--binary-file".to_string()));
    }

    #[test]
    fn build_install_argv_local_file_binary_references_uploaded_remote_path() {
        let mut params = base_params();
        params.binary = BinarySource::LocalFile(std::path::PathBuf::from("/home/me/aivpn-server"));
        let argv = build_install_argv(&params, "/tmp/x");

        assert!(argv
            .windows(2)
            .any(|w| w == ["--binary-file", "/tmp/x/aivpn-server-bin"]));
        assert!(!argv.contains(&"--binary-url".to_string()));
    }

    #[test]
    fn build_install_argv_server_ip_port_and_device_pubkey() {
        let mut params = base_params();
        params.server_ip = Some("vpn.example.com:443".to_string());
        params.server_port = Some(443);
        params.device_pubkey_b64 = Some("QUJDRA==".to_string());
        let argv = build_install_argv(&params, "/tmp/x");

        assert!(argv
            .windows(2)
            .any(|w| w == ["--server-ip", "vpn.example.com:443"]));
        assert!(argv.windows(2).any(|w| w == ["--port", "443"]));
        // Base64 padding ('=') isn't in the "plain" charset, so the value is
        // shell-quoted like any other non-trivial token.
        assert!(argv
            .windows(2)
            .any(|w| w == ["--device-pubkey", "'QUJDRA=='"]));
    }

    #[test]
    fn build_install_argv_dangerous_values_are_shell_quoted() {
        let mut params = base_params();
        params.server_ip = Some("vpn.example.com; rm -rf /".to_string());
        params.extra_args = vec!["--admin-name".to_string(), "o'brien".to_string()];
        let argv = build_install_argv(&params, "/tmp/x");

        let ip_idx = argv
            .iter()
            .position(|a| a == "--server-ip")
            .expect("--server-ip present");
        assert_eq!(argv[ip_idx + 1], "'vpn.example.com; rm -rf /'");

        assert!(argv.contains(&"--admin-name".to_string()));
        assert!(argv.iter().any(|a| a == r"'o'\''brien'"));

        // Sanity: joining into a single command line never lets the
        // dangerous value's `;` terminate the quoted string early.
        let cmd = argv.join(" ");
        assert!(cmd.contains("'vpn.example.com; rm -rf /'"));
    }

    // --- install_params_from_json ------------------------------------------

    #[test]
    fn install_params_from_json_password_auth_and_defaults() {
        let json = r#"{
            "host": "1.2.3.4", "port": 22, "user": "root",
            "auth": {"type":"password","password":"hunter2"},
            "fingerprint": "SHA256:abc"
        }"#;
        let params = install_params_from_json(json).expect("should parse");

        assert_eq!(params.target.host, "1.2.3.4");
        assert_eq!(params.target.port, 22);
        assert_eq!(params.target.user, "root");
        assert!(matches!(params.auth, SshAuth::Password(ref p) if p == "hunter2"));
        assert_eq!(params.expected_fingerprint, "SHA256:abc");
        // binary/mode/extra_args all absent -> defaults.
        assert!(matches!(params.binary, BinarySource::Default));
        assert_eq!(params.mode, InstallMode::Systemd);
        assert_eq!(params.server_ip, None);
        assert_eq!(params.server_port, None);
        assert_eq!(params.device_pubkey_b64, None);
        assert!(params.extra_args.is_empty());
    }

    #[test]
    fn install_params_from_json_key_pem_auth() {
        let json = r#"{
            "host": "h", "port": 2222, "user": "deploy",
            "auth": {"type":"key_pem","pem":"-----BEGIN KEY-----","passphrase":"p4ss"},
            "fingerprint": "SHA256:xyz",
            "binary": {"type":"url","url":"https://example.com/bin"},
            "server_ip": "5.6.7.8", "server_port": 18444,
            "mode": "docker",
            "device_pubkey_b64": "QUJDRA==",
            "extra_args": ["--foo", "bar"]
        }"#;
        let params = install_params_from_json(json).expect("should parse");

        match params.auth {
            SshAuth::PrivateKey { pem, passphrase } => {
                assert_eq!(pem, "-----BEGIN KEY-----");
                assert_eq!(passphrase.as_deref(), Some("p4ss"));
            }
            _ => panic!("expected PrivateKey auth"),
        }
        assert!(
            matches!(params.binary, BinarySource::Url(ref u) if u == "https://example.com/bin")
        );
        assert_eq!(params.server_ip.as_deref(), Some("5.6.7.8"));
        assert_eq!(params.server_port, Some(18444));
        assert_eq!(params.mode, InstallMode::Docker);
        assert_eq!(params.device_pubkey_b64.as_deref(), Some("QUJDRA=="));
        assert_eq!(
            params.extra_args,
            vec!["--foo".to_string(), "bar".to_string()]
        );
    }

    #[test]
    fn install_params_from_json_key_file_auth_reads_local_file() {
        let path = std::env::temp_dir().join(format!(
            "aivpn_ssh_install_test_key_{}_{}.pem",
            std::process::id(),
            random_suffix()
        ));
        std::fs::write(&path, "-----BEGIN FILE KEY-----\ncontent\n").expect("write temp key");

        let json = serde_json::json!({
            "host": "h", "port": 22, "user": "root",
            "auth": {"type":"key_file","path": path.to_string_lossy(), "passphrase": null},
            "fingerprint": "SHA256:abc",
            "binary": {"type":"file","path":"/local/aivpn-server"},
        })
        .to_string();

        let result = install_params_from_json(&json);
        std::fs::remove_file(&path).ok();
        let params = result.expect("should parse and read key file");

        match params.auth {
            SshAuth::PrivateKey { pem, passphrase } => {
                assert_eq!(pem, "-----BEGIN FILE KEY-----\ncontent\n");
                assert_eq!(passphrase, None);
            }
            _ => panic!("expected PrivateKey auth"),
        }
        assert!(matches!(
            params.binary,
            BinarySource::LocalFile(ref p) if p == std::path::Path::new("/local/aivpn-server")
        ));
    }

    #[test]
    fn install_params_from_json_unknown_auth_type_is_clear_error() {
        let json = r#"{
            "host": "h", "port": 22, "user": "root",
            "auth": {"type":"carrier_pigeon"},
            "fingerprint": "SHA256:abc"
        }"#;
        let msg = match install_params_from_json(json) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("must reject unknown auth.type"),
        };
        assert!(
            msg.contains("carrier_pigeon") || msg.contains("unknown variant"),
            "error message should name the bad tag: {msg}"
        );
    }

    #[test]
    fn install_params_from_json_missing_fingerprint_is_error() {
        let json = r#"{
            "host": "h", "port": 22, "user": "root",
            "auth": {"type":"password","password":"x"}
        }"#;
        assert!(install_params_from_json(json).is_err());
    }

    // --- install_event_to_json ---------------------------------------------

    #[test]
    fn install_event_to_json_connected() {
        let ev = InstallEvent::Connected {
            fingerprint: "SHA256:abc".to_string(),
        };
        assert_eq!(
            install_event_to_json(&ev),
            r#"{"fingerprint":"SHA256:abc","type":"connected"}"#
        );
    }

    #[test]
    fn install_event_to_json_uploading() {
        let ev = InstallEvent::Uploading {
            what: "masks/".to_string(),
        };
        assert_eq!(
            install_event_to_json(&ev),
            r#"{"type":"uploading","what":"masks/"}"#
        );
    }

    #[test]
    fn install_event_to_json_line_escapes_quotes_and_unicode() {
        let ev = InstallEvent::Line("he said \"привет\" \\n".to_string());
        let json = install_event_to_json(&ev);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["type"], "line");
        assert_eq!(parsed["line"], "he said \"привет\" \\n");
        // Must be a single line (no raw newlines snuck through un-escaped).
        assert_eq!(json.lines().count(), 1);
    }

    #[test]
    fn install_event_to_json_marker_all_fields() {
        let marker = AivpnMarker {
            step: "listen".to_string(),
            status: "error".to_string(),
            code: Some("port_busy".to_string()),
            msg: Some("port in use".to_string()),
            connection_key: Some("aivpn://x".to_string()),
            raw: serde_json::json!({"step":"listen"}),
        };
        let ev = InstallEvent::Marker(marker);
        let json = install_event_to_json(&ev);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["type"], "marker");
        assert_eq!(parsed["step"], "listen");
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "port_busy");
        assert_eq!(parsed["msg"], "port in use");
        assert_eq!(parsed["connection_key"], "aivpn://x");
    }

    #[test]
    fn install_event_to_json_marker_optional_fields_null() {
        let marker = AivpnMarker {
            step: "done".to_string(),
            status: "ok".to_string(),
            code: None,
            msg: None,
            connection_key: None,
            raw: serde_json::json!({}),
        };
        let json = install_event_to_json(&InstallEvent::Marker(marker));
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(parsed["code"].is_null());
        assert!(parsed["msg"].is_null());
        assert!(parsed["connection_key"].is_null());
    }

    #[test]
    fn install_event_to_json_finished_with_and_without_connection_key() {
        let with_key = InstallEvent::Finished {
            exit_code: 0,
            connection_key: Some("aivpn://x".to_string()),
        };
        let json = install_event_to_json(&with_key);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["type"], "finished");
        assert_eq!(parsed["exit_code"], 0);
        assert_eq!(parsed["connection_key"], "aivpn://x");

        let without_key = InstallEvent::Finished {
            exit_code: 1,
            connection_key: None,
        };
        let json = install_event_to_json(&without_key);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["exit_code"], 1);
        assert!(parsed["connection_key"].is_null());
    }
}
