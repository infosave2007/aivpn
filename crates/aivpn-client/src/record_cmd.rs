//! Recording CLI Commands — Client-side recording controls
//!
//! Handles `aivpn record start/stop/status` and `aivpn masks list/delete/retrain`
//! by sending appropriate ControlPayload messages to the server.

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Returns platform-appropriate paths for recording status files.
pub fn recording_status_paths() -> Vec<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let mut paths = Vec::new();
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
            let dir = std::path::PathBuf::from(local_app).join("AIVPN");
            let _ = std::fs::create_dir_all(&dir);
            paths.push(dir.join("recording.status"));
        }
        paths.push(std::env::temp_dir().join("aivpn-recording.status"));
        paths
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![
            std::path::PathBuf::from("/var/run/aivpn/recording.status"),
            std::path::PathBuf::from("/tmp/aivpn-recording.status"),
        ]
    }
}

/// Per-user path for the local admin-socket auth token. The admin UDP socket
/// (127.0.0.1:44301) accepts recording start/stop/status commands from any
/// local process; on a shared/multi-user host that meant any other local
/// user could start, stop, or read another user's recording session. The
/// token scopes commands to whoever can read this 0600 file — i.e. the same
/// OS user the daemon is running as.
fn admin_token_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
            return std::path::PathBuf::from(local_app)
                .join("AIVPN")
                .join("admin.token");
        }
        std::env::temp_dir().join("aivpn-admin.token")
    }
    #[cfg(not(target_os = "windows"))]
    {
        #[cfg(unix)]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(unix))]
        let uid = 0u32;
        // Prefer XDG_RUNTIME_DIR (tmpfs, mode 0700, per-user, auto-cleaned on
        // logout) over the world-writable /tmp namespace, which invites
        // symlink/pre-create attacks on a predictable shared path.
        if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            return std::path::PathBuf::from(runtime_dir)
                .join("aivpn")
                .join("admin.token");
        }
        // Per-uid SUBDIRECTORY under /tmp, never a bare file in /tmp:
        // ensure_admin_token() chmods the token's PARENT to 0700, so the parent
        // must be our own `/tmp/aivpn-{uid}` dir. A bare `/tmp/aivpn-admin-{uid}.token`
        // makes the parent `/tmp` itself and flips /tmp to 0700, breaking the
        // whole system's temp dir (this process usually runs as root for TUN).
        std::path::PathBuf::from(format!("/tmp/aivpn-{uid}")).join("admin.token")
    }
}

/// Generate a fresh admin-socket auth token and persist it for this run.
/// Called once by the daemon at startup; invalidates any token from a prior
/// run (each connection gets its own).
pub fn ensure_admin_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let token: String = (0..32)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();

    let path = admin_token_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    // Best-effort unlink of any prior file (ours from a previous run, or an
    // attacker's pre-created symlink/file) before creating fresh with O_EXCL
    // so the permission window never opens and symlinks aren't followed.
    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(token.as_bytes()))
        {
            Ok(()) => {}
            Err(e) => warn!("Failed to write admin token to {}: {e}", path.display()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&path, &token);
    }
    token
}

/// Read the admin-socket auth token written by the running daemon. Used by
/// `aivpn-client record start/stop/status` before sending a command.
pub fn read_admin_token() -> Option<String> {
    std::fs::read_to_string(admin_token_path())
        .ok()
        .map(|s| s.trim().to_string())
}

/// Constant-time token comparison to avoid leaking match-length via timing.
/// Always walks a fixed-size window regardless of input length, instead of
/// early-returning on a length mismatch, so the comparison takes the same
/// time whether the candidate is the right length or not.
pub fn tokens_match(a: &str, b: &str) -> bool {
    const WINDOW: usize = 64; // generous over our fixed 32-char token length
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = (a.len() != b.len()) as u8;
    for i in 0..WINDOW {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingLocalStatus {
    pub can_record: Option<bool>,
    pub state: String,
    pub service: Option<String>,
    pub message: Option<String>,
    pub mask_id: Option<String>,
    pub confidence: Option<f32>,
    pub updated_at_ms: u64,
}

impl Default for RecordingLocalStatus {
    fn default() -> Self {
        Self {
            can_record: None,
            state: "idle".into(),
            service: None,
            message: Some("Recording access not checked yet".into()),
            mask_id: None,
            confidence: None,
            updated_at_ms: current_timestamp_ms(),
        }
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn write_status(status: &RecordingLocalStatus) {
    if let Ok(json) = serde_json::to_vec(status) {
        for path in recording_status_paths() {
            // Atomic temp+rename (not plain std::fs::write, which
            // open+truncate+writes in place) so a CLI `record status` poll
            // landing mid-write never sees a 0-byte/partial file — and
            // O_NOFOLLOW/create_new-hardened, since this can fall back to a
            // predictable world-writable /tmp path (see secure_write.rs).
            crate::secure_write::write_status_best_effort(&path, &json);
        }
    }
}

pub fn reset_local_status() {
    write_status(&RecordingLocalStatus::default());
}

pub fn read_local_status() -> Option<RecordingLocalStatus> {
    recording_status_paths().iter().find_map(|path| {
        let data = std::fs::read(path).ok()?;
        serde_json::from_slice::<RecordingLocalStatus>(&data).ok()
    })
}

pub fn print_local_status(status: &RecordingLocalStatus) {
    let headline = match status.state.as_str() {
        "recording" => "Recording is active",
        "stopping" => "Recording stop requested",
        "analyzing" => "Server is analyzing the recording",
        "success" => "Mask recorded successfully",
        "failed" => "Recording failed",
        _ => {
            if status.can_record == Some(true) {
                "Recording is available"
            } else if status.can_record == Some(false) {
                "Current key cannot record masks"
            } else {
                "Recording status is not available yet"
            }
        }
    };

    println!("{}", headline);
    if let Some(service) = &status.service {
        println!("Service: {}", service);
    }
    if let Some(mask_id) = &status.mask_id {
        println!("Mask ID: {}", mask_id);
    }
    if let Some(confidence) = status.confidence {
        println!("Confidence: {:.2}", confidence);
    }
    if let Some(message) = &status.message {
        println!("Status: {}", message);
    }
}

pub fn handle_recording_status(can_record: bool, active_service: Option<&str>) {
    let message = if can_record {
        if let Some(service) = active_service {
            format!("Recording is active for '{}'", service)
        } else {
            "Recording is available for this key".to_string()
        }
    } else {
        "This key is not allowed to record masks".to_string()
    };
    write_status(&RecordingLocalStatus {
        can_record: Some(can_record),
        state: if active_service.is_some() {
            "recording".into()
        } else {
            "idle".into()
        },
        service: active_service.map(|value| value.to_string()),
        message: Some(message),
        mask_id: None,
        confidence: None,
        updated_at_ms: current_timestamp_ms(),
    });
}

pub fn mark_recording_stop_requested(service: Option<&str>) {
    write_status(&RecordingLocalStatus {
        can_record: Some(true),
        state: "stopping".into(),
        service: service.map(|value| value.to_string()),
        message: Some("Recording stop requested".into()),
        mask_id: None,
        confidence: None,
        updated_at_ms: current_timestamp_ms(),
    });
}

/// Display recording acknowledgment from server
pub fn handle_recording_ack(session_id: &[u8; 16], status: &str) {
    let sid_hex = session_id
        .iter()
        .take(4)
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    match status {
        "started" => {
            info!("📹 Recording started (session: {}...)", sid_hex);
            write_status(&RecordingLocalStatus {
                can_record: Some(true),
                state: "recording".into(),
                service: read_local_status().and_then(|status| status.service),
                message: Some("Recording started. Use the service normally.".into()),
                mask_id: None,
                confidence: None,
                updated_at_ms: current_timestamp_ms(),
            });
            println!("Recording started. Use the service normally.");
            println!("No manual stop needed — recording will finish automatically.");
            println!("It will analyze the capture once enough traffic is collected or the session goes idle.");
        }
        "analyzing" => {
            info!("🔍 Recording finished, server analyzing...");
            let service = read_local_status().and_then(|status| status.service);
            write_status(&RecordingLocalStatus {
                can_record: Some(true),
                state: "analyzing".into(),
                service,
                message: Some("Recording finished. Server is analyzing traffic.".into()),
                mask_id: None,
                confidence: None,
                updated_at_ms: current_timestamp_ms(),
            });
            println!("Recording finished. Server is analyzing traffic...");
        }
        other => {
            info!("Recording status: {}", other);
            println!("Recording status: {}", other);
        }
    }
}

/// Display recording completion
pub fn handle_recording_complete(service: &str, mask_id: &str, confidence: f32) {
    info!("✅ Mask generated for '{}'", service);
    write_status(&RecordingLocalStatus {
        can_record: Some(true),
        state: "success".into(),
        service: Some(service.to_string()),
        message: Some("Mask generated and tested".into()),
        mask_id: Some(mask_id.to_string()),
        confidence: Some(confidence),
        updated_at_ms: current_timestamp_ms(),
    });
    println!();
    println!("✅ Mask generated and tested!");
    println!();
    println!("   Mask ID:     {}", mask_id);
    println!("   Service:     {}", service);
    println!("   Confidence:  {:.2}", confidence);
    println!();
    println!("   Broadcasting to all clients...");
}

/// P2.3-desktop: parsed form of an admin-socket command, once the
/// `"{token}:"` prefix has already been verified and stripped (see
/// [`tokens_match`]). Extends the pre-existing `record_*` commands with a
/// generic in-tunnel management bridge (`Mgmt`), the cached role
/// (`Role`), and QR PNG generation (`Qr`) — all reachable by the desktop
/// GUIs (Windows egui / Linux iced) via `aivpn-client` subcommands, since
/// those GUIs shell out to the binary rather than embedding the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommand {
    RecordStart(String),
    RecordStop,
    RecordStatus,
    /// Report `AivpnClient::cached_role()`.
    Role,
    /// Generate a QR PNG for the given (UTF-8) text.
    Qr(String),
    /// Issue `AivpnClient::mgmt_call(method, path, body)`. `method`: 0=GET,
    /// 1=POST, 2=PATCH, 3=DELETE, 4=PUT (mirrors `ControlPayload::MgmtRequest`).
    Mgmt {
        method: u8,
        path: String,
        body: Vec<u8>,
    },
}

/// Decode a base64 (standard alphabet, padded) blob. Used for both the
/// `mgmt:` body field and the `qr:` text field — chosen (over URL-safe) to
/// match the majority of existing base64 use in this crate's `main.rs`.
pub fn decode_body_b64(b64: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64)
}

/// Encode bytes as base64 (standard alphabet, padded). Inverse of
/// [`decode_body_b64`].
pub fn encode_body_b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Parse the command portion of an admin-socket datagram — i.e. everything
/// after the already-verified `"{token}:"` prefix. Grammar:
///
/// - `"record_start:{service}"`, `"record_stop"`, `"record_status"` — pre-existing.
/// - `"role"` — report the cached server-assigned role.
/// - `"qr:{base64(text)}"` — generate a QR PNG for `text`.
/// - `"mgmt:{method}:{path}:{base64(body)}"` — in-tunnel management call;
///   `method` is the decimal `u8` (0=GET,1=POST,2=PATCH,3=DELETE,4=PUT),
///   `path` is the REST-shaped API path, `body` is base64 (may be empty).
///
/// Returns `None` on any malformed input (unknown command, non-numeric
/// method, invalid base64, etc.) — callers should treat that identically to
/// a rejected token, i.e. drop the datagram.
pub fn parse_admin_command(rest: &str) -> Option<AdminCommand> {
    if let Some(service) = rest.strip_prefix("record_start:") {
        return Some(AdminCommand::RecordStart(service.to_string()));
    }
    if rest == "record_stop" {
        return Some(AdminCommand::RecordStop);
    }
    if rest == "record_status" {
        return Some(AdminCommand::RecordStatus);
    }
    if rest == "role" {
        return Some(AdminCommand::Role);
    }
    if let Some(b64) = rest.strip_prefix("qr:") {
        let bytes = decode_body_b64(b64).ok()?;
        let text = String::from_utf8(bytes).ok()?;
        return Some(AdminCommand::Qr(text));
    }
    if let Some(mgmt_rest) = rest.strip_prefix("mgmt:") {
        let mut parts = mgmt_rest.splitn(3, ':');
        let method: u8 = parts.next()?.parse().ok()?;
        let path = parts.next()?.to_string();
        if path.is_empty() {
            return None;
        }
        let body_b64 = parts.next().unwrap_or("");
        let body = if body_b64.is_empty() {
            Vec::new()
        } else {
            decode_body_b64(body_b64).ok()?
        };
        return Some(AdminCommand::Mgmt { method, path, body });
    }
    None
}

/// Format the reply sent back on the admin socket for a `Mgmt` command:
/// `"{status}:{base64(body)}"`.
pub fn format_mgmt_reply(status: u16, body: &[u8]) -> String {
    format!("{}:{}", status, encode_body_b64(body))
}

/// Inverse of [`format_mgmt_reply`] — used by the CLI side to decode the
/// daemon's reply.
pub fn parse_mgmt_reply(reply: &str) -> Option<(u16, Vec<u8>)> {
    let (status_str, body_b64) = reply.split_once(':')?;
    let status: u16 = status_str.parse().ok()?;
    let body = decode_body_b64(body_b64).ok()?;
    Some((status, body))
}

/// Display recording failure
pub fn handle_recording_failed(reason: &str) {
    info!("❌ Recording failed: {}", reason);
    let can_record = if reason.to_lowercase().contains("recording-admin") {
        Some(false)
    } else {
        read_local_status().and_then(|status| status.can_record)
    };
    write_status(&RecordingLocalStatus {
        can_record,
        state: "failed".into(),
        service: read_local_status().and_then(|status| status.service),
        message: Some(reason.to_string()),
        mask_id: None,
        confidence: None,
        updated_at_ms: current_timestamp_ms(),
    });
    println!();
    println!("❌ Recording failed!");
    println!("   Reason: {}", reason);
    println!();
    println!("   Tips:");
    println!("   - Use the service for at least 1 minute");
    println!("   - Ensure active traffic (not idle)");
    println!("   - Need at least 500 packets captured");
}

#[cfg(test)]
mod admin_command_tests {
    use super::*;

    #[test]
    fn tokens_match_rejects_bad_token() {
        assert!(!tokens_match("wrong-token", "correct-token-abcdef"));
        assert!(tokens_match("same-token-1234", "same-token-1234"));
    }

    #[test]
    fn parses_record_commands_unchanged() {
        assert_eq!(
            parse_admin_command("record_start:netflix"),
            Some(AdminCommand::RecordStart("netflix".to_string()))
        );
        assert_eq!(
            parse_admin_command("record_stop"),
            Some(AdminCommand::RecordStop)
        );
        assert_eq!(
            parse_admin_command("record_status"),
            Some(AdminCommand::RecordStatus)
        );
    }

    #[test]
    fn parses_role_command() {
        assert_eq!(parse_admin_command("role"), Some(AdminCommand::Role));
    }

    #[test]
    fn parses_qr_command_roundtrip() {
        let b64 = encode_body_b64(b"aivpn://connect-payload");
        let cmd = parse_admin_command(&format!("qr:{b64}"));
        assert_eq!(
            cmd,
            Some(AdminCommand::Qr("aivpn://connect-payload".to_string()))
        );
    }

    #[test]
    fn qr_command_rejects_invalid_base64() {
        assert_eq!(parse_admin_command("qr:not-valid-b64!!"), None);
    }

    #[test]
    fn parses_mgmt_command_with_body() {
        let body = br#"{"k":"v"}"#;
        let b64 = encode_body_b64(body);
        let line = format!("mgmt:1:/api/v1/clients:{b64}");
        let parsed = parse_admin_command(&line);
        assert_eq!(
            parsed,
            Some(AdminCommand::Mgmt {
                method: 1,
                path: "/api/v1/clients".to_string(),
                body: body.to_vec(),
            })
        );
    }

    #[test]
    fn parses_mgmt_command_with_empty_body() {
        let line = "mgmt:0:/api/v1/clients:";
        assert_eq!(
            parse_admin_command(line),
            Some(AdminCommand::Mgmt {
                method: 0,
                path: "/api/v1/clients".to_string(),
                body: Vec::new(),
            })
        );
    }

    #[test]
    fn mgmt_command_rejects_non_numeric_method() {
        assert_eq!(parse_admin_command("mgmt:GET:/api/v1/clients:"), None);
    }

    #[test]
    fn mgmt_command_rejects_missing_method_or_path() {
        assert_eq!(parse_admin_command("mgmt:1"), None);
        assert_eq!(parse_admin_command("mgmt:"), None);
        assert_eq!(parse_admin_command("mgmt:1:"), None);
    }

    /// A missing trailing `:{base64(body)}` field (as opposed to an empty
    /// one, `"...:path:"`) is treated the same as an explicit empty body —
    /// lenient parsing, not a malformed command — since the method and path
    /// (the two fields that actually select the request) are both present.
    #[test]
    fn mgmt_command_tolerates_missing_body_field_as_empty() {
        assert_eq!(
            parse_admin_command("mgmt:1:/api/v1/clients"),
            Some(AdminCommand::Mgmt {
                method: 1,
                path: "/api/v1/clients".to_string(),
                body: Vec::new(),
            })
        );
    }

    #[test]
    fn unknown_command_returns_none() {
        assert_eq!(parse_admin_command("frobnicate"), None);
        assert_eq!(parse_admin_command(""), None);
    }

    #[test]
    fn mgmt_reply_roundtrips() {
        let body = b"{\"clients\":[]}";
        let reply = format_mgmt_reply(200, body);
        assert_eq!(reply, format!("200:{}", encode_body_b64(body)));
        let (status, decoded) = parse_mgmt_reply(&reply).expect("reply must parse");
        assert_eq!(status, 200);
        assert_eq!(decoded, body);
    }

    #[test]
    fn mgmt_reply_roundtrips_empty_body() {
        let reply = format_mgmt_reply(204, &[]);
        let (status, decoded) = parse_mgmt_reply(&reply).expect("reply must parse");
        assert_eq!(status, 204);
        assert!(decoded.is_empty());
    }

    #[test]
    fn mgmt_reply_parse_rejects_malformed_input() {
        assert_eq!(parse_mgmt_reply("not-a-reply"), None);
        assert_eq!(parse_mgmt_reply("abc:AAAA"), None);
    }

    /// End-to-end: the token-check step (as done by the admin task in
    /// `client.rs`) followed by command parsing, exercised together the way
    /// a real datagram is processed.
    #[test]
    fn full_datagram_pipeline_token_then_parse() {
        let token = "abcdefghijklmnopqrstuvwxyzABCDEF";
        let raw = format!(
            "{token}:mgmt:2:/api/v1/clients/1:{}",
            encode_body_b64(b"{}")
        );
        let (tok, rest) = raw.split_once(':').expect("datagram has a token prefix");
        assert!(tokens_match(tok, token));
        assert_eq!(
            parse_admin_command(rest),
            Some(AdminCommand::Mgmt {
                method: 2,
                path: "/api/v1/clients/1".to_string(),
                body: b"{}".to_vec(),
            })
        );

        let bad_raw = format!("wrong-token:mgmt:2:/api/v1/clients/1:");
        let (tok2, _rest2) = bad_raw
            .split_once(':')
            .expect("datagram has a token prefix");
        assert!(!tokens_match(tok2, token));
    }

    /// Loopback test of the request/reply framing the admin task in
    /// `client.rs` uses, over a real UDP socket, with a stub standing in
    /// for `AivpnClient::mgmt_call` (whose own correlation/timeout behavior
    /// is covered directly by `client.rs`'s `mgmt_call_*` tests — this test
    /// is about the wire framing, not the mgmt correlation logic).
    #[tokio::test]
    async fn admin_socket_mgmt_roundtrip_with_stub_callback() {
        let token = "loopback-test-token-0123456789ab";
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind server socket");
        let server_addr = server.local_addr().expect("server local_addr");

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (len, peer) = server.recv_from(&mut buf).await.expect("recv request");
            let raw = std::str::from_utf8(&buf[..len]).expect("utf8 request");
            let (tok, rest) = raw.split_once(':').expect("token prefix");
            assert!(tokens_match(tok, token), "token must match");
            let cmd = parse_admin_command(rest).expect("command must parse");
            let AdminCommand::Mgmt { method, path, body } = cmd else {
                panic!("expected an AdminCommand::Mgmt, got {cmd:?}");
            };
            assert_eq!(method, 1);
            assert_eq!(path, "/api/v1/clients");
            assert_eq!(body, b"{}");

            // Stub standing in for `mgmt.mgmt_call(...).await` in client.rs.
            let reply = format_mgmt_reply(200, b"[]");
            server
                .send_to(reply.as_bytes(), peer)
                .await
                .expect("send reply");
        });

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client socket");
        let line = format!("{token}:mgmt:1:/api/v1/clients:{}", encode_body_b64(b"{}"));
        client
            .send_to(line.as_bytes(), server_addr)
            .await
            .expect("send request");

        let mut buf = [0u8; 4096];
        let (len, _) = client.recv_from(&mut buf).await.expect("recv reply");
        let reply = std::str::from_utf8(&buf[..len]).expect("utf8 reply");
        let (status, body) = parse_mgmt_reply(reply).expect("reply must parse");
        assert_eq!(status, 200);
        assert_eq!(body, b"[]");

        server_task.await.expect("server task must not panic");
    }

    /// Same idea, but for the token-rejection path: a bad token must never
    /// reach `parse_admin_command` (mirrors the `None =>` arm in client.rs's
    /// admin task, which drops the datagram before parsing).
    #[tokio::test]
    async fn admin_socket_rejects_bad_token_before_parsing() {
        let real_token = "real-token-0123456789abcdefghij";
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind server socket");
        let server_addr = server.local_addr().expect("server local_addr");

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (len, _peer) = server.recv_from(&mut buf).await.expect("recv request");
            let raw = std::str::from_utf8(&buf[..len]).expect("utf8 request");
            let (tok, _rest) = raw.split_once(':').expect("token prefix");
            // Simulates the admin task's token check: a mismatched token
            // never gets as far as `parse_admin_command`.
            assert!(!tokens_match(tok, real_token));
        });

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client socket");
        let line = format!(
            "wrong-token:mgmt:1:/api/v1/clients:{}",
            encode_body_b64(b"{}")
        );
        client
            .send_to(line.as_bytes(), server_addr)
            .await
            .expect("send request");

        server_task.await.expect("server task must not panic");
    }
}
