//! In-app admin client-management panel — async bridge from the Linux GUI to
//! the running `aivpn-client` daemon's in-tunnel management API.
//!
//! Two transports are used here, deliberately mirroring what already exists
//! elsewhere in this codebase rather than inventing a third pattern:
//!
//!  - `aivpn-client mgmt`/`aivpn-client role` subcommands (added alongside
//!    the desktop admin-socket mgmt bridge, commit defa271) for the curated
//!    REST-shaped admin API and the cached role — the same "shell out to the
//!    client binary" pattern `vpn_manager.rs`/`app.rs` already use for
//!    connect/bench/record.
//!  - a direct UDP datagram to the client's local admin socket
//!    (`127.0.0.1:44301`) for `qr:` PNG generation. There is no CLI
//!    subcommand for this (only `record_start`/`record_stop`/`record_status`
//!    and now `mgmt`/`role` do), so this reuses the exact wire pattern
//!    `aivpn-client record start/stop` already speaks on the same socket in
//!    `main.rs`, including the per-uid token file both paths read.
//!
//! All calls here are cheap, short-lived subprocess/socket round trips,
//! always run through `Task::perform` by the caller in `app.rs` — nothing in
//! this module blocks the iced event loop.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use crate::vpn_manager::find_client_binary;

/// Admin socket the running `aivpn-client` daemon listens on for its local,
/// token-authed control commands (record/mgmt/role/qr). Matches the
/// hardcoded address `aivpn-client`'s own `main.rs`/`client.rs` use.
const ADMIN_SOCKET_ADDR: &str = "127.0.0.1:44301";

/// One row of `GET /api/v1/clients` / `GET /api/v1/clients/{id}`, trimmed to
/// the fields the panel displays or edits. Deliberately loose (`#[serde(default)]`
/// on everything, unknown fields ignored) rather than mirroring
/// `mgmt_service::ClientView` field-for-field — this is a UI-facing view type,
/// not a wire contract, and staying tolerant means a server-side field
/// addition/rename doesn't break parsing here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub vpn_ip: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub one_time: bool,
    #[serde(default)]
    pub device_bound: bool,
    /// RFC3339 timestamp string, kept opaque (no chrono dependency needed
    /// just to display it back).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// "user" | "viewer" | "admin" (`ClientRole`, `#[serde(rename_all = "lowercase")]`
    /// server-side).
    #[serde(default)]
    pub role: String,
}

impl ClientRecord {
    pub fn role_label(&self) -> &str {
        match self.role.as_str() {
            "admin" => "Admin",
            "viewer" => "Viewer",
            _ => "User",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectionKeyResponse {
    connection_key: String,
}

#[derive(Debug, Clone, Copy)]
pub enum MgmtMethod {
    Get,
    Post,
    Patch,
    /// Not wired to any panel action yet (the panel uses `POST .../revoke`
    /// rather than a raw client delete) — kept for API completeness/parity
    /// with the server's curated allowlist and `aivpn-client mgmt`'s own
    /// `MgmtMethod`.
    #[allow(dead_code)]
    Delete,
    #[allow(dead_code)]
    Put,
}

impl MgmtMethod {
    fn as_clap_arg(self) -> &'static str {
        // Matches the `#[value(rename_all = "UPPER")]` clap::ValueEnum on
        // `aivpn-client`'s own `MgmtMethod` (main.rs).
        match self {
            MgmtMethod::Get => "GET",
            MgmtMethod::Post => "POST",
            MgmtMethod::Patch => "PATCH",
            MgmtMethod::Delete => "DELETE",
            MgmtMethod::Put => "PUT",
        }
    }
}

/// Unique-enough filename suffix for a scratch body file — avoids pulling in
/// a uuid dependency just for this. Collisions are not a correctness issue
/// even so (last writer for a given nanosecond+pid wins, and each mgmt call
/// deletes its own file), just a name-reuse cosmetic.
fn scratch_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

/// Run `aivpn-client mgmt --method <M> --path <P> [--body-file <F>]` and
/// parse the `{status}\n` (stderr) / body (stdout) result the subcommand
/// prints (see `main.rs::ClientCommand::Mgmt`).
pub async fn mgmt_call(
    method: MgmtMethod,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(u16, Vec<u8>), String> {
    let bin = find_client_binary()?;

    let mut tmp_path: Option<PathBuf> = None;
    let mut cmd = tokio::process::Command::new(&bin);
    cmd.args(["mgmt", "--method", method.as_clap_arg(), "--path", path]);
    if let Some(b) = body {
        let p = std::env::temp_dir().join(format!("aivpn-admin-body-{}.json", scratch_suffix()));
        tokio::fs::write(&p, &b)
            .await
            .map_err(|e| format!("Failed to write request body: {e}"))?;
        cmd.arg("--body-file").arg(&p);
        tmp_path = Some(p);
    }

    let out = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to run aivpn-client: {e}"));
    if let Some(p) = tmp_path {
        let _ = tokio::fs::remove_file(p).await;
    }
    let out = out?;

    let stderr = String::from_utf8_lossy(&out.stderr);
    let status: u16 = stderr
        .lines()
        .next()
        .unwrap_or("0")
        .trim()
        .parse()
        .unwrap_or(0);
    if status == 0 {
        let msg = stderr.trim();
        return Err(if msg.is_empty() {
            "No reply from aivpn-client daemon (is the VPN connected?)".to_string()
        } else {
            msg.to_string()
        });
    }
    if !(200..300).contains(&status) {
        let body_txt = String::from_utf8_lossy(&out.stdout);
        return Err(format!("HTTP {status}: {}", body_txt.trim()));
    }
    Ok((status, out.stdout))
}

fn parse_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| format!("Malformed response: {e}"))
}

pub async fn list_clients() -> Result<Vec<ClientRecord>, String> {
    let (_, body) = mgmt_call(MgmtMethod::Get, "/api/v1/clients", None).await?;
    parse_json(&body)
}

pub async fn get_role() -> Result<u8, String> {
    let bin = find_client_binary()?;
    let out = tokio::process::Command::new(&bin)
        .arg("role")
        .output()
        .await
        .map_err(|e| format!("Failed to run aivpn-client: {e}"))?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.trim()
        .parse::<u8>()
        .map_err(|_| format!("Unexpected role reply: {}", s.trim()))
}

#[derive(Debug, Clone, Default)]
pub struct NewClientArgs {
    pub name: String,
    pub one_time: bool,
    /// RFC3339 timestamp string, or empty for "no expiry".
    pub expires_at: String,
}

pub async fn add_client(args: NewClientArgs) -> Result<ClientRecord, String> {
    let mut obj = serde_json::json!({
        "name": args.name,
        "one_time": args.one_time,
    });
    if !args.expires_at.trim().is_empty() {
        obj["expires_at"] = serde_json::Value::String(args.expires_at.trim().to_string());
    }
    let body = serde_json::to_vec(&obj).map_err(|e| e.to_string())?;
    let (_, resp) = mgmt_call(MgmtMethod::Post, "/api/v1/clients", Some(body)).await?;
    parse_json(&resp)
}

#[derive(Debug, Clone, Default)]
pub struct EditClientArgs {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    /// `Some(Some(ts))` sets expiry, `Some(None)` clears it, `None` leaves
    /// unchanged — matches `PatchClientRequest::expires_at` server-side.
    pub expires_at: Option<Option<String>>,
}

pub async fn update_client(id: &str, args: EditClientArgs) -> Result<ClientRecord, String> {
    let mut obj = serde_json::Map::new();
    if let Some(name) = args.name {
        obj.insert("name".into(), serde_json::Value::String(name));
    }
    if let Some(enabled) = args.enabled {
        obj.insert("enabled".into(), serde_json::Value::Bool(enabled));
    }
    if let Some(expires) = args.expires_at {
        obj.insert(
            "expires_at".into(),
            match expires {
                Some(ts) => serde_json::Value::String(ts),
                None => serde_json::Value::Null,
            },
        );
    }
    let body = serde_json::to_vec(&obj).map_err(|e| e.to_string())?;
    let (_, resp) = mgmt_call(
        MgmtMethod::Patch,
        &format!("/api/v1/clients/{id}"),
        Some(body),
    )
    .await?;
    parse_json(&resp)
}

pub async fn revoke_client(id: &str) -> Result<(), String> {
    mgmt_call(
        MgmtMethod::Post,
        &format!("/api/v1/clients/{id}/revoke"),
        None,
    )
    .await
    .map(|_| ())
}

pub async fn reset_device(id: &str) -> Result<(), String> {
    mgmt_call(
        MgmtMethod::Post,
        &format!("/api/v1/clients/{id}/reset-device"),
        None,
    )
    .await
    .map(|_| ())
}

pub async fn connection_key(id: &str) -> Result<String, String> {
    let (_, body) = mgmt_call(
        MgmtMethod::Get,
        &format!("/api/v1/clients/{id}/connection-key"),
        None,
    )
    .await?;
    let resp: ConnectionKeyResponse = parse_json(&body)?;
    Ok(resp.connection_key)
}

// ── Raw admin-socket transport (QR only — no CLI subcommand exists) ────────

/// Per-user admin-socket token path. Mirrors
/// `aivpn-client::record_cmd::admin_token_path()` exactly (this crate has no
/// dependency on `aivpn-client` as a library, only as a subprocess, so the
/// lookup is duplicated rather than shared).
fn admin_token_path() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("aivpn").join("admin.token");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/aivpn-{uid}")).join("admin.token")
}

fn read_admin_token() -> Option<String> {
    std::fs::read_to_string(admin_token_path())
        .ok()
        .map(|s| s.trim().to_string())
}

/// Request a QR-code PNG for `text` from the running client daemon's admin
/// socket: `"{token}:qr:{base64(text)}"` -> `"{base64(png)}"` (see
/// `record_cmd.rs::parse_admin_command`/`AdminCommand::Qr`,
/// `client.rs`'s admin-socket loop). Run on a blocking thread since
/// `std::net::UdpSocket` doesn't yield to the async runtime — the same
/// approach the CLI's own `send_admin_request` (main.rs) uses synchronously
/// from its one-shot process.
pub async fn qr_png(text: String) -> Result<Vec<u8>, String> {
    let token = read_admin_token()
        .ok_or_else(|| "No admin token found (is the VPN connected?)".to_string())?;
    tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let payload = format!(
            "{token}:qr:{}",
            base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
        );
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        socket
            .send_to(payload.as_bytes(), ADMIN_SOCKET_ADDR)
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 65536];
        let (len, _addr) = socket
            .recv_from(&mut buf)
            .map_err(|_| "No reply from aivpn-client daemon".to_string())?;
        let reply = std::str::from_utf8(&buf[..len]).map_err(|_| "Malformed reply".to_string())?;
        base64::engine::general_purpose::STANDARD
            .decode(reply.trim())
            .map_err(|e| format!("Malformed QR reply: {e}"))
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}
