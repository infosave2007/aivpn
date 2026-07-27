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
    /// Wave B3: per-client exit-node override (`host:port`), or `None` to
    /// fall back to the pool's global default (`pool.exit_node`). Matches
    /// `mgmt_service::ClientView::exit_node` verbatim.
    #[serde(default)]
    pub exit_node: Option<String>,
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

/// One row of `GET /api/v1/pool/nodes`. Field names match
/// `mgmt_service::PoolNodeInfo` verbatim (this crate has no dependency on
/// `aivpn-server`, so the shape is duplicated rather than shared — same
/// tolerant-parsing rationale as `ClientRecord`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolNode {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub last_seen_unix: Option<i64>,
}

/// `GET /api/v1/pool/health`. Field names match `mgmt_service::PoolHealth`
/// verbatim.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolHealth {
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub total_nodes: usize,
    #[serde(default)]
    pub connected_peers: usize,
    #[serde(default)]
    pub converged_peers: usize,
    #[serde(default)]
    pub diverged: bool,
    #[serde(default)]
    pub partition_conflict: bool,
    #[serde(default)]
    pub subnet_mismatch: bool,
}

pub async fn pool_nodes() -> Result<Vec<PoolNode>, String> {
    let (_, body) = mgmt_call(MgmtMethod::Get, "/api/v1/pool/nodes", None).await?;
    parse_json(&body)
}

pub async fn pool_health() -> Result<PoolHealth, String> {
    let (_, body) = mgmt_call(MgmtMethod::Get, "/api/v1/pool/health", None).await?;
    parse_json(&body)
}

/// One entry of the append-only admin audit log
/// (`aivpn-server::audit_log::AuditEntry`), as returned by
/// `GET /api/v1/audit-log?verify=1`. Field names match verbatim (same
/// tolerant-parsing rationale as `ClientRecord`/`PoolNode` above) — `actor`
/// stays a plain `String` (server-side `AuditActor` serializes as
/// `"cli"`/`"api"`/`"system"` via `#[serde(rename_all = "snake_case")]`)
/// rather than mirroring the enum, since this is a display-only view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditEntry {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub result: String,
}

/// `GET /api/v1/audit-log?verify=1` response — matches
/// `mgmt_service::AuditVerifyView` verbatim. `verified`/`broken_at` report
/// the hash-chain check over the returned (tail-windowed) entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLogView {
    #[serde(default)]
    pub entries: Vec<AuditEntry>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub broken_at: Option<usize>,
}

/// Fetch the audit log tail with hash-chain verification. Available to
/// both Viewer (1) and Admin (2) roles server-side — `authorize()` allows
/// every curated GET route, and `audit-log` is one of them.
pub async fn audit_log() -> Result<AuditLogView, String> {
    let (_, body) = mgmt_call(MgmtMethod::Get, "/api/v1/audit-log?verify=1", None).await?;
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
    /// `host:port`, or empty for "use the pool's global default". Wave B3:
    /// `POST /api/v1/clients` has no `exit_node` field server-side (see
    /// `TunnelAddClientRequest`) — a non-empty value here is applied with a
    /// follow-up `PATCH` right after creation, same as the edit-form path.
    pub exit_node: String,
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
    let created: ClientRecord = parse_json(&resp)?;
    let exit_node = args.exit_node.trim();
    if exit_node.is_empty() {
        return Ok(created);
    }
    update_client(
        &created.id,
        EditClientArgs {
            exit_node: Some(Some(exit_node.to_string())),
            ..Default::default()
        },
    )
    .await
}

#[derive(Debug, Clone, Default)]
pub struct EditClientArgs {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    /// `Some(Some(ts))` sets expiry, `Some(None)` clears it, `None` leaves
    /// unchanged — matches `PatchClientRequest::expires_at` server-side.
    pub expires_at: Option<Option<String>>,
    /// Wave B3: `Some(Some(addr))` sets a `host:port` per-client exit-node
    /// override, `Some(None)` clears it (falls back to the pool's global
    /// default), `None` leaves it unchanged — matches
    /// `TunnelPatchClientRequest::exit_node` server-side.
    pub exit_node: Option<Option<String>>,
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
    if let Some(exit_node) = args.exit_node {
        obj.insert(
            "exit_node".into(),
            match exit_node {
                Some(addr) => serde_json::Value::String(addr),
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

/// G-A3: which `HeavySetting` (`mgmt_service.rs`) a `POST /api/v1/config/apply`
/// call selects — mirrors the server's `TunnelApplyRequest`: presence of the
/// `exit_node` key (even as JSON `null`, to clear it) selects the pool's
/// global default exit node; its absence selects the per-client active-mask
/// override via `client`/`mask`.
///
/// IMPORTANT: unlike a per-client `exit_node` override, `ActiveMask` has NO
/// "apply to every client"/global form server-side —
/// `mgmt_service::resolve_heavy_setting` rejects an empty `client` with
/// `400 Bad Request` and otherwise resolves it by name-or-id against the
/// live client database. So `ActiveMask` here always names one specific
/// client, not a server-wide default (the panel's client picker in `app.rs`
/// is not cosmetic — it is required for the call to succeed at all).
#[derive(Debug, Clone)]
pub enum ConfigSetting {
    /// Set `client` (name or id)'s active-mask override to `mask` — applied
    /// live, no reconnect needed (`management_api.rs::set_active_mask`'s
    /// same on-disk override file).
    ActiveMask { client: String, mask: String },
    /// Set (`Some(addr)`) or clear (`None`) the pool's global default exit
    /// node (`pool.exit_node` in `server.json`). Persisted immediately but
    /// only takes effect after the server process restarts — see
    /// `HeavySetting::ExitNode`'s doc comment server-side.
    ExitNode(Option<String>),
}

#[derive(Debug, Clone, Deserialize)]
struct ApplyConfigResponse {
    token: String,
    /// Echoed back by the server (always `true` on a `200` — a failed apply
    /// never reaches here at all, `mgmt_call` already turned a non-2xx
    /// status into an `Err`) — kept only for wire-shape completeness, not
    /// read anywhere.
    #[allow(dead_code)]
    applied: bool,
}

/// `POST /api/v1/config/apply` — Admin-only (role 2; a Viewer's `mgmt_call`
/// would get `403` from the server's `authorize()` before this even runs).
/// Returns the confirm token the caller must round-trip to
/// [`confirm_config`] within the server's `PENDING_CONFIG_TIMEOUT` (~120s)
/// or the change is automatically rolled back by the gateway's sweep task.
pub async fn apply_config(setting: ConfigSetting) -> Result<String, String> {
    let obj = match setting {
        ConfigSetting::ActiveMask { client, mask } => serde_json::json!({
            "client": client,
            "mask": mask,
        }),
        // `exit_node` must be PRESENT (even as JSON `null`) to select the
        // `HeavySetting::ExitNode` branch server-side — `json!` serializes
        // `Option::None` as `Value::Null`, never omits the key, so this is
        // correct for both "set" and "clear".
        ConfigSetting::ExitNode(addr) => serde_json::json!({ "exit_node": addr }),
    };
    let body = serde_json::to_vec(&obj).map_err(|e| e.to_string())?;
    let (_, resp) = mgmt_call(MgmtMethod::Post, "/api/v1/config/apply", Some(body)).await?;
    let parsed: ApplyConfigResponse = parse_json(&resp)?;
    Ok(parsed.token)
}

/// `POST /api/v1/config/confirm` — Admin-only. Confirms a still-pending
/// token from [`apply_config`] before the server's confirm window elapses.
/// `204 No Content` on success (nothing to parse; `mgmt_call` already turns
/// a non-2xx status, e.g. an expired/unknown token, into an `Err`).
pub async fn confirm_config(token: String) -> Result<(), String> {
    let body =
        serde_json::to_vec(&serde_json::json!({ "token": token })).map_err(|e| e.to_string())?;
    mgmt_call(MgmtMethod::Post, "/api/v1/config/confirm", Some(body))
        .await
        .map(|_| ())
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
