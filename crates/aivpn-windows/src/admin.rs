//! Admin panel bridge — in-tunnel client-management commands (P3.4).
//!
//! The Windows GUI never links the Rust client core directly (see
//! `vpn_manager.rs`'s module doc) — it drives `aivpn-client.exe` as a
//! subprocess. Wave 2 (commit defa271) added a desktop admin-socket bridge
//! to that binary: `aivpn-client mgmt --method M --path P [--body-file F]`
//! issues a curated REST-shaped call against the server's management API
//! over the *live tunnel* (no separate network path, no extra credentials —
//! it rides the same PSK/device-key session), and `aivpn-client role`
//! reports the server-assigned role (0=User, 1=Viewer, 2=Admin) the running
//! daemon cached from the handshake.
//!
//! There is no CLI subcommand for QR rendering yet, so `qr_png_for` speaks
//! the daemon's raw UDP admin-socket protocol directly instead (the same
//! `"{token}:qr:{base64(text)}"` -> `"{base64(png)}"` datagram exchange the
//! `mgmt`/`role` subcommands use internally under the hood) — this crate
//! never links `aivpn-client`, so the admin-token file path logic is
//! duplicated here from `record_cmd.rs::admin_token_path()`'s Windows
//! branch rather than imported.
//!
//! Every call in this module is blocking (subprocess spawn + wait, or a
//! bounded-timeout UDP round-trip) — `spawn()` always runs it on a fresh
//! `std::thread`, reporting back through an `mpsc::Sender<AdminResponse>`
//! polled once per frame in `main.rs`'s `tick()`, so the egui update loop
//! is never blocked waiting on the client daemon (a `mgmt` call can take up
//! to ~5s if the daemon is unreachable).

use base64::Engine as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;

/// Default admin-socket address of the running `aivpn-client` daemon —
/// matches the CLI's own `--socket` default in `main.rs`'s `Mgmt`/`Role`
/// subcommands (aivpn-client crate).
const ADMIN_SOCKET_ADDR: &str = "127.0.0.1:44301";

// ── Curated REST-shaped paths (mgmt_service.rs's in-tunnel allowlist) ──────
// Role assignment is deliberately absent — `TunnelPatchClientRequest`/
// `TunnelAddClientRequest` on the server carry no `role` field, so no path
// here can ever change it; that's a web/CLI-only operation.

pub const PATH_CLIENTS: &str = "/api/v1/clients";
pub const PATH_STATUS: &str = "/api/v1/status";
pub const PATH_AUDIT_LOG: &str = "/api/v1/audit-log";

pub fn path_client(id: &str) -> String {
    format!("/api/v1/clients/{id}")
}
pub fn path_connection_key(id: &str) -> String {
    format!("/api/v1/clients/{id}/connection-key")
}
pub fn path_revoke(id: &str) -> String {
    format!("/api/v1/clients/{id}/revoke")
}
pub fn path_reset_device(id: &str) -> String {
    format!("/api/v1/clients/{id}/reset-device")
}

// ── View models ─────────────────────────────────────────────────────────
//
// Parsed defensively via `serde_json::Value` rather than a strict `#[derive
// (Deserialize)]` struct: this crate never shares the server's types, and a
// missing/renamed field degrading gracefully (falls back to a default)
// matters more here than a hard parse failure taking down the whole panel.

#[derive(Debug, Clone)]
pub struct AdminClient {
    pub id: String,
    pub name: String,
    pub vpn_ip: String,
    pub enabled: bool,
    pub one_time: bool,
    pub device_bound: bool,
    /// "user" | "viewer" | "admin" (`ClientRole`'s `#[serde(rename_all =
    /// "lowercase")]` wire form). Never settable from this panel — role
    /// elevation is deliberately excluded from the in-tunnel allowlist.
    pub role: String,
    /// RFC3339 timestamp string, or `None` if the client never expires.
    pub expires_at: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl AdminClient {
    fn from_value(v: &serde_json::Value) -> Option<Self> {
        Some(Self {
            id: v.get("id")?.as_str()?.to_string(),
            name: v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            vpn_ip: v
                .get("vpn_ip")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            enabled: v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true),
            one_time: v.get("one_time").and_then(|x| x.as_bool()).unwrap_or(false),
            device_bound: v
                .get("device_bound")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            role: v
                .get("role")
                .and_then(|x| x.as_str())
                .unwrap_or("user")
                .to_string(),
            expires_at: v
                .get("expires_at")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            bytes_in: v
                .get("stats")
                .and_then(|s| s.get("bytes_in"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
            bytes_out: v
                .get("stats")
                .and_then(|s| s.get("bytes_out"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
        })
    }
}

fn parse_client_list(body: &[u8]) -> Result<Vec<AdminClient>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| "Expected a JSON array of clients".to_string())?;
    Ok(arr.iter().filter_map(AdminClient::from_value).collect())
}

fn parse_client(body: &[u8]) -> Result<AdminClient, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    AdminClient::from_value(&v).ok_or_else(|| "Malformed client record from server".to_string())
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
}

impl AuditEntry {
    fn from_value(v: &serde_json::Value) -> Option<Self> {
        Some(Self {
            ts: v
                .get("ts")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            actor: v
                .get("actor")
                .map(|a| {
                    a.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| a.to_string())
                })
                .unwrap_or_default(),
            action: v
                .get("action")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            target: v
                .get("target")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            result: v
                .get("result")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }
}

fn parse_audit_log(body: &[u8]) -> Result<Vec<AuditEntry>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    // Bare array is the default (no `?verify=1`) shape; also accept
    // `{ "entries": [...], ... }` in case a future server version changes
    // the default response shape to match the verified one.
    let arr = v
        .as_array()
        .cloned()
        .or_else(|| v.get("entries").and_then(|e| e.as_array()).cloned())
        .ok_or_else(|| "Expected a JSON array of audit entries".to_string())?;
    Ok(arr.iter().filter_map(AuditEntry::from_value).collect())
}

#[derive(Debug, Clone, Default)]
pub struct AdminStatus {
    pub clients_total: u64,
    pub clients_enabled: u64,
    pub kernel_module: bool,
}

fn parse_status(body: &[u8]) -> Result<AdminStatus, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    Ok(AdminStatus {
        clients_total: v.get("clients_total").and_then(|x| x.as_u64()).unwrap_or(0),
        clients_enabled: v
            .get("clients_enabled")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        kernel_module: v
            .get("kernel_module")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
    })
}

// ── Add/Edit form payloads ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct NewClientForm {
    pub name: String,
    pub one_time: bool,
    /// RFC3339 timestamp, e.g. "2026-08-01T00:00:00Z". Empty = no expiry.
    pub expires_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct EditClientForm {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// RFC3339 timestamp, or empty to clear/leave-without expiry.
    pub expires_at: String,
}

// ── Requests / responses ────────────────────────────────────────────────

pub enum AdminRequest {
    Role,
    ListClients,
    AddClient(NewClientForm),
    EditClient(EditClientForm),
    DeleteClient {
        id: String,
    },
    RevokeClient {
        id: String,
    },
    ResetDevice {
        id: String,
    },
    ConnectionKey {
        id: String,
    },
    /// `text` is typically the connection key just fetched for `id`.
    Qr {
        id: String,
        text: String,
    },
    Status,
    AuditLog,
}

pub enum AdminResponse {
    Role(Result<u8, String>),
    Clients(Result<Vec<AdminClient>, String>),
    /// Result of both `AddClient` and `EditClient` — the server returns the
    /// same `ClientView` shape for both.
    ClientSaved(Result<AdminClient, String>),
    ClientDeleted {
        id: String,
        result: Result<(), String>,
    },
    ClientRevoked {
        id: String,
        result: Result<(), String>,
    },
    DeviceReset {
        id: String,
        result: Result<(), String>,
    },
    ConnectionKey {
        id: String,
        result: Result<String, String>,
    },
    /// PNG bytes for the client `id` the QR was requested for.
    Qr {
        id: String,
        result: Result<Vec<u8>, String>,
    },
    Status(Result<AdminStatus, String>),
    AuditLog(Result<Vec<AuditEntry>, String>),
}

/// Run one admin operation on a background thread and send exactly one
/// `AdminResponse` back over `tx`. Safe to call from the egui update loop —
/// never blocks the caller.
pub fn spawn(client_binary: PathBuf, req: AdminRequest, tx: Sender<AdminResponse>) {
    std::thread::spawn(move || {
        let resp = match req {
            AdminRequest::Role => AdminResponse::Role(run_role(&client_binary)),
            AdminRequest::ListClients => AdminResponse::Clients(list_clients(&client_binary)),
            AdminRequest::AddClient(form) => {
                AdminResponse::ClientSaved(add_client(&client_binary, &form))
            }
            AdminRequest::EditClient(form) => {
                AdminResponse::ClientSaved(edit_client(&client_binary, &form))
            }
            AdminRequest::DeleteClient { id } => {
                let result = mgmt_status_only(&client_binary, "DELETE", &path_client(&id));
                AdminResponse::ClientDeleted { id, result }
            }
            AdminRequest::RevokeClient { id } => {
                let result = mgmt_status_only(&client_binary, "POST", &path_revoke(&id));
                AdminResponse::ClientRevoked { id, result }
            }
            AdminRequest::ResetDevice { id } => {
                let result = mgmt_status_only(&client_binary, "POST", &path_reset_device(&id));
                AdminResponse::DeviceReset { id, result }
            }
            AdminRequest::ConnectionKey { id } => {
                let result = connection_key(&client_binary, &id);
                AdminResponse::ConnectionKey { id, result }
            }
            AdminRequest::Qr { id, text } => AdminResponse::Qr {
                id,
                result: qr_png_for(&text),
            },
            AdminRequest::Status => AdminResponse::Status(get_status(&client_binary)),
            AdminRequest::AuditLog => AdminResponse::AuditLog(get_audit_log(&client_binary)),
        };
        let _ = tx.send(resp);
    });
}

// ── `aivpn-client mgmt` / `role` bridge ─────────────────────────────────────

/// Run `aivpn-client mgmt --method M --path P [--body-file F]` and parse its
/// output per the documented contract (`ClientCommand::Mgmt`'s doc comment
/// in aivpn-client's `main.rs`): numeric HTTP-style status on stderr, raw
/// response body on stdout. A non-empty body is written to a uniquely-named
/// temp file first (the CLI only accepts `--body-file`, not inline JSON)
/// and removed afterward — best-effort, a leaked temp file on a crash
/// mid-call is harmless.
fn mgmt_call(
    client_binary: &Path,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let body_file = if body.is_empty() {
        None
    } else {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "aivpn-admin-body-{}-{ts}-{n}.json",
            std::process::id()
        ));
        std::fs::write(&p, body).map_err(|e| format!("Failed to write request body: {e}"))?;
        Some(p)
    };

    let mut cmd = Command::new(client_binary);
    cmd.arg("mgmt")
        .arg("--method")
        .arg(method)
        .arg("--path")
        .arg(path);
    if let Some(p) = &body_file {
        cmd.arg("--body-file").arg(p);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let out = cmd.output();
    if let Some(p) = &body_file {
        let _ = std::fs::remove_file(p);
    }
    let out = out.map_err(|e| format!("Failed to run aivpn-client: {e}"))?;

    let stderr_trim = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if let Ok(status) = stderr_trim.parse::<u16>() {
        // A genuine numeric `0` only happens on the CLI's own local-failure
        // sentinel path (the "no reply"/"malformed reply" cases print a
        // non-numeric message instead, caught by the `else` branch below) —
        // `check_status` below treats it uniformly as an error, since no
        // caller ever expects a real HTTP-style status of 0.
        Ok((status, out.stdout))
    } else if stderr_trim.is_empty() {
        Err("aivpn-client mgmt produced no output".to_string())
    } else {
        Err(stderr_trim)
    }
}

fn mgmt_status_only(client_binary: &Path, method: &str, path: &str) -> Result<(), String> {
    let (status, body) = mgmt_call(client_binary, method, path, &[])?;
    check_status(status, &body)
}

fn check_status(status: u16, body: &[u8]) -> Result<(), String> {
    if status == 0 {
        return Err(
            "No response from the VPN client — make sure it's connected and your account has Admin access"
                .to_string(),
        );
    }
    if !(200..300).contains(&status) {
        let msg = String::from_utf8_lossy(body);
        let msg = msg.trim();
        return Err(if msg.is_empty() {
            format!("Server returned status {status}")
        } else {
            format!("Server returned status {status}: {msg}")
        });
    }
    Ok(())
}

fn list_clients(client_binary: &Path) -> Result<Vec<AdminClient>, String> {
    let (status, body) = mgmt_call(client_binary, "GET", PATH_CLIENTS, &[])?;
    check_status(status, &body)?;
    parse_client_list(&body)
}

fn add_client(client_binary: &Path, form: &NewClientForm) -> Result<AdminClient, String> {
    // Matches the server's `TunnelAddClientRequest` (mgmt_service.rs): name
    // (required), one_time (defaults false if omitted), expires_at
    // (plain `Option<DateTime<Utc>>` — omitting the key deserializes as
    // `None`, same as leaving it blank in the form). No `role` field: role
    // assignment is not exposed over this path.
    let mut json = serde_json::json!({
        "name": form.name,
        "one_time": form.one_time,
    });
    if !form.expires_at.trim().is_empty() {
        json["expires_at"] = serde_json::Value::String(form.expires_at.trim().to_string());
    }
    let bytes = serde_json::to_vec(&json).map_err(|e| format!("Failed to encode request: {e}"))?;
    let (status, body) = mgmt_call(client_binary, "POST", PATH_CLIENTS, &bytes)?;
    check_status(status, &body)?;
    parse_client(&body)
}

fn edit_client(client_binary: &Path, form: &EditClientForm) -> Result<AdminClient, String> {
    // Matches `TunnelPatchClientRequest`: `expires_at` uses the
    // absent/null/value tri-state (`deserialize_opt_opt`) — omit the key to
    // leave unchanged, `null` to clear, a string to set. This panel always
    // reflects the form's current expiry, so the key is always sent
    // explicitly (null when the field was cleared).
    let mut json = serde_json::json!({
        "name": form.name,
        "enabled": form.enabled,
    });
    json["expires_at"] = if form.expires_at.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(form.expires_at.trim().to_string())
    };
    let bytes = serde_json::to_vec(&json).map_err(|e| format!("Failed to encode request: {e}"))?;
    let (status, body) = mgmt_call(client_binary, "PATCH", &path_client(&form.id), &bytes)?;
    check_status(status, &body)?;
    parse_client(&body)
}

fn connection_key(client_binary: &Path, id: &str) -> Result<String, String> {
    let (status, body) = mgmt_call(client_binary, "GET", &path_connection_key(id), &[])?;
    check_status(status, &body)?;
    let v: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    // The in-tunnel dispatcher (`mgmt_service::dispatch`, `Route::
    // ClientConnectionKey`) wraps this as `{"key": ...}` — accept
    // `connection_key` too in case a future server version aligns the
    // tunnel path's response shape with the plain REST handler's.
    v.get("key")
        .or_else(|| v.get("connection_key"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Server response did not include a connection key".to_string())
}

fn get_status(client_binary: &Path) -> Result<AdminStatus, String> {
    let (status, body) = mgmt_call(client_binary, "GET", PATH_STATUS, &[])?;
    check_status(status, &body)?;
    parse_status(&body)
}

fn get_audit_log(client_binary: &Path) -> Result<Vec<AuditEntry>, String> {
    let (status, body) = mgmt_call(client_binary, "GET", PATH_AUDIT_LOG, &[])?;
    check_status(status, &body)?;
    parse_audit_log(&body)
}

/// Run `aivpn-client role` and parse the bare decimal digit it prints to
/// stdout on success (0=User, 1=Viewer, 2=Admin).
fn run_role(client_binary: &Path) -> Result<u8, String> {
    let mut cmd = Command::new(client_binary);
    cmd.arg("role");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("Failed to run aivpn-client: {e}"))?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        s.parse::<u8>()
            .map_err(|_| format!("Unexpected role reply: {s:?}"))
    } else {
        let s = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if s.is_empty() {
            "aivpn-client role failed".to_string()
        } else {
            s
        })
    }
}

// ── QR rendering — raw admin-socket protocol (no CLI subcommand exists) ────

/// Mirrors `aivpn_client::record_cmd::admin_token_path()`'s Windows branch —
/// duplicated here because this crate only subprocesses `aivpn-client`
/// rather than linking it, and no CLI subcommand bridges the `qr:` admin
/// command.
fn admin_token_path() -> PathBuf {
    if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app).join("AIVPN").join("admin.token");
    }
    std::env::temp_dir().join("aivpn-admin.token")
}

fn read_admin_token() -> Option<String> {
    std::fs::read_to_string(admin_token_path())
        .ok()
        .map(|s| s.trim().to_string())
}

/// Ask the running daemon to render `text` (typically a client's
/// `aivpn://` connection key) as a QR code PNG, via the admin socket's
/// `"{token}:qr:{base64(text)}"` -> `"{base64(png)}"` datagram exchange —
/// the same wire protocol the `mgmt`/`role` CLI subcommands use
/// internally (`send_admin_request` in aivpn-client's `main.rs`),
/// reimplemented here since this crate has no way to call that function
/// directly and no CLI subcommand wraps it.
fn qr_png_for(text: &str) -> Result<Vec<u8>, String> {
    let token = read_admin_token().ok_or_else(|| {
        "No admin token found — is the VPN client running and connected as Admin?".to_string()
    })?;
    let b64_text = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let line = format!("{token}:qr:{b64_text}");

    let socket =
        std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("Socket bind failed: {e}"))?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| format!("Socket configuration failed: {e}"))?;
    socket
        .send_to(line.as_bytes(), ADMIN_SOCKET_ADDR)
        .map_err(|e| format!("Failed to reach the VPN client: {e}"))?;

    let mut buf = [0u8; 65536];
    let (len, _addr) = socket.recv_from(&mut buf).map_err(|e| {
        format!("No reply from the VPN client at {ADMIN_SOCKET_ADDR} (is it running?): {e}")
    })?;
    let reply =
        std::str::from_utf8(&buf[..len]).map_err(|_| "Invalid reply encoding".to_string())?;
    base64::engine::general_purpose::STANDARD
        .decode(reply.trim())
        .map_err(|e| format!("Failed to decode QR image: {e}"))
}
