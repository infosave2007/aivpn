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
/// G-A2: `?verify=1` requests hash-chain verification alongside the tail —
/// the server always answers with the `{entries, verified, broken_at}`
/// shape (`AuditVerifyView`, `mgmt_service.rs`) when this query param is
/// present, rather than the bare-array shape it uses without it. Viewer(1)
/// and Admin(2) both reach this route — `authorize()` treats every curated
/// route as GET-only-or-full depending on role, and `audit-log` only ever
/// has a GET method to begin with.
pub const PATH_AUDIT_LOG: &str = "/api/v1/audit-log?verify=1";
/// B3: `GET /api/v1/pool/nodes` — read-only pool topology, Viewer+Admin
/// (`mgmt_service.rs`'s `authorize`: role 1 is GET-only, role 2 is full).
pub const PATH_POOL_NODES: &str = "/api/v1/pool/nodes";
/// B3: `GET /api/v1/pool/health` — aggregate pool-sync health summary.
pub const PATH_POOL_HEALTH: &str = "/api/v1/pool/health";
/// G-A3: `POST /api/v1/config/apply` — apply-with-rollback for a
/// [`HeavySetting`]-class change (server's `mgmt_service.rs`). Admin-only
/// (`authorize()`: role 2 required for any non-GET curated route).
pub const PATH_CONFIG_APPLY: &str = "/api/v1/config/apply";
/// G-A3: `POST /api/v1/config/confirm` — makes a pending apply permanent,
/// cancelling its auto-rollback.
pub const PATH_CONFIG_CONFIRM: &str = "/api/v1/config/confirm";

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
    /// B3: this client's per-client exit-node routing override
    /// (`host:port`), or `None` to fall back to the server's global
    /// default (`pool.exit_node`) — mirrors `ClientView::exit_node`
    /// (mgmt_service.rs). Settable only via `PATCH /api/v1/clients/:id`,
    /// never on create — see `TunnelAddClientRequest`'s doc comment.
    pub exit_node: Option<String>,
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
            exit_node: v
                .get("exit_node")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
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

/// G-A2: `GET /api/v1/audit-log?verify=1` response — mirrors
/// `mgmt_service::AuditVerifyView` verbatim (`{entries, verified,
/// broken_at}`). `verified`/`broken_at` report the hash-chain check over
/// the returned (possibly tail-windowed) `entries` — see that struct's doc
/// comment on the server for the tail-window caveat.
#[derive(Debug, Clone, Default)]
pub struct AuditLogView {
    pub entries: Vec<AuditEntry>,
    /// `None` only for the defensive bare-array fallback below (no
    /// verification info available at all) — never conflated with
    /// `Some(false)` ("verified and broken"), so the UI can distinguish
    /// "unknown" from "BROKEN" rather than defaulting an unknown state to
    /// a scary red badge.
    pub verified: Option<bool>,
    /// Tail-window index (0-based, oldest-first, matching `entries`) of the
    /// first broken link, present only when `verified == Some(false)`.
    pub broken_at: Option<usize>,
}

fn parse_audit_log(body: &[u8]) -> Result<AuditLogView, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    // `PATH_AUDIT_LOG` always sends `?verify=1`, so the server always
    // answers with the `{entries, verified, broken_at}` object shape — but
    // still accept a bare array defensively (an older server that doesn't
    // recognize `verify` yet, or an intermediary that stripped the query),
    // reporting no verification result in that case rather than failing
    // the whole panel.
    if let Some(arr) = v.as_array() {
        return Ok(AuditLogView {
            entries: arr.iter().filter_map(AuditEntry::from_value).collect(),
            verified: None,
            broken_at: None,
        });
    }
    let entries = v
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| "Expected a JSON array of audit entries".to_string())?
        .iter()
        .filter_map(AuditEntry::from_value)
        .collect();
    Ok(AuditLogView {
        entries,
        verified: v.get("verified").and_then(|x| x.as_bool()),
        broken_at: v
            .get("broken_at")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize),
    })
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

// ── Pool topology view models (B3) ──────────────────────────────────────
//
// Mirror `mgmt_service.rs`'s `PoolNodeInfo`/`PoolHealth` — parsed
// defensively via `serde_json::Value` for the same reason as `AdminClient`
// above (this crate never shares the server's types).

#[derive(Debug, Clone)]
pub struct PoolNode {
    pub node_id: String,
    pub address: Option<String>,
    pub verified: bool,
    pub revoked: bool,
    pub connected: bool,
    pub last_seen_unix: Option<i64>,
}

impl PoolNode {
    fn from_value(v: &serde_json::Value) -> Option<Self> {
        Some(Self {
            node_id: v.get("node_id")?.as_str()?.to_string(),
            address: v
                .get("address")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            verified: v.get("verified").and_then(|x| x.as_bool()).unwrap_or(false),
            revoked: v.get("revoked").and_then(|x| x.as_bool()).unwrap_or(false),
            connected: v
                .get("connected")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            last_seen_unix: v.get("last_seen_unix").and_then(|x| x.as_i64()),
        })
    }
}

fn parse_pool_nodes(body: &[u8]) -> Result<Vec<PoolNode>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| "Expected a JSON array of pool nodes".to_string())?;
    Ok(arr.iter().filter_map(PoolNode::from_value).collect())
}

// ── G-B1: exit-node picker (pool-node dropdown) ─────────────────────────
//
// The add/edit forms used to be a bare free-text `host:port` field. G-B1
// replaces it with an egui `ComboBox` sourced from the pool's own node
// addresses (`GET /api/v1/pool/nodes`, already fetched for the pool
// topology section above) plus two synthetic entries: "(default)" — clears
// the override so the client falls back to the server's global
// `pool.exit_node` — and "custom" — keeps the field free-text for an
// address that isn't (yet) a pool member. Both helpers below are pure/
// host-clean so they're unit-testable on Linux even though the `ComboBox`
// itself only ever draws under `cfg(windows)`.

/// Distinct, non-empty candidate addresses to list in the dropdown, in
/// server order (`Vec` preserves first-seen order; a `HashSet` would not).
/// Revoked nodes are excluded — routing a client's exit traffic through a
/// pool member the operator just revoked would be actively wrong, not just
/// stale.
pub fn exit_node_addresses(nodes: &[PoolNode]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for n in nodes {
        if n.revoked {
            continue;
        }
        let Some(addr) = n.address.as_deref().map(str::trim) else {
            continue;
        };
        if addr.is_empty() {
            continue;
        }
        if seen.insert(addr.to_string()) {
            out.push(addr.to_string());
        }
    }
    out
}

/// Which dropdown entry the form's current free-text value corresponds to.
/// Purely a function of the text + the known address list — the caller
/// (egui code) additionally tracks an explicit "user picked custom" flag so
/// switching to Custom in the UI doesn't immediately snap back to Default/
/// a Node entry just because the text happens to match one (see
/// `draw_admin_clients_section`'s `admin_add_exit_custom_mode` field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitNodeChoice {
    /// Empty field — no override, server's global default applies.
    Default,
    /// Field matches one of `exit_node_addresses`'s entries exactly.
    Node(String),
    /// Non-empty field that isn't a known pool-node address.
    Custom,
}

pub fn classify_exit_node(current: &str, known_addresses: &[String]) -> ExitNodeChoice {
    let trimmed = current.trim();
    if trimmed.is_empty() {
        return ExitNodeChoice::Default;
    }
    if known_addresses.iter().any(|a| a == trimmed) {
        return ExitNodeChoice::Node(trimmed.to_string());
    }
    ExitNodeChoice::Custom
}

#[derive(Debug, Clone, Default)]
pub struct PoolHealth {
    pub transport: String,
    pub total_nodes: u64,
    pub connected_peers: u64,
    pub converged_peers: u64,
    pub diverged: bool,
    pub partition_conflict: bool,
    pub subnet_mismatch: bool,
}

fn parse_pool_health(body: &[u8]) -> Result<PoolHealth, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    Ok(PoolHealth {
        transport: v
            .get("transport")
            .and_then(|x| x.as_str())
            .unwrap_or("none")
            .to_string(),
        total_nodes: v.get("total_nodes").and_then(|x| x.as_u64()).unwrap_or(0),
        connected_peers: v
            .get("connected_peers")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        converged_peers: v
            .get("converged_peers")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        diverged: v.get("diverged").and_then(|x| x.as_bool()).unwrap_or(false),
        partition_conflict: v
            .get("partition_conflict")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        subnet_mismatch: v
            .get("subnet_mismatch")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
    })
}

// ── G-A3: Server Settings — apply-with-rollback (active mask + global ──────
// exit node) ─────────────────────────────────────────────────────────────
//
// Two of the server's `HeavySetting` variants (`mgmt_service.rs`) are
// exposed here, both through the SAME `POST /api/v1/config/apply` ->
// `POST /api/v1/config/confirm` flow:
//
// - `HeavySetting::ActiveMask { client, mask }` — sets ONE client's active-
//   mask override (`resolve_heavy_setting`'s `ActiveMask` arm requires a
//   non-empty, resolvable `client` — this is a PER-CLIENT setting, not a
//   server-wide default, despite the client being free to pass an empty
//   string on the wire; an empty `client` always 400s server-side with
//   "fields 'client' and 'mask' are required"). The panel therefore always
//   sends a real client id, picked from the already-loaded admin client
//   list.
// - `HeavySetting::ExitNode { addr }` — sets (`Some`) or clears (`None`)
//   the server's GLOBAL default exit node (`pool.exit_node`); unlike the
//   per-client `exit_node` override on `EditClientForm`, this only takes
//   effect after the server process restarts (see that variant's doc
//   comment in `mgmt_service.rs`).
//
// NOTE ON THE MISSING MASK PICKER: there is deliberately no `ListMasks`
// request here. `GET /api/v1/masks` (`management_api.rs::list_masks`) is a
// plain REST route with no equivalent in the tunnel's curated `Route`
// enum/`classify_route` table (`mgmt_service.rs`) — every call this crate
// makes rides `aivpn-client mgmt`, which only ever reaches the tunnel, so
// there is no way to fetch the mask list from here. The mask id is
// therefore free text, validated client-side by `mask_id_looks_valid`
// (UX only — the server remains the authority) against the same
// character class `resolve_heavy_setting`'s `ActiveMask` arm enforces.

/// Which `HeavySetting` an apply/confirm round-trip is for — lets the UI
/// route a response to the right form's busy/error/pending-token state
/// without a second channel per setting. Both settings can have an
/// independently pending (unconfirmed) token at once — the server's
/// `PendingConfigManager` keys entries by `target_path`, and
/// `ActiveMask`/`ExitNode` write different files, so they never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSetting {
    ActiveMask,
    ExitNode,
}

/// Result of a successful `POST /api/v1/config/apply` — mirrors the
/// server's `ApplyResponse` (`mgmt_service.rs`) `{"token","applied"}`
/// verbatim. The caller must present `token` to `POST /api/v1/config/
/// confirm` within the server's `PENDING_CONFIG_TIMEOUT` (~120s, not
/// itself sent over the wire) or the server's sweep task rolls the change
/// back automatically.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub token: String,
    pub applied: bool,
}

fn parse_apply_response(body: &[u8]) -> Result<ApplyResult, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Bad JSON from server: {e}"))?;
    let token = v
        .get("token")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "Server response did not include a token".to_string())?
        .to_string();
    let applied = v.get("applied").and_then(|x| x.as_bool()).unwrap_or(false);
    Ok(ApplyResult { token, applied })
}

/// Body for `POST /api/v1/config/apply` selecting `HeavySetting::
/// ActiveMask { client, mask }`. Deliberately omits the `exit_node` key
/// entirely (rather than sending it as `null`) — the tunnel's
/// `TunnelApplyRequest::exit_node` uses the same absent/null/value
/// tri-state as `EditClientForm`'s PATCH body (`deserialize_opt_opt`), and
/// its mere PRESENCE (even `null`) is what selects `HeavySetting::
/// ExitNode` on the server (`management_api.rs::apply_config`: `if let
/// Some(exit_node) = body.exit_node { ExitNode } else { ActiveMask }`) —
/// so this body must never contain that key at all.
pub fn build_apply_mask_body(client_id: &str, mask_id: &str) -> Vec<u8> {
    serde_json::json!({ "client": client_id, "mask": mask_id })
        .to_string()
        .into_bytes()
}

/// Body for `POST /api/v1/config/apply` selecting `HeavySetting::ExitNode
/// { addr }`. Always includes the `exit_node` key (see
/// `build_apply_mask_body`'s doc comment) — `null` clears the global
/// default, a string sets it.
pub fn build_apply_exit_node_body(addr: Option<&str>) -> Vec<u8> {
    let json = serde_json::json!({ "exit_node": addr });
    json.to_string().into_bytes()
}

/// Body for `POST /api/v1/config/confirm`.
pub fn build_confirm_body(token: &str) -> Vec<u8> {
    serde_json::json!({ "token": token })
        .to_string()
        .into_bytes()
}

/// Client-side mirror of `resolve_heavy_setting`'s `ActiveMask` arm's mask-
/// name character class (`mgmt_service.rs`: alphanumeric, `-`, `_`) — used
/// only to disable the Apply button before round-tripping to the server
/// for a predictable 400. Not security-relevant; the server re-validates
/// unconditionally.
pub fn mask_id_looks_valid(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

// ── Add/Edit form payloads ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct NewClientForm {
    pub name: String,
    pub one_time: bool,
    /// RFC3339 timestamp, e.g. "2026-08-01T00:00:00Z". Empty = no expiry.
    pub expires_at: String,
    /// B3: `host:port`, or empty to use the server's global default. Not
    /// part of `TunnelAddClientRequest` on the wire — `add_client` below
    /// issues a follow-up `PATCH` after creation when this is non-empty,
    /// since the tunnel's create route has no `exit_node` field.
    pub exit_node: String,
}

#[derive(Debug, Clone, Default)]
pub struct EditClientForm {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// RFC3339 timestamp, or empty to clear/leave-without expiry.
    pub expires_at: String,
    /// B3: `host:port`, or empty to clear the override (fall back to the
    /// server's global default). Always sent explicitly, same tri-state
    /// convention as `expires_at` above.
    pub exit_node: String,
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
    /// B3: `GET /api/v1/pool/nodes` — Viewer+Admin.
    PoolNodes,
    /// B3: `GET /api/v1/pool/health` — Viewer+Admin.
    PoolHealth,
    /// G-A3: `POST /api/v1/config/apply` selecting `HeavySetting::
    /// ActiveMask` — Admin only.
    ApplyActiveMask {
        client_id: String,
        mask: String,
    },
    /// G-A3: `POST /api/v1/config/apply` selecting `HeavySetting::
    /// ExitNode` — Admin only.
    ApplyExitNode {
        addr: Option<String>,
    },
    /// G-A3: `POST /api/v1/config/confirm` — Admin only. `setting` is
    /// carried through unchanged so the matching `AdminResponse` can route
    /// back to the right form.
    ConfirmConfig {
        setting: ConfigSetting,
        token: String,
    },
}

pub enum AdminResponse {
    Role(Result<u8, String>),
    Clients(Result<Vec<AdminClient>, String>),
    /// Result of both `AddClient` and `EditClient` — the server returns the
    /// same `ClientView` shape for both. `editing` records WHICH request
    /// this answers (`true` = `EditClient`), so the UI routes the result to
    /// the right form even if the user opened the other form while the
    /// (up to ~5s per call) request was still in flight — the UI's own
    /// "is the edit form open right now" state is not a reliable proxy for
    /// that (BUG FIX, review: an Add error used to land in the Edit form's
    /// error slot, and an Add success used to close a just-opened Edit
    /// form, whenever the two overlapped).
    ClientSaved {
        editing: bool,
        result: Result<AdminClient, String>,
    },
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
    /// G-A2: response to `AdminRequest::AuditLog`.
    AuditLog(Result<AuditLogView, String>),
    /// B3: response to `AdminRequest::PoolNodes`.
    PoolNodes(Result<Vec<PoolNode>, String>),
    /// B3: response to `AdminRequest::PoolHealth`.
    PoolHealth(Result<PoolHealth, String>),
    /// G-A3: response to `AdminRequest::ApplyActiveMask` /
    /// `AdminRequest::ApplyExitNode`.
    ConfigApplied {
        setting: ConfigSetting,
        result: Result<ApplyResult, String>,
    },
    /// G-A3: response to `AdminRequest::ConfirmConfig`.
    ConfigConfirmed {
        setting: ConfigSetting,
        result: Result<(), String>,
    },
}

/// Run one admin operation on a background thread and send exactly one
/// `AdminResponse` back over `tx`. Safe to call from the egui update loop —
/// never blocks the caller.
pub fn spawn(client_binary: PathBuf, req: AdminRequest, tx: Sender<AdminResponse>) {
    std::thread::spawn(move || {
        let resp = match req {
            AdminRequest::Role => AdminResponse::Role(run_role(&client_binary)),
            AdminRequest::ListClients => AdminResponse::Clients(list_clients(&client_binary)),
            AdminRequest::AddClient(form) => AdminResponse::ClientSaved {
                editing: false,
                result: add_client(&client_binary, &form),
            },
            AdminRequest::EditClient(form) => AdminResponse::ClientSaved {
                editing: true,
                result: edit_client(&client_binary, &form),
            },
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
            AdminRequest::PoolNodes => AdminResponse::PoolNodes(list_pool_nodes(&client_binary)),
            AdminRequest::PoolHealth => AdminResponse::PoolHealth(get_pool_health(&client_binary)),
            AdminRequest::ApplyActiveMask { client_id, mask } => AdminResponse::ConfigApplied {
                setting: ConfigSetting::ActiveMask,
                result: apply_active_mask(&client_binary, &client_id, &mask),
            },
            AdminRequest::ApplyExitNode { addr } => AdminResponse::ConfigApplied {
                setting: ConfigSetting::ExitNode,
                result: apply_exit_node(&client_binary, addr.as_deref()),
            },
            AdminRequest::ConfirmConfig { setting, token } => AdminResponse::ConfigConfirmed {
                setting,
                result: confirm_pending_config(&client_binary, &token),
            },
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

    let stderr = String::from_utf8_lossy(&out.stderr);
    match parse_mgmt_status(&stderr) {
        Some(status) => {
            // A genuine numeric `0` only happens on the CLI's own
            // local-failure sentinel path (the "no reply"/"malformed reply"
            // cases print a non-numeric message instead, caught by the `None`
            // branches below) — `check_status` below treats it uniformly as
            // an error, since no caller ever expects a real HTTP-style
            // status of 0.
            Ok((status, out.stdout))
        }
        None if stderr.trim().is_empty() => Err("aivpn-client mgmt produced no output".to_string()),
        None => Err(stderr.trim().to_string()),
    }
}

/// Extract the HTTP status `aivpn-client mgmt` prints to stderr
/// (`eprintln!("{status}")` in its `main.rs`, the LAST thing it writes
/// there). The client initializes a stderr-writing tracing subscriber
/// before dispatching the subcommand, so stderr may carry log lines BEFORE
/// the status line (e.g. with `RUST_LOG` set) — scan for the last
/// purely-numeric line rather than requiring the whole stderr to be the
/// status. Same contract as aivpn-linux's `parse_mgmt_status`; `None` = no
/// parseable status (the caller then surfaces the raw stderr as the error).
fn parse_mgmt_status(stderr: &str) -> Option<u16> {
    stderr.lines().rev().find_map(|l| l.trim().parse().ok())
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
    // assignment is not exposed over this path. `exit_node` is likewise
    // absent from `TunnelAddClientRequest` — see `NewClientForm::
    // exit_node`'s doc comment for the follow-up `PATCH` below.
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
    let created = parse_client(&body)?;

    let exit_node = form.exit_node.trim();
    if exit_node.is_empty() {
        return Ok(created);
    }
    // The create route can't set `exit_node`, so apply it as a second
    // in-tunnel call against the client id the server just handed back. If
    // this fails the client still exists (with no exit-node override) —
    // surface that half-applied state as an error rather than silently
    // dropping the field the caller asked for.
    let patch_form = EditClientForm {
        id: created.id.clone(),
        name: created.name.clone(),
        enabled: created.enabled,
        expires_at: created.expires_at.clone().unwrap_or_default(),
        exit_node: exit_node.to_string(),
    };
    edit_client(client_binary, &patch_form).map_err(|e| {
        format!(
            "Client \"{}\" was created, but setting its exit node failed: {e}",
            created.name
        )
    })
}

fn edit_client(client_binary: &Path, form: &EditClientForm) -> Result<AdminClient, String> {
    // Matches `TunnelPatchClientRequest`: `expires_at`/`exit_node` both use
    // the absent/null/value tri-state (`deserialize_opt_opt`) — omit the
    // key to leave unchanged, `null` to clear, a string to set. This panel
    // always reflects the form's current values, so both keys are always
    // sent explicitly (null when the field was cleared).
    let mut json = serde_json::json!({
        "name": form.name,
        "enabled": form.enabled,
    });
    json["expires_at"] = if form.expires_at.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(form.expires_at.trim().to_string())
    };
    json["exit_node"] = if form.exit_node.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(form.exit_node.trim().to_string())
    };
    let bytes = serde_json::to_vec(&json).map_err(|e| format!("Failed to encode request: {e}"))?;
    let (status, body) = mgmt_call(client_binary, "PATCH", &path_client(&form.id), &bytes)?;
    check_status(status, &body)?;
    parse_client(&body)
}

fn list_pool_nodes(client_binary: &Path) -> Result<Vec<PoolNode>, String> {
    let (status, body) = mgmt_call(client_binary, "GET", PATH_POOL_NODES, &[])?;
    check_status(status, &body)?;
    parse_pool_nodes(&body)
}

fn get_pool_health(client_binary: &Path) -> Result<PoolHealth, String> {
    let (status, body) = mgmt_call(client_binary, "GET", PATH_POOL_HEALTH, &[])?;
    check_status(status, &body)?;
    parse_pool_health(&body)
}

/// G-A3: `POST /api/v1/config/apply` selecting `HeavySetting::ActiveMask`.
fn apply_active_mask(
    client_binary: &Path,
    client_id: &str,
    mask_id: &str,
) -> Result<ApplyResult, String> {
    let body = build_apply_mask_body(client_id, mask_id);
    let (status, resp_body) = mgmt_call(client_binary, "POST", PATH_CONFIG_APPLY, &body)?;
    check_status(status, &resp_body)?;
    parse_apply_response(&resp_body)
}

/// G-A3: `POST /api/v1/config/apply` selecting `HeavySetting::ExitNode`.
fn apply_exit_node(client_binary: &Path, addr: Option<&str>) -> Result<ApplyResult, String> {
    let body = build_apply_exit_node_body(addr);
    let (status, resp_body) = mgmt_call(client_binary, "POST", PATH_CONFIG_APPLY, &body)?;
    check_status(status, &resp_body)?;
    parse_apply_response(&resp_body)
}

/// G-A3: `POST /api/v1/config/confirm` — the server answers `204 No
/// Content` on success, so `check_status` (which never requires a
/// non-empty body) is the whole implementation.
fn confirm_pending_config(client_binary: &Path, token: &str) -> Result<(), String> {
    let body = build_confirm_body(token);
    let (status, resp_body) = mgmt_call(client_binary, "POST", PATH_CONFIG_CONFIRM, &body)?;
    check_status(status, &resp_body)
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

fn get_audit_log(client_binary: &Path) -> Result<AuditLogView, String> {
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

// ── Tests ────────────────────────────────────────────────────────────────
//
// Only host-clean, allocation-free-of-Windows-only-things logic is covered
// here (JSON parsing) — same split as `install_wizard.rs`'s test module:
// this crate has no `#[cfg(windows)]` gate on `mod admin;` itself, so these
// run on every host, including the Linux dev/CI machine this was written
// on (see `mgmt_call`'s `#[cfg(windows)]`-gated `CREATE_NO_WINDOW` bits,
// which these tests never exercise).

#[cfg(test)]
mod tests {
    use super::*;

    // ── G-A2: parse_audit_log / AuditLogView ────────────────────────────

    #[test]
    fn parse_audit_log_verified_object_shape() {
        let body = br#"{
            "entries": [
                {"ts": "2026-07-24T00:00:00Z", "actor": "admin", "action": "add_client", "target": "c1", "result": "ok"},
                {"ts": "2026-07-24T00:01:00Z", "actor": "admin", "action": "revoke", "target": "c2", "result": "ok"}
            ],
            "verified": true,
            "broken_at": null
        }"#;
        let view = parse_audit_log(body).expect("parse ok");
        assert_eq!(view.entries.len(), 2);
        assert_eq!(view.entries[0].action, "add_client");
        assert_eq!(view.entries[1].target, "c2");
        assert_eq!(view.verified, Some(true));
        assert_eq!(view.broken_at, None);
    }

    #[test]
    fn parse_audit_log_broken_chain_reports_index() {
        let body = br#"{
            "entries": [
                {"ts": "t0", "actor": "admin", "action": "a", "target": "x", "result": "ok"}
            ],
            "verified": false,
            "broken_at": 3
        }"#;
        let view = parse_audit_log(body).expect("parse ok");
        assert_eq!(view.verified, Some(false));
        assert_eq!(view.broken_at, Some(3));
    }

    #[test]
    fn parse_audit_log_bare_array_fallback_has_no_verification_info() {
        // Defensive fallback for an older server / an intermediary that
        // stripped `?verify=1` — must not be misread as "verified: false"
        // (which would render as a scary BROKEN badge for a server that
        // simply never answered the question).
        let body = br#"[
            {"ts": "t0", "actor": "cli", "action": "add_client", "target": "c1", "result": "ok"}
        ]"#;
        let view = parse_audit_log(body).expect("parse ok");
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.verified, None);
        assert_eq!(view.broken_at, None);
    }

    #[test]
    fn parse_audit_log_missing_entries_field_is_error() {
        let body = br#"{"verified": true}"#;
        assert!(parse_audit_log(body).is_err());
    }

    #[test]
    fn parse_audit_log_malformed_json_is_error() {
        let body = b"not json";
        assert!(parse_audit_log(body).is_err());
    }

    #[test]
    fn parse_audit_log_skips_entries_missing_required_fields() {
        // `AuditEntry::from_value` has no required fields (every field
        // falls back to a default), so a malformed entry never gets
        // dropped for missing fields — only a non-object array element
        // would fail `filter_map`. Verifies the tolerant-parsing
        // convention this crate uses throughout (`AdminClient`, `PoolNode`)
        // also applies to `AuditEntry`.
        let body = br#"{"entries": [{}], "verified": true, "broken_at": null}"#;
        let view = parse_audit_log(body).expect("parse ok");
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].ts, "");
        assert_eq!(view.entries[0].action, "");
    }

    #[test]
    fn path_audit_log_requests_verification() {
        assert!(PATH_AUDIT_LOG.contains("verify=1"));
    }

    // ── G-B1: exit_node_addresses / classify_exit_node ──────────────────

    fn node(node_id: &str, address: Option<&str>, revoked: bool) -> PoolNode {
        PoolNode {
            node_id: node_id.to_string(),
            address: address.map(str::to_string),
            verified: true,
            revoked,
            connected: true,
            last_seen_unix: None,
        }
    }

    #[test]
    fn exit_node_addresses_dedups_preserving_order() {
        let nodes = vec![
            node("n1", Some("a.example.com:51820"), false),
            node("n2", Some("b.example.com:51820"), false),
            node("n3", Some("a.example.com:51820"), false),
        ];
        assert_eq!(
            exit_node_addresses(&nodes),
            vec![
                "a.example.com:51820".to_string(),
                "b.example.com:51820".to_string(),
            ]
        );
    }

    #[test]
    fn exit_node_addresses_excludes_revoked_and_empty() {
        let nodes = vec![
            node("n1", Some("a.example.com:51820"), true),
            node("n2", None, false),
            node("n3", Some(""), false),
            node("n4", Some("  "), false),
            node("n5", Some("d.example.com:51820"), false),
        ];
        assert_eq!(
            exit_node_addresses(&nodes),
            vec!["d.example.com:51820".to_string()]
        );
    }

    #[test]
    fn exit_node_addresses_trims_whitespace() {
        let nodes = vec![node("n1", Some("  a.example.com:51820  "), false)];
        assert_eq!(
            exit_node_addresses(&nodes),
            vec!["a.example.com:51820".to_string()]
        );
    }

    #[test]
    fn classify_exit_node_empty_is_default() {
        let known = vec!["a.example.com:51820".to_string()];
        assert_eq!(classify_exit_node("", &known), ExitNodeChoice::Default);
        assert_eq!(classify_exit_node("   ", &known), ExitNodeChoice::Default);
    }

    #[test]
    fn classify_exit_node_known_address_is_node() {
        let known = vec!["a.example.com:51820".to_string()];
        assert_eq!(
            classify_exit_node("a.example.com:51820", &known),
            ExitNodeChoice::Node("a.example.com:51820".to_string())
        );
        // Untrimmed input still matches a known trimmed address.
        assert_eq!(
            classify_exit_node("  a.example.com:51820  ", &known),
            ExitNodeChoice::Node("a.example.com:51820".to_string())
        );
    }

    #[test]
    fn classify_exit_node_unknown_address_is_custom() {
        let known = vec!["a.example.com:51820".to_string()];
        assert_eq!(
            classify_exit_node("z.example.com:9999", &known),
            ExitNodeChoice::Custom
        );
    }

    // ── G-A3: Server Settings apply-with-rollback ────────────────────────

    #[test]
    fn build_apply_mask_body_has_client_and_mask_no_exit_node_key() {
        let body = build_apply_mask_body("client-123", "webrtc_zoom_v3");
        let v: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
        assert_eq!(v.get("client").and_then(|x| x.as_str()), Some("client-123"));
        assert_eq!(
            v.get("mask").and_then(|x| x.as_str()),
            Some("webrtc_zoom_v3")
        );
        // Presence of `exit_node` (even null) would select the WRONG
        // `HeavySetting` on the server — must be entirely absent, not just
        // null.
        assert!(v.get("exit_node").is_none());
    }

    #[test]
    fn build_apply_exit_node_body_sets_address() {
        let body = build_apply_exit_node_body(Some("exit.example.com:51820"));
        let v: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
        assert_eq!(
            v.get("exit_node").and_then(|x| x.as_str()),
            Some("exit.example.com:51820")
        );
    }

    #[test]
    fn build_apply_exit_node_body_none_sends_explicit_null() {
        let body = build_apply_exit_node_body(None);
        let v: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
        // The key must be PRESENT (selects HeavySetting::ExitNode) but
        // null (clears the global default) — not simply absent.
        assert!(v.get("exit_node").is_some());
        assert!(v.get("exit_node").unwrap().is_null());
    }

    #[test]
    fn build_confirm_body_has_token() {
        let body = build_confirm_body("abc123");
        let v: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
        assert_eq!(v.get("token").and_then(|x| x.as_str()), Some("abc123"));
    }

    #[test]
    fn parse_apply_response_ok() {
        let body = br#"{"token": "deadbeef", "applied": true}"#;
        let r = parse_apply_response(body).expect("parse ok");
        assert_eq!(r.token, "deadbeef");
        assert!(r.applied);
    }

    #[test]
    fn parse_apply_response_missing_token_is_error() {
        let body = br#"{"applied": true}"#;
        assert!(parse_apply_response(body).is_err());
    }

    #[test]
    fn parse_apply_response_missing_applied_defaults_false() {
        // Tolerant-parsing convention matches AdminClient/PoolNode/etc. —
        // a missing/renamed field degrades rather than failing the whole
        // response, even though the real server always sends `applied`.
        let body = br#"{"token": "t"}"#;
        let r = parse_apply_response(body).expect("parse ok");
        assert!(!r.applied);
    }

    #[test]
    fn parse_apply_response_malformed_json_is_error() {
        assert!(parse_apply_response(b"not json").is_err());
    }

    #[test]
    fn mask_id_looks_valid_accepts_alnum_dash_underscore() {
        assert!(mask_id_looks_valid("webrtc_zoom_v3"));
        assert!(mask_id_looks_valid("quic-https-v2"));
        assert!(mask_id_looks_valid("Abc123"));
    }

    #[test]
    fn mask_id_looks_valid_rejects_empty_and_bad_chars() {
        assert!(!mask_id_looks_valid(""));
        assert!(!mask_id_looks_valid("has space"));
        assert!(!mask_id_looks_valid("has/slash"));
        assert!(!mask_id_looks_valid("has.dot"));
    }

    // ── mgmt stderr status parse (same contract as aivpn-linux) ─────────

    #[test]
    fn parse_mgmt_status_plain() {
        assert_eq!(parse_mgmt_status("200\n"), Some(200));
        assert_eq!(parse_mgmt_status("404"), Some(404));
    }

    #[test]
    fn parse_mgmt_status_ignores_leading_log_lines() {
        // tracing writes to stderr before the status eprintln (e.g. with
        // RUST_LOG set) — the status is the LAST numeric line, and leading
        // noise must not fail the parse.
        let stderr = "2026-08-19T10:00:00Z  INFO aivpn_client: NoNewPrivs\n204\n";
        assert_eq!(parse_mgmt_status(stderr), Some(204));
    }

    #[test]
    fn parse_mgmt_status_no_numeric_line_is_none() {
        assert_eq!(
            parse_mgmt_status("No reply from daemon at 127.0.0.1:44301\n"),
            None
        );
        assert_eq!(parse_mgmt_status(""), None);
    }
}
