//! Pure, HTTP-agnostic management-operation layer.
//!
//! Shared by BOTH the axum management API (`management_api.rs`, Unix
//! socket, used by the web panel / CLI) and the upcoming in-tunnel
//! `MgmtRequest` dispatch (Phase A P1.2), so client-CRUD / connection-key /
//! status / audit logic is never duplicated between the two transports.
//!
//! **Deliberately free of `axum`/`hyper`/`tokio::net` dependencies.** This
//! module must compile in an `aivpn-server` build with NO features enabled
//! (unlike `management_api.rs`, which is `#[cfg(feature = "management-api",
//! unix)]`-only) because the in-tunnel mgmt path is not feature-gated —
//! every server build needs it.
//!
//! Every mutating operation audits itself (via `MgmtCtx::audit`, when
//! wired up) INSIDE the service function — never in the caller — so the
//! REST API and the tunnel path produce identical audit trails.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::audit_log::{AuditActor, AuditEntry, AuditLogger};
use crate::client_db::{ClientConfig, ClientDatabase, ClientRole, ClientStats};
use crate::pending_config::{PendingConfig, PendingConfigManager, PENDING_CONFIG_TIMEOUT};

mod tunnel_router;

pub use tunnel_router::*;

mod heavy_settings;

pub use heavy_settings::*;

mod pool_view;

pub use pool_view::*;

mod client_ops;

pub use client_ops::*;

// ── Context ──────────────────────────────────────────────────────────────

/// Read-only bundle of everything a management operation might need.
/// Borrowed for the duration of one call (or one `spawn_blocking` closure);
/// callers with async/blocking-thread constraints should build it from
/// already-owned data inside the blocking closure (see
/// `management_api.rs`'s `ApiState::mgmt_ctx`).
pub struct MgmtCtx<'a> {
    pub db: &'a ClientDatabase,
    pub server_pub_key: Option<[u8; 32]>,
    pub server_addr: Option<String>,
    pub server_signing_pubkey: Option<[u8; 32]>,
    pub mask_operator_pubkey: Option<[u8; 32]>,
    pub audit: Option<&'a AuditLogger>,
    pub mask_dir: &'a Path,
    pub config_path: Option<&'a Path>,
    /// Path to the append-only audit-log JSONL file, read by `audit_tail`.
    /// Not part of the original P1.1 design sketch (which only carried a
    /// write-side `audit: Option<&AuditLogger>`) — added because reading
    /// requires the on-disk path and `AuditLogger` exposes no reader.
    pub audit_log_path: Option<&'a Path>,
    /// P1.5: the shared apply-with-rollback tracker. `None` disables
    /// `apply_heavy`/`confirm_config` (they return `MgmtError::Internal`)
    /// — every real caller (REST `ApiState`, the tunnel's
    /// `dispatch_mgmt_request`) wires a real `Some`, sharing the SAME
    /// `PendingConfigManager` instance the gateway's periodic sweep task
    /// reads from `Gateway::pending_config()`/`AivpnServer::pending_config()`
    /// (mirrors how `bootstrap_descriptors` is shared today) — a REST- or
    /// tunnel-initiated apply must be swept by the SAME timer regardless of
    /// which transport started it.
    pub pending_config: Option<&'a PendingConfigManager>,
    /// Wave B1 (pool topology read endpoints): a pre-built, owned snapshot
    /// of this node's pool state, or `None` when pool sync isn't configured
    /// at all on this node. Owned (not borrowed) because both callers build
    /// it fresh from live state just before constructing `MgmtCtx` (see
    /// `gateway.rs`'s `dispatch_mgmt_request` and `management_api.rs`'s
    /// `ApiState::mgmt_ctx`) — there is no long-lived `PoolSnapshot` to
    /// borrow from. The `pool/{nodes,health,links}` routes degrade to `200`
    /// with empty lists / `transport: "none"` when this is `None`, never an
    /// error — see [`PoolHealth::empty`] and the `dispatch` arms below.
    pub pool: Option<PoolSnapshot>,
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Domain-level result of a management operation, transport-agnostic.
/// `management_api.rs` maps this to a `StatusCode` (see its handlers); the
/// P1.2 tunnel dispatch will map it to a `MgmtResponse.status` u16.
#[derive(Debug)]
pub enum MgmtError {
    NotFound,
    Conflict(String),
    BadRequest(String),
    Forbidden,
    /// A prerequisite (e.g. `--server-ip`/`--key-file`) is not configured
    /// on this node, so the operation cannot complete right now. Maps to
    /// `503 Service Unavailable` in the REST API — matches the pre-refactor
    /// `get_connection_key` handler's behavior. Added beyond the P1.1
    /// design sketch's five-variant enum: none of
    /// `NotFound/Conflict/BadRequest/Forbidden/Internal` can carry that
    /// status without losing information the caller needs.
    Unavailable(String),
    Internal(String),
}

impl std::fmt::Display for MgmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MgmtError::NotFound => write!(f, "not found"),
            MgmtError::Conflict(msg) => write!(f, "{}", msg),
            MgmtError::BadRequest(msg) => write!(f, "{}", msg),
            MgmtError::Forbidden => write!(f, "forbidden"),
            MgmtError::Unavailable(msg) => write!(f, "{}", msg),
            MgmtError::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for MgmtError {}

fn audit(ctx: &MgmtCtx, action: &str, target: &str, result: &str) {
    if let Some(log) = ctx.audit {
        log.log(AuditActor::Api, action, target, result);
    }
}

// ── Client view (PSK-stripped) ──────────────────────────────────────────

/// The PSK-stripped client shape returned to callers — never include
/// `ClientConfig::psk` in anything handed back across a transport boundary.
#[derive(Debug, Clone, Serialize)]
pub struct ClientView {
    pub id: String,
    pub name: String,
    pub vpn_ip: String,
    pub enabled: bool,
    pub one_time: bool,
    pub device_bound: bool,
    pub created_at: DateTime<Utc>,
    pub stats: ClientStats,
    pub qos: Option<crate::qos::ClientQos>,
    pub expires_at: Option<DateTime<Utc>>,
    pub role: ClientRole,
    /// Wave B2a: this client's per-client exit-node override, or `None` to
    /// fall back to the server's global default (`pool.exit_node`). Storage
    /// only — see `ClientConfig::exit_node`'s doc comment for the routing
    /// caveat (Wave B2b wires the actual data-plane routing decision).
    pub exit_node: Option<String>,
}

impl From<ClientConfig> for ClientView {
    fn from(c: ClientConfig) -> Self {
        Self {
            device_bound: c.device_pubkey.is_some(),
            id: c.id,
            name: c.name,
            vpn_ip: c.vpn_ip.to_string(),
            enabled: c.enabled,
            one_time: c.one_time,
            created_at: c.created_at,
            stats: c.stats,
            qos: c.qos,
            expires_at: c.expires_at,
            role: c.role,
            exit_node: c.exit_node,
        }
    }
}

// ── Status / audit views ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct StatusView {
    pub clients_total: usize,
    pub clients_enabled: usize,
    pub kernel_module: bool,
}

/// Bounded tail-read of the append-only audit log (most recent `limit`
/// entries, oldest first) — logic moved verbatim from the pre-refactor
/// `get_audit_log` handler so behavior (bounded-byte-window read, dropping
/// a possibly-truncated first line) is unchanged.
pub fn audit_tail(ctx: &MgmtCtx, limit: usize) -> Result<Vec<AuditEntry>, MgmtError> {
    use std::io::{Read as _, Seek, SeekFrom};

    // Every failure mode here (not configured, missing file, read error)
    // maps to the same `MgmtError::NotFound` — matching the pre-refactor
    // `get_audit_log` handler, which returned `404 Not Found` uniformly for
    // "audit log not configured" and any `std::io::Error`.
    let log_path = ctx.audit_log_path.ok_or(MgmtError::NotFound)?;

    let mut file = std::fs::File::open(log_path).map_err(|_| MgmtError::NotFound)?;
    let file_len = file.metadata().map_err(|_| MgmtError::NotFound)?.len();
    let max_bytes = (limit as u64)
        .saturating_mul(1024)
        .clamp(64 * 1024, 4 * 1024 * 1024);
    let start = file_len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))
        .map_err(|_| MgmtError::NotFound)?;
    let mut buf = Vec::with_capacity((file_len - start) as usize);
    file.read_to_end(&mut buf)
        .map_err(|_| MgmtError::NotFound)?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let entries: Vec<AuditEntry> = lines
        .iter()
        .rev()
        .take(limit)
        .rev()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    Ok(entries)
}

/// Response shape for `GET /api/v1/audit-log?verify=1` — shared by the REST
/// handler (`management_api.rs`) and the in-tunnel dispatch below, so both
/// transports report hash-chain verification identically (P1.4).
///
/// `broken_at` is the tail-window index (0-based, oldest-first, matching
/// `entries`) from `audit_log::verify_chain` — see that function's doc for
/// exactly what it detects and its tail-window caveat (it verifies the
/// returned window's internal consistency, not the whole on-disk log, when
/// `limit` didn't cover the entire file).
#[derive(Debug, Serialize)]
pub struct AuditVerifyView {
    pub entries: Vec<AuditEntry>,
    pub verified: bool,
    pub broken_at: Option<usize>,
}

/// Same bounded tail-read as `audit_tail`, plus hash-chain verification of
/// the returned window (`audit_log::verify_chain`).
pub fn audit_verify(ctx: &MgmtCtx, limit: usize) -> Result<AuditVerifyView, MgmtError> {
    let entries = audit_tail(ctx, limit)?;
    let broken_at = crate::audit_log::verify_chain(&entries).err();
    Ok(AuditVerifyView {
        verified: broken_at.is_none(),
        entries,
        broken_at,
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::net::Ipv4Addr;

    use aivpn_common::network_config::VpnNetworkConfig;

    pub(crate) const ROLE_USER: u8 = 0;
    pub(crate) const ROLE_VIEWER: u8 = 1;
    pub(crate) const ROLE_ADMIN: u8 = 2;

    pub(crate) fn test_network_config() -> VpnNetworkConfig {
        VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 99, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            keepalive_secs: None,
            ..Default::default()
        }
    }
    pub(crate) fn test_db() -> (tempfile::TempDir, ClientDatabase) {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        (dir, db)
    }
    pub(crate) fn ctx<'a>(db: &'a ClientDatabase, mask_dir: &'a Path) -> MgmtCtx<'a> {
        MgmtCtx {
            db,
            server_pub_key: Some([7u8; 32]),
            server_addr: Some("203.0.113.10:443".to_string()),
            server_signing_pubkey: None,
            mask_operator_pubkey: None,
            audit: None,
            mask_dir,
            config_path: None,
            audit_log_path: None,
            pending_config: None,
            pool: None,
        }
    }
    pub(crate) fn ctx_with_pending<'a>(
        db: &'a ClientDatabase,
        mask_dir: &'a Path,
        pending: &'a PendingConfigManager,
    ) -> MgmtCtx<'a> {
        let mut c = ctx(db, mask_dir);
        c.pending_config = Some(pending);
        c
    }
    pub(crate) fn setup_mask_file(mask_dir: &Path, name: &str) {
        std::fs::write(mask_dir.join(format!("{}.json", name)), b"{}").unwrap();
    }
    pub(crate) fn ctx_with_pending_and_config<'a>(
        db: &'a ClientDatabase,
        mask_dir: &'a Path,
        pending: &'a PendingConfigManager,
        config_path: &'a Path,
    ) -> MgmtCtx<'a> {
        let mut c = ctx_with_pending(db, mask_dir, pending);
        c.config_path = Some(config_path);
        c
    }
    pub(crate) fn sample_status(
        connected: bool,
        converged: bool,
        last_converged_unix: Option<i64>,
        last_seen_unix: Option<i64>,
    ) -> crate::pool_dialer::PeerSyncStatus {
        crate::pool_dialer::PeerSyncStatus {
            connected,
            last_converged_unix,
            converged,
            last_seen_unix,
            partition_conflict: false,
            subnet_mismatch: false,
        }
    }
}
