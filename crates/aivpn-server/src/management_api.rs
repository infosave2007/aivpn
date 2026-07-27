//! Management HTTP API over Unix socket.
//!
//! Enabled via `--features management-api`. Binds to a Unix domain socket
//! (default `/run/aivpn/api.sock`) and exposes a REST API for managing clients,
//! config, masks, backups, and server state.
//!
//! Unix-only: Unix domain sockets are not available on Windows.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt as _;
use tower::util::ServiceExt;

use crate::audit_log::{AuditActor, AuditLogger};
use crate::client_db::{ClientDatabase, ClientRole};
use crate::mgmt_service::{self, ClientView as ClientResponse, HeavySetting, MgmtCtx, MgmtError};
use crate::pending_config::PendingConfigManager;

// ── Config passed by main ────────────────────────────────────────────────────

/// Configuration bundle for `serve()`.
/// Avoids an ever-growing positional argument list.
pub struct ServeConfig {
    pub db: Option<Arc<ClientDatabase>>,
    pub socket_path: Option<String>,
    pub server_pub_key: Option<[u8; 32]>,
    pub server_addr: Option<String>,
    /// Ed25519 signing (verifying) public key, emitted as the `sk` field of
    /// API-issued connection keys — same value the CLI embeds, so
    /// panel-provisioned clients can verify signed server messages too.
    pub server_signing_pubkey: Option<[u8; 32]>,
    /// Path to the server.json config file (for live read/write).
    pub config_path: Option<PathBuf>,
    /// Path to clients.json (for backup export).
    pub clients_db_path: Option<PathBuf>,
    /// Directory containing mask JSON profiles.
    pub mask_dir: PathBuf,
    /// Path to the append-only audit log (for `GET /api/v1/audit-log`).
    pub audit_log_path: Option<PathBuf>,
    /// Live audit logger — API mutations are recorded with `AuditActor::Api`.
    pub audit_log: Option<AuditLogger>,
    /// Live bootstrap descriptors, shared with the gateway's rotation task.
    /// `None` if bootstrap descriptors weren't initialized (should not
    /// normally happen — `Gateway::new()` always builds them).
    pub bootstrap_descriptors:
        Option<Arc<parking_lot::RwLock<Vec<aivpn_common::mask::BootstrapDescriptor>>>>,
    /// Operator mask verifying key + verification mode, applied to masks
    /// uploaded via `POST /api/v1/masks` (mirrors mask_store's disk-load
    /// policy so the API can't be used to smuggle unverified profiles past
    /// `mask_verify_mode=enforce`).
    pub mask_operator_pubkey: Option<[u8; 32]>,
    pub mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    /// Live metrics collector, for enriching the `/api/v1/events` SSE
    /// `state` payload with sessions/bandwidth/latency/rotation data for the
    /// web panel's live dashboard graphs. Only present when the server
    /// binary was built with `--features metrics`; the field itself only
    /// exists in that build (see `#[cfg]` below) so a `metrics`-less build
    /// of `management-api` never needs to know about `MetricsCollector`.
    #[cfg(feature = "metrics")]
    pub metrics: Option<Arc<crate::metrics::MetricsCollector>>,
    /// 3a: optional numeric GID to chown the socket's group to. When `Some`,
    /// the socket is created mode 0660 (group read/write added) instead of
    /// the default owner-only 0600, and its group ownership is set to this
    /// GID (owner is left as the server process's uid). Lets an operator run
    /// a non-root web-panel container's uid in this group so it can open the
    /// socket without running aivpn-server itself as that uid. `None` (the
    /// default) keeps the existing owner-only 0600 socket.
    pub socket_group: Option<u32>,
    /// P1.5: the shared apply-with-rollback tracker for
    /// `POST /api/v1/config/apply` / `/config/confirm`. Must be the SAME
    /// `Arc<PendingConfigManager>` handed to `GatewayConfig` (via
    /// `AivpnServer::pending_config()`, mirroring how `bootstrap_descriptors`
    /// is shared) — otherwise a REST-initiated apply would never be swept
    /// by the gateway's rollback timer. `None` disables both routes (they
    /// 500 — see `mgmt_service::apply_heavy`'s doc comment), which only
    /// happens if a caller builds `ServeConfig` without wiring this up.
    pub pending_config: Option<std::sync::Arc<PendingConfigManager>>,
    /// Wave B1 (pool topology read endpoints): whether pool sync is
    /// configured on this node AT ALL (`server.json`'s `pool` block
    /// present), regardless of transport — mirrors
    /// `gateway::GatewayConfig::pool_configured`; see that field's doc
    /// comment for why this is needed to tell `"legacy"` apart from
    /// `"none"` when `pool_dialer_slot` below is empty.
    pub pool_configured: bool,
    /// Wave B1: a shared, fillable-later handle to the live `NodeRegistry`.
    /// `main.rs` constructs this `ServeConfig` (and spawns the REST API)
    /// BEFORE the pool-sync setup block that actually creates the
    /// `NodeRegistry`/`PoolDialer` (they're only built once
    /// `pool.transport == "masked"` is confirmed, deep inside the
    /// post-`AivpnServer::new()` match arm) — reordering that spawn was
    /// judged too invasive for this change. Passing the SAME
    /// `Arc<Mutex<Option<..>>>` cell into both `ServeConfig` (read at
    /// request time, in `ApiState::mgmt_ctx`) and the pool-sync setup block
    /// (written once, right after `NodeRegistry::load`/`PoolDialer::new`
    /// succeed) sidesteps the ordering problem entirely: a REST request
    /// that lands before the pool-sync block finishes just observes an
    /// empty slot (degrades to `pool_configured`'s `"legacy"`/`"none"`
    /// label, never an error) and self-heals on the very next request once
    /// `main.rs` fills it in — no restart needed. `None` when pool sync
    /// isn't configured at all (`main.rs` never allocates a cell it will
    /// never fill).
    pub pool_registry_slot: Option<
        std::sync::Arc<
            parking_lot::Mutex<Option<std::sync::Arc<crate::node_registry::NodeRegistry>>>,
        >,
    >,
    /// Wave B1: same deferred-fill pattern as `pool_registry_slot`, for the
    /// live `PoolDialer`.
    pub pool_dialer_slot: Option<
        std::sync::Arc<parking_lot::Mutex<Option<std::sync::Arc<crate::pool_dialer::PoolDialer>>>>,
    >,
    /// B2b (per-client exit routing) parity fix: the SAME
    /// `exit_route_cache` handle the gateway's in-tunnel
    /// `dispatch_mgmt_request` clears after every mutating mgmt call (see
    /// `Gateway::exit_route_cache`'s doc comment) — via
    /// `AivpnServer::exit_route_cache()`, the same accessor `main.rs`'s
    /// SIGHUP handler already uses. Without this, a client's `exit_node`
    /// set/cleared over THIS (REST/Unix-socket, i.e. web-panel/CLI)
    /// transport would silently never take effect on a live gateway: the
    /// gateway process shares the SAME `ClientDatabase` (so the write
    /// itself lands fine) but has its own separate per-IP exit-resolution
    /// cache that nothing on this path ever invalidated, so it would keep
    /// routing to the stale exit (or stale "no exit") indefinitely —
    /// until a pool-sync merge happened to clear it, or the process
    /// restarted. `None` only for a `ServeConfig` built without a live
    /// gateway to share with (e.g. a unit test) — `patch_client` simply
    /// skips invalidation in that case, same degrade-gracefully pattern as
    /// `pool_dialer_slot`/`pool_registry_slot` above.
    pub exit_route_cache:
        Option<std::sync::Arc<dashmap::DashMap<std::net::Ipv4Addr, Option<String>>>>,
}

// ── Shared handler state ─────────────────────────────────────────────────────

#[derive(Clone)]
struct ApiState {
    db: Arc<ClientDatabase>,
    started_at: Instant,
    server_pub_key: Option<[u8; 32]>,
    server_addr: Option<String>,
    server_signing_pubkey: Option<[u8; 32]>,
    config_path: Option<PathBuf>,
    clients_db_path: Option<PathBuf>,
    mask_dir: PathBuf,
    audit_log_path: Option<PathBuf>,
    audit_log: Option<AuditLogger>,
    bootstrap_descriptors:
        Option<Arc<parking_lot::RwLock<Vec<aivpn_common::mask::BootstrapDescriptor>>>>,
    mask_operator_pubkey: Option<[u8; 32]>,
    mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<crate::metrics::MetricsCollector>>,
    pending_config: Option<Arc<PendingConfigManager>>,
    pool_configured: bool,
    pool_registry_slot:
        Option<Arc<parking_lot::Mutex<Option<Arc<crate::node_registry::NodeRegistry>>>>>,
    pool_dialer_slot: Option<Arc<parking_lot::Mutex<Option<Arc<crate::pool_dialer::PoolDialer>>>>>,
    exit_route_cache: Option<Arc<dashmap::DashMap<std::net::Ipv4Addr, Option<String>>>>,
}

impl ApiState {
    /// Build the shared `mgmt_service` context from this (already-owned,
    /// per-request) state. Borrows from `self`, so callers that need to
    /// cross an `.await`/`spawn_blocking` boundary should `move` the whole
    /// `ApiState` into the blocking closure first and call this from
    /// inside it (see the handlers below) rather than trying to smuggle a
    /// borrowed `MgmtCtx` across the boundary itself.
    fn mgmt_ctx(&self) -> MgmtCtx<'_> {
        MgmtCtx {
            db: &self.db,
            server_pub_key: self.server_pub_key,
            server_addr: self.server_addr.clone(),
            server_signing_pubkey: self.server_signing_pubkey,
            mask_operator_pubkey: self.mask_operator_pubkey,
            audit: self.audit_log.as_ref(),
            mask_dir: &self.mask_dir,
            config_path: self.config_path.as_deref(),
            audit_log_path: self.audit_log_path.as_deref(),
            pending_config: self.pending_config.as_deref(),
            pool: Some(self.build_pool_snapshot()),
        }
    }

    /// Wave B1 (pool topology read endpoints): build a fresh
    /// `mgmt_service::PoolSnapshot` from whatever `pool_registry_slot`/
    /// `pool_dialer_slot` currently hold — see those fields' doc comments
    /// (on `ServeConfig`) for the deferred-fill mechanism and why this can
    /// legitimately observe an empty slot early in the server's lifetime.
    fn build_pool_snapshot(&self) -> mgmt_service::PoolSnapshot {
        let dialer = self
            .pool_dialer_slot
            .as_ref()
            .and_then(|slot| slot.lock().clone());
        match dialer {
            Some(dialer) => {
                let registry = self
                    .pool_registry_slot
                    .as_ref()
                    .and_then(|slot| slot.lock().clone());
                let (registry_nodes, revoked) = match registry {
                    Some(r) => (r.list(), r.list_revoked()),
                    None => (Vec::new(), Vec::new()),
                };
                let statuses = dialer.pool_status_snapshot();
                mgmt_service::build_pool_snapshot(mgmt_service::PoolSnapshotInputs {
                    peers: dialer.peers(),
                    registry_nodes: &registry_nodes,
                    revoked: &revoked,
                    statuses: &statuses,
                    transport: "masked",
                })
            }
            None if self.pool_configured => mgmt_service::PoolSnapshot::empty("legacy"),
            None => mgmt_service::PoolSnapshot::empty("none"),
        }
    }
}

/// Map a `MgmtError` from `add_client`/`connection_key`-style operations
/// where the pre-refactor handler had exactly two outcomes: a specific
/// `BadRequest` (400, name validation) and everything else as `Conflict`
/// (409). Kept as a named helper (rather than inlined per handler) since
/// two handlers (`add_client`) share this exact mapping.
fn conflict_or_bad_request(e: &MgmtError) -> StatusCode {
    match e {
        MgmtError::BadRequest(_) => StatusCode::BAD_REQUEST,
        MgmtError::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::CONFLICT,
    }
}

// ── Wire types ───────────────────────────────────────────────────────────────
//
// `ClientResponse` is a type alias for `mgmt_service::ClientView` (the
// PSK-stripped shape shared with the in-tunnel mgmt path) — same fields,
// same order, so the JSON this API has always returned is unchanged.

#[derive(Deserialize)]
struct AddClientRequest {
    name: String,
    #[serde(default)]
    one_time: bool,
    expires_at: Option<DateTime<Utc>>,
    /// Elevate the newly created client's role. Setting `viewer`/`admin`
    /// requires the client to already be device-bound (fresh clients never
    /// are), so this normally fails with 409 — provision via one-time
    /// enroll, then elevate the role afterwards with `PATCH`. Kept for
    /// completeness / already-bound re-adds.
    #[serde(default)]
    role: ClientRole,
}

#[derive(Deserialize)]
struct PatchClientRequest {
    name: Option<String>,
    enabled: Option<bool>,
    one_time: Option<bool>,
    /// Pass `null` in JSON to clear QoS; omit the field to leave it unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    qos: Option<Option<crate::qos::ClientQos>>,
    /// Pass `null` to clear expiry; omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    expires_at: Option<Option<DateTime<Utc>>>,
    /// Role assignment (web/CLI-only path; the tunnel path is P1.2).
    role: Option<ClientRole>,
    /// Wave B2a: per-client exit-node override (`host:port`). Pass `null`
    /// to clear (fall back to the server's global default); omit to leave
    /// unchanged. Also settable over the tunnel (see
    /// `mgmt_service::TunnelPatchClientRequest`) — unlike `role`, this is
    /// not a privilege grant.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    exit_node: Option<Option<String>>,
}

/// Deserialises a field that can be absent (don't touch), null (clear), or a value (set).
fn deserialize_opt_opt<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(de)?))
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    uptime_secs: u64,
    clients_total: usize,
    clients_enabled: usize,
    kernel_module: bool,
}

#[derive(Serialize)]
struct MaskInfo {
    id: String,
    file: String,
    size_bytes: u64,
    modified: Option<DateTime<Utc>>,
    /// True when the mask was auto-generated by mask_gen from a recording
    /// (read from the profile's `generated` flag). Lets the panel mark it "(авто)".
    generated: bool,
}

#[derive(Deserialize)]
struct SetActiveMaskRequest {
    client: String,
    mask: String,
}

#[derive(Serialize)]
struct KernelResponse {
    loaded: bool,
    device: &'static str,
}

#[derive(Deserialize, Default)]
struct AuditLogQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
    /// `?verify=1` (also accepts `true`/`yes`) requests hash-chain
    /// verification of the returned window (P1.4). Kept as `Option<String>`
    /// rather than `bool` because `serde_urlencoded` (axum's `Query`
    /// extractor) only accepts the literal strings `"true"`/`"false"` for a
    /// native bool field — `?verify=1` would fail to deserialize and 400
    /// the whole request instead of just defaulting to "no verify".
    #[serde(default)]
    verify: Option<String>,
}
fn default_audit_limit() -> usize {
    200
}

/// `AuditLogQuery::verify` truthy check, shared by the one call site below.
fn wants_audit_verify(q: &AuditLogQuery) -> bool {
    matches!(q.verify.as_deref(), Some("1") | Some("true") | Some("yes"))
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn err(msg: impl ToString) -> Json<ErrorResponse> {
    Json(ErrorResponse {
        error: msg.to_string(),
    })
}

fn kernel_loaded() -> bool {
    std::path::Path::new("/dev/aivpn").exists()
}

/// Audit-log a mutating API action (no-op when no logger was wired up,
/// e.g. in unit tests).
fn audit(state: &ApiState, action: &str, target: &str, result: &str) {
    if let Some(ref log) = state.audit_log {
        log.log(AuditActor::Api, action, target, result);
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn get_status(State(state): State<ApiState>) -> impl IntoResponse {
    let started_at = state.started_at;
    let v = mgmt_service::status(&state.mgmt_ctx());
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: started_at.elapsed().as_secs(),
        clients_total: v.clients_total,
        clients_enabled: v.clients_enabled,
        kernel_module: v.kernel_module,
    })
}

async fn list_clients(State(state): State<ApiState>) -> impl IntoResponse {
    let clients: Vec<ClientResponse> = mgmt_service::list_clients(&state.mgmt_ctx());
    Json(clients)
}

// ── Pool topology (Wave B1) ─────────────────────────────────────────────

async fn get_pool_nodes(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.build_pool_snapshot().nodes)
}

async fn get_pool_health(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.build_pool_snapshot().health)
}

async fn get_pool_links(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.build_pool_snapshot().links)
}

async fn add_client(
    State(state): State<ApiState>,
    Json(body): Json<AddClientRequest>,
) -> impl IntoResponse {
    let args = mgmt_service::AddClientArgs {
        name: body.name.clone(),
        one_time: body.one_time,
        expires_at: body.expires_at,
        role: body.role,
        qos: None,
    };
    let result =
        tokio::task::spawn_blocking(move || mgmt_service::add_client(&state.mgmt_ctx(), args))
            .await;
    match result {
        Ok(Ok(c)) => (StatusCode::CREATED, Json(c)).into_response(),
        Ok(Err(e)) => (conflict_or_bad_request(&e), err(e)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn get_client(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    match state.db.find_by_id(&id) {
        Some(c) => Json(ClientResponse::from(c)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            err(format!("Client '{}' not found", id)),
        )
            .into_response(),
    }
}

async fn patch_client(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<PatchClientRequest>,
) -> impl IntoResponse {
    // B2b/B2c parity fix: this REST/Unix-socket transport shares the SAME
    // live `ClientDatabase` as the gateway (see `ServeConfig::db`'s call
    // site in `main.rs`), so the write below lands correctly either way —
    // but the gateway keeps its OWN per-IP exit-resolution cache
    // (`Gateway::exit_route_cache`) that only `dispatch_mgmt_request` (the
    // in-tunnel path) and a pool-sync merge used to invalidate. Without
    // wiring this too, a client's `exit_node` set/cleared from the web
    // panel / CLI over THIS transport would silently never take effect on
    // a live gateway — see `ServeConfig::exit_route_cache`'s doc comment.
    // Capture what's needed BEFORE `state`/`body` are moved into the
    // blocking closure below.
    let touches_exit_node = body.exit_node.is_some();
    let exit_route_cache = state.exit_route_cache.clone();
    let pool_dialer_slot = state.pool_dialer_slot.clone();
    let db_for_dial = state.db.clone();
    let args = mgmt_service::UpdateClientArgs {
        name: body.name,
        enabled: body.enabled,
        one_time: body.one_time,
        qos: body.qos,
        expires_at: body.expires_at,
        role: body.role,
        exit_node: body.exit_node,
    };
    let result = tokio::task::spawn_blocking(move || {
        mgmt_service::update_client(&state.mgmt_ctx(), &id, args)
    })
    .await;
    if touches_exit_node && matches!(result, Ok(Ok(_))) {
        // Mirrors `Gateway::dispatch_mgmt_request`'s B2b (cache
        // invalidation) + B2c (runtime dial add-peer) handling for the
        // in-tunnel path — see those doc comments.
        if let Some(cache) = &exit_route_cache {
            cache.clear();
        }
        if let Some(slot) = &pool_dialer_slot {
            let dialer = slot.lock().clone();
            if let Some(dialer) = dialer {
                let already: std::collections::HashSet<String> =
                    dialer.dialed_peer_addrs().into_iter().collect();
                for addr in
                    crate::gateway::exits_needing_dial(&db_for_dial.list_clients(), &already)
                {
                    dialer.add_peer(addr);
                }
            }
        }
    }
    match result {
        Ok(Ok(c)) => Json(c).into_response(),
        Ok(Err(e)) => {
            // `Forbidden` (role change without a bound device) is mapped to
            // the same `409 Conflict` every other non-not-found
            // `update_client` failure got before this refactor — preserves
            // the REST API's exact pre-refactor status codes; the P1.2
            // tunnel dispatch maps `Forbidden` to its own 403 instead.
            let status = match e {
                MgmtError::NotFound => StatusCode::NOT_FOUND,
                MgmtError::BadRequest(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::CONFLICT,
            };
            (status, err(e)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn remove_client(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    let result =
        tokio::task::spawn_blocking(move || mgmt_service::remove_client(&state.mgmt_ctx(), &id))
            .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => (StatusCode::NOT_FOUND, err(e)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn reset_device(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    let result =
        tokio::task::spawn_blocking(move || mgmt_service::reset_device(&state.mgmt_ctx(), &id))
            .await;
    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(Err(e)) => (StatusCode::NOT_FOUND, err(e)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

/// P1.3 admin revoke — `POST /api/v1/clients/:id/revoke`. Tombstones via
/// `mgmt_service::revoke` (audited as `"ClientRevoke"`, distinct from the
/// plain `DELETE`'s `"ClientRemove"`).
///
/// **Disconnect timing note:** unlike the in-tunnel `MgmtRequest` revoke
/// path (`gateway.rs`), this REST handler does NOT immediately
/// force-disconnect a live session for the client — `ApiState` carries no
/// `Gateway`/`SessionManager`/`PoolDialer` handle (the REST management API
/// is constructed independently of the gateway in `main.rs`). A live
/// session is instead torn down by the gateway's existing periodic
/// revocation sweep (~5s cadence), which now also sends
/// `Shutdown{reason:4}` before dropping the session (P1.3), and peers
/// converge on the tombstone via the next scheduled pool anti-entropy
/// beacon rather than an immediate priority one. See `mgmt_service::revoke`'s
/// doc comment for the full split of responsibility between this REST path
/// and the in-tunnel path.
async fn revoke_client(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    let result =
        tokio::task::spawn_blocking(move || mgmt_service::revoke(&state.mgmt_ctx(), &id)).await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => (StatusCode::NOT_FOUND, err(e)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn reload(State(state): State<ApiState>) -> impl IntoResponse {
    let db = state.db.clone();
    match tokio::task::spawn_blocking(move || db.reload_if_changed()).await {
        Ok(changed) => Json(serde_json::json!({ "reloaded": changed })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn get_connection_key(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match mgmt_service::connection_key(&state.mgmt_ctx(), &id) {
        Ok(key) => Json(serde_json::json!({ "connection_key": key })).into_response(),
        Err(MgmtError::Unavailable(msg)) => {
            (StatusCode::SERVICE_UNAVAILABLE, err(msg)).into_response()
        }
        Err(MgmtError::NotFound) => (
            StatusCode::NOT_FOUND,
            err(format!("Client '{}' not found", id)),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err(e)).into_response(),
    }
}

// ── Config ───────────────────────────────────────────────────────────────────

async fn get_config(State(state): State<ApiState>) -> impl IntoResponse {
    let path = match &state.config_path {
        Some(p) => p.clone(),
        None => return (StatusCode::NOT_FOUND, err("config path not configured")).into_response(),
    };
    match tokio::task::spawn_blocking(move || std::fs::read_to_string(&path)).await {
        Ok(Ok(content)) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(v) => Json(v).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("config parse error: {}", e)),
            )
                .into_response(),
        },
        Ok(Err(e)) => (
            StatusCode::NOT_FOUND,
            err(format!("config not found: {}", e)),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn put_config(
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let path = match &state.config_path {
        Some(p) => p.clone(),
        None => return (StatusCode::NOT_FOUND, err("config path not configured")).into_response(),
    };
    // Structural validation: config must be a JSON object (not array, string, etc.)
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            err("invalid config: must be a JSON object"),
        )
            .into_response();
    }
    // Unknown-key validation: a PUT body is a live, operator-authored write
    // (typically from the web panel), so a top-level key that isn't part of
    // the schema is almost certainly a typo — reject it here with a clear
    // 400. This is intentionally STRICTER than the startup loader in
    // `main.rs` (`load_server_file_config`), which tolerates unknown keys
    // (with a warning) so a config left over from an older release doesn't
    // brick the next boot; see `server_config.rs`'s module doc for the
    // rationale split. `ServerFileConfig` itself no longer carries
    // `#[serde(deny_unknown_fields)]` — serde can't apply that per call site
    // on one struct — so the check is explicit here via
    // `unknown_top_level_keys`.
    let unknown_keys = crate::server_config::unknown_top_level_keys(&body);
    if !unknown_keys.is_empty() {
        let msg = format!("unknown config key(s): {}", unknown_keys.join(", "));
        audit(
            &state,
            "ConfigPut",
            &path.display().to_string(),
            &format!("rejected: {}", msg),
        );
        return (
            StatusCode::BAD_REQUEST,
            err(format!("invalid config: {}", msg)),
        )
            .into_response();
    }
    // Type-level validation: the body must deserialize into the SAME
    // `ServerFileConfig` the server parses at startup. A key-name allowlist
    // used to live here; it drifted out of sync with the real schema and
    // either 400'd valid configs or accepted wrong-typed values that bricked
    // the next server start (`load_server_file_config` exits on parse
    // failure). The allowlist is back (`CONFIG_KNOWN_KEYS`, checked above),
    // but guarded by a test that catches drift against the shipped example.
    if let Err(e) = serde_json::from_value::<crate::server_config::ServerFileConfig>(body.clone()) {
        audit(
            &state,
            "ConfigPut",
            &path.display().to_string(),
            &format!("rejected: {}", e),
        );
        return (
            StatusCode::BAD_REQUEST,
            err(format!("invalid config: {}", e)),
        )
            .into_response();
    }
    let content = match serde_json::to_string_pretty(&body) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, err(format!("invalid JSON: {}", e))).into_response()
        }
    };
    let db = state.db.clone();
    let path_for_log = path.display().to_string();
    match tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &content)?;
        std::fs::rename(&tmp, &path)?;
        db.reload_if_changed();
        Ok(())
    })
    .await
    {
        Ok(Ok(())) => {
            audit(&state, "ConfigPut", &path_for_log, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Ok(Err(e)) => {
            audit(
                &state,
                "ConfigPut",
                &path_for_log,
                &format!("write failed: {}", e),
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("write failed: {}", e)),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

// ── Masks ────────────────────────────────────────────────────────────────────

async fn list_masks(State(state): State<ApiState>) -> impl IntoResponse {
    let mask_dir = state.mask_dir.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<MaskInfo>, std::io::Error> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&mask_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let meta = entry.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta.and_then(|m| m.modified().ok()).and_then(|t| {
                let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
                DateTime::from_timestamp(secs as i64, 0)
            });
            let file = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            // Cheaply read just the `generated` flag from the profile JSON so
            // the panel can mark auto-generated masks — avoids deserializing the
            // full MaskProfile.
            let generated = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v.get("generated").and_then(|g| g.as_bool()))
                .unwrap_or(false);
            entries.push(MaskInfo {
                id,
                file,
                size_bytes: size,
                modified,
                generated,
            });
        }
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    })
    .await;

    match result {
        Ok(Ok(masks)) => Json(masks).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            err(format!("mask dir read error: {}", e)),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn upload_mask(
    State(state): State<ApiState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let name = match params.get("name") {
        Some(n) => n.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, err("query param 'name' required")).into_response()
        }
    };
    // Only allow safe filename characters to prevent path traversal
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            err("name must be 1–64 alphanumeric/dash/underscore chars"),
        )
            .into_response();
    }
    if body.len() > 5 * 1024 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            err("mask file exceeds 5 MB limit"),
        )
            .into_response();
    }
    // Must deserialize as an actual MaskProfile — plain `Value` validation
    // accepted any JSON with {"ok":true} and the file was then silently
    // skipped at load time (misleading operator feedback).
    let profile = match serde_json::from_slice::<aivpn_common::mask::MaskProfile>(&body) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                err(format!("not a valid mask profile: {}", e)),
            )
                .into_response()
        }
    };
    // Config-gated operator signature verification, mirroring mask_store's
    // disk-load policy: enforce → reject, warn → accept with a warning.
    let verdict = aivpn_common::mask::verify_mask_artifact(
        &profile,
        state.mask_operator_pubkey.as_ref(),
        state.mask_verify_mode,
    );
    if !verdict.accept {
        return (
            StatusCode::BAD_REQUEST,
            err(format!(
                "mask signature verification failed (mask_verify_mode=enforce): {:?}",
                verdict.detail
            )),
        )
            .into_response();
    }
    if verdict.is_failure() && state.mask_operator_pubkey.is_some() {
        tracing::warn!(
            "Uploaded mask '{}' failed operator signature verification ({:?}) — \
             accepted because mask_verify_mode=warn",
            name,
            verdict.detail
        );
    }
    let mask_path = state.mask_dir.join(format!("{}.json", name));
    match tokio::fs::write(&mask_path, &body).await {
        Ok(()) => {
            audit(&state, "MaskUpload", &name, "ok");
            Json(serde_json::json!({ "ok": true, "file": format!("{}.json", name) }))
                .into_response()
        }
        Err(e) => {
            audit(&state, "MaskUpload", &name, &format!("write error: {}", e));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("write error: {}", e)),
            )
                .into_response()
        }
    }
}

async fn delete_mask(State(state): State<ApiState>, Path(name): Path<String>) -> impl IntoResponse {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (StatusCode::BAD_REQUEST, err("invalid mask name")).into_response();
    }
    let mask_path = state.mask_dir.join(format!("{}.json", name));
    match tokio::fs::remove_file(&mask_path).await {
        Ok(()) => {
            audit(&state, "MaskDelete", &name, "ok");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            err(format!("mask '{}' not found", name)),
        )
            .into_response(),
        Err(e) => {
            audit(&state, "MaskDelete", &name, &format!("delete error: {}", e));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("delete error: {}", e)),
            )
                .into_response()
        }
    }
}

async fn set_active_mask(
    State(state): State<ApiState>,
    Json(body): Json<SetActiveMaskRequest>,
) -> impl IntoResponse {
    if body.client.is_empty() || body.mask.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            err("fields 'client' and 'mask' are required"),
        )
            .into_response();
    }
    if !body
        .mask
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (StatusCode::BAD_REQUEST, err("invalid mask name")).into_response();
    }

    // Resolve client → id
    let client = state
        .db
        .find_by_name(&body.client)
        .or_else(|| state.db.find_by_id(&body.client));
    let client_id = match client {
        Some(c) => c.id,
        None => {
            return (
                StatusCode::NOT_FOUND,
                err(format!("client '{}' not found", body.client)),
            )
                .into_response()
        }
    };

    // Validate mask exists on disk or is a built-in preset (mirrors --set-mask CLI logic)
    let mask_path = state.mask_dir.join(format!("{}.json", body.mask));
    let on_disk = mask_path.exists();
    let is_preset = aivpn_common::mask::preset_masks::by_id(&body.mask).is_some();
    if !on_disk && !is_preset {
        return (
            StatusCode::NOT_FOUND,
            err(format!(
                "mask '{}' not found in mask directory or built-in presets",
                body.mask
            )),
        )
            .into_response();
    }

    // Write override file: <mask_dir>/.overrides/<client-id>.mask
    let overrides_dir = state.mask_dir.join(".overrides");
    match tokio::fs::create_dir_all(&overrides_dir).await {
        Ok(()) => {}
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("cannot create overrides dir: {}", e)),
            )
                .into_response()
        }
    }
    let override_path = overrides_dir.join(format!("{}.mask", client_id));
    match tokio::fs::write(&override_path, body.mask.as_bytes()).await {
        Ok(()) => {
            audit(
                &state,
                "MaskSetActive",
                &format!("{} → {}", client_id, body.mask),
                "ok",
            );
            Json(serde_json::json!({ "ok": true, "client": body.client, "mask": body.mask }))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            err(format!("write error: {}", e)),
        )
            .into_response(),
    }
}

// ── P1.5: apply-with-rollback for heavy config ─────────────────────────────
//
// See `mgmt_service.rs`'s "Apply-with-rollback for heavy config" section
// for the full design + v1 scope boundary. These two handlers are the REST
// (Unix-socket) counterpart of the in-tunnel `POST /api/v1/config/apply` /
// `/config/confirm` routes (`mgmt_service::dispatch`'s `ConfigApply`/
// `ConfigConfirm` arms) — both delegate to the SAME `mgmt_service::
// apply_heavy`/`confirm_config` functions and the SAME shared
// `PendingConfigManager` (`ApiState::pending_config`), so an apply started
// from the web panel can be confirmed from the tunnel (or vice versa) and
// is swept by the same gateway rollback timer either way.

/// Which [`HeavySetting`] this selects follows the SAME "field presence,
/// not a type tag" convention as `mgmt_service::TunnelApplyRequest` (see
/// its doc comment): presence of `exit_node` (even JSON `null`) selects
/// `HeavySetting::ExitNode`; its absence selects the original
/// `HeavySetting::ActiveMask` via `client`/`mask` (unchanged wire shape).
#[derive(Deserialize)]
struct ApplyConfigRequest {
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    mask: Option<String>,
    /// Wave B2a: global default exit node (`host:port`), or `null` to
    /// disable it. See `HeavySetting::ExitNode`'s doc comment — this
    /// persists to `server.json` with rollback but does NOT live-apply
    /// (takes effect on restart).
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    exit_node: Option<Option<String>>,
}

#[derive(Serialize)]
struct ApplyConfigResponse {
    token: String,
    applied: bool,
}

async fn apply_config(
    State(state): State<ApiState>,
    Json(body): Json<ApplyConfigRequest>,
) -> impl IntoResponse {
    let result = tokio::task::spawn_blocking(move || {
        let ctx = state.mgmt_ctx();
        let setting = if let Some(exit_node) = body.exit_node {
            HeavySetting::ExitNode { addr: exit_node }
        } else {
            HeavySetting::ActiveMask {
                client: body.client.unwrap_or_default(),
                mask: body.mask.unwrap_or_default(),
            }
        };
        mgmt_service::apply_heavy(&ctx, setting, Instant::now())
    })
    .await;
    match result {
        Ok(Ok(resp)) => Json(ApplyConfigResponse {
            token: resp.token,
            applied: resp.applied,
        })
        .into_response(),
        Ok(Err(e)) => mgmt_error_response(&e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

#[derive(Deserialize)]
struct ConfirmConfigRequest {
    token: String,
}

async fn confirm_config(
    State(state): State<ApiState>,
    Json(body): Json<ConfirmConfigRequest>,
) -> impl IntoResponse {
    let result = tokio::task::spawn_blocking(move || {
        mgmt_service::confirm_config(&state.mgmt_ctx(), &body.token)
    })
    .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => mgmt_error_response(&e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

/// Map a `MgmtError` to a REST status + body for the apply/confirm
/// handlers — a superset of `conflict_or_bad_request` (also needs
/// `Forbidden`/`Unavailable`/`Internal`, which `apply_heavy`/
/// `confirm_config` can both return).
fn mgmt_error_response(e: &MgmtError) -> axum::response::Response {
    let status = match e {
        MgmtError::NotFound => StatusCode::NOT_FOUND,
        MgmtError::Conflict(_) => StatusCode::CONFLICT,
        MgmtError::BadRequest(_) => StatusCode::BAD_REQUEST,
        MgmtError::Forbidden => StatusCode::FORBIDDEN,
        MgmtError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        MgmtError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, err(e.to_string())).into_response()
}

// ── Backup ───────────────────────────────────────────────────────────────────

async fn export_backup(State(state): State<ApiState>) -> impl IntoResponse {
    use crate::backup::{export_server, ExportOptions};
    let mask_dir = state.mask_dir.clone();
    let clients_db_path = state.clients_db_path.clone();
    let config_path = state.config_path.clone();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        // server-sec HIGH5: a predictable /tmp path with default perms lets
        // any local user race to read (or pre-create/symlink) the backup —
        // which contains every client's plaintext PSK. Use an unpredictable
        // name and create it 0600 up front (before `export_server` ever
        // writes to it) rather than chmod-ing after the fact.
        let mut suffix = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let tmp = std::env::temp_dir().join(format!("aivpn-backup-{}.tar.gz", hex::encode(suffix)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
        }
        let opts = ExportOptions {
            include_clients: true,
            include_masks: true,
            include_config: true,
            config_path,
            mask_dir: Some(mask_dir),
            clients_db: clients_db_path,
        };
        export_server(&opts, &tmp)?;
        let data = std::fs::read(&tmp)?;
        let _ = std::fs::remove_file(&tmp);
        Ok(data)
    })
    .await;

    match result {
        Ok(Ok(data)) => (
            [
                (header::CONTENT_TYPE, "application/gzip"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"aivpn-backup.tar.gz\"",
                ),
            ],
            data,
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            err(format!("backup failed: {}", e)),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

/// Current signed bootstrap descriptors (previous/current/next epoch), same
/// JSON-array shape as `--export-bootstrap-descriptor` and what
/// already-connected clients receive — for an operator to publish manually,
/// or for future web-panel tooling. Admin-only in the web-panel proxy layer
/// (see `VIEWER_BLOCKED_PATHS`), matching the treatment already given to
/// `/config` and `/backup/*`.
async fn export_bootstrap(State(state): State<ApiState>) -> impl IntoResponse {
    match &state.bootstrap_descriptors {
        Some(lock) => Json(lock.read().clone()).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            err("bootstrap descriptors not available"),
        )
            .into_response(),
    }
}

/// Query params for `POST /backup/import`. `dry_run=true` validates the
/// archive and returns the would-apply summary without writing any files —
/// the API/web equivalent of the CLI's `--import --dry-run`.
#[derive(Deserialize)]
struct ImportBackupQuery {
    #[serde(default)]
    dry_run: bool,
}

async fn import_backup(
    State(state): State<ApiState>,
    Query(q): Query<ImportBackupQuery>,
    body: Bytes,
) -> impl IntoResponse {
    use crate::backup::import_server;
    const MAX_BACKUP_SIZE: usize = 50 * 1024 * 1024; // 50 MB
    if body.len() > MAX_BACKUP_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "backup too large (max 50 MB)"})),
        )
            .into_response();
    }
    let target_dir = match state.config_path.as_ref().and_then(|p| p.parent()) {
        Some(d) => d.to_path_buf(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                err("config path not configured"),
            )
                .into_response()
        }
    };

    let dry_run = q.dry_run;
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<crate::backup::ImportSummary> {
            // server-sec HIGH5: unpredictable name + created 0600 up front (the
            // uploaded archive contains plaintext PSKs until it is fully
            // validated and either imported or discarded) instead of a
            // predictable timestamp path with default perms.
            let mut suffix = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut suffix);
            let tmp =
                std::env::temp_dir().join(format!("aivpn-import-{}.tar.gz", hex::encode(suffix)));
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)?;
            }
            std::fs::write(&tmp, &body)?;
            let r = import_server(&tmp, &target_dir, dry_run);
            let _ = std::fs::remove_file(&tmp);
            Ok(r?)
        })
        .await;

    match result {
        Ok(Ok(summary)) => {
            audit(
                &state,
                "BackupImport",
                "server backup",
                if summary.dry_run { "dry-run ok" } else { "ok" },
            );
            Json(serde_json::json!({
                "ok": true,
                "dry_run": summary.dry_run,
                "aivpn_version": summary.aivpn_version,
                "created_at": summary.created_at,
                "components": summary.components,
                "signed": summary.signed,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            audit(
                &state,
                "BackupImport",
                "server backup",
                &format!("failed: {}", e),
            );
            (
                StatusCode::BAD_REQUEST,
                err(format!("import failed: {}", e)),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

// ── Audit log ────────────────────────────────────────────────────────────────

async fn get_audit_log(
    State(state): State<ApiState>,
    Query(q): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let limit = q.limit.min(1000);

    // `?verify=1` returns `{ entries, verified, broken_at }` (P1.4); the
    // default (no `verify` param) KEEPS the pre-existing plain-array shape
    // for backward compat with any existing caller of this endpoint.
    if wants_audit_verify(&q) {
        let result = tokio::task::spawn_blocking(move || {
            mgmt_service::audit_verify(&state.mgmt_ctx(), limit)
        })
        .await;
        return match result {
            Ok(Ok(view)) => Json(view).into_response(),
            Ok(Err(e)) => (StatusCode::NOT_FOUND, err(e)).into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
        };
    }

    let result =
        tokio::task::spawn_blocking(move || mgmt_service::audit_tail(&state.mgmt_ctx(), limit))
            .await;

    match result {
        Ok(Ok(entries)) => Json(entries).into_response(),
        Ok(Err(e)) => (StatusCode::NOT_FOUND, err(e)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

// ── Kernel module status ──────────────────────────────────────────────────────

async fn get_kernel() -> impl IntoResponse {
    Json(KernelResponse {
        loaded: kernel_loaded(),
        device: "/dev/aivpn",
    })
}

// ── SSE events (periodic state snapshots) ────────────────────────────────────

async fn sse_events(State(state): State<ApiState>) -> impl IntoResponse {
    let interval = tokio::time::interval(std::time::Duration::from_secs(5));
    let stream = IntervalStream::new(interval).map(move |_| {
        let clients = state.db.list_clients();
        #[allow(unused_mut)]
        let mut payload = serde_json::json!({
            "uptime_secs": state.started_at.elapsed().as_secs(),
            "clients_total": clients.len(),
            "clients_enabled": clients.iter().filter(|c| c.enabled).count(),
            // `last_connected` is never cleared, so this counts clients that
            // have EVER connected — named accordingly. The LIVE count is
            // `clients_connected`, derived from the metrics collector's
            // active-session gauge below (metrics builds only).
            "clients_ever_connected": clients.iter()
                .filter(|c| c.stats.last_connected.is_some()).count(),
            "kernel_module": kernel_loaded(),
            "ts": Utc::now().to_rfc3339(),
        });

        // Enrich with live Prometheus metrics for the web panel's live
        // dashboard graphs (active sessions, bandwidth, packet rates,
        // processing latency p50/p95, rotation/DPI counters). Only when
        // built with `--features metrics` AND a collector was wired up by
        // main.rs — otherwise the payload is unchanged from before this
        // feature existed. Counters are sent as raw cumulative totals; the
        // frontend derives per-second rates from consecutive SSE ticks.
        #[cfg(feature = "metrics")]
        if let Some(m) = &state.metrics {
            let (p50_ms, p95_ms) = m.packet_processing_percentiles_ms();
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "active_sessions".into(),
                    serde_json::json!(m.active_sessions()),
                );
                // Live connected count for the web panel's dashboard chart
                // (it reads `clients_connected` from this SSE payload). The
                // previous value counted ever-connected clients and never
                // went down; the active-session gauge is the real live count.
                obj.insert(
                    "clients_connected".into(),
                    serde_json::json!(m.active_sessions()),
                );
                obj.insert(
                    "bytes_received_total".into(),
                    serde_json::json!(m.bytes_received_total()),
                );
                obj.insert(
                    "bytes_sent_total".into(),
                    serde_json::json!(m.bytes_sent_total()),
                );
                obj.insert(
                    "packets_received_total".into(),
                    serde_json::json!(m.packets_received_total()),
                );
                obj.insert(
                    "packets_sent_total".into(),
                    serde_json::json!(m.packets_sent_total()),
                );
                obj.insert(
                    "mask_rotations_total".into(),
                    serde_json::json!(m.mask_rotations_total()),
                );
                obj.insert(
                    "key_rotations_total".into(),
                    serde_json::json!(m.key_rotations_total()),
                );
                obj.insert(
                    "neural_checks_total".into(),
                    serde_json::json!(m.neural_checks_total()),
                );
                obj.insert(
                    "neural_checks_failed_total".into(),
                    serde_json::json!(m.neural_checks_failed_total()),
                );
                obj.insert(
                    "dpi_attacks_detected_total".into(),
                    serde_json::json!(m.dpi_attacks_detected_total()),
                );
                obj.insert("packet_processing_p50_ms".into(), serde_json::json!(p50_ms));
                obj.insert("packet_processing_p95_ms".into(), serde_json::json!(p95_ms));

                // §2 crowdsourced mask feedback + §3 polymorphic masks —
                // same feature-gated, best-effort enrichment as the §1
                // fields above.
                obj.insert(
                    "mask_feedback_received_total".into(),
                    serde_json::json!(m.mask_feedback_received_total()),
                );
                obj.insert(
                    "regional_hints_sent_total".into(),
                    serde_json::json!(m.regional_hints_sent_total()),
                );
                obj.insert(
                    "feedback_buckets".into(),
                    serde_json::json!(m.feedback_buckets()),
                );
                obj.insert(
                    "feedback_regions".into(),
                    serde_json::json!(m.feedback_regions()),
                );
                obj.insert(
                    "mask_preference_requests_total".into(),
                    serde_json::json!(m.mask_preference_requests_total()),
                );
                obj.insert(
                    "polymorphic_variants_pushed_total".into(),
                    serde_json::json!(m.polymorphic_variants_pushed_total()),
                );
                obj.insert(
                    "polymorphic_sessions_active".into(),
                    serde_json::json!(m.polymorphic_sessions_active()),
                );
            }
        }

        Ok::<Event, std::convert::Infallible>(
            Event::default().event("state").data(payload.to_string()),
        )
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ── Router ───────────────────────────────────────────────────────────────────

fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/clients", get(list_clients).post(add_client))
        .route(
            "/api/v1/clients/:id",
            get(get_client).patch(patch_client).delete(remove_client),
        )
        .route(
            "/api/v1/clients/:id/connection-key",
            get(get_connection_key),
        )
        .route("/api/v1/clients/:id/reset-device", post(reset_device))
        .route("/api/v1/clients/:id/revoke", post(revoke_client))
        .route("/api/v1/config", get(get_config).put(put_config))
        .route("/api/v1/config/apply", post(apply_config))
        .route("/api/v1/config/confirm", post(confirm_config))
        .route("/api/v1/masks", get(list_masks).post(upload_mask))
        .route("/api/v1/masks/:name", axum::routing::delete(delete_mask))
        .route("/api/v1/masks/active", post(set_active_mask))
        .route("/api/v1/backup/export", get(export_backup))
        .route("/api/v1/backup/import", post(import_backup))
        .route("/api/v1/bootstrap/export", get(export_bootstrap))
        .route("/api/v1/audit-log", get(get_audit_log))
        .route("/api/v1/kernel", get(get_kernel))
        .route("/api/v1/events", get(sse_events))
        .route("/api/v1/reload", post(reload))
        .route("/api/v1/pool/nodes", get(get_pool_nodes))
        .route("/api/v1/pool/health", get(get_pool_health))
        .route("/api/v1/pool/links", get(get_pool_links))
        .with_state(state)
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// 3a: chown `path`'s group to `gid`, leaving the owner (uid) unchanged.
/// Passing `-1` (all-ones) as the uid argument to `chown(2)` is the POSIX
/// idiom for "leave this ID alone" — used here so the socket keeps being
/// owned by the server process's uid and only the group changes.
fn chown_group_only(path: &std::path::Path, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let ret = unsafe { libc::chown(c_path.as_ptr(), -1i32 as libc::uid_t, gid as libc::gid_t) };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub async fn serve(cfg: ServeConfig) {
    let Some(db) = cfg.db else {
        tracing::info!("Management API: no client database configured, skipping");
        return;
    };
    let Some(path) = cfg.socket_path else {
        tracing::info!("Management API: no socket path configured, skipping");
        return;
    };

    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                "Management API: could not remove existing socket '{}': {}",
                path,
                e
            );
        }
    }

    if let Some(parent) = std::path::Path::new(&path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "Management API: cannot create socket directory '{}': {}",
                parent.display(),
                e
            );
            return;
        }
    }

    // The API has no in-band auth (a connection is full admin), so the socket
    // must never be even briefly connectable by other local users. Bind it
    // inside a fresh 0700 staging directory (the missing search bit blocks
    // everyone else), chmod it to 0600 while still shielded, then atomically
    // rename it to the final path. This avoids the previous umask() dance:
    // umask is process-wide, so flipping it here silently broke the mode of
    // any file or directory another thread created in the same window.
    // The staging name carries pid + an in-process sequence number so
    // concurrent serve() calls (e.g. the integration tests, which spawn one
    // API per test in the same process and directory) never share a dir.
    static STAGING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let staging_dir = std::path::Path::new(&path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!(
            ".aivpn-api-staging.{}.{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
    let _ = std::fs::remove_dir_all(&staging_dir);
    if let Err(e) = std::fs::create_dir(&staging_dir) {
        tracing::warn!(
            "Management API: cannot create staging dir '{}': {}",
            staging_dir.display(),
            e
        );
        return;
    }
    if let Err(e) = std::fs::set_permissions(
        &staging_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    ) {
        tracing::warn!("Management API: failed to restrict staging dir: {}", e);
        let _ = std::fs::remove_dir_all(&staging_dir);
        return;
    }
    let staged_sock = staging_dir.join("api.sock");
    let listener = match UnixListener::bind(&staged_sock) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Management API: failed to bind '{}': {}", path, e);
            let _ = std::fs::remove_dir_all(&staging_dir);
            return;
        }
    };
    // 3a: mode 0660 (adds group r/w) when an operator-configured group is
    // set, so a non-root web-panel container in that group can open the
    // socket; otherwise keep the historical owner-only 0600.
    let socket_mode: u32 = if cfg.socket_group.is_some() {
        0o660
    } else {
        0o600
    };
    if let Err(e) = std::fs::set_permissions(
        &staged_sock,
        std::os::unix::fs::PermissionsExt::from_mode(socket_mode),
    ) {
        tracing::warn!("Management API: failed to set socket permissions: {}", e);
        let _ = std::fs::remove_dir_all(&staging_dir);
        return;
    }
    if let Some(gid) = cfg.socket_group {
        // Still inside the 0700 staging dir at this point — chown before the
        // rename into the final (public) path, same ordering rationale as
        // the mode change above.
        if let Err(e) = chown_group_only(&staged_sock, gid) {
            tracing::warn!(
                "Management API: failed to chown socket group to gid {}: {}",
                gid,
                e
            );
            let _ = std::fs::remove_dir_all(&staging_dir);
            return;
        }
    }
    if let Err(e) = std::fs::rename(&staged_sock, &path) {
        tracing::warn!(
            "Management API: failed to move socket into place at '{}': {}",
            path,
            e
        );
        let _ = std::fs::remove_dir_all(&staging_dir);
        return;
    }
    let _ = std::fs::remove_dir_all(&staging_dir);

    tracing::info!("Management API listening on unix:{}", path);

    let state = ApiState {
        db,
        started_at: Instant::now(),
        server_pub_key: cfg.server_pub_key,
        server_addr: cfg.server_addr,
        server_signing_pubkey: cfg.server_signing_pubkey,
        config_path: cfg.config_path,
        clients_db_path: cfg.clients_db_path,
        mask_dir: cfg.mask_dir,
        audit_log_path: cfg.audit_log_path,
        audit_log: cfg.audit_log,
        bootstrap_descriptors: cfg.bootstrap_descriptors,
        mask_operator_pubkey: cfg.mask_operator_pubkey,
        mask_verify_mode: cfg.mask_verify_mode,
        #[cfg(feature = "metrics")]
        metrics: cfg.metrics,
        pending_config: cfg.pending_config,
        pool_configured: cfg.pool_configured,
        pool_registry_slot: cfg.pool_registry_slot,
        pool_dialer_slot: cfg.pool_dialer_slot,
        exit_route_cache: cfg.exit_route_cache,
    };
    let app = router(state);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Management API: accept error: {}", e);
                // Back off briefly: a persistent error (e.g. EMFILE) would
                // otherwise spin this loop at 100% CPU and starve the runtime.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let svc = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let hyper_svc = hyper::service::service_fn(move |req| svc.clone().oneshot(req));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper_svc)
                .await
            {
                tracing::debug!("Management API: connection error: {}", e);
            }
        });
    }
}

// PUT /api/v1/config validation is now type-level: the body must deserialize
// into `crate::server_config::ServerFileConfig` (see that module's tests for
// the shipped-example round-trip and unknown/typo-key rejection coverage).
