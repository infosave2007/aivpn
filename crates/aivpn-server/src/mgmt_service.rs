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
use std::time::Instant;

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::audit_log::{AuditActor, AuditEntry, AuditLogger};
use crate::client_db::{ClientConfig, ClientDatabase, ClientRole, ClientStats, UpdateClientParams};
use crate::pending_config::{PendingConfig, PendingConfigManager, PENDING_CONFIG_TIMEOUT};

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

// ── Arguments ────────────────────────────────────────────────────────────

pub struct AddClientArgs {
    pub name: String,
    pub one_time: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub role: ClientRole,
    /// Not exposed over the REST wire today (kept `None` by
    /// `management_api.rs`'s `add_client` handler to preserve the existing
    /// `AddClientRequest` JSON shape) — available for the P1.2 tunnel path.
    pub qos: Option<crate::qos::ClientQos>,
}

/// Fields set to `None` are left unchanged. For `qos`/`expires_at`, use
/// `Some(None)` to clear the setting — mirrors `UpdateClientParams`.
pub struct UpdateClientArgs {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub one_time: Option<bool>,
    pub qos: Option<Option<crate::qos::ClientQos>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub role: Option<ClientRole>,
    /// Wave B2a: same double-Option semantics as `qos`/`expires_at`. Unlike
    /// `role`, this IS settable over the in-tunnel path (see
    /// `TunnelPatchClientRequest`) — it's a routing preference, not a
    /// privilege escalation.
    pub exit_node: Option<Option<String>>,
}

// ── Status / audit views ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct StatusView {
    pub clients_total: usize,
    pub clients_enabled: usize,
    pub kernel_module: bool,
}

fn kernel_loaded() -> bool {
    std::path::Path::new("/dev/aivpn").exists()
}

// ── Pool topology views (Wave B1) ───────────────────────────────────────
//
// Read-only pool topology exposed over the SAME curated mgmt path as
// client-CRUD (Phase A): `GET /api/v1/pool/{nodes,health,links}`, both
// in-tunnel (`gateway.rs`'s `dispatch_mgmt_request`) and REST
// (`management_api.rs`'s `ApiState::mgmt_ctx`). Built by MERGING three
// independently-sourced views of "who is in the pool":
//
//   - configured membership (`PoolDialer::peers()` — `host:port` addresses,
//     this node's self-filtered masked-transport dial set);
//   - crypto identity (`NodeRegistry::list()`/`list_revoked()` — `node_id ->
//     pubkey` bindings, keyed by `node_id`, which by convention SHOULD equal
//     a peer's `host:port` but isn't guaranteed to — see `PoolSyncConfig::
//     node_id`'s doc comment);
//   - live/retained sync state (`PoolDialer::pool_status_snapshot()` —
//     connected/converged/last-seen, keyed by the dialed peer address).
//
// The merge key is simply the string itself: an address that happens to
// equal a bound `node_id` merges into one [`PoolNodeInfo`] entry with both
// `address` and `verified: true` populated; anything that doesn't match
// still shows up as its own (partial) entry rather than being dropped —
// "represent what you can" per the module's design brief, never silently
// hide a peer just because the two identity systems don't line up.
//
// **Legacy-transport degradation**: [`PoolDialer`]/[`crate::node_registry::
// NodeRegistry`] are ONLY ever constructed on a masked-transport node (see
// `main.rs`'s pool-sync wiring) — the legacy, mask-independent `PeerSyncer`
// path has no dialed sessions and therefore no notion of "peer link state"
// at all. A node running legacy pool sync (or no pool sync) simply has no
// `PoolDialer`/`NodeRegistry` to build a snapshot from; both call sites
// detect this and hand `dispatch` a degraded [`PoolSnapshot::empty`]
// (`transport: "legacy"` or `"none"`) instead of attempting to call into
// either type — see those call sites' doc comments for how they tell the
// two degraded cases apart.

/// One pool node as reported by [`build_pool_snapshot`]. `node_id` is
/// always populated (falling back to the address string when no crypto
/// identity is bound for it — see the module doc's merge-key note);
/// `address` is `None` for a node this registry knows about but that isn't
/// (or isn't yet) one of this node's configured dial-set peers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolNodeInfo {
    pub node_id: String,
    pub address: Option<String>,
    /// `true` iff `node_id` has a durable, TOFU/manually-pinned Ed25519
    /// binding in [`crate::node_registry::NodeRegistry`] (i.e. it appears in
    /// `NodeRegistry::list()`).
    pub verified: bool,
    /// `true` iff `node_id` (or the matching address) appears in
    /// `NodeRegistry::list_revoked()`.
    pub revoked: bool,
    /// `true` iff a masked dialed session to this peer is up right now.
    /// Always `false` for a node this registry only knows about via
    /// `NodeRegistry` (we track live sessions only for our own configured
    /// dial-set peers — an inbound-only peer that dials US has no entry in
    /// `PoolDialer::pool_status_snapshot`).
    pub connected: bool,
    pub last_seen_unix: Option<i64>,
}

/// One live/retained sync link, as reported by [`build_pool_snapshot`] —
/// one entry per [`crate::pool_dialer::PeerSyncStatus`] this node has ever
/// observed for a dialed peer (see that type's doc comment for what
/// `connected`/`converged` mean).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolLinkInfo {
    pub peer: String,
    pub connected: bool,
    pub converged: bool,
    pub last_converged_unix: Option<i64>,
    /// Wave B-IP.2: true iff the most recent `ControlPayload::PartitionAnnounce`
    /// exchange with this peer found both nodes claiming the same VPN-IP
    /// partition index on the same subnet — see
    /// `crate::pool_partition::PartitionCheck::IndexConflict`.
    pub partition_conflict: bool,
    /// Wave B-IP.2: true iff the most recent `ControlPayload::PartitionAnnounce`
    /// exchange with this peer found a different VPN subnet CIDR than ours —
    /// see `crate::pool_partition::PartitionCheck::SubnetMismatch`.
    pub subnet_mismatch: bool,
}

/// Aggregate pool-sync health summary, as reported by [`build_pool_snapshot`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolHealth {
    /// `"masked"` (this node runs [`crate::pool_dialer::PoolDialer`]),
    /// `"legacy"` (pool sync is configured but runs the mask-independent
    /// `PeerSyncer`, which has no queryable link state — see the module
    /// doc's legacy-transport note), or `"none"` (pool sync isn't
    /// configured on this node at all).
    pub transport: String,
    pub total_nodes: usize,
    pub connected_peers: usize,
    pub converged_peers: usize,
    /// `true` iff at least one currently-connected peer's last anti-entropy
    /// signal was a mismatch (i.e. `connected && !converged` for some
    /// entry) — a coarse "is anything actively out of sync right now"
    /// summary flag for a dashboard, not a precise count.
    pub diverged: bool,
    /// Wave B-IP.2: true iff any link's `partition_conflict` is set — a
    /// coarse "at least one peer collides with our VPN-IP partition index"
    /// dashboard flag, not a precise count.
    pub partition_conflict: bool,
    /// Wave B-IP.2: true iff any link's `subnet_mismatch` is set — a coarse
    /// "at least one peer disagrees with our VPN subnet" dashboard flag.
    pub subnet_mismatch: bool,
}

impl PoolHealth {
    /// The degraded health view for `transport` `"legacy"` or `"none"` —
    /// see [`PoolSnapshot::empty`].
    fn empty(transport: &str) -> Self {
        Self {
            transport: transport.to_string(),
            total_nodes: 0,
            connected_peers: 0,
            converged_peers: 0,
            diverged: false,
            partition_conflict: false,
            subnet_mismatch: false,
        }
    }
}

/// The full pool topology view returned by `GET /api/v1/pool/{nodes,health,
/// links}` — `dispatch` slices out the field the specific route asked for
/// (see the `Route::Pool*` arms below).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PoolSnapshot {
    pub nodes: Vec<PoolNodeInfo>,
    pub links: Vec<PoolLinkInfo>,
    pub health: PoolHealth,
}

impl PoolSnapshot {
    /// The degraded snapshot a call site hands `MgmtCtx::pool` when there is
    /// no live [`crate::pool_dialer::PoolDialer`] to build a real one from —
    /// `transport` should be `"legacy"` (pool sync configured, but running
    /// the legacy mask-independent transport) or `"none"` (pool sync isn't
    /// configured at all). Never an error condition: the `pool/*` routes
    /// always return `200` for this.
    pub fn empty(transport: &str) -> Self {
        Self {
            nodes: Vec::new(),
            links: Vec::new(),
            health: PoolHealth::empty(transport),
        }
    }
}

/// Inputs to [`build_pool_snapshot`] — a pure function of already-collected
/// data, so it's trivially unit-testable with fake inputs (no `PoolDialer`/
/// `NodeRegistry`/live session needed). Both real call sites
/// (`gateway.rs`'s `dispatch_mgmt_request`, `management_api.rs`'s
/// `ApiState::mgmt_ctx`) collect these from a live `PoolDialer`/
/// `NodeRegistry` pair before calling in.
pub struct PoolSnapshotInputs<'a> {
    /// `PoolDialer::peers()` — this node's configured masked-transport dial
    /// set (addresses).
    pub peers: &'a [String],
    /// `NodeRegistry::list()` — bound `(node_id, pubkey)` pairs.
    pub registry_nodes: &'a [(String, [u8; 32])],
    /// `NodeRegistry::list_revoked()` — revoked `node_id`s.
    pub revoked: &'a [String],
    /// `PoolDialer::pool_status_snapshot()` — retained per-peer sync state,
    /// keyed by dialed peer address.
    pub statuses: &'a [(String, crate::pool_dialer::PeerSyncStatus)],
    /// Always `"masked"` from both real call sites (this function is only
    /// ever called when a live `PoolDialer` exists) — taken as a parameter
    /// rather than hardcoded so a test can exercise the merge logic without
    /// asserting a specific literal.
    pub transport: &'a str,
}

/// Merge [`PoolSnapshotInputs`] into one [`PoolSnapshot`]. Pure and
/// side-effect-free — see that type's doc comment for the merge-key
/// semantics. Node/link ordering is deterministic (nodes sorted by
/// `node_id`, links sorted by `peer`) so callers/tests can compare shapes
/// without normalizing order themselves.
pub fn build_pool_snapshot(inputs: PoolSnapshotInputs) -> PoolSnapshot {
    use std::collections::{BTreeMap, HashSet};

    let revoked_set: HashSet<&str> = inputs.revoked.iter().map(String::as_str).collect();
    let mut nodes: BTreeMap<String, PoolNodeInfo> = BTreeMap::new();

    let blank_node = |key: &str, revoked_set: &HashSet<&str>| PoolNodeInfo {
        node_id: key.to_string(),
        address: None,
        verified: false,
        revoked: revoked_set.contains(key),
        connected: false,
        last_seen_unix: None,
    };

    // 1. Crypto identity: every bound node_id is `verified: true`.
    for (node_id, _pubkey) in inputs.registry_nodes {
        let mut entry = blank_node(node_id, &revoked_set);
        entry.verified = true;
        nodes.insert(node_id.clone(), entry);
    }

    // 2. Revoked node_ids that aren't (or are no longer) bound — `revoke()`
    //    removes the binding, so a revoked identity is typically absent
    //    from `registry_nodes` above; still surface it (verified: false,
    //    revoked: true) rather than silently dropping it.
    for node_id in inputs.revoked {
        nodes
            .entry(node_id.clone())
            .or_insert_with(|| blank_node(node_id, &revoked_set));
    }

    // 3. Configured membership: fill in `address` on a matching identity
    //    entry, or add a new (unverified) one keyed by the address itself.
    for peer in inputs.peers {
        let entry = nodes
            .entry(peer.clone())
            .or_insert_with(|| blank_node(peer, &revoked_set));
        entry.address = Some(peer.clone());
    }

    // 4. Live/retained sync state: merge connected/last_seen onto a
    //    matching node entry (creating one, address-keyed, if none exists —
    //    e.g. an exit_node peer not otherwise in `peers`), and build the
    //    `links` list one-to-one with `statuses`.
    let mut links: Vec<PoolLinkInfo> = Vec::with_capacity(inputs.statuses.len());
    for (peer, status) in inputs.statuses {
        let entry = nodes.entry(peer.clone()).or_insert_with(|| {
            let mut e = blank_node(peer, &revoked_set);
            e.address = Some(peer.clone());
            e
        });
        entry.connected = status.connected;
        entry.last_seen_unix = status.last_seen_unix;

        links.push(PoolLinkInfo {
            peer: peer.clone(),
            connected: status.connected,
            converged: status.converged,
            last_converged_unix: status.last_converged_unix,
            partition_conflict: status.partition_conflict,
            subnet_mismatch: status.subnet_mismatch,
        });
    }
    links.sort_by(|a, b| a.peer.cmp(&b.peer));

    let total_nodes = nodes.len();
    let connected_peers = inputs.statuses.iter().filter(|(_, s)| s.connected).count();
    let converged_peers = inputs.statuses.iter().filter(|(_, s)| s.converged).count();
    let diverged = inputs
        .statuses
        .iter()
        .any(|(_, s)| s.connected && !s.converged);
    let partition_conflict = inputs.statuses.iter().any(|(_, s)| s.partition_conflict);
    let subnet_mismatch = inputs.statuses.iter().any(|(_, s)| s.subnet_mismatch);

    PoolSnapshot {
        nodes: nodes.into_values().collect(),
        links,
        health: PoolHealth {
            transport: inputs.transport.to_string(),
            total_nodes,
            connected_peers,
            converged_peers,
            diverged,
            partition_conflict,
            subnet_mismatch,
        },
    }
}

fn client_name_valid(name: &str) -> Result<(), MgmtError> {
    if name.is_empty() || name.len() > 64 {
        return Err(MgmtError::BadRequest("name must be 1–64 characters".into()));
    }
    Ok(())
}

// ── Operations ───────────────────────────────────────────────────────────

/// List all non-tombstoned clients (PSK-stripped).
pub fn list_clients(ctx: &MgmtCtx) -> Vec<ClientView> {
    ctx.db.list_clients().into_iter().map(Into::into).collect()
}

/// Create a client, optionally setting `expires_at`/`role`/`qos` in the
/// same atomic follow-up `update_client` call (mirrors the pre-refactor
/// `add_client` handler, which did the same two-step create-then-update).
pub fn add_client(ctx: &MgmtCtx, args: AddClientArgs) -> Result<ClientView, MgmtError> {
    client_name_valid(&args.name)?;

    let client = if args.one_time {
        ctx.db.add_client_one_time(&args.name)
    } else {
        ctx.db.add_client(&args.name)
    };
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            audit(ctx, "ClientAdd", &args.name, &format!("failed: {}", e));
            return Err(MgmtError::Conflict(e.to_string()));
        }
    };

    let needs_followup =
        args.expires_at.is_some() || args.role != ClientRole::User || args.qos.is_some();
    let result = if needs_followup {
        ctx.db.update_client(
            &client.id,
            UpdateClientParams {
                expires_at: args.expires_at.map(Some),
                role: if args.role != ClientRole::User {
                    Some(args.role)
                } else {
                    None
                },
                qos: args.qos.map(Some),
                ..Default::default()
            },
        )
    } else {
        Ok(client)
    };

    match result {
        Ok(c) => {
            audit(ctx, "ClientAdd", &format!("{} ({})", c.name, c.id), "ok");
            Ok(c.into())
        }
        Err(e) => {
            audit(ctx, "ClientAdd", &args.name, &format!("failed: {}", e));
            Err(MgmtError::Conflict(e.to_string()))
        }
    }
}

/// Update mutable fields on an existing client. Setting `role` to
/// `Viewer`/`Admin` requires the client to already be device-bound; that
/// failure surfaces as `MgmtError::Forbidden` here (the REST handler maps
/// it back to `409 Conflict` to preserve pre-refactor wire compatibility —
/// see `management_api.rs::patch_client`).
pub fn update_client(
    ctx: &MgmtCtx,
    id: &str,
    args: UpdateClientArgs,
) -> Result<ClientView, MgmtError> {
    if let Some(ref name) = args.name {
        client_name_valid(name)?;
    }
    let params = UpdateClientParams {
        name: args.name,
        enabled: args.enabled,
        one_time: args.one_time,
        qos: args.qos,
        expires_at: args.expires_at,
        role: args.role,
        exit_node: args.exit_node,
    };
    match ctx.db.update_client(id, params) {
        Ok(c) => {
            audit(ctx, "ClientPatch", id, "ok");
            Ok(c.into())
        }
        Err(e) => {
            let msg = e.to_string();
            audit(ctx, "ClientPatch", id, &format!("failed: {}", msg));
            if msg.contains("not found") {
                Err(MgmtError::NotFound)
            } else if msg.contains("device binding") {
                Err(MgmtError::Forbidden)
            } else if msg.contains("exit_node") {
                Err(MgmtError::BadRequest(msg))
            } else {
                Err(MgmtError::Conflict(msg))
            }
        }
    }
}

/// Tombstone a client (revoke). Never hard-deletes — see
/// `ClientDatabase::remove_client`'s doc for why (pool-sync convergence).
pub fn remove_client(ctx: &MgmtCtx, id: &str) -> Result<(), MgmtError> {
    match ctx.db.remove_client(id) {
        Ok(()) => {
            audit(ctx, "ClientRemove", id, "ok");
            Ok(())
        }
        Err(e) => {
            audit(ctx, "ClientRemove", id, &format!("failed: {}", e));
            Err(MgmtError::NotFound)
        }
    }
}

/// Admin "revoke" (P1.3) — tombstones `id` exactly like [`remove_client`]
/// (same `ClientDatabase::remove_client` call, same LWW/tombstone-sticky
/// pool-sync convergence guarantee), but under its own `"ClientRevoke"`
/// audit action and its own dedicated route
/// (`POST /api/v1/clients/:id/revoke`, both REST and in-tunnel) so a revoke
/// is distinguishable from a plain `DELETE` in the audit trail and can carry
/// its own side effects.
///
/// **This function is the DB-tombstone + audit half only.** The two other
/// admin-revoke side effects the design calls for — (a) immediately
/// force-disconnecting any live session for `id` on this node, and (b)
/// triggering a high-priority pool beacon so peers converge fast — need a
/// `Gateway`/`SessionManager`/`PoolDialer` handle this axum-free,
/// gateway-unaware module deliberately never holds (see the module-level
/// doc comment). Callers that DO have one perform those side effects
/// themselves right after a successful `revoke()` call:
///   - the in-tunnel path: `gateway.rs`'s `MgmtRequest` handling, which
///     calls `Gateway::force_disconnect_client` + a `PoolDialer::broadcast`
///     priority beacon (both immediate — the gateway holds a live
///     `SessionManager`/`PoolDialer`);
///   - the REST path (`management_api.rs`): `ApiState` carries no
///     `Gateway`/`SessionManager`/`PoolDialer` handle (it's constructed
///     independently of the gateway in `main.rs`, wired only to
///     `ClientDatabase`/`AuditLogger`/etc.), so a REST-triggered revoke
///     relies on the gateway's existing periodic revocation sweep
///     (`gateway.rs`, ~5s cleanup-task cadence) to tear down any live
///     session — that sweep now also sends `Shutdown{reason:4}` before
///     `remove_session` (P1.3), and on the next scheduled pool anti-entropy
///     beacon/tick for peer convergence. Both still happen, just not
///     synchronously with the REST call returning.
pub fn revoke(ctx: &MgmtCtx, id: &str) -> Result<(), MgmtError> {
    match ctx.db.remove_client(id) {
        Ok(()) => {
            audit(ctx, "ClientRevoke", id, "ok");
            Ok(())
        }
        Err(e) => {
            audit(ctx, "ClientRevoke", id, &format!("failed: {}", e));
            Err(MgmtError::NotFound)
        }
    }
}

/// Clear a client's bound device key and re-enable one-time enrollment.
pub fn reset_device(ctx: &MgmtCtx, id: &str) -> Result<(), MgmtError> {
    match ctx.db.reset_device_binding(id) {
        Ok(()) => {
            audit(ctx, "DeviceReset", id, "ok");
            Ok(())
        }
        Err(e) => {
            audit(ctx, "DeviceReset", id, &format!("failed: {}", e));
            Err(MgmtError::NotFound)
        }
    }
}

/// Build the `aivpn://<base64url-json>` connection key for client `id` —
/// THE single implementation of this security-sensitive wire format.
/// Previously duplicated between `main.rs::build_connection_key` (CLI) and
/// `management_api.rs::get_connection_key` (REST) — both now delegate here.
/// JSON body: `{s,k,p,i,n}` always, plus `sk`/`mop` when those keys are
/// configured on this node.
pub fn connection_key(ctx: &MgmtCtx, id: &str) -> Result<String, MgmtError> {
    let (pub_key, server_addr) = match (&ctx.server_pub_key, &ctx.server_addr) {
        (Some(k), Some(a)) => (k, a.as_str()),
        _ => {
            return Err(MgmtError::Unavailable(
                "--server-ip or --key-file not configured; cannot build connection key".into(),
            ))
        }
    };
    let client = ctx.db.find_by_id(id).ok_or(MgmtError::NotFound)?;
    let client_net_cfg = ctx
        .db
        .network_config()
        .client_config(client.vpn_ip)
        .map_err(|e| MgmtError::Internal(e.to_string()))?;

    use base64::Engine;
    let psk_b64 = base64::engine::general_purpose::STANDARD.encode(client.psk);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_key);
    let mut json = serde_json::json!({
        "s": server_addr, "k": pub_b64, "p": psk_b64,
        "i": client_net_cfg.client_ip, "n": client_net_cfg,
    });
    // Parity fields: the server's ed25519 signing pubkey (`sk`) and the
    // operator mask-verifying pubkey (`mop`) so a client provisioned via
    // this key can verify signed server messages / pushed masks out of the
    // box, exactly like every other issuance path.
    if let Some(sk) = &ctx.server_signing_pubkey {
        json["sk"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(sk));
    }
    if let Some(mop) = &ctx.mask_operator_pubkey {
        json["mop"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(mop));
    }
    let json_str = serde_json::to_string(&json)
        .map_err(|e| MgmtError::Internal(format!("connection key serialization error: {}", e)))?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_str.as_bytes());
    Ok(format!("aivpn://{}", encoded))
}

/// Server status summary (kernel-module presence + client counts). Uptime
/// isn't tracked here (this module has no notion of "process start time")
/// — `management_api.rs::get_status` merges this with its own
/// `ApiState::started_at` before responding, keeping the REST JSON shape
/// unchanged.
pub fn status(ctx: &MgmtCtx) -> StatusView {
    let clients = ctx.db.list_clients();
    StatusView {
        clients_total: clients.len(),
        clients_enabled: clients.iter().filter(|c| c.enabled).count(),
        kernel_module: kernel_loaded(),
    }
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

// ── Apply-with-rollback for heavy config (P1.5) ─────────────────────────
//
// "Commit confirmed", like network gear: a HEAVY setting change — one that
// could plausibly lock an admin out of the tunnel they're managing it
// through (wrong active mask today; port/DNS/exit-node in later phases) —
// is applied immediately, a rollback timer starts, and if the admin
// doesn't re-confirm within `PENDING_CONFIG_TIMEOUT` over a still-working
// session, the gateway's periodic sweep (see `gateway.rs`'s cleanup task)
// restores the prior value.
//
// **v1 scope boundary (deliberately narrow):** the one heavy op wired
// through this mechanism today is the active-mask override — the same
// `<mask_dir>/.overrides/<client-id>.mask` file `management_api.rs`'s
// pre-existing `set_active_mask` REST handler and `main.rs`'s
// `--set-mask` CLI path already write. That file is a **persisted
// setting**, not something this server continuously re-reads into a live
// in-memory structure on every packet (grep confirms no `gateway.rs` code
// path reads `.overrides/*.mask` today) — exactly the same "file-only"
// characteristic `server.json` has (this module's doc / the P1.5 plan
// explicitly permits scoping to settings that are "safe as
// file-only-until-restart" when they don't already hot-reload). Wrapping
// this SAME write in a rollback timer neither improves nor regresses that
// pre-existing behavior; it only adds the safety net. `PriorSnapshot`/
// `PendingConfig` (see `pending_config.rs`) are written generically
// (`target_path` + raw prior bytes), so a future heavy op — exit-node
// selection in Phase B, say — reuses `apply_heavy`/`confirm_config`
// unchanged by adding a new `HeavySetting` variant and a new
// `resolve_heavy_setting` arm below, without touching the rollback engine.

/// One heavy, rollback-guarded setting `apply_heavy` knows how to apply.
pub enum HeavySetting {
    /// Set client `client`'s active-mask override to `mask` — same file
    /// `management_api.rs::set_active_mask` writes.
    ActiveMask { client: String, mask: String },
    /// Wave B2a: set (or clear, when `addr` is `None`) the server's GLOBAL
    /// default exit node — `pool.exit_node` in `server.json`. This is the
    /// fallback used by any client that has no per-client
    /// `ClientConfig::exit_node` override set (see that field's doc
    /// comment).
    ///
    /// IMPORTANT SCOPE NOTE: this only PERSISTS the change to `server.json`
    /// with the same apply-with-rollback safety net every other
    /// `HeavySetting` gets — it does NOT live-apply. `pool.exit_node` is
    /// read once at startup (`main.rs`/pool wiring); the new value takes
    /// effect only after the server process is restarted. Live-applying a
    /// global exit-node change without a restart is Wave B2c, not this
    /// wave.
    ExitNode { addr: Option<String> },
}

/// Result of resolving a [`HeavySetting`] to a concrete file write, before
/// the write actually happens — lets `apply_heavy` validate everything
/// (client exists, mask exists) and compute `target_path`/`descriptor`
/// without yet touching disk, so a validation failure never registers a
/// half-applied `PendingConfig`.
struct ResolvedHeavyWrite {
    target_path: std::path::PathBuf,
    new_content: Vec<u8>,
    descriptor: String,
}

fn resolve_heavy_setting(
    ctx: &MgmtCtx,
    setting: &HeavySetting,
) -> Result<ResolvedHeavyWrite, MgmtError> {
    match setting {
        HeavySetting::ActiveMask { client, mask } => {
            if client.is_empty() || mask.is_empty() {
                return Err(MgmtError::BadRequest(
                    "fields 'client' and 'mask' are required".into(),
                ));
            }
            if !mask
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                return Err(MgmtError::BadRequest("invalid mask name".into()));
            }
            let resolved_client = ctx
                .db
                .find_by_name(client)
                .or_else(|| ctx.db.find_by_id(client))
                .ok_or(MgmtError::NotFound)?;

            let mask_path = ctx.mask_dir.join(format!("{}.json", mask));
            let on_disk = mask_path.exists();
            let is_preset = aivpn_common::mask::preset_masks::by_id(mask).is_some();
            if !on_disk && !is_preset {
                return Err(MgmtError::NotFound);
            }

            let target_path = ctx
                .mask_dir
                .join(".overrides")
                .join(format!("{}.mask", resolved_client.id));
            Ok(ResolvedHeavyWrite {
                target_path,
                new_content: mask.as_bytes().to_vec(),
                descriptor: format!("active mask: {} -> {}", resolved_client.id, mask),
            })
        }
        HeavySetting::ExitNode { addr } => {
            if let Some(a) = addr {
                crate::client_db::validate_exit_node_addr(a)
                    .map_err(|e| MgmtError::BadRequest(e.to_string()))?;
            }

            let config_path = ctx.config_path.ok_or_else(|| {
                MgmtError::Unavailable("server config path not configured on this node".into())
            })?;

            // Read-mutate-write round-trip: parse the EXISTING server.json
            // as generic JSON (not `ServerFileConfig` — round-tripping
            // through the typed struct would silently drop any field this
            // server build doesn't know about, corrupting a config written
            // by a newer/differently-featured node), touch only
            // `pool.exit_node`, and re-serialize. `apply_heavy` (the only
            // caller) separately reads the file's CURRENT bytes as `prior`
            // for rollback — this function only computes `new_content`.
            let content = std::fs::read_to_string(config_path)
                .map_err(|e| MgmtError::Internal(format!("read config: {}", e)))?;
            let mut value: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| MgmtError::Internal(format!("parse config: {}", e)))?;
            let obj = value
                .as_object_mut()
                .ok_or_else(|| MgmtError::Internal("config root is not a JSON object".into()))?;
            let pool_entry = obj
                .entry("pool".to_string())
                .or_insert_with(|| serde_json::json!({}));
            if !pool_entry.is_object() {
                *pool_entry = serde_json::json!({});
            }
            let pool_obj = pool_entry.as_object_mut().expect("just ensured object");
            match addr {
                Some(a) => {
                    pool_obj.insert(
                        "exit_node".to_string(),
                        serde_json::Value::String(a.clone()),
                    );
                }
                None => {
                    pool_obj.remove("exit_node");
                }
            }
            let new_content = serde_json::to_string_pretty(&value)
                .map_err(|e| MgmtError::Internal(format!("serialize config: {}", e)))?
                .into_bytes();

            Ok(ResolvedHeavyWrite {
                target_path: config_path.to_path_buf(),
                new_content,
                descriptor: format!(
                    "global exit node: {}",
                    addr.as_deref().unwrap_or("(disabled)")
                ),
            })
        }
    }
}

/// A successful [`apply_heavy`] call: the caller must present `token` back
/// to [`confirm_config`] within [`PENDING_CONFIG_TIMEOUT`] or the change is
/// automatically rolled back by the gateway's sweep task.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyResponse {
    pub token: String,
    pub applied: bool,
}

/// Generate a fresh, unpredictable pending-config token — 16 random bytes,
/// hex-encoded (32 chars). Same `OsRng`-backed pattern
/// `management_api.rs::export_backup` uses for its unpredictable temp-file
/// suffix.
fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Apply a [`HeavySetting`] immediately (temp-file + rename, same pattern
/// `put_config` uses) and register a [`PendingConfig`] so the change
/// auto-rolls-back unless [`confirm_config`] is called within
/// [`PENDING_CONFIG_TIMEOUT`] of `now`. `now` is the caller's observation
/// of the current time — real `Instant::now()` in production
/// (`gateway.rs`'s `dispatch_mgmt_request`, the REST handler), an injected
/// fixed value in tests — this function itself never reads the wall clock.
///
/// Returns `MgmtError::Internal` if `ctx.pending_config` is `None` (a
/// caller that never wired a `PendingConfigManager` — should not happen
/// for any real REST/tunnel `MgmtCtx`, see that field's doc comment).
pub fn apply_heavy(
    ctx: &MgmtCtx,
    setting: HeavySetting,
    now: Instant,
) -> Result<ApplyResponse, MgmtError> {
    let manager = ctx.pending_config.ok_or_else(|| {
        MgmtError::Internal("pending-config manager not configured on this node".into())
    })?;

    let resolved = match resolve_heavy_setting(ctx, &setting) {
        Ok(r) => r,
        Err(e) => {
            audit(
                ctx,
                "ConfigApply",
                "(validation)",
                &format!("failed: {}", e),
            );
            return Err(e);
        }
    };

    let prior = std::fs::read(&resolved.target_path).ok();

    if let Some(parent) = resolved.target_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            audit(
                ctx,
                "ConfigApply",
                &resolved.descriptor,
                &format!("failed: mkdir: {}", e),
            );
            return Err(MgmtError::Internal(format!("mkdir failed: {}", e)));
        }
    }
    let tmp = resolved.target_path.with_extension("tmp");
    if let Err(e) = std::fs::write(&tmp, &resolved.new_content) {
        audit(
            ctx,
            "ConfigApply",
            &resolved.descriptor,
            &format!("failed: write: {}", e),
        );
        return Err(MgmtError::Internal(format!("write failed: {}", e)));
    }
    if let Err(e) = std::fs::rename(&tmp, &resolved.target_path) {
        audit(
            ctx,
            "ConfigApply",
            &resolved.descriptor,
            &format!("failed: rename: {}", e),
        );
        return Err(MgmtError::Internal(format!("rename failed: {}", e)));
    }

    let token = generate_token();
    manager.begin(PendingConfig::begin(
        token.clone(),
        resolved.target_path,
        prior,
        resolved.descriptor.clone(),
        now,
        PENDING_CONFIG_TIMEOUT,
    ));

    audit(
        ctx,
        "ConfigApply",
        &format!("{} (token {})", resolved.descriptor, token),
        "ok, pending confirmation",
    );

    Ok(ApplyResponse {
        token,
        applied: true,
    })
}

/// Confirm a pending change by `token` — cancels its rollback, making the
/// change permanent. `MgmtError::NotFound` for an unknown token OR one
/// that already expired and was rolled back by the sweep task before this
/// call arrived (both are indistinguishable to the caller: "there is
/// nothing left to confirm").
pub fn confirm_config(ctx: &MgmtCtx, token: &str) -> Result<(), MgmtError> {
    let manager = ctx.pending_config.ok_or_else(|| {
        MgmtError::Internal("pending-config manager not configured on this node".into())
    })?;
    if manager.confirm(token) {
        audit(ctx, "ConfigConfirm", token, "ok");
        Ok(())
    } else {
        audit(
            ctx,
            "ConfigConfirm",
            token,
            "failed: unknown or expired token",
        );
        Err(MgmtError::NotFound)
    }
}

// ── In-tunnel dispatch (P1.2) ───────────────────────────────────────────
//
// `dispatch` is the ONE router shared by the `MgmtRequest`/`MgmtResponse`
// control messages the gateway proxies over the masked tunnel (design
// doc §3.3–3.4). It intentionally supports a strict SUBSET of the axum
// `management_api.rs` routes — the "curated allowlist" — never the full
// REST surface: no `PUT /config`, no `backup/import`, no mask-signing-key
// management, and (critically) **no role assignment**, even for an Admin
// caller — see `TunnelPatchClientRequest` below, which has no `role`
// field at all, so a `role` key in the request JSON is silently ignored
// by serde rather than ever reaching `UpdateClientArgs`.
//
// `method` follows the wire convention documented on
// `ControlPayload::MgmtRequest`: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT.

const METHOD_GET: u8 = 0;
const METHOD_POST: u8 = 1;
const METHOD_PATCH: u8 = 2;
const METHOD_DELETE: u8 = 3;

/// Default `audit-log` tail length when the request path carries no
/// `?limit=` query — mirrors `management_api.rs`'s `default_audit_limit`.
const DEFAULT_AUDIT_LIMIT: usize = 200;
/// Same clamp `management_api.rs`'s `get_audit_log` applies to the query
/// param, so the tunnel path can't be used to force an unbounded read.
const MAX_AUDIT_LIMIT: usize = 1000;

/// One entry in the curated in-tunnel management allowlist (design §3.4).
/// `dispatch` and `authorize` both classify a `(method, path)` pair
/// through this SAME table (`classify_route`), so the two can never drift
/// out of sync — a route `dispatch` doesn't implement here is simply
/// unreachable via the tunnel, full stop, regardless of role.
enum Route {
    Status,
    ClientsList,
    ClientAdd,
    ClientGet(String),
    ClientPatch(String),
    ClientDelete(String),
    ClientConnectionKey(String),
    ClientResetDevice(String),
    /// P1.3: `POST /api/v1/clients/:id/revoke` — see [`revoke`]'s doc
    /// comment for why this is a distinct route from `ClientDelete` even
    /// though both tombstone via the same `ClientDatabase::remove_client`.
    ClientRevoke(String),
    AuditLog {
        limit: usize,
        verify: bool,
    },
    /// P1.5: `POST /api/v1/config/apply` — see the "Apply-with-rollback"
    /// section above.
    ConfigApply,
    /// P1.5: `POST /api/v1/config/confirm`.
    ConfigConfirm,
    /// Wave B1: `GET /api/v1/pool/nodes` — see the "Pool topology views"
    /// section above.
    PoolNodes,
    /// Wave B1: `GET /api/v1/pool/health`.
    PoolHealth,
    /// Wave B1: `GET /api/v1/pool/links`.
    PoolLinks,
}

/// Parse `?limit=N` out of a raw query string, clamped to
/// `[1, MAX_AUDIT_LIMIT]`. Any missing/unparsable value falls back to
/// `DEFAULT_AUDIT_LIMIT` — mirrors `management_api.rs`'s
/// `#[serde(default = "default_audit_limit")] limit: usize` + `.min(1000)`
/// handling for the same query param on the REST path.
fn parse_audit_limit(query: Option<&str>) -> usize {
    let raw = query
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("limit=")))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_AUDIT_LIMIT);
    raw.clamp(1, MAX_AUDIT_LIMIT)
}

/// Parse `?verify=1` (also accepts `verify=true`/`verify=yes`) out of a raw
/// query string — mirrors `management_api.rs`'s `AuditLogQuery::verify`
/// parsing for the same query param on the REST path. Any other/missing
/// value is `false` (the existing plain-array response shape).
fn parse_audit_verify(query: Option<&str>) -> bool {
    query
        .map(|q| {
            q.split('&').any(|kv| match kv.split_once('=') {
                Some(("verify", v)) => matches!(v, "1" | "true" | "yes"),
                _ => false,
            })
        })
        .unwrap_or(false)
}

/// Classify a raw `(method, path)` `MgmtRequest` into a curated `Route`,
/// or `None` if it falls outside the allowlist (§3.4) — including every
/// REST route `management_api.rs` exposes but the tunnel deliberately
/// never will (`PUT /config`, `backup/import`, mask-signing-key mgmt,
/// role assignment). `path` may carry a `?query`; only `audit-log`'s
/// `limit` is currently recognized.
fn classify_route(method: u8, path: &str) -> Option<Route> {
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let segments: Vec<&str> = path_only
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.len() < 3 || segments[0] != "api" || segments[1] != "v1" {
        return None;
    }
    let rest = &segments[2..];
    match (method, rest) {
        (METHOD_GET, ["status"]) => Some(Route::Status),
        (METHOD_GET, ["clients"]) => Some(Route::ClientsList),
        (METHOD_POST, ["clients"]) => Some(Route::ClientAdd),
        (METHOD_GET, ["clients", id]) => Some(Route::ClientGet((*id).to_string())),
        (METHOD_PATCH, ["clients", id]) => Some(Route::ClientPatch((*id).to_string())),
        (METHOD_DELETE, ["clients", id]) => Some(Route::ClientDelete((*id).to_string())),
        (METHOD_GET, ["clients", id, "connection-key"]) => {
            Some(Route::ClientConnectionKey((*id).to_string()))
        }
        (METHOD_POST, ["clients", id, "reset-device"]) => {
            Some(Route::ClientResetDevice((*id).to_string()))
        }
        (METHOD_POST, ["clients", id, "revoke"]) => Some(Route::ClientRevoke((*id).to_string())),
        (METHOD_GET, ["audit-log"]) => Some(Route::AuditLog {
            limit: parse_audit_limit(query),
            verify: parse_audit_verify(query),
        }),
        (METHOD_POST, ["config", "apply"]) => Some(Route::ConfigApply),
        (METHOD_POST, ["config", "confirm"]) => Some(Route::ConfigConfirm),
        (METHOD_GET, ["pool", "nodes"]) => Some(Route::PoolNodes),
        (METHOD_GET, ["pool", "health"]) => Some(Route::PoolHealth),
        (METHOD_GET, ["pool", "links"]) => Some(Route::PoolLinks),
        _ => None,
    }
}

/// Authorize a `MgmtRequest` before it's allowed to reach `dispatch`.
/// `role_u8` is the CALLER's server-assigned role (`ClientRole::as_u8`,
/// resolved server-side from the session's `client_id` — NEVER trust
/// anything the request itself claims): `0`=User, `1`=Viewer, `2`=Admin.
///
/// - User (0): denied everything — a `User`-role client has no
///   management access at all.
/// - Viewer (1): every curated route, but GET only (read-only monitoring
///   — status/clients/single-client/connection-key/audit-log).
/// - Admin (2): the full curated allowlist, both reads and mutations.
///
/// A path/method combination outside the curated allowlist (see
/// `classify_route`) is denied for EVERY role, including Admin — the
/// allowlist itself, not just the role check, is what keeps `PUT
/// /config`, `backup/import`, and role assignment off the tunnel.
pub fn authorize(role_u8: u8, method: u8, path: &str) -> bool {
    if classify_route(method, path).is_none() {
        return false;
    }
    match role_u8 {
        2 => true,
        1 => method == METHOD_GET,
        _ => false,
    }
}

/// If `(method, path)` classifies as the P1.3 admin "revoke" route, returns
/// the target client id — `None` for every other route. Used by the
/// gateway's in-tunnel `MgmtRequest` handling: after `dispatch` returns a
/// success status for this specific route, the gateway (which — unlike this
/// module — holds a live `SessionManager`/`PoolDialer`) performs the two
/// side effects `revoke()` itself cannot: an immediate forced session
/// disconnect and a priority pool beacon. See `revoke`'s doc comment for
/// the full split of responsibility.
pub fn revoke_target(method: u8, path: &str) -> Option<String> {
    match classify_route(method, path) {
        Some(Route::ClientRevoke(id)) => Some(id),
        _ => None,
    }
}

fn mgmt_error_status(e: &MgmtError) -> u16 {
    match e {
        MgmtError::NotFound => 404,
        MgmtError::Conflict(_) => 409,
        MgmtError::BadRequest(_) => 400,
        MgmtError::Forbidden => 403,
        MgmtError::Unavailable(_) => 503,
        MgmtError::Internal(_) => 500,
    }
}

/// Serialize `value` to JSON for a `MgmtResponse` body. A serialization
/// failure (should be unreachable for the `Serialize` types this module
/// returns) degrades to `500` with an empty body rather than panicking —
/// this runs on every server build, unauthenticated-adjacent input included
/// (an authorized-but-malicious peer controls `body`/`path`), so it must
/// never be a panic surface.
fn json_response<T: Serialize>(status: u16, value: &T) -> (u16, Vec<u8>) {
    match serde_json::to_vec(value) {
        Ok(bytes) => (status, bytes),
        Err(_) => (500, Vec::new()),
    }
}

fn err_response(e: MgmtError) -> (u16, Vec<u8>) {
    (mgmt_error_status(&e), Vec::new())
}

/// Deserializes a field that can be absent (don't touch), null (clear), or
/// a value (set) — same three-state shape as `management_api.rs`'s
/// private helper of the same name, duplicated here rather than shared
/// because this module must stay free of that module's
/// `#[cfg(feature = "management-api", unix)]` gate (see the module-level
/// doc comment).
fn deserialize_opt_opt<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(de)?))
}

/// Wire body for `POST /api/v1/clients` over the tunnel. Deliberately has
/// NO `role` field — see the module-level allowlist doc comment — so a
/// `role` key present in the caller's JSON is silently dropped by serde
/// rather than reaching `AddClientArgs`.
#[derive(Deserialize)]
struct TunnelAddClientRequest {
    name: String,
    #[serde(default)]
    one_time: bool,
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    qos: Option<crate::qos::ClientQos>,
}

/// Wire body for `PATCH /api/v1/clients/:id` over the tunnel. Deliberately
/// has NO `role` field — see `TunnelAddClientRequest`'s doc comment; role
/// assignment is a web/CLI-only operation (`management_api.rs`'s
/// `PatchClientRequest`), never available through this path even to an
/// Admin-role caller.
#[derive(Deserialize)]
struct TunnelPatchClientRequest {
    name: Option<String>,
    enabled: Option<bool>,
    one_time: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    qos: Option<Option<crate::qos::ClientQos>>,
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    expires_at: Option<Option<DateTime<Utc>>>,
    /// Wave B2a: UNLIKE `role`, `exit_node` IS settable over the tunnel —
    /// see `UpdateClientArgs::exit_node`'s doc comment for why this is
    /// safe (a routing preference, not a privilege grant). Pass `null` to
    /// clear (fall back to the global default); omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    exit_node: Option<Option<String>>,
}

/// Wire body for `POST /api/v1/config/apply`. Which [`HeavySetting`] this
/// selects is determined by WHICH fields are present, not a `type` tag:
/// presence of the `exit_node` key (even as JSON `null`, to clear it)
/// selects [`HeavySetting::ExitNode`]; its absence selects the original
/// v1 [`HeavySetting::ActiveMask`] using `client`/`mask` (unchanged wire
/// shape, so existing callers are unaffected). Mirrors
/// `management_api.rs`'s `ApplyConfigRequest`, which the same convention.
#[derive(Deserialize)]
struct TunnelApplyRequest {
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    mask: Option<String>,
    /// Wave B2a: presence (even `null`) selects `HeavySetting::ExitNode`.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    exit_node: Option<Option<String>>,
}

/// Wire body for `POST /api/v1/config/confirm`.
#[derive(Deserialize)]
struct TunnelConfirmRequest {
    token: String,
}

/// Dispatch a decoded `MgmtRequest` (already authorized by `authorize`)
/// to the matching `mgmt_service` operation, returning the `(status,
/// body)` pair the gateway wraps into a `MgmtResponse`. Unknown/
/// unsupported `(method, path)` combinations return `404` with an empty
/// body — the same "route doesn't exist" signal `authorize` short-circuits
/// on before this is ever reached in the live gateway flow (see that
/// function's doc comment), but kept correct here too so this function is
/// safe and well-defined to call directly (as the unit tests below do).
pub fn dispatch(ctx: &MgmtCtx, method: u8, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let Some(route) = classify_route(method, path) else {
        return (404, Vec::new());
    };
    match route {
        Route::Status => json_response(200, &status(ctx)),
        Route::ClientsList => json_response(200, &list_clients(ctx)),
        Route::ClientAdd => {
            let req: TunnelAddClientRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            let args = AddClientArgs {
                name: req.name,
                one_time: req.one_time,
                expires_at: req.expires_at,
                role: ClientRole::User,
                qos: req.qos,
            };
            match add_client(ctx, args) {
                Ok(view) => json_response(201, &view),
                Err(e) => err_response(e),
            }
        }
        Route::ClientGet(id) => match ctx.db.find_by_id(&id) {
            Some(c) => json_response(200, &ClientView::from(c)),
            None => (404, Vec::new()),
        },
        Route::ClientPatch(id) => {
            let req: TunnelPatchClientRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            let args = UpdateClientArgs {
                name: req.name,
                enabled: req.enabled,
                one_time: req.one_time,
                qos: req.qos,
                expires_at: req.expires_at,
                // Never settable over the tunnel — see this route's doc
                // comment and `TunnelPatchClientRequest`.
                role: None,
                // Wave B2a: settable over the tunnel — see
                // `TunnelPatchClientRequest::exit_node`'s doc comment.
                exit_node: req.exit_node,
            };
            match update_client(ctx, &id, args) {
                Ok(view) => json_response(200, &view),
                Err(e) => err_response(e),
            }
        }
        Route::ClientDelete(id) => match remove_client(ctx, &id) {
            Ok(()) => (204, Vec::new()),
            Err(e) => err_response(e),
        },
        Route::ClientConnectionKey(id) => match connection_key(ctx, &id) {
            // Field name unified with the REST handler (management_api::get_connection_key)
            // so tunnel and socket clients parse the same key. Both use "connection_key".
            Ok(key) => json_response(200, &serde_json::json!({ "connection_key": key })),
            Err(e) => err_response(e),
        },
        Route::ClientResetDevice(id) => match reset_device(ctx, &id) {
            Ok(()) => (204, Vec::new()),
            Err(e) => err_response(e),
        },
        Route::ClientRevoke(id) => match revoke(ctx, &id) {
            Ok(()) => (204, Vec::new()),
            Err(e) => err_response(e),
        },
        Route::AuditLog { limit, verify } => {
            if verify {
                match audit_verify(ctx, limit) {
                    Ok(view) => json_response(200, &view),
                    Err(e) => err_response(e),
                }
            } else {
                match audit_tail(ctx, limit) {
                    Ok(entries) => json_response(200, &entries),
                    Err(e) => err_response(e),
                }
            }
        }
        Route::ConfigApply => {
            let req: TunnelApplyRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            let setting = if let Some(exit_node) = req.exit_node {
                HeavySetting::ExitNode { addr: exit_node }
            } else {
                HeavySetting::ActiveMask {
                    client: req.client.unwrap_or_default(),
                    mask: req.mask.unwrap_or_default(),
                }
            };
            match apply_heavy(ctx, setting, Instant::now()) {
                Ok(resp) => json_response(200, &resp),
                Err(e) => err_response(e),
            }
        }
        Route::ConfigConfirm => {
            let req: TunnelConfirmRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            match confirm_config(ctx, &req.token) {
                Ok(()) => (204, Vec::new()),
                Err(e) => err_response(e),
            }
        }
        // Wave B1: `ctx.pool` is `None` on a node with no pool sync
        // configured at all (or when a caller built `MgmtCtx` without
        // wiring it — should not happen for a real REST/tunnel caller, see
        // that field's doc comment) — degrade to the same `empty("none")`
        // shape a real "pool not configured" node would report, rather than
        // erroring. Always `200`.
        Route::PoolNodes => {
            let empty = PoolSnapshot::empty("none");
            let nodes = ctx.pool.as_ref().map(|p| &p.nodes).unwrap_or(&empty.nodes);
            json_response(200, nodes)
        }
        Route::PoolHealth => {
            let health = ctx
                .pool
                .as_ref()
                .map(|p| &p.health)
                .cloned()
                .unwrap_or_else(|| PoolHealth::empty("none"));
            json_response(200, &health)
        }
        Route::PoolLinks => {
            let empty = PoolSnapshot::empty("none");
            let links = ctx.pool.as_ref().map(|p| &p.links).unwrap_or(&empty.links);
            json_response(200, links)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use aivpn_common::network_config::VpnNetworkConfig;

    fn test_network_config() -> VpnNetworkConfig {
        VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 99, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            keepalive_secs: None,
            ..Default::default()
        }
    }

    fn test_db() -> (tempfile::TempDir, ClientDatabase) {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        (dir, db)
    }

    fn ctx<'a>(db: &'a ClientDatabase, mask_dir: &'a Path) -> MgmtCtx<'a> {
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

    #[test]
    fn add_client_happy_path_returns_view_without_psk() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let view = add_client(
            &c,
            AddClientArgs {
                name: "alice".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .expect("add_client should succeed");
        assert_eq!(view.name, "alice");
        assert!(!view.device_bound);
        assert_eq!(view.role, ClientRole::User);
        // ClientView has no `psk` field at all — this is a compile-time
        // guarantee, not just a runtime check, but assert the shape holds
        // by round-tripping through JSON and checking no psk/p key leaked.
        let json = serde_json::to_value(&view).unwrap();
        assert!(json.get("psk").is_none());
    }

    #[test]
    fn update_client_role_without_device_binding_is_rejected() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "bob".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let err = update_client(
            &c,
            &created.id,
            UpdateClientArgs {
                name: None,
                enabled: None,
                one_time: None,
                qos: None,
                expires_at: None,
                role: Some(ClientRole::Admin),
                exit_node: None,
            },
        )
        .expect_err("elevating role without a bound device must fail");
        assert!(matches!(
            err,
            MgmtError::Forbidden | MgmtError::BadRequest(_)
        ));
    }

    #[test]
    fn update_client_role_succeeds_once_device_bound() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "carol".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        db.enroll_device(&created.id, &[9u8; 32]).unwrap();

        let updated = update_client(
            &c,
            &created.id,
            UpdateClientArgs {
                name: None,
                enabled: None,
                one_time: None,
                qos: None,
                expires_at: None,
                role: Some(ClientRole::Admin),
                exit_node: None,
            },
        )
        .expect("elevating a device-bound client's role must succeed");
        assert_eq!(updated.role, ClientRole::Admin);
    }

    #[test]
    fn connection_key_starts_with_scheme_and_decodes_to_expected_fields() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "dave".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let key = connection_key(&c, &created.id).expect("connection_key should succeed");
        assert!(key.starts_with("aivpn://"));

        use base64::Engine;
        let payload = key.strip_prefix("aivpn://").unwrap();
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        for field in ["s", "k", "p", "i", "n"] {
            assert!(
                json.get(field).is_some(),
                "connection key JSON missing field '{}'",
                field
            );
        }
    }

    #[test]
    fn list_clients_excludes_tombstoned_clients() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "erin".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        assert_eq!(list_clients(&c).len(), 1);

        remove_client(&c, &created.id).unwrap();
        assert!(
            list_clients(&c).is_empty(),
            "a tombstoned (revoked) client must not appear in list_clients"
        );
    }

    // ── P1.2: dispatch / authorize ──────────────────────────────────────

    const ROLE_USER: u8 = 0;
    const ROLE_VIEWER: u8 = 1;
    const ROLE_ADMIN: u8 = 2;

    #[test]
    fn authorize_viewer_get_ok_post_denied() {
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/clients"));
        assert!(!authorize(ROLE_VIEWER, METHOD_POST, "/api/v1/clients"));
    }

    #[test]
    fn authorize_user_denied_everything() {
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/status"));
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/clients"));
        assert!(!authorize(ROLE_USER, METHOD_POST, "/api/v1/clients"));
    }

    #[test]
    fn authorize_admin_post_ok() {
        assert!(authorize(ROLE_ADMIN, METHOD_POST, "/api/v1/clients"));
        assert!(authorize(ROLE_ADMIN, METHOD_PATCH, "/api/v1/clients/abc"));
        assert!(authorize(ROLE_ADMIN, METHOD_DELETE, "/api/v1/clients/abc"));
    }

    #[test]
    fn authorize_denies_routes_outside_the_curated_allowlist_for_every_role() {
        // Never-through-the-tunnel operations (design §3.4): full config
        // PUT, backup import, mask-signing-key management. None of these
        // are in `classify_route`'s table at all, so even Admin is denied.
        for role in [ROLE_USER, ROLE_VIEWER, ROLE_ADMIN] {
            assert!(!authorize(role, METHOD_POST, "/api/v1/backup/import"));
            assert!(!authorize(role, 4 /* PUT */, "/api/v1/config"));
            assert!(!authorize(role, METHOD_GET, "/api/v1/masks/signing-key"));
        }
    }

    #[test]
    fn dispatch_get_clients_as_admin_returns_200_and_json_array() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        add_client(
            &c,
            AddClientArgs {
                name: "frank".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/clients", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn dispatch_get_missing_client_by_id_is_404() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/clients/does-not-exist", &[]);
        assert_eq!(status, 404);
        assert!(body.is_empty());
    }

    #[test]
    fn dispatch_get_existing_client_by_id_returns_200() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "gina".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let (status, body) = dispatch(&c, METHOD_GET, &path, &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["id"], created.id);
        assert!(
            parsed.get("psk").is_none(),
            "PSK must never appear in a tunnel dispatch response"
        );
    }

    #[test]
    fn dispatch_unknown_path_is_404() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let (status, _) = dispatch(&c, METHOD_GET, "/api/v1/nope", &[]);
        assert_eq!(status, 404);
        let (status, _) = dispatch(&c, METHOD_POST, "/api/v1/backup/import", &[]);
        assert_eq!(status, 404);
    }

    #[test]
    fn dispatch_patch_client_ignores_role_field_in_body() {
        // Even though the JSON body claims `"role":"admin"`, the tunnel
        // PATCH path must never honor it — `TunnelPatchClientRequest` has
        // no `role` field at all, so serde silently drops the key and
        // `UpdateClientArgs.role` is always `None` on this path.
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "hank".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let body = br#"{"role":"admin","enabled":false}"#;
        let (status, resp_body) = dispatch(&c, METHOD_PATCH, &path, body);
        assert_eq!(status, 200);
        let updated: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(
            updated["role"], "user",
            "role must stay unchanged via the tunnel PATCH path, even when the body claims otherwise"
        );
        assert_eq!(
            updated["enabled"], false,
            "non-role fields must still apply"
        );
    }

    #[test]
    fn dispatch_post_clients_creates_and_returns_201() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let body = br#"{"name":"ivy","one_time":false}"#;
        let (status, resp_body) = dispatch(&c, METHOD_POST, "/api/v1/clients", body);
        assert_eq!(status, 201);
        let view: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(view["name"], "ivy");
        assert_eq!(list_clients(&c).len(), 1);
    }

    #[test]
    fn dispatch_delete_client_returns_204_and_removes_it() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "jack".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let (status, body) = dispatch(&c, METHOD_DELETE, &path, &[]);
        assert_eq!(status, 204);
        assert!(body.is_empty());
        assert!(list_clients(&c).is_empty());
    }

    #[test]
    fn dispatch_audit_log_status_matches_ctx_configuration() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        // `ctx()` leaves `audit_log_path` as `None` — the same "not
        // configured" state `MgmtError::NotFound` maps to `404` for.
        let (status, _) = dispatch(&c, METHOD_GET, "/api/v1/audit-log", &[]);
        assert_eq!(status, 404);
    }

    /// P1.2b regression: with a populated `MgmtCtx` (the `ctx()` fixture
    /// already sets `server_pub_key`/`server_addr`, the same "keys set"
    /// state `GatewayConfig::mgmt_server_addr` gives `dispatch_mgmt_request`
    /// once `main.rs` threads it through), the in-tunnel
    /// `GET .../connection-key` route must return `200` with a real
    /// `aivpn://` connection key — not the `503 Unavailable` it degraded to
    /// before `server_addr` was wired onto `GatewayConfig`.
    #[test]
    fn dispatch_connection_key_returns_200_with_aivpn_uri() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "erin".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}/connection-key", created.id);
        let (status, body) = dispatch(&c, METHOD_GET, &path, &[]);
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON body");
        let key = json["connection_key"]
            .as_str()
            .expect("response has string 'connection_key'");
        assert!(
            key.starts_with("aivpn://"),
            "connection key must start with aivpn:// scheme, got: {}",
            key
        );
    }

    /// P1.2b regression: with `audit_log_path` set to a real (even empty)
    /// file — the same populated state `GatewayConfig::audit_log_path`
    /// gives `dispatch_mgmt_request` once `main.rs` threads it through —
    /// the in-tunnel `GET /api/v1/audit-log` route must return `200` with a
    /// JSON array body, not the `404 NotFound` it degraded to before
    /// `audit_log_path` was wired onto `GatewayConfig`.
    #[test]
    fn dispatch_audit_log_returns_200_when_path_configured() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let audit_dir = tempfile::tempdir().unwrap();
        let audit_log_path = audit_dir.path().join("audit.jsonl");
        std::fs::write(&audit_log_path, b"").expect("create empty audit log file");

        let mut c = ctx(&db, &mask_dir);
        c.audit_log_path = Some(&audit_log_path);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/audit-log", &[]);
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON body");
        assert!(
            json.as_array().expect("body is a JSON array").is_empty(),
            "empty audit log file should decode to an empty entries array"
        );
    }

    // ── P1.3: revoke ─────────────────────────────────────────────────────

    #[test]
    fn revoke_tombstones_client_and_it_no_longer_appears_in_list_clients() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "kate".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        assert_eq!(list_clients(&c).len(), 1);

        revoke(&c, &created.id).expect("revoke should succeed on a live client");
        assert!(
            list_clients(&c).is_empty(),
            "a revoked client must not appear in list_clients"
        );
    }

    #[test]
    fn revoke_missing_client_is_not_found() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let err = revoke(&c, "does-not-exist").expect_err("revoking an absent id must fail");
        assert!(matches!(err, MgmtError::NotFound));
    }

    #[test]
    fn revoke_emits_client_revoke_audit_action() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let audit_dir = tempfile::tempdir().unwrap();
        let audit_log_path = audit_dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::new(&audit_log_path);

        let mut c = ctx(&db, &mask_dir);
        c.audit = Some(&audit);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "leo".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        revoke(&c, &created.id).unwrap();

        let logged = std::fs::read_to_string(&audit_log_path).unwrap();
        assert!(
            logged.contains("\"action\":\"ClientRevoke\""),
            "audit log must contain a ClientRevoke entry, got: {}",
            logged
        );
        assert!(
            logged.contains(&created.id),
            "audit log's ClientRevoke entry must target the revoked client id"
        );
    }

    #[test]
    fn authorize_revoke_route_is_admin_only() {
        let path = "/api/v1/clients/abc/revoke";
        assert!(
            !authorize(ROLE_USER, METHOD_POST, path),
            "User must be denied the revoke route"
        );
        assert!(
            !authorize(ROLE_VIEWER, METHOD_POST, path),
            "Viewer (read-only) must be denied the revoke route"
        );
        assert!(
            authorize(ROLE_ADMIN, METHOD_POST, path),
            "Admin must be allowed the revoke route"
        );
    }

    #[test]
    fn dispatch_revoke_returns_204_and_tombstones() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "mona".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}/revoke", created.id);
        let (status, body) = dispatch(&c, METHOD_POST, &path, &[]);
        assert_eq!(status, 204);
        assert!(body.is_empty());
        assert!(list_clients(&c).is_empty());
    }

    #[test]
    fn dispatch_revoke_missing_client_is_404() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let (status, _) = dispatch(&c, METHOD_POST, "/api/v1/clients/nope/revoke", &[]);
        assert_eq!(status, 404);
    }

    #[test]
    fn revoke_target_identifies_the_revoke_route_only() {
        assert_eq!(
            revoke_target(METHOD_POST, "/api/v1/clients/abc/revoke"),
            Some("abc".to_string())
        );
        assert_eq!(revoke_target(METHOD_DELETE, "/api/v1/clients/abc"), None);
        assert_eq!(revoke_target(METHOD_GET, "/api/v1/clients"), None);
        assert_eq!(
            revoke_target(METHOD_POST, "/api/v1/clients/abc/reset-device"),
            None
        );
    }

    // ── P1.5: apply-with-rollback ───────────────────────────────────────

    fn ctx_with_pending<'a>(
        db: &'a ClientDatabase,
        mask_dir: &'a Path,
        pending: &'a PendingConfigManager,
    ) -> MgmtCtx<'a> {
        let mut c = ctx(db, mask_dir);
        c.pending_config = Some(pending);
        c
    }

    fn setup_mask_file(mask_dir: &Path, name: &str) {
        std::fs::write(mask_dir.join(format!("{}.json", name)), b"{}").unwrap();
    }

    #[test]
    fn authorize_config_apply_and_confirm_are_admin_only() {
        for path in ["/api/v1/config/apply", "/api/v1/config/confirm"] {
            assert!(
                !authorize(ROLE_USER, METHOD_POST, path),
                "User must be denied {}",
                path
            );
            assert!(
                !authorize(ROLE_VIEWER, METHOD_POST, path),
                "Viewer (read-only) must be denied {}",
                path
            );
            assert!(
                authorize(ROLE_ADMIN, METHOD_POST, path),
                "Admin must be allowed {}",
                path
            );
        }
    }

    #[test]
    fn apply_heavy_returns_token_and_confirm_succeeds() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        setup_mask_file(&mask_dir, "quic-video");
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "nadia".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let resp = apply_heavy(
            &c,
            HeavySetting::ActiveMask {
                client: created.id.clone(),
                mask: "quic-video".into(),
            },
            Instant::now(),
        )
        .expect("apply_heavy should succeed for a valid client+mask");
        assert!(resp.applied);
        assert!(!resp.token.is_empty());
        assert_eq!(
            pending.len(),
            1,
            "apply_heavy must register a pending entry"
        );

        let override_path = mask_dir
            .join(".overrides")
            .join(format!("{}.mask", created.id));
        assert_eq!(
            std::fs::read_to_string(&override_path).unwrap(),
            "quic-video",
            "apply_heavy must persist the new value immediately"
        );

        confirm_config(&c, &resp.token).expect("confirm_config should succeed for a fresh token");
        assert!(
            pending.is_empty(),
            "confirming must remove the entry from the pending manager"
        );

        // File must still hold the applied value after confirmation.
        assert_eq!(
            std::fs::read_to_string(&override_path).unwrap(),
            "quic-video"
        );
    }

    #[test]
    fn confirm_config_unknown_token_is_not_found() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);

        let err = confirm_config(&c, "not-a-real-token")
            .expect_err("confirming an unknown token must fail");
        assert!(matches!(err, MgmtError::NotFound));
    }

    #[test]
    fn apply_heavy_without_pending_manager_is_internal_error() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        setup_mask_file(&mask_dir, "quic-video");
        let c = ctx(&db, &mask_dir); // no pending_config wired
        let created = add_client(
            &c,
            AddClientArgs {
                name: "omar".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let err = apply_heavy(
            &c,
            HeavySetting::ActiveMask {
                client: created.id,
                mask: "quic-video".into(),
            },
            Instant::now(),
        )
        .expect_err("apply_heavy must fail cleanly with no PendingConfigManager wired");
        assert!(matches!(err, MgmtError::Internal(_)));
    }

    #[test]
    fn apply_heavy_unknown_mask_is_not_found_and_does_not_register_pending() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "priya".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let err = apply_heavy(
            &c,
            HeavySetting::ActiveMask {
                client: created.id,
                mask: "does-not-exist".into(),
            },
            Instant::now(),
        )
        .expect_err("an unknown mask must be rejected");
        assert!(matches!(err, MgmtError::NotFound));
        assert!(
            pending.is_empty(),
            "a failed apply must never register a pending rollback"
        );
    }

    #[test]
    fn dispatch_config_apply_then_confirm_round_trip() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        setup_mask_file(&mask_dir, "steam-udp");
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "quentin".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let apply_body =
            serde_json::to_vec(&serde_json::json!({"client": created.id, "mask": "steam-udp"}))
                .unwrap();
        let (status, body) = dispatch(&c, METHOD_POST, "/api/v1/config/apply", &apply_body);
        assert_eq!(status, 200);
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = resp["token"].as_str().unwrap().to_string();
        assert_eq!(resp["applied"], true);

        let confirm_body = serde_json::to_vec(&serde_json::json!({"token": token})).unwrap();
        let (status, body) = dispatch(&c, METHOD_POST, "/api/v1/config/confirm", &confirm_body);
        assert_eq!(status, 204);
        assert!(body.is_empty());
        assert!(pending.is_empty());
    }

    // ── Wave B2a: per-client exit_node config layer ─────────────────────

    #[test]
    fn client_view_exposes_exit_node() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "rex".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        assert_eq!(created.exit_node, None);

        let updated = update_client(
            &c,
            &created.id,
            UpdateClientArgs {
                name: None,
                enabled: None,
                one_time: None,
                qos: None,
                expires_at: None,
                role: None,
                exit_node: Some(Some("exit.example.com:51820".to_string())),
            },
        )
        .unwrap();
        assert_eq!(
            updated.exit_node,
            Some("exit.example.com:51820".to_string())
        );
    }

    /// UNLIKE `role` (see `dispatch_patch_client_ignores_role_field_in_body`),
    /// `exit_node` MUST be settable over the tunnel PATCH path — it's a
    /// routing preference, not a privilege escalation.
    #[test]
    fn dispatch_patch_client_sets_exit_node_over_tunnel() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "sam".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let body = br#"{"exit_node":"exit.example.com:51820"}"#;
        let (status, resp_body) = dispatch(&c, METHOD_PATCH, &path, body);
        assert_eq!(status, 200);
        let updated: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(updated["exit_node"], "exit.example.com:51820");

        // null clears it back to "fall back to the global default".
        let clear_body = br#"{"exit_node":null}"#;
        let (status2, resp_body2) = dispatch(&c, METHOD_PATCH, &path, clear_body);
        assert_eq!(status2, 200);
        let updated2: serde_json::Value = serde_json::from_slice(&resp_body2).unwrap();
        assert!(updated2["exit_node"].is_null());
    }

    #[test]
    fn dispatch_patch_client_rejects_malformed_exit_node() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "tara".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let body = br#"{"exit_node":"not-a-valid-addr"}"#;
        let (status, _) = dispatch(&c, METHOD_PATCH, &path, body);
        assert_eq!(status, 400);
    }

    fn ctx_with_pending_and_config<'a>(
        db: &'a ClientDatabase,
        mask_dir: &'a Path,
        pending: &'a PendingConfigManager,
        config_path: &'a Path,
    ) -> MgmtCtx<'a> {
        let mut c = ctx_with_pending(db, mask_dir, pending);
        c.config_path = Some(config_path);
        c
    }

    #[test]
    fn apply_heavy_exit_node_writes_pool_exit_node_to_server_json_with_rollback_prior() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        let original: &[u8] = br#"{"listen_addr":"0.0.0.0:443"}"#;
        std::fs::write(&config_path, original).unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        let resp = apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("198.51.100.7:51820".to_string()),
            },
            Instant::now(),
        )
        .expect("apply_heavy ExitNode should succeed");
        assert!(resp.applied);
        assert!(!resp.token.is_empty());
        assert_eq!(
            pending.len(),
            1,
            "apply_heavy must register a pending entry"
        );

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(written["pool"]["exit_node"], "198.51.100.7:51820");
        assert_eq!(
            written["listen_addr"], "0.0.0.0:443",
            "the read-mutate-write round-trip must preserve unrelated existing keys"
        );

        // Rollback prior must be the file's ORIGINAL bytes, exactly.
        let expired_at =
            Instant::now() + PENDING_CONFIG_TIMEOUT + std::time::Duration::from_secs(1);
        let mut expired = pending.tick(expired_at);
        assert_eq!(expired.len(), 1, "the unconfirmed entry must be swept");
        let entry = expired.pop().unwrap();
        assert_eq!(entry.target_path(), config_path.as_path());
        assert_eq!(
            entry.rollback_value(),
            Some(original),
            "prior bytes for rollback must be the file's ORIGINAL content, byte-for-byte"
        );

        // Simulate the gateway sweep task performing the actual restore.
        std::fs::write(&config_path, entry.rollback_value().unwrap()).unwrap();
        assert_eq!(std::fs::read(&config_path).unwrap(), original);
    }

    #[test]
    fn apply_heavy_exit_node_none_clears_existing_value() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(
            &config_path,
            br#"{"listen_addr":"0.0.0.0:443","pool":{"exit_node":"old.example.com:1","peers":[]}}"#,
        )
        .unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        apply_heavy(&c, HeavySetting::ExitNode { addr: None }, Instant::now())
            .expect("clearing exit_node should succeed");

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(
            written["pool"]["exit_node"].is_null(),
            "exit_node key must be removed, not just emptied"
        );
        assert_eq!(
            written["pool"]["peers"],
            serde_json::json!([]),
            "unrelated pool sub-keys must survive the clear"
        );
    }

    #[test]
    fn apply_heavy_exit_node_rejects_malformed_addr_and_registers_nothing() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(&config_path, br#"{}"#).unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        let err = apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("not-a-valid-addr".to_string()),
            },
            Instant::now(),
        )
        .expect_err("a malformed exit_node addr must be rejected");
        assert!(matches!(err, MgmtError::BadRequest(_)));
        assert!(
            pending.is_empty(),
            "a rejected apply must never register a pending rollback"
        );
    }

    #[test]
    fn apply_heavy_exit_node_without_config_path_is_unavailable() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending); // no config_path wired

        let err = apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("1.2.3.4:1".to_string()),
            },
            Instant::now(),
        )
        .expect_err("ExitNode must fail cleanly when this node has no config_path");
        assert!(matches!(err, MgmtError::Unavailable(_)));
    }

    /// `POST /api/v1/config/apply` is the SAME curated route for every
    /// `HeavySetting` (v1 `ActiveMask` and Wave B2a `ExitNode` alike) — see
    /// `classify_route`/`authorize`, which never inspect the request body.
    /// `authorize_config_apply_and_confirm_are_admin_only` already proves
    /// Admin-only for this exact route; this test additionally exercises
    /// `dispatch` end-to-end with an `exit_node` body to confirm the
    /// ExitNode heavy op is actually reachable through it.
    #[test]
    fn dispatch_config_apply_exit_node_is_reachable_and_gated_admin_only() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(&config_path, br#"{}"#).unwrap();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        assert!(authorize(ROLE_ADMIN, METHOD_POST, "/api/v1/config/apply"));
        assert!(!authorize(ROLE_VIEWER, METHOD_POST, "/api/v1/config/apply"));
        assert!(!authorize(ROLE_USER, METHOD_POST, "/api/v1/config/apply"));

        let body = serde_json::to_vec(&serde_json::json!({"exit_node": "9.9.9.9:51820"})).unwrap();
        let (status, resp_body) = dispatch(&c, METHOD_POST, "/api/v1/config/apply", &body);
        assert_eq!(status, 200);
        let resp: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(resp["applied"], true);

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(written["pool"]["exit_node"], "9.9.9.9:51820");
    }

    // ── Wave B1: pool topology read endpoints ───────────────────────────

    fn sample_status(
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

    /// The core merge case: a peer that is both configured (an address in
    /// `peers`) AND bound in the registry AND has live status all collapse
    /// into ONE node entry — not three separate ones — because its address
    /// happens to equal its `node_id` (the documented convention).
    #[test]
    fn build_pool_snapshot_merges_config_registry_and_status_for_matching_identity() {
        let peers = vec!["node-a:443".to_string()];
        let registry_nodes = vec![("node-a:443".to_string(), [7u8; 32])];
        let revoked: Vec<String> = vec![];
        let statuses = vec![(
            "node-a:443".to_string(),
            sample_status(true, true, Some(1000), Some(1000)),
        )];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert_eq!(
            snap.nodes.len(),
            1,
            "matching address/node_id must merge into one entry"
        );
        let node = &snap.nodes[0];
        assert_eq!(node.node_id, "node-a:443");
        assert_eq!(node.address.as_deref(), Some("node-a:443"));
        assert!(node.verified);
        assert!(!node.revoked);
        assert!(node.connected);
        assert_eq!(node.last_seen_unix, Some(1000));

        assert_eq!(snap.links.len(), 1);
        assert_eq!(snap.links[0].peer, "node-a:443");
        assert!(snap.links[0].converged);
        assert_eq!(snap.links[0].last_converged_unix, Some(1000));

        assert_eq!(snap.health.transport, "masked");
        assert_eq!(snap.health.total_nodes, 1);
        assert_eq!(snap.health.connected_peers, 1);
        assert_eq!(snap.health.converged_peers, 1);
        assert!(!snap.health.diverged);
    }

    /// When identity keys DON'T line up (registry keyed by a `node_id` that
    /// isn't the dial address), the merge must not silently drop or
    /// conflate them — "represent what you can" per the design brief.
    #[test]
    fn build_pool_snapshot_keeps_non_matching_identity_and_address_as_separate_entries() {
        let peers = vec!["203.0.113.5:443".to_string()];
        let registry_nodes = vec![("node-b-identity".to_string(), [9u8; 32])];
        let revoked: Vec<String> = vec![];
        let statuses: Vec<(String, crate::pool_dialer::PeerSyncStatus)> = vec![];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert_eq!(
            snap.nodes.len(),
            2,
            "non-matching identity/address must both be represented"
        );
        let by_id: std::collections::HashMap<&str, &PoolNodeInfo> =
            snap.nodes.iter().map(|n| (n.node_id.as_str(), n)).collect();
        assert!(by_id["node-b-identity"].verified);
        assert!(by_id["node-b-identity"].address.is_none());
        assert!(!by_id["203.0.113.5:443"].verified);
        assert_eq!(
            by_id["203.0.113.5:443"].address.as_deref(),
            Some("203.0.113.5:443")
        );
    }

    /// A revoked node_id no longer present in `registry_nodes` (revoke()
    /// removes the binding) must still surface as its own entry —
    /// `revoked: true`, `verified: false` — rather than vanishing.
    #[test]
    fn build_pool_snapshot_surfaces_revoked_identity_no_longer_bound() {
        let peers: Vec<String> = vec![];
        let registry_nodes: Vec<(String, [u8; 32])> = vec![];
        let revoked = vec!["node-c:443".to_string()];
        let statuses: Vec<(String, crate::pool_dialer::PeerSyncStatus)> = vec![];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert_eq!(snap.nodes.len(), 1);
        assert_eq!(snap.nodes[0].node_id, "node-c:443");
        assert!(snap.nodes[0].revoked);
        assert!(!snap.nodes[0].verified);
    }

    /// `diverged` is true iff some CONNECTED peer's last signal was a
    /// mismatch — a disconnected-and-never-converged peer must not trip it.
    #[test]
    fn build_pool_snapshot_diverged_true_only_for_connected_mismatched_peer() {
        let peers = vec!["p1:443".to_string(), "p2:443".to_string()];
        let registry_nodes: Vec<(String, [u8; 32])> = vec![];
        let revoked: Vec<String> = vec![];
        let statuses = vec![
            (
                "p1:443".to_string(),
                sample_status(true, false, None, Some(500)),
            ),
            (
                "p2:443".to_string(),
                sample_status(false, false, None, Some(100)),
            ),
        ];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert!(snap.health.diverged);
        assert_eq!(snap.health.connected_peers, 1);
        assert_eq!(snap.health.converged_peers, 0);
    }

    /// Empty inputs (no pool sync configured) must build a well-formed,
    /// empty snapshot — never panic on empty slices.
    #[test]
    fn build_pool_snapshot_empty_inputs_yields_empty_snapshot() {
        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &[],
            registry_nodes: &[],
            revoked: &[],
            statuses: &[],
            transport: "masked",
        });
        assert!(snap.nodes.is_empty());
        assert!(snap.links.is_empty());
        assert_eq!(snap.health.total_nodes, 0);
        assert!(!snap.health.diverged);
    }

    /// `PoolSnapshot::empty` — the degraded value both call sites hand
    /// `MgmtCtx::pool` when there's no live `PoolDialer` — must always yield
    /// empty lists and echo the given transport label.
    #[test]
    fn pool_snapshot_empty_has_given_transport_and_empty_lists() {
        for transport in ["legacy", "none"] {
            let snap = PoolSnapshot::empty(transport);
            assert!(snap.nodes.is_empty());
            assert!(snap.links.is_empty());
            assert_eq!(snap.health.transport, transport);
            assert_eq!(snap.health.total_nodes, 0);
        }
    }

    fn ctx_with_pool<'a>(
        db: &'a ClientDatabase,
        mask_dir: &'a Path,
        pool: Option<PoolSnapshot>,
    ) -> MgmtCtx<'a> {
        let mut c = ctx(db, mask_dir);
        c.pool = pool;
        c
    }

    /// `GET /api/v1/pool/nodes` with `ctx.pool == None` (no pool sync
    /// configured on this node) must degrade to `200` + an empty array —
    /// never a 404/500.
    #[test]
    fn dispatch_pool_nodes_returns_200_empty_when_ctx_pool_none() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx_with_pool(&db, &mask_dir, None);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/nodes", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, serde_json::json!([]));
    }

    /// `GET /api/v1/pool/health` with `ctx.pool == None` must degrade to
    /// `200` + `transport: "none"`, not an error.
    #[test]
    fn dispatch_pool_health_returns_200_transport_none_when_ctx_pool_none() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx_with_pool(&db, &mask_dir, None);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/health", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["transport"], "none");
        assert_eq!(parsed["total_nodes"], 0);
    }

    /// `GET /api/v1/pool/links` with `ctx.pool == None` must degrade to
    /// `200` + an empty array.
    #[test]
    fn dispatch_pool_links_returns_200_empty_when_ctx_pool_none() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx_with_pool(&db, &mask_dir, None);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/links", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, serde_json::json!([]));
    }

    /// With a real `Some(PoolSnapshot)` wired in, `dispatch` returns exactly
    /// that snapshot's field, sliced per-route — confirms the three routes
    /// actually read `ctx.pool` rather than always degrading.
    #[test]
    fn dispatch_pool_routes_return_populated_snapshot_when_ctx_pool_is_some() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let snapshot = build_pool_snapshot(PoolSnapshotInputs {
            peers: &["peer-z:443".to_string()],
            registry_nodes: &[("peer-z:443".to_string(), [3u8; 32])],
            revoked: &[],
            statuses: &[(
                "peer-z:443".to_string(),
                sample_status(true, true, Some(42), Some(42)),
            )],
            transport: "masked",
        });
        let c = ctx_with_pool(&db, &mask_dir, Some(snapshot));

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/nodes", &[]);
        assert_eq!(status, 200);
        let nodes: Vec<PoolNodeInfo> = serde_json::from_slice(&body).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "peer-z:443");
        assert!(nodes[0].verified);
        assert!(nodes[0].connected);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/health", &[]);
        assert_eq!(status, 200);
        let health: PoolHealth = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.transport, "masked");
        assert_eq!(health.connected_peers, 1);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/links", &[]);
        assert_eq!(status, 200);
        let links: Vec<PoolLinkInfo> = serde_json::from_slice(&body).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].peer, "peer-z:443");
        assert!(links[0].converged);
    }

    /// Viewer (read-only) must be allowed on all three GET pool routes —
    /// they fall out of the existing "Viewer = GET only" rule automatically,
    /// this just confirms the allowlist entries actually classify.
    #[test]
    fn authorize_viewer_allowed_on_pool_get_routes() {
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/pool/nodes"));
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/pool/health"));
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/pool/links"));
    }

    /// Admin is allowed too (Admin = every curated route).
    #[test]
    fn authorize_admin_allowed_on_pool_get_routes() {
        assert!(authorize(ROLE_ADMIN, METHOD_GET, "/api/v1/pool/nodes"));
        assert!(authorize(ROLE_ADMIN, METHOD_GET, "/api/v1/pool/health"));
        assert!(authorize(ROLE_ADMIN, METHOD_GET, "/api/v1/pool/links"));
    }

    /// User (no management access) is denied on all three, same as every
    /// other curated route.
    #[test]
    fn authorize_user_denied_on_pool_get_routes() {
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/pool/nodes"));
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/pool/health"));
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/pool/links"));
    }

    /// Pool routes are GET-only over the tunnel (read-only by design) —
    /// even Admin gets no POST/PATCH/DELETE on `/api/v1/pool/*` since no
    /// such route exists in `classify_route`'s allowlist at all.
    #[test]
    fn authorize_pool_routes_reject_non_get_methods_for_every_role() {
        for role in [ROLE_USER, ROLE_VIEWER, ROLE_ADMIN] {
            assert!(!authorize(role, METHOD_POST, "/api/v1/pool/nodes"));
            assert!(!authorize(role, METHOD_PATCH, "/api/v1/pool/health"));
            assert!(!authorize(role, METHOD_DELETE, "/api/v1/pool/links"));
        }
    }
}
