//! Gateway Engine - Full Implementation
//!
//! Handles:
//! - UDP packet reception with O(1) tag validation
//! - Decryption and de-mimicry
//! - NAT forwarding to internet
//! - Bidirectional traffic shaping
//! - Neural Resonance validation (Patent 1)
//! - Automatic mask rotation on compromise (Patent 3)

use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use aivpn_common::crypto::{self, decrypt_payload, encrypt_payload_into, NONCE_SIZE, TAG_SIZE};
use aivpn_common::error::{Error, Result};
use aivpn_common::fec::FecRepair;
use aivpn_common::kernel_accel::KernelAccel;
use aivpn_common::mask::{
    current_unix_secs, derive_bootstrap_candidates, BootstrapDescriptor, MaskProfile,
};
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType, MAX_PACKET_SIZE};
use libc;
use rand::{RngCore as _, SeedableRng as _};
use zeroize::Zeroize;

/// A7 downlink shaping packet-size ceiling. Kept in sync with mimicry.rs's
/// `SAFE_OUTER_PACKET_BUDGET` (1380) so a padded downlink datagram never
/// exceeds the WAN-safe budget the client uses for uplink — padding above
/// this would risk IP fragmentation and a DPI-visible size anomaly.
const SAFE_DOWNLINK_BUDGET: usize = 1380;

/// 1c `ShapingLevel::Light` padding ceiling. Small enough that most of the
/// bandwidth/CPU cost `Full` pays for full size-distribution padding is
/// avoided, but non-zero so `Light` downlink packets are still not trivially
/// distinguishable from `Off`'s "always exactly the unpadded payload size".
const LIGHT_SHAPING_MAX_PAD: u16 = 96;

mod config;
pub use config::{
    GatewayConfig, ShapingLevel, DEFAULT_FEEDBACK_FAILURE_THRESHOLD,
    DEFAULT_FEEDBACK_REPORT_INTERVAL_SECS,
};

mod throttle;
use throttle::{
    try_claim_mask_feedback_slot, try_claim_mask_preference_slot, try_claim_mgmt_slot,
    MASK_FEEDBACK_THROTTLE, MASK_PREFERENCE_THROTTLE, MGMT_THROTTLE,
};

mod chain_reverse;
use chain_reverse::{chain_reverse_route_insert, chain_reverse_route_lookup};

mod mask_catalog;
pub use mask_catalog::MaskCatalog;
use mask_catalog::{
    distinct_tag_offsets_of, extract_tag_for_layout, inner_l7_prefix, packet_layout_for_mask,
    packet_mdh_bytes_for_mask, tag_prefix_len,
};

mod security;
use security::{hash_addr, verify_device_enrollment_proof};

mod kernel_offload;
use kernel_offload::{
    kernel_session_sig, kernel_wire_layout, make_kernel_downlink, make_kernel_session_add,
    make_kernel_update_tags, KERNEL_DOWNLINK_ARMED,
};

mod recording;

mod control_send;

mod bootstrap;
use bootstrap::bootstrap_epoch;
pub use bootstrap::{build_bootstrap_descriptors, derive_server_signing_key};

mod exit_routing;
pub(crate) use exit_routing::apply_global_exit_and_teardown;
// `exits_needing_dial` and `teardown_unused_exit_dials_for` are called
// cross-module as `crate::gateway::X` from `management_api.rs` (behind the
// `management-api` feature) — re-exported (not just `use`d) so that path
// keeps resolving after the move. `#[allow(unused_imports)]` because
// without that feature this re-export has no caller in-crate (mod.rs's own
// use of both is entirely internal to `exit_routing.rs` now).
#[cfg(test)]
use exit_routing::apply_global_exit_swap;
use exit_routing::{add_dial_peers_for_client_exits_for, choose_exit, ExitDecision};
#[allow(unused_imports)]
pub(crate) use exit_routing::{exits_needing_dial, teardown_unused_exit_dials_for};

mod control_dispatch;

mod packet_ingress;

mod packet_demux;

mod data_plane;

mod run_loop;

use crate::audit_log::{AuditActor, AuditLogger};
use crate::batch_io::PacketBatchIo as _;
use crate::client_db::{ClientDatabase, ClientRole};
use crate::ebpf_observer::EbpfObserver;
use crate::mask_store::MaskStore;
use crate::metrics::MetricsCollector;
use crate::mgmt_service;
use crate::nat::NatForwarder;
use crate::neural::{NeuralResonanceModule, ResonanceStatus};
use crate::qos::QosEnforcer;
use crate::recording::RecordingManager;
use crate::recording::RecordingStopOutcome;
use crate::session::{Session, SessionManager, MAX_SESSIONS};
use aivpn_common::event_log::EventBus;

struct QueuedPacket {
    packet_data: Vec<u8>,
    client_addr: SocketAddr,
}

/// Hash a socket address for privacy-preserving logging (MED-4)
/// §3 F idempotency predicate: whether a session's current (active or pending)
/// mask id already equals the polymorphic `variant` id the server would push in
/// response to a `MaskPreference`. When true, the gateway skips re-pushing a
/// `MaskUpdate` so a retried MaskPreference does not reset the mimicry FSM.
fn polymorphic_variant_already_active(
    current_mask_id: Option<&str>,
    variant_mask_id: &str,
) -> bool {
    current_mask_id == Some(variant_mask_id)
}

/// BUG D1 fix (route-auth identity enforcement): `true` when a `RouteSync`
/// from a masked pool-peer session must be dropped outright rather than
/// processed with a self-asserted identity. Only fires when ALL of: the
/// session is a masked pool-peer (`is_masked_pool`); the deployment has
/// opted into strict enforcement (`require_node_enrollment`); and the
/// session has no crypto-verified `verified_node_id` yet (no successful
/// `NodeEnrollment` proof). Legacy `is_site_peer`-only sessions are never
/// affected — they're authenticated via the directional site_sync key, not
/// per-node identity, so this gate simply doesn't apply to them. Pulled out
/// of the `ControlPayload::RouteSync` arm in `handle_control_message` as a
/// pure function so the gate condition is directly unit-testable without
/// needing to drive a full session + site_sync-configured RouteSync
/// round-trip.
fn route_sync_must_be_dropped_unverified(
    is_masked_pool: bool,
    require_node_enrollment: bool,
    verified_node_id: &Option<String>,
) -> bool {
    is_masked_pool && require_node_enrollment && verified_node_id.is_none()
}

/// Gateway server
pub struct Gateway {
    config: GatewayConfig,
    session_manager: Arc<SessionManager>,
    udp_socket: Option<Arc<UdpSocket>>,
    nat_forwarder: Option<Arc<NatForwarder>>,
    /// Channel-based TUN writer (replaces Mutex for upload throughput)
    tun_write_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Per-IP rate limiter: (packet_count, window_start)
    rate_limits: Arc<DashMap<IpAddr, (u64, Instant)>>,
    /// Per-IP handshake failure cooldown: (failure_count, last_failure_time)
    /// Prevents rapid session-creation loops when client retries with stale keys
    handshake_cooldowns: Arc<DashMap<IpAddr, (u32, Instant)>>,
    /// Per-IP handshake mutex: serializes concurrent handshakes arriving on
    /// different source ports from the same client, preventing duplicate sessions
    /// that compete for the same VPN IP and cause aead::Error on data packets.
    handshake_locks: Arc<DashMap<IpAddr, Arc<tokio::sync::Mutex<()>>>>,
    /// Global (cross-IP) token-bucket budget for the expensive tag-window
    /// rescan fallback (`refresh_and_find_by_tag` / `recover_session_by_tag`).
    /// See `MAX_FALLBACK_SCANS_PER_SEC` for rationale. Fields: (count, window_start).
    fallback_scan_budget: Arc<parking_lot::Mutex<(u64, Instant)>>,
    /// Global (source-IP-independent) budget for the expensive per-client ×
    /// per-mask handshake candidate scan. The per-IP `handshake_cooldowns` gate
    /// is defeated by source-IP spoofing, so this bounds the aggregate scan rate.
    /// See `MAX_HANDSHAKE_SCANS_PER_SEC`. Fields: (count, window_start).
    handshake_scan_budget: Arc<parking_lot::Mutex<(u64, Instant)>>,
    /// Neural Resonance Module (Patent 1) — periodic traffic validation
    neural_module: Arc<parking_lot::Mutex<NeuralResonanceModule>>,
    /// R2 Phase D — inline ML-DPI "reads-as-tunnel" gate. A sibling to the neural
    /// resonance MSE check: both feed the same mask-rotation path. Only built
    /// under the `neural` feature.
    #[cfg(feature = "neural")]
    dpi_gate: Arc<crate::dpi_gate::DpiGate>,
    /// Mask catalog for automatic rotation (Patent 3)
    mask_catalog: Arc<MaskCatalog>,
    /// FIX E (pre-auth CPU amplification): distinct tag-offset set
    /// contributed by the built-in preset masks, computed ONCE at
    /// construction from `preset_masks::all()` and cached here. The presets
    /// are compile-time constants (see `preset_masks::all`'s `OnceLock`
    /// statics) — their offsets never change for the lifetime of the
    /// process — so there is no invalidation to manage: this field is
    /// write-once. See `distinct_tag_offsets` for why avoiding a
    /// per-packet `preset_masks::all()` call matters (it used to deep-clone
    /// all 5 preset `MaskProfile`s, including their 64-float
    /// `signature_vector`s and boxed FSM/header-spec data, on every single
    /// inbound UDP datagram — including pre-auth garbage packets).
    preset_tag_offsets: Vec<usize>,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    /// Client database for PSK-based authentication
    client_db: Option<Arc<ClientDatabase>>,
    /// Recording manager for auto mask recording
    recording_manager: Option<Arc<RecordingManager>>,
    /// Mask store for auto-generated masks
    #[allow(dead_code)]
    mask_store: Option<Arc<MaskStore>>,
    /// Active bootstrap descriptors for previous/current/next epochs. Shared
    /// with the periodic rotation task (see `run()`), which rebuilds and
    /// swaps this in-place once the current epoch advances — without the
    /// lock, descriptors were only ever built once at startup and silently
    /// went stale (`expires_at`) on any server that stayed up longer than
    /// ~3 days, so newly-connecting clients kept being handed expired,
    /// self-rejected descriptors.
    bootstrap_descriptors: Arc<parking_lot::RwLock<Vec<BootstrapDescriptor>>>,
    /// Optional kernel-module accelerator (auto-detected via /dev/aivpn).
    kernel_accel: Option<Arc<KernelAccel>>,
    /// Structured event bus for JSON-lines output.
    event_bus: EventBus,
    /// Per-client QoS enforcer (token bucket + DSCP marking).
    qos_enforcer: Arc<QosEnforcer>,
    /// Multi-hop exit node forwarder (None = local NAT).
    chain_forwarder: Option<Arc<crate::chain_forwarder::ChainForwarder>>,
    /// PHASE 3 (exit / chain-forward over masked transport): the
    /// `PoolDialer` this node uses to reach `masked_exit_addr` as a masked
    /// pool-peer session, instead of the legacy dedicated-socket
    /// `ChainForwarder`. `Some` only when `pool.transport == "masked"` AND
    /// an `exit_node` is configured — see `set_masked_exit`. The two exit
    /// strategies are the operator's `pool.transport` choice (wired
    /// mutually exclusively in `main.rs`); both fields staying `None` (the
    /// default) reproduces the exact pre-existing single-hop behavior.
    pool_dialer: Option<Arc<crate::pool_dialer::PoolDialer>>,
    /// The exit node's dial-set key (`host:port`) — MUST be the exact
    /// string used both as an entry in `pool_dialer`'s configured peer set
    /// and as the `peer` argument to `PoolDialer::send_to_peer`, or
    /// forwarded `ChainForward` payloads will silently find no live
    /// sender. See `set_masked_exit`.
    ///
    /// P1 (global exit live-swap): interior-mutable (`RwLock`, not a plain
    /// field) so `apply_global_exit_and_teardown` can hot-swap it from the
    /// mgmt side-effect path (`dispatch_mgmt_request`, and now also the
    /// REST/Unix-socket `confirm_config`) without needing `&mut self` — the
    /// hot packet-forwarding read in `exit_decision_for_session`
    /// takes a short-lived read guard around the pure `choose_exit` call
    /// only, well before any actual packet send, so a concurrent write here
    /// never blocks (or is blocked by) a send in flight.
    ///
    /// P1 REST parity fix: wrapped in `Arc` (not a bare `RwLock`) so the
    /// SAME cell can be shared with the REST/Unix-socket management API's
    /// `ApiState` (via `masked_exit_addr()`/`AivpnServer::masked_exit_addr()`,
    /// mirroring `exit_route_cache()`'s existing sharing pattern) — without
    /// this, a `pool.exit_node` change confirmed over REST could only ever
    /// mutate a copy, never this node's actual live routing state.
    masked_exit_addr: Arc<parking_lot::RwLock<Option<String>>>,
    /// B2b (per-client exit routing, data plane): caches the resolved
    /// per-client masked-exit target for each client VPN IP, so the
    /// per-packet uplink path never does more than a single `DashMap` get
    /// (`resolve_client_exit_addr`) instead of a linear
    /// `ClientDatabase::find_by_vpn_ip` scan on every `Data` packet.
    /// `None` cached against a key means "this client has no per-client
    /// `exit_node` override — use the global default"; a missing key means
    /// "not yet resolved" and triggers exactly one `find_by_vpn_ip` lookup
    /// on the next packet from that IP.
    ///
    /// Invalidated (cleared wholesale — this is a small, low-churn map, one
    /// entry per currently-active client VPN IP, so a full clear is cheap)
    /// whenever the underlying `ClientDatabase` can change:
    /// `reload_if_changed()` returning `true` (periodic hot-reload poll AND
    /// SIGHUP), after any `dispatch_mgmt_request` mutation (so an admin
    /// changing a client's `exit_node` takes effect live, without the
    /// client reconnecting), and after a successful pool-sync
    /// `merge_from_json` (so an `exit_node` change made on a PEER node also
    /// takes effect live once it propagates here, not just admin-local
    /// changes).
    exit_route_cache: Arc<DashMap<Ipv4Addr, Option<String>>>,
    /// PHASE 4 (per-node identity): binds a masked pool-peer's self-asserted
    /// `node_id` to a durable Ed25519 key via `NodeEnrollment` (TOFU / manual
    /// pin). `None` (default) leaves node identity unauthenticated (pre-Phase-4
    /// behavior). Set on masked-transport nodes via `set_node_registry`.
    node_registry: Option<Arc<crate::node_registry::NodeRegistry>>,
    /// Wave B1 (pool topology read endpoints): mirrors
    /// `GatewayConfig::pool_configured` — see that field's doc comment.
    pool_configured: bool,
    /// PHASE 4 (reverse chain-forward / exit downlink gap): on an exit node,
    /// remembers which masked pool-peer session (a dial-set entry on the
    /// ENTRY side — see `pool_dialer.rs`) an origin client's `ChainForward`
    /// uplink most recently arrived on, keyed by that client's VPN IP as
    /// embedded in the forwarded packet's own IP header (the exit has no
    /// local `Session` for it — the client is registered on the entry, not
    /// here). The TUN read loop's downlink worker (`downlink_worker`)
    /// consults this whenever `SessionManager::get_session_by_vpn_ip` finds
    /// no local session for a reply's destination; if a route is still
    /// within `CHAIN_REVERSE_ROUTE_TTL`, the reply is sent back to the entry
    /// as a `ChainForward` control message over that same session instead of
    /// being silently dropped (closing the pre-existing "TUN: no session for
    /// VPN IP" gap for exit-node reply traffic). Populated in the
    /// `ChainForward` RECEIVE arm of `handle_control_message`, gated
    /// strictly on `is_masked_pool_peer` — never the legacy dedicated-socket
    /// `is_pool_peer`/`is_site_peer` roles, which relay over a fixed UDP
    /// socket with no session-based return path to record here. Empty and
    /// inert on any node that never acts as a masked-transport exit.
    chain_reverse_routes: Arc<DashMap<Ipv4Addr, ([u8; 16], Instant)>>,
    /// BUG C3 fix: monotonic count of calls to `chain_reverse_route_insert`,
    /// driving its opportunistic TTL sweep instead of `chain_reverse_routes.len()`
    /// (which plateaus — and so stops firing the sweep — once the map's
    /// distinct-IP population stabilizes, the common case for any subnet no
    /// larger than `CHAIN_REVERSE_SWEEP_EVERY` hosts). See
    /// `chain_reverse_route_insert`'s doc comment.
    chain_reverse_insert_count: Arc<std::sync::atomic::AtomicUsize>,
    /// PHASE 4 (reverse chain-forward / entry-side downlink): sender half of
    /// the channel `pool_dialer.rs`'s `anti_entropy` forwards a reverse
    /// `ChainForward` payload into — see `chain_reverse_downlink_sender`,
    /// which hands a clone of this out to `PoolDialer::new` (wired by
    /// `main.rs` only on nodes that both run the masked pool-client
    /// transport AND have `pool.exit_node` configured, i.e. entry nodes that
    /// actually dial an exit). The receiver half (`chain_reverse_rx`) is
    /// taken by `run()` and handed to `tun_read_loop`, which drains it into
    /// the SAME per-worker downlink dispatch (`downlink_worker`, sharded by
    /// dst VPN IP) the ordinary TUN reader feeds — i.e. the normal
    /// client-downlink encrypt+send path — and deliberately NEVER into
    /// `tun_write_tx`, which would wrongly re-inject the packet into this
    /// node's own local TUN/internet egress instead of delivering it to the
    /// origin client.
    chain_reverse_tx: mpsc::Sender<Vec<u8>>,
    /// Receiver half of `chain_reverse_tx`. `Some` until `run()` takes it to
    /// hand to `tun_read_loop`; `None` afterward (there is only ever one
    /// consumer). See `chain_reverse_tx`'s doc comment.
    chain_reverse_rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// Append-only audit log (H-S-8).
    audit_log: AuditLogger,
    /// §2 crowdsourced blocking feedback — k-anonymity-gated aggregation of
    /// client-reported mask success/fail outcomes by region. Opt-in on the
    /// client side; see `crate::mask_feedback`.
    mask_feedback: Arc<crate::mask_feedback::MaskFeedbackStore>,
    /// Per-session `MaskPreference` throttle: `session_id -> Instant` of the
    /// last time a `MaskPreference` was actually *processed* (i.e. reached
    /// the Ed25519-sign-and-encrypt `build_mask_update_packet` path, not
    /// short-circuited by the idempotency check). See
    /// `MASK_PREFERENCE_THROTTLE` and the `MaskPreference` arm in
    /// `handle_control_message` for the full rationale.
    mask_preference_throttle: Arc<DashMap<[u8; 16], Instant>>,
    /// FIX F (§2 amplification): per-session throttle on the expensive
    /// `MaskFeedback` scan+reply path (`top_masks_for_region` plus up to two
    /// encrypted control-message replies). Same shape as
    /// `mask_preference_throttle`: `session_id -> Instant` of the last time
    /// this session was actually served (not merely received). See
    /// `MASK_FEEDBACK_THROTTLE` and the `MaskFeedback` arm in
    /// `handle_control_message`.
    mask_feedback_throttle: Arc<DashMap<[u8; 16], Instant>>,
    /// P1.2 (in-tunnel management channel): per-session throttle on the
    /// `MgmtRequest` dispatch path (`mgmt_service::dispatch`, which does
    /// DB reads/writes and JSON encoding). Same shape and atomicity
    /// guarantee as `mask_feedback_throttle` — `session_id -> Instant` of
    /// the last time this session's `MgmtRequest` was actually served (a
    /// throttled request never reaches `dispatch`, it gets an immediate
    /// `429` `MgmtResponse` instead). See `MGMT_THROTTLE` and the
    /// `MgmtRequest` arm in `handle_control_message`.
    mgmt_request_throttle: Arc<DashMap<[u8; 16], Instant>>,
    /// FORK-B pool-sync: mirrors `GatewayConfig::pool_server_keypair`. `None`
    /// disables all masked-pool-peer handshake recognition.
    pool_server_keypair: Option<aivpn_common::crypto::KeyPair>,
    /// FORK-B pool-sync: mirrors `GatewayConfig::pool_client_psk`.
    pool_client_psk: Option<[u8; 32]>,
    /// BUG D1 fix (route-auth identity enforcement): when `true`, a masked
    /// pool-peer session's `RouteSync` announcement is dropped unless the
    /// session has a crypto-verified `verified_node_id` (see the
    /// `ControlPayload::RouteSync` arm in `handle_control_message` and
    /// `pool_sync::PoolSyncConfig::require_node_enrollment`, which this is
    /// meant to mirror). Currently hardcoded to `false` at construction
    /// (see `Gateway::new`'s doc comment there) rather than sourced from
    /// `GatewayConfig`, since `main.rs` builds `GatewayConfig` with an
    /// exhaustive struct literal and threading this through it is a
    /// separate, out-of-scope task.
    require_node_enrollment: bool,
    /// P1.5 (apply-with-rollback): shared tracker for in-flight
    /// "commit-confirmed" heavy config changes. Read from
    /// `dispatch_mgmt_request`'s `MgmtCtx` (both `apply_heavy` and
    /// `confirm_config` operate on it) and swept every cleanup tick in
    /// `run()`, which restores `target_path` from `rollback_value()` for
    /// every entry `tick()` returns. Also handed out via
    /// `pending_config()`/`AivpnServer::pending_config()` so
    /// `management_api.rs`'s REST `ServeConfig` shares the SAME instance —
    /// a REST-initiated apply must be swept by this SAME timer (see
    /// `mgmt_service::MgmtCtx::pending_config`'s doc comment).
    pending_config: Arc<crate::pending_config::PendingConfigManager>,
}

/// Global cap (packets/sec, shared across ALL source IPs) on how often the
/// expensive "scan every session and recompute its tag window" fallback
/// (`refresh_and_find_by_tag` / `recover_session_by_tag`) may run.
///
/// Every packet whose 8-byte resonance tag misses the O(1) `tag_map` lookup
/// — including arbitrary garbage UDP payloads from an unauthenticated sender,
/// no PSK/session required — falls through to this fallback, which iterates
/// every active session (`MAX_SESSIONS` = 500) and recomputes its ~256-512
/// wide tag window (one keyed BLAKE3 hash per counter slot). Measured cost is
/// ~69ns/hash, so one full scan over 500 sessions costs roughly 20ms of CPU.
/// The per-IP packet-rate limiter (`per_ip_pps_limit`, default 1000/s) alone
/// is not sufficient: it is keyed by source IP, which UDP senders can vary or
/// spoof per packet, so a distributed/spoofed sender could otherwise force
/// unbounded full-table rescans. This budget is independent of source IP and
/// bounds the worst-case aggregate cost regardless of how many distinct
/// (possibly spoofed) source addresses are used. It is intentionally generous
/// relative to legitimate reconnection/time-window-drift recovery traffic,
/// which is rare compared to steady-state data packets that hit the fast
/// `tag_map` path directly.
const MAX_FALLBACK_SCANS_PER_SEC: u64 = 20;
/// Global cap on the per-client × per-mask handshake candidate scan (the most
/// expensive pre-auth path: DH + key derivation + tag-window build per
/// candidate). Bounds worst-case aggregate cost under a source-IP-spoofed flood
/// that the per-IP `handshake_cooldowns` gate cannot stop. Generous relative to
/// legitimate new-connection rate (established clients hit the fast tag_map
/// path, not this scan).
const MAX_HANDSHAKE_SCANS_PER_SEC: u64 = 100;

impl Gateway {
    /// Resolve a session's server-assigned management role:
    /// `client_id -> client_db.find_by_id -> ClientConfig::role`, defaulting
    /// to `ClientRole::User` when the session has no `client_id` yet
    /// (pre-enrollment), no `client_db` is configured, or the client record
    /// can no longer be found (e.g. it was just revoked). Deliberately
    /// re-resolved on every call rather than cached on `Session` — a live
    /// revoke or role downgrade must take effect on the client's very next
    /// `MgmtRequest`/`Capabilities` push, not just after it reconnects.
    /// Used by both the `Capabilities` announcement and the `MgmtRequest`
    /// authorization gate (see the `Keepalive` and `MgmtRequest` arms in
    /// `handle_control_message`).
    fn session_role(&self, session: &Arc<parking_lot::Mutex<Session>>) -> ClientRole {
        let client_id = session.lock().client_id.clone();
        client_id
            .and_then(|cid| self.client_db.as_ref().and_then(|db| db.find_by_id(&cid)))
            .map(|c| c.role)
            .unwrap_or_default()
    }

    /// `MgmtRequest`-specific wrapper around `try_claim_slot` (P1.2) — see
    /// that function's doc comment for the atomicity guarantee. Bounds
    /// `mgmt_service::dispatch` (DB IO + JSON encoding) to at most once per
    /// session per `MGMT_THROTTLE`; a call that doesn't claim a slot must
    /// reply with an immediate `429` `MgmtResponse` instead of dispatching.
    fn try_claim_mgmt_slot(&self, session_id: [u8; 16], now: Instant) -> bool {
        try_claim_mgmt_slot(&self.mgmt_request_throttle, session_id, now)
    }

    /// P1 (global exit live-swap): parse `pool.exit_node` out of the
    /// `server.json` at `path` as generic JSON — mirrors
    /// `mgmt_service::resolve_heavy_setting`'s own read-and-parse of the
    /// same key, but READ-ONLY (no mutation, no rollback tracking) and
    /// tolerant of any failure by simply returning `None` rather than
    /// propagating an error: an unreadable/unparsable file or an
    /// absent/blank key all collapse to "no global exit configured",
    /// exactly like `main.rs`'s own startup resolution would treat them.
    /// Never panics.
    fn read_global_exit_node(path: &std::path::Path) -> Option<String> {
        let content = std::fs::read_to_string(path).ok()?;
        let value: serde_json::Value = serde_json::from_str(&content).ok()?;
        let addr = value
            .get("pool")?
            .get("exit_node")?
            .as_str()?
            .trim()
            .to_string();
        if addr.is_empty() {
            None
        } else {
            Some(addr)
        }
    }

    /// P1 (global exit live-swap): apply a freshly re-read `pool.exit_node`
    /// value (`new_global` — `None` means "the file has no global exit
    /// configured", see `read_global_exit_node`) to `masked_exit_addr`.
    ///
    /// A no-op — cheaply, without ever touching `masked_exit_addr` — when
    /// `pool_dialer` isn't wired at all (legacy transport / no masked
    /// pool-client dialer running on this node): the field would stay
    /// meaningless without a dialer to route through, matching
    /// `set_masked_exit`'s existing precondition and preserving this
    /// node's exact pre-P1 behavior in that configuration.
    ///
    /// Otherwise: a no-op unless `new_global` actually differs from the
    /// CURRENT in-memory value (avoids taking the write lock on every mgmt
    /// request when nothing changed). On an actual change, updates
    /// `masked_exit_addr` and — if the new value is `Some` — ensures a
    /// dial task is spawned for it via `PoolDialer::add_peer` (idempotent;
    /// mirrors B2c's per-client handling), so the new global default goes
    /// live in this SAME mgmt round-trip rather than only after a fresh
    /// packet triggers `exit_decision_for_session`. A change to `None`
    /// (global exit cleared) intentionally does NOT tear down the old
    /// dial here — that is `teardown_unused_exit_dials`'s job, run right
    /// after this in `dispatch_mgmt_request`.
    ///
    /// A thin `&self` wrapper around the free `apply_global_exit_swap` —
    /// production code (`dispatch_mgmt_request`) now calls
    /// `apply_global_exit_and_teardown` directly instead (which itself
    /// re-reads `new_global` from disk and calls `apply_global_exit_swap`),
    /// so this method is `#[cfg(test)]`-only: a convenient, direct entry
    /// point for feeding an already-known value in unit tests.
    #[cfg(test)]
    fn apply_global_exit_update(&self, new_global: Option<String>) {
        apply_global_exit_swap(
            &self.masked_exit_addr,
            self.pool_dialer.as_ref(),
            new_global,
        );
    }

    /// Wave 2 (dial-teardown): compute the set of masked-exit addresses
    /// this node currently has ANY reason to keep dialing — the global
    /// default (`masked_exit_addr`, if set) plus every distinct per-client
    /// `exit_node` override still present in `client_db` — and
    /// `PoolDialer::remove_peer` any RUNTIME-added exit dial (one
    /// `add_peer` previously spawned for a client or global exit — see
    /// `PoolDialer::runtime_exit_peer_addrs`) that is no longer in that
    /// referenced set.
    ///
    /// NEVER touches a startup-configured `pool.peers` sync peer or a
    /// startup `pool.exit_node` (both dialed via `PoolDialer::start()`,
    /// never tracked as a runtime-exit peer) — `PoolDialer::remove_peer`
    /// itself independently refuses to act on anything outside that set
    /// (see its doc comment), so this is belt-and-suspenders against ever
    /// tearing down real pool-sync membership even if this function's own
    /// "referenced" computation were ever wrong.
    ///
    /// A no-op — cheaply — when `pool_dialer` isn't wired at all (legacy
    /// transport / no pool-sync at all). Production code now runs this
    /// logic via `apply_global_exit_and_teardown` (called from the mgmt
    /// side-effect block in `dispatch_mgmt_request`, right after its own
    /// swap + `add_dial_peers_for_client_exits_for`), so a mutation that
    /// clears/changes a client's or the global `exit_node` prunes the
    /// now-unused dial in the SAME mgmt round-trip that (possibly) added a
    /// new one.
    ///
    /// A thin `&self` wrapper around the free `teardown_unused_exit_dials_for`
    /// — `#[cfg(test)]`-only, same rationale as `apply_global_exit_update`
    /// above.
    #[cfg(test)]
    fn teardown_unused_exit_dials(&self) {
        if self.pool_dialer.is_none() {
            return;
        }
        let clients = self
            .client_db
            .as_ref()
            .map(|db| db.list_clients())
            .unwrap_or_default();
        teardown_unused_exit_dials_for(&self.masked_exit_addr, self.pool_dialer.as_ref(), &clients);
    }

    /// P1.3 (admin revoke): force-disconnect any live session(s) for
    /// `client_id` on THIS node — sends `ControlPayload::Shutdown{reason:
    /// 4 /* revoked */}` to each, then immediately `remove_session`s it.
    /// Called synchronously from the in-tunnel `MgmtRequest` revoke arm
    /// (see `handle_control_message`'s `MgmtRequest` match) right after a
    /// successful `mgmt_service::revoke`, so a connected client is dropped
    /// in the SAME round-trip as the admin's revoke request — unlike the
    /// REST revoke path (`management_api.rs`), whose `ApiState` holds no
    /// `Gateway`/`SessionManager` handle and so falls back to the periodic
    /// revocation sweep in `run()` (which now also sends this same
    /// `Shutdown{reason:4}`, just up to ~5s later). See
    /// `mgmt_service::revoke`'s doc comment for the full split.
    ///
    /// Reason code 4 = revoked, alongside the pre-existing
    /// 1=one-time-used/2=expired/3=disabled `Shutdown` reasons already sent
    /// elsewhere in this file.
    ///
    /// A client should hold at most one live session per node in normal
    /// operation (`SessionManager::cleanup_old_sessions_for_client_id`
    /// already evicts stale duplicates on every fresh handshake), but this
    /// collects and drops every matching session defensively rather than
    /// assuming exactly one.
    async fn force_disconnect_client(&self, client_id: &str) {
        if self.udp_socket.is_none() {
            return;
        }
        let targets: Vec<([u8; 16], Arc<parking_lot::Mutex<Session>>)> = self
            .session_manager
            .iter_sessions()
            .filter_map(|entry| {
                let session = entry.value().clone();
                let is_target = session.lock().client_id.as_deref() == Some(client_id);
                is_target.then(|| (*entry.key(), session))
            })
            .collect();

        for (session_id, session) in targets {
            let shutdown = ControlPayload::Shutdown { reason: 4 };
            // `send_control_message` (not `_via` with the CATALOG mdh):
            // a session running a generated/custom mask has a different
            // MDH length, and a catalog-mdh packet lands at the wrong
            // ciphertext offset client-side — the client would never
            // decode the revoke reason (it still gets disconnected
            // server-side, but silently).
            if let Err(e) = self.send_control_message(&shutdown, &session).await {
                debug!(
                    "force_disconnect_client: Shutdown send failed for revoked client {}: {}",
                    client_id, e
                );
            }
            self.session_manager.remove_session(&session_id);
            warn!(
                "Force-disconnected session {:02x}{:02x}{:02x}{:02x} — client {} revoked",
                session_id[0], session_id[1], session_id[2], session_id[3], client_id
            );
        }
    }

    /// P1.3 (priority pool beacon): if a masked `PoolDialer` handle is
    /// installed on this node (`set_masked_exit`/`set_pool_dialer` — see
    /// those setters' doc comments) and a `ClientDatabase` is configured,
    /// push an immediate `PoolStateDigest` beacon to every currently
    /// connected pool peer via `PoolDialer::broadcast` — the SAME send
    /// path `pool_dialer.rs`'s scheduled anti-entropy tick uses, just
    /// triggered right now instead of waiting up to `pool.sync_beacon_secs`
    /// for the next tick. A revoke already bumps the tombstoned client's
    /// `updated_at` (see `ClientDatabase::remove_client`), so a peer that
    /// receives this beacon and diffs its `state_digest` against its own
    /// will pull the fresh tombstone on its next anti-entropy round either
    /// way — this just gets that round started immediately instead of on
    /// the peer's own schedule.
    ///
    /// No-op (and no error) when no `PoolDialer` is installed — the common
    /// case for a single-node deployment, or a node still on the legacy
    /// mask-independent `PeerSyncer` transport, which has no equivalent
    /// "beacon now" hook and keeps propagating tombstones on its existing
    /// periodic push schedule (out of scope here — see the design's Phase-
    /// out-of-legacy-transport plan).
    fn trigger_priority_pool_beacon(&self) {
        let (Some(dialer), Some(db)) = (self.pool_dialer.as_ref(), self.client_db.as_ref()) else {
            return;
        };
        let digest = db.state_digest();
        let peers_notified = dialer.broadcast(ControlPayload::PoolStateDigest { digest });
        debug!(
            "Priority pool beacon (post-revoke) sent to {} connected peer(s)",
            peers_notified
        );
    }

    pub fn new(config: GatewayConfig) -> Result<Self> {
        // Create server keypair (use config key if provided, otherwise generate ephemeral)
        let server_keys = if config.server_private_key != [0u8; 32] {
            crypto::KeyPair::from_private_key(config.server_private_key)
        } else {
            crypto::KeyPair::generate()
        };

        // Create Ed25519 signing key
        let signing_key = derive_server_signing_key(&config.server_private_key);
        let bootstrap_descriptors =
            Arc::new(parking_lot::RwLock::new(build_bootstrap_descriptors(
                &config.server_private_key,
                &signing_key,
                &config.bootstrap_masks,
            )));

        // Initialize mask catalog (empty — populated from disk only)
        let mask_catalog = Arc::new(MaskCatalog::new());

        // FIX E: compute the preset masks' distinct tag offsets exactly once,
        // here at construction — never again on the per-packet hot path. See
        // `Gateway::preset_tag_offsets`'s doc comment.
        //
        // H6: also fold in `config.bootstrap_masks` — a custom embedded-tag
        // bootstrap mask configured by the operator. `build_bootstrap_descriptors`
        // (called just above) embeds these directly into the descriptors it
        // hands out (`descriptor.embedded_masks`), and `derive_bootstrap_candidate`
        // never changes a candidate's `tag_offset` from its base mask's (only
        // `eph_pub_offset` shifts, by PSK-seeded entropy). So a handshake can
        // succeed on one of these custom masks (pinning the session to it for
        // life) while its offset was never in the probed set here — every
        // subsequent DATA packet's tag then sits at an offset this scan never
        // checks, making the session unroutable immediately after ServerHello.
        // `config.bootstrap_masks` is fixed at startup (never rotated), so —
        // like the presets — this is safe to compute exactly once.
        let preset_tag_offsets = distinct_tag_offsets_of(
            aivpn_common::mask::preset_masks::all()
                .iter()
                .chain(config.bootstrap_masks.iter()),
        );

        // Initialize mask store — loads masks from disk into catalog.
        // R2 Phase B: pass the operator signing key (signs generated masks)
        // and the verify key + mode (config-gated verification on disk load).
        // If no explicit operator pubkey is configured, derive it from the
        // signing key so a single-host generate+verify setup needs one flag.
        let operator_signing = config
            .mask_signing_key
            .map(|seed| ed25519_dalek::SigningKey::from_bytes(&seed));
        let operator_pubkey = config.mask_operator_pubkey.or_else(|| {
            operator_signing
                .as_ref()
                .map(|k| k.verifying_key().to_bytes())
        });
        let mask_store = Arc::new(MaskStore::new(
            mask_catalog.clone(),
            config.mask_dir.clone(),
            operator_signing,
            operator_pubkey,
            config.mask_verify_mode,
        ));

        // Runtime primary mask is selected from the masks loaded on disk.
        // Bootstrap compatibility is handled separately using built-in presets.
        let primary_id = if let Some(first) = mask_catalog.masks.iter().next() {
            let id = first.key().clone();
            id
        } else {
            String::new()
        };
        if !primary_id.is_empty() {
            info!("Primary mask set to '{}' (loaded from disk)", primary_id);
            mask_catalog.set_primary_mask_id(primary_id);
        } else {
            warn!("No masks found in {:?} — server will not accept connections until masks are recorded", config.mask_dir);
        }

        // Get default mask from catalog (required — at least one mask must exist on disk)
        let default_mask = mask_catalog.primary_mask().ok_or_else(|| {
            Error::Session(format!(
                "No masks found in {:?} — place mask JSON files there before starting the server",
                config.mask_dir
            ))
        })?;

        let session_manager = Arc::new(SessionManager::with_timeouts(
            server_keys,
            signing_key,
            default_mask,
            config.session_timeout_secs,
            config.idle_timeout_secs,
        ));

        // Initialize neural resonance module (Patent 1)
        let mut neural = NeuralResonanceModule::new(config.neural_config.clone())
            .map_err(|e| Error::Session(format!("Neural module init failed: {}", e)))?;

        if config.enable_neural {
            // Register all catalog masks for signature-based resonance checking
            for entry in mask_catalog.masks.iter() {
                let _ = neural.register_mask(entry.value());
            }
            // Load neural model (Baked Mask Encoder — ~66KB per mask)
            let _ = neural.load_model();
            info!("Neural Resonance Module initialized (Patent 1)");
        }

        let recording_manager = Arc::new(RecordingManager::new(mask_store.clone()));
        info!(
            "Auto Mask Recording system initialized ({} masks loaded from disk)",
            mask_catalog.available_count()
        );

        let kernel_accel: Option<Arc<KernelAccel>> = KernelAccel::try_open().map(Arc::new);
        if kernel_accel.is_some() {
            info!("Kernel acceleration: active (aivpn.ko loaded — /dev/aivpn ready)");
        } else {
            info!("Kernel acceleration: not available — using built-in user-space data path");
        }

        let event_bus = config.event_bus.clone();
        let qos_enforcer = config.qos_enforcer.clone();
        let audit_log = config.audit_log.clone();

        // PHASE 4 (reverse chain-forward): channel is always constructed —
        // cheap and inert when this node never dials an exit — so
        // `chain_reverse_downlink_sender` needs no `Option` handling at the
        // call site. See the fields' doc comments.
        let (chain_reverse_tx, chain_reverse_rx) = mpsc::channel::<Vec<u8>>(4096);

        Ok(Self {
            config: config.clone(),
            session_manager,
            udp_socket: None,
            nat_forwarder: None,
            tun_write_tx: None,
            rate_limits: Arc::new(DashMap::new()),
            handshake_cooldowns: Arc::new(DashMap::new()),
            handshake_locks: Arc::new(DashMap::new()),
            fallback_scan_budget: Arc::new(parking_lot::Mutex::new((0, Instant::now()))),
            handshake_scan_budget: Arc::new(parking_lot::Mutex::new((0, Instant::now()))),
            neural_module: Arc::new(parking_lot::Mutex::new(neural)),
            #[cfg(feature = "neural")]
            dpi_gate: Arc::new(crate::dpi_gate::DpiGate::new(
                config.neural_config.dpi_gate_threshold,
            )),
            mask_catalog,
            preset_tag_offsets,
            metrics: Arc::new(MetricsCollector::new()),
            client_db: config.client_db,
            recording_manager: Some(recording_manager),
            mask_store: Some(mask_store),
            bootstrap_descriptors,
            kernel_accel,
            event_bus,
            qos_enforcer,
            chain_forwarder: config.chain_forwarder.clone(),
            pool_dialer: None,
            masked_exit_addr: Arc::new(parking_lot::RwLock::new(None)),
            exit_route_cache: Arc::new(DashMap::new()),
            node_registry: None,
            pool_configured: config.pool_configured,
            chain_reverse_routes: Arc::new(DashMap::new()),
            chain_reverse_insert_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            chain_reverse_tx,
            chain_reverse_rx: Some(chain_reverse_rx),
            audit_log,
            mask_feedback: Arc::new(crate::mask_feedback::MaskFeedbackStore::new()),
            mask_preference_throttle: Arc::new(DashMap::new()),
            mask_feedback_throttle: Arc::new(DashMap::new()),
            mgmt_request_throttle: Arc::new(DashMap::new()),
            pool_server_keypair: config.pool_server_keypair,
            pool_client_psk: config.pool_client_psk,
            // BUG D1 fix: NOT sourced from `GatewayConfig` — `main.rs`
            // constructs `GatewayConfig` with an exhaustive struct literal
            // (no `..Default::default()`), so adding a field there would
            // require an out-of-scope edit to `main.rs` (this task is
            // scoped to `gateway.rs`/`pool_sync.rs` only). Hardcoded to
            // `false` here — migration-safe, byte-for-byte unchanged
            // default behavior. TODO(main.rs wiring, separate task): thread
            // `pool.require_node_enrollment()` (see
            // `pool_sync::PoolSyncConfig::require_node_enrollment`) through
            // `GatewayConfig` (alongside the existing
            // `pool_server_keypair`/`pool_client_psk` wiring at the
            // `GatewayConfig { .. }` literal in `main.rs`) and read it here
            // instead of the literal `false`.
            require_node_enrollment: false,
            pending_config: Arc::new(crate::pending_config::PendingConfigManager::new()),
        })
    }

    /// Shared handle to the apply-with-rollback tracker (P1.5), so
    /// `management_api.rs`'s REST `ServeConfig` and `dispatch_mgmt_request`
    /// operate on the SAME `PendingConfigManager` the cleanup task in
    /// `run()` sweeps — mirrors `bootstrap_descriptors()`'s sharing pattern.
    /// Must be called before `run()` consumes the gateway (see
    /// `AivpnServer::pending_config()`, `server.rs`).
    pub fn pending_config(&self) -> Arc<crate::pending_config::PendingConfigManager> {
        self.pending_config.clone()
    }

    /// Set (or replace) the multi-hop chain forwarder after server construction.
    pub fn set_chain_forwarder(&mut self, cf: Arc<crate::chain_forwarder::ChainForwarder>) {
        self.chain_forwarder = Some(cf);
    }

    /// PHASE 3 (exit / chain-forward over masked transport): wire the
    /// masked pool-client exit route in place of the legacy `ChainForwarder`.
    /// `dialer` must already be dialing `exit_addr` (see the `main.rs`
    /// wiring site, which appends the exit node to the `PoolDialer`'s dial
    /// set when it isn't already one of `pool.peers`); `exit_addr` must be
    /// the exact same string used as that dial-set entry, since it doubles
    /// as the `PoolDialer::send_to_peer` lookup key. Must be called before
    /// `run()`. `main.rs` selects exactly one of `set_chain_forwarder` /
    /// `set_masked_exit` per `pool.transport` — the client-data-path sites
    /// prefer the masked route whenever `masked_exit_addr` is `Some`.
    pub fn set_masked_exit(
        &mut self,
        dialer: Arc<crate::pool_dialer::PoolDialer>,
        exit_addr: String,
    ) {
        self.pool_dialer = Some(dialer);
        *self.masked_exit_addr.write() = Some(exit_addr);
    }

    /// P1.3 (priority pool beacon): install a handle to this node's masked
    /// `PoolDialer` even when no `exit_node` is configured. `set_masked_exit`
    /// above only wires `self.pool_dialer` for the exit-dialing case; a
    /// plain pool-sync-only masked-transport node never got a `pool_dialer`
    /// handle on `Gateway` before this, so the admin "revoke" mgmt route's
    /// immediate priority beacon (`trigger_priority_pool_beacon`) had
    /// nothing to call `broadcast` on. `main.rs` calls this unconditionally
    /// whenever the masked `PoolDialer` actually started, right alongside
    /// (and independent of) the `exit_node`-only `set_masked_exit` call —
    /// calling both with the same `Arc` (when this node ALSO dials an
    /// exit) is harmless, the second call just re-sets the same pointer.
    /// Must be called before `run()`.
    pub fn set_pool_dialer(&mut self, dialer: Arc<crate::pool_dialer::PoolDialer>) {
        self.pool_dialer = Some(dialer);
    }

    /// B2b (per-client exit routing): shared handle to the exit-resolution
    /// cache, for callers (`main.rs`'s SIGHUP reload handler) that need to
    /// invalidate it from outside `Gateway`/`AivpnServer` — see the field's
    /// doc comment for the full invalidation policy. Cheap (one `Arc`
    /// clone); safe to call at any time, including before `run()`.
    pub fn exit_route_cache(&self) -> Arc<DashMap<Ipv4Addr, Option<String>>> {
        self.exit_route_cache.clone()
    }

    /// P1 REST parity fix: shared handle to the live `masked_exit_addr`
    /// cell, for callers outside `Gateway`/`AivpnServer`
    /// (`management_api.rs`'s REST `ApiState`, via
    /// `AivpnServer::masked_exit_addr()`) that need to observe/hot-swap this
    /// node's global default exit — mirrors `exit_route_cache()`'s existing
    /// sharing pattern. Cheap (one `Arc` clone); safe to call at any time,
    /// including before `run()`.
    pub fn masked_exit_addr(&self) -> Arc<parking_lot::RwLock<Option<String>>> {
        self.masked_exit_addr.clone()
    }

    /// B2b (per-client exit routing): resolve `ip`'s masked-exit override,
    /// if any, via a single `exit_route_cache` lookup — falling back to
    /// exactly one `ClientDatabase::find_by_vpn_ip` scan (and caching the
    /// result, `None` included) the first time this IP is seen since the
    /// cache was last cleared. See `exit_route_cache`'s doc comment for the
    /// invalidation policy that keeps this from ever serving a stale
    /// `exit_node` after an admin change.
    fn resolve_client_exit_addr(&self, ip: Ipv4Addr) -> Option<String> {
        if let Some(cached) = self.exit_route_cache.get(&ip) {
            return cached.clone();
        }
        let resolved = self
            .client_db
            .as_ref()
            .and_then(|db| db.find_by_vpn_ip(&ip))
            .and_then(|c| c.exit_node);
        self.exit_route_cache.insert(ip, resolved.clone());
        resolved
    }

    /// Wave B2c (runtime dial add-peer): scan every non-deleted client's
    /// `exit_node` and `PoolDialer::add_peer` any address this node isn't
    /// already dialing — makes a freshly-set (or peer-merged-in) per-client
    /// exit route go live WITHOUT a server restart. B2b's `choose_exit`
    /// only ever routes to an exit with a LIVE dial session; before this
    /// wave, the dial set was fixed at `PoolDialer::new` construction, so an
    /// admin pointing a client at a brand-new exit address silently fell
    /// back to the global default (or `NoExit`) forever. Called from
    /// `dispatch_mgmt_request` (right alongside the existing
    /// `exit_route_cache.clear()`) and from the `PoolSync` merge arm of
    /// `handle_control_message` (a peer node's admin can introduce a new
    /// `exit_node` too).
    ///
    /// A no-op — cheaply — when `pool_dialer` isn't wired (legacy transport
    /// or no pool-sync at all) or `client_db` isn't wired. Uses
    /// `PoolDialer::dialed_peer_addrs()` as the "already being dialed" set
    /// so `add_peer` isn't even attempted for an address already tracked
    /// (though `add_peer` is itself idempotent regardless).
    ///
    /// Scope note: this only ever ADDS dial sessions, matching
    /// `PoolDialer::add_peer`'s own scope note — it never tears one down,
    /// and it never touches the GLOBAL default (`masked_exit_addr`) path,
    /// which stays restart-only for this wave (see `PoolDialer::add_peer`'s
    /// doc comment for both follow-ups).
    fn add_dial_peers_for_client_exits(&self) {
        let (Some(dialer), Some(db)) = (self.pool_dialer.as_ref(), self.client_db.as_ref()) else {
            return;
        };
        let clients = db.list_clients();
        add_dial_peers_for_client_exits_for(dialer, &clients);
    }

    /// B2b (per-client exit routing): resolve the full `ExitDecision` for
    /// `session`'s owning client — the pure `choose_exit` decision, fed with
    /// this client's cached per-client override (`resolve_client_exit_addr`),
    /// the node's global default (`masked_exit_addr`), and a live-session
    /// check (`PoolDialer::has_live_session`). A session with no `vpn_ip`
    /// yet (shouldn't happen for a `Data`/FEC packet post-handshake, but
    /// handled defensively) has no per-client override to resolve and
    /// behaves exactly like `client_exit = None`.
    fn exit_decision_for_session(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> ExitDecision {
        let vpn_ip = session.lock().vpn_ip;
        let client_exit = vpn_ip.and_then(|ip| self.resolve_client_exit_addr(ip));
        // P1 (global exit live-swap): short-lived read guard — released at
        // the end of this function, well before `forward_via_exit`'s actual
        // send. Never held across an `.await`.
        let global_guard = self.masked_exit_addr.read();
        choose_exit(client_exit.as_deref(), global_guard.as_deref(), |addr| {
            self.pool_dialer
                .as_ref()
                .is_some_and(|d| d.has_live_session(addr))
        })
    }

    /// B2b (per-client exit routing): execute an `ExitDecision::Send` — try
    /// `PoolDialer::send_to_peer(addr, ChainForward{payload})`; on failure,
    /// either silently drop (`local_fallback == false` — the pre-B2b,
    /// global-default-only behavior, REGRESSION INVARIANT: must never
    /// change) or fall back to local TUN/NAT egress (`local_fallback ==
    /// true` — only reachable via a per-client `exit_node` override, a
    /// strictly new B2b code path). Never falls back to the legacy
    /// `chain_forwarder` — that stays global-only, wired independently by
    /// `main.rs` and mutually exclusive with masked-transport exit routing.
    ///
    /// Only clones `payload` when `local_fallback` is `true` (it may be
    /// needed again for the local-egress fallback) — the common
    /// no-per-client-override path (`local_fallback == false`) moves it
    /// straight into the `send_to_peer` call, same as the pre-B2b code.
    async fn forward_via_exit(
        &self,
        addr: &str,
        local_fallback: bool,
        payload: Vec<u8>,
    ) -> Result<()> {
        if !local_fallback {
            let sent = self
                .pool_dialer
                .as_ref()
                .is_some_and(|d| d.send_to_peer(addr, ControlPayload::ChainForward { payload }));
            if !sent {
                debug!(
                    "masked exit: no live pool-peer session to {} — dropping data packet",
                    addr
                );
            }
            return Ok(());
        }

        let sent = self.pool_dialer.as_ref().is_some_and(|d| {
            d.send_to_peer(
                addr,
                ControlPayload::ChainForward {
                    payload: payload.clone(),
                },
            )
        });
        if sent {
            return Ok(());
        }
        debug!(
            "masked exit: client exit {} has no live dial session — falling back to local egress",
            addr
        );
        if let Some(ref tx) = self.tun_write_tx {
            if tx.send(payload).await.is_err() {
                debug!("TUN write channel closed, dropping packet");
            }
        } else if let Some(ref nat) = self.nat_forwarder {
            nat.forward_packet(&payload).await?;
        } else {
            debug!("NAT disabled, dropping packet");
        }
        Ok(())
    }

    /// PHASE 4 (per-node identity): install the pool-node identity registry so
    /// a masked pool-peer's `NodeEnrollment` is verified and its `node_id`
    /// cryptographically bound. `main.rs` wires this on masked-transport nodes.
    pub fn set_node_registry(&mut self, registry: Arc<crate::node_registry::NodeRegistry>) {
        self.node_registry = Some(registry);
    }

    /// Wave B1 (pool topology read endpoints): shared handle to the
    /// installed node registry, if any — for `dispatch_mgmt_request` (and,
    /// via `AivpnServer::node_registry`, the REST `ApiState`) to build a
    /// `mgmt_service::PoolSnapshot` from live state. `None` on a node with
    /// no pool sync configured, or one running the legacy transport (see
    /// `pool_configured`'s doc comment).
    pub fn node_registry(&self) -> Option<Arc<crate::node_registry::NodeRegistry>> {
        self.node_registry.clone()
    }

    /// Wave B1 (pool topology read endpoints): shared handle to the
    /// installed masked pool-client dialer, if any — see
    /// [`Self::node_registry`]'s doc comment for the same caveat.
    pub fn pool_dialer(&self) -> Option<Arc<crate::pool_dialer::PoolDialer>> {
        self.pool_dialer.clone()
    }

    /// BUG D1 fix (route-auth identity enforcement): install the
    /// `require_node_enrollment` policy — when `true`, a masked pool-peer's
    /// `RouteSync` is dropped unless its session has already proven a
    /// crypto-verified identity via `NodeEnrollment`. Defaults to `false`
    /// (set at construction) for migration-safe, byte-for-byte unchanged
    /// behavior. TODO(main.rs wiring, separate task): once `main.rs` reads
    /// `pool.require_node_enrollment()` from the parsed `PoolSyncConfig`
    /// (see `pool_sync::PoolSyncConfig::require_node_enrollment`), it should
    /// call this setter post-construction — the same pattern already used
    /// for `set_node_registry` above — rather than needing a new field on
    /// `GatewayConfig`'s exhaustive struct literal.
    pub fn set_require_node_enrollment(&mut self, require: bool) {
        self.require_node_enrollment = require;
    }

    /// PHASE 4 (reverse chain-forward): hand out a clone of the sender an
    /// exit node's reverse-direction `ChainForward` reply should be pushed
    /// into on THIS (entry) node, so it reaches the origin client over the
    /// normal downlink path instead of being dropped. `main.rs` wires a
    /// clone of this into `PoolDialer::new` only when this node is both
    /// running the masked pool-client transport AND has `pool.exit_node`
    /// configured (i.e. only on entry nodes that actually dial an exit) —
    /// see `pool_dialer.rs`'s `anti_entropy`, which forwards inbound
    /// `ChainForward` payloads here via `try_send`. Cheap and safe to call
    /// unconditionally: the channel always exists (see `chain_reverse_tx`'s
    /// doc comment), so a node that never dials an exit simply never has
    /// anything sent into it.
    pub fn chain_reverse_downlink_sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.chain_reverse_tx.clone()
    }

    async fn send_bootstrap_descriptors(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let descriptors = self.bootstrap_descriptors.read().clone();
        for descriptor in &descriptors {
            let payload = ControlPayload::BootstrapDescriptorUpdate {
                descriptor_data: rmp_serde::to_vec(descriptor).map_err(|e| {
                    Error::Session(format!("Failed to serialize bootstrap descriptor: {}", e))
                })?,
            };
            self.send_control_message(&payload, session).await?;
        }
        Ok(())
    }

    /// Return a shared reference to the session manager.
    /// Used by pool sync to register the synthetic cluster session before `run()` is called.
    pub fn session_manager(&self) -> Arc<crate::session::SessionManager> {
        self.session_manager.clone()
    }

    /// Return the default mask-dependent header bytes from the mask catalog.
    /// Pool sync packets use this MDH so the receiver can locate the ciphertext
    /// boundary using the same session-mask heuristic as regular client packets.
    pub fn catalog_mdh(&self) -> Vec<u8> {
        self.mask_catalog.packet_mdh_bytes()
    }

    /// Return a shared handle to the live bootstrap descriptors — for the
    /// management API's export endpoint. Must be called before `run()`
    /// consumes the gateway.
    pub fn bootstrap_descriptors(&self) -> Arc<parking_lot::RwLock<Vec<BootstrapDescriptor>>> {
        self.bootstrap_descriptors.clone()
    }

    /// Global throttle gate for the expensive iterate-all-sessions tag
    /// rescan fallback. Returns `true` (and consumes one budget unit) if the
    /// call is allowed this second; `false` if the global budget for this
    /// 1-second window is already exhausted. Unlike `rate_limits`, this is
    /// NOT keyed by source IP — see `MAX_FALLBACK_SCANS_PER_SEC` doc comment.
    fn fallback_scan_allowed(&self) -> bool {
        let mut guard = self.fallback_scan_budget.lock();
        let now = Instant::now();
        if now.duration_since(guard.1) > Duration::from_secs(1) {
            guard.0 = 0;
            guard.1 = now;
        }
        guard.0 += 1;
        guard.0 <= MAX_FALLBACK_SCANS_PER_SEC
    }

    /// Global throttle gate for the expensive per-client × per-mask handshake
    /// candidate scan. Consumes one budget unit and returns `true` if allowed in
    /// the current 1-second window. NOT keyed by source IP (spoof-resistant) —
    /// see `MAX_HANDSHAKE_SCANS_PER_SEC`.
    fn handshake_scan_allowed(&self) -> bool {
        let mut guard = self.handshake_scan_budget.lock();
        let now = Instant::now();
        if now.duration_since(guard.1) > Duration::from_secs(1) {
            guard.0 = 0;
            guard.1 = now;
        }
        guard.0 += 1;
        guard.0 <= MAX_HANDSHAKE_SCANS_PER_SEC
    }

    /// Distinct packet byte offsets at which an incoming resonance tag may sit
    /// (Variant A DPI fix). Always 0 (legacy tag-prefix layout) plus each
    /// embedded `tag_offset` used by a preset bootstrap mask or a runtime
    /// catalog mask. The tag VALUE is offset-agnostic — only its packet position
    /// varies per mask — so probing these offsets locates a session's tag
    /// regardless of which layout the client is currently speaking.
    ///
    /// FIX E (pre-auth CPU amplification): this runs on the receive hot path
    /// — TWICE per inbound datagram (`worker_index_for_packet` before any
    /// rate limiting / session resolution, and again in
    /// `find_existing_session`), including for unauthenticated garbage UDP
    /// floods. It used to call `aivpn_common::mask::preset_masks::all()`
    /// directly here, which deep-clones all 5 built-in `MaskProfile`s
    /// (64-float `signature_vector`s, boxed FSM states, header specs, ...) on
    /// every call. The presets never change at runtime, so that clone is
    /// pure waste — `self.preset_tag_offsets` computes it once, at
    /// `Gateway::new`, and this method only ever reads that cached `Vec` and
    /// cheaply merges in the (also non-cloning) runtime catalog scan below.
    fn distinct_tag_offsets(&self) -> Vec<usize> {
        let mut offsets = self.preset_tag_offsets.clone();
        for entry in self.mask_catalog.masks.iter() {
            if let Some(off) = entry.value().embedded_tag_offset() {
                if !offsets.contains(&off) {
                    offsets.push(off);
                }
            }
        }
        offsets
    }

    /// Compute nonce from counter
    fn compute_nonce(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Get mask catalog reference
    pub fn mask_catalog(&self) -> &Arc<MaskCatalog> {
        &self.mask_catalog
    }

    /// Get metrics reference
    pub fn metrics(&self) -> &Arc<MetricsCollector> {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::polymorphic_variant_already_active;
    use super::route_sync_must_be_dropped_unverified;
    use super::ExitDecision;
    use super::Gateway;
    use super::GatewayConfig;
    use super::Session;
    use aivpn_common::mask::preset_masks::webrtc_zoom_v3;
    use dashmap::DashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// `resolve_client_exit_addr` must: (1) return a client's own
    /// `exit_node` when set, (2) return `None` for a client with no
    /// override AND for an IP matching no client at all, and (3) actually
    /// CACHE the result — a DB change made without invalidating the cache
    /// must not be observed until the cache is explicitly cleared (the same
    /// `.clear()` call the reload/mgmt-mutation/pool-merge hooks perform).
    #[test]
    fn resolve_client_exit_addr_uses_client_override_and_caches_result() {
        use crate::client_db::{ClientDatabase, UpdateClientParams};

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 77, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());
        let with_exit = db.add_client("has-exit").unwrap();
        db.update_client(
            &with_exit.id,
            UpdateClientParams {
                exit_node: Some(Some("exit-a.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();
        let without_exit = db.add_client("no-exit").unwrap();

        let mut config = make_test_gateway_config("exit-cache");
        config.client_db = Some(db.clone());
        let gateway = Gateway::new(config).expect("gateway constructs");

        assert_eq!(
            gateway.resolve_client_exit_addr(with_exit.vpn_ip),
            Some("exit-a.example.com:51820".to_string()),
            "must return the client's own exit_node override"
        );
        assert_eq!(
            gateway.resolve_client_exit_addr(without_exit.vpn_ip),
            None,
            "a client with no override resolves to None (caller falls back to global)"
        );
        let unknown_ip = Ipv4Addr::new(10, 77, 0, 250);
        assert_eq!(
            gateway.resolve_client_exit_addr(unknown_ip),
            None,
            "an IP matching no client at all also resolves to None, not a scan every time"
        );

        // Mutate the DB directly WITHOUT invalidating the cache — the
        // already-cached (now stale) `None` must still be served.
        db.update_client(
            &without_exit.id,
            UpdateClientParams {
                exit_node: Some(Some("exit-b.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            gateway.resolve_client_exit_addr(without_exit.vpn_ip),
            None,
            "a cached result must be served until the cache is explicitly invalidated"
        );

        // After invalidation (the exact `.clear()` the reload/mgmt/pool-merge
        // hooks call), the next resolution re-scans and picks up the change.
        gateway.exit_route_cache().clear();
        assert_eq!(
            gateway.resolve_client_exit_addr(without_exit.vpn_ip),
            Some("exit-b.example.com:51820".to_string()),
            "after cache invalidation, the new exit_node must be resolved"
        );
    }

    /// End-to-end `exit_decision_for_session` wiring (cache + `choose_exit`
    /// + `PoolDialer::has_live_session`) against a REAL `Gateway` +
    /// `PoolDialer`, covering the three routing-helper scenarios from the
    /// B2b spec:
    /// - a client with `exit_node` A and a LIVE session to A → forwards to A
    /// - a client with `exit_node` B but NO live session to B → falls back
    ///   to the global default
    /// - a client with no `exit_node` at all → uses the global default,
    ///   with `local_fallback: false` (the REGRESSION-INVARIANT path,
    ///   byte-identical to pre-B2b `Send{addr: global}`)
    #[tokio::test]
    async fn exit_decision_for_session_routes_per_client_then_falls_back_to_global() {
        use crate::client_db::{ClientDatabase, UpdateClientParams};
        use crate::pool_dialer::PoolDialer;
        use crate::pool_sync::PoolSyncConfig;
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 88, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());

        let live_client = db.add_client("live-exit").unwrap();
        db.update_client(
            &live_client.id,
            UpdateClientParams {
                exit_node: Some(Some("exit-a.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        let dead_client = db.add_client("dead-exit").unwrap();
        db.update_client(
            &dead_client.id,
            UpdateClientParams {
                exit_node: Some(Some("exit-b.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        let plain_client = db.add_client("no-exit").unwrap();

        let pool_cfg = PoolSyncConfig {
            peers: vec![
                "exit-a.example.com:51820".to_string(),
                "exit-b.example.com:51820".to_string(),
            ],
            node_id: Some("this-node:443".to_string()),
            sync_port: None,
            sync_key: Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32])),
            exit_node: None,
            exit_node_enabled: None,
            sync_beacon_secs: None,
            transport: Some("masked".to_string()),
            allow_auto_add: None,
            node_identity_key: None,
            require_node_enrollment: None,
            node_ip_partition: None,
        };
        let dialer = PoolDialer::new(db.clone(), &pool_cfg, vec![], None, None)
            .expect("dialer constructs with a valid sync_key + node_id");
        // Only exit-a has a live dialed session; exit-b's dial_loop is
        // still backing off / never connected.
        let _rx_a = dialer.test_register_live_session("exit-a.example.com:51820");

        let mut config = make_test_gateway_config("exit-decision");
        config.client_db = Some(db.clone());
        let mut gateway = Gateway::new(config).expect("gateway constructs");
        gateway.set_masked_exit(dialer, "global-exit.example.com:51820".to_string());

        let live_session = make_bare_session(Some(live_client.id.clone()));
        live_session.lock().vpn_ip = Some(live_client.vpn_ip);
        assert_eq!(
            gateway.exit_decision_for_session(&live_session),
            ExitDecision::Send {
                addr: "exit-a.example.com:51820".to_string(),
                local_fallback: true,
            },
            "a client with a LIVE per-client exit session must route to its own exit"
        );

        let dead_session = make_bare_session(Some(dead_client.id.clone()));
        dead_session.lock().vpn_ip = Some(dead_client.vpn_ip);
        assert_eq!(
            gateway.exit_decision_for_session(&dead_session),
            ExitDecision::Send {
                addr: "global-exit.example.com:51820".to_string(),
                local_fallback: true,
            },
            "a client whose per-client exit has NO live session must fall back to the global \
             default"
        );

        let plain_session = make_bare_session(Some(plain_client.id.clone()));
        plain_session.lock().vpn_ip = Some(plain_client.vpn_ip);
        assert_eq!(
            gateway.exit_decision_for_session(&plain_session),
            ExitDecision::Send {
                addr: "global-exit.example.com:51820".to_string(),
                local_fallback: false,
            },
            "REGRESSION INVARIANT: a client with NO per-client exit_node must resolve exactly \
             like the pre-B2b global-only path (local_fallback: false)"
        );
    }

    // ── P1: global exit live-swap (masked_exit_addr hot-swap) ────────────

    /// `read_global_exit_node` must extract `pool.exit_node` from a real
    /// `server.json`-shaped file, trimming whitespace.
    #[test]
    fn read_global_exit_node_parses_present_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.json");
        std::fs::write(
            &path,
            r#"{"listen_addr":"0.0.0.0:443","pool":{"exit_node":"  global-exit.example.com:51820  ","peers":[]}}"#,
        )
        .unwrap();
        assert_eq!(
            Gateway::read_global_exit_node(&path),
            Some("global-exit.example.com:51820".to_string())
        );
    }

    /// A missing file must resolve to `None`, never panic — the common
    /// case when `server_config_path` was never configured, or the file
    /// was briefly unreadable.
    #[test]
    fn read_global_exit_node_none_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert_eq!(Gateway::read_global_exit_node(&path), None);
    }

    /// A `server.json` with no `pool` block, or a `pool` block with no
    /// `exit_node` key, must both resolve to `None`.
    #[test]
    fn read_global_exit_node_none_when_key_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.json");
        std::fs::write(&path, r#"{"listen_addr":"0.0.0.0:443"}"#).unwrap();
        assert_eq!(Gateway::read_global_exit_node(&path), None);

        std::fs::write(&path, r#"{"pool":{"peers":[]}}"#).unwrap();
        assert_eq!(Gateway::read_global_exit_node(&path), None);
    }

    /// A blank/whitespace-only `exit_node` value must resolve to `None`,
    /// not `Some("")`/`Some("   ")`.
    #[test]
    fn read_global_exit_node_none_when_value_blank() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.json");
        std::fs::write(&path, r#"{"pool":{"exit_node":"   "}}"#).unwrap();
        assert_eq!(Gateway::read_global_exit_node(&path), None);
    }

    /// Core P1 live-swap guarantee: calling `apply_global_exit_update` with
    /// a new address must (1) make `exit_decision_for_session` route a
    /// plain (no per-client override) client's packet to the NEW global
    /// exit, and (2) spawn a dial task for it via `PoolDialer::add_peer` so
    /// it is actually live — no server restart required. A subsequent
    /// update to `None` must clear the global default again (`NoExit` for
    /// a plain client, matching the REGRESSION INVARIANT in `choose_exit`'s
    /// own tests).
    #[tokio::test]
    async fn apply_global_exit_update_live_swaps_masked_exit_addr() {
        use crate::pool_dialer::PoolDialer;
        use crate::pool_sync::PoolSyncConfig;
        use base64::Engine as _;

        let pool_cfg = PoolSyncConfig {
            peers: vec![],
            node_id: Some("this-node:443".to_string()),
            sync_port: None,
            sync_key: Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32])),
            exit_node: None,
            exit_node_enabled: None,
            sync_beacon_secs: None,
            transport: Some("masked".to_string()),
            allow_auto_add: None,
            node_identity_key: None,
            require_node_enrollment: None,
            node_ip_partition: None,
        };
        let db_dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 95, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(
            crate::client_db::ClientDatabase::load(&db_dir.path().join("clients.json"), network)
                .unwrap(),
        );
        let dialer = PoolDialer::new(db, &pool_cfg, vec![], None, None)
            .expect("dialer constructs with a valid sync_key + node_id");
        dialer.test_mark_started(Arc::new(std::sync::atomic::AtomicBool::new(false)));

        let config = make_test_gateway_config("p1-live-swap");
        let mut gateway = Gateway::new(config).expect("gateway constructs");
        gateway.set_pool_dialer(dialer.clone());

        let plain_session = make_bare_session(None);
        plain_session.lock().vpn_ip = Some(Ipv4Addr::new(10, 95, 0, 50));

        // Before any update: no global default configured at all.
        assert_eq!(
            gateway.exit_decision_for_session(&plain_session),
            ExitDecision::NoExit
        );

        // Live-swap in a brand-new global exit.
        gateway.apply_global_exit_update(Some("new-global-exit.example.com:51820".to_string()));

        assert_eq!(
            gateway.exit_decision_for_session(&plain_session),
            ExitDecision::Send {
                addr: "new-global-exit.example.com:51820".to_string(),
                local_fallback: false,
            },
            "choose_exit must observe the NEW global default immediately, without a restart"
        );
        assert!(
            dialer.is_dialed_peer("new-global-exit.example.com:51820"),
            "the new global exit must get a live dial task via PoolDialer::add_peer"
        );
        assert!(
            dialer.is_runtime_exit_peer("new-global-exit.example.com:51820"),
            "a global exit dialed via apply_global_exit_update must be a RUNTIME exit peer \
             (eligible for later teardown), never a startup pool-sync peer"
        );

        // Clearing the global default must reflect immediately too.
        gateway.apply_global_exit_update(None);
        assert_eq!(
            gateway.exit_decision_for_session(&plain_session),
            ExitDecision::NoExit,
            "REGRESSION INVARIANT: clearing the global default must return exactly to NoExit \
             for a plain client, matching choose_exit's documented truth table"
        );
    }

    /// `apply_global_exit_update` must be a safe, cheap no-op when this
    /// node has no `pool_dialer` wired at all (legacy transport / no
    /// pool-sync) — `masked_exit_addr` must stay untouched (observed via
    /// `exit_decision_for_session` still returning `NoExit`).
    #[test]
    fn apply_global_exit_update_noop_without_pool_dialer() {
        let config = make_test_gateway_config("p1-live-swap-no-dialer");
        let gateway = Gateway::new(config).expect("gateway constructs");

        gateway.apply_global_exit_update(Some("should-be-ignored:51820".to_string()));

        let plain_session = make_bare_session(None);
        plain_session.lock().vpn_ip = Some(Ipv4Addr::new(10, 96, 0, 50));
        assert_eq!(
            gateway.exit_decision_for_session(&plain_session),
            ExitDecision::NoExit,
            "without a pool_dialer, a global exit update must never take effect"
        );
    }

    // ── Wave 2: dial-teardown (unused exit dial pruning) ─────────────────

    /// `teardown_unused_exit_dials` must remove a RUNTIME exit dial that is
    /// no longer referenced by the global default OR any client's
    /// `exit_node`, while leaving a still-referenced runtime exit (and any
    /// startup pool-sync peer) fully intact.
    #[tokio::test]
    async fn teardown_unused_exit_dials_prunes_only_unreferenced_runtime_exits() {
        use crate::client_db::{ClientDatabase, UpdateClientParams};
        use crate::pool_dialer::PoolDialer;
        use crate::pool_sync::PoolSyncConfig;
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 97, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());

        let still_referenced_client = db.add_client("still-referenced").unwrap();
        db.update_client(
            &still_referenced_client.id,
            UpdateClientParams {
                exit_node: Some(Some("still-referenced-exit:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        let pool_cfg = PoolSyncConfig {
            peers: vec!["startup-pool-sync-peer:443".to_string()],
            node_id: Some("this-node:443".to_string()),
            sync_port: None,
            sync_key: Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32])),
            exit_node: None,
            exit_node_enabled: None,
            sync_beacon_secs: None,
            transport: Some("masked".to_string()),
            allow_auto_add: None,
            node_identity_key: None,
            require_node_enrollment: None,
            node_ip_partition: None,
        };
        let dialer = PoolDialer::new(db.clone(), &pool_cfg, vec![], None, None)
            .expect("dialer constructs with a valid sync_key + node_id");
        dialer.test_mark_started(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        // Simulate the startup pool-sync dial `start()` would spawn for
        // `pool.peers`, WITHOUT calling the real `start()` (would try a
        // real network dial for it) — mirrors `pool_dialer.rs`'s own
        // teardown tests.
        dialer.test_spawn_startup_peer("startup-pool-sync-peer:443");

        let mut config = make_test_gateway_config("wave2-teardown");
        config.client_db = Some(db.clone());
        let mut gateway = Gateway::new(config).expect("gateway constructs");
        gateway.set_pool_dialer(dialer.clone());

        // Global default + the referenced client's exit both go live via
        // the SAME runtime paths P1/B2c use.
        gateway.apply_global_exit_update(Some("global-exit:51820".to_string()));
        gateway.add_dial_peers_for_client_exits();
        // A stale runtime exit that NOTHING references any more (e.g. the
        // client that used to point here was deleted/repointed on a prior
        // mgmt request).
        dialer.add_peer("stale-unreferenced-exit:51820");

        assert!(dialer.is_dialed_peer("global-exit:51820"));
        assert!(dialer.is_dialed_peer("still-referenced-exit:51820"));
        assert!(dialer.is_dialed_peer("stale-unreferenced-exit:51820"));
        assert!(dialer.is_dialed_peer("startup-pool-sync-peer:443"));

        gateway.teardown_unused_exit_dials();

        assert!(
            !dialer.is_dialed_peer("stale-unreferenced-exit:51820"),
            "an unreferenced runtime exit must be torn down"
        );
        assert!(
            dialer.is_dialed_peer("global-exit:51820"),
            "the current global default must survive teardown"
        );
        assert!(
            dialer.is_dialed_peer("still-referenced-exit:51820"),
            "a still-referenced client exit must survive teardown"
        );
        assert!(
            dialer.is_dialed_peer("startup-pool-sync-peer:443"),
            "CRITICAL: a startup pool-sync peer must NEVER be torn down by this path"
        );
    }

    /// `teardown_unused_exit_dials` must be a safe, cheap no-op when this
    /// node has no `pool_dialer` wired at all.
    #[test]
    fn teardown_unused_exit_dials_noop_without_pool_dialer() {
        let config = make_test_gateway_config("wave2-teardown-no-dialer");
        let gateway = Gateway::new(config).expect("gateway constructs");
        gateway.teardown_unused_exit_dials();
    }

    /// End-to-end (well short of a network) check of `Gateway::
    /// add_dial_peers_for_client_exits`: with a real `ClientDatabase`
    /// holding a client whose `exit_node` was just set to an address the
    /// node's `PoolDialer` was NOT configured to dial at startup, calling
    /// the hook must actually register that address in the dialer's dial
    /// set (`is_dialed_peer`) — the live-wiring guarantee this whole wave
    /// exists to provide.
    #[tokio::test]
    async fn add_dial_peers_for_client_exits_dials_a_freshly_set_client_exit() {
        use crate::client_db::{ClientDatabase, UpdateClientParams};
        use crate::pool_dialer::PoolDialer;
        use crate::pool_sync::PoolSyncConfig;
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 91, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());

        let client = db.add_client("needs-runtime-dial").unwrap();
        db.update_client(
            &client.id,
            UpdateClientParams {
                exit_node: Some(Some("runtime-exit.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        let pool_cfg = PoolSyncConfig {
            peers: vec!["startup-peer:443".to_string()],
            node_id: Some("this-node:443".to_string()),
            sync_port: None,
            sync_key: Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32])),
            exit_node: None,
            exit_node_enabled: None,
            sync_beacon_secs: None,
            transport: Some("masked".to_string()),
            allow_auto_add: None,
            node_identity_key: None,
            require_node_enrollment: None,
            node_ip_partition: None,
        };
        let dialer = PoolDialer::new(db.clone(), &pool_cfg, vec![], None, None)
            .expect("dialer constructs with a valid sync_key + node_id");
        // Simulate `start()`: the runtime-added exit must NOT already be
        // dialed at this point.
        dialer.test_mark_started(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        assert!(!dialer.is_dialed_peer("runtime-exit.example.com:51820"));

        let mut config = make_test_gateway_config("b2c-runtime-add-peer");
        config.client_db = Some(db.clone());
        let mut gateway = Gateway::new(config).expect("gateway constructs");
        gateway.set_pool_dialer(dialer.clone());

        gateway.add_dial_peers_for_client_exits();

        assert!(
            dialer.is_dialed_peer("runtime-exit.example.com:51820"),
            "a freshly set per-client exit_node must be dialed at runtime, without a restart"
        );
    }

    /// Calling the hook again after nothing changed must not spawn a
    /// second dial task for the same address — `add_peer`'s idempotency
    /// carries through the whole hook.
    #[tokio::test]
    async fn add_dial_peers_for_client_exits_is_idempotent_across_repeated_calls() {
        use crate::client_db::{ClientDatabase, UpdateClientParams};
        use crate::pool_dialer::PoolDialer;
        use crate::pool_sync::PoolSyncConfig;
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 92, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());
        let client = db.add_client("repeat-hook").unwrap();
        db.update_client(
            &client.id,
            UpdateClientParams {
                exit_node: Some(Some("repeat-exit.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        let pool_cfg = PoolSyncConfig {
            peers: vec![],
            node_id: Some("this-node:443".to_string()),
            sync_port: None,
            sync_key: Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32])),
            exit_node: None,
            exit_node_enabled: None,
            sync_beacon_secs: None,
            transport: Some("masked".to_string()),
            allow_auto_add: None,
            node_identity_key: None,
            require_node_enrollment: None,
            node_ip_partition: None,
        };
        let dialer = PoolDialer::new(db.clone(), &pool_cfg, vec![], None, None).unwrap();
        dialer.test_mark_started(Arc::new(std::sync::atomic::AtomicBool::new(false)));

        let mut config = make_test_gateway_config("b2c-idempotent-hook");
        config.client_db = Some(db.clone());
        let mut gateway = Gateway::new(config).expect("gateway constructs");
        gateway.set_pool_dialer(dialer.clone());

        gateway.add_dial_peers_for_client_exits();
        assert_eq!(dialer.spawn_count(), 1);

        gateway.add_dial_peers_for_client_exits();
        assert_eq!(
            dialer.spawn_count(),
            1,
            "a repeated hook call for an unchanged client DB must not double-spawn"
        );
    }

    /// The hook must be a safe, cheap no-op when this node has no
    /// `pool_dialer` wired at all (legacy transport / no pool-sync) — no
    /// panic, nothing to assert beyond "it returns".
    #[test]
    fn add_dial_peers_for_client_exits_noop_without_pool_dialer() {
        use crate::client_db::ClientDatabase;

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 93, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());
        db.add_client("no-pool-dialer-client").unwrap();

        let mut config = make_test_gateway_config("b2c-no-dialer");
        config.client_db = Some(db);
        let gateway = Gateway::new(config).expect("gateway constructs");

        gateway.add_dial_peers_for_client_exits();
    }

    /// Build a `GatewayConfig` pointing at a fresh temp mask directory
    /// seeded with one preset mask, so `Gateway::new` (which requires at
    /// least one mask on disk) succeeds without needing root or any real
    /// network/TUN setup — `Gateway::new` never binds a socket or opens a
    /// TUN device, only `run()` does. `label` plus a monotonic counter keep
    /// each call's directory unique so parallel `#[test]` runs never
    /// collide. Neural is disabled to keep construction fast and dependency-
    /// free for these tests.
    fn make_test_gateway_config(label: &str) -> GatewayConfig {
        make_test_gateway_config_with_mask(label, webrtc_zoom_v3())
    }

    /// Like `make_test_gateway_config`, but seeds the mask dir with the given
    /// mask, which therefore becomes the catalog's primary mask.
    fn make_test_gateway_config_with_mask(
        label: &str,
        mask: aivpn_common::mask::MaskProfile,
    ) -> GatewayConfig {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mask_dir = std::env::temp_dir().join(format!(
            "aivpn-test-gw-{}-{}-{}",
            std::process::id(),
            label,
            id
        ));
        std::fs::create_dir_all(&mask_dir).expect("create temp mask dir");
        let json = serde_json::to_string_pretty(&mask).expect("serialize preset mask");
        std::fs::write(mask_dir.join(format!("{}.json", mask.mask_id)), &json)
            .expect("write mask json");
        std::fs::write(mask_dir.join(format!("{}.stats", mask.mask_id)), "{}")
            .expect("write mask stats");
        let mut config = GatewayConfig::default();
        config.mask_dir = mask_dir;
        config.enable_neural = false;
        config
    }

    /// BUG regression (pool-sync transport): a REAL PoolSync packet built by
    /// `PeerSyncer::build_sync_packet` must decode through the REAL gateway
    /// RECEIVE path (`handle_packet`) — not just a build→decode round-trip,
    /// which bypasses the gateway's mask-layout logic and is exactly the gap
    /// that let the bug escape unit tests. Before the fix the gateway derived
    /// the pool session's payload offset from the node's PRIMARY mask
    /// (`tag_prefix_len(mask.tag_offset) + mdh_len`): with an embedded-tag
    /// primary (8 of the 11 bundled masks) every pool packet failed AEAD and
    /// the peer's clients DB never synced.
    async fn pool_packet_through_gateway(label: &str, mask: aivpn_common::mask::MaskProfile) {
        use crate::client_db::ClientDatabase;
        use crate::pool_sync::{PeerSyncer, PoolSyncConfig};
        use aivpn_common::event_log::{EventBus, EventSinkConfig};
        use aivpn_common::protocol::ControlPayload;
        use base64::Engine as _;
        use std::sync::Arc;

        fn make_syncer(
            dir: &std::path::Path,
            node_id: &str,
            peer: &str,
        ) -> (Arc<ClientDatabase>, Arc<PeerSyncer>) {
            let network = aivpn_common::network_config::VpnNetworkConfig {
                server_vpn_ip: std::net::Ipv4Addr::new(10, 88, 0, 1),
                prefix_len: 24,
                mtu: 1400,
                ..Default::default()
            };
            let db = Arc::new(ClientDatabase::load(&dir.join("clients.json"), network).unwrap());
            let cfg = PoolSyncConfig {
                peers: vec![peer.to_string()],
                node_id: Some(node_id.to_string()),
                sync_port: None,
                sync_key: Some(base64::engine::general_purpose::STANDARD.encode([7u8; 32])),
                exit_node: None,
                exit_node_enabled: None,
                sync_beacon_secs: None,
                transport: None,
                allow_auto_add: None,
                node_identity_key: None,
                require_node_enrollment: None,
                node_ip_partition: None,
            };
            let events = EventBus::new(EventSinkConfig {
                stdout: false,
                webhook_url: None,
            });
            let syncer = PeerSyncer::new(db.clone(), &cfg, events).unwrap();
            (db, syncer)
        }

        // Receiving node "B": a gateway whose ONLY (and therefore primary)
        // mask is `mask`, with a client DB so the merge result is observable.
        let dir_b = tempfile::tempdir().unwrap();
        let (db_b, b_syncer) = make_syncer(dir_b.path(), "node-b:443", "node-a:443");
        let mut config = make_test_gateway_config_with_mask(label, mask);
        config.client_db = Some(db_b.clone());
        let gateway = Gateway::new(config).expect("gateway constructs");
        // Register B's receive session for the A→B link, exactly like
        // `PeerSyncer::start` does on a live node.
        let sentinel: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        gateway
            .session_manager()
            .create_pool_peer_session(&b_syncer.test_peer_recv_root(0), sentinel);

        // Sending node "A": one real client record, pushed in a REAL sync
        // packet (byte-identical to what `push_to_peer` puts on the wire).
        let dir_a = tempfile::tempdir().unwrap();
        let (db_a, a_syncer) = make_syncer(dir_a.path(), "node-a:443", "node-b:443");
        db_a.add_client("pool-test-client").unwrap();
        let clients_json = serde_json::to_vec(&db_a.list_clients_including_deleted()).unwrap();
        let payload = ControlPayload::PoolSync { clients_json };
        let packet = a_syncer.test_build_packet_for_peer(&payload, 0).unwrap();

        // The REAL receive path (tag lookup → layout → decrypt → dispatch).
        let from: std::net::SocketAddr = "203.0.113.7:40000".parse().unwrap();
        gateway
            .handle_packet(&packet, from)
            .await
            .expect("pool sync packet must decode through the gateway receive path");

        assert!(
            db_b.list_clients()
                .iter()
                .any(|c| c.name == "pool-test-client"),
            "peer's client record must be merged into the receiving node's DB"
        );
    }

    #[tokio::test]
    async fn pool_sync_decodes_via_gateway_with_embedded_tag_primary_mask() {
        // webrtc_zoom_v3 embeds the resonance tag at offset 8 (no prefix) —
        // the primary-mask layout that used to break every pool packet.
        pool_packet_through_gateway("pool-embed", webrtc_zoom_v3()).await;
    }

    #[tokio::test]
    async fn pool_sync_decodes_via_gateway_with_prefix_tag_primary_mask() {
        // Legacy prefix-tag primary (tag_offset = u16::MAX) must keep working.
        let mut mask = webrtc_zoom_v3();
        mask.mask_id = "prefix_variant_test".to_string();
        mask.tag_offset = u16::MAX;
        pool_packet_through_gateway("pool-prefix", mask).await;
    }

    #[test]
    fn maskpreference_idempotency_skips_when_variant_already_active() {
        // Same id → skip the re-push (idempotent retry).
        assert!(polymorphic_variant_already_active(
            Some("polymorphic:webrtc_zoom_v3:ab12"),
            "polymorphic:webrtc_zoom_v3:ab12"
        ));
        // Different variant id → must push.
        assert!(!polymorphic_variant_already_active(
            Some("polymorphic:webrtc_zoom_v3:ab12"),
            "polymorphic:webrtc_zoom_v3:ff99"
        ));
        // Still on the base/bootstrap mask → must push.
        assert!(!polymorphic_variant_already_active(
            Some("webrtc_zoom_v3"),
            "polymorphic:webrtc_zoom_v3:ab12"
        ));
        // No mask yet → must push.
        assert!(!polymorphic_variant_already_active(
            None,
            "polymorphic:webrtc_zoom_v3:ab12"
        ));
    }

    /// §3.2 "every session polymorphic" policy: exercises the exact building
    /// blocks the gateway's post-handshake policy-push block uses
    /// (`MaskProfile::to_polymorphic` + `polymorphic_variant_already_active`)
    /// without needing a full UDP/session harness — the gateway code path
    /// itself is a thin, deterministic composition of these two primitives
    /// plus the already-covered `try_claim_mask_preference_slot` throttle.
    ///
    /// Proves two things the policy relies on:
    ///   1. Deriving a variant from a base mask + a session's `prng_seed`
    ///      always yields a `"polymorphic:"`-prefixed mask id (so a fresh
    ///      session, whose current mask id is the plain base id, is always
    ///      seen as "not yet polymorphic" and gets the policy push).
    ///   2. Deriving twice from the SAME base + seed is deterministic, and
    ///      once a session's current mask id equals that derived variant id,
    ///      `polymorphic_variant_already_active` reports it as idempotent —
    ///      i.e. re-running the policy-push logic for an already-migrated
    ///      session (e.g. a duplicate handshake retry) does not re-push.
    #[test]
    fn polymorphic_all_sessions_policy_derives_polymorphic_variant_and_is_idempotent() {
        let base = webrtc_zoom_v3();
        let prng_seed = [0x42u8; 32];

        // Fresh session: current mask is still the plain base id, not a
        // polymorphic variant yet — the policy must push.
        let variant = base.to_polymorphic(&prng_seed);
        assert!(variant.mask_id.starts_with("polymorphic:"));
        assert!(!polymorphic_variant_already_active(
            Some(base.mask_id.as_str()),
            &variant.mask_id
        ));

        // Deterministic re-derivation from the same base + seed (e.g. a
        // second post-handshake pass racing a retried handshake packet)
        // yields the identical variant id.
        let variant_again = base.to_polymorphic(&prng_seed);
        assert_eq!(variant.mask_id, variant_again.mask_id);

        // Once the session's current/pending mask IS that variant (as it
        // would be after `update_session_mask` ran), a second policy pass
        // must be idempotent — no re-push.
        assert!(polymorphic_variant_already_active(
            Some(variant.mask_id.as_str()),
            &variant_again.mask_id
        ));

        // A different prng_seed (different session) derives a different
        // variant id, so it is correctly NOT considered already-active
        // against the first session's variant.
        let other_seed = [0x99u8; 32];
        let other_variant = base.to_polymorphic(&other_seed);
        assert_ne!(variant.mask_id, other_variant.mask_id);
        assert!(!polymorphic_variant_already_active(
            Some(variant.mask_id.as_str()),
            &other_variant.mask_id
        ));
    }

    /// BUG D1 (route-auth identity enforcement): `route_sync_must_be_dropped_unverified`
    /// only fires when the session is a masked pool-peer, strict enforcement
    /// is on, AND the session has no crypto-verified identity yet. Any other
    /// combination (not strict, already verified, or not a masked pool-peer
    /// at all — e.g. a legacy `is_site_peer`-only session) must NOT be
    /// dropped by this gate.
    #[test]
    fn route_sync_drop_gate_fires_only_when_strict_and_unverified_masked_peer() {
        // Strict + masked pool-peer + no verified identity: drop.
        assert!(route_sync_must_be_dropped_unverified(true, true, &None));

        // Strict + masked pool-peer + verified identity: NOT dropped —
        // `handle_route_sync` is called with the proven identity.
        assert!(!route_sync_must_be_dropped_unverified(
            true,
            true,
            &Some("node-a:443".to_string())
        ));

        // require_node_enrollment off (default): never dropped by this gate,
        // regardless of verification — migration-safe legacy behavior.
        assert!(!route_sync_must_be_dropped_unverified(true, false, &None));
        assert!(!route_sync_must_be_dropped_unverified(
            true,
            false,
            &Some("node-a:443".to_string())
        ));

        // Not a masked pool-peer session (e.g. legacy is_site_peer-only,
        // authenticated via the directional site_sync key rather than
        // per-node identity): this gate never applies, strict or not.
        assert!(!route_sync_must_be_dropped_unverified(false, true, &None));
        assert!(!route_sync_must_be_dropped_unverified(false, false, &None));
    }

    /// Build a real server session and return `(SessionManager, session, keys,
    /// mdh_len)` for the given mask. The session registers the resonance tags in
    /// `tag_map` for the current time window, so a client packet built with the
    /// returned keys (same `tag_secret`) resolves via the server tag-lookup.
    #[cfg(test)]
    fn e2e_server_session(
        mask: &aivpn_common::mask::MaskProfile,
    ) -> (
        crate::session::SessionManager,
        std::sync::Arc<parking_lot::Mutex<crate::session::Session>>,
        aivpn_common::crypto::SessionKeys,
        usize,
    ) {
        use aivpn_common::crypto::KeyPair;
        let mdh_len = super::packet_layout_for_mask(mask).0;
        let server_kp = KeyPair::generate();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sm = crate::session::SessionManager::new(server_kp, signing_key, mask.clone());
        let client_kp = KeyPair::generate();
        let client_addr: std::net::SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let session = sm
            .create_session(client_addr, client_kp.public_key_bytes(), None, None)
            .expect("session created");
        let mut keys = session.lock().keys.clone();
        // These e2e tests build a client-uplink packet (C2S key) and decode it
        // with decode_packet_* (which uses the S2C key, the client-downlink
        // path). Equalise the two so the format round-trips in-test; production
        // uplink decrypt uses the C2S key directly in the gateway receive path.
        keys.session_key_s2c = keys.session_key;
        (sm, session, keys, mdh_len)
    }

    /// Variant A end-to-end (the real correctness gate): build a Data packet
    /// exactly as a CLIENT would for a NEW-LAYOUT preset mask (webrtc_zoom_v3,
    /// `tag_offset = 8`), then run it through the SERVER's tag-lookup and
    /// layout-aware decode. Asserts the tag is found at the mask's embedded
    /// offset — and specifically NOT at legacy offset 0 — and that the plaintext
    /// round-trips.
    #[test]
    fn embedded_preset_packet_found_and_decoded_by_server_e2e() {
        use aivpn_common::client_wire::{
            build_inner_packet, build_random_mdh_packet_with_tag_offset, decode_packet_with_layout,
            RecvWindow,
        };
        use aivpn_common::mask::preset_masks;
        use aivpn_common::protocol::InnerType;

        let mask = preset_masks::webrtc_zoom_v3();
        assert_eq!(
            mask.tag_offset, 8,
            "webrtc_zoom_v3 must ship embedded tag@8"
        );
        let (sm, _session, keys, mdh_len) = e2e_server_session(&mask);

        // Client builds a Data packet in the mask's NEW (embedded) layout.
        let inner = build_inner_packet(InnerType::Data, 0, b"variant-a-roundtrip");
        let mut counter = 0u64;
        let packet = build_random_mdh_packet_with_tag_offset(
            &keys,
            &mut counter,
            &inner,
            None,
            mdh_len,
            mask.tag_offset,
        )
        .unwrap();

        // SERVER tag-lookup: the distinct offset set must include 0 (legacy) and
        // 8 (webrtc embedded).
        let offsets = super::distinct_tag_offsets_of(preset_masks::all().iter());
        assert!(offsets.contains(&0) && offsets.contains(&8));

        // The tag resolves at the embedded offset, and NOT at offset 0 (which is
        // the real STUN header, not a resonance tag) — no misattribution.
        let tag_at_8 = super::extract_tag_for_layout(&packet, mask.tag_offset).unwrap();
        assert!(
            sm.get_session_by_tag(&tag_at_8).is_some(),
            "embedded tag@8 must resolve to the session"
        );
        let tag_at_0 = super::extract_tag_for_layout(&packet, u16::MAX).unwrap();
        assert!(
            sm.get_session_by_tag(&tag_at_0).is_none(),
            "offset-0 bytes are the STUN header, not a tag — must NOT match"
        );

        // SERVER decode with the resolved session's layout: plaintext round-trips.
        let mut win = RecvWindow::new();
        let decoded =
            decode_packet_with_layout(&packet, &keys, &mut win, mdh_len, mask.tag_offset).unwrap();
        assert_eq!(decoded.payload, b"variant-a-roundtrip");
    }

    /// A legacy (`tag_offset = u16::MAX`) mask still works unchanged: tag at
    /// offset 0, ciphertext after the `TAG_SIZE` prefix, decode round-trips.
    #[test]
    fn legacy_mask_packet_found_and_decoded_by_server_e2e() {
        use aivpn_common::client_wire::{
            build_inner_packet, build_random_mdh_packet_with_tag_offset, decode_packet_with_layout,
            RecvWindow,
        };
        use aivpn_common::mask::preset_masks;
        use aivpn_common::protocol::InnerType;

        // Force the legacy layout on an otherwise-normal mask.
        let mut mask = preset_masks::webrtc_zoom_v3();
        mask.tag_offset = u16::MAX;
        let (sm, _session, keys, mdh_len) = e2e_server_session(&mask);

        let inner = build_inner_packet(InnerType::Data, 0, b"legacy-roundtrip");
        let mut counter = 0u64;
        let packet = build_random_mdh_packet_with_tag_offset(
            &keys,
            &mut counter,
            &inner,
            None,
            mdh_len,
            u16::MAX,
        )
        .unwrap();

        // Legacy tag lives at offset 0 (the fast path) and resolves the session.
        let tag_at_0 = super::extract_tag_for_layout(&packet, u16::MAX).unwrap();
        assert!(sm.get_session_by_tag(&tag_at_0).is_some());

        let mut win = RecvWindow::new();
        let decoded =
            decode_packet_with_layout(&packet, &keys, &mut win, mdh_len, u16::MAX).unwrap();
        assert_eq!(decoded.payload, b"legacy-roundtrip");
    }

    /// A WRONG layout on a correctly-identified session must NOT misattribute:
    /// the poly1305 decrypt (or the tag search) rejects and drops the packet.
    #[test]
    fn wrong_offset_decode_is_rejected_no_misattribution() {
        use aivpn_common::client_wire::{
            build_inner_packet, build_random_mdh_packet_with_tag_offset, decode_packet_with_layout,
            RecvWindow,
        };
        use aivpn_common::mask::preset_masks;
        use aivpn_common::protocol::InnerType;

        let mask = preset_masks::webrtc_zoom_v3(); // tag_offset = 8
        let (_sm, _session, keys, mdh_len) = e2e_server_session(&mask);

        let inner = build_inner_packet(InnerType::Data, 0, b"do-not-misattribute");
        let mut counter = 0u64;
        let packet = build_random_mdh_packet_with_tag_offset(
            &keys,
            &mut counter,
            &inner,
            None,
            mdh_len,
            mask.tag_offset,
        )
        .unwrap();

        // (a) Legacy layout reads the tag from offset 0 (the STUN header) — the
        //     resonance-tag search fails outright.
        let mut win1 = RecvWindow::new();
        assert!(
            decode_packet_with_layout(&packet, &keys, &mut win1, mdh_len, u16::MAX).is_err(),
            "legacy-layout decode of an embedded packet must be rejected"
        );

        // (b) Correct tag offset (8) but a WRONG ciphertext boundary (quic's
        //     14-byte MDH): the tag matches counter 0, but poly1305 fails on the
        //     misaligned ciphertext → rejected, never silently accepted.
        let mut win2 = RecvWindow::new();
        assert!(
            decode_packet_with_layout(&packet, &keys, &mut win2, 14, 8).is_err(),
            "wrong ciphertext boundary must be rejected by poly1305"
        );
    }

    // ========================================================================
    // FIX E: cached preset tag offsets (pre-auth CPU amplification)
    // ========================================================================

    /// `Gateway::preset_tag_offsets` must be computed once at construction
    /// and exactly match what a direct `distinct_tag_offsets_of` call over
    /// the live presets would produce — proving the cached field is correct,
    /// not just present.
    #[test]
    fn preset_tag_offsets_cached_at_construction_matches_presets() {
        let config = make_test_gateway_config("presetoffsets");
        let gateway = Gateway::new(config).expect("gateway constructs");
        let expected =
            super::distinct_tag_offsets_of(aivpn_common::mask::preset_masks::all().iter());
        assert_eq!(
            gateway.preset_tag_offsets, expected,
            "cached preset_tag_offsets must match a direct preset scan"
        );
        // With an empty runtime catalog (nothing registered beyond what was
        // loaded from the temp mask dir at construction — this test's mask
        // is a preset, contributing no new offset), distinct_tag_offsets()
        // must equal the cached preset set exactly.
        assert_eq!(gateway.distinct_tag_offsets(), expected);
    }

    /// `distinct_tag_offsets()` must merge the cached preset offsets with
    /// whatever the LIVE runtime catalog currently holds — proving the
    /// cache isn't stale merely because it never re-reads the catalog — while
    /// the cached `preset_tag_offsets` field itself never changes, proving
    /// the expensive `preset_masks::all()` clone genuinely only ran once, at
    /// construction, not on every call.
    #[test]
    fn distinct_tag_offsets_merges_cached_presets_with_live_catalog_without_mutating_cache() {
        let config = make_test_gateway_config("mergeoffsets");
        let gateway = Gateway::new(config).expect("gateway constructs");
        let preset_only = gateway.preset_tag_offsets.clone();

        // Register a runtime mask whose tag_offset is NOT among any preset's.
        let mut custom = webrtc_zoom_v3();
        custom.mask_id = "custom-test-mask".to_string();
        custom.tag_offset = 123;
        assert!(
            !preset_only.contains(&123),
            "test setup: 123 must not already be a preset offset"
        );
        gateway.mask_catalog.register_mask(custom);

        let merged = gateway.distinct_tag_offsets();
        assert!(
            merged.contains(&123),
            "a newly-registered runtime catalog mask's offset must be included"
        );
        for off in &preset_only {
            assert!(
                merged.contains(off),
                "preset offset {off} must survive the merge"
            );
        }
        assert_eq!(
            gateway.preset_tag_offsets, preset_only,
            "the cached preset field itself must be untouched by a catalog change"
        );
    }

    /// Hot-path cheapness check: `candidate_tags` (called twice per inbound
    /// datagram, per FIX E's description — once in `worker_index_for_packet`
    /// before any rate limiting, once in `find_existing_session`) must stay
    /// cheap at high call volume. Before the fix, each call deep-cloned all
    /// 5 preset `MaskProfile`s (64-float `signature_vector`s, boxed FSM
    /// states, header specs, ...).
    ///
    /// Self-calibrating rather than a fixed millisecond budget (flaky across
    /// debug/release and differently-loaded machines/CI runners): it times
    /// the fixed `distinct_tag_offsets()` against a reconstruction of the
    /// exact OLD method body (same `mask_catalog` scan, but re-cloning the
    /// presets every call) and asserts the fixed version is not slower.
    /// Takes the best of several repeated trials per arm to smooth out
    /// scheduler noise from other tests running concurrently in the same
    /// process (the full crate's test suite runs multi-threaded by default).
    #[test]
    fn distinct_tag_offsets_hot_path_is_cheap_at_scale() {
        let config = make_test_gateway_config("perfoffsets");
        let gateway = Gateway::new(config).expect("gateway constructs");

        const N: u32 = 50_000;
        const TRIALS: u32 = 5;

        fn best_of<F: FnMut()>(trials: u32, n: u32, mut f: F) -> Duration {
            let mut best = Duration::MAX;
            for _ in 0..trials {
                let start = std::time::Instant::now();
                for _ in 0..n {
                    f();
                }
                let elapsed = start.elapsed();
                if elapsed < best {
                    best = elapsed;
                }
            }
            best
        }

        // Fixed: reads the cached `preset_tag_offsets` field, then does the
        // same cheap, non-cloning `mask_catalog` scan as before.
        let cached_elapsed = best_of(TRIALS, N, || {
            let _ = gateway.distinct_tag_offsets();
        });

        // Reconstructed OLD method body: a fresh `preset_masks::all()`
        // deep-clone of all 5 preset `MaskProfile`s on every call, followed
        // by the SAME `mask_catalog` scan the fixed version still does (so
        // that part of the cost is identical in both arms and only the
        // preset-cloning difference is being measured).
        let uncached_elapsed = best_of(TRIALS, N, || {
            let mut offsets =
                super::distinct_tag_offsets_of(aivpn_common::mask::preset_masks::all().iter());
            for entry in gateway.mask_catalog.masks.iter() {
                if let Some(off) = entry.value().embedded_tag_offset() {
                    if !offsets.contains(&off) {
                        offsets.push(off);
                    }
                }
            }
            let _ = offsets;
        });

        assert!(
            cached_elapsed <= uncached_elapsed,
            "the fixed distinct_tag_offsets() (best-of-{TRIALS}: {:?}) must \
             not be slower than the reconstructed old per-call \
             preset_masks::all() path (best-of-{TRIALS}: {:?}) — if it is, \
             the cache regressed back to cloning MaskProfiles on every call",
            cached_elapsed,
            uncached_elapsed
        );
    }

    /// Build a bare, unratcheted `Session` wrapped the way the gateway
    /// stores it (`Arc<parking_lot::Mutex<Session>>`), for tests that only
    /// need `client_id` and don't drive the handshake state machine.
    fn make_bare_session(client_id: Option<String>) -> Arc<parking_lot::Mutex<Session>> {
        let keys = aivpn_common::crypto::SessionKeys {
            session_key: [1u8; 32],
            session_key_s2c: [1u8; 32],
            tag_secret: [1u8; 32],
            prng_seed: [1u8; 32],
        };
        let addr: SocketAddr = "203.0.113.9:41000".parse().unwrap();
        let mut s = Session::new([9u8; 16], addr, keys, [0u8; 32]);
        s.client_id = client_id;
        Arc::new(parking_lot::Mutex::new(s))
    }

    /// `Gateway::session_role` (used by both the `Capabilities` push and
    /// the `MgmtRequest` authorization gate) must resolve
    /// `client_id -> client_db.find_by_id -> ClientConfig::role`, and must
    /// default to `ClientRole::User` — never trust anything the client
    /// itself could claim — when the session has no `client_id` at all.
    #[test]
    fn session_role_resolves_from_client_db_and_defaults_to_user_without_client_id() {
        use crate::client_db::{ClientDatabase, ClientRole, UpdateClientParams};
        use std::sync::Arc as StdArc;

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 66, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db =
            StdArc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());
        let client = db.add_client("role-test").unwrap();
        db.enroll_device(&client.id, &[3u8; 32]).unwrap();
        db.update_client(
            &client.id,
            UpdateClientParams {
                role: Some(ClientRole::Admin),
                ..Default::default()
            },
        )
        .unwrap();

        let mut config = make_test_gateway_config("session-role");
        config.client_db = Some(db.clone());
        let gateway = Gateway::new(config).expect("gateway constructs");

        let bound_session = make_bare_session(Some(client.id.clone()));
        assert_eq!(gateway.session_role(&bound_session), ClientRole::Admin);

        let unbound_session = make_bare_session(None);
        assert_eq!(
            gateway.session_role(&unbound_session),
            ClientRole::User,
            "a session with no client_id must default to User, never inherit a stale role"
        );

        let unknown_client_session = make_bare_session(Some("does-not-exist".to_string()));
        assert_eq!(
            gateway.session_role(&unknown_client_session),
            ClientRole::User,
            "a client_id that can no longer be found (e.g. just revoked) must default to User"
        );
    }

    /// `authorize`/`dispatch` are unit-tested exhaustively in
    /// `mgmt_service`; this covers the one piece of glue that lives in
    /// `gateway.rs` — `ClientRole::as_u8` feeding straight into
    /// `mgmt_service::authorize` the way the `MgmtRequest` arm in
    /// `handle_control_message` does.
    #[test]
    fn client_role_as_u8_matches_mgmt_service_authorize_expectations() {
        use crate::client_db::ClientRole;
        use crate::mgmt_service::authorize;

        assert_eq!(ClientRole::User.as_u8(), 0);
        assert_eq!(ClientRole::Viewer.as_u8(), 1);
        assert_eq!(ClientRole::Admin.as_u8(), 2);

        assert!(!authorize(ClientRole::User.as_u8(), 0, "/api/v1/clients"));
        assert!(authorize(ClientRole::Viewer.as_u8(), 0, "/api/v1/clients"));
        assert!(!authorize(ClientRole::Viewer.as_u8(), 1, "/api/v1/clients"));
        assert!(authorize(ClientRole::Admin.as_u8(), 1, "/api/v1/clients"));
    }
}
