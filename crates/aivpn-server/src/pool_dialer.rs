//! FORK-B pool-sync DIALER — the masked pool-client half of pool sync.
//!
//! [`crate::pool_sync::PeerSyncer`] is the legacy mask-INDEPENDENT push-only
//! path: it sends `PoolSync` snapshots over a fixed, non-mask wire layout and
//! never dials anything (peers only exchange data if BOTH sides independently
//! push — no bidirectional session, no shared "we are connected" state).
//!
//! [`PoolDialer`] is the new "server-B" strategy: each node DIALS every peer
//! as a normal, fully masked `AivpnClient` running in headless
//! `control_only` mode (see `aivpn_client::client::ClientConfig::control_only`)
//! using a shared, pool-wide identity:
//!
//! - `preshared_key` = [`aivpn_common::crypto::pool_client_psk`] (same for
//!   every pool node — the trust model is a single-operator trusted pool).
//! - `server_public_key` = the pool-wide static X25519 identity every node
//!   shares, [`aivpn_common::crypto::pool_server_keypair`]`(sync_key)`
//!   `.public_key_bytes()`. Every node derives the SAME keypair from the same
//!   `sync_key`, so "the peer's server public key" is simply this node's own
//!   derived pool keypair's public key — no additional config or key exchange
//!   is required.
//!
//! Because the dialed session is a real, bidirectional, ordinary masked VPN
//! session (indistinguishable on the wire from a real client), asymmetric
//! DPI that blocks one direction of a raw push (the original
//! `PeerSyncer`/`site_sync` problem) cannot block this: whichever side
//! successfully DIALS OUT gets a working bidirectional channel, and the
//! anti-entropy protocol below (digest beacon + snapshot push both ways)
//! converges the client DB regardless of which side initiated the link.
//!
//! ## Anti-entropy protocol over the dialed session
//!
//! Once connected, this task and the peer's gateway (already implemented,
//! see `gateway.rs`'s masked-pool-client handling) exchange three control
//! messages:
//!
//! - `PoolStateDigest { digest }` — a periodic beacon of
//!   `ClientDatabase::state_digest()`, the cheap steady-state "are we in
//!   sync?" root check. Sent by us on a timer.
//! - `PoolBucketDigests { digests, reply_requested }` — Phase 2:
//!   `ClientDatabase::bucket_digests()`, sent in reaction to a root-digest
//!   mismatch (`reply_requested: true`) or in reply to such a message
//!   (`reply_requested: false`). The receiver diffs the enclosed digests
//!   against its own bucket digests and pushes a `PoolSync` containing just
//!   the differing buckets' records. If `reply_requested` was true, the
//!   receiver ALSO sends back its own `bucket_digests()` with
//!   `reply_requested: false`, so the original sender can compute its own
//!   differing buckets and push its delta too.
//! - `PoolSync { clients_json }` — the (tombstone-inclusive) client records
//!   for the differing buckets, merged by the receiver via `merge_from_json`.
//!
//! Both sides run the identical rule (see `gateway.rs`'s masked-pool-client
//! handling), so a single dialed session converges both directions over a
//! bounded number of messages with no ping-pong: on a root mismatch, the
//! rule is `digest -> buckets(reply_requested=true) -> (PoolSync delta +
//! buckets(reply_requested=false)) -> (PoolSync delta) -> silence`. A
//! `PoolBucketDigests` is NEVER answered with another `PoolStateDigest`
//! (that echo caused an earlier storm regression), and
//! `reply_requested: false` is never itself answered with another
//! `PoolBucketDigests` (that would ping-pong forever). No separate "am I
//! the client or the server" coordination is needed — the rule is symmetric
//! and idempotent, and a matching root digest on the next beacon ends the
//! exchange.
//!
//! ## Known follow-up (not fixed here)
//!
//! `AivpnClient::new` unconditionally calls (client.rs)
//! `load_or_generate_static_keypair()`, which reads/writes a single on-disk
//! `~/.config/aivpn/device.key`. Running N concurrent control-only dialers
//! (one per peer) in the same server process means N concurrent accesses to
//! that same file path — benign today (the static keypair value is unused in
//! `control_only` mode: no mTLS cert, no persisted per-device identity is
//! read back), but a real race if that file is ever relied upon for
//! something control-only sessions need. Flagged for a future fix, not
//! addressed here.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use tracing::{debug, info, warn};

use aivpn_client::client::{AivpnClient, ClientConfig};
use aivpn_common::crypto;
use aivpn_common::protocol::ControlPayload;

use crate::client_db::ClientDatabase;
use crate::pool_sync::PoolSyncConfig;

/// Default digest-beacon interval when `pool.sync_beacon_secs` is unset.
const DEFAULT_BEACON_SECS: u64 = 30;

/// Initial reconnect backoff after a dialed session ends.
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
/// Reconnect backoff cap.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// A session alive at least this long resets the backoff to `INITIAL_BACKOFF`
/// on its next disconnect — distinguishes a healthy link that dropped once
/// from a peer that is persistently unreachable.
const BACKOFF_RESET_THRESHOLD: Duration = Duration::from_secs(60);

/// Dials configured pool peers as masked, headless `control_only` VPN
/// clients and runs bidirectional client-DB anti-entropy over each session.
///
/// Additive and gated: only constructed/started when
/// `PoolSyncConfig::transport_is_masked()` is true (see the `main.rs` wiring
/// site). Leaves the legacy [`crate::pool_sync::PeerSyncer`] path completely
/// untouched.
pub struct PoolDialer {
    db: Arc<ClientDatabase>,
    peers: Vec<String>,
    pool_kp: crypto::KeyPair,
    pool_psk: [u8; 32],
    beacon_secs: u64,
    /// This node's own pool `node_id` (`PoolSyncConfig::node_id`), carried in
    /// every outbound `RouteSync` advertisement so the receiving
    /// `site_sync::handle_route_sync` can bind the advertised subnets to
    /// THIS node's `site_to_site.peers[].node_id` entry instead of falling
    /// back to a union of every configured peer's `remote_subnets` (the
    /// route-hijack fixed alongside this field). `None` when
    /// `pool.node_id` is unset — in that case the receiver cannot attribute
    /// the advert to any peer and drops it (fail-closed), matching
    /// `PeerSyncer`'s existing node_id-required behavior.
    node_id: Option<String>,
    /// PHASE 3 (site-to-site over masked transport): local subnets this node
    /// advertises to every dialed peer via `ControlPayload::RouteSync`,
    /// mirroring what `site_sync::SitePeer` advertises over the legacy
    /// mask-independent channel. Empty unless the caller of [`Self::new`]
    /// passes a non-empty list (see the `main.rs` wiring site, which only
    /// does so when `pool.transport == "masked"` AND `site_to_site` is
    /// configured) — additive, and a no-op for plain pool-sync-only setups.
    local_subnets: Vec<String>,
    /// Per-peer live control-channel senders, registered while a masked
    /// dialed session to that peer is up (see `run_one_session`) and removed
    /// the instant the session ends (including across reconnects — a fresh
    /// entry replaces the old one on the next successful dial). Lets other
    /// code push a `ControlPayload` to one connected peer or broadcast to
    /// all of them without reaching into the per-peer dial tasks directly.
    peer_senders:
        Arc<parking_lot::Mutex<HashMap<String, tokio::sync::mpsc::Sender<ControlPayload>>>>,
    /// Wave B1 (pool topology read endpoints): retained per-peer sync
    /// status, updated by `run_one_session` (connect/disconnect) and
    /// `anti_entropy` (convergence/divergence). See [`PeerSyncStatus`] and
    /// [`Self::pool_status_snapshot`].
    pool_status: Arc<parking_lot::Mutex<HashMap<String, PeerSyncStatus>>>,
    /// PHASE 4 (reverse chain-forward): when this node is an entry that
    /// dials an exit node (`main.rs` passes `Some(..)` only when this node
    /// runs the masked pool-client transport AND has `pool.exit_node`
    /// configured), the inner IP payload of any `ChainForward` this dialer
    /// receives FROM a peer — i.e. a reply the exit relayed back for one of
    /// our clients — is handed to this sender (see `anti_entropy`'s inbound
    /// tap). The receiving end is `Gateway::chain_reverse_rx`, drained by
    /// `tun_read_loop` into the normal client-downlink path. `None` on any
    /// node that never dials an exit — the tap then simply drops inbound
    /// `ChainForward` (a peer/plain pool-sync node has no reason to receive
    /// one anyway).
    reverse_downlink_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// PHASE 4 (per-node cryptographic identity, SEND side): this node's own
    /// durable Ed25519 identity keypair. `Some` only when `main.rs` resolved
    /// (loaded from `pool.node_identity_key` or generated) a node-identity
    /// seed for this masked-transport node; `None` reproduces pre-Phase-4
    /// behavior byte-for-byte — no `NodeEnrollment` is ever built or sent,
    /// and a peer's registry (if any) never learns/pins this node's key.
    ///
    /// B2/D2 fix (session-bound proof): the `NodeEnrollment` proof itself is
    /// no longer built or sent HERE. It is signed by `aivpn-client`'s
    /// `AivpnClient` (see `client.rs`'s `ServerHello` handler), the only
    /// place that has this session's ephemeral transcript
    /// (`server_eph_pub`/`client_eph_pub`) needed to bind the proof against
    /// cross-session replay — a captured proof built without that binding
    /// (the pre-fix behavior) could be replayed onto a different peer's
    /// session to steal this node's verified identity. This field is simply
    /// forwarded into the `ClientConfig` (`node_identity`/`pool_node_id`)
    /// passed to `AivpnClient::new` in [`Self::run_one_session`].
    node_identity: Option<ed25519_dalek::SigningKey>,
    /// Wave B2c (runtime dial add-peer): the peer addresses that currently
    /// have (or are about to have) a `dial_loop` task spawned for them — a
    /// SUPERSET of `self.peers` (the startup-configured dial set) once
    /// `add_peer` has added any runtime peer. Populated by
    /// [`Self::spawn_dial_loop`] BEFORE it actually spawns, so it doubles as
    /// the idempotency gate: a repeated `start()`/`add_peer` call for an
    /// address already tracked here is guaranteed to no-op rather than
    /// double-spawn a `dial_loop`. Distinct from `peer_senders` (which only
    /// holds an entry while a session is actually CONNECTED) — an address
    /// stays in this set for the whole process lifetime once dialed, through
    /// every reconnect/backoff cycle, while `peer_senders` only intermittently
    /// contains it.
    dialed_peers: Arc<parking_lot::Mutex<HashSet<String>>>,
    /// Wave B2c: the shutdown flag `start()` was called with, retained so
    /// [`Self::add_peer`] can spawn additional `dial_loop` tasks that share
    /// the EXACT same shutdown signal as the peers dialed at startup — a
    /// runtime-added dial task must stop on the same signal as everything
    /// else, not run forever independent of process shutdown. `None` until
    /// `start()` runs; [`Self::spawn_dial_loop`] treats that as "the dialer
    /// hasn't been started yet" and refuses to spawn (see its doc comment).
    shutdown: Arc<parking_lot::Mutex<Option<Arc<AtomicBool>>>>,
    /// Wave B2c: counts every dial task [`Self::spawn_dial_loop`] actually
    /// spawned (i.e. every time the idempotency gate above let a NEW peer
    /// through). Kept unconditionally (not `cfg(test)`) for simplicity —
    /// the counter itself is cheap (one atomic increment per peer, ever) —
    /// but in practice it exists so tests can assert "`add_peer` didn't
    /// double-spawn" without needing to observe a real live connection.
    spawn_count: Arc<AtomicUsize>,
}

impl PoolDialer {
    /// Returns `None` if `sync_key` is absent, invalid, or all-zero (mirrors
    /// `PeerSyncer::new`'s fail-closed decode) — masked pool-client dialing
    /// stays fully disabled in that case, exactly like the legacy path.
    ///
    /// `local_subnets` are advertised to every dialed peer as `RouteSync`
    /// (PHASE 3 site-to-site-over-masked-transport); pass an empty `Vec` for
    /// plain pool-sync-only setups (site-to-site not configured, or running
    /// under the legacy transport where `site_sync::start` handles it).
    ///
    /// `reverse_downlink_tx` (PHASE 4, reverse chain-forward) should be
    /// `Some(server.chain_reverse_downlink_sender())` when this node is both
    /// running the masked pool-client transport AND has `pool.exit_node`
    /// configured (an entry node that actually dials an exit); `None`
    /// otherwise. See the field's doc comment.
    ///
    /// `node_identity` (PHASE 4, per-node cryptographic identity, SEND side)
    /// should be `Some(signing_key)` — this node's own durable Ed25519
    /// identity, loaded/generated by `main.rs` from `pool.node_identity_key`
    /// — when this node runs the masked pool-client transport; `None` keeps
    /// this node from ever sending a `NodeEnrollment` proof (legacy /
    /// Phase-4-off, byte-for-byte unchanged).
    pub fn new(
        db: Arc<ClientDatabase>,
        config: &PoolSyncConfig,
        local_subnets: Vec<String>,
        reverse_downlink_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
        node_identity: Option<ed25519_dalek::SigningKey>,
    ) -> Option<Arc<Self>> {
        use base64::Engine as _;

        let sync_key: [u8; 32] = config
            .sync_key
            .as_deref()
            .and_then(|k| base64::engine::general_purpose::STANDARD.decode(k).ok())
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 32]);

        if sync_key == [0u8; 32] {
            warn!("pool_dialer: sync_key not configured — masked pool dialer disabled");
            return None;
        }

        let pool_kp = crypto::pool_server_keypair(&sync_key);
        let pool_psk = crypto::pool_client_psk(&sync_key);
        let beacon_secs = config
            .sync_beacon_secs
            .unwrap_or(DEFAULT_BEACON_SECS)
            .max(1);

        // Skip self exactly like `PeerSyncer::new`: a node must never dial
        // its own `node_id` as though it were a distinct peer.
        let node_id = match config
            .node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(id) => id,
            None => {
                warn!(
                    "pool_dialer: pool.node_id not configured — masked pool dialer disabled \
                     (mirrors PeerSyncer::new's fail-closed behavior: without a node_id, self-\
                     filtering cannot skip this node's own address in `peers`, risking a self-\
                     dial reconnect loop, and NodeEnrollment would sign with an empty node_id)"
                );
                return None;
            }
        };
        let node_id = Some(node_id);
        let peers: Vec<String> = config
            .peers
            .iter()
            .filter(|peer| {
                let is_self = node_id.is_some_and(|id| *peer == id);
                if is_self {
                    warn!(
                        "pool_dialer: peer '{}' equals this node's node_id — skipped",
                        peer
                    );
                }
                !is_self
            })
            .cloned()
            .collect();

        Some(Arc::new(Self {
            db,
            peers,
            pool_kp,
            pool_psk,
            beacon_secs,
            node_id: config.node_id.clone(),
            local_subnets,
            peer_senders: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            pool_status: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            reverse_downlink_tx,
            node_identity,
            dialed_peers: Arc::new(parking_lot::Mutex::new(HashSet::new())),
            shutdown: Arc::new(parking_lot::Mutex::new(None)),
            spawn_count: Arc::new(AtomicUsize::new(0)),
        }))
    }

    /// Queue `payload` for delivery to `peer` over its currently-live dialed
    /// session, if any. Returns `true` if a live sender was found and the
    /// payload was successfully queued (`try_send` — never blocks the
    /// caller; a full channel or a peer with no live session both count as
    /// "not delivered"). `false` means `peer` has no connected session right
    /// now (dial loop backing off, peer down, or an unrecognised peer id).
    pub fn send_to_peer(&self, peer: &str, payload: ControlPayload) -> bool {
        let senders = self.peer_senders.lock();
        match senders.get(peer) {
            Some(tx) => tx.try_send(payload).is_ok(),
            None => false,
        }
    }

    /// B2b (per-client exit routing): non-mutating liveness check for
    /// `peer` — `true` iff a live dialed session is currently registered in
    /// `peer_senders`, without attempting to queue anything. Used by
    /// `gateway.rs`'s `choose_exit` decision to pick between a client's
    /// per-client `exit_node` override and the node's global default
    /// BEFORE committing to a `send_to_peer` call, so the decision itself
    /// stays a pure, side-effect-free check. A `true` here does not
    /// guarantee a subsequent `send_to_peer` will succeed (the session can
    /// drop between the two calls) — callers must still handle that
    /// `send_to_peer` returning `false`.
    pub fn has_live_session(&self, peer: &str) -> bool {
        self.peer_senders.lock().contains_key(peer)
    }

    /// Test-only: register a fake live session for `peer` in `peer_senders`,
    /// exactly as `run_one_session` does after a real successful dial — for
    /// tests OUTSIDE this module (e.g. `gateway.rs`'s B2b
    /// `exit_decision_for_session`/`forward_via_exit` integration tests)
    /// that need `has_live_session`/`send_to_peer` to observe `peer` as
    /// live without driving a real socket/session. `pub(crate)` + `cfg(test)`
    /// keeps this out of non-test builds entirely.
    #[cfg(test)]
    pub(crate) fn test_register_live_session(
        &self,
        peer: &str,
    ) -> tokio::sync::mpsc::Receiver<ControlPayload> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        self.peer_senders.lock().insert(peer.to_string(), tx);
        rx
    }

    /// Wave B2c test-only: simulate `start()` having run — sets the
    /// `shutdown` field so `add_peer` will actually spawn a `dial_loop`
    /// task, WITHOUT spawning tasks for the startup-configured `self.peers`
    /// (unlike a real `start()` call, which would try to actually dial
    /// them). Lets `add_peer` idempotency tests exercise the real
    /// `spawn_dial_loop` path (including the real `tokio::spawn` call) for
    /// just the one runtime-added peer under test, without any of this
    /// dialer's OTHER configured peers making real (bound-to-fail) network
    /// attempts in the background for the rest of the test process.
    #[cfg(test)]
    pub(crate) fn test_mark_started(&self, shutdown: Arc<AtomicBool>) {
        *self.shutdown.lock() = Some(shutdown);
    }

    /// Wave B2c test-only: `true` iff `peer` is currently tracked in
    /// `dialed_peers` (i.e. `spawn_dial_loop` successfully claimed it,
    /// whether or not the spawned task has connected yet).
    #[cfg(test)]
    pub(crate) fn is_dialed_peer(&self, peer: &str) -> bool {
        self.dialed_peers.lock().contains(peer)
    }

    /// Wave B2c test-only: how many `dial_loop` tasks this dialer has
    /// actually spawned in total (startup `start()` peers + any `add_peer`
    /// runtime additions) — the idempotency proxy `add_peer` tests assert
    /// on to confirm a repeated call never double-spawns.
    #[cfg(test)]
    pub(crate) fn spawn_count(&self) -> usize {
        self.spawn_count.load(Ordering::Relaxed)
    }

    /// Queue `payload` for delivery to every currently-connected peer.
    /// Returns the number of peers it was successfully queued for.
    pub fn broadcast(&self, payload: ControlPayload) -> usize {
        let senders = self.peer_senders.lock();
        senders
            .values()
            .filter(|tx| tx.try_send(payload.clone()).is_ok())
            .count()
    }

    /// Wave B1 (pool topology read endpoints): snapshot of every peer's
    /// retained sync status. Includes peers that were once connected but
    /// currently aren't — `PeerSyncStatus::connected` on the entry reflects
    /// the LIVE state as of the last update, not just "ever seen".
    pub fn pool_status_snapshot(&self) -> Vec<(String, PeerSyncStatus)> {
        self.pool_status
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// This node's configured masked-transport dial set: self-filtered
    /// (see [`Self::new`]) and, when `main.rs` wired an exit node, including
    /// `pool.exit_node`. Used by the Phase B pool topology read endpoints as
    /// the "configured membership" input to `mgmt_service::build_pool_snapshot`.
    pub fn peers(&self) -> &[String] {
        &self.peers
    }

    /// Peers with a currently-live dialed session (the keys of
    /// `peer_senders`, at the moment of the call).
    pub fn connected_peers(&self) -> Vec<String> {
        self.peer_senders.lock().keys().cloned().collect()
    }

    /// Spawn one reconnecting dialer task per configured peer.
    pub fn start(self: Arc<Self>, shutdown: Arc<AtomicBool>) {
        // Retained so `add_peer` (Wave B2c) can spawn additional dial tasks
        // sharing this exact shutdown signal, and so `spawn_dial_loop` can
        // tell "not started yet" apart from "started" (see both fields'
        // doc comments).
        *self.shutdown.lock() = Some(shutdown);

        info!(
            "pool_dialer: active ({} peers, masked pool-client transport)",
            self.peers.len()
        );
        for peer in self.peers.clone() {
            self.spawn_dial_loop(peer);
        }
    }

    /// Shared per-peer spawn logic used by BOTH `start()` (the startup-
    /// configured dial set) and [`Self::add_peer`] (Wave B2c runtime
    /// additions) — factored out so the two call sites can never drift on
    /// how a dial task is constructed.
    ///
    /// Idempotent: returns `false` without spawning anything if `peer`
    /// already has a task tracked in `dialed_peers` (a duplicate `start()`
    /// peer, or a repeated `add_peer` call for the same address), or if
    /// `start()` has not run yet (no shutdown flag exists to hand the new
    /// task, so — rather than spawn a task with no way to ever be told to
    /// stop — this rolls back the `dialed_peers` insert and no-ops, letting
    /// a legitimate later `start()`/`add_peer` call spawn it for real).
    fn spawn_dial_loop(self: &Arc<Self>, peer: String) -> bool {
        {
            let mut dialed = self.dialed_peers.lock();
            if !dialed.insert(peer.clone()) {
                debug!(
                    "pool_dialer: spawn_dial_loop({}) — already dialing, no-op",
                    peer
                );
                return false;
            }
        }

        let shutdown = match self.shutdown.lock().clone() {
            Some(s) => s,
            None => {
                self.dialed_peers.lock().remove(&peer);
                warn!(
                    "pool_dialer: spawn_dial_loop({}) called before start() — dropped",
                    peer
                );
                return false;
            }
        };

        self.spawn_count.fetch_add(1, Ordering::Relaxed);
        let me = self.clone();
        tokio::spawn(async move {
            me.dial_loop(peer, shutdown).await;
        });
        true
    }

    /// Wave B2c (runtime dial add-peer): idempotently ensure `addr` has a
    /// live `dial_loop` task, so a per-client `exit_node` set to an address
    /// this node was NOT already dialing at startup goes live WITHOUT a
    /// server restart. Called from `gateway.rs` after any mgmt mutation
    /// that may have set/changed a client's `exit_node`, and after a
    /// successful pool-sync `merge_from_json` (a peer node's admin can also
    /// introduce a new exit_node, which then needs dialing here too).
    ///
    /// A no-op when:
    /// - `addr` (after trimming) is empty;
    /// - `addr` equals this node's own configured `node_id` — never
    ///   self-dial, mirrors [`Self::new`]'s startup self-filter;
    /// - `addr` already has a dial task tracked — startup-configured OR a
    ///   previous `add_peer` call (see [`Self::spawn_dial_loop`]'s
    ///   idempotency gate);
    /// - the dialer has not been [`Self::start`]ed yet.
    ///
    /// Scope note (Wave B2c): this only ADDS dial sessions. Teardown of an
    /// unused runtime-added session (e.g. after an admin later clears that
    /// client's `exit_node` and no other client references it) is
    /// intentionally NOT implemented here — an idling unused dial session
    /// is acceptable for this wave; pruning it is a future optimization.
    /// Making the global default (`masked_exit_addr`) itself hot-swappable
    /// is a separate follow-up, also out of scope here.
    pub fn add_peer(self: &Arc<Self>, addr: impl Into<String>) {
        let addr = addr.into();
        let addr = addr.trim();
        if addr.is_empty() {
            return;
        }
        if self.node_id.as_deref().is_some_and(|id| id == addr) {
            debug!(
                "pool_dialer: add_peer({}) ignored — this node's own node_id",
                addr
            );
            return;
        }
        if self.spawn_dial_loop(addr.to_string()) {
            info!(
                "pool_dialer: runtime add_peer — now dialing new peer {} (live without restart)",
                addr
            );
        }
    }

    /// Wave B2c: every peer address currently tracked in `dialed_peers` —
    /// the startup-configured dial set PLUS any peer `add_peer` has added
    /// at runtime. Used by `gateway.rs`'s post-mutation hook to compute
    /// which of a scanned client DB's `exit_node` addresses are actually
    /// new (see `exits_needing_dial`), so a redundant `add_peer` call isn't
    /// even attempted for an address already being dialed.
    pub fn dialed_peer_addrs(&self) -> Vec<String> {
        self.dialed_peers.lock().iter().cloned().collect()
    }

    /// Reconnect loop for a single peer: dial, run anti-entropy until the
    /// session ends, back off, repeat — until `shutdown` is set.
    async fn dial_loop(self: Arc<Self>, peer: String, shutdown: Arc<AtomicBool>) {
        let mut backoff = INITIAL_BACKOFF;

        while !shutdown.load(Ordering::Relaxed) {
            let started = std::time::Instant::now();
            info!("pool_dialer: connecting to peer {}", peer);

            match self.run_one_session(&peer, shutdown.clone()).await {
                Ok(()) => {
                    debug!("pool_dialer: session with {} ended cleanly", peer);
                }
                Err(e) => {
                    warn!("pool_dialer: session with {} ended: {}", peer, e);
                }
            }

            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // A long-lived session indicates a healthy link — reset backoff
            // so a single transient drop doesn't leave us waiting up to
            // MAX_BACKOFF before retrying a peer that is actually fine.
            if started.elapsed() >= BACKOFF_RESET_THRESHOLD {
                backoff = INITIAL_BACKOFF;
            }

            debug!("pool_dialer: reconnecting to {} in {:?}", peer, backoff);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Dial `peer` once, then drive the anti-entropy loop until the
    /// underlying `AivpnClient` session ends (peer disconnect, handshake
    /// failure, etc.) or `shutdown` is set.
    async fn run_one_session(
        &self,
        peer: &str,
        shutdown: Arc<AtomicBool>,
    ) -> aivpn_common::error::Result<()> {
        let (tap_tx, tap_rx) = tokio::sync::mpsc::channel::<ControlPayload>(64);

        // Any preset mask works: the peer's gateway scans ALL built-in
        // presets when recognizing a masked pool-client handshake candidate
        // (see gateway.rs's `pool_server_keypair`/`pool_client_psk` branch),
        // so there is no coordination requirement on which one we pick here.
        let initial_mask = aivpn_common::mask::preset_masks::all()
            .into_iter()
            .next()
            .expect("preset_masks::all() is never empty");
        let recv_mdh_len = mask_mdh_len(&initial_mask);

        let cfg = ClientConfig {
            server_addr: peer.to_string(),
            server_public_key: self.pool_kp.public_key_bytes(),
            server_signing_key: None,
            preshared_key: Some(self.pool_psk),
            initial_mask,
            tun_config: control_only_tun_config(recv_mdh_len),
            proxy_listen: None,
            mtls_cert: None,
            initial_adaptive_level: aivpn_common::quality::AdaptiveLevel::Off,
            polymorphic_base: None,
            share_mask_feedback: false,
            receive_mask_hints: false,
            country_code: None,
            mask_operator_pubkey: None,
            mask_verify_mode: aivpn_common::mask::MaskVerifyMode::Off,
            network_change_notify: None,
            is_bootstrap_fallback: false,
            control_only: true,
            inbound_control_tap: Some(tap_tx),
            // B2/D2 fix (session-bound proof): `AivpnClient` itself signs and
            // sends the `NodeEnrollment` proof — right after its PFS ratchet
            // completes, where the session's ephemeral transcript
            // (server_eph_pub/client_eph_pub) is actually available — rather
            // than this dialer building one blind to that transcript. `None`
            // for `node_identity` reproduces the pre-Phase-4 no-op exactly.
            node_identity: self.node_identity.clone(),
            pool_node_id: self.node_id.clone(),
        };

        let mut client = AivpnClient::new(cfg)
            .map_err(|e| aivpn_common::error::Error::Session(format!("pool_dialer: {}", e)))?;
        let ctrl = client.control_handle();

        // Registry: make this peer's control sender reachable via
        // `send_to_peer`/`broadcast` for the lifetime of this session.
        self.peer_senders
            .lock()
            .insert(peer.to_string(), ctrl.clone());

        // Wave B1 (pool topology read endpoints): record this connect so
        // `pool_status_snapshot` reflects a live session immediately, even
        // before the first anti-entropy beacon/convergence signal arrives.
        {
            let now = Utc::now().timestamp();
            let mut status = self.pool_status.lock();
            let entry = status
                .entry(peer.to_string())
                .or_insert_with(|| PeerSyncStatus {
                    connected: false,
                    last_converged_unix: None,
                    converged: false,
                    last_seen_unix: None,
                    partition_conflict: false,
                    subnet_mismatch: false,
                });
            entry.connected = true;
            entry.last_seen_unix = Some(now);
        }

        // PHASE 3: advertise our local subnets to this peer immediately on
        // connect (in addition to the periodic re-advertise folded into
        // `anti_entropy`'s beacon tick below) so a freshly (re)connected
        // link doesn't wait a full beacon interval before the peer learns
        // our routes. No-op when `local_subnets` is empty (plain pool-sync,
        // no site-to-site configured).
        if !self.local_subnets.is_empty() {
            match masked_route_sync_payload(&self.node_id, &self.local_subnets) {
                Ok(subnets_json) => {
                    if ctrl
                        .send(ControlPayload::RouteSync { subnets_json })
                        .await
                        .is_err()
                    {
                        warn!(
                            "pool_dialer: failed to send initial RouteSync advert to {}",
                            peer
                        );
                    }
                }
                Err(e) => warn!(
                    "pool_dialer: failed to serialize local_subnets for {}: {}",
                    peer, e
                ),
            }
        }

        // B2/D2 fix (session-bound proof): the `NodeEnrollment` proof (both
        // the initial send and the periodic resend) is now built and sent by
        // `AivpnClient` itself — see `client.rs`'s `ServerHello` handler —
        // using the `node_identity`/`pool_node_id` just threaded through
        // `cfg` above. This dialer no longer builds or sends one directly.

        let db = self.db.clone();
        let beacon_secs = self.beacon_secs;
        let peer_label = peer.to_string();
        let local_subnets = self.local_subnets.clone();
        let node_id = self.node_id.clone();
        let reverse_downlink_tx = self.reverse_downlink_tx.clone();
        let pool_status = self.pool_status.clone();
        let driver = tokio::spawn(async move {
            anti_entropy(
                ctrl,
                tap_rx,
                db,
                beacon_secs,
                peer_label,
                local_subnets,
                node_id,
                reverse_downlink_tx,
                pool_status,
            )
            .await;
        });

        let run_result = client.run(shutdown).await;
        driver.abort();

        // Registry cleanup: this peer no longer has a live session. A
        // reconnect (via `dial_loop`) inserts a fresh entry the next time
        // `run_one_session` succeeds, so this never leaves a stale sender
        // behind for `send_to_peer`/`broadcast` to find.
        self.peer_senders.lock().remove(peer);

        // Wave B1: mirror the disconnect into the retained status too —
        // `converged`/`last_converged_unix` are left untouched (they record
        // the last time convergence WAS observed, which stays meaningful
        // across a disconnect/reconnect).
        if let Some(entry) = self.pool_status.lock().get_mut(peer) {
            entry.connected = false;
        }

        run_result
    }
}

/// Wave B1 (pool topology read endpoints): live per-peer sync status,
/// retained across anti-entropy rounds so `mgmt_service::build_pool_snapshot`
/// can report it over the curated mgmt path (`GET /api/v1/pool/*`). Unlike
/// `PoolDialer::peer_senders` (a live map that only ever reflects "is a
/// session up right now") this is a small, `Clone`-able, `Serialize`-able
/// summary retained for the endpoints — cleared/refreshed as
/// `run_one_session`/`anti_entropy` observe connect/disconnect/convergence
/// events, never read back into any protocol decision.
#[derive(Debug, Clone, Serialize)]
pub struct PeerSyncStatus {
    /// A masked dialed session to this peer is up right now (mirrors
    /// `peer_senders`'s membership at the moment this was last updated).
    pub connected: bool,
    /// Unix seconds of the most recent observed convergence (root or
    /// bucket digest match) with this peer. `None` if never observed.
    pub last_converged_unix: Option<i64>,
    /// Whether the last anti-entropy signal from this peer indicated
    /// convergence (root/bucket digests matched) as opposed to a mismatch
    /// that triggered (or is still resolving) a bucket-diff/`PoolSync`
    /// exchange.
    pub converged: bool,
    /// Unix seconds of the most recent activity (connect or any
    /// convergence/divergence signal) observed for this peer.
    pub last_seen_unix: Option<i64>,
    /// Wave B-IP.2: true iff the most recent `ControlPayload::PartitionAnnounce`
    /// exchange with this peer resolved to `PartitionCheck::IndexConflict` —
    /// both nodes claim the same VPN-IP partition index on the same subnet.
    pub partition_conflict: bool,
    /// Wave B-IP.2: true iff the most recent `ControlPayload::PartitionAnnounce`
    /// exchange with this peer resolved to `PartitionCheck::SubnetMismatch` —
    /// this peer is configured with a different VPN subnet than ours.
    pub subnet_mismatch: bool,
}

/// Mark `peer` as converged as of `now` (unix seconds) — called from
/// `anti_entropy` whenever a `PoolStateDigest`/`PoolBucketDigests` exchange
/// shows agreement with `peer`. Creates a fresh entry (optimistically
/// `connected: true`, since only a live session can receive this signal) if
/// none existed yet.
fn mark_converged(
    pool_status: &parking_lot::Mutex<HashMap<String, PeerSyncStatus>>,
    peer: &str,
    now: i64,
) {
    let mut status = pool_status.lock();
    let entry = status
        .entry(peer.to_string())
        .or_insert_with(|| PeerSyncStatus {
            connected: true,
            last_converged_unix: None,
            converged: false,
            last_seen_unix: None,
            partition_conflict: false,
            subnet_mismatch: false,
        });
    entry.converged = true;
    entry.last_converged_unix = Some(now);
    entry.last_seen_unix = Some(now);
}

/// Mark `peer` as currently diverged as of `now` (unix seconds) — called
/// from `anti_entropy` whenever a digest mismatch is observed. Leaves
/// `last_converged_unix` untouched (it records the last time convergence
/// WAS observed, not "now").
fn mark_diverged(
    pool_status: &parking_lot::Mutex<HashMap<String, PeerSyncStatus>>,
    peer: &str,
    now: i64,
) {
    let mut status = pool_status.lock();
    let entry = status
        .entry(peer.to_string())
        .or_insert_with(|| PeerSyncStatus {
            connected: true,
            last_converged_unix: None,
            converged: false,
            last_seen_unix: None,
            partition_conflict: false,
            subnet_mismatch: false,
        });
    entry.converged = false;
    entry.last_seen_unix = Some(now);
}

/// Wave B-IP.2: record `check` (from a `ControlPayload::PartitionAnnounce`
/// exchange with `peer`) onto that peer's `PeerSyncStatus`, so
/// `GET /api/v1/pool/health`/`links` can badge a partition-index collision
/// or subnet mismatch. Overwrites unconditionally — the flags always reflect
/// the MOST RECENT check, not a sticky "ever seen" latch, so a resolved
/// misconfiguration clears itself on the next converged announce.
fn mark_partition_check(
    pool_status: &parking_lot::Mutex<HashMap<String, PeerSyncStatus>>,
    peer: &str,
    check: crate::pool_partition::PartitionCheck,
) {
    use crate::pool_partition::PartitionCheck;
    let mut status = pool_status.lock();
    let entry = status
        .entry(peer.to_string())
        .or_insert_with(|| PeerSyncStatus {
            connected: true,
            last_converged_unix: None,
            converged: false,
            last_seen_unix: None,
            partition_conflict: false,
            subnet_mismatch: false,
        });
    entry.partition_conflict = matches!(check, PartitionCheck::IndexConflict { .. });
    entry.subnet_mismatch = matches!(check, PartitionCheck::SubnetMismatch);
}

/// A peer that has gone this many beacon intervals without its root digest
/// matching ours gets one `warn!` (see `anti_entropy`'s `warned_stale`
/// latch) — visibility for an anti-entropy link that keeps exchanging
/// buckets/records every round but never actually converges (e.g. a bug in
/// the delta logic, or two nodes stuck disagreeing on the same field).
const STALE_WARN_BEACONS: u32 = 5;

/// Drives the bidirectional anti-entropy protocol over one dialed session:
/// periodically beacons our root digest, and reacts to whatever the peer
/// sends back through `tap_rx` (forwarded there by
/// `ClientConfig::inbound_control_tap`).
///
/// Phase 2: the root `PoolStateDigest` beacon is unchanged (cheap steady-
/// state "are we in sync?" check), but a mismatch no longer triggers a
/// full-DB `PoolSync` push — it triggers a `PoolBucketDigests` exchange
/// first, so only the actually-differing buckets' records travel. See the
/// module doc comment for the full symmetric-rule trace.
///
/// Also tracks un-reconciled visibility: if `peer` goes `STALE_WARN_BEACONS`
/// beacon intervals without converging, log one `warn!` (latched — reset the
/// moment convergence is observed, so this can never spam). The reset fires
/// on two signals: an inbound `PoolStateDigest` equal to ours (the
/// PoolStateDigest receive arm below), and — the actually reachable path on
/// this dialer side, since the peer's gateway never sends a
/// `PoolStateDigest` back by design — an inbound `PoolBucketDigests` whose
/// diff against our own buckets is empty (the PoolBucketDigests receive arm
/// below). Without the latter, a perfectly converged session would still
/// warn after `STALE_WARN_BEACONS` beacons on every run, since the former
/// path is structurally unreachable from this side.
#[allow(clippy::too_many_arguments)]
async fn anti_entropy(
    ctrl: tokio::sync::mpsc::Sender<ControlPayload>,
    mut tap_rx: tokio::sync::mpsc::Receiver<ControlPayload>,
    db: Arc<ClientDatabase>,
    beacon_secs: u64,
    peer: String,
    local_subnets: Vec<String>,
    node_id: Option<String>,
    reverse_downlink_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    pool_status: Arc<parking_lot::Mutex<HashMap<String, PeerSyncStatus>>>,
) {
    let mut beacon = tokio::time::interval(Duration::from_secs(beacon_secs));
    // The first tick fires immediately; that's desirable here — beacon as
    // soon as the session is up rather than waiting a full interval.

    // Un-reconciled visibility: start "converged" optimistically (a fresh
    // session hasn't had a chance to diverge yet) so the very first beacon
    // round never spuriously warns.
    let mut last_converged = std::time::Instant::now();
    let mut warned_stale = false;
    // Wave B-IP.2: dedupe the partition-conflict/subnet-mismatch log to one
    // line per state TRANSITION (mirrors `warned_stale`'s latch) instead of
    // re-logging on every beacon interval.
    let mut last_partition_check: Option<crate::pool_partition::PartitionCheck> = None;

    loop {
        tokio::select! {
            _ = beacon.tick() => {
                let digest = db.state_digest();
                if ctrl.send(ControlPayload::PoolStateDigest { digest }).await.is_err() {
                    // Session gone — the outer dial_loop will reconnect.
                    break;
                }

                // PHASE 3: fold the periodic RouteSync re-advertise into the
                // same tick as the pool digest beacon (control-plane traffic,
                // no need for a separate timer) — mirrors `site_sync`'s
                // periodic advert, just carried over the masked session
                // instead of the legacy fixed-framing channel. No-op when
                // `local_subnets` is empty.
                if !local_subnets.is_empty() {
                    match masked_route_sync_payload(&node_id, &local_subnets) {
                        Ok(subnets_json) => {
                            if ctrl
                                .send(ControlPayload::RouteSync { subnets_json })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => warn!(
                            "pool_dialer: failed to serialize local_subnets for {}: {}",
                            peer, e
                        ),
                    }
                }

                // B2/D2 fix (session-bound proof): the periodic NodeEnrollment
                // resend now lives in `aivpn-client`'s `AivpnClient` (see
                // `client.rs`'s `ServerHello` handler) — only it has this
                // session's ephemeral transcript needed to bind the proof
                // against cross-session replay. This dialer no longer builds
                // or resends one here.

                // Wave B-IP.2: announce our VPN-IP partition assignment on
                // the same cadence as the state-digest beacon — this dialer
                // (unlike `NodeEnrollment` above) has `db` directly, so no
                // session-transcript binding or extra plumbing through
                // `aivpn-client`'s `ClientConfig` is needed; it's a plain
                // operator-visibility payload, not a security proof. Sent
                // on every beacon (self-healing, like `PoolStateDigest`)
                // rather than once, so a late-configured/late-repartitioned
                // peer's mismatch is picked up without a reconnect.
                let local_cidr = db.network_config().cidr_string();
                let local_partition = db.partition_info().unwrap_or(crate::client_db::PartitionInfo {
                    partition_index: 0,
                    partition_size: 0,
                    num_partitions: 1,
                    explicit: false,
                });
                if ctrl
                    .send(ControlPayload::PartitionAnnounce {
                        subnet_cidr: local_cidr,
                        partition_index: local_partition.partition_index,
                        partition_size: local_partition.partition_size,
                        num_partitions: local_partition.num_partitions,
                        explicit: local_partition.explicit,
                    })
                    .await
                    .is_err()
                {
                    break;
                }

                let stale_for = last_converged.elapsed();
                let stale_threshold = Duration::from_secs(beacon_secs) * STALE_WARN_BEACONS;
                if !warned_stale && stale_for >= stale_threshold {
                    warn!(
                        "pool_dialer: peer {} has not reconciled in {:?} (>= {} beacon intervals) — \
                         anti-entropy is exchanging data but the DB state never converges",
                        peer, stale_for, STALE_WARN_BEACONS
                    );
                    warned_stale = true;
                }
            }
            msg = tap_rx.recv() => {
                match msg {
                    Some(ControlPayload::PoolStateDigest { digest }) => {
                        let local = db.state_digest();
                        if digest == local {
                            // Converged — reset the stale-visibility latch.
                            last_converged = std::time::Instant::now();
                            warned_stale = false;
                            mark_converged(&pool_status, &peer, Utc::now().timestamp());
                        } else {
                            mark_diverged(&pool_status, &peer, Utc::now().timestamp());
                            // Phase 2: send our bucketed digest (not the
                            // whole DB) so the peer can work out exactly
                            // which buckets differ and push us the delta.
                            // `reply_requested: true` asks the peer to hand
                            // its own bucket_digests() back to us in turn
                            // (see the PoolBucketDigests arm below) so this
                            // one session reconciles BOTH directions. We
                            // deliberately do NOT also echo a PoolStateDigest
                            // here — that used to cause an unbounded
                            // digest/bucket ping-pong.
                            if ctrl
                                .send(ControlPayload::PoolBucketDigests {
                                    digests: db.bucket_digests(),
                                    reply_requested: true,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Some(ControlPayload::PoolBucketDigests {
                        digests: peer_buckets,
                        reply_requested,
                    }) => {
                        let local_buckets = db.bucket_digests();
                        let differing = crate::client_db::differing_pool_buckets(
                            &local_buckets,
                            &peer_buckets,
                        );
                        if !differing.is_empty() {
                            mark_diverged(&pool_status, &peer, Utc::now().timestamp());
                            let clients_json =
                                db.clients_json_for_buckets(&differing).into_bytes();
                            if ctrl
                                .send(ControlPayload::PoolSync { clients_json })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else {
                            // Our buckets already match the peer's — this IS
                            // the reachable convergence signal on the dialer
                            // side (see BUG A1 above `anti_entropy`'s
                            // doc comment): the peer never sends a
                            // `PoolStateDigest` back (by design, to avoid a
                            // digest/bucket ping-pong), so the
                            // `PoolStateDigest` receive arm's reset is
                            // structurally unreachable here. An empty diff on
                            // a `PoolBucketDigests` exchange — sent either
                            // proactively by the peer on ITS OWN beacon
                            // mismatch, or as its `reply_requested: false`
                            // reply to ours — is the genuine "we agree"
                            // signal, so reset the stale-visibility latch on
                            // it too.
                            last_converged = std::time::Instant::now();
                            warned_stale = false;
                            mark_converged(&pool_status, &peer, Utc::now().timestamp());
                        }
                        if reply_requested {
                            // Hand our own buckets back so the peer can
                            // compute ITS differing buckets and push its
                            // delta to us — completing the reverse
                            // direction. `reply_requested: false` here
                            // guarantees this never triggers another round.
                            if ctrl
                                .send(ControlPayload::PoolBucketDigests {
                                    digests: local_buckets,
                                    reply_requested: false,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Some(ControlPayload::PoolSync { clients_json }) => {
                        match String::from_utf8(clients_json) {
                            Ok(s) => {
                                if let Err(e) = db.merge_from_json(&s) {
                                    warn!("pool_dialer: merge_from_json failed: {}", e);
                                }
                            }
                            Err(e) => warn!("pool_dialer: PoolSync payload not UTF-8: {}", e),
                        }
                    }
                    Some(ControlPayload::RouteSync { subnets_json }) => {
                        // PHASE 3: the peer advertised its subnets over this
                        // same masked session. Feed it through the shared
                        // `site_sync::handle_route_sync` entry point — the
                        // exact function the legacy site-to-site channel and
                        // the gateway's masked-pool-peer arm both call — so
                        // this dialer side installs the peer's routes too.
                        // One dialed session reconciles routes bidirectionally,
                        // just like it does for the client DB above.
                        // PHASE 4: this dialer-side inbound tap does not
                        // (yet) carry a verified NodeEnrollment identity for
                        // the peer being dialed, so it passes `None` here —
                        // out of scope for this change (task instructions
                        // restrict edits to site_sync.rs/gateway.rs/main.rs/
                        // server.rs); this is the minimal signature-only fix
                        // required to keep this call site compiling after
                        // `handle_route_sync` gained the parameter.
                        crate::site_sync::handle_route_sync(&subnets_json, &peer, None);
                    }
                    Some(ControlPayload::ChainForward { payload }) => {
                        // PHASE 4 (reverse chain-forward): the exit node
                        // we're dialing sent back a reply for one of our
                        // clients over this same masked session (see the
                        // exit-side `chain_reverse_routes` table in
                        // `gateway.rs`). Hand it to the entry gateway's
                        // client-downlink path — never processed here
                        // directly, since this dialer has no session state
                        // of its own. `try_send` never blocks the
                        // anti-entropy loop; a full channel or no configured
                        // sender both just drop the reply (best-effort,
                        // matching every other control-plane relay in this
                        // module).
                        if let Some(tx) = &reverse_downlink_tx {
                            let _ = tx.try_send(payload);
                        }
                    }
                    Some(ControlPayload::PartitionAnnounce {
                        subnet_cidr: peer_cidr,
                        partition_index: peer_index,
                        partition_size: _peer_partition_size,
                        num_partitions: _peer_num_partitions,
                        explicit: peer_explicit,
                    }) => {
                        // Wave B-IP.2: this is the gateway's reply to the
                        // announce we just sent on this same beacon tick
                        // (see the `PartitionAnnounce` reply in
                        // `gateway.rs`'s `handle_control_message`) — run the
                        // identical check from our side so a conflict is
                        // visible regardless of which side happens to log
                        // first.
                        let local_cidr = db.network_config().cidr_string();
                        let local_partition =
                            db.partition_info().map(|p| (p.partition_index, p.explicit));
                        let check = crate::pool_partition::check_partition(
                            &local_cidr,
                            local_partition,
                            &peer_cidr,
                            Some((peer_index, peer_explicit)),
                        );
                        if last_partition_check != Some(check) {
                            crate::pool_partition::log_partition_check(
                                check, &peer, &local_cidr, &peer_cidr,
                            );
                            last_partition_check = Some(check);
                        }
                        mark_partition_check(&pool_status, &peer, check);
                    }
                    Some(_) => {
                        // Any other future control variant — not our concern here.
                    }
                    None => {
                        // Channel closed: the client session ended.
                        break;
                    }
                }
            }
        }
    }
}

/// Minimal placeholder `TunnelConfig` for a `control_only` session — no TUN
/// device is ever created in this mode (`AivpnClient::connect` skips it), so
/// none of these values are used for real routing. `mdh_len` is still wired
/// through correctly since it feeds `recv_mdh_candidates` initialisation.
fn control_only_tun_config(mdh_len: u16) -> aivpn_client::tunnel::TunnelConfig {
    aivpn_client::tunnel::TunnelConfig {
        mdh_len,
        ..Default::default()
    }
}

/// Build the masked-transport `RouteSync` payload: a JSON OBJECT
/// `{"node_id": <self node_id or "">, "subnets": [<local_subnets>]}`.
///
/// This is deliberately NOT a bare array like the legacy
/// `site_sync::SitePeer::send_advert` payload: a dialed masked pool-client
/// session's source socket is an ephemeral dialer port, so it can never be
/// attributed to a configured `site_to_site.peers[].endpoint` by IP the way
/// the legacy channel is. Carrying `node_id` in the payload itself lets
/// `site_sync::handle_route_sync`'s MASKED PATH bind the advertised subnets
/// to exactly the one `site_to_site.peers[]` entry whose `node_id` matches —
/// and FAIL-CLOSED (drop the whole message) when none does — instead of the
/// prior union-of-all-peers fallback that let any masked pool-peer advertise
/// any other peer's subnets (the route-hijack this format change fixes).
///
/// An absent `node_id` (i.e. `pool.node_id` unset) serializes as `""`, which
/// `handle_route_sync` treats as unattributable and drops — matching
/// `PeerSyncer`'s existing "pool sync disabled without node_id" behavior.
fn masked_route_sync_payload(
    node_id: &Option<String>,
    local_subnets: &[String],
) -> serde_json::Result<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct MaskedRouteSync<'a> {
        node_id: &'a str,
        subnets: &'a [String],
    }
    serde_json::to_vec(&MaskedRouteSync {
        node_id: node_id.as_deref().unwrap_or(""),
        subnets: local_subnets,
    })
}

/// Mirrors the private `packet_mdh_len_for_mask` helper in
/// `aivpn-client::client` (not exported): the MDH byte length for a mask
/// with an explicit `header_spec`, falling back to `header_template.len()`.
fn mask_mdh_len(mask: &aivpn_common::mask::MaskProfile) -> u16 {
    let len = mask
        .header_spec
        .as_ref()
        .map(|spec| spec.min_length())
        .unwrap_or_else(|| mask.header_template.len());
    len as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::network_config::VpnNetworkConfig;
    use base64::Engine as _;
    use std::net::Ipv4Addr;

    fn test_network_config() -> VpnNetworkConfig {
        VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 88, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            keepalive_secs: None,
            ..Default::default()
        }
    }

    fn test_db() -> Arc<ClientDatabase> {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        // Leak the tempdir so the ClientDatabase's backing file stays valid
        // for the duration of the test — fine for a short-lived unit test.
        std::mem::forget(dir);
        Arc::new(ClientDatabase::load(&db_path, test_network_config()).unwrap())
    }

    fn base_pool_config() -> PoolSyncConfig {
        PoolSyncConfig {
            peers: vec!["peer-a:443".to_string()],
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
        }
    }

    #[test]
    fn new_is_some_when_sync_key_present() {
        let cfg = base_pool_config();
        assert!(PoolDialer::new(test_db(), &cfg, vec![], None, None).is_some());
    }

    #[test]
    fn new_is_none_when_sync_key_absent() {
        let mut cfg = base_pool_config();
        cfg.sync_key = None;
        assert!(PoolDialer::new(test_db(), &cfg, vec![], None, None).is_none());
    }

    #[test]
    fn new_is_none_when_sync_key_zero() {
        let mut cfg = base_pool_config();
        cfg.sync_key = Some(base64::engine::general_purpose::STANDARD.encode([0u8; 32]));
        assert!(PoolDialer::new(test_db(), &cfg, vec![], None, None).is_none());
    }

    /// BUG E2 fix: without a `node_id`, self-filtering
    /// (`node_id.is_some_and(|id| *peer == id)`) never skips this node's own
    /// address in `peers`, risking a self-dial reconnect loop, and the
    /// `NodeEnrollment` `AivpnClient` builds from `ClientConfig::pool_node_id`
    /// would sign with an empty `node_id`. Must fail closed exactly like
    /// `PeerSyncer::new`.
    #[test]
    fn new_is_none_when_node_id_absent() {
        let mut cfg = base_pool_config();
        cfg.node_id = None;
        assert!(
            PoolDialer::new(test_db(), &cfg, vec![], None, None).is_none(),
            "masked pool dialer must be disabled without a configured node_id"
        );
    }

    /// Same fail-closed behavior for a `node_id` that is present but empty
    /// (or all whitespace) after trimming — mirrors `PeerSyncer::new`'s
    /// `.filter(|s| !s.is_empty())` check.
    #[test]
    fn new_is_none_when_node_id_empty_after_trim() {
        let mut cfg = base_pool_config();
        cfg.node_id = Some("   ".to_string());
        assert!(
            PoolDialer::new(test_db(), &cfg, vec![], None, None).is_none(),
            "masked pool dialer must be disabled when node_id is blank"
        );
    }

    #[test]
    fn self_is_filtered_out_of_peers() {
        let mut cfg = base_pool_config();
        cfg.peers = vec!["this-node:443".to_string(), "peer-b:443".to_string()];
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        assert_eq!(dialer.peers, vec!["peer-b:443".to_string()]);
    }

    #[test]
    fn transport_is_masked_reads_config_flag() {
        let mut cfg = base_pool_config();
        assert!(cfg.transport_is_masked());
        cfg.transport = Some("legacy".to_string());
        assert!(!cfg.transport_is_masked());
        cfg.transport = None;
        assert!(!cfg.transport_is_masked());
    }

    #[test]
    fn local_subnets_are_stored_from_constructor_param() {
        let cfg = base_pool_config();
        let subnets = vec!["192.168.1.0/24".to_string()];
        let dialer = PoolDialer::new(test_db(), &cfg, subnets.clone(), None, None).unwrap();
        assert_eq!(dialer.local_subnets, subnets);
    }

    #[test]
    fn local_subnets_default_empty_when_not_passed() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        assert!(dialer.local_subnets.is_empty());
    }

    /// `send_to_peer` on a peer with no live session (nothing ever inserted
    /// into `peer_senders`) must return `false` without panicking or
    /// blocking — this is the steady state whenever a peer is unreachable or
    /// the dial loop is backing off.
    #[test]
    fn send_to_peer_false_when_no_live_session() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        let sent = dialer.send_to_peer(
            "peer-a:443",
            ControlPayload::RouteSync {
                subnets_json: b"[]".to_vec(),
            },
        );
        assert!(!sent, "no session registered for peer-a:443 yet");
    }

    /// `broadcast` with zero connected peers must return 0, not panic.
    #[test]
    fn broadcast_zero_when_no_peers_connected() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        let n = dialer.broadcast(ControlPayload::PoolStateDigest { digest: [0u8; 32] });
        assert_eq!(n, 0);
    }

    /// `has_live_session` must mirror `send_to_peer`'s notion of "live"
    /// exactly (same `peer_senders` map, non-mutating) — false before
    /// registration, true once registered, false again after removal.
    #[test]
    fn has_live_session_tracks_peer_senders_membership() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();

        assert!(!dialer.has_live_session("peer-a:443"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<ControlPayload>(4);
        dialer
            .peer_senders
            .lock()
            .insert("peer-a:443".to_string(), tx);
        assert!(dialer.has_live_session("peer-a:443"));
        assert!(
            !dialer.has_live_session("peer-b:443"),
            "an unrelated peer must not appear live"
        );

        dialer.peer_senders.lock().remove("peer-a:443");
        assert!(!dialer.has_live_session("peer-a:443"));
    }

    /// Registry insert/remove/broadcast logic exercised directly against
    /// `peer_senders` (no live socket/session needed — this is the same map
    /// `run_one_session` inserts into after connecting and removes from when
    /// the session ends). Confirms: an inserted sender is reachable via
    /// `send_to_peer`, counted by `broadcast`, and — once removed — behaves
    /// exactly like the "never connected" case again.
    #[test]
    fn peer_senders_registry_insert_send_remove_round_trip() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<ControlPayload>(4);
        dialer
            .peer_senders
            .lock()
            .insert("peer-a:443".to_string(), tx);

        // Reachable while registered.
        let sent = dialer.send_to_peer(
            "peer-a:443",
            ControlPayload::RouteSync {
                subnets_json: b"[]".to_vec(),
            },
        );
        assert!(sent, "peer-a:443 has a live sender registered");
        assert!(rx.try_recv().is_ok(), "payload should have been queued");

        assert_eq!(
            dialer.broadcast(ControlPayload::PoolStateDigest { digest: [0u8; 32] }),
            1,
            "exactly one connected peer"
        );
        assert!(rx.try_recv().is_ok());

        // Simulate session end: registry entry removed (as `run_one_session`
        // does after `client.run(...)` returns).
        dialer.peer_senders.lock().remove("peer-a:443");

        let sent_after_remove = dialer.send_to_peer(
            "peer-a:443",
            ControlPayload::RouteSync {
                subnets_json: b"[]".to_vec(),
            },
        );
        assert!(
            !sent_after_remove,
            "peer-a:443 must not be reachable after its session ended"
        );
        assert_eq!(
            dialer.broadcast(ControlPayload::PoolStateDigest { digest: [0u8; 32] }),
            0,
            "no connected peers left"
        );
    }

    // ── Wave B1: pool topology read-endpoint retained state ────────────

    /// A freshly constructed dialer has no retained sync status for any
    /// peer yet — `pool_status_snapshot` must return an empty vec, not
    /// panic or fabricate an entry.
    #[test]
    fn pool_status_snapshot_empty_initially() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        assert!(dialer.pool_status_snapshot().is_empty());
    }

    /// `connected_peers` mirrors `peer_senders`'s membership and starts
    /// empty, matching `broadcast_zero_when_no_peers_connected`'s coverage
    /// of the same underlying map from the other accessor.
    #[test]
    fn connected_peers_empty_initially() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        assert!(dialer.connected_peers().is_empty());
    }

    /// `peers()` exposes the same self-filtered dial set `self_is_filtered_
    /// out_of_peers` already verifies against the private field — confirms
    /// the public getter agrees with it.
    #[test]
    fn peers_getter_matches_self_filtered_dial_set() {
        let mut cfg = base_pool_config();
        cfg.peers = vec!["this-node:443".to_string(), "peer-b:443".to_string()];
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        assert_eq!(dialer.peers(), &["peer-b:443".to_string()]);
    }

    /// Direct manipulation of the retained `pool_status` map (the same
    /// pattern `peer_senders_registry_insert_send_remove_round_trip` uses
    /// for `peer_senders`, since driving a real `run_one_session`/
    /// `anti_entropy` round needs a live socket) confirms
    /// `pool_status_snapshot` reflects whatever is stored, unmodified.
    #[test]
    fn pool_status_snapshot_reflects_stored_entries() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        dialer.pool_status.lock().insert(
            "peer-a:443".to_string(),
            PeerSyncStatus {
                connected: true,
                last_converged_unix: Some(1_700_000_000),
                converged: true,
                last_seen_unix: Some(1_700_000_005),
                partition_conflict: false,
                subnet_mismatch: false,
            },
        );

        let snap = dialer.pool_status_snapshot();
        assert_eq!(snap.len(), 1);
        let (peer, status) = &snap[0];
        assert_eq!(peer, "peer-a:443");
        assert!(status.connected);
        assert!(status.converged);
        assert_eq!(status.last_converged_unix, Some(1_700_000_000));
        assert_eq!(status.last_seen_unix, Some(1_700_000_005));
    }

    /// `mark_converged`/`mark_diverged` (the helpers `anti_entropy` calls)
    /// create a fresh entry optimistically `connected: true` when none
    /// existed, and correctly flip `converged` without disturbing
    /// `last_converged_unix` on a divergence signal.
    #[test]
    fn mark_converged_then_diverged_updates_status_correctly() {
        let pool_status: Arc<parking_lot::Mutex<HashMap<String, PeerSyncStatus>>> =
            Arc::new(parking_lot::Mutex::new(HashMap::new()));

        mark_converged(&pool_status, "peer-x:443", 1000);
        {
            let status = pool_status.lock();
            let entry = status.get("peer-x:443").unwrap();
            assert!(entry.connected);
            assert!(entry.converged);
            assert_eq!(entry.last_converged_unix, Some(1000));
            assert_eq!(entry.last_seen_unix, Some(1000));
        }

        mark_diverged(&pool_status, "peer-x:443", 2000);
        {
            let status = pool_status.lock();
            let entry = status.get("peer-x:443").unwrap();
            assert!(!entry.converged);
            // last_converged_unix records the last time convergence WAS
            // observed — a divergence signal must not clear it.
            assert_eq!(entry.last_converged_unix, Some(1000));
            assert_eq!(entry.last_seen_unix, Some(2000));
        }
    }

    // ── Wave B2c: runtime dial add-peer ─────────────────────────────────

    /// Before `start()` ever runs, `add_peer` must be a safe no-op: no
    /// task spawned (so this needs no tokio runtime — the guard in
    /// `spawn_dial_loop` returns before ever calling `tokio::spawn`), and
    /// the address must not linger in `dialed_peers` afterwards (the
    /// rollback), so a LATER legitimate `start()`/`add_peer` can still pick
    /// it up.
    #[test]
    fn add_peer_before_start_is_noop() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();

        dialer.add_peer("late-peer:443");

        assert_eq!(dialer.spawn_count(), 0, "dialer was never start()ed");
        assert!(
            !dialer.is_dialed_peer("late-peer:443"),
            "the rejected add must not leave a stale entry behind"
        );
    }

    /// Core B2c idempotency guarantee: calling `add_peer` twice for the
    /// SAME new address (one this node was NOT dialing at startup) must
    /// spawn exactly one `dial_loop` task, not two — verified via the
    /// `spawn_count` proxy rather than trying to observe a real network
    /// connection.
    #[tokio::test]
    async fn add_peer_is_idempotent_and_spawns_exactly_once() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        dialer.test_mark_started(Arc::new(AtomicBool::new(false)));

        assert!(!dialer.is_dialed_peer("new-exit:51820"));

        dialer.add_peer("new-exit:51820");
        assert_eq!(dialer.spawn_count(), 1);
        assert!(
            dialer.is_dialed_peer("new-exit:51820"),
            "add_peer must register the new address in the dial set"
        );

        // Repeated call for the exact same address — must NOT double-spawn.
        dialer.add_peer("new-exit:51820");
        assert_eq!(
            dialer.spawn_count(),
            1,
            "a repeated add_peer for an already-dialed address must be a no-op"
        );
    }

    /// `add_peer` for a genuinely different second address, after the
    /// first is already being dialed, must spawn a second task — the
    /// idempotency gate is per-address, not "at most one add_peer spawn
    /// ever".
    #[tokio::test]
    async fn add_peer_spawns_once_per_distinct_new_address() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        dialer.test_mark_started(Arc::new(AtomicBool::new(false)));

        dialer.add_peer("exit-one:51820");
        dialer.add_peer("exit-two:51820");
        dialer.add_peer("exit-one:51820"); // repeat, must not add a 3rd

        assert_eq!(dialer.spawn_count(), 2);
        assert!(dialer.is_dialed_peer("exit-one:51820"));
        assert!(dialer.is_dialed_peer("exit-two:51820"));
    }

    /// `add_peer` must never dial this node's own configured `node_id` —
    /// mirrors `self_is_filtered_out_of_peers`'s startup-time guarantee for
    /// the runtime-add path.
    #[tokio::test]
    async fn add_peer_skips_own_node_id() {
        let cfg = base_pool_config(); // node_id = "this-node:443"
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        dialer.test_mark_started(Arc::new(AtomicBool::new(false)));

        dialer.add_peer("this-node:443");

        assert_eq!(dialer.spawn_count(), 0);
        assert!(!dialer.is_dialed_peer("this-node:443"));
    }

    /// An empty (or all-whitespace) address must be rejected without
    /// panicking or spawning anything.
    #[tokio::test]
    async fn add_peer_rejects_empty_address() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        dialer.test_mark_started(Arc::new(AtomicBool::new(false)));

        dialer.add_peer("   ");

        assert_eq!(dialer.spawn_count(), 0);
    }

    /// End-to-end plumbing check: once `add_peer` has registered a runtime
    /// peer in the dial set, that SAME address string is exactly what
    /// `has_live_session`/`send_to_peer` (the B2b routing decision) key on
    /// once a real session connects — simulated here via
    /// `test_register_live_session` rather than a live socket, per the
    /// task's guidance. Confirms `add_peer` and the live-session registry
    /// agree on the peer's identity (no normalization/casing drift between
    /// the two paths).
    #[tokio::test]
    async fn add_peer_registered_address_is_reachable_once_session_connects() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        dialer.test_mark_started(Arc::new(AtomicBool::new(false)));

        dialer.add_peer("fresh-exit.example.com:51820");
        assert!(dialer.is_dialed_peer("fresh-exit.example.com:51820"));

        // No live session yet — the routing decision must not see it as
        // live just because a dial task was spawned.
        assert!(!dialer.has_live_session("fresh-exit.example.com:51820"));

        // Simulate the dial task's `run_one_session` succeeding.
        let _rx = dialer.test_register_live_session("fresh-exit.example.com:51820");
        assert!(dialer.has_live_session("fresh-exit.example.com:51820"));
        assert!(dialer.send_to_peer(
            "fresh-exit.example.com:51820",
            ControlPayload::PoolStateDigest { digest: [0u8; 32] }
        ));
    }

    /// `dialed_peer_addrs` must reflect both the startup-configured peer
    /// (added by `start()`... simulated here via `test_mark_started` +
    /// manual `add_peer`, since a real `start()` would attempt a live
    /// dial) and any runtime `add_peer` additions.
    #[tokio::test]
    async fn dialed_peer_addrs_reflects_all_tracked_peers() {
        let cfg = base_pool_config();
        let dialer = PoolDialer::new(test_db(), &cfg, vec![], None, None).unwrap();
        dialer.test_mark_started(Arc::new(AtomicBool::new(false)));

        dialer.add_peer("peer-a:443");
        dialer.add_peer("peer-b:443");

        let mut addrs = dialer.dialed_peer_addrs();
        addrs.sort();
        assert_eq!(
            addrs,
            vec!["peer-a:443".to_string(), "peer-b:443".to_string()]
        );
    }
}
