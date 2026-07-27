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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
            reverse_downlink_tx,
            node_identity,
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

    /// Queue `payload` for delivery to every currently-connected peer.
    /// Returns the number of peers it was successfully queued for.
    pub fn broadcast(&self, payload: ControlPayload) -> usize {
        let senders = self.peer_senders.lock();
        senders
            .values()
            .filter(|tx| tx.try_send(payload.clone()).is_ok())
            .count()
    }

    /// Spawn one reconnecting dialer task per configured peer.
    pub fn start(self: Arc<Self>, shutdown: Arc<AtomicBool>) {
        info!(
            "pool_dialer: active ({} peers, masked pool-client transport)",
            self.peers.len()
        );
        for peer in self.peers.clone() {
            let me = self.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                me.dial_loop(peer, shutdown).await;
            });
        }
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

        run_result
    }
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
) {
    let mut beacon = tokio::time::interval(Duration::from_secs(beacon_secs));
    // The first tick fires immediately; that's desirable here — beacon as
    // soon as the session is up rather than waiting a full interval.

    // Un-reconciled visibility: start "converged" optimistically (a fresh
    // session hasn't had a chance to diverge yet) so the very first beacon
    // round never spuriously warns.
    let mut last_converged = std::time::Instant::now();
    let mut warned_stale = false;

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
                        } else {
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
}
