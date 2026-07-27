//! Server pool synchronisation — keeps clients.json in sync across pool nodes.
//!
//! ## Design
//! Pool nodes share a secret `sync_key` (32-byte BLAKE3 key, base64 in server.json)
//! and each node declares a unique `node_id` (the string the OTHER nodes use for
//! it in their `peers` lists).  For every peer link the node derives DIRECTIONAL
//! sub-keys via `crypto::derive_directional_peer_keys`: roles are assigned by
//! lexicographic order of the two ids (smaller id = "client" — sends with the
//! pair's c2s sub-key, receives with s2c; larger id does the opposite), so both
//! ends independently agree on which key encrypts which direction — no
//! handshake.  A *synthetic peer session* is registered in the `SessionManager`
//! per peer, keyed by the RECEIVE sub-key for that link, and outbound packets
//! are encrypted with the SEND sub-key.  This means A→B and B→A never share an
//! AEAD (key, nonce) space even though each node's nonce counter runs
//! independently.  Consequence: pool nodes must list each other MUTUALLY in
//! `peers` — a node only accepts sync from peers it has a link (and therefore a
//! receive session) for.
//!
//! Outbound sync packets are standard-looking VPN UDP datagrams sent to the
//! peer's VPN port. Their framing is FIXED and mask-independent (see
//! [`CLUSTER_MDH_LEN`]): `[8-byte resonance tag][CLUSTER_MDH_LEN random
//! bytes][ChaCha20-Poly1305 ciphertext]`. Cluster packets deliberately do NOT
//! follow the node's primary mask layout: the primary mask differs across
//! nodes and over time (rotation), and embedded-tag masks (`tag_offset !=
//! u16::MAX`) move both the tag and the ciphertext offsets — a sender framing
//! with ITS primary mask while the receiver decodes with THEIRS fails AEAD on
//! every packet. The gateway decodes any `is_pool_peer`/`is_site_peer`
//! session with this exact fixed layout.
//!
//! Incoming PoolSync packets are processed by the gateway's normal receive loop
//! and dispatched to `handle_control_message` as `ControlPayload::PoolSync`.
//!
//! ## Replay protection
//! The resonance counter is set to `unix_ms / 5_000` (5-second buckets).
//! Both sender and receiver independently compute the same counter for the same
//! wall-clock window.  The 511-counter tag window covers ±42 minutes of clock
//! drift, making time-based replay attacks impractical.
//!
//! ## Nonce-reuse safety across restarts
//! The pool session key is derived deterministically from the long-lived,
//! operator-configured `sync_key` — it never changes across restarts (unlike a
//! normal client session's key, which is fresh per handshake). The AEAD nonce
//! is built directly from the send counter, and the gateway's generic receive
//! path reconstructs that exact nonce from the counter it recovers via the
//! resonance tag (see `Session::next_send_nonce` / `compute_nonce`) — so, unlike
//! `chain_forwarder.rs`/`site_sync.rs`, the nonce here cannot simply be replaced
//! with a fully random value without breaking peer decryption.
//!
//! Instead, the send counter's high-water mark is persisted to disk
//! (`pool_sync_counter.state`, next to the clients DB) and durably bumped
//! *before* every packet that uses it. On restart the counter resumes at
//! `max(persisted + 1, current_time_bucket)`, so a fast restart landing in the
//! same 5-second wall-clock bucket as a prior run can never reuse a counter
//! value under the same static session key — closing the (key, nonce) reuse
//! window that would otherwise let ChaCha20-Poly1305 keystreams collide.

use portable_atomic::AtomicU64;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

use parking_lot::Mutex;
use rand::Rng;
use tracing::{info, warn};

use tokio::net::UdpSocket;

use aivpn_common::crypto::{
    self, encrypt_payload, SessionKeys, DEFAULT_WINDOW_MS, NONCE_SIZE, TAG_SIZE,
};
use aivpn_common::error::{Error, Result};
use aivpn_common::event_log::{AivpnEvent, EventBus, PeerSyncAction};
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType};
use base64::Engine as _;

use crate::client_db::ClientDatabase;
use crate::session::SessionManager;

const SYNC_INTERVAL: Duration = Duration::from_secs(5);
const TAG_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Fixed decoy-header (MDH) length of the mask-INDEPENDENT cluster wire
/// framing used by ALL server-to-server traffic (pool sync, site-to-site
/// RouteSync, multi-hop ChainForward):
///
/// `[8-byte resonance tag][CLUSTER_MDH_LEN random bytes][ciphertext]`
///
/// Sender ([`PeerSyncer::build_sync_packet`], `site_sync`, `chain_forwarder`)
/// and receiver (`gateway::handle_packet` for `is_pool_peer`/`is_site_peer`
/// sessions) both key off this constant, so the byte layout agrees regardless
/// of which mask is primary on either node.
pub const CLUSTER_MDH_LEN: usize = 20;

/// Random decoy-header bytes for the fixed cluster framing. Fresh randomness
/// per packet — like ciphertext, it carries no structure for DPI to key on.
pub fn cluster_mdh_bytes() -> Vec<u8> {
    let mut mdh = vec![0u8; CLUSTER_MDH_LEN];
    rand::thread_rng().fill(&mut mdh[..]);
    mdh
}

/// Pool configuration stored in server.json under `"pool"`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PoolSyncConfig {
    /// Peer server addresses in `host:vpn_port` format (same port clients use).
    #[serde(default)]
    pub peers: Vec<String>,
    /// Unique identifier of THIS node within the pool — must be exactly the
    /// string the other nodes use for this node in their `peers` lists
    /// (recommended: this node's public `host:vpn_port`).  Required: it anchors
    /// the deterministic directional-key role assignment (lexicographically
    /// smaller id sends with the pair's c2s sub-key).  Pool sync is disabled
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Deprecated — pool sync now uses the VPN port directly, not a separate port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_port: Option<u16>,
    /// 32-byte BLAKE3 key (base64).  All pool nodes must share this exact value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_key: Option<String>,
    /// Optional exit node for multi-hop routing (`host:port`).  When set,
    /// the entry node wraps client IP payloads in `ChainForward` and relays
    /// them to this address; the exit node routes to the internet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    /// Set to `true` on the node that acts as the exit point for multi-hop
    /// traffic.  When `false` (default), incoming `ChainForward` messages are
    /// rejected, preventing this node from being used as an open relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node_enabled: Option<bool>,
    /// FORK-B pool-sync dialer ([`crate::pool_dialer::PoolDialer`]):
    /// interval, in seconds, between `PoolStateDigest` beacons sent over a
    /// dialed masked pool-client session. `None` defaults to 30. Ignored
    /// unless `transport` is `"masked"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_beacon_secs: Option<u64>,
    /// FORK-B pool-sync transport selector: `"legacy"` (default, `None`) runs
    /// the existing mask-independent push-only [`PeerSyncer`]; `"masked"`
    /// activates [`crate::pool_dialer::PoolDialer`] instead — each node
    /// dials its peers as a fully masked, headless pool-client and runs
    /// bidirectional anti-entropy over that session. Additive: any value
    /// other than exactly `"masked"` (including unset) reproduces the
    /// pre-existing legacy behavior byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Phase 4 (per-node cryptographic identity): whether an UNKNOWN peer
    /// `node_id` presenting a valid `NodeEnrollment` proof gets bound
    /// (Trust-On-First-Use) automatically, or is rejected pending manual
    /// operator approval (e.g. via a future admin/CLI pinning command).
    /// `None` defaults to `true` — TOFU — so an existing masked pool
    /// deployment upgraded to a build with `node_registry` wired in keeps
    /// working without any operator action; set explicitly to `false` to
    /// require manual pinning of every pool node's identity key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_auto_add: Option<bool>,
    /// Path to this node's own 32-byte Ed25519 identity seed (see
    /// `aivpn_common::crypto::node_identity_from_seed`), used by the masked
    /// pool-client dialer to sign this node's own `NodeEnrollment` proof
    /// when connecting to a peer. Consumed by the dialer, not by anything in
    /// this file — wiring it into `PoolDialer` is a separate task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_identity_key: Option<String>,
    /// BUG D1 (route-auth identity enforcement): whether a masked pool-peer
    /// session MUST have a crypto-verified `verified_node_id` (bound via a
    /// validated `NodeEnrollment` proof) before its `RouteSync` announcements
    /// are honored. `None`/`false` (default) keeps the pre-existing
    /// migration-safe behavior — `handle_route_sync` is called with
    /// `verified_node_id` when present and otherwise falls back to the
    /// self-asserted node_id embedded in the payload (with a warn). Set to
    /// `true` on a deployment that has fully rolled out per-node identity
    /// (Phase 4 `NodeEnrollment`) to require every route-announcing peer to
    /// have proven its identity — self-asserted-identity RouteSync is
    /// dropped outright instead of being trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_node_enrollment: Option<bool>,
}

impl PoolSyncConfig {
    /// `true` only when `transport` is exactly `"masked"` — see the
    /// `transport` field doc for the additive/gating rationale.
    pub fn transport_is_masked(&self) -> bool {
        self.transport.as_deref() == Some("masked")
    }

    /// Whether an unknown pool-node identity should be auto-bound
    /// (Trust-On-First-Use) on first valid `NodeEnrollment` proof. Defaults
    /// to `true` when unset — see the `allow_auto_add` field doc.
    pub fn allow_auto_add(&self) -> bool {
        self.allow_auto_add.unwrap_or(true)
    }

    /// Whether `RouteSync` from a masked pool-peer without a crypto-verified
    /// `verified_node_id` must be dropped rather than trusted with a
    /// self-asserted identity. Defaults to `false` when unset — see the
    /// `require_node_enrollment` field doc.
    pub fn require_node_enrollment(&self) -> bool {
        self.require_node_enrollment.unwrap_or(false)
    }
}

/// One configured pool peer with its directional key material.
struct PeerLink {
    /// Peer address in `host:vpn_port` format (as written in `pool.peers`).
    addr: String,
    /// Keys this node ENCRYPTS with when sending to the peer (derived from
    /// the link's send-direction sub-key).
    send_keys: SessionKeys,
    /// Root sub-key for the RECEIVE direction of this link — passed to
    /// `SessionManager::create_pool_peer_session`, which derives from it the
    /// exact `SessionKeys` the peer uses when sending to us.
    recv_sync_key: [u8; 32],
}

/// Derive the pool wire `SessionKeys` from a (directional) root key.
///
/// Must stay byte-for-byte identical to the derivation inside
/// `SessionManager::create_pool_peer_session` — the sender runs this on its
/// send-direction root, the receiver registers a session from the same root
/// (its recv-direction root) and the gateway decrypts with the resulting
/// `session_key`.
fn pool_session_keys(root: &[u8; 32]) -> SessionKeys {
    SessionKeys {
        session_key: blake3::derive_key("aivpn-pool-enc-v1", root),
        session_key_s2c: blake3::derive_key("aivpn-pool-enc-v1", root),
        tag_secret: blake3::derive_key("aivpn-pool-tag-v1", root),
        prng_seed: blake3::derive_key("aivpn-pool-prng-v1", root),
    }
}

/// Manages outbound peer synchronisation using the main VPN protocol.
pub struct PeerSyncer {
    db: Arc<ClientDatabase>,
    peer_links: Vec<PeerLink>,
    events: EventBus,
    /// Strictly-monotonic per-node send counter.  Initialised to at least the
    /// current 5-second time bucket AND past any previously persisted
    /// high-water mark (see `counter_state_path`), then incremented atomically
    /// for every outbound packet.  Because the per-link send keys are static
    /// across restarts (derived deterministically from the long-lived
    /// `sync_key` + node ids),
    /// the persisted high-water mark — not just the time bucket — is what
    /// guarantees this counter, and therefore the AEAD nonce built from it,
    /// is never reused across process restarts.
    send_counter: AtomicU64,
    /// Path to the small on-disk file recording the highest send-counter
    /// value durably known to have been consumed. Lives next to the clients
    /// DB file. Best-effort: if persistence fails (e.g. read-only
    /// filesystem) a warning is logged and sync continues, falling back to
    /// the time-bucket-only protection that regular sessions rely on.
    counter_state_path: PathBuf,
    /// In-memory cache of the last value durably written to
    /// `counter_state_path`, guarded by a mutex so the concurrent per-peer
    /// send loops (which all share `send_counter`) can never race each
    /// other's writes into persisting a smaller value after a larger one.
    persisted_high_water: Mutex<u64>,
    /// H3: advisory exclusive `flock` held on `<counter_state_path>.lock` for
    /// the lifetime of this `PeerSyncer`. The persisted high-water mark alone
    /// only protects against *sequential* restarts — it does nothing to stop
    /// two overlapping processes (e.g. a crash-restart loop or an operator
    /// launching a duplicate) from both reading the same on-disk counter,
    /// then independently advancing `send_counter` from that same start
    /// value and encrypting with the same static per-peer session key. That
    /// is a real (key, nonce) reuse — catastrophic for ChaCha20-Poly1305.
    /// Held here (never explicitly unlocked) so the OS releases it
    /// automatically on process exit/crash; a second instance's attempt to
    /// acquire it fails immediately and `new()` refuses to start pool sync
    /// rather than risk nonce reuse.
    _counter_lock_file: std::fs::File,
}

impl PeerSyncer {
    /// Returns `None` if `sync_key` is absent or zero (sync disabled for safety).
    pub fn new(
        db: Arc<ClientDatabase>,
        config: &PoolSyncConfig,
        events: EventBus,
    ) -> Option<Arc<Self>> {
        let sync_key: [u8; 32] = config
            .sync_key
            .as_deref()
            .and_then(|k| base64::engine::general_purpose::STANDARD.decode(k).ok())
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 32]);

        if sync_key == [0u8; 32] {
            warn!("pool_sync: sync_key not configured — pool sync disabled for security");
            return None;
        }

        let node_id = match config
            .node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(id) => id.to_string(),
            None => {
                warn!(
                    "pool_sync: pool.node_id not configured — pool sync disabled. \
                     Directional AEAD keys require every node to set a unique node_id \
                     matching the string the other nodes use for it in their `peers` lists \
                     (recommended: this node's public host:vpn_port). All pool nodes must \
                     be updated and configured together."
                );
                return None;
            }
        };

        let mut peer_links = Vec::with_capacity(config.peers.len());
        for peer in &config.peers {
            if peer == &node_id {
                warn!(
                    "pool_sync: peer '{}' equals this node's node_id — skipped \
                     (directional roles require distinct ids)",
                    peer
                );
                continue;
            }
            // Lexicographically smaller id = "client" role: sends with the
            // pair's c2s sub-key, receives with s2c. Both ends compute this
            // independently, so no handshake is needed. Fails closed on a
            // duplicate id — never derive (and reuse) a shared-direction key.
            let (send_root, recv_root) =
                match crypto::derive_directional_peer_keys(&sync_key, &node_id, peer) {
                    Ok(roots) => roots,
                    Err(e) => {
                        warn!("pool_sync: peer '{}' skipped: {}", peer, e);
                        continue;
                    }
                };
            peer_links.push(PeerLink {
                addr: peer.clone(),
                send_keys: pool_session_keys(&send_root),
                recv_sync_key: recv_root,
            });
        }

        // `session_keys` above is static across restarts, so the send counter
        // (reused directly as the AEAD nonce, see `build_sync_packet`) must
        // never repeat a value it has already used in a prior run. Resume
        // from whatever high-water mark was last persisted to disk, falling
        // back to the current time bucket only when no persisted state
        // exists (first run) or it is stale/unreadable.
        let counter_state_path = db.file_path().with_file_name("pool_sync_counter.state");

        // H3: acquire an advisory exclusive flock on a dedicated lock file
        // BEFORE touching the counter state, and hold it for the process's
        // lifetime. This is what actually prevents cross-process nonce
        // reuse: the persisted high-water mark only protects sequential
        // restarts, not two overlapping processes racing the same read-then-
        // write. Fail closed — refuse to start pool sync — if the lock is
        // already held.
        let lock_path = counter_state_path.with_extension("state.lock");
        let lock_file = match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "pool_sync: failed to open counter lock file {} — pool sync disabled: {}",
                    lock_path.display(),
                    e
                );
                return None;
            }
        };
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: `lock_file` is a valid, open file descriptor for the
            // duration of this call; `flock` only inspects/mutates kernel
            // lock state for that fd and does not touch Rust-owned memory.
            let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                warn!(
                    "pool_sync: another process already holds the counter lock at {} — \
                     refusing to start a second overlapping pool-sync instance (would risk \
                     AEAD nonce reuse under the static pool session key)",
                    lock_path.display()
                );
                return None;
            }
        }

        // Best-effort cleanup of orphaned temp files. `write_counter_file` names
        // its temp `pool_sync_counter.<pid>.tmp`; a process that is killed
        // mid-persist (e.g. the crash-restart loops this survives) leaves its
        // temp behind, and since the name is per-PID nothing ever reclaimed
        // them — they accumulated unboundedly (hundreds observed in the field).
        // Sweep any stale `pool_sync_counter.*.tmp` at startup. Safe: this runs
        // before this process writes its own temp, and a co-located second
        // instance's in-flight temp is only ever consumed by an atomic rename,
        // so at worst one best-effort persist retries.
        if let Some(dir) = counter_state_path.parent() {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with("pool_sync_counter.") && name.ends_with(".tmp") {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }

        let wall_clock_bucket = crypto::current_timestamp_ms() / 5_000;
        let resume_from = read_counter_file(&counter_state_path)
            .map(|c| c.saturating_add(1))
            .unwrap_or(0);
        let start_counter = resume_from.max(wall_clock_bucket);

        // Persist the seed immediately (before any packet is sent) so that
        // even a crash before the first send leaves a high-water mark at
        // least as large as the value we are about to start from.
        if let Err(e) = write_counter_file(&counter_state_path, start_counter) {
            warn!(
                "pool_sync: failed to persist initial send counter to {} \
                 (restart nonce-reuse protection degraded): {}",
                counter_state_path.display(),
                e
            );
        }

        let send_counter = AtomicU64::new(start_counter);
        let persisted_high_water = Mutex::new(start_counter);

        Some(Arc::new(Self {
            db,
            peer_links,
            events,
            send_counter,
            counter_state_path,
            persisted_high_water,
            _counter_lock_file: lock_file,
        }))
    }

    /// Register one synthetic receive session per peer and spawn background tasks.
    pub fn start(self: Arc<Self>, session_manager: Arc<SessionManager>) {
        // Sentinel addr — peer sessions have no single client addr; incoming
        // packets arrive from various peer IPs and are matched by resonance tag.
        let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();
        // Each link gets its own receive session, keyed by the link's
        // recv-direction sub-key — the exact keys that peer sends with.
        let mut session_ids = Vec::with_capacity(self.peer_links.len());
        for link in &self.peer_links {
            session_ids
                .push(session_manager.create_pool_peer_session(&link.recv_sync_key, sentinel));
        }
        info!(
            "pool_sync: active ({} peers, directional keys)",
            self.peer_links.len()
        );

        // Periodically refresh the time-bucket counter in every tag window.
        let sm = session_manager.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(TAG_REFRESH_INTERVAL);
            loop {
                ticker.tick().await;
                for session_id in &session_ids {
                    sm.refresh_pool_peer_tags(session_id);
                }
            }
        });

        // One outbound loop per configured peer.
        for link_idx in 0..self.peer_links.len() {
            let me = self.clone();
            tokio::spawn(async move {
                me.outbound_loop(link_idx).await;
            });
        }
    }

    async fn outbound_loop(self: Arc<Self>, link_idx: usize) {
        let peer = self.peer_links[link_idx].addr.clone();
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("pool_sync: bind failed for peer {}: {}", peer, e);
                return;
            }
        };

        let mut ticker = tokio::time::interval(SYNC_INTERVAL);
        let mut consecutive_failures: u32 = 0;
        loop {
            ticker.tick().await;
            match self.push_to_peer(&socket, link_idx).await {
                Ok(n) => {
                    consecutive_failures = 0;
                    self.events.emit(AivpnEvent::PeerSync {
                        peer: peer.clone(),
                        action: PeerSyncAction::FullSync,
                        clients_synced: n as u32,
                    });
                }
                Err(e) => {
                    consecutive_failures += 1;
                    // Exponential backoff: 5s, 10s, 20s, 40s, capped at 60s.
                    let backoff = Duration::from_secs(
                        (SYNC_INTERVAL.as_secs() * (1u64 << consecutive_failures.min(4))).min(60),
                    );
                    warn!(
                        "pool_sync: send to {} failed ({} consecutive): {} — backoff {:?}",
                        peer, consecutive_failures, e, backoff
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    async fn push_to_peer(&self, socket: &UdpSocket, link_idx: usize) -> Result<usize> {
        let link = &self.peer_links[link_idx];
        // Fast path: a literal IP:port. Fall back to DNS resolution so a peer
        // configured as `host:port` (which the docs explicitly recommend as the
        // node_id form) actually pushes instead of failing to parse every tick.
        let peer_addr: SocketAddr = match link.addr.parse() {
            Ok(addr) => addr,
            Err(_) => tokio::net::lookup_host(&link.addr)
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
                .ok_or_else(|| {
                    Error::Session(format!(
                        "pool_sync: cannot resolve peer addr: {}",
                        link.addr
                    ))
                })?,
        };

        // Include tombstones: revocations propagate as `deleted == true`
        // records, so a peer's stale live copy is overwritten via LWW merge.
        // Using `list_clients()` here would silently drop every deletion.
        let clients = self.db.list_clients_including_deleted();
        let n = clients.len();
        let clients_json = serde_json::to_vec(&clients)
            .map_err(|e| Error::Session(format!("pool_sync: serialize: {}", e)))?;

        // UDP payload is capped at ~65 507 bytes (65 535 - 28 byte IP+UDP header).
        // Reserve ~500 bytes for the AIVPN framing + encryption overhead.
        const MAX_SYNC_PAYLOAD: usize = 65_000;
        if clients_json.len() > MAX_SYNC_PAYLOAD {
            return Err(Error::Session(format!(
                "pool_sync: client list too large for single UDP datagram \
                 ({} bytes, {} clients) — consider splitting the pool",
                clients_json.len(),
                n
            )));
        }

        let payload = ControlPayload::PoolSync { clients_json };
        let packet = self.build_sync_packet(&payload, &link.send_keys)?;
        socket
            .send_to(&packet, peer_addr)
            .await
            .map_err(|e| Error::Session(format!("pool_sync: udp send: {}", e)))?;
        Ok(n)
    }

    /// Build a VPN UDP packet carrying a PoolSync control message, encrypted
    /// with the given link's SEND-direction keys.
    ///
    /// Wire format is the FIXED cluster framing (see [`CLUSTER_MDH_LEN`]):
    /// `[8-byte resonance tag][CLUSTER_MDH_LEN random bytes][ciphertext]` —
    /// deliberately independent of any node's primary mask, so the receiving
    /// gateway (which decodes pool-peer sessions with this exact layout) and
    /// this sender always agree on the byte offsets.
    pub(crate) fn build_sync_packet(
        &self,
        payload: &ControlPayload,
        send_keys: &SessionKeys,
    ) -> Result<Vec<u8>> {
        let encoded = payload.encode()?;

        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: 0,
        };
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);

        // Atomically increment the per-node send counter.  Initialised near
        // the current 5-second time bucket (and past any persisted high-water
        // mark) so the receiver's tag window covers it.
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);

        // Durably record that `counter` has now been consumed BEFORE it is
        // used below as the AEAD nonce. `session_keys` is static across
        // restarts, so without this a crash between sending this packet and
        // persisting could let a restarted process reuse this exact
        // (key, nonce) pair — catastrophic for ChaCha20-Poly1305 (keystream
        // reuse, forgery). Best-effort: failures are logged, not fatal.
        self.persist_counter_floor(counter + 1);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());

        let pad_len: u16 = 16;
        let mut padded = Vec::with_capacity(2 + inner_payload.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner_payload);
        let mut rng = rand::thread_rng();
        for _ in 0..pad_len {
            padded.push(rng.gen::<u8>());
        }

        let ciphertext = encrypt_payload(&send_keys.session_key, &nonce, &padded)?;

        let time_window =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let tag = crypto::generate_resonance_tag(&send_keys.tag_secret, counter, time_window);

        let mdh = cluster_mdh_bytes();
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    /// Ensure the on-disk high-water mark is at least `min_counter`, writing
    /// a new value only when it actually advances the mark. The in-memory
    /// cache is updated only after a successful write, and the mutex
    /// serialises concurrent calls from the per-peer send loops so a smaller
    /// value can never clobber a larger one already persisted.
    fn persist_counter_floor(&self, min_counter: u64) {
        let mut high_water = self.persisted_high_water.lock();
        if *high_water >= min_counter {
            return;
        }
        match write_counter_file(&self.counter_state_path, min_counter) {
            Ok(()) => *high_water = min_counter,
            Err(e) => warn!(
                "pool_sync: failed to persist send counter high-water mark to {}: {}",
                self.counter_state_path.display(),
                e
            ),
        }
    }

    /// Test-only: the RECEIVE-direction root key for peer link `idx` — the
    /// exact root a receiving node registers via `create_pool_peer_session`.
    #[cfg(test)]
    pub(crate) fn test_peer_recv_root(&self, idx: usize) -> [u8; 32] {
        self.peer_links[idx].recv_sync_key
    }

    /// Test-only: build a REAL outbound sync packet for peer link `idx`,
    /// byte-identical to what `push_to_peer` puts on the wire. Used by the
    /// gateway receive-path regression test.
    #[cfg(test)]
    pub(crate) fn test_build_packet_for_peer(
        &self,
        payload: &ControlPayload,
        idx: usize,
    ) -> Result<Vec<u8>> {
        let keys = self.peer_links[idx].send_keys.clone();
        self.build_sync_packet(payload, &keys)
    }
}

/// Read the persisted send-counter high-water mark. Returns `None` if the
/// file is missing, unreadable, or does not contain a valid `u64` — callers
/// fall back to the wall-clock-derived starting counter in that case.
fn read_counter_file(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Durably persist `counter` as the new high-water mark, replacing any
/// previous value via write-then-rename so a crash mid-write can never leave
/// a corrupt or half-written file behind. The temp file name includes the
/// PID to avoid colliding with a concurrently-running second instance.
fn write_counter_file(path: &Path, counter: u64) -> std::io::Result<()> {
    let tmp_path = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp_path, counter.to_string())?;
    std::fs::rename(&tmp_path, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::event_log::EventSinkConfig;
    use aivpn_common::network_config::VpnNetworkConfig;
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

    fn test_pool_config() -> PoolSyncConfig {
        test_pool_config_for("node-a:443", "node-b:443")
    }

    /// Pool config for a node named `node_id` with a single peer `peer`.
    fn test_pool_config_for(node_id: &str, peer: &str) -> PoolSyncConfig {
        PoolSyncConfig {
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
        }
    }

    fn test_events() -> EventBus {
        EventBus::new(EventSinkConfig {
            stdout: false,
            webhook_url: None,
        })
    }

    /// Regression test for the (key, nonce) reuse bug: `session_keys` is
    /// derived deterministically from the static `sync_key` so it is
    /// byte-identical every time `PeerSyncer::new` runs. Without the
    /// persisted high-water mark, a second `PeerSyncer` constructed
    /// immediately after the first (simulating a fast restart landing in the
    /// same 5-second wall-clock bucket) would resume at the exact same
    /// counter value the first instance already used to encrypt a packet —
    /// reusing the AEAD nonce under the same key. This test asserts that can
    /// never happen.
    #[test]
    fn restart_never_reuses_a_send_counter_value() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        let db = Arc::new(ClientDatabase::load(&db_path, test_network_config()).unwrap());
        let cfg = test_pool_config();

        // "Process 1": send a handful of packets, advancing (and persisting) the counter.
        let syncer1 = PeerSyncer::new(db.clone(), &cfg, test_events()).unwrap();
        let payload = ControlPayload::PoolSync {
            clients_json: b"[]".to_vec(),
        };
        let mut last_used_counter = 0u64;
        for _ in 0..5 {
            last_used_counter = syncer1.send_counter.load(Ordering::Relaxed);
            let send_keys = syncer1.peer_links[0].send_keys.clone();
            syncer1.build_sync_packet(&payload, &send_keys).unwrap();
        }

        // "Process 2": a fresh PeerSyncer built right away, against the same
        // clients DB (and therefore the same counter-state file) — the
        // worst case for landing in the same wall-clock bucket as process 1.
        // Drop process 1's syncer first to release its advisory counter-file
        // flock (H3) — a real restart closes the old process's fd before the
        // new one opens, which is exactly what this drop simulates; two
        // genuinely *overlapping* instances are covered by
        // `overlapping_instances_are_refused` below.
        drop(syncer1);
        let syncer2 = PeerSyncer::new(db, &cfg, test_events()).unwrap();
        let resumed_counter = syncer2.send_counter.load(Ordering::Relaxed);

        assert!(
            resumed_counter > last_used_counter,
            "restarted instance must never reuse a counter value already used under \
             the same static session key (last used = {last_used_counter}, resumed at \
             = {resumed_counter})"
        );
    }

    /// H3 regression: two `PeerSyncer`s that are genuinely overlapping (the
    /// first is still alive, unlike the restart test above which drops it
    /// first) must not both be able to run against the same counter-state
    /// file — the second construction must fail closed rather than risk
    /// reusing a (key, nonce) pair the first instance might already be using.
    #[test]
    fn overlapping_instances_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        let db = Arc::new(ClientDatabase::load(&db_path, test_network_config()).unwrap());
        let cfg = test_pool_config();

        let syncer1 = PeerSyncer::new(db.clone(), &cfg, test_events()).unwrap();
        let syncer2 = PeerSyncer::new(db, &cfg, test_events());
        assert!(
            syncer2.is_none(),
            "a second overlapping PeerSyncer instance must be refused, not silently \
             allowed to race the first over the same counter state"
        );
        drop(syncer1);
    }

    /// Build a `PeerSyncer` named `node_id` whose single peer is `peer`,
    /// backed by its own private tempdir (own clients DB + counter state).
    fn make_syncer(node_id: &str, peer: &str) -> (tempfile::TempDir, Arc<PeerSyncer>) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        let db = Arc::new(ClientDatabase::load(&db_path, test_network_config()).unwrap());
        let cfg = test_pool_config_for(node_id, peer);
        let syncer = PeerSyncer::new(db, &cfg, test_events()).unwrap();
        (dir, syncer)
    }

    /// A12 regression: pool sync must not reuse one symmetric AEAD key in both
    /// directions. Node A ("node-a:443") and node B ("node-b:443") assign
    /// directional roles by lexicographic node_id order (A < B ⇒ A = "client",
    /// sends c2s / receives s2c) with no handshake, and must agree exactly:
    /// each side's SEND keys are what the other side derives for RECEIVING,
    /// while A→B and B→A use different keys.
    #[test]
    fn directional_roles_mirror_between_two_nodes() {
        let (_da, a) = make_syncer("node-a:443", "node-b:443");
        let (_db_, b) = make_syncer("node-b:443", "node-a:443");

        let a_link = &a.peer_links[0];
        let b_link = &b.peer_links[0];

        // A's send keys == keys B registers for receiving from A (and vice
        // versa) — pool_session_keys(recv root) is exactly what
        // SessionManager::create_pool_peer_session derives on the peer.
        let b_recv_keys = pool_session_keys(&b_link.recv_sync_key);
        let a_recv_keys = pool_session_keys(&a_link.recv_sync_key);
        assert_eq!(a_link.send_keys.session_key, b_recv_keys.session_key);
        assert_eq!(a_link.send_keys.tag_secret, b_recv_keys.tag_secret);
        assert_eq!(b_link.send_keys.session_key, a_recv_keys.session_key);
        assert_eq!(b_link.send_keys.tag_secret, a_recv_keys.tag_secret);

        // The two directions must NOT share an AEAD key — the whole point of
        // the fix: independent per-node counters can never collide into the
        // same (key, nonce) pair again.
        assert_ne!(
            a_link.send_keys.session_key, b_link.send_keys.session_key,
            "A→B and B→A must encrypt under different AEAD keys"
        );
        assert_ne!(a_link.send_keys.tag_secret, b_link.send_keys.tag_secret);
    }

    /// End-to-end over the real packet builder: a packet built by A decrypts
    /// with the keys B registers for the A→B direction (nonce reconstructed
    /// from the counter, as the gateway does) — and does NOT decrypt with the
    /// reverse-direction (B→A) key.
    #[test]
    fn sync_packet_round_trips_across_roles() {
        let (_da, a) = make_syncer("node-a:443", "node-b:443");
        let (_db_, b) = make_syncer("node-b:443", "node-a:443");

        let payload = ControlPayload::PoolSync {
            clients_json: b"[]".to_vec(),
        };
        let counter = a.send_counter.load(Ordering::Relaxed);
        let send_keys = a.peer_links[0].send_keys.clone();
        let packet = a.build_sync_packet(&payload, &send_keys).unwrap();

        // Receiver side (B): nonce is rebuilt from the recovered counter,
        // exactly like Gateway::compute_nonce.
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        // Fixed cluster framing: ciphertext starts after tag + CLUSTER_MDH_LEN.
        let ciphertext = &packet[TAG_SIZE + CLUSTER_MDH_LEN..];

        let recv_keys = pool_session_keys(&b.peer_links[0].recv_sync_key);
        let plaintext = crypto::decrypt_payload(&recv_keys.session_key, &nonce, ciphertext)
            .expect("B must decrypt A's packet with the A→B direction key");

        // Plaintext layout: [pad_len u16][InnerHeader][ControlPayload][padding].
        let pad_len = u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;
        let inner = &plaintext[2..plaintext.len() - pad_len];
        let header = InnerHeader::decode(inner).unwrap();
        assert_eq!(header.inner_type, InnerType::Control);

        // The REVERSE direction key (what B sends with / A receives with)
        // must NOT decrypt this packet — proving the two directions do not
        // share a key.
        let reverse_keys = pool_session_keys(&a.peer_links[0].recv_sync_key);
        assert_ne!(recv_keys.session_key, reverse_keys.session_key);
        assert!(
            crypto::decrypt_payload(&reverse_keys.session_key, &nonce, ciphertext).is_err(),
            "reverse-direction key must not decrypt A→B traffic"
        );
    }

    #[test]
    fn missing_node_id_disables_pool_sync() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        let db = Arc::new(ClientDatabase::load(&db_path, test_network_config()).unwrap());
        let mut cfg = test_pool_config();
        cfg.node_id = None;

        assert!(
            PeerSyncer::new(db, &cfg, test_events()).is_none(),
            "pool sync must be disabled when node_id is not configured"
        );
    }

    #[test]
    fn counter_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool_sync_counter.state");

        assert_eq!(read_counter_file(&path), None);

        write_counter_file(&path, 42).unwrap();
        assert_eq!(read_counter_file(&path), Some(42));

        write_counter_file(&path, 43).unwrap();
        assert_eq!(read_counter_file(&path), Some(43));
    }
}
