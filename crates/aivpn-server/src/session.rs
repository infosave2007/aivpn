//! Session Manager
//!
//! Manages active VPN sessions with O(1) tag validation

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use std::time::{Duration, Instant};

use chacha20poly1305::aead::OsRng;
use dashmap::DashMap;
use hex;
use parking_lot::Mutex;
use rand::RngCore;
use subtle::ConstantTimeEq;
use tracing::{debug, info, trace, warn};

use aivpn_common::crypto::{
    self, KeyPair, SessionKeys, DEFAULT_WINDOW_MS, NONCE_SIZE, TAG_SIZE, X25519_PUBLIC_KEY_SIZE,
};
use aivpn_common::error::{Error, Result};
use aivpn_common::mask::MaskProfile;
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType};

/// Maximum sessions on 1GB VPS
pub const MAX_SESSIONS: usize = 500;

/// Session idle timeout (default)
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Session hard timeout — 0 means unlimited (Issue #33).
/// Configurable via `session_timeout_secs` in server.json.
/// PFS ratchet already handles key rotation, so forced session
/// expiration is unnecessary and causes reconnect failures.
pub const HARD_TIMEOUT: Duration = Duration::ZERO;

/// Tag window size (allow out-of-order packets).
///
/// Doubled from 256 to 512: at high pps a 256-tag window is only a few ms of
/// history, so GRO batches / reordering could push a legitimate packet out of
/// the anti-replay window and cause a false drop. 512 doubles the reorder
/// tolerance. Per-packet CPU stays flat because the refresh cadence in the
/// gateway is halved in step (refresh every 128 packets instead of 64), so the
/// amortised precompute/tag_map churn per packet is unchanged.
pub const TAG_WINDOW_SIZE: usize = 512;

/// Number of u64 words backing the anti-replay bitmap (one bit per counter of
/// history, covering exactly `TAG_WINDOW_SIZE` counters behind the newest one).
const REPLAY_WORDS: usize = TAG_WINDOW_SIZE / 64;

/// Time-window offsets accepted for the 0-RTT handshake (clock-skew tolerance).
/// ±2 windows (~±25 s at the default 10 s window) so mobile clients with a poor
/// RTC can still establish. The data plane keeps the tighter ±1 in `validate_tag`.
const HANDSHAKE_SKEW_WINDOWS: [i64; 5] = [0, -1, 1, -2, 2];

/// How often to rotate session keys (in-flight, no reconnect).
pub const REKEY_INTERVAL_SECS: u64 = 120;
/// Rotate after this many bytes even if the time interval hasn't elapsed.
///
/// The 120 s interval above is the primary trigger; this byte cap only exists
/// to bound keystream volume per key on bulk transfers. The former 1 MB value
/// forced a full DH rekey roughly every 0.7 s at line rate (~5.7 MB/s) — pure
/// churn that burned CPU and re-armed counters constantly. With per-direction
/// keys (nonce-reuse fix) already in place, 64 MB is safely conservative:
/// ~11 s between rekeys at line rate instead of sub-second.
pub const REKEY_BYTES_THRESHOLD: u64 = 64 * 1024 * 1024;

/// Maximum number of times a single pending rekey's `KeyRotate` is sent
/// (1 initial + up to 4 fast retransmits, one every `REKEY_RETRANSMIT_SECS`)
/// before the server gives up, clears the stuck pending state, and lets a
/// fresh rekey re-initiate after the normal interval.
///
/// KeyRotate rides plain UDP with no delivery guarantee: with a single
/// one-shot send, a lost KeyRotate left `pending_rekey_keypair` set forever —
/// `start_rekeying_sessions` skipped the session on every subsequent tick, so
/// PFS rotation silently stopped for the rest of the session's life.
pub const MAX_REKEY_SEND_ATTEMPTS: u32 = 5;

/// Minimum seconds between KeyRotate retransmits for a pending rekey.
///
/// This MUST stay well under the client's RX-silence watchdog floor (12 s,
/// `3 × keepalive` clamped to 12–45 s): if the KeyRotate (or the client's
/// rekey response) is lost, the retransmit must reach the client and re-sync
/// the tunnel BEFORE the watchdog declares the path dead and reconnects.
/// Riding the 30 s rekey-initiation tick was too slow — one lost packet
/// still cost a full reconnect. With a 3 s cadence swept by a ~2 s gateway
/// tick, all `MAX_REKEY_SEND_ATTEMPTS` sends land within ~12 s of initiation.
pub const REKEY_RETRANSMIT_SECS: u64 = 3;

/// Extra FORWARD span precomputed into the expected-tag window while an
/// inline rekey is pending (see `update_tag_window`). A client whose rekey
/// RESPONSE was lost keeps uploading under the new (server-unreadable) keys
/// with its shared monotonic counter, so its re-sent response — under the
/// old keys the server still accepts — can arrive with a counter thousands
/// past the server's frozen inbound counter (~170 pps over the 3 s
/// retransmit cadence, more under heavier upload). Outside the precomputed
/// band the response only had the globally rate-limited fallback scan
/// (`recover_session_by_tag`, ±2048, 20 scans/s shared) — which the flood of
/// undecryptable new-key data packets starves, so every retransmit was
/// wasted and the tunnel healed only via the client's RX-silence reconnect.
/// The response is content-authenticated (old-key AEAD + the client eph the
/// server committed to derive from), so accepting it from a far-ahead
/// counter is sound; validating it also advances `counter` to the client's
/// live edge, which is exactly what resyncs the post-commit window. Bounded
/// to cap the per-refresh tag precompute and `tag_map` memory.
const REKEY_TAG_LOOKAHEAD: u64 = 4096;

/// Session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Active,
    Idle,
    Rotating,
    MaskChange,
    Expired,
    Closed,
}

/// Session information
pub struct Session {
    pub session_id: [u8; 16],
    pub client_addr: SocketAddr,
    pub state: SessionState,
    pub keys: SessionKeys,
    pub eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],

    /// Packet counter for tag generation
    pub counter: u64,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Created timestamp
    pub created_at: Instant,
    /// Last server-to-client packet timestamp (for downlink recording IAT)
    pub last_server_send: Instant,

    /// Current mask profile
    pub mask: Option<MaskProfile>,
    /// Pending mask awaiting grace period before activation.
    /// Stored as (new_mask, timestamp_when_MaskUpdate_was_sent).
    pub pending_mask: Option<(MaskProfile, Instant)>,
    /// Current FSM state
    pub fsm_state: u16,
    /// Packets in current FSM state
    pub fsm_packets: u32,
    /// Duration in current FSM state
    pub fsm_state_start: Instant,

    /// Sequence number for outgoing packets
    pub send_seq: u32,
    /// Last received sequence (for ACK)
    pub recv_seq: u32,
    /// Send counter for nonce generation (u64, same space as tags)
    pub send_counter: u64,

    /// Expected tags (counter -> tag)
    pub expected_tags: HashMap<u64, [u8; TAG_SIZE]>,
    /// Counter value used as the base for the currently precomputed tag window.
    pub tag_window_base: u64,
    /// Received tag bitmap (for anti-replay)
    pub received_bitmap: ReplayWindow,
    /// Accumulated inbound bytes to flush into client_db in batches.
    pub pending_bytes_in: u64,
    /// Accumulated outbound (downlink) bytes to flush into client_db in batches.
    pub pending_bytes_out: u64,

    // --- PFS Ratchet fields (CRIT-3) ---
    /// Server's ephemeral public key for this session
    pub server_eph_pub: Option<[u8; 32]>,
    /// Ed25519 signature for ServerHello
    pub server_hello_signature: Option<[u8; 64]>,
    /// Ratcheted session keys (PFS)
    pub ratcheted_keys: Option<SessionKeys>,
    /// Ratcheted tags for validation (counter -> tag)
    pub ratcheted_expected_tags: HashMap<u64, [u8; TAG_SIZE]>,
    /// Whether session has completed PFS ratchet
    pub is_ratcheted: bool,
    /// Assigned VPN IP (e.g. 10.0.0.2)
    pub vpn_ip: Option<Ipv4Addr>,
    /// Registered client ID (from client_db) for traffic accounting
    pub client_id: Option<String>,

    /// Pre-ratchet expected tags preserved for a 2-second grace window after
    /// complete_ratchet() so client packets that were already in-flight with
    /// the old keys are not silently dropped as unrecognised.
    pub pre_ratchet_tags: HashMap<u64, [u8; TAG_SIZE]>,
    /// Deadline until which pre_ratchet_tags are still accepted.
    pub pre_ratchet_expire: Option<Instant>,
    /// Anti-replay set for pre_ratchet_tags — prevents replaying old-key packets
    /// during the grace window (C-S-2). Keyed by the raw packet counter: a 256-bit
    /// bitmap aliased counters 256 apart within the 511-wide tag window, so two
    /// distinct in-flight packets could be falsely rejected as replays. A set
    /// keyed by counter cannot alias; it is cleared each ratchet and bounded by
    /// the ~2s grace window, so it stays small.
    pub pre_ratchet_received: std::collections::HashSet<u64>,
    /// The AEAD keys those `pre_ratchet_tags` were minted under, retained for
    /// the same grace window. Without these the grace mechanism was inert:
    /// the tag resolved, the packet passed anti-replay, and then decryption
    /// used the freshly installed CURRENT key — so every in-flight old-key
    /// packet failed authentication and was dropped anyway, which is exactly
    /// what the grace window exists to prevent (worst on the high-RTT links
    /// `rekey_grace` scales for). Cleared with the tags in `cleanup_expired`.
    pub pre_ratchet_keys: Option<crypto::SessionKeys>,

    /// mTLS certificate gate — true means the client is cleared to send Data.
    /// Defaults to true (non-mTLS deployments are unaffected). When the
    /// gateway has `mtls.required = true` it resets this to false at session
    /// creation; a valid `ClientCert` message flips it back to true.
    pub mtls_ok: bool,

    /// True when this session was established via a site-to-site peer sync_key
    /// (registered by `site_sync::start()`).  Only sessions with this flag set
    /// are allowed to carry `ControlPayload::RouteSync` messages.
    pub is_site_peer: bool,

    /// True when this session was registered as a pool-sync peer via
    /// `create_pool_peer_session()`.  Only pool peer sessions are allowed to
    /// carry `ControlPayload::PoolSync` messages — any other session sending
    /// PoolSync is an attempt to inject or overwrite client records.
    pub is_pool_peer: bool,

    /// True when this session was established via the masked pool-client
    /// handshake — a sibling aivpn server dialed us as a control-only
    /// pool-client (PSK = `pool_client_psk(sync_key)`, DH against the shared
    /// `pool_server_keypair(sync_key)`) to run DB anti-entropy. FORK-B of the
    /// pool-sync redesign. Unlike `is_pool_peer` (a synthetic static-key
    /// cluster session forced onto FIXED cluster framing), this session rides
    /// a NORMAL per-session masked handshake — ServerHello PFS ratchet and
    /// MaskUpdate mask adoption both apply — so it uses normal mask framing,
    /// never cluster framing. It has NO `vpn_ip` and is never NATed; it is
    /// only permitted to exchange `ControlPayload::PoolSync` /
    /// `PoolStateDigest` for DB anti-entropy.
    pub is_masked_pool_peer: bool,

    /// Crypto-authenticated pool-node identity (Phase 4 — per-node
    /// cryptographic identity). Set once a masked pool-peer session
    /// (`is_masked_pool_peer`) proves its `node_id` via a valid
    /// `ControlPayload::NodeEnrollment` — verified and bound/pinned by
    /// `crate::node_registry::NodeRegistry::authenticate`. `None` until
    /// proven, even if the peer has already self-asserted a `node_id`
    /// elsewhere (e.g. in pool-sync payloads): this field supersedes any
    /// self-asserted node_id for route authorization, since a self-asserted
    /// id alone is trivially spoofable by anyone who can complete the masked
    /// pool-client handshake.
    pub verified_node_id: Option<String>,

    /// Wave B-IP.2: the last `pool_partition::PartitionCheck` decision
    /// computed for this session's peer (from an inbound
    /// `ControlPayload::PartitionAnnounce`). `None` until the first
    /// announce arrives. Used purely to dedupe the operator-visibility
    /// log — a peer that keeps re-announcing the same conflict/mismatch
    /// (or stays fine) logs only on a state TRANSITION, not on every
    /// anti-entropy beacon.
    pub last_partition_check: Option<crate::pool_partition::PartitionCheck>,

    /// Return-routability gate for the (potentially amplifying)
    /// `BootstrapDescriptorUpdate` burst: set once that burst has actually
    /// been sent for this session. Sending is deferred from immediately
    /// after ServerHello until the client proves — by sending a packet
    /// tagged with the ratcheted keys — that it genuinely received
    /// ServerHello at its real address (see the `is_ratcheted_tag` branch in
    /// `Gateway::handle_packet`). Without this a spoofed-source handshake
    /// alone triggers a multi-packet reply burst toward the spoofed victim
    /// with no proof the initiator can even receive it — a reflection/
    /// amplification primitive.
    pub bootstrap_descriptors_sent: bool,

    /// Pending keypair for in-flight key rotation. Set when server sends KeyRotate,
    /// cleared when client responds.
    pub pending_rekey_keypair: Option<KeyPair>,
    /// How many times the CURRENT pending rekey's `KeyRotate` has been sent
    /// (initial send + retransmits). Bounded by `MAX_REKEY_SEND_ATTEMPTS`;
    /// reset to 0 on commit or when the stuck pending state is cleared.
    pub pending_rekey_attempts: u32,
    /// When the CURRENT pending rekey's `KeyRotate` was last sent. Drives the
    /// fast retransmit sweep (`rekey_retransmits_due`): a pending rekey whose
    /// last send is ≥ `REKEY_RETRANSMIT_SECS` old is re-sent so a lost
    /// KeyRotate heals before the client's RX-silence watchdog reconnects.
    pub last_keyrotate_sent_at: Instant,
    /// Timestamp of the last successful key rotation (or session creation).
    pub last_rekey_at: Instant,
    /// Bytes sent+received since last rekey (for data-triggered rotation).
    pub bytes_since_rekey: u64,
    /// Last reported client-side quality score (0–100). Updated via QualityReport (0.9.0+).
    pub client_quality: u8,
    /// Smoothed client RTT in ms (EWMA of QualityReport rtt_ms). 0 = unknown.
    /// Used to scale the rekey/ratchet grace window so high-latency links
    /// (e.g. satellite) don't silently drop in-flight packets at the key seam.
    pub client_srtt_ms: u32,

    // --- FEC server-side recovery state (0.9.0+) ---
    /// Data packets received in the current FEC group (reset on each FecRepair).
    pub fec_recv_count: u8,
    /// XOR accumulator for in-flight FEC group payloads.
    pub fec_xor_buf: Vec<u8>,
    /// Max payload length seen in the current FEC group.
    pub fec_xor_len: usize,
    /// Next expected FEC group_seq. Mismatches indicate a lost FecRepair
    /// and mean the XOR buffer is stale — recovery must be skipped.
    pub fec_pending_seq: u16,
    /// Inner seq_num of the most recently processed FecRepair packet.
    /// The client numbers all inner packets monotonically, so a Data packet
    /// arriving after this repair with a seq NOT AHEAD of it belongs to an
    /// already-closed group: it is either the just-FEC-recovered packet
    /// arriving late (a duplicate) or a straggler whose group is gone —
    /// either way it must not be delivered again nor pollute the new group's
    /// XOR accumulator (a false `recv == group_size - 1` trigger recovers
    /// garbage). None until the first FecRepair is seen.
    pub fec_repair_seq_hi: Option<u16>,
    /// Highest mask-catalog version already pushed to this client. The gateway
    /// bumps a global catalog version whenever the mask set changes; when this
    /// lags behind, the next Keepalive triggers a fresh `MaskCatalog` push.
    /// Starts at 0 so the catalog is sent once shortly after connect.
    pub mask_catalog_version_sent: u64,

    /// True once a `ControlPayload::Capabilities` announcement (this
    /// session's server-assigned role) has been pushed to the client.
    /// Mirrors `mask_catalog_version_sent`'s send-once gate, but a plain
    /// bool suffices — role doesn't change mid-session the way the mask
    /// catalog does; a role change takes effect on the client's next
    /// reconnect, when a fresh `Session` (and a fresh `false`) is created.
    pub capabilities_sent: bool,

    /// Signature of the session state last pushed to the kernel accelerator
    /// (c2s key + wire offsets). 0 = never installed. When the live state
    /// diverges (mask switch, key rotation) the kernel session is re-installed
    /// so its frozen key/offsets don't silently fail every decrypt.
    pub kernel_install_sig: u64,

    /// Time window (`current_timestamp_ms / DEFAULT_WINDOW_MS`) that the current
    /// kernel-downlink reservation's pre-computed resonance tags were derived
    /// for. The kernel stamps these frozen tags verbatim (no in-kernel BLAKE3),
    /// and the client only accepts a downlink tag whose window is within ±1 of
    /// its own. So when the wall-clock window advances past this value we must
    /// re-arm the reservation with fresh tags, or every kernel-egress downlink
    /// packet is rejected as "Invalid resonance tag". 0 = never armed.
    pub kernel_dl_window: u64,

    /// Time window (`current_timestamp_ms / DEFAULT_WINDOW_MS`) that
    /// `expected_tags` was last precomputed for. Lets the fallback scan skip
    /// rebuilding windows that are already current (a fallback miss used to
    /// rebuild EVERY session's window — O(sessions × window) BLAKE3 per miss).
    /// 0 = never built.
    pub tag_window_tw: u64,

    /// 1a perf fix: pre-generated pool of mask-dependent headers (MDH) for
    /// this session's current `mask`, so `next_mdh()` round-robins through
    /// cached headers on the downlink hot path instead of calling the mask's
    /// RNG-based `HeaderSpec::generate()` fresh for every packet. Empty when
    /// `mask` is `None` or has no dynamic `header_spec` (a static
    /// `header_template` mask always yields the same bytes, so no pool is
    /// needed). Rebuilt by `rebuild_mdh_pool()` whenever `mask` changes —
    /// scoped per-session (not a global cache) so per-session polymorphic
    /// mask variants (unique `mask_id` per session) never share a pool and a
    /// mask switch can never serve a stale header.
    mdh_pool: Vec<Vec<u8>>,
    /// Round-robin cursor into `mdh_pool`.
    mdh_pool_idx: usize,
}

/// Number of headers pre-generated per mask pool (1a). Large enough that the
/// on-wire header distribution still looks freshly random across a session's
/// packet stream; small enough to build in microseconds on a mask switch.
const MDH_POOL_SIZE: usize = 64;

/// Anti-replay bitmap tracking which of the last `TAG_WINDOW_SIZE` counters
/// (relative to the newest seen) have already been received. Bit 0 is the
/// newest counter; higher bit indices are older. Backed by `REPLAY_WORDS`
/// little-endian u64 words so the window width scales with `TAG_WINDOW_SIZE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayWindow {
    words: [u64; REPLAY_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            words: [0u64; REPLAY_WORDS],
        }
    }
}

impl ReplayWindow {
    pub fn set_bit(&mut self, bit: usize) {
        if bit >= TAG_WINDOW_SIZE {
            return;
        }
        self.words[bit / 64] |= 1u64 << (bit % 64);
    }

    /// Shift all bits toward higher indices (older) by `shift` positions.
    /// Called when the newest counter advances: history slides down and the
    /// oldest bits fall off the end of the window.
    pub fn shift_left(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        if shift >= TAG_WINDOW_SIZE {
            self.clear();
            return;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        if bit_shift == 0 {
            for i in (0..REPLAY_WORDS).rev() {
                self.words[i] = if i >= word_shift {
                    self.words[i - word_shift]
                } else {
                    0
                };
            }
        } else {
            for i in (0..REPLAY_WORDS).rev() {
                let mut v = 0u64;
                if i >= word_shift {
                    v = self.words[i - word_shift] << bit_shift;
                    if i > word_shift {
                        v |= self.words[i - word_shift - 1] >> (64 - bit_shift);
                    }
                }
                self.words[i] = v;
            }
        }
    }

    pub fn get_bit(&self, bit: usize) -> bool {
        if bit >= TAG_WINDOW_SIZE {
            return false;
        }
        (self.words[bit / 64] & (1u64 << (bit % 64))) != 0
    }

    pub fn clear(&mut self) {
        self.words = [0u64; REPLAY_WORDS];
    }
}

impl Session {
    pub fn new(
        session_id: [u8; 16],
        client_addr: SocketAddr,
        keys: SessionKeys,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            client_addr,
            state: SessionState::Pending,
            keys,
            eph_pub,
            counter: 0,
            last_seen: now,
            created_at: now,
            last_server_send: now,
            mask: None,
            pending_mask: None,
            fsm_state: 0,
            fsm_packets: 0,
            fsm_state_start: now,
            send_seq: 0,
            recv_seq: 0,
            send_counter: 0,
            expected_tags: HashMap::with_capacity(TAG_WINDOW_SIZE),
            tag_window_base: 0,
            received_bitmap: ReplayWindow::default(),
            pending_bytes_in: 0,
            pending_bytes_out: 0,
            server_eph_pub: None,
            server_hello_signature: None,
            ratcheted_keys: None,
            ratcheted_expected_tags: HashMap::new(),
            is_ratcheted: false,
            vpn_ip: None,
            client_id: None,
            pre_ratchet_tags: HashMap::new(),
            pre_ratchet_expire: None,
            pre_ratchet_received: std::collections::HashSet::new(),
            pre_ratchet_keys: None,
            mtls_ok: true,
            is_site_peer: false,
            is_pool_peer: false,
            is_masked_pool_peer: false,
            verified_node_id: None,
            last_partition_check: None,
            bootstrap_descriptors_sent: false,
            pending_rekey_keypair: None,
            pending_rekey_attempts: 0,
            last_keyrotate_sent_at: now,
            last_rekey_at: now,
            bytes_since_rekey: 0,
            client_quality: 100,
            client_srtt_ms: 0,
            fec_recv_count: 0,
            fec_xor_buf: Vec::new(),
            fec_xor_len: 0,
            fec_pending_seq: 0,
            fec_repair_seq_hi: None,
            mask_catalog_version_sent: 0,
            capabilities_sent: false,
            kernel_install_sig: 0,
            kernel_dl_window: 0,
            tag_window_tw: 0,
            mdh_pool: Vec::new(),
            mdh_pool_idx: 0,
        }
    }

    /// Rebuild `mdh_pool` for the session's current `mask`. Cheap relative to
    /// per-packet cost but never called on the hot path itself — only from
    /// the two places `mask` is assigned (initial bootstrap mask and
    /// `commit_pending_mask` below).
    pub fn rebuild_mdh_pool(&mut self) {
        self.mdh_pool.clear();
        self.mdh_pool_idx = 0;
        if let Some(spec) = self.mask.as_ref().and_then(|m| m.header_spec.as_ref()) {
            let mut rng = rand::thread_rng();
            self.mdh_pool = (0..MDH_POOL_SIZE)
                .map(|_| spec.generate(&mut rng))
                .collect();
        }
    }

    /// Next mask-dependent header for a downlink packet (1a). Round-robins
    /// through the pre-generated pool — no RNG call on the hot path — falling
    /// back to the static `header_template` for masks with no `header_spec`,
    /// and lazily (re)building the pool if it is unexpectedly empty (should
    /// not happen once `rebuild_mdh_pool` runs on every mask assignment, but
    /// keeps this safe against future call sites that set `mask` directly).
    pub fn next_mdh(&mut self) -> Vec<u8> {
        let Some(mask) = self.mask.as_ref() else {
            return Vec::new();
        };
        if mask.header_spec.is_none() {
            return mask.header_template.clone();
        }
        if self.mdh_pool.is_empty() {
            self.rebuild_mdh_pool();
        }
        if self.mdh_pool.is_empty() {
            // header_spec generated zero-length headers (e.g. no fields) —
            // nothing to round-robin; return the empty header directly.
            return Vec::new();
        }
        let idx = self.mdh_pool_idx % self.mdh_pool.len();
        self.mdh_pool_idx = self.mdh_pool_idx.wrapping_add(1);
        self.mdh_pool[idx].clone()
    }

    /// Compute next nonce for encryption from send_counter (u64)
    /// Uses the same counter space as tag generation for consistency
    pub fn next_send_nonce(&mut self) -> ([u8; NONCE_SIZE], u64) {
        let counter = self.send_counter;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        self.send_counter += 1;
        (nonce, counter)
    }

    /// Update expected tags for validation window
    pub fn update_tag_window(&mut self) {
        let time_window =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);

        // Pre-compute tags for a bidirectional window around the highest
        // validated counter so minor UDP reordering does not fall out of the
        // fast path lookup map.
        self.expected_tags.clear();
        self.tag_window_base = self.counter;
        let window_back = TAG_WINDOW_SIZE as u64 - 1;
        let window_start = self.counter.saturating_sub(window_back);
        // While a rekey is pending, reach further FORWARD so the client's
        // re-sent KeyRotate response — old-key authenticated but potentially
        // thousands of counters ahead of our frozen inbound counter — lands
        // in the precomputed band and the O(1) tag_map path (see
        // REKEY_TAG_LOOKAHEAD).
        let window_fwd = TAG_WINDOW_SIZE as u64 - 1
            + if self.pending_rekey_keypair.is_some() {
                REKEY_TAG_LOOKAHEAD
            } else {
                0
            };
        let window_end = self.counter.saturating_add(window_fwd);

        for counter_val in window_start..=window_end {
            let tag =
                crypto::generate_resonance_tag(&self.keys.tag_secret, counter_val, time_window);
            self.expected_tags.insert(counter_val, tag);
        }
        self.tag_window_tw = time_window;
    }

    /// Validate received tag (constant-time)
    /// Returns (counter, is_ratcheted_tag) if valid.
    /// Checks the current time window first, then adjacent windows (±1)
    /// for clock skew tolerance.
    pub fn validate_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<(u64, bool)> {
        let is_replay = |counter_val: u64| {
            if counter_val > self.counter {
                return false;
            }

            let bit_index = (self.counter - counter_val) as usize;
            // A counter older than the replay bitmap can hold cannot be proven
            // fresh, so it must be rejected as a replay. Returning false here
            // would accept it: the precomputed `expected_tags` window reaches
            // slightly further back than the bitmap (base is pinned at refresh
            // time while `counter` drifts up to the refresh stride), so a tag
            // just past the bitmap edge still matches `ct_eq` and, with the
            // bit permanently unmarkable, would be replayable until the next
            // refresh.
            if bit_index >= TAG_WINDOW_SIZE {
                return true;
            }
            self.received_bitmap.get_bit(bit_index)
        };

        let history_window = TAG_WINDOW_SIZE as u64 - 1;
        let window_start = self.counter.saturating_sub(history_window);
        let window_end = self.counter.saturating_add(
            TAG_WINDOW_SIZE as u64 - 1
                + if self.pending_rekey_keypair.is_some() {
                    REKEY_TAG_LOOKAHEAD
                } else {
                    0
                },
        );

        // Check initial keys — current time window (pre-computed)
        for (counter, expected) in &self.expected_tags {
            if bool::from(expected.ct_eq(tag)) {
                if is_replay(*counter) {
                    return None; // Already received
                }
                return Some((*counter, false));
            }
        }
        // Check the live time window and its neighbours on-the-fly for clock
        // skew. Normally the live window is already in `expected_tags`, but a
        // tag can arrive just after the clock crosses a window boundary and
        // before the precomputed map is refreshed. Skipping the live window
        // unconditionally created a short validation blackout at every
        // boundary. During a pending rekey the wider forward span is required
        // here too: a re-sent response can be both far ahead of the frozen
        // counter and in a different time window from the cached map.
        let current_tw =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        for tw_offset in [
            current_tw,
            current_tw.wrapping_sub(1),
            current_tw.wrapping_add(1),
        ] {
            if tw_offset == self.tag_window_tw {
                continue;
            }
            for counter_val in window_start..=window_end {
                let expected =
                    crypto::generate_resonance_tag(&self.keys.tag_secret, counter_val, tw_offset);
                if bool::from(expected.ct_eq(tag)) {
                    if is_replay(counter_val) {
                        return None;
                    }
                    return Some((counter_val, false));
                }
            }
        }
        // Check pre-ratchet tags during grace window (in-flight packets from client
        // that were encrypted with old keys before it switched to ratcheted ones).
        if let Some(expire) = self.pre_ratchet_expire {
            if Instant::now() < expire {
                for (counter, expected) in &self.pre_ratchet_tags {
                    if bool::from(expected.ct_eq(tag)) {
                        // C-S-2: dedicated pre-ratchet replay set (keyed by raw
                        // counter — see field doc for why a bitmap aliased here).
                        if self.pre_ratchet_received.contains(counter) {
                            return None; // Already received — replay
                        }
                        return Some((*counter, false));
                    }
                }
            }
        }

        // Check ratcheted keys (only during transition, before ratchet is complete)
        if !self.is_ratcheted {
            for (counter, expected) in &self.ratcheted_expected_tags {
                if bool::from(expected.ct_eq(tag)) {
                    return Some((*counter, true));
                }
            }
            // Also check adjacent windows for ratcheted keys
            if let Some(ratcheted_keys) = &self.ratcheted_keys {
                for tw_offset in [current_tw.wrapping_sub(1), current_tw.wrapping_add(1)] {
                    for i in 0..TAG_WINDOW_SIZE {
                        let expected = crypto::generate_resonance_tag(
                            &ratcheted_keys.tag_secret,
                            i as u64,
                            tw_offset,
                        );
                        if bool::from(expected.ct_eq(tag)) {
                            return Some((i as u64, true));
                        }
                    }
                }
            }
        }
        None
    }

    /// Validate the first handshake packet against the session's initial keys,
    /// tolerating ±2 time windows of client clock skew (data-plane `validate_tag`
    /// only tolerates ±1). Used exclusively at session-creation time, mirroring
    /// `handshake_tag_precheck`'s skew budget so a client that passes the cheap
    /// pre-check is not then rejected by a narrower post-create validation.
    pub fn validate_handshake_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<(u64, bool)> {
        const HANDSHAKE_TAG_SEARCH: u64 = 16;
        let base_tw =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        for tw in HANDSHAKE_SKEW_WINDOWS
            .iter()
            .map(|d| base_tw.wrapping_add(*d as u64))
        {
            for counter in 0..=HANDSHAKE_TAG_SEARCH {
                let expected = crypto::generate_resonance_tag(&self.keys.tag_secret, counter, tw);
                if bool::from(expected.ct_eq(tag)) {
                    return Some((counter, false));
                }
            }
        }
        None
    }

    /// Mark tag as received
    pub fn mark_tag_received(&mut self, counter: u64) {
        if counter > self.counter {
            let shift = (counter - self.counter) as usize;
            self.received_bitmap.shift_left(shift);
            self.counter = counter;
            self.received_bitmap.set_bit(0);
            return;
        }

        let bit_index = (self.counter - counter) as usize;
        if bit_index < TAG_WINDOW_SIZE {
            self.received_bitmap.set_bit(bit_index);
        }
    }

    /// Pre-ratchet keys, but only while the grace window is still open.
    ///
    /// Deliberately replaces the old `is_pre_ratchet_counter(counter)` helper:
    /// counter membership CANNOT identify the epoch. `complete_ratchet` resets
    /// `counter` to 0 and the ratcheted tag window is minted for 0..512, while
    /// `pre_ratchet_tags` (an old window built by `update_tag_window`, whose
    /// start is `saturating_sub`bed to 0 for the small counters seen at the
    /// post-handshake ratchet) also covers 0..512 — so the two counter spaces
    /// overlap almost entirely. Only which key actually authenticates the
    /// packet can tell the epochs apart.
    pub fn pre_ratchet_keys_in_grace(&self) -> Option<&crypto::SessionKeys> {
        let live = self
            .pre_ratchet_expire
            .is_some_and(|expire| Instant::now() < expire);
        if live {
            self.pre_ratchet_keys.as_ref()
        } else {
            None
        }
    }

    /// Mark a pre-ratchet counter as received so it cannot be replayed (C-S-2).
    pub fn mark_pre_ratchet_received(&mut self, counter: u64) {
        self.pre_ratchet_received.insert(counter);
    }

    /// Get next sequence number for inner header
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }

    /// Update FSM state
    pub fn update_fsm(&mut self) {
        if let Some(mask) = &self.mask {
            let duration_ms = self.fsm_state_start.elapsed().as_millis() as u64;
            let (new_state, _size_override, _iat_override, _padding_override) =
                mask.process_transition(self.fsm_state, self.fsm_packets, duration_ms);

            if new_state != self.fsm_state {
                self.fsm_state = new_state;
                self.fsm_packets = 0;
                self.fsm_state_start = Instant::now();
            }
        }
        self.fsm_packets += 1;
    }

    /// Check if session is idle
    pub fn is_idle(&self) -> bool {
        self.last_seen.elapsed() > IDLE_TIMEOUT
    }

    /// Pre-compute tags for ratcheted keys
    pub fn update_ratcheted_tag_window(&mut self) {
        if let Some(ratcheted_keys) = &self.ratcheted_keys {
            let time_window =
                crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
            self.ratcheted_expected_tags.clear();
            // Ratcheted counter starts at 0
            for i in 0..TAG_WINDOW_SIZE {
                let tag = crypto::generate_resonance_tag(
                    &ratcheted_keys.tag_secret,
                    i as u64,
                    time_window,
                );
                self.ratcheted_expected_tags.insert(i as u64, tag);
            }
        }
    }

    /// Fold a fresh client-reported RTT sample into the smoothed estimate
    /// (EWMA, 1/8 weight). Clamped to a sane range to reject bogus reports.
    pub fn observe_client_rtt(&mut self, rtt_ms: u32) {
        let sample = rtt_ms.clamp(1, 60_000);
        self.client_srtt_ms = if self.client_srtt_ms == 0 {
            sample
        } else {
            ((self.client_srtt_ms as u64 * 7 + sample as u64) / 8) as u32
        };
    }

    /// Grace window during which pre-ratchet keys stay valid so in-flight
    /// packets encrypted with the old keys are not dropped at a rekey/ratchet
    /// seam. Scales with RTT (`4 × srtt`) so high-latency links (satellite,
    /// RTT+jitter > 2 s) don't silently lose packets, with a 2 s floor and a
    /// 30 s cap so stale keys are not retained indefinitely.
    pub fn rekey_grace(&self) -> Duration {
        const FLOOR: Duration = Duration::from_secs(2);
        const CAP: Duration = Duration::from_secs(30);
        if self.client_srtt_ms == 0 {
            return FLOOR;
        }
        let scaled = Duration::from_millis(self.client_srtt_ms as u64 * 4);
        scaled.clamp(FLOOR, CAP)
    }

    /// Complete PFS ratchet: switch to ratcheted keys, zeroize old ones
    pub fn complete_ratchet(&mut self) {
        if let Some(ratcheted_keys) = self.ratcheted_keys.take() {
            // Preserve old expected_tags for an RTT-scaled grace so client
            // packets already in-flight with the pre-ratchet keys are not
            // dropped (see rekey_grace).
            let grace = self.rekey_grace();
            self.pre_ratchet_tags = std::mem::take(&mut self.expected_tags);
            self.pre_ratchet_expire = Some(Instant::now() + grace);
            self.pre_ratchet_received.clear();

            // Retain the keys those tags belong to for the same window, or the
            // grace is inert (see `pre_ratchet_keys`).
            self.pre_ratchet_keys = Some(std::mem::replace(&mut self.keys, ratcheted_keys));
            self.counter = 0;
            self.send_counter = 0;
            self.tag_window_base = self.counter;
            self.expected_tags = std::mem::take(&mut self.ratcheted_expected_tags);
            self.received_bitmap.clear();
            self.pending_bytes_in = 0;
            self.pending_bytes_out = 0;
            self.is_ratcheted = true;
            // Keep `server_eph_pub` (a PUBLIC key) — the client sends its
            // transcript-bound `DeviceEnrollment` proof immediately AFTER the
            // ratchet, and the server must still hold this ratchet's
            // `server_eph_pub` to recompute the expected proof (see
            // `verify_device_enrollment_proof`). PFS only requires erasing the
            // PRIVATE ephemeral (the `server_eph_kp` secret, already dropped
            // after DH2 in `create_session`); retaining the public half leaks
            // nothing. Nulling it here made the server reject every enrollment
            // with Shutdown reason 3, killing the session right after the
            // handshake — the whole data plane went dead.
            self.server_hello_signature = None;
        }
    }

    /// Check and commit a pending mask if the grace period has elapsed.
    /// Returns true if a mask was committed.
    /// Grace period = 500ms — enough for the MaskUpdate packet to reach the client.
    pub fn commit_pending_mask(&mut self) -> bool {
        const MASK_GRACE_PERIOD: Duration = Duration::from_millis(500);
        if let Some((_, sent_at)) = &self.pending_mask {
            if sent_at.elapsed() >= MASK_GRACE_PERIOD {
                let (new_mask, _) = self.pending_mask.take().unwrap();
                info!("Committing deferred mask switch to '{}'", new_mask.mask_id);
                self.mask = Some(new_mask);
                // 1a: the old pool's headers belong to the mask we just left
                // — rebuild before the next downlink packet picks one up.
                self.rebuild_mdh_pool();
                // Reset FSM state for the new mask
                self.fsm_state = 0;
                self.fsm_packets = 0;
                self.fsm_state_start = Instant::now();
                return true;
            }
        }
        false
    }
}

/// Session Manager with O(1) tag lookup
pub struct SessionManager {
    /// Sessions by ID
    sessions: DashMap<[u8; 16], Arc<Mutex<Session>>>,
    /// Tag -> Session ID mapping for O(1) lookup
    tag_map: DashMap<[u8; TAG_SIZE], [u8; 16]>,
    /// VPN IP -> Session ID mapping for TUN return routing
    vpn_ip_map: DashMap<Ipv4Addr, [u8; 16]>,
    /// Next VPN IP to assign (last octet)
    /// Pool of free VPN IP octets (2..=254). IPs are returned when sessions end.
    ip_pool: Mutex<BTreeSet<u8>>,
    /// Server's long-term keypair
    server_keys: KeyPair,
    /// Server's signing key (Ed25519)
    signing_key: ed25519_dalek::SigningKey,
    /// Default mask profile
    default_mask: MaskProfile,
    /// Configurable session hard timeout
    hard_timeout: Duration,
    /// Configurable session idle timeout
    idle_timeout: Duration,
}

impl SessionManager {
    pub fn new(
        server_keys: KeyPair,
        signing_key: ed25519_dalek::SigningKey,
        default_mask: MaskProfile,
    ) -> Self {
        Self::with_timeouts(server_keys, signing_key, default_mask, None, None)
    }

    pub fn with_timeouts(
        server_keys: KeyPair,
        signing_key: ed25519_dalek::SigningKey,
        default_mask: MaskProfile,
        session_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Self {
        let hard_timeout = session_timeout_secs
            .map(|s| Duration::from_secs(s))
            .unwrap_or(HARD_TIMEOUT);
        let idle_timeout = idle_timeout_secs
            .map(|s| Duration::from_secs(s))
            .unwrap_or(IDLE_TIMEOUT);
        Self {
            sessions: DashMap::new(),
            tag_map: DashMap::new(),
            vpn_ip_map: DashMap::new(),
            ip_pool: Mutex::new((2..=254u8).collect()),
            server_keys,
            signing_key,
            default_mask,
            hard_timeout,
            idle_timeout,
        }
    }

    /// Cheap handshake tag pre-check used to gate the expensive `create_session`
    /// during the pre-auth handshake scan (DoS hardening).
    ///
    /// `create_session` does two X25519 DHs, an Ed25519 signature, ~767 keyed
    /// hashes to populate the tag windows, and three O(session_count) scans of
    /// the session table — all before the tag is even checked. The handshake
    /// scan runs it for every (registered client × candidate mask) pair per
    /// admitted packet, so a spoofed-source UDP flood against a server with many
    /// registered clients drove CPU cost as O(clients × masks) per packet.
    ///
    /// This does only ONE DH + key derivation + a handful of tag computations.
    /// A handshake init packet is always sent with counter 0, so checking a small
    /// counter range across the current ±1 time windows matches every legitimate
    /// handshake (mirroring `Session::validate_tag`'s window logic) while letting
    /// the scan skip `create_session` entirely for the overwhelming majority of
    /// non-matching (client, mask) candidates.
    pub fn handshake_tag_precheck(
        &self,
        eph_pub: &[u8; X25519_PUBLIC_KEY_SIZE],
        preshared_key: Option<[u8; 32]>,
        cand_tag: &[u8; TAG_SIZE],
    ) -> bool {
        let Ok(dh1) = self.server_keys.compute_shared(eph_pub) else {
            return false;
        };
        self.handshake_tag_precheck_inner(eph_pub, preshared_key, cand_tag, &dh1)
    }

    /// FORK-B of the pool-sync redesign: identical cheap pre-check as
    /// `handshake_tag_precheck`, but for a sibling aivpn server dialing us as
    /// a masked pool-client. The DH uses the shared pool server keypair
    /// (`static_kp`, derived from `sync_key` via `crypto::pool_server_keypair`)
    /// instead of `self.server_keys`, since the dialer computed its side of
    /// DH1 against that shared keypair's public key, not our real long-term
    /// server static key.
    pub fn handshake_tag_precheck_with_static(
        &self,
        eph_pub: &[u8; X25519_PUBLIC_KEY_SIZE],
        preshared_key: Option<[u8; 32]>,
        cand_tag: &[u8; TAG_SIZE],
        static_kp: &crypto::KeyPair,
    ) -> bool {
        let Ok(dh1) = static_kp.compute_shared(eph_pub) else {
            return false;
        };
        self.handshake_tag_precheck_inner(eph_pub, preshared_key, cand_tag, &dh1)
    }

    /// Shared tag-search loop behind `handshake_tag_precheck` and
    /// `handshake_tag_precheck_with_static` — the two differ only in which
    /// key material produces `dh1`; everything after that (session-key
    /// derivation + windowed tag search) is identical.
    fn handshake_tag_precheck_inner(
        &self,
        eph_pub: &[u8; X25519_PUBLIC_KEY_SIZE],
        preshared_key: Option<[u8; 32]>,
        cand_tag: &[u8; TAG_SIZE],
        dh1: &[u8; 32],
    ) -> bool {
        // Small counter window — init is counter 0; a few extra tolerate the rare
        // case where the very first datagram reordered ahead of the init is the
        // one that reaches the scan.
        const HANDSHAKE_TAG_SEARCH: u64 = 16;
        let keys = crypto::derive_session_keys(dh1, preshared_key.as_ref(), eph_pub);
        let now = crypto::current_timestamp_ms();
        let base_tw = crypto::compute_time_window(now, DEFAULT_WINDOW_MS);
        // ±2 windows of clock-skew tolerance for the 0-RTT handshake. Data-plane
        // validation stays at ±1 (see validate_tag); handshakes get an extra
        // window because mobile clients with a poor RTC otherwise fail to
        // establish at all — a one-time cost bounded by HANDSHAKE_TAG_SEARCH.
        for tw in HANDSHAKE_SKEW_WINDOWS
            .iter()
            .map(|d| base_tw.wrapping_add(*d as u64))
        {
            for counter in 0..=HANDSHAKE_TAG_SEARCH {
                let expected = crypto::generate_resonance_tag(&keys.tag_secret, counter, tw);
                if bool::from(expected.ct_eq(cand_tag)) {
                    return true;
                }
            }
        }
        false
    }

    /// Create new session from initial packet.
    /// NOTE: Does NOT remove old sessions for the same client IP.
    /// The caller must call `cleanup_old_sessions_for_ip()` after
    /// validating that the new session is legitimate (tag matches).
    pub fn create_session(
        &self,
        client_addr: SocketAddr,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
        preshared_key: Option<[u8; 32]>,
        static_vpn_ip: Option<Ipv4Addr>,
    ) -> Result<Arc<Mutex<Session>>> {
        // Look for a reusable VPN IP from an existing session for the same
        // client IP, but do NOT remove the old session yet — the caller
        // will do that only after the handshake tag validates.
        let reused_vpn_ip: Option<Ipv4Addr> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.client_addr.ip() == client_addr.ip() {
                    session.vpn_ip
                } else {
                    None
                }
            })
            .next();

        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Error::Session("Max sessions reached".into()));
        }

        // MED-6: Per-IP session limit (max 5 sessions per IP)
        let ip_count = self
            .sessions
            .iter()
            .filter(|e| e.value().lock().client_addr.ip() == client_addr.ip())
            .count();
        if ip_count >= 5 {
            return Err(Error::Session("Per-IP session limit reached".into()));
        }

        // Prevent VPN IP pool exhaustion: cap concurrent sessions per /24 subnet.
        // The per-IP cap of 5 alone is insufficient — a spoofed-source flood from
        // 51 distinct IPs in one /24 can drain all 253 assignable VPN addresses
        // while remaining within the per-IP limit.
        if let std::net::IpAddr::V4(v4) = client_addr.ip() {
            let subnet24 = u32::from(v4) >> 8;
            let subnet_count = self
                .sessions
                .iter()
                .filter(|e| {
                    if let std::net::IpAddr::V4(ip) = e.value().lock().client_addr.ip() {
                        (u32::from(ip) >> 8) == subnet24
                    } else {
                        false
                    }
                })
                .count();
            if subnet_count >= 10 {
                return Err(Error::Session(
                    "Per-subnet (/24) session limit reached".into(),
                ));
            }
        }

        // DH1: server_static * client_eph → initial keys (0-RTT)
        let dh1 = self.server_keys.compute_shared(&eph_pub)?;

        let session =
            self.build_and_insert_session(client_addr, eph_pub, dh1, preshared_key, false)?;
        let session_id = session.lock().session_id;

        // Assign VPN IP and register mapping.
        // Priority: 1) static IP from client config, 2) reused IP, 3) auto-assign
        let vpn_ip = if let Some(ip) = static_vpn_ip.or(reused_vpn_ip) {
            // Static or reused IP — ensure it's removed from the free pool
            self.ip_pool.lock().remove(&ip.octets()[3]);
            Some(ip)
        } else {
            // Allocate the lowest available IP from the pool
            self.ip_pool
                .lock()
                .pop_first()
                .map(|octet| Ipv4Addr::new(10, 0, 0, octet))
        };

        if let Some(vpn_ip) = vpn_ip {
            session.lock().vpn_ip = Some(vpn_ip);
            self.vpn_ip_map.insert(vpn_ip, session_id);
            debug!("Assigned VPN IP {} to session", vpn_ip);
        }

        Ok(session)
    }

    /// FORK-B of the pool-sync redesign: register a session for a sibling
    /// aivpn server that dialed us as a control-only masked pool-client, to
    /// run DB anti-entropy (`ControlPayload::PoolSync` / `PoolStateDigest`).
    ///
    /// Unlike `create_pool_peer_session` (a synthetic, handshake-free,
    /// static-key cluster session forced onto FIXED cluster framing), this
    /// rides the SAME masked-handshake machinery as `create_session` — DH1
    /// against the shared `pool_kp` (= `crypto::pool_server_keypair(sync_key)`)
    /// with `pool_psk` (= `crypto::pool_client_psk(sync_key)`) as the initial
    /// PSK, followed by the identical PFS ratchet prep + ServerHello signature
    /// + tag-window population — so the dialer's normal ServerHello/ratchet/
    /// MaskUpdate flow works completely unchanged and the session uses normal
    /// mask framing, not cluster framing.
    ///
    /// No VPN IP is assigned (no `ip_pool`/`vpn_ip_map` touched) and the
    /// per-IP (5) / per-subnet (10) caps in `create_session` are bypassed —
    /// those caps defend against unauthenticated, spoofable client floods,
    /// whereas this peer is already authenticated by the pool-client PSK.
    /// The `MAX_SESSIONS` guard is still enforced.
    pub fn create_masked_pool_peer_session(
        &self,
        client_addr: SocketAddr,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
        pool_kp: &crypto::KeyPair,
        pool_psk: &[u8; 32],
    ) -> Result<Arc<Mutex<Session>>> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Error::Session("Max sessions reached".into()));
        }

        // DH1: shared pool server keypair * dialer's ephemeral pub → initial keys
        let dh1 = pool_kp.compute_shared(&eph_pub)?;

        self.build_and_insert_session(client_addr, eph_pub, dh1, Some(*pool_psk), true)
    }

    /// Shared core of `create_session` and `create_masked_pool_peer_session`:
    /// derive initial keys from the caller-supplied `dh1` + PSK, run PFS
    /// ratchet preparation (fresh server ephemeral keypair, DH2, ratcheted
    /// keys, ServerHello signature), build the `Session`, populate both tag
    /// windows into `tag_map`, and insert the session into `self.sessions`.
    ///
    /// Does NOT touch VPN-IP assignment or any session-count/rate caps —
    /// callers handle those before/after, since the two session kinds differ
    /// there (a masked pool peer gets no VPN IP and bypasses the per-IP/
    /// per-subnet caps that only defend against unauthenticated client
    /// floods).
    fn build_and_insert_session(
        &self,
        client_addr: SocketAddr,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
        dh1: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        is_masked_pool_peer: bool,
    ) -> Result<Arc<Mutex<Session>>> {
        // Never log key material (DH shared secret, PSK, tag_secret) — even at
        // trace, RUST_LOG is operator-controllable and these secrets are what
        // make sessions unlinkable. eph_pub is a public key, so it is safe to log.
        trace!(
            "Server eph_pub (after deobfuscation): {}",
            hex::encode(&eph_pub)
        );
        let initial_keys = crypto::derive_session_keys(&dh1, preshared_key.as_ref(), &eph_pub);

        // --- CRIT-3 + HIGH-6: PFS ratchet preparation ---
        // Generate server ephemeral keypair
        let server_eph_kp = crypto::KeyPair::generate();
        let server_eph_pub = server_eph_kp.public_key_bytes();

        // DH2: server_eph * client_eph → PFS keys
        let dh2 = server_eph_kp.compute_shared(&eph_pub)?;
        // Use initial session_key as PSK for domain separation
        let ratcheted_keys =
            crypto::derive_session_keys(&dh2, Some(&initial_keys.session_key), &eph_pub);

        // Sign (server_eph_pub || client_eph_pub) for server authentication (HIGH-6)
        use ed25519_dalek::Signer;
        let mut sign_message = Vec::with_capacity(64);
        sign_message.extend_from_slice(&server_eph_pub);
        sign_message.extend_from_slice(&eph_pub);
        let signature = self.signing_key.sign(&sign_message).to_bytes();

        // Generate session ID
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);

        // Create session with initial (DH1) keys
        let session = Arc::new(Mutex::new(Session::new(
            session_id,
            client_addr,
            initial_keys,
            eph_pub,
        )));

        // Setup ratchet state + populate tag maps
        {
            let mut sess = session.lock();
            sess.state = SessionState::Active;

            // Store ratchet data
            sess.server_eph_pub = Some(server_eph_pub);
            sess.server_hello_signature = Some(signature);
            sess.ratcheted_keys = Some(ratcheted_keys);
            sess.is_masked_pool_peer = is_masked_pool_peer;

            // Compute initial tags
            sess.update_tag_window();
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }

            // Pre-compute ratcheted tags (for when client switches to PFS keys)
            sess.update_ratcheted_tag_window();
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }
        }

        // Insert into session map
        self.sessions.insert(session_id, session.clone());

        Ok(session)
    }

    /// Remove all sessions for a given IP except the specified one.
    /// Called after a new handshake is validated to clean up stale sessions.
    /// Returns list of removed session IDs (for stopping recordings).
    pub fn cleanup_old_sessions_for_ip(
        &self,
        ip: &std::net::IpAddr,
        keep_session_id: &[u8; 16],
    ) -> Vec<[u8; 16]> {
        let to_remove: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.client_addr.ip() == *ip && entry.key() != keep_session_id {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let mut removed = Vec::new();
        for session_id in to_remove {
            info!(
                "Removing stale session for IP {} after successful re-handshake",
                ip
            );
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }

    /// B1 fix companion: dedup masked pool-client peer sessions from the same
    /// source IP. Unlike `cleanup_old_sessions_for_ip`, this ONLY removes
    /// sessions with `is_masked_pool_peer == true` — ordinary client, pool-peer
    /// (`is_pool_peer`), and site-peer (`is_site_peer`) sessions from that same
    /// IP are never touched, since a masked pool-client dialer's source IP can
    /// legitimately be a sibling aivpn node that also happens to be a normal
    /// client's egress (or vice versa) and those session kinds have entirely
    /// separate dedup rules already.
    ///
    /// `create_masked_pool_peer_session` gives every dialer handshake a fresh
    /// random session_id (`build_and_insert_session`, unlike the deterministic
    /// `create_pool_peer_session`), and masked peers have neither a `vpn_ip`
    /// nor a `client_id`, so none of the existing dedup paths
    /// (`cleanup_old_sessions_for_ip`/`_vpn_ip`/`_client_id`) ever fire for
    /// them. Without an explicit dedup call, every reconnect from a legitimate
    /// dialer (backoff 2–30 s, see `pool_dialer.rs`) — or every handshake from
    /// anyone who knows the pool-client PSK — piles up a new permanent session
    /// instead of replacing the old one. The caller (gateway, after a masked
    /// handshake validates) is expected to call this right after
    /// `create_masked_pool_peer_session` succeeds, mirroring how
    /// `create_session` callers must call `cleanup_old_sessions_for_ip`.
    ///
    /// Returns the list of removed session IDs (for stopping recordings, etc.,
    /// mirroring the other `cleanup_*` helpers — masked peers never have
    /// recordings in practice, but the shape stays consistent).
    pub fn cleanup_masked_peer_sessions_for_ip(
        &self,
        ip: &std::net::IpAddr,
        keep_session_id: &[u8; 16],
    ) -> Vec<[u8; 16]> {
        let to_remove: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.is_masked_pool_peer
                    && session.client_addr.ip() == *ip
                    && entry.key() != keep_session_id
                {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let mut removed = Vec::new();
        for session_id in to_remove {
            info!(
                "Removing stale masked pool-peer session for IP {} after successful re-handshake",
                ip
            );
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }

    /// Remove old sessions for the same VPN IP (same client) except the
    /// specified one. Unlike `cleanup_old_sessions_for_ip`, this does NOT
    /// affect sessions belonging to other clients behind the same NAT.
    /// Returns list of removed session IDs (for stopping recordings).
    pub fn cleanup_old_sessions_for_vpn_ip(
        &self,
        vpn_ip: &Ipv4Addr,
        keep_session_id: &[u8; 16],
    ) -> Vec<[u8; 16]> {
        let to_remove: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.vpn_ip == Some(*vpn_ip) && entry.key() != keep_session_id {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let mut removed = Vec::new();
        for session_id in to_remove {
            info!(
                "Removing stale session for VPN IP {} after successful re-handshake",
                vpn_ip
            );
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }

    /// Remove old sessions for the same authenticated client (by client_id) except
    /// the specified one. Handles reconnects from different source IPs (WiFi → cellular)
    /// where source IP changes but PSK/client_id remains the same.
    pub fn cleanup_old_sessions_for_client_id(
        &self,
        client_id: &str,
        keep_session_id: &[u8; 16],
    ) -> Vec<[u8; 16]> {
        let to_remove: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.client_id.as_deref() == Some(client_id) && entry.key() != keep_session_id
                {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let mut removed = Vec::new();
        for session_id in to_remove {
            info!(
                "Removing stale session for client '{}' after successful re-handshake",
                client_id
            );
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }

    /// Rollback a session that was created but failed tag validation.
    /// Restores vpn_ip_map to the old session that still owns that IP.
    pub fn rollback_failed_session(&self, session_id: &[u8; 16]) {
        // Grab the VPN IP before removal so we can restore the old mapping.
        let vpn_ip = self
            .sessions
            .get(session_id)
            .map(|e| e.value().lock().vpn_ip)
            .flatten();

        self.remove_session(session_id);

        // If there is still another session that owns this VPN IP, restore
        // the mapping and take the IP back out of the free pool.
        if let Some(vpn_ip) = vpn_ip {
            for entry in self.sessions.iter() {
                let sess = entry.value().lock();
                if sess.vpn_ip == Some(vpn_ip) {
                    self.vpn_ip_map.insert(vpn_ip, *entry.key());
                    self.ip_pool.lock().remove(&vpn_ip.octets()[3]);
                    break;
                }
            }
        }
    }

    /// Register a synthetic "cluster session" used for pool-node synchronisation.
    ///
    /// All pool nodes derive identical `SessionKeys` from the shared `sync_key`
    /// (same blake3 KDF domain strings) and the resonance counter is pinned to
    /// a 5-second wall-clock bucket, so every node independently computes the
    /// same expected tag for the same 5-second window — no handshake required.
    pub fn create_pool_peer_session(
        &self,
        sync_key: &[u8; 32],
        peer_addr: std::net::SocketAddr,
    ) -> [u8; 16] {
        let keys = aivpn_common::crypto::SessionKeys {
            session_key: blake3::derive_key("aivpn-pool-enc-v1", sync_key),
            session_key_s2c: blake3::derive_key("aivpn-pool-enc-v1", sync_key),
            tag_secret: blake3::derive_key("aivpn-pool-tag-v1", sync_key),
            prng_seed: blake3::derive_key("aivpn-pool-prng-v1", sync_key),
        };

        // Deterministic session_id — all pool nodes agree on the same value.
        let id_hash = blake3::hash(sync_key);
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&id_hash.as_bytes()[..16]);

        let counter = crypto::current_timestamp_ms() / 5_000;

        let session_arc = {
            let mut s = Session::new(session_id, peer_addr, keys, [0u8; X25519_PUBLIC_KEY_SIZE]);
            s.state = SessionState::Active;
            s.counter = counter;
            s.is_pool_peer = true;
            s.update_tag_window();
            Arc::new(Mutex::new(s))
        };

        {
            let sess = session_arc.lock();
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }
        }

        // Bypass MAX_SESSIONS cap — synthetic sessions don't count against client quota.
        self.sessions.insert(session_id, session_arc);
        info!(
            "pool_sync: cluster session registered ({} tag slots)",
            TAG_WINDOW_SIZE * 2 - 1
        );
        session_id
    }

    /// Register a synthetic session for an authenticated site-to-site peer.
    /// Identical to `create_pool_peer_session` but marks `is_site_peer = true`
    /// so the gateway will accept `RouteSync` messages from this session.
    /// Like pool peers, site peers bypass the `MAX_SESSIONS` cap — synthetic sessions
    /// must not consume the client quota.
    pub fn create_site_peer_session(
        &self,
        sync_key: &[u8; 32],
        peer_addr: std::net::SocketAddr,
        peer_name: &str,
    ) -> [u8; 16] {
        let keys = aivpn_common::crypto::SessionKeys {
            session_key: blake3::derive_key("aivpn-pool-enc-v1", sync_key),
            session_key_s2c: blake3::derive_key("aivpn-pool-enc-v1", sync_key),
            tag_secret: blake3::derive_key("aivpn-pool-tag-v1", sync_key),
            prng_seed: blake3::derive_key("aivpn-pool-prng-v1", sync_key),
        };

        // Deterministic session_id per (sync_key, peer_name) pair.
        let mut id_input = sync_key.to_vec();
        id_input.extend_from_slice(peer_name.as_bytes());
        let id_hash = blake3::hash(&id_input);
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&id_hash.as_bytes()[..16]);

        let counter = crypto::current_timestamp_ms() / 5_000;

        let session_arc = {
            let mut s = Session::new(session_id, peer_addr, keys, [0u8; X25519_PUBLIC_KEY_SIZE]);
            s.state = SessionState::Active;
            s.counter = counter;
            s.is_site_peer = true;
            s.update_tag_window();
            Arc::new(Mutex::new(s))
        };

        {
            let sess = session_arc.lock();
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }
        }

        self.sessions.insert(session_id, session_arc);
        info!(
            "site_sync: peer session registered for '{}' ({} tag slots)",
            peer_name,
            TAG_WINDOW_SIZE * 2 - 1
        );
        session_id
    }

    /// Advance the synthetic cluster session's tag window to the current 5-second
    /// time bucket.  Call every ≤60 s to keep expected-tag map aligned with wall
    /// time and to refresh `last_seen` so the session is not idle-evicted.
    pub fn refresh_pool_peer_tags(&self, session_id: &[u8; 16]) {
        if let Some(entry) = self.sessions.get(session_id) {
            let old_tags: Vec<[u8; TAG_SIZE]> = {
                entry
                    .value()
                    .lock()
                    .expected_tags
                    .values()
                    .cloned()
                    .collect()
            };
            for t in &old_tags {
                self.tag_map.remove(t);
            }
            let mut sess = entry.value().lock();
            sess.counter = crypto::current_timestamp_ms() / 5_000;
            sess.last_seen = std::time::Instant::now();
            sess.update_tag_window();
            for t in sess.expected_tags.values() {
                self.tag_map.insert(*t, *session_id);
            }
        }
    }

    /// Get session by tag (O(1) lookup)
    pub fn get_session_by_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<Arc<Mutex<Session>>> {
        if let Some(entry) = self.tag_map.get(tag) {
            let session_id = *entry;
            drop(entry);
            self.sessions.get(&session_id).map(|e| e.clone())
        } else {
            None
        }
    }

    /// Whether an active session is already bound to this exact peer address.
    ///
    /// A packet from such a peer that misses the tag lookup is a stale or
    /// out-of-window packet from a live tunnel, not an unknown host probing the
    /// port — the handshake-failure cooldown must not fire on it, or the peer
    /// locks itself out of its own reconnect. Linear over the session table,
    /// which only runs on the already-rate-limited handshake failure path.
    pub fn has_session_for_addr(&self, addr: &SocketAddr) -> bool {
        self.sessions
            .iter()
            .any(|entry| entry.value().lock().client_addr == *addr)
    }

    /// Refresh stale tag windows (time window may have advanced) and try to
    /// find a session matching the given tag.
    ///
    /// DoS containment: a fallback miss used to rebuild EVERY session's tag
    /// windows (O(sessions × window) BLAKE3 per miss) and run the expensive
    /// `validate_tag` (with its on-the-fly ±1-window search) against every
    /// session — an attacker-influenceable CPU amplifier. Now the rebuild is
    /// skipped for sessions whose windows are already current (amortized to
    /// once per session per time window), and full validation only runs for
    /// sessions belonging to the packet's source IP (mirroring
    /// `recover_session_by_tag`'s scoping). Roamed clients whose windows were
    /// stale are still recovered by the caller's O(1) re-probe of the
    /// refreshed `tag_map`.
    pub fn refresh_and_find_by_tag(
        &self,
        tag: &[u8; TAG_SIZE],
        client_ip: &std::net::IpAddr,
    ) -> Option<(Arc<Mutex<Session>>, u64, bool)> {
        let current_tw =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        for entry in self.sessions.iter() {
            let session = entry.value().clone();
            let session_id = *entry.key();
            let mut sess = session.lock();

            if sess.tag_window_tw != current_tw {
                // Refresh initial key tags
                let old_tags: Vec<[u8; TAG_SIZE]> = sess.expected_tags.values().cloned().collect();
                for old_tag in &old_tags {
                    self.tag_map.remove(old_tag);
                }
                sess.update_tag_window();
                for t in sess.expected_tags.values() {
                    self.tag_map.insert(*t, session_id);
                }

                // Refresh ratcheted key tags
                let old_ratcheted: Vec<[u8; TAG_SIZE]> =
                    sess.ratcheted_expected_tags.values().cloned().collect();
                for old_tag in &old_ratcheted {
                    self.tag_map.remove(old_tag);
                }
                sess.update_ratcheted_tag_window();
                for t in sess.ratcheted_expected_tags.values() {
                    self.tag_map.insert(*t, session_id);
                }
            }

            // Try to validate the tag now (only for this source IP's sessions)
            if sess.client_addr.ip() == *client_ip {
                if let Some((counter, is_ratcheted)) = sess.validate_tag(tag) {
                    drop(sess);
                    return Some((session, counter, is_ratcheted));
                }
            }
        }
        None
    }

    /// Wide-range counter recovery: brute-force search over a large counter
    /// range to recover from counter drift (e.g., client race condition).
    /// Only called when normal tag lookup + refresh both fail but a session
    /// exists for this client IP.
    pub fn recover_session_by_tag(
        &self,
        tag: &[u8; TAG_SIZE],
        client_ip: &std::net::IpAddr,
    ) -> Option<(Arc<Mutex<Session>>, u64, bool)> {
        let current_tw =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        // Bounded forward-only search ahead of the session's last known
        // counter. The former forward-only 65536 window meant 3 × 65 536 ≈
        // 196k BLAKE3 per matching session — a spoofed tag from a known client
        // IP could force the full scan (CPU-DoS). 2048 (2049 × 3 ≈ 6k) still
        // absorbs realistic counter drift from a client race while capping
        // the attacker's work; the per-IP session limit (5) bounds the total.
        //
        // M2: the search is FORWARD-only because the client counter is
        // monotone — legitimate drift is always the client running AHEAD of
        // the server (the documented client-race case). A backward match can
        // only be a replayed old packet; accepting it used to rewind
        // `s.counter`, so the next legitimate packet shifted the replay
        // bitmap by ≥ TAG_WINDOW_SIZE and wiped the session's whole
        // anti-replay history (ReplayWindow::clear).
        const RECOVERY_RANGE: u64 = 2048;

        for entry in self.sessions.iter() {
            let session = entry.value().clone();
            let session_id = *entry.key();
            let (base, tag_secret) = {
                let sess = session.lock();
                if sess.client_addr.ip() != *client_ip {
                    continue;
                }
                // Copy [u8;32] (Copy type) and release the mutex before the
                // BLAKE3 iterations that would otherwise hold it.
                (sess.counter, sess.keys.tag_secret)
            };

            for tw_offset in [0i64, -1, 1] {
                let tw = (current_tw as i64 + tw_offset) as u64;
                for i in 0..=RECOVERY_RANGE {
                    let c = base.wrapping_add(i);
                    let expected = crypto::generate_resonance_tag(&tag_secret, c, tw);
                    if bool::from(expected.ct_eq(tag)) {
                        // c > base is fresh by construction (`counter` is the
                        // highest validated counter). c == base is fresh only
                        // when the newest counter was never marked received
                        // (fresh session); otherwise this is a replay of the
                        // latest packet — reject without touching state.
                        if c == base && session.lock().received_bitmap.get_bit(0) {
                            debug!(
                                "Counter recovery: counter {} already received — \
                                 rejecting replay",
                                c
                            );
                            return None;
                        }
                        info!(
                            "Counter recovery: found counter {} (drift=+{}) for session",
                            c, i
                        );
                        // Update tag window to the recovered counter (mutex already released).
                        {
                            let mut s = session.lock();
                            // Collect old tags before updating window so we can
                            // do targeted removal (retain would create a visibility gap).
                            let old_tags: Vec<[u8; TAG_SIZE]> =
                                s.expected_tags.values().cloned().collect();
                            // Shift the replay bitmap and mark this counter
                            // received (ingress marks it again — idempotent).
                            s.mark_tag_received(c);
                            s.update_tag_window();
                            for t in &old_tags {
                                self.tag_map.remove(t);
                            }
                            for t in s.expected_tags.values() {
                                self.tag_map.insert(*t, session_id);
                            }
                        }
                        return Some((session, c, false));
                    }
                }
            }
        }
        None
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &[u8; 16]) -> Option<Arc<Mutex<Session>>> {
        self.sessions.get(session_id).map(|e| e.clone())
    }

    /// Get session by VPN IP (for routing TUN responses back to clients)
    pub fn get_session_by_vpn_ip(&self, vpn_ip: &Ipv4Addr) -> Option<Arc<Mutex<Session>>> {
        if let Some(entry) = self.vpn_ip_map.get(vpn_ip) {
            let session_id = *entry;
            drop(entry);
            if let Some(sess) = self.sessions.get(&session_id).map(|e| e.clone()) {
                return Some(sess);
            }
            // Map points at a session that no longer exists (removed without the
            // map being cleaned). Fall through to the self-healing scan below.
        }
        // Self-heal: the fast index missed, but a live session may still own this
        // VPN IP (its map entry can be lost to a reconnect/duplicate-handshake
        // race in create_session/rollback that overwrites vpn_ip_map before tag
        // validation). Without this, downlink to that IP is a permanent
        // blackhole — the client uploads fine (tag-matched) but receives nothing,
        // trips its RX watchdog, and reconnects forever. The scan runs only on a
        // miss (the cold path), so it costs nothing on the hot downlink path.
        let repaired = self.sessions.iter().find_map(|entry| {
            if entry.value().lock().vpn_ip == Some(*vpn_ip) {
                Some((*entry.key(), entry.value().clone()))
            } else {
                None
            }
        });
        if let Some((session_id, sess)) = repaired {
            self.vpn_ip_map.insert(*vpn_ip, session_id);
            debug!(
                "Repaired lost vpn_ip_map entry for {} on downlink miss",
                vpn_ip
            );
            return Some(sess);
        }
        None
    }

    /// Make `session_id` the authoritative owner of `vpn_ip` in the downlink
    /// index. Called at the end of a successful handshake (after old-session
    /// cleanup) so a concurrent duplicate/reconnect handshake that overwrote
    /// `vpn_ip_map` while its own tag validation was still pending can never
    /// leave the winning session without a downlink mapping.
    pub fn bind_vpn_ip(&self, vpn_ip: &Ipv4Addr, session_id: &[u8; 16]) {
        self.vpn_ip_map.insert(*vpn_ip, *session_id);
    }

    /// Remove session and return its ID if it existed.
    /// The returned session_id can be used to stop active recording.
    pub fn remove_session(&self, session_id: &[u8; 16]) -> Option<[u8; 16]> {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            let sess = session.lock();
            // Remove all tags from tag map (initial + ratcheted + pre-ratchet grace)
            for tag in sess.expected_tags.values() {
                self.tag_map.remove(tag);
            }
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.remove(tag);
            }
            for tag in sess.pre_ratchet_tags.values() {
                self.tag_map.remove(tag);
            }
            // Remove VPN IP mapping only if it still points to THIS session.
            // A newer session may have already claimed the same VPN IP.
            if let Some(vpn_ip) = sess.vpn_ip {
                if self
                    .vpn_ip_map
                    .remove_if(&vpn_ip, |_, sid| sid == session_id)
                    .is_some()
                {
                    // No other session owns this IP — return it to the free pool
                    let octet = vpn_ip.octets()[3];
                    if octet >= 2 {
                        self.ip_pool.lock().insert(octet);
                    }
                }
            }
            Some(*session_id)
        } else {
            None
        }
    }

    /// Refresh tag_map after session's tag window has been updated
    pub fn refresh_session_tags(&self, session_id: &[u8; 16]) {
        if let Some(session) = self.sessions.get(session_id) {
            let sess = session.lock();
            // Remove only this session's tags by iterating its own expected_tags
            // rather than scanning the entire global tag_map with retain().
            // Collect old tags first to avoid holding lock during removal.
            let old_tags: Vec<[u8; TAG_SIZE]> = self
                .tag_map
                .iter()
                .filter(|e| e.value() == session_id)
                .map(|e| *e.key())
                .collect();
            for tag in &old_tags {
                self.tag_map.remove(tag);
            }
            // Re-add current tags
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
            // Keep pre-ratchet grace tags resolvable O(1) while the grace
            // window is still open (in-flight old-key packets at a rekey seam).
            if sess
                .pre_ratchet_expire
                .is_some_and(|expire| Instant::now() < expire)
            {
                for tag in sess.pre_ratchet_tags.values() {
                    self.tag_map.insert(*tag, *session_id);
                }
            }
        }
    }

    /// Complete PFS ratchet for a session: switch to ratcheted keys, remove old tags
    pub fn complete_session_ratchet(&self, session_id: &[u8; 16]) {
        if let Some(session) = self.sessions.get(session_id) {
            let mut sess = session.lock();
            if sess.ratcheted_keys.is_none() {
                return; // nothing to ratchet — complete_ratchet would be a no-op
            }
            // Purge any PREVIOUS grace window's tags. The current initial-key
            // tags deliberately STAY in the tag_map: complete_ratchet moves
            // them into pre_ratchet_tags, and keeping them mapped preserves
            // the O(1) lookup path for in-flight old-key packets during the
            // grace window (see commit_session_rekey). Expired grace tags are
            // purged by cleanup_expired.
            for tag in sess.pre_ratchet_tags.values() {
                self.tag_map.remove(tag);
            }
            // Complete the ratchet (swaps keys, moves ratcheted_expected_tags → expected_tags)
            sess.complete_ratchet();
            // Re-add the now-active tags (which were the ratcheted tags)
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
        }
    }

    /// Cleanup expired sessions and return list of removed session IDs.
    /// The returned IDs can be used to stop active recordings.
    pub fn cleanup_expired(&self) -> Vec<[u8; 16]> {
        // Purge pre-ratchet grace tags whose window has expired from the
        // global tag_map (they are kept there during the grace window so
        // in-flight old-key packets keep the O(1) lookup path).
        let now = Instant::now();
        for entry in self.sessions.iter() {
            let mut sess = entry.value().lock();
            if sess.pre_ratchet_expire.is_some_and(|expire| now >= expire) {
                for tag in sess.pre_ratchet_tags.values() {
                    self.tag_map.remove(tag);
                }
                sess.pre_ratchet_tags.clear();
                sess.pre_ratchet_received.clear();
                sess.pre_ratchet_expire = None;
                sess.pre_ratchet_keys = None;
            }
        }

        let expired: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|e| {
                let sess = e.value().lock();
                // Synthetic pool/site peer sessions must never idle-expire:
                // they are created once at startup and only kept alive by
                // refresh_pool_peer_tags (every 60 s > idle_timeout) and
                // inbound peer traffic. Evicting one silently kills pool/site
                // sync from that peer until a full restart, because nothing
                // ever re-creates a removed peer session.
                //
                // `is_masked_pool_peer` sessions are deliberately EXCLUDED from
                // this exemption (B1 fix): unlike the synthetic sync_key
                // sessions above, a masked pool-client session is a real,
                // ordinary masked handshake — `build_and_insert_session` runs
                // the identical PFS/keepalive machinery a normal client uses,
                // and the dialer (a normal `AivpnClient` in `control_only`
                // mode, see pool_dialer.rs) sends real protocol Keepalive
                // packets on the same NAT-capped interval (≤25 s) as any
                // client, refreshing `last_seen` well inside the (default
                // 30 s) idle window. So a LIVE dialer session is never
                // wrongly evicted here. Leaving it exempt let every dialer
                // reconnect (or unauthenticated handshake against the
                // pool-client PSK) accumulate a permanent session — no
                // dedup path fires for these (no vpn_ip, no client_id) and
                // nothing else ever removes them — exhausting MAX_SESSIONS
                // in seconds. A dead/gone dialer now ages out normally.
                if sess.is_pool_peer || sess.is_site_peer {
                    return false;
                }
                sess.last_seen.elapsed() > self.idle_timeout
                    || (self.hard_timeout > Duration::ZERO
                        && sess.created_at.elapsed() > self.hard_timeout)
            })
            .map(|e| *e.key())
            .collect();

        let mut removed = Vec::new();
        for session_id in expired {
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }

    /// Get active session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Log diagnostic information about all sessions and tag state
    pub fn log_session_diagnostics(&self, incoming_tag: &[u8; TAG_SIZE]) {
        let tag_map_size = self.tag_map.len();
        let current_tw =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        info!(
            "DIAG: tag_map_size={}, current_tw={}",
            tag_map_size, current_tw
        );
        for entry in self.sessions.iter() {
            let sess = entry.value().lock();
            let sid_hex = format!(
                "{:02x}{:02x}{:02x}{:02x}",
                entry.key()[0],
                entry.key()[1],
                entry.key()[2],
                entry.key()[3]
            );
            let is_ratcheted = sess.is_ratcheted;
            let counter = sess.counter;
            let expected_count = sess.expected_tags.len();
            let ratcheted_count = sess.ratcheted_expected_tags.len();
            let has_ratcheted_keys = sess.ratcheted_keys.is_some();
            // Check if any expected tag matches (manually)
            let mut found = false;
            for (c, t) in &sess.expected_tags {
                if t == incoming_tag {
                    found = true;
                    info!(
                        "DIAG: Session {} — expected tag MATCHES at counter {}",
                        sid_hex, c
                    );
                    break;
                }
            }
            info!(
                "DIAG: Session {} — ratcheted={}, counter={}, expected_tags={}, ratcheted_tags={}, has_ratchet_keys={}, tag_matched={}",
                sid_hex, is_ratcheted, counter, expected_count, ratcheted_count, has_ratcheted_keys, found
            );
        }
    }

    /// Get server public key
    pub fn server_public_key(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.server_keys.public_key_bytes()
    }

    /// Sign mask data
    pub fn sign_mask(&self, mask_data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(mask_data);
        signature.to_bytes()
    }

    /// Iterate over all sessions (for neural resonance checks)
    pub fn iter_sessions(&self) -> dashmap::iter::Iter<'_, [u8; 16], Arc<Mutex<Session>>> {
        self.sessions.iter()
    }

    /// Schedule a deferred mask switch for a session.
    /// The MaskUpdate control message has already been sent to the client;
    /// we store the new mask in `pending_mask` and let it activate after a
    /// grace period (see `commit_pending_mask`).
    pub fn update_session_mask(
        &self,
        session_id: &[u8; 16],
        new_mask: MaskProfile,
    ) -> Option<(Arc<Mutex<Session>>, SocketAddr)> {
        if let Some(session) = self.sessions.get(session_id) {
            let client_addr;
            {
                let mut sess = session.lock();
                info!(
                    "Session mask scheduled: {} → {} (grace period 500ms)",
                    sess.mask
                        .as_ref()
                        .map(|m| m.mask_id.as_str())
                        .unwrap_or("default"),
                    new_mask.mask_id
                );
                // Don't switch immediately — store as pending
                sess.pending_mask = Some((new_mask, Instant::now()));
                sess.state = SessionState::Active;
                client_addr = sess.client_addr;
            }
            Some((session.clone(), client_addr))
        } else {
            None
        }
    }

    /// Build an encrypted MaskUpdate control packet for the given session.
    /// Returns the raw UDP datagram bytes ready to send.
    pub fn build_mask_update_packet(
        &self,
        session: &Arc<Mutex<Session>>,
        new_mask: &MaskProfile,
    ) -> Result<Vec<u8>> {
        use aivpn_common::crypto::encrypt_payload;

        // Serialize mask profile → mask_data (MessagePack to match client's rmp_serde::from_slice)
        let mask_data = rmp_serde::to_vec(new_mask)
            .map_err(|e| Error::Session(format!("Failed to serialize mask: {}", e)))?;

        // Sign mask_data with server's Ed25519 key
        let signature = self.sign_mask(&mask_data);

        // Build control payload
        let control = ControlPayload::MaskUpdate {
            mask_data,
            signature,
        };
        let encoded = control.encode()?;

        let mut sess = session.lock();
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: sess.next_seq() as u16,
        };
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);

        // Encrypt (same logic as Gateway::build_packet)
        let (nonce, counter) = sess.next_send_nonce();
        let pad_len = 16u16;
        let mut padded = Vec::with_capacity(2 + inner_payload.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner_payload);
        {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            for _ in 0..pad_len {
                padded.push(rng.gen::<u8>());
            }
        }

        let ciphertext = encrypt_payload(&sess.keys.session_key_s2c, &nonce, &padded)?; // downlink → S2C

        // Generate tag
        let time_window =
            crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let tag = crypto::generate_resonance_tag(&sess.keys.tag_secret, counter, time_window);

        // Wrap MaskUpdate in the session's current mask. The switch to `new_mask`
        // happens only after the packet is successfully delivered.
        let transport_mask = sess.mask.as_ref().unwrap_or(&self.default_mask);
        let mdh = if let Some(ref spec) = transport_mask.header_spec {
            let mut rng = rand::thread_rng();
            spec.generate(&mut rng)
        } else {
            transport_mask.header_template.clone()
        };

        // Assemble: TAG | MDH | ciphertext
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// Scan all sessions that need rekeying (time or bytes threshold exceeded).
    /// Generates a new ephemeral keypair per session, stores it as pending, and
    /// returns a Vec of (session_id, new_server_eph_pub) for the caller to send
    /// KeyRotate control messages.
    pub fn start_rekeying_sessions(&self) -> Vec<([u8; 16], [u8; X25519_PUBLIC_KEY_SIZE])> {
        let now = Instant::now();
        let mut due: Vec<([u8; 16], [u8; X25519_PUBLIC_KEY_SIZE])> = Vec::new();

        for entry in self.sessions.iter() {
            let session_id = *entry.key();
            let mut sess = entry.value().lock();

            // Skip pool/site peers (synthetic sync_key sessions with no real
            // ephemeral ratchet state) and sessions still pending ratchet.
            //
            // `is_masked_pool_peer` sessions are deliberately NOT skipped here
            // (B3 fix): `build_and_insert_session` runs the same PFS ratchet
            // preparation for a masked pool peer as for a normal client
            // (fresh server ephemeral keypair, DH2, ratcheted keys), so these
            // sessions have real ratchet state and should rotate keys like
            // any other session instead of running on a single static key
            // for the session's entire (potentially days-long) lifetime.
            if sess.is_pool_peer || sess.is_site_peer || !sess.is_ratcheted {
                continue;
            }

            // A KeyRotate for this session is already in flight but no valid
            // rekey response has arrived. Retransmits are driven by the FAST
            // sweep (`rekey_retransmits_due`, every ~2 s gateway tick), not
            // this 30 s initiation tick — riding this tick was slower than
            // the client's RX-silence watchdog (12 s floor), so a lost
            // KeyRotate still cost a full reconnect before healing.
            if sess.pending_rekey_keypair.is_some() {
                continue;
            }

            let time_due = now.duration_since(sess.last_rekey_at).as_secs() >= REKEY_INTERVAL_SECS;
            let bytes_due = sess.bytes_since_rekey >= REKEY_BYTES_THRESHOLD;
            if !time_due && !bytes_due {
                continue;
            }

            let server_rekey_kp = crypto::KeyPair::generate();
            let new_eph_pub = server_rekey_kp.public_key_bytes();
            sess.pending_rekey_keypair = Some(server_rekey_kp);
            sess.pending_rekey_attempts = 1;
            sess.last_keyrotate_sent_at = now;
            // Rebuild the expected-tag window NOW so the pending-rekey
            // forward lookahead (see `update_tag_window`) is populated before
            // the client's response can arrive; the tag_map refresh below
            // publishes it.
            sess.update_tag_window();
            due.push((session_id, new_eph_pub));
        }

        for (session_id, _) in &due {
            self.refresh_session_tags(session_id);
        }

        due
    }

    /// Fast retransmit sweep for pending in-flight rekeys. Called by the
    /// gateway on a SHORT cadence (~2 s tick), decoupled from the 30 s
    /// rekey-INITIATION tick, so a lost KeyRotate is re-sent within
    /// ~`REKEY_RETRANSMIT_SECS` and the client re-syncs BEFORE its RX-silence
    /// watchdog (12–45 s) gives up and reconnects.
    ///
    /// KeyRotate rides plain UDP with no delivery guarantee: if the KeyRotate
    /// (or the client's response) is lost, the pending state would otherwise
    /// stick — every initiation tick skips the session, PFS rotation silently
    /// stops and, on a lost response, both sides desync until a reconnect.
    /// Retransmit the SAME pending eph pub a bounded number of times.
    /// Reusing the keypair is what makes the retransmit idempotent for the
    /// client (identical keys whichever copy it processes; its
    /// duplicate-suppression keys off this exact eph pub), and each
    /// retransmitted packet is encrypted as a normal control message under a
    /// fresh send counter — no (key, nonce) reuse, and data-plane counters
    /// stay monotonic. In-flight old-key uplink at the eventual commit seam
    /// stays covered by the pre_ratchet grace-tag window in
    /// `commit_session_rekey`.
    ///
    /// Returns (session_id, pending_eph_pub) pairs to (re-)send KeyRotate for.
    pub fn rekey_retransmits_due(&self) -> Vec<([u8; 16], [u8; X25519_PUBLIC_KEY_SIZE])> {
        let now = Instant::now();
        let mut due: Vec<([u8; 16], [u8; X25519_PUBLIC_KEY_SIZE])> = Vec::new();

        for entry in self.sessions.iter() {
            let session_id = *entry.key();
            let mut sess = entry.value().lock();

            if sess.pending_rekey_keypair.is_none() {
                continue;
            }
            if now.duration_since(sess.last_keyrotate_sent_at).as_secs() < REKEY_RETRANSMIT_SECS {
                continue; // last send is recent — give the response time to arrive
            }

            if sess.pending_rekey_attempts < MAX_REKEY_SEND_ATTEMPTS {
                sess.pending_rekey_attempts += 1;
                sess.last_keyrotate_sent_at = now;
                let new_eph_pub = sess
                    .pending_rekey_keypair
                    .as_ref()
                    .expect("checked is_some above")
                    .public_key_bytes();
                debug!(
                    "Inline rekey: no response yet — retransmitting KeyRotate \
                     (attempt {}/{})",
                    sess.pending_rekey_attempts, MAX_REKEY_SEND_ATTEMPTS
                );
                due.push((session_id, new_eph_pub));
            } else {
                // All attempts exhausted: clear the stuck pending state so a
                // FRESH rekey (new keypair) can re-initiate after the normal
                // interval, instead of blocking rekeying forever. Bounded so
                // a truly dead client eventually stops being retransmitted to.
                warn!(
                    "Inline rekey: no rekey response after {} KeyRotate sends — \
                     clearing stuck pending rekey (fresh rekey will re-initiate)",
                    MAX_REKEY_SEND_ATTEMPTS
                );
                sess.pending_rekey_keypair = None;
                sess.pending_rekey_attempts = 0;
                sess.last_rekey_at = now;
            }
        }

        due
    }

    /// Complete an in-flight rekey: client has replied with its new ephemeral public key.
    /// Derives new session keys, swaps tag maps, resets counters.
    pub fn commit_session_rekey(
        &self,
        session_id: &[u8; 16],
        client_rekey_eph_pub: &[u8; X25519_PUBLIC_KEY_SIZE],
    ) {
        let session = match self.sessions.get(session_id) {
            Some(s) => s.clone(),
            None => return,
        };

        let mut sess = session.lock();

        let server_rekey_kp = match sess.pending_rekey_keypair.take() {
            Some(kp) => kp,
            None => {
                warn!("commit_session_rekey: no pending keypair for session");
                return;
            }
        };
        sess.pending_rekey_attempts = 0;

        let dh_rekey = match server_rekey_kp.compute_shared(client_rekey_eph_pub) {
            Ok(dh) => dh,
            Err(e) => {
                warn!("commit_session_rekey: DH failed: {}", e);
                return;
            }
        };

        // Mirror exactly what the client does:
        // new_keys = derive_session_keys(&dh_rekey, Some(&current_session_key), &client_rekey_eph_pub)
        let current_session_key = sess.keys.session_key;
        let new_keys = crypto::derive_session_keys(
            &dh_rekey,
            Some(&current_session_key),
            client_rekey_eph_pub,
        );

        // Purge any PREVIOUS grace window's tags, then drop stale ratcheted
        // tags. The CURRENT expected_tags deliberately STAY in the global
        // tag_map: they become pre_ratchet_tags below, and keeping them mapped
        // preserves the O(1) lookup path for in-flight old-key packets during
        // the grace window — the fallback scan is globally rate-limited
        // (20/s), so relying on it drops legitimate packets at the rekey seam
        // under load. Expired grace tags are purged by cleanup_expired.
        for tag in sess.pre_ratchet_tags.values() {
            self.tag_map.remove(tag);
        }
        for tag in sess.ratcheted_expected_tags.values() {
            self.tag_map.remove(tag);
        }

        // Preserve old keys for an RTT-scaled grace window (in-flight packets from client).
        let grace = sess.rekey_grace();
        sess.pre_ratchet_tags = std::mem::take(&mut sess.expected_tags);
        sess.pre_ratchet_expire = Some(Instant::now() + grace);
        sess.pre_ratchet_received.clear();

        // Install new keys, retaining the outgoing ones for the grace window so
        // in-flight old-key packets can actually be decrypted (see
        // `pre_ratchet_keys`) — preserving only their tags is not enough.
        sess.pre_ratchet_keys = Some(std::mem::replace(&mut sess.keys, new_keys));
        // BOTH counters stay MONOTONIC across the inline rekey. The AEAD key
        // changes here (new tag_secret / session_key_s2c / session_key_c2s), so
        // continuing the counters never reuses a (key, nonce) pair.
        //
        // Resetting to 0 stranded the tunnel under load:
        //  * Downlink (s2c, `send_counter`): the client resets its recv-window to
        //    the unsynced state, whose forward tag search is a fixed
        //    [0, RECV_FUTURE_SEARCH_WINDOW) span that cannot advance until it
        //    decodes one packet — so if the 16 sharded downlink workers race past
        //    that span, or its first packets are lost, the client never resyncs
        //    and every downlink packet fails "Invalid resonance tag".
        //  * Uplink (c2s, `counter` + `tag_window_base`): `update_tag_window`
        //    precomputes expected inbound tags in a ±TAG_WINDOW_SIZE band around
        //    `counter`. Reset to 0 that band is [0, 511]; under a simultaneous
        //    heavy upload the client races past 511 while its first c2s packets
        //    are lost, so the server can never match its tags — uplink dies, the
        //    download's inner-TCP ACKs stop, downlink dries up and the client
        //    hits RX-silence and reconnects.
        //
        // Keeping both counters monotonic keeps each side's window synced so it
        // slides with the stream. `update_tag_window()` below rebuilds the c2s
        // expected-tag band around the preserved `counter` with the new
        // tag_secret; the anti-replay bitmap is preserved (monotonic counters
        // never revisit a consumed slot, and the old tags were already dropped
        // from the global map above).
        sess.bytes_since_rekey = 0;
        sess.last_rekey_at = Instant::now();
        sess.ratcheted_expected_tags.clear();

        // Compute new tag window and insert into global map.
        sess.update_tag_window();
        let new_sid = *session_id;
        for tag in sess.expected_tags.values() {
            self.tag_map.insert(*tag, new_sid);
        }

        info!("Session inline rekey complete (new keys installed)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::crypto::{SessionKeys, CHACHA20_KEY_SIZE};

    fn make_keys(seed: u8) -> SessionKeys {
        SessionKeys {
            session_key: [seed; CHACHA20_KEY_SIZE],
            session_key_s2c: [seed; CHACHA20_KEY_SIZE],
            tag_secret: [seed + 1; 32],
            prng_seed: [seed + 2; 32],
        }
    }

    fn make_session() -> Session {
        let session_id = [0u8; 16];
        let addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        Session::new(
            session_id,
            addr,
            make_keys(1),
            [0u8; X25519_PUBLIC_KEY_SIZE],
        )
    }

    // ── RTT-scaled rekey grace (A5) ───────────────────────────────────────────

    #[test]
    fn rekey_grace_floors_at_2s_when_rtt_unknown() {
        let s = make_session();
        assert_eq!(s.client_srtt_ms, 0);
        assert_eq!(s.rekey_grace(), Duration::from_secs(2));
    }

    #[test]
    fn rekey_grace_floors_at_2s_for_low_rtt() {
        let mut s = make_session();
        s.observe_client_rtt(50); // 4×50ms = 200ms < 2s floor
        assert_eq!(s.rekey_grace(), Duration::from_secs(2));
    }

    #[test]
    fn rekey_grace_scales_with_high_rtt() {
        let mut s = make_session();
        // First sample seeds EWMA directly: srtt = 1500ms → 4× = 6s.
        s.observe_client_rtt(1500);
        assert_eq!(s.client_srtt_ms, 1500);
        assert_eq!(s.rekey_grace(), Duration::from_secs(6));
    }

    #[test]
    fn rekey_grace_caps_at_30s() {
        let mut s = make_session();
        s.observe_client_rtt(20_000); // 4×20s = 80s, capped to 30s
        assert_eq!(s.rekey_grace(), Duration::from_secs(30));
    }

    #[test]
    fn observe_client_rtt_is_ewma_after_first_sample() {
        let mut s = make_session();
        s.observe_client_rtt(800);
        assert_eq!(s.client_srtt_ms, 800);
        // (800*7 + 80) / 8 = 710
        s.observe_client_rtt(80);
        assert_eq!(s.client_srtt_ms, 710);
    }

    // ── ReplayWindow bitmap ───────────────────────────────────────────────────

    #[test]
    fn replay_set_and_get_bit_low_range() {
        let mut b = ReplayWindow::default();
        b.set_bit(0);
        assert!(b.get_bit(0));
        assert!(!b.get_bit(1));
    }

    #[test]
    fn replay_set_and_get_bit_word_boundary_63_64() {
        let mut b = ReplayWindow::default();
        b.set_bit(63);
        assert!(b.get_bit(63));
        assert!(!b.get_bit(62));
        assert!(!b.get_bit(64));
        b.set_bit(64);
        assert!(b.get_bit(64));
        assert!(b.get_bit(63));
    }

    #[test]
    fn replay_set_and_get_bit_high_range() {
        let mut b = ReplayWindow::default();
        b.set_bit(128);
        assert!(b.get_bit(128));
        assert!(!b.get_bit(127));
        b.set_bit(TAG_WINDOW_SIZE - 1);
        assert!(b.get_bit(TAG_WINDOW_SIZE - 1));
    }

    #[test]
    fn replay_get_bit_out_of_range_is_false() {
        let mut b = ReplayWindow::default();
        // Setting an out-of-range bit is a no-op, and reading one is false.
        b.set_bit(TAG_WINDOW_SIZE);
        b.set_bit(TAG_WINDOW_SIZE + 1000);
        assert!(!b.get_bit(TAG_WINDOW_SIZE));
        assert!(!b.get_bit(TAG_WINDOW_SIZE + 1000));
    }

    #[test]
    fn replay_shift_left_moves_bits() {
        let mut b = ReplayWindow::default();
        b.set_bit(0);
        b.shift_left(1);
        assert!(!b.get_bit(0));
        assert!(b.get_bit(1));
    }

    #[test]
    fn replay_shift_left_by_window_clears_all() {
        let mut b = ReplayWindow::default();
        b.set_bit(0);
        b.set_bit(TAG_WINDOW_SIZE - 1);
        b.shift_left(TAG_WINDOW_SIZE);
        assert!(!b.get_bit(0));
        assert!(!b.get_bit(TAG_WINDOW_SIZE - 1));
    }

    #[test]
    fn replay_shift_left_across_word_boundary() {
        let mut b = ReplayWindow::default();
        b.set_bit(63);
        b.shift_left(1);
        assert!(!b.get_bit(63));
        assert!(b.get_bit(64));
    }

    #[test]
    fn replay_shift_left_whole_word() {
        let mut b = ReplayWindow::default();
        b.set_bit(3);
        b.set_bit(70);
        b.shift_left(64);
        assert!(!b.get_bit(3));
        assert!(b.get_bit(67));
        assert!(b.get_bit(134));
    }

    #[test]
    fn replay_shift_left_drops_bits_off_the_end() {
        let mut b = ReplayWindow::default();
        b.set_bit(TAG_WINDOW_SIZE - 1);
        b.shift_left(1);
        // Bit shifted past the top of the window must be gone.
        assert!(!b.get_bit(TAG_WINDOW_SIZE - 1));
        for i in 0..TAG_WINDOW_SIZE {
            assert!(!b.get_bit(i), "bit {i} unexpectedly set");
        }
    }

    #[test]
    fn replay_clear_zeroes_all_bits() {
        let mut b = ReplayWindow::default();
        b.set_bit(0);
        b.set_bit(200);
        b.set_bit(TAG_WINDOW_SIZE - 1);
        b.clear();
        assert!(!b.get_bit(0));
        assert!(!b.get_bit(200));
        assert!(!b.get_bit(TAG_WINDOW_SIZE - 1));
    }

    #[test]
    fn replay_multiple_bits_independent() {
        let mut b = ReplayWindow::default();
        b.set_bit(5);
        b.set_bit(130);
        b.set_bit(300);
        assert!(b.get_bit(5));
        assert!(b.get_bit(130));
        assert!(b.get_bit(300));
        assert!(!b.get_bit(6));
        assert!(!b.get_bit(129));
        assert!(!b.get_bit(299));
    }

    // ── Session state & anti-replay ───────────────────────────────────────────

    #[test]
    fn session_initial_state_is_pending() {
        let s = make_session();
        assert!(matches!(s.state, SessionState::Pending));
    }

    #[test]
    fn session_initial_counters_are_zero() {
        let s = make_session();
        assert_eq!(s.counter, 0);
        assert_eq!(s.send_counter, 0);
    }

    #[test]
    fn mark_tag_received_advances_counter() {
        let mut s = make_session();
        s.mark_tag_received(5);
        assert_eq!(s.counter, 5);
    }

    #[test]
    fn mark_tag_received_older_counter_does_not_regress() {
        let mut s = make_session();
        s.mark_tag_received(10);
        s.mark_tag_received(3);
        assert_eq!(s.counter, 10);
    }

    #[test]
    fn replay_detected_after_mark_tag_received() {
        let mut s = make_session();
        s.update_tag_window();

        // Take any precomputed tag from the window.
        let (counter, tag) = s
            .expected_tags
            .iter()
            .next()
            .map(|(&c, &t)| (c, t))
            .expect("expected_tags must be non-empty after update_tag_window");

        // First receipt must be accepted.
        assert!(s.validate_tag(&tag).is_some());

        // Mark it as received.
        s.mark_tag_received(counter);

        // Replay: same tag must be rejected (bitmap bit is now set).
        // Re-generate the window so the tag stays in the lookup table.
        s.update_tag_window();
        assert!(s.validate_tag(&tag).is_none(), "replay must be rejected");
    }

    // ── Inline-rekey robustness (lost KeyRotate / lost response) ────────────

    fn make_manager() -> SessionManager {
        SessionManager::new(
            crypto::KeyPair::generate(),
            ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
            aivpn_common::mask::preset_masks::bootstrap_default(),
        )
    }

    /// A live peer must be recognised by its exact address, so a stale packet
    /// that misses the tag lookup is never charged to the handshake cooldown —
    /// and a neighbour sharing its public IP behind NAT is never mistaken for it.
    #[test]
    fn has_session_for_addr_matches_the_port_not_just_the_ip() {
        let sm = make_manager();
        let peer: SocketAddr = "203.0.113.7:47135".parse().unwrap();
        let neighbour: SocketAddr = "203.0.113.7:38163".parse().unwrap();
        let stranger: SocketAddr = "198.51.100.9:47135".parse().unwrap();

        assert!(!sm.has_session_for_addr(&peer));

        let sid = [7u8; 16];
        sm.sessions.insert(
            sid,
            Arc::new(Mutex::new(Session::new(
                sid,
                peer,
                make_keys(1),
                [0u8; X25519_PUBLIC_KEY_SIZE],
            ))),
        );

        assert!(sm.has_session_for_addr(&peer));
        assert!(
            !sm.has_session_for_addr(&neighbour),
            "another device behind the same NAT must not inherit this session"
        );
        assert!(!sm.has_session_for_addr(&stranger));
    }

    /// Insert a ratcheted session whose last rekey is overdue, so
    /// `start_rekeying_sessions` considers it due on the next tick.
    fn insert_overdue_session(sm: &SessionManager, sid: [u8; 16]) -> Instant {
        let mut s = Session::new(
            sid,
            "127.0.0.1:5555".parse().unwrap(),
            make_keys(1),
            [0u8; X25519_PUBLIC_KEY_SIZE],
        );
        s.is_ratcheted = true;
        let overdue = Instant::now()
            .checked_sub(Duration::from_secs(REKEY_INTERVAL_SECS + 5))
            .expect("host uptime exceeds the rekey interval");
        s.last_rekey_at = overdue;
        sm.sessions.insert(sid, Arc::new(Mutex::new(s)));
        overdue
    }

    /// Backdate the pending rekey's last-send stamp so the fast retransmit
    /// sweep sees it as due (tests can't wait REKEY_RETRANSMIT_SECS of wall
    /// clock).
    fn backdate_last_keyrotate(sm: &SessionManager, sid: &[u8; 16]) {
        let entry = sm.sessions.get(sid).unwrap();
        let mut s = entry.value().lock();
        s.last_keyrotate_sent_at = Instant::now()
            .checked_sub(Duration::from_secs(REKEY_RETRANSMIT_SECS + 1))
            .expect("host uptime exceeds the retransmit interval");
    }

    /// Regression for the inline-rekey deadlock: `start_rekeying_sessions`
    /// used to skip any session with `pending_rekey_keypair.is_some()`, so a
    /// single lost KeyRotate (one-shot UDP, no retransmit) left the pending
    /// state stuck forever — PFS rotation silently stopped for the session.
    /// The fix must (1) RETRANSMIT the SAME pending eph pub for a bounded
    /// number of attempts on the FAST sweep (`rekey_retransmits_due`, ~3 s
    /// cadence — under the client's 12 s RX-silence watchdog floor, so the
    /// tunnel self-heals with ZERO reconnects; same keypair — a fresh one
    /// would permanently desync a client that already committed against the
    /// first one), then (2) clear the stuck state so a fresh rekey can
    /// re-initiate.
    #[test]
    fn stuck_pending_rekey_is_retransmitted_then_cleared() {
        let sm = make_manager();
        let sid = [7u8; 16];
        let overdue = insert_overdue_session(&sm, sid);

        // Initiation tick: rekey due → initial KeyRotate, fresh pending keypair.
        let due1 = sm.start_rekeying_sessions();
        assert_eq!(due1.len(), 1, "overdue session must start rekeying");
        let eph1 = due1[0].1;

        // Immediately after the initial send nothing is due for retransmit
        // (last send is recent) and the initiation tick must SKIP the
        // pending session rather than start a second rekey.
        assert!(
            sm.rekey_retransmits_due().is_empty(),
            "retransmit must wait REKEY_RETRANSMIT_SECS after the last send"
        );
        assert!(
            sm.start_rekeying_sessions().is_empty(),
            "initiation tick must skip a session with a rekey in flight"
        );

        // Fast-sweep ticks with no client response: retransmit the SAME eph.
        for attempt in 2..=MAX_REKEY_SEND_ATTEMPTS {
            backdate_last_keyrotate(&sm, &sid);
            let due = sm.rekey_retransmits_due();
            assert_eq!(
                due.len(),
                1,
                "attempt {attempt}: pending rekey must be retransmitted, not skipped"
            );
            assert_eq!(
                due[0].1, eph1,
                "attempt {attempt}: retransmit must reuse the pending keypair, \
                 never generate a fresh one"
            );
        }

        // Attempts exhausted: stuck pending state is cleared, nothing sent.
        backdate_last_keyrotate(&sm, &sid);
        let after = sm.rekey_retransmits_due();
        assert!(
            after.is_empty(),
            "after {MAX_REKEY_SEND_ATTEMPTS} sends the stuck rekey must be dropped"
        );
        {
            let entry = sm.sessions.get(&sid).unwrap();
            let mut s = entry.value().lock();
            assert!(
                s.pending_rekey_keypair.is_none(),
                "stuck pending rekey must be cleared so rekeying can re-initiate"
            );
            assert_eq!(s.pending_rekey_attempts, 0);
            // The clear reset last_rekey_at (full-interval backoff); make the
            // session due again to prove a FRESH rekey re-initiates.
            s.last_rekey_at = overdue;
        }
        let fresh = sm.start_rekeying_sessions();
        assert_eq!(
            fresh.len(),
            1,
            "cleared session must be able to rekey again"
        );
        assert_ne!(
            fresh[0].1, eph1,
            "re-initiated rekey must use a brand-new keypair"
        );
    }

    /// Regression for the downlink blackhole: a live session owns a VPN IP but
    /// its `vpn_ip_map` entry was lost (a reconnect/duplicate-handshake race can
    /// overwrite it before tag validation, and the loser's rollback does not
    /// restore the winner). `get_session_by_vpn_ip` must self-heal by scanning
    /// live sessions and repairing the map, so downlink never permanently
    /// blackholes while uplink (tag-matched) keeps working.
    #[test]
    fn get_session_by_vpn_ip_self_heals_lost_mapping() {
        let sm = make_manager();
        let sid = [3u8; 16];
        let vpn_ip = Ipv4Addr::new(10, 0, 0, 8);
        let mut s = Session::new(
            sid,
            "127.0.0.1:6000".parse().unwrap(),
            make_keys(2),
            [0u8; X25519_PUBLIC_KEY_SIZE],
        );
        s.vpn_ip = Some(vpn_ip);
        sm.sessions.insert(sid, Arc::new(Mutex::new(s)));

        // Simulate the lost mapping: the session is live but absent from the index.
        assert!(sm.vpn_ip_map.get(&vpn_ip).is_none());

        // Lookup must still find it AND repair the map.
        let found = sm
            .get_session_by_vpn_ip(&vpn_ip)
            .expect("live session must be found via self-healing scan");
        assert_eq!(found.lock().session_id, sid);
        assert_eq!(
            sm.vpn_ip_map.get(&vpn_ip).map(|e| *e),
            Some(sid),
            "map must be repaired after the self-healing scan"
        );

        // bind_vpn_ip makes a given session authoritative for the IP.
        let sid2 = [4u8; 16];
        let mut s2 = Session::new(
            sid2,
            "127.0.0.1:6001".parse().unwrap(),
            make_keys(5),
            [0u8; X25519_PUBLIC_KEY_SIZE],
        );
        s2.vpn_ip = Some(vpn_ip);
        sm.sessions.insert(sid2, Arc::new(Mutex::new(s2)));
        sm.bind_vpn_ip(&vpn_ip, &sid2);
        assert_eq!(
            sm.get_session_by_vpn_ip(&vpn_ip).unwrap().lock().session_id,
            sid2,
            "bind_vpn_ip must make the named session the downlink owner"
        );
    }

    /// The happy path must be unaffected: a client response between ticks
    /// commits the rekey, resets the attempt counter, and stops retransmits.
    #[test]
    fn rekey_response_between_ticks_commits_and_stops_retransmits() {
        let sm = make_manager();
        let sid = [8u8; 16];
        insert_overdue_session(&sm, sid);

        let due = sm.start_rekeying_sessions();
        assert_eq!(due.len(), 1);

        // Client responds with its rekey eph pub → server commits.
        let client_kp = crypto::KeyPair::generate();
        sm.commit_session_rekey(&sid, &client_kp.public_key_bytes());

        {
            let entry = sm.sessions.get(&sid).unwrap();
            let s = entry.value().lock();
            assert!(s.pending_rekey_keypair.is_none());
            assert_eq!(s.pending_rekey_attempts, 0);
        }
        // Next ticks: nothing pending, nothing due (last_rekey_at was reset)
        // — the commit must also stop the fast retransmit sweep.
        assert!(sm.start_rekeying_sessions().is_empty());
        backdate_last_keyrotate(&sm, &sid);
        assert!(
            sm.rekey_retransmits_due().is_empty(),
            "a committed rekey must never be retransmitted"
        );
    }

    /// M3 regression (legacy-client safety net): a client whose rekey RESPONSE
    /// was lost keeps uploading under the NEW (server-unreadable) keys with its
    /// shared monotonic counter, so its re-sent response — under the OLD keys
    /// the server still accepts — arrives with a counter far past the server's
    /// frozen inbound counter (~170 pps × the 3 s retransmit cadence already
    /// exceeds the plain ±TAG_WINDOW_SIZE band). While the rekey is pending
    /// `update_tag_window` reaches REKEY_TAG_LOOKAHEAD counters forward, so
    /// the re-sent response still validates and the rekey commits instead of
    /// burning all MAX_REKEY_SEND_ATTEMPTS retransmits and dying to the
    /// client's RX-silence watchdog. (New clients additionally keep TX on the
    /// old keys until commit, so the band never freezes at all.)
    #[test]
    fn rekey_resent_response_validates_past_frozen_counter() {
        let sm = make_manager();
        let sid = [11u8; 16];
        insert_overdue_session(&sm, sid);

        // Simulate a live session: 1000 packets already validated.
        {
            let entry = sm.sessions.get(&sid).unwrap();
            let mut s = entry.value().lock();
            s.mark_tag_received(1000);
        }

        let due = sm.start_rekeying_sessions();
        assert_eq!(due.len(), 1, "overdue session must start rekeying");

        // The client's response is lost; it switches to the new keys and keeps
        // uploading. Those packets are undecryptable to the pre-commit server
        // (different tag_secret) — the inbound counter stays frozen at 1000.
        {
            let entry = sm.sessions.get(&sid).unwrap();
            let s = entry.value().lock();
            let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
            let new_key_tag = crypto::generate_resonance_tag(&[0xEEu8; 32], 1500, tw);
            assert!(
                s.validate_tag(&new_key_tag).is_none(),
                "new-key data must not validate before the rekey commits"
            );
            assert_eq!(
                s.counter, 1000,
                "unreadable flood must not move the counter"
            );
        }

        // The server retransmits KeyRotate; the client re-sends its response
        // under the OLD keys with its CURRENT counter — 1001 counters past the
        // server's frozen edge, far outside the plain ±TAG_WINDOW_SIZE band.
        let (response_counter, response_tag) = {
            let entry = sm.sessions.get(&sid).unwrap();
            let mut s = entry.value().lock();
            let counter = s.counter + 1001;
            let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);

            // Deterministically simulate crossing a time-window boundary
            // before the precomputed tag map is refreshed. This also guards
            // the pending-rekey lookahead in the on-the-fly live-window path.
            let stale_tw = tw.wrapping_sub(1);
            let tag_secret = s.keys.tag_secret;
            for (cached_counter, cached_tag) in &mut s.expected_tags {
                *cached_tag =
                    crypto::generate_resonance_tag(&tag_secret, *cached_counter, stale_tw);
            }
            s.tag_window_tw = stale_tw;

            let tag = crypto::generate_resonance_tag(&s.keys.tag_secret, counter, tw);
            (counter, tag)
        };
        {
            let entry = sm.sessions.get(&sid).unwrap();
            let mut s = entry.value().lock();
            let (counter, is_ratcheted_tag) = s
                .validate_tag(&response_tag)
                .expect("re-sent rekey response must validate via the pending-rekey lookahead");
            assert!(!is_ratcheted_tag);
            assert_eq!(counter, response_counter);
            s.mark_tag_received(counter);
            assert_eq!(
                s.counter, response_counter,
                "validating the far-ahead response resyncs the live edge"
            );
        }

        // The response reaches the control plane → the rekey commits.
        let client_kp = crypto::KeyPair::generate();
        sm.commit_session_rekey(&sid, &client_kp.public_key_bytes());
        let entry = sm.sessions.get(&sid).unwrap();
        let s = entry.value().lock();
        assert!(s.pending_rekey_keypair.is_none(), "rekey must commit");
        assert_ne!(
            s.keys.tag_secret,
            make_keys(1).tag_secret,
            "commit must install the new keys"
        );
        assert_eq!(
            s.counter, response_counter,
            "counters stay monotonic across the commit — no nonce reuse, window resynced"
        );
    }

    // ── Masked pool-peer handshake (FORK-B of pool-sync redesign) ───────────

    /// Simulate the dialer's side of the masked pool-client handshake: derive
    /// `dh1` against the shared pool server keypair's public key exactly like
    /// a real dialing peer would, then compute the counter-0 handshake tag
    /// for the current time window (mirrors how `create_session`'s init
    /// packet tag is produced).
    fn dial_masked_pool_peer(sync_key: &[u8; 32]) -> (crypto::KeyPair, [u8; 32], [u8; TAG_SIZE]) {
        let pool_kp = crypto::pool_server_keypair(sync_key);
        let pool_psk = crypto::pool_client_psk(sync_key);

        let client_eph = crypto::KeyPair::generate();
        let dh = client_eph
            .compute_shared(&pool_kp.public_key_bytes())
            .expect("dial DH must succeed");
        let keys =
            crypto::derive_session_keys(&dh, Some(&pool_psk), &client_eph.public_key_bytes());

        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let tag = crypto::generate_resonance_tag(&keys.tag_secret, 0, tw);

        (client_eph, pool_psk, tag)
    }

    #[test]
    fn masked_pool_peer_precheck_accepts_dialer_tag() {
        let sm = make_manager();
        let sync_key = [42u8; 32];
        let pool_kp = crypto::pool_server_keypair(&sync_key);
        let (client_eph, pool_psk, tag) = dial_masked_pool_peer(&sync_key);

        assert!(sm.handshake_tag_precheck_with_static(
            &client_eph.public_key_bytes(),
            Some(pool_psk),
            &tag,
            &pool_kp,
        ));
    }

    #[test]
    fn masked_pool_peer_precheck_rejects_wrong_psk() {
        let sm = make_manager();
        let sync_key = [42u8; 32];
        let pool_kp = crypto::pool_server_keypair(&sync_key);
        let (client_eph, _pool_psk, tag) = dial_masked_pool_peer(&sync_key);

        let wrong_psk = [7u8; 32];
        assert!(!sm.handshake_tag_precheck_with_static(
            &client_eph.public_key_bytes(),
            Some(wrong_psk),
            &tag,
            &pool_kp,
        ));
    }

    #[test]
    fn masked_pool_peer_precheck_rejects_wrong_static_key() {
        let sm = make_manager();
        let sync_key = [42u8; 32];
        let (client_eph, pool_psk, tag) = dial_masked_pool_peer(&sync_key);

        // A different sync_key derives a different pool server keypair — the
        // DH the receiver computes no longer matches the dialer's, so the
        // pre-check must fail closed.
        let other_sync_key = [43u8; 32];
        let wrong_pool_kp = crypto::pool_server_keypair(&other_sync_key);

        assert!(!sm.handshake_tag_precheck_with_static(
            &client_eph.public_key_bytes(),
            Some(pool_psk),
            &tag,
            &wrong_pool_kp,
        ));
    }

    #[test]
    fn create_masked_pool_peer_session_has_no_vpn_ip_and_validates_tag() {
        let sm = make_manager();
        let sync_key = [42u8; 32];
        let pool_kp = crypto::pool_server_keypair(&sync_key);
        let pool_psk = crypto::pool_client_psk(&sync_key);
        let (client_eph, _psk, tag) = dial_masked_pool_peer(&sync_key);

        let addr: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let session = sm
            .create_masked_pool_peer_session(
                addr,
                client_eph.public_key_bytes(),
                &pool_kp,
                &pool_psk,
            )
            .expect("masked pool peer session creation must succeed");

        let sess = session.lock();
        assert!(
            sess.is_masked_pool_peer,
            "must be flagged as masked pool peer"
        );
        assert_eq!(
            sess.vpn_ip, None,
            "masked pool peer must never get a VPN IP"
        );
        assert!(
            sess.validate_handshake_tag(&tag).is_some(),
            "dialer's handshake tag must validate against the created session's initial keys"
        );
    }

    // ── B1 fix: cleanup_masked_peer_sessions_for_ip dedup scoping ──────────

    #[test]
    fn cleanup_masked_peer_sessions_for_ip_only_removes_matching_masked_peers() {
        let sm = make_manager();
        let sync_key = [42u8; 32];
        let pool_kp = crypto::pool_server_keypair(&sync_key);
        let pool_psk = crypto::pool_client_psk(&sync_key);

        let addr_a: SocketAddr = "127.0.0.1:6001".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.2:6002".parse().unwrap();

        // Two masked pool-peer sessions from the SAME source IP — simulates a
        // reconnecting (or attacking) dialer whose earlier session was never
        // deduped (the B1 leak).
        let (eph1, _, _) = dial_masked_pool_peer(&sync_key);
        let keep_session = sm
            .create_masked_pool_peer_session(addr_a, eph1.public_key_bytes(), &pool_kp, &pool_psk)
            .expect("first masked peer session must be created");
        let keep_id = keep_session.lock().session_id;

        let (eph2, _, _) = dial_masked_pool_peer(&sync_key);
        let stale_session = sm
            .create_masked_pool_peer_session(addr_a, eph2.public_key_bytes(), &pool_kp, &pool_psk)
            .expect("second masked peer session must be created");
        let stale_id = stale_session.lock().session_id;

        // A masked peer session from a DIFFERENT source IP must never be
        // touched by a cleanup scoped to `addr_a`.
        let (eph3, _, _) = dial_masked_pool_peer(&sync_key);
        let other_ip_session = sm
            .create_masked_pool_peer_session(addr_b, eph3.public_key_bytes(), &pool_kp, &pool_psk)
            .expect("third masked peer session must be created");
        let other_ip_id = other_ip_session.lock().session_id;

        // An ORDINARY client session sharing the SAME source IP must survive:
        // cleanup_masked_peer_sessions_for_ip must be scoped to
        // `is_masked_pool_peer` sessions only, never touching real clients
        // (or pool_peer/site_peer synthetic sessions) that happen to share an
        // address with a dialer.
        let client_eph = crypto::KeyPair::generate();
        let client_session = sm
            .create_session(addr_a, client_eph.public_key_bytes(), None, None)
            .expect("ordinary client session must be created");
        let client_id = client_session.lock().session_id;

        let removed = sm.cleanup_masked_peer_sessions_for_ip(&addr_a.ip(), &keep_id);

        assert_eq!(
            removed,
            vec![stale_id],
            "only the stale same-IP masked peer session must be removed"
        );
        assert!(
            sm.get_session(&keep_id).is_some(),
            "the kept masked peer session must survive"
        );
        assert!(
            sm.get_session(&stale_id).is_none(),
            "the stale same-IP masked peer session must be removed"
        );
        assert!(
            sm.get_session(&other_ip_id).is_some(),
            "a masked peer session on a DIFFERENT IP must survive"
        );
        assert!(
            sm.get_session(&client_id).is_some(),
            "an ordinary client session on the SAME IP must survive"
        );
    }

    // ── Pre-ratchet grace: keys must outlive the tags ─────────────────────────

    #[test]
    fn complete_ratchet_retains_pre_ratchet_keys_for_the_grace_window() {
        let mut s = make_session();
        let old_session_key = s.keys.session_key;
        s.ratcheted_keys = Some(make_keys(9));
        s.update_ratcheted_tag_window();

        s.complete_ratchet();

        // The new epoch is installed...
        assert_eq!(s.keys.session_key, [9u8; CHACHA20_KEY_SIZE]);
        // ...and the OLD AEAD key is still reachable while the grace is open.
        // Retaining only `pre_ratchet_tags` made the whole grace mechanism
        // inert: the tag resolved but the packet could never be decrypted.
        let retained = s
            .pre_ratchet_keys_in_grace()
            .expect("pre-ratchet keys must be retained for the grace window");
        assert_eq!(retained.session_key, old_session_key);
    }

    #[test]
    fn pre_ratchet_keys_are_not_offered_once_the_grace_expires() {
        let mut s = make_session();
        s.ratcheted_keys = Some(make_keys(9));
        s.update_ratcheted_tag_window();
        s.complete_ratchet();

        // Force the deadline into the past.
        s.pre_ratchet_expire = Some(Instant::now() - Duration::from_secs(1));
        assert!(
            s.pre_ratchet_keys_in_grace().is_none(),
            "expired grace must not keep offering the old keys"
        );
    }

    #[test]
    fn post_ratchet_counter_spaces_overlap_so_counters_cannot_identify_the_epoch() {
        // Guards the reason the epoch discriminator is "which key decrypted"
        // rather than "is this counter in pre_ratchet_tags". `complete_ratchet`
        // resets counter to 0 and the ratcheted window is minted for 0..512,
        // while the outgoing window (built around a small post-handshake
        // counter, start saturating_sub'd to 0) also covers 0..512 — so a
        // membership test classifies early CURRENT-epoch packets as
        // pre-ratchet, skipping mark_tag_received() and leaving the replay
        // bitmap empty.
        let mut s = make_session();
        s.counter = 3; // realistic: the ratchet fires right after the handshake
        s.update_tag_window();
        s.ratcheted_keys = Some(make_keys(9));
        s.update_ratcheted_tag_window();

        s.complete_ratchet();

        assert_eq!(s.counter, 0, "ratchet restarts the counter space");
        let overlap = s
            .expected_tags
            .keys()
            .filter(|c| s.pre_ratchet_tags.contains_key(c))
            .count();
        assert!(
            overlap > 0,
            "counter spaces must be shown to overlap — this is why membership \
             cannot identify the epoch (overlap was {overlap})"
        );
    }

    // ── M2: forward-only counter recovery ────────────────────────────────────

    fn make_manager_with_session() -> (SessionManager, Arc<Mutex<Session>>, SessionKeys) {
        let server_kp = KeyPair::generate();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let mgr = SessionManager::new(server_kp, signing_key, mask);
        let session = mgr
            .create_session(
                "10.9.9.9:10000".parse().unwrap(),
                [7u8; X25519_PUBLIC_KEY_SIZE],
                None,
                None,
            )
            .unwrap();
        let keys = session.lock().keys.clone();
        (mgr, session, keys)
    }

    fn session_ip() -> std::net::IpAddr {
        "10.9.9.9".parse().unwrap()
    }

    /// M2 regression: a replayed old packet whose counter sits behind
    /// `sess.counter` (beyond the replay bitmap's reach but inside the old
    /// ±2048 recovery range) must NOT rewind the session counter — accepting
    /// it used to erase the whole anti-replay history via ReplayWindow::clear
    /// on the next legitimate packet. Client counters are monotone, so
    /// backward drift is always a replay.
    #[test]
    fn counter_recovery_rejects_backward_replay() {
        let (mgr, session, keys) = make_manager_with_session();
        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        {
            let mut s = session.lock();
            for c in 0..=3000u64 {
                s.mark_tag_received(c);
            }
        }
        // Counter 2000 is 1000 behind — inside the old ±2048 range, outside
        // the 512-deep replay bitmap.
        let replay_tag = crypto::generate_resonance_tag(&keys.tag_secret, 2000, tw);
        assert!(
            mgr.recover_session_by_tag(&replay_tag, &session_ip())
                .is_none(),
            "backward counter match must be rejected as a replay"
        );
        // Session state untouched: no counter rewind, no bitmap wipe.
        let s = session.lock();
        assert_eq!(s.counter, 3000);
        assert!(s.received_bitmap.get_bit(0));
    }

    /// M2 companion: the documented client-race case is FORWARD drift and
    /// must keep working; the recovered counter is marked received so the
    /// same packet cannot be replayed through either validation path.
    #[test]
    fn counter_recovery_accepts_forward_drift_and_marks_received() {
        let (mgr, session, keys) = make_manager_with_session();
        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        {
            let mut s = session.lock();
            for c in 0..=100u64 {
                s.mark_tag_received(c);
            }
        }
        // Client 800 ahead of the server — past the ±512 validation window
        // but inside RECOVERY_RANGE.
        let drift_tag = crypto::generate_resonance_tag(&keys.tag_secret, 900, tw);
        let (recovered_session, counter, is_ratcheted) = mgr
            .recover_session_by_tag(&drift_tag, &session_ip())
            .expect("forward drift must recover");
        assert_eq!(counter, 900);
        assert!(!is_ratcheted);
        assert_eq!(recovered_session.lock().counter, 900);
        // Marked received: validate_tag now rejects the same tag as a replay…
        assert!(recovered_session.lock().validate_tag(&drift_tag).is_none());
        // …and a second recovery attempt with it is rejected too (c == base
        // with the newest-counter bit set).
        assert!(mgr
            .recover_session_by_tag(&drift_tag, &session_ip())
            .is_none());
    }
}
