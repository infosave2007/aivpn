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

use aivpn_common::crypto::{
    self, decrypt_payload, encrypt_payload, encrypt_payload_into, DEFAULT_WINDOW_MS, NONCE_SIZE,
    TAG_SIZE,
};
use aivpn_common::error::{Error, Result};
use aivpn_common::fec::FecRepair;
use aivpn_common::kernel_accel::{
    KernelAccel, SessionAdd, SessionDownlink, TagWindowEntry, UpdateTagsPayload, DL_MDH_MAX,
};
use aivpn_common::mask::{
    current_unix_secs, derive_bootstrap_candidates, BootstrapDescriptor, MaskProfile,
    LEGACY_TAG_OFFSET,
};
use aivpn_common::network_config::VpnNetworkConfig;
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType, MAX_PACKET_SIZE};
use libc;
use rand::{RngCore as _, SeedableRng as _};
use zeroize::Zeroize;

/// A7 downlink shaping packet-size ceiling. Kept in sync with mimicry.rs's
/// `SAFE_OUTER_PACKET_BUDGET` (1380) so a padded downlink datagram never
/// exceeds the WAN-safe budget the client uses for uplink — padding above
/// this would risk IP fragmentation and a DPI-visible size anomaly.
const SAFE_DOWNLINK_BUDGET: usize = 1380;

use crate::audit_log::{AuditActor, AuditLogger};
use crate::batch_io::PacketBatchIo as _;
use crate::client_db::ClientDatabase;
use crate::ebpf_observer::EbpfObserver;
use crate::mask_gen::generate_and_store_mask;
use crate::mask_store::MaskStore;
use crate::metrics::MetricsCollector;
use crate::nat::NatForwarder;
use crate::neural::{NeuralConfig, NeuralResonanceModule, ResonanceStatus};
use crate::qos::QosEnforcer;
use crate::recording::RecordingManager;
use crate::recording::{RecordingStopOutcome, RecordingStopReason};
use crate::session::{Session, SessionManager, MAX_SESSIONS};
use aivpn_common::event_log::EventBus;

struct QueuedPacket {
    packet_data: Vec<u8>,
    client_addr: SocketAddr,
}

/// Gateway configuration
#[derive(Clone)]
pub struct GatewayConfig {
    pub listen_addr: String,
    pub per_ip_pps_limit: u64,
    pub tun_name: String,
    pub tun_addr: String,
    pub tun_netmask: String,
    pub network_config: VpnNetworkConfig,
    pub server_private_key: [u8; 32],
    pub signing_key: [u8; 64],
    pub enable_nat: bool,
    /// Enable neural resonance module (Patent 1)
    pub enable_neural: bool,
    /// Neural resonance configuration
    pub neural_config: NeuralConfig,
    /// Client database for PSK-based authentication
    pub client_db: Option<Arc<ClientDatabase>>,
    /// Directory for mask storage (default: /var/lib/aivpn/masks)
    pub mask_dir: std::path::PathBuf,
    /// Session hard timeout in seconds (default: 7 days). `None` uses the default.
    pub session_timeout_secs: Option<u64>,
    /// Session idle timeout in seconds (default: 300). `None` uses the default.
    pub idle_timeout_secs: Option<u64>,
    /// Optional custom bootstrap masks embedded into signed descriptors.
    pub bootstrap_masks: Vec<MaskProfile>,
    /// Server-side NAT TUN MTU. Does not affect client VPN MTU (carried in ServerHello).
    pub tun_mtu: u16,
    /// Structured event bus — emits JSON-lines events to stdout (and optional webhook).
    pub event_bus: EventBus,
    /// Per-client QoS enforcer (token bucket + DSCP).
    pub qos_enforcer: Arc<QosEnforcer>,
    /// Multi-hop exit node forwarder.  When `Some`, client Data packets are
    /// relayed to the exit node instead of being NAT-forwarded locally.
    pub chain_forwarder: Option<Arc<crate::chain_forwarder::ChainForwarder>>,
    /// Optional mTLS certificate policy.  `None` = no cert verification.
    pub mtls: Option<crate::mtls::MtlsConfig>,
    /// When `true`, this node accepts `ChainForward` control messages and
    /// injects them directly into the TUN device (exit-node role).
    /// Must be set explicitly — defaults to `false` to prevent open relay.
    pub exit_node_enabled: bool,
    /// Append-only audit log (H-S-8). Records security-relevant session events.
    /// Defaults to `AuditLogger::disabled()` (writes to /dev/null).
    pub audit_log: AuditLogger,
    /// Allow direct client-to-client packet routing inside the VPN subnet (0.9.0+).
    /// When false (default), VPN-to-VPN traffic is silently dropped at the TUN level.
    pub allow_peer_routing: bool,
    /// Optional auto-publish configuration: pushes freshly-rotated bootstrap
    /// descriptors to external channels (S3-compatible CDN, GitHub release,
    /// Telegram) so brand-new clients without a working connection key yet
    /// can discover them. `None` disables auto-publish entirely.
    pub bootstrap_publish: Option<crate::bootstrap_publish::BootstrapPublishConfig>,
    /// §2 crowdsourced blocking feedback — minimum consecutive failed
    /// connection attempts with the same mask family before a client records a
    /// failure outcome. Pushed to opted-in clients via `FeedbackConfig`.
    /// Sourced from the optional `"feedback"` block in server.json.
    pub feedback_report_failure_threshold: u8,
    /// §2 crowdsourced blocking feedback — minimum spacing (seconds) between a
    /// client's successive `MaskFeedback` sends. Pushed via `FeedbackConfig`.
    pub feedback_report_interval_secs: u32,
    /// §3 F "every session polymorphic" server policy. When `true`, every
    /// session gets a polymorphic mask variant pushed automatically right
    /// after its handshake completes — the client does not need to opt in
    /// via `MaskPreference`. Sourced from the optional `"polymorphic"` block
    /// in server.json (`{"all_sessions": true, "base_mask": "..."}`).
    /// Defaults to `false` (opt-in per-client `MaskPreference` remains the
    /// only way to get a polymorphic mask).
    pub polymorphic_all_sessions: bool,
    /// §3 F policy base mask preset id (e.g. `"webrtc_zoom_v3"`) used as the
    /// input to `MaskProfile::to_polymorphic` when `polymorphic_all_sessions`
    /// is enabled. `None` means "use the session's own current mask as the
    /// base" — the same fallback the client-driven `MaskPreference` path
    /// would use if it deferred to the active mask instead of an explicit
    /// `base_mask_id`.
    pub polymorphic_base_mask: Option<String>,
    /// A7 downlink shaping parity. When `true` (default), the server pads
    /// server→client DATA packets to a size sampled from the session mask's
    /// own size distribution — the same distribution the client uses for
    /// uplink — so uplink and downlink packets share one size signature on a
    /// 5-tuple instead of downlink being systematically smaller (pad_len=0).
    /// Padding is written into the existing `pad_len` field, which every
    /// client already strips (`parse_downlink_inner`), so this is wire- and
    /// decode-compatible with all client versions. Set `false` for the
    /// throughput-first profile (no downlink padding). Sourced from the
    /// optional `"downlink_shaping"` key in server.json.
    pub downlink_shaping: bool,
    /// R2 Phase B: operator Ed25519 mask-signing key SEED (32 bytes). When
    /// `Some`, freshly generated masks are signed after the KS self-test
    /// passes. Separate from `server_private_key`/`signing_key` (transport):
    /// a compromised edge server key must not be able to forge mask
    /// provenance. Sourced from `--mask-signing-key` / server.json
    /// `mask_signing_key` (a key file path). `None` = generate unsigned.
    pub mask_signing_key: Option<[u8; 32]>,
    /// R2 Phase B: operator Ed25519 verifying key for mask artifact
    /// verification on disk load. When `None` but `mask_signing_key` is set,
    /// the public key is derived from it. Sourced from
    /// `--mask-operator-pubkey` / server.json `mask_operator_pubkey` (base64).
    pub mask_operator_pubkey: Option<[u8; 32]>,
    /// R2 Phase B: config-gated verification level for masks loaded from
    /// `mask_dir` (off | warn | enforce). Default `warn` — log-and-accept, so
    /// existing unsigned corpora keep working. Sourced from
    /// `--mask-verify-mode` / server.json `mask_verify_mode`.
    pub mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
}

/// Default §2 `report_failure_threshold`. Kept in sync with the client's
/// `mask_feedback_log::DEFAULT_FAILURE_THRESHOLD`.
pub const DEFAULT_FEEDBACK_FAILURE_THRESHOLD: u8 = 3;
/// Default §2 `report_interval_secs` (1 hour).
pub const DEFAULT_FEEDBACK_REPORT_INTERVAL_SECS: u32 = 3600;

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".to_string(),
            per_ip_pps_limit: 1000,
            tun_name: "aivpn0".to_string(),
            tun_addr: "10.0.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            network_config: VpnNetworkConfig::default(),
            server_private_key: [0u8; 32],
            signing_key: [0u8; 64],
            enable_nat: true,
            enable_neural: true,
            neural_config: NeuralConfig::default(),
            client_db: None,
            mask_dir: std::path::PathBuf::from("/var/lib/aivpn/masks"),
            session_timeout_secs: None,
            idle_timeout_secs: None,
            bootstrap_masks: Vec::new(),
            tun_mtu: crate::nat::DEFAULT_TUN_MTU,
            event_bus: EventBus::new(aivpn_common::event_log::EventSinkConfig {
                stdout: false,
                webhook_url: None,
            }),
            qos_enforcer: Arc::new(QosEnforcer::new()),
            chain_forwarder: None,
            mtls: None,
            exit_node_enabled: false,
            audit_log: AuditLogger::disabled(),
            allow_peer_routing: false,
            bootstrap_publish: None,
            feedback_report_failure_threshold: DEFAULT_FEEDBACK_FAILURE_THRESHOLD,
            feedback_report_interval_secs: DEFAULT_FEEDBACK_REPORT_INTERVAL_SECS,
            polymorphic_all_sessions: false,
            polymorphic_base_mask: None,
            downlink_shaping: true,
            mask_signing_key: None,
            mask_operator_pubkey: None,
            mask_verify_mode: aivpn_common::mask::MaskVerifyMode::default(),
        }
    }
}

/// Mask catalog for automatic rotation (Patent 3 + Patent 9)
///
/// Holds a pool of pre-generated masks. When neural resonance detects
/// that a mask is compromised by DPI, the catalog provides a replacement.
pub struct MaskCatalog {
    /// Available masks (mask_id → MaskProfile)
    masks: DashMap<String, MaskProfile>,
    /// Compromised mask IDs — never reuse
    compromised: DashMap<String, Instant>,
    /// Primary mask used for initial handshake parsing.
    primary_mask_id: parking_lot::Mutex<String>,
}

impl MaskCatalog {
    pub fn new() -> Self {
        Self {
            masks: DashMap::new(),
            compromised: DashMap::new(),
            primary_mask_id: parking_lot::Mutex::new(String::new()),
        }
    }

    /// Set the primary mask ID (first mask loaded from disk)
    pub fn set_primary_mask_id(&self, mask_id: String) {
        *self.primary_mask_id.lock() = mask_id;
    }

    /// Register a new mask (e.g., received via passive distribution or neural unpack)
    pub fn register_mask(&self, mask: MaskProfile) {
        if !self.compromised.contains_key(&mask.mask_id) {
            self.masks.insert(mask.mask_id.clone(), mask);
        }
    }

    /// Mark a mask as compromised — remove from rotation
    pub fn mark_compromised(&self, mask_id: &str) {
        self.compromised.insert(mask_id.to_string(), Instant::now());
        self.masks.remove(mask_id);
    }

    /// Remove a mask from live rotation without marking it as compromised.
    pub fn remove_mask(&self, mask_id: &str) {
        self.masks.remove(mask_id);
    }

    /// Select the best non-compromised mask, excluding `current_mask_id`
    pub fn select_fallback(&self, current_mask_id: &str) -> Option<MaskProfile> {
        self.masks
            .iter()
            .filter(|e| e.key() != current_mask_id)
            .map(|e| e.value().clone())
            .next()
    }

    /// Get mask count
    pub fn available_count(&self) -> usize {
        self.masks.len()
    }

    /// Get the primary packet layout for client->server traffic.
    /// Returns `(packet_mdh_len, handshake_mdh_len, eph_offset, eph_len)`.
    /// Normal packets use only the protocol header, while the initial
    /// handshake embeds `eph_pub` inside the MDH at `eph_offset`.
    pub fn packet_layout(&self) -> (usize, usize, usize, usize) {
        let fallback = (20usize, 52usize, 20usize, 32usize);
        let Some(mask) = self.primary_mask() else {
            return fallback;
        };

        packet_layout_for_mask(&mask)
    }

    /// Get the regular MDH bytes used for server->client packets.
    /// Uses HeaderSpec for dynamic per-packet generation when available (Issue #30 fix).
    pub fn packet_mdh_bytes(&self) -> Vec<u8> {
        self.primary_mask()
            .map(|mask| packet_mdh_bytes_for_mask(&mask))
            .unwrap_or_else(|| vec![0u8; 20])
    }

    pub fn primary_mask(&self) -> Option<MaskProfile> {
        let primary_id = self.primary_mask_id.lock().clone();
        self.masks
            .get(&primary_id)
            .map(|entry| entry.value().clone())
            .or_else(|| {
                // Deterministic fallback: smallest mask_id. `DashMap::iter()
                // .next()` depends on hash/shard order, so two nodes (or two
                // runs) with the same mask set could disagree on the primary
                // mask — and with it on every layout derived from it.
                self.masks
                    .iter()
                    .min_by(|a, b| a.key().cmp(b.key()))
                    .map(|entry| entry.value().clone())
            })
    }
}

fn packet_layout_for_mask(mask: &MaskProfile) -> (usize, usize, usize, usize) {
    let eph_offset = mask.eph_pub_offset as usize;
    let eph_len = mask.eph_pub_length as usize;
    let packet_mdh_len = mask
        .header_spec
        .as_ref()
        .map(|spec| spec.min_length())
        .unwrap_or_else(|| mask.header_template.len());
    let handshake_mdh_len = packet_mdh_len.max(eph_offset.saturating_add(eph_len));
    (packet_mdh_len, handshake_mdh_len, eph_offset, eph_len)
}

fn packet_mdh_bytes_for_mask(mask: &MaskProfile) -> Vec<u8> {
    if let Some(ref spec) = mask.header_spec {
        let mut rng = rand::thread_rng();
        spec.generate(&mut rng)
    } else {
        mask.header_template.clone()
    }
}

/// Byte length of the legacy tag prefix for a given mask wire layout
/// (Variant A DPI fix). See [`aivpn_common::mask::MaskProfile::tag_offset`].
///
/// * Legacy (`u16::MAX`): the 8-byte resonance tag is a separate prefix at
///   packet offset 0, so the real protocol header and the ciphertext start
///   `TAG_SIZE` bytes into the packet.
/// * Embedded (`N`): the tag hides INSIDE the header at byte offset `N` and
///   there is NO separate prefix, so the header sits at packet offset 0 and the
///   ciphertext starts right after the MDH.
fn tag_prefix_len(tag_offset: u16) -> usize {
    if tag_offset == u16::MAX {
        TAG_SIZE
    } else {
        0
    }
}

/// Extract up to 16 bytes of the L7 (transport-payload) prefix from a
/// *decrypted* inner IP packet, for auto-mask header learning.
///
/// The recording→mask_gen pipeline (`detect_mimic_protocol`,
/// `infer_header_spec`) keys off the cleartext application header — the STUN
/// magic cookie at offset 4, the QUIC long-header bits at offset 0, the DNS
/// header — which lives in the UDP/TCP payload of the tunnelled packet, NOT
/// in the encrypted AIVPN wire framing. Recording the raw ciphertext prefix
/// instead (as the code originally did) yields near-random bytes, so
/// `infer_header_spec` finds no constant positions and the self-test
/// `header_match` gate rejects every mask built from a real tunnel capture.
///
/// Returns an empty vec for non-IPv4 / non-UDP-TCP / truncated packets, which
/// then simply contribute no constant bytes to the inferred header spec.
fn inner_l7_prefix(ip: &[u8]) -> Vec<u8> {
    // IPv4 data plane only. (An IPv6 inner packet, if ever tunnelled, would
    // need the fixed-40-byte v6 header path added here.)
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return Vec::new();
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return Vec::new();
    }
    let l7_off = match ip[9] {
        17 => ihl + 8, // UDP: fixed 8-byte header
        6 => {
            // TCP: data offset = high nibble of byte 12, in 32-bit words.
            match ip.get(ihl..) {
                Some(tcp) if tcp.len() >= 13 => ihl + ((tcp[12] >> 4) as usize) * 4,
                _ => return Vec::new(),
            }
        }
        _ => return Vec::new(),
    };
    match ip.get(l7_off..) {
        Some(l7) => l7[..l7.len().min(16)].to_vec(),
        None => Vec::new(),
    }
}

/// Packet byte offset at which the resonance tag lives for a given layout:
/// 0 for the legacy tag-prefixed layout, `N` for an embedded-tag mask.
fn tag_byte_offset(tag_offset: u16) -> usize {
    if tag_offset == u16::MAX {
        0
    } else {
        tag_offset as usize
    }
}

/// Extract the 8-byte resonance tag from `packet` at the position dictated by
/// `tag_offset`'s layout, or `None` if the packet is too short to hold it.
fn extract_tag_for_layout(packet: &[u8], tag_offset: u16) -> Option<[u8; TAG_SIZE]> {
    let off = tag_byte_offset(tag_offset);
    let end = off.checked_add(TAG_SIZE)?;
    if packet.len() < end {
        return None;
    }
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&packet[off..end]);
    Some(tag)
}

/// Distinct packet byte offsets where an incoming resonance tag may live, given
/// the set of currently-relevant masks. Always includes 0 (legacy tag-prefix /
/// fast path) and adds each embedded mask's `tag_offset`. Bounded and tiny in
/// practice (the presets contribute at most 2 distinct embedded offsets).
fn distinct_tag_offsets_of<'a>(masks: impl Iterator<Item = &'a MaskProfile>) -> Vec<usize> {
    let mut offsets = vec![0usize];
    for mask in masks {
        if let Some(off) = mask.embedded_tag_offset() {
            if !offsets.contains(&off) {
                offsets.push(off);
            }
        }
    }
    offsets
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

/// Generic per-session throttle predicate shared by `MaskPreference`
/// (`mask_preference_throttled`) and `MaskFeedback`
/// (`mask_feedback_throttled`): `true` means "a slot for this session was
/// already claimed within `window`, so the caller must drop the request
/// without reaching its expensive path". Factored out so both throttles
/// share one reviewed implementation instead of two hand-copied windows.
fn throttled(last_processed: Option<Instant>, now: Instant, window: Duration) -> bool {
    match last_processed {
        Some(last) => now.duration_since(last) < window,
        None => false,
    }
}

/// Per-session `MaskPreference` throttle predicate: `true` means the gateway
/// should drop this `MaskPreference` without reaching the sign+encrypt
/// `build_mask_update_packet` path, because one was already processed for
/// this session within `MASK_PREFERENCE_THROTTLE`. See that constant's doc
/// comment for why this cannot break the client's legitimate same-id retry
/// loop (those never reach this check — they're caught by the pre-existing
/// idempotency check first).
fn mask_preference_throttled(last_processed: Option<Instant>, now: Instant) -> bool {
    throttled(last_processed, now, MASK_PREFERENCE_THROTTLE)
}

/// Per-session `MaskFeedback` throttle predicate — same shape as
/// `mask_preference_throttled`, gating the `top_masks_for_region` scan +
/// up to two encrypted replies (see `MASK_FEEDBACK_THROTTLE`) instead of the
/// sign+encrypt `MaskUpdate` path.
fn mask_feedback_throttled(last_processed: Option<Instant>, now: Instant) -> bool {
    throttled(last_processed, now, MASK_FEEDBACK_THROTTLE)
}

/// Atomically check-and-claim a per-session throttle slot (LOW #3 hardening:
/// sign-amplification race, generalized — see FIX F's per-session
/// `MaskFeedback` throttle for the second use). The naive way to use
/// `throttled` — `throttle.get(&id)` to read, then `throttle.insert(id, now)`
/// to claim — has a TOCTOU gap: `get` and `insert` each take (and release)
/// the DashMap shard lock separately, so two packets for the *same* session,
/// processed by two different `tokio::spawn`ed tasks from
/// `process_packets_concurrent` (genuinely concurrent, not just
/// interleaved), can both read "not throttled yet" before either has
/// inserted, and both fall through to the expensive path this throttle
/// exists to bound.
///
/// `DashMap::entry()` holds one shard lock across the whole read-decide-write
/// sequence, so this makes the check-and-claim atomic: of any set of callers
/// racing for the same `session_id`, exactly one observes `claimed = true`
/// (and the slot now reflects `now`); every other one — whether truly
/// concurrent or arriving moments later within the window — observes
/// `claimed = false`. Returns `true` if the caller should proceed (the slot
/// is now claimed for `now`), `false` if throttled.
fn try_claim_slot(
    throttle: &DashMap<[u8; 16], Instant>,
    session_id: [u8; 16],
    now: Instant,
    is_throttled: fn(Option<Instant>, Instant) -> bool,
) -> bool {
    let mut claimed = true;
    throttle
        .entry(session_id)
        .and_modify(|last| {
            if is_throttled(Some(*last), now) {
                claimed = false;
            } else {
                *last = now;
            }
        })
        .or_insert(now);
    claimed
}

/// `MaskPreference`-specific wrapper around `try_claim_slot` — see that
/// function's doc comment for the atomicity guarantee.
fn try_claim_mask_preference_slot(
    throttle: &DashMap<[u8; 16], Instant>,
    session_id: [u8; 16],
    now: Instant,
) -> bool {
    try_claim_slot(throttle, session_id, now, mask_preference_throttled)
}

/// `MaskFeedback`-specific wrapper around `try_claim_slot` (FIX F) — bounds
/// the expensive `top_masks_for_region` scan + up to two encrypted replies to
/// at most once per session per `MASK_FEEDBACK_THROTTLE`, regardless of how
/// many `MaskFeedback` packets (with or without entries) the session sends.
fn try_claim_mask_feedback_slot(
    throttle: &DashMap<[u8; 16], Instant>,
    session_id: [u8; 16],
    now: Instant,
) -> bool {
    try_claim_slot(throttle, session_id, now, mask_feedback_throttled)
}

fn hash_addr(addr: &SocketAddr) -> String {
    let hash = crypto::blake3_hash(addr.to_string().as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
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
}

/// Per-session `MaskPreference` throttle window. `handle_control_message`'s
/// `MaskPreference` arm derives a polymorphic variant and, unless the
/// session's current/pending mask already IS that variant (the pre-existing
/// idempotency check), signs (Ed25519) and encrypts a fresh `MaskUpdate`
/// packet — non-trivial per-packet cost. A client that varies `base_mask_id`
/// on every packet defeats the idempotency check (the derived variant differs
/// every time) and can force that sign+encrypt path on every single packet it
/// sends.
///
/// The legitimate client-side retry loop (see `aivpn-client/src/client.rs`,
/// `polymorphic_base` handling) resends the *same* `base_mask_id` up to 5
/// times over ~5s (immediate, then +0.5s/+1s/+1.5s/+2s) purely for reliability
/// against a lost first packet. Because it always resends the same id, only
/// the first of those ever reaches the sign+encrypt path — every retry after
/// the first hits the idempotency check instead (the variant is already
/// active/pending) and returns before ever consuming this throttle. So a
/// throttle keyed on "was the last *processed* (non-idempotent) request for
/// this session within the window" does not interfere with that retry
/// sequence at all, regardless of how tight the window is.
///
/// What it does bound is a spammer sending a *different* `base_mask_id` on
/// every packet (always missing the idempotency check): at most one
/// sign+encrypt per session per window, no matter how many distinct ids it
/// sends. 2 seconds is comfortably below "a human deliberately changing their
/// mask preference again" cadence, so it costs legitimate usage nothing
/// beyond a sub-2s cooldown between genuinely different preference changes.
const MASK_PREFERENCE_THROTTLE: Duration = Duration::from_secs(2);

/// Per-session `MaskFeedback` throttle window (FIX F, §2 amplification).
/// `handle_control_message`'s `MaskFeedback` arm always runs
/// `MaskFeedbackStore::top_masks_for_region` (which, under the feedback
/// `Mutex`, calls `Hll::estimate` — summing 1024 registers — for every mask
/// bucket in the client's claimed country, plus the continent roll-up) and
/// then sends up to two encrypted replies (`RegionalMaskHints` +
/// `FeedbackConfig`) — regardless of whether the packet carried any real
/// outcome `entries`. A bare "hints-only probe" (empty `entries`, essentially
/// free for the sender to construct) triggers the exact same scan+reply cost
/// as a real report, so without a throttle a client could force that 1-in/2-
/// out amplification on every single packet it sends.
///
/// This throttle guards ONLY the scan+reply path, not `record_feedback`
/// itself (see the `MaskFeedback` arm) — real outcome reporting is cheap
/// (an O(1) HLL update, already bounded by `MAX_BUCKETS` /
/// `MAX_BUCKETS_PER_COUNTRY`) and must never be dropped merely because the
/// same session also asked for hints recently. 5 seconds is far below the
/// server-pushed `feedback_report_interval_secs` (default 3600s) a
/// legitimate opted-in client waits between real reports, so it costs
/// legitimate usage nothing while bounding a spammer to at most one
/// scan+reply pair per session per window.
const MASK_FEEDBACK_THROTTLE: Duration = Duration::from_secs(5);

const BOOTSTRAP_ROTATION_SECS: u64 = 24 * 3600;
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
const BOOTSTRAP_DESCRIPTOR_CANDIDATES: u8 = 4;

fn bootstrap_epoch(unix_secs: u64) -> u64 {
    unix_secs / BOOTSTRAP_ROTATION_SECS
}

pub fn derive_server_signing_key(server_private_key: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let seed = blake3::derive_key("aivpn-ed25519-signing-v1", server_private_key);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn sign_bootstrap_descriptor(
    mut descriptor: BootstrapDescriptor,
    signing_key: &ed25519_dalek::SigningKey,
) -> BootstrapDescriptor {
    use ed25519_dalek::Signer;
    descriptor.signature = signing_key.sign(&descriptor.signing_bytes()).to_bytes();
    descriptor
}

fn build_bootstrap_descriptor(
    server_seed: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    epoch: u64,
    bootstrap_masks: &[MaskProfile],
) -> BootstrapDescriptor {
    let mut hasher = blake3::Hasher::new_keyed(server_seed);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut kdf_salt = [0u8; 32];
    kdf_salt.copy_from_slice(&hash.as_bytes()[..32]);
    let created_at = epoch * BOOTSTRAP_ROTATION_SECS;
    let expires_at = created_at + (2 * BOOTSTRAP_ROTATION_SECS);
    let (base_mask_ids, embedded_masks) = if bootstrap_masks.is_empty() {
        (
            aivpn_common::mask::preset_masks::all()
                .into_iter()
                .map(|mask| mask.mask_id)
                .collect(),
            Vec::new(),
        )
    } else {
        (Vec::new(), bootstrap_masks.to_vec())
    };

    sign_bootstrap_descriptor(
        BootstrapDescriptor {
            descriptor_id: format!("epoch-{}", epoch),
            version: 1,
            created_at,
            expires_at,
            base_mask_ids,
            embedded_masks,
            candidate_count: BOOTSTRAP_DESCRIPTOR_CANDIDATES,
            kdf_salt,
            signature: [0u8; 64],
        },
        signing_key,
    )
}

pub fn build_bootstrap_descriptors(
    server_seed: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    bootstrap_masks: &[MaskProfile],
) -> Vec<BootstrapDescriptor> {
    let epoch = bootstrap_epoch(current_unix_secs());
    // Accept a WINDOW of recent descriptor epochs so a client that reconnects
    // on a slightly stale cached descriptor still matches a LEGITIMATE covert
    // (epoch-rotated, ed25519-signed) mask rather than being forced onto a
    // public preset or into a reconnect loop. With BOOTSTRAP_ROTATION_SECS =
    // 24h, `epoch-2 ..= epoch+1` tolerates a client up to ~48h behind (the
    // client cache retains descriptors for `expires_at + 24h`, i.e. up to two
    // rotations old) plus a +1 slot for a client whose clock runs ahead. This
    // widens the previous `epoch-1 ..= epoch+1` (±24h) window without ever
    // exposing a static/known handshake shape: every candidate here is still a
    // rotated descriptor mask.
    BOOTSTRAP_EPOCH_WINDOW
        .iter()
        .map(|delta| {
            let value = if *delta < 0 {
                epoch.saturating_sub(delta.unsigned_abs())
            } else {
                epoch.saturating_add(*delta as u64)
            };
            build_bootstrap_descriptor(server_seed, signing_key, value, bootstrap_masks)
        })
        .collect()
}

/// Descriptor epochs (relative to the current epoch) the server derives and
/// accepts during the handshake candidate scan. See `build_bootstrap_descriptors`
/// for the sizing rationale. Kept as a named constant so the accepted-epoch
/// window and the derived-descriptor set stay in lock-step.
const BOOTSTRAP_EPOCH_WINDOW: [i64; 4] = [-2, -1, 0, 1];

impl Gateway {
    fn can_start_recording(&self, client_id: Option<&str>) -> bool {
        let Some(client_id) = client_id else {
            return false;
        };

        self.client_db
            .as_ref()
            .and_then(|db| db.find_by_id(client_id))
            .map(|client| client.name.starts_with("recording-admin"))
            .unwrap_or(false)
    }

    async fn handle_recording_outcome(
        socket: &Arc<UdpSocket>,
        sessions: &Arc<SessionManager>,
        store: &Arc<MaskStore>,
        mdh: &[u8],
        outcome: RecordingStopOutcome,
        notify_session: Option<Arc<parking_lot::Mutex<Session>>>,
    ) {
        match outcome {
            RecordingStopOutcome::Completed(completed) => {
                if let Some(ref session) = notify_session {
                    let ack = ControlPayload::RecordingAck {
                        session_id: completed.session_id,
                        status: "analyzing".into(),
                    };
                    if let Err(e) =
                        Self::send_control_message_via(socket.as_ref(), mdh, &ack, session).await
                    {
                        warn!("Failed to send RecordingAck: {}", e);
                    }
                }

                info!(
                    "Recording stopped for '{}' ({} packets, {}s), analyzing...",
                    completed.service, completed.total_packets, completed.duration_secs
                );

                let socket = socket.clone();
                let sessions = sessions.clone();
                let store = store.clone();
                let mdh = mdh.to_vec();
                tokio::spawn(async move {
                    match generate_and_store_mask(&completed.service, &completed.packets, &store)
                        .await
                    {
                        Ok(mask_id) => {
                            info!(
                                "✅ Mask generated: '{}' for service '{}' by {}",
                                mask_id, completed.service, completed.admin_key_id
                            );
                            if let Some(target_session) =
                                sessions.get_session(&completed.session_id)
                            {
                                let confidence = store
                                    .get_mask(&mask_id)
                                    .map(|entry| entry.stats.confidence)
                                    .unwrap_or(0.0);
                                let payload = ControlPayload::RecordingComplete {
                                    service: completed.service.clone(),
                                    mask_id,
                                    confidence,
                                };
                                if let Err(e) = Self::send_control_message_via(
                                    socket.as_ref(),
                                    &mdh,
                                    &payload,
                                    &target_session,
                                )
                                .await
                                {
                                    warn!("Failed to send RecordingComplete: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Mask generation failed for '{}': {}", completed.service, e);
                            if let Some(target_session) =
                                sessions.get_session(&completed.session_id)
                            {
                                let payload = ControlPayload::RecordingFailed {
                                    reason: e.to_string(),
                                };
                                if let Err(send_err) = Self::send_control_message_via(
                                    socket.as_ref(),
                                    &mdh,
                                    &payload,
                                    &target_session,
                                )
                                .await
                                {
                                    warn!("Failed to send RecordingFailed: {}", send_err);
                                }
                            }
                        }
                    }
                });
            }
            RecordingStopOutcome::Incomplete(incomplete) => {
                let reason = match incomplete.reason {
                    RecordingStopReason::IdleTimeout => {
                        "Recording stopped after idle timeout before enough traffic was captured"
                    }
                    RecordingStopReason::SessionEnded => {
                        "Recording ended with the session before enough traffic was captured"
                    }
                    _ => "Too few packets or too short duration",
                };
                if let Some(ref session) = notify_session {
                    let payload = ControlPayload::RecordingFailed {
                        reason: reason.into(),
                    };
                    if let Err(e) =
                        Self::send_control_message_via(socket.as_ref(), mdh, &payload, session)
                            .await
                    {
                        warn!("Failed to send RecordingFailed: {}", e);
                    }
                }
                warn!(
                    "Recording for '{}' ended without mask generation: {} packets, {}s ({:?})",
                    incomplete.service,
                    incomplete.total_packets,
                    incomplete.duration_secs,
                    incomplete.reason
                );
            }
            RecordingStopOutcome::NotFound => {}
        }
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
        let preset_tag_offsets =
            distinct_tag_offsets_of(aivpn_common::mask::preset_masks::all().iter());

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
            audit_log,
            mask_feedback: Arc::new(crate::mask_feedback::MaskFeedbackStore::new()),
            mask_preference_throttle: Arc::new(DashMap::new()),
            mask_feedback_throttle: Arc::new(DashMap::new()),
        })
    }

    /// Set (or replace) the multi-hop chain forwarder after server construction.
    pub fn set_chain_forwarder(&mut self, cf: Arc<crate::chain_forwarder::ChainForwarder>) {
        self.chain_forwarder = Some(cf);
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

    /// Start the gateway
    pub async fn run(mut self) -> Result<()> {
        info!("Starting AIVPN Gateway on {}", self.config.listen_addr);
        info!(
            "Per-IP UDP rate limit: {} pps",
            self.config.per_ip_pps_limit
        );

        // Start eBPF observer (no-op when xdp_prog.o is absent)
        Arc::new(EbpfObserver::new(self.event_bus.clone())).start();

        // Create NAT forwarder (requires root — deferred from constructor for testability)
        if self.config.enable_nat {
            let mut nat = NatForwarder::new(
                &self.config.tun_name,
                &self.config.tun_addr,
                &self.config.tun_netmask,
                self.config.tun_mtu,
                self.config.network_config.clone(),
            )?;
            nat.create()?;

            // IPv6 dual-stack (NAT66) — optional, off by default.
            if self.config.network_config.ipv6_enabled {
                let tun = self.config.tun_name.as_str();
                let prefix = self.config.network_config.ipv6_prefix.as_str();
                match crate::nat::setup_nat66(tun, prefix) {
                    Ok(()) => info!("NAT66 configured for prefix {}", prefix),
                    Err(e) => warn!("NAT66 setup failed (non-fatal): {}", e),
                }
                match crate::nat::assign_ipv6_to_tun(tun, "fd10:cafe::1", 48) {
                    Ok(()) => info!("Assigned fd10:cafe::1/48 to {}", tun),
                    Err(e) => warn!("IPv6 TUN address assignment failed (non-fatal): {}", e),
                }
            }

            self.nat_forwarder = Some(Arc::new(nat));
            info!(
                "TUN device: {} ({}/{})",
                self.config.tun_name, self.config.tun_addr, self.config.tun_netmask
            );
        }

        // Create UDP socket with 4MB OS buffers (OPTIMIZATION)
        let bind_addr: SocketAddr =
            self.config
                .listen_addr
                .parse()
                .map_err(|e: std::net::AddrParseError| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        e.to_string(),
                    ))
                })?;

        let socket2_sock = socket2::Socket::new(
            if bind_addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(Error::Io)?;

        socket2_sock.set_nonblocking(true).map_err(Error::Io)?;
        let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
        socket2_sock.bind(&bind_addr.into()).map_err(Error::Io)?;

        let std_sock: std::net::UdpSocket = socket2_sock.into();
        let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;

        info!(
            "UDP listener bound to {} (4MB buffers via socket2)",
            self.config.listen_addr
        );

        self.udp_socket = Some(Arc::new(socket));

        // Wire kernel accelerator to live TUN + UDP socket.
        if let Some(ref ka) = self.kernel_accel {
            let mut tun_ifindex: u32 = 0;
            if self.config.enable_nat {
                let tun_name = self.config.tun_name.as_str();
                if let Ok(cname) = std::ffi::CString::new(tun_name) {
                    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
                    if ifindex > 0 {
                        tun_ifindex = ifindex;
                        if let Err(e) = ka.set_tun(ifindex) {
                            warn!("aivpn: kernel set_tun failed: {e}");
                        } else {
                            info!(
                                "Kernel acceleration wired to TUN {} (ifindex={ifindex})",
                                tun_name
                            );
                        }
                    }
                }
            }
            use std::os::unix::io::AsRawFd;
            let udp_fd = self.udp_socket.as_ref().unwrap().as_raw_fd();
            if let Err(e) = ka.set_udp_sock(udp_fd) {
                warn!("aivpn: kernel set_udp_sock failed: {e}");
            }

            // Kernel downlink (server->client) encryption is OPT-IN and OFF by
            // default: it is a new, live-unproven fast path. Enable it only when
            // AIVPN_KERNEL_DOWNLINK=1 is set in the environment. With it off, the
            // egress hook is never registered and the user-space downlink path
            // (downlink_worker) runs exactly as before.
            let downlink_enabled = std::env::var("AIVPN_KERNEL_DOWNLINK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if downlink_enabled {
                if tun_ifindex == 0 {
                    warn!(
                        "aivpn: AIVPN_KERNEL_DOWNLINK set but TUN ifindex unknown \
                         (enable_nat off?) — downlink egress not enabled"
                    );
                } else if let Err(e) = ka.set_egress(udp_fd, tun_ifindex, true) {
                    warn!("aivpn: kernel set_egress (downlink) failed: {e}");
                } else {
                    KERNEL_DOWNLINK_ARMED.store(true, std::sync::atomic::Ordering::Relaxed);
                    info!(
                        "Kernel downlink egress enabled (tun ifindex={tun_ifindex}) \
                         — server->client encryption offloaded to /dev/aivpn"
                    );
                }
            }
        }

        // Spawn neural resonance check loop (Patent 1 — periodic validation)
        if self.config.enable_neural {
            let neural = self.neural_module.clone();
            let sessions = self.session_manager.clone();
            let catalog = self.mask_catalog.clone();
            let metrics = self.metrics.clone();
            let check_interval = self.config.neural_config.check_interval_secs;
            let socket = self.udp_socket.as_ref().unwrap().clone();
            #[cfg(feature = "neural")]
            let dpi_gate = self.dpi_gate.clone();

            tokio::spawn(async move {
                Self::resonance_check_loop(
                    neural,
                    sessions,
                    catalog,
                    metrics,
                    check_interval,
                    socket,
                    #[cfg(feature = "neural")]
                    dpi_gate,
                )
                .await;
            });
            info!(
                "Neural resonance check loop spawned (interval: {}s)",
                check_interval
            );
        }

        // Spawn TUN → Client read loop (reads packets from TUN, routes back to clients)
        // Also set up channel-based TUN writer for upload path (avoids Mutex contention)
        if let Some(ref nat) = self.nat_forwarder {
            if let Some(tun_reader) = nat.take_reader().await {
                let sessions = self.session_manager.clone();
                let socket = self.udp_socket.as_ref().unwrap().clone();
                let Some(mask) = self
                    .mask_catalog
                    .masks
                    .iter()
                    .next()
                    .map(|e| e.value().clone())
                else {
                    error!("No masks loaded — cannot start gateway");
                    return Ok(());
                };
                let server_vpn_ip = self.config.network_config.server_vpn_ip;
                let recorder = self.recording_manager.clone();

                // Channel for writing packets to TUN device (upload + ICMP replies)
                let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
                self.tun_write_tx = Some(tun_tx.clone());

                // Spawn dedicated TUN writer task — owns the DeviceWriter, no Mutex needed
                if let Some(tun_writer) = nat.take_writer().await {
                    tokio::spawn(async move {
                        Self::tun_write_loop(tun_writer, tun_rx).await;
                    });
                    info!("TUN write loop spawned (channel-based, no Mutex)");
                } else {
                    warn!("Could not take TUN writer — falling back to forward_packet");
                }

                let client_db = self.client_db.clone();
                let qos_enforcer = self.qos_enforcer.clone();
                let allow_peer_routing = self.config.allow_peer_routing;
                let downlink_shaping = self.config.downlink_shaping;
                tokio::spawn(async move {
                    Self::tun_read_loop(
                        tun_reader,
                        tun_tx,
                        sessions,
                        socket,
                        mask,
                        server_vpn_ip,
                        recorder,
                        client_db,
                        qos_enforcer,
                        allow_peer_routing,
                        downlink_shaping,
                    )
                    .await;
                });
                info!("TUN read loop spawned");
            }
        }

        // Spawn periodic session cleanup task (remove expired/idle sessions and stop recordings)
        {
            let sessions = self.session_manager.clone();
            let recorder = self.recording_manager.clone();
            let socket = self.udp_socket.as_ref().unwrap().clone();
            let mdh = self.mask_catalog.packet_mdh_bytes();
            let neural = self.neural_module.clone();
            let client_db_cleanup = self.client_db.clone();
            #[cfg(feature = "neural")]
            let dpi_gate_cleanup = self.dpi_gate.clone();
            let ka_cleanup = self.kernel_accel.clone();
            let rate_limits_cleanup = self.rate_limits.clone();
            let handshake_cooldowns_cleanup = self.handshake_cooldowns.clone();
            let handshake_locks_cleanup = self.handshake_locks.clone();
            let mask_preference_throttle_cleanup = self.mask_preference_throttle.clone();
            let mask_feedback_throttle_cleanup = self.mask_feedback_throttle.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if let Some(ref rec) = recorder {
                        let store = rec.store();
                        for outcome in rec.take_ready_or_stale(
                            aivpn_common::recording::RECORDING_IDLE_TIMEOUT_SECS,
                        ) {
                            let notify_session = match &outcome {
                                RecordingStopOutcome::Completed(completed) => {
                                    sessions.get_session(&completed.session_id)
                                }
                                RecordingStopOutcome::Incomplete(incomplete) => {
                                    sessions.get_session(&incomplete.session_id)
                                }
                                RecordingStopOutcome::NotFound => None,
                            };
                            Self::handle_recording_outcome(
                                &socket,
                                &sessions,
                                &store,
                                &mdh,
                                outcome,
                                notify_session,
                            )
                            .await;
                        }
                    }

                    // Prune stale per-IP rate-limit, handshake-cooldown, and
                    // handshake-lock entries.  handshake_locks is never pruned
                    // elsewhere so it grows without bound under sustained churn.
                    // Entries whose Arc strong_count == 1 have no active waiters
                    // and are safe to remove.
                    rate_limits_cleanup.retain(|_, v| v.1.elapsed() < Duration::from_secs(30));
                    handshake_cooldowns_cleanup
                        .retain(|_, v| v.1.elapsed() < Duration::from_secs(60));
                    handshake_locks_cleanup.retain(|_, v| std::sync::Arc::strong_count(v) > 1);
                    // Prune expired MaskPreference throttle entries so this
                    // DashMap doesn't grow unbounded across session churn —
                    // same pattern as rate_limits/handshake_cooldowns above.
                    // Entries older than the throttle window are dead weight
                    // (the next MaskPreference for that session would not be
                    // throttled anyway).
                    mask_preference_throttle_cleanup
                        .retain(|_, v| v.elapsed() < MASK_PREFERENCE_THROTTLE);
                    // Same pruning for the FIX F MaskFeedback throttle map.
                    mask_feedback_throttle_cleanup
                        .retain(|_, v| v.elapsed() < MASK_FEEDBACK_THROTTLE);

                    // Enforce client revocation on ALREADY-ACTIVE sessions. The
                    // handshake scan only checks enabled/expires_at when creating a
                    // NEW session; once Active, traffic routes purely via the tag
                    // map, so --remove-client / disable / expiry (picked up by the
                    // 10s client-DB hot-reload) would otherwise let a connected
                    // client keep full access indefinitely (it controls its own
                    // keepalives, so it never idles out). Drop any session whose
                    // client is now missing, disabled, or expired.
                    let mut revoked: Vec<[u8; 16]> = Vec::new();
                    if let Some(ref db) = client_db_cleanup {
                        for entry in sessions.iter_sessions() {
                            let (sid, cid) = {
                                let s = entry.value().lock();
                                (s.session_id, s.client_id.clone())
                            };
                            if let Some(cid) = cid {
                                let live = db
                                    .find_by_id(&cid)
                                    .map(|c| {
                                        c.enabled
                                            && c.expires_at.is_none_or(|t| t > chrono::Utc::now())
                                    })
                                    .unwrap_or(false);
                                if !live {
                                    revoked.push(sid);
                                }
                            }
                        }
                        for sid in &revoked {
                            warn!(
                                "Dropping active session {:02x}{:02x}{:02x}{:02x} — client revoked/disabled/expired",
                                sid[0], sid[1], sid[2], sid[3]
                            );
                            sessions.remove_session(sid);
                        }
                    }

                    let expired = sessions.cleanup_expired();
                    // Union of revoked + idle-expired sessions for per-session cleanup.
                    let removed: Vec<[u8; 16]> =
                        revoked.into_iter().chain(expired.into_iter()).collect();
                    for session_id in &removed {
                        // Release per-session neural traffic stats; without this the
                        // neural_module's DashMap grows unbounded as sessions expire.
                        neural.lock().cleanup_stats(*session_id);
                        // Same for the R2 Phase D ML-DPI gate's per-session ring.
                        #[cfg(feature = "neural")]
                        dpi_gate_cleanup.cleanup(session_id);
                        if let Some(ref ka) = ka_cleanup {
                            let _ = ka.session_remove(session_id);
                        }
                    }
                    // Stop active recordings for removed sessions
                    if let Some(ref rec) = recorder {
                        let store = rec.store();
                        for session_id in removed {
                            let outcome = rec.stop_for_session_end(session_id);
                            Self::handle_recording_outcome(
                                &socket, &sessions, &store, &mdh, outcome, None,
                            )
                            .await;
                        }
                    }
                }
            });
            info!("Session cleanup / recording auto-finish task spawned (5s interval)");
        }

        // Spawn periodic §2 mask-feedback bucket sweep. Mirrors the
        // rate_limits/handshake_cooldowns/handshake_locks cleanup pattern
        // above (same "prune stale entries on an interval" shape), but on a
        // much coarser cadence since `MaskFeedbackStore` retention is
        // measured in days, not seconds — this is a backstop for buckets
        // that go quiet well before the store ever hits its hard capacity
        // eviction (see `MaskFeedbackStore::record_feedback`).
        //
        // Also doubles as the refresh point for two `metrics` gauges that
        // are cheapest to maintain by periodic recomputation rather than
        // incrementally at every mutation site:
        //   - `aivpn_feedback_buckets` / `aivpn_feedback_regions`: already
        //     refreshed in real time right after every `record_feedback`
        //     call (see the `MaskFeedback` control-message arm), but that
        //     doesn't observe *evictions* (capacity eviction or this same
        //     sweep's stale-bucket removal) — re-synced here so the gauges
        //     never drift from `bucket_count()`/`region_count()`.
        //   - `aivpn_polymorphic_sessions_active`: counts sessions whose
        //     current mask id starts with `"polymorphic:"`. A session can
        //     leave a polymorphic mask more ways than "session ended" (a
        //     neural-triggered rotation onto a non-polymorphic fallback, a
        //     fresh `MaskPreference` deriving a mask_id — always
        //     `"polymorphic:...")` from a *different* base, etc.), so an
        //     incremental increment/decrement pair would need a correctness
        //     guard at every one of those call sites. A periodic O(active
        //     sessions) scan is simple, always correct, and cheap at the
        //     documented `MAX_SESSIONS = 500` scale — see
        //     `MetricsCollector::set_polymorphic_sessions_active`'s doc
        //     comment for the same rationale.
        {
            let mask_feedback = self.mask_feedback.clone();
            let metrics_sweep = self.metrics.clone();
            let sessions_sweep = self.session_manager.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    let now_hour = current_unix_secs() / 3600;
                    let removed = mask_feedback
                        .sweep_stale(now_hour, crate::mask_feedback::DEFAULT_RETENTION_HOURS);
                    if removed > 0 {
                        debug!("Mask-feedback sweep: evicted {} stale bucket(s)", removed);
                    }
                    metrics_sweep.set_feedback_buckets(mask_feedback.bucket_count());
                    metrics_sweep.set_feedback_regions(mask_feedback.region_count());

                    let polymorphic_active = sessions_sweep
                        .iter_sessions()
                        .filter(|entry| {
                            entry
                                .value()
                                .lock()
                                .mask
                                .as_ref()
                                .is_some_and(|m| m.mask_id.starts_with("polymorphic:"))
                        })
                        .count();
                    metrics_sweep.set_polymorphic_sessions_active(polymorphic_active);
                }
            });
            info!(
                "Mask-feedback bucket sweep task spawned (300s interval, {}h retention)",
                crate::mask_feedback::DEFAULT_RETENTION_HOURS
            );
        }

        // Spawn periodic inline rekey task (PFS key rotation every 30s check, 120s actual)
        {
            let sessions = self.session_manager.clone();
            let socket = self.udp_socket.as_ref().unwrap().clone();
            // Fallback MDH only for sessions with no mask assigned yet; the
            // per-session mask (below) is used whenever present so the KeyRotate
            // is framed with the SAME layout as that session's DATA downlink. A
            // frozen catalog snapshot here would frame the rekey with a
            // different mask than the session's data plane, which — before the
            // client's multi-length decode fallback — permanently stranded the
            // tunnel on the first rekey.
            let fallback_mdh = self.mask_catalog.packet_mdh_bytes();
            tokio::spawn(async move {
                // Two cadences share one task: rekey INITIATION every 30 s
                // (15 × 2 s ticks), and a fast retransmit sweep for pending
                // rekeys every 2 s tick. KeyRotate is one-shot UDP; if it (or
                // the client's response) is lost, the retransmit must land
                // BEFORE the client's RX-silence watchdog (12 s floor) trips
                // — riding the 30 s tick cost a reconnect per lost packet.
                let mut tick: u32 = 0;
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    tick = tick.wrapping_add(1);
                    let mut due = sessions.rekey_retransmits_due();
                    if tick % 15 == 0 {
                        due.extend(sessions.start_rekeying_sessions());
                    }
                    for (session_id, new_eph_pub) in due {
                        if let Some(session) = sessions.get_session(&session_id) {
                            let payload =
                                aivpn_common::protocol::ControlPayload::KeyRotate { new_eph_pub };
                            let mdh = session
                                .lock()
                                .mask
                                .as_ref()
                                .map(packet_mdh_bytes_for_mask)
                                .unwrap_or_else(|| fallback_mdh.clone());
                            if let Err(e) = Self::send_control_message_via(
                                socket.as_ref(),
                                &mdh,
                                &payload,
                                &session,
                            )
                            .await
                            {
                                warn!("Inline rekey: failed to send KeyRotate to session: {}", e);
                            } else {
                                info!("Inline rekey: KeyRotate sent to session");
                            }
                        }
                    }
                }
            });
            info!(
                "Inline rekey task spawned (30s initiation, 120s rekey period, \
                 2s retransmit sweep)"
            );
        }

        // Spawn client DB stats flush task (persist traffic stats every 5 min)
        if let Some(ref db) = self.client_db {
            let db = db.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    db.flush_stats();
                }
            });
            info!("Client stats flush task spawned (300s interval)");
        }

        // Spawn client DB hot-reload task (pick up new clients without restart)
        if let Some(ref db) = self.client_db {
            let db = db.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    db.reload_if_changed();
                }
            });
            info!("Client DB hot-reload task spawned (10s interval)");
        }

        // Spawn bootstrap descriptor rotation task. Descriptors were
        // previously only ever built once at Gateway::new() and went stale
        // (expires_at) after ~3 days of uptime; this checks hourly whether
        // the epoch has advanced and rebuilds+swaps the shared descriptors
        // if so. Auto-publish (when configured) only fires on an actual
        // epoch change, not on every hourly check.
        {
            let bootstrap_descriptors = self.bootstrap_descriptors.clone();
            let server_private_key = self.config.server_private_key;
            let bootstrap_masks = self.config.bootstrap_masks.clone();
            let bootstrap_publish = self.config.bootstrap_publish.clone();
            let mut last_epoch = bootstrap_epoch(current_unix_secs());
            tokio::spawn(async move {
                let signing_key = derive_server_signing_key(&server_private_key);
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    let epoch = bootstrap_epoch(current_unix_secs());
                    if epoch == last_epoch {
                        continue;
                    }
                    last_epoch = epoch;
                    let fresh = build_bootstrap_descriptors(
                        &server_private_key,
                        &signing_key,
                        &bootstrap_masks,
                    );
                    *bootstrap_descriptors.write() = fresh.clone();
                    info!("Bootstrap descriptors rotated (epoch {epoch})");

                    if let Some(publish_config) = &bootstrap_publish {
                        match serde_json::to_string(&fresh) {
                            Ok(json) => {
                                crate::bootstrap_publish::publish_all(&json, publish_config).await
                            }
                            Err(e) => error!(
                                "Failed to serialize rotated bootstrap descriptors for publish: {e}"
                            ),
                        }
                    }
                }
            });
            info!("Bootstrap descriptor rotation task spawned (hourly epoch check, 24h rotation)");
        }

        // Use session-aware receive sharding: preserve ordering within one
        // session, but allow different sessions to make progress in parallel.
        let gateway = Arc::new(self);
        Self::process_packets_concurrent(gateway).await?;

        Ok(())
    }

    /// Background task: periodic neural resonance checks (Patent 1)
    ///
    /// For each active session, computes reconstruction error between
    /// observed traffic features and the assigned mask's signature vector.
    /// If MSE exceeds threshold → mask is detected as compromised by DPI.
    /// Triggers automatic mask rotation (Patent 3).
    async fn resonance_check_loop(
        neural: Arc<parking_lot::Mutex<NeuralResonanceModule>>,
        sessions: Arc<SessionManager>,
        catalog: Arc<MaskCatalog>,
        metrics: Arc<MetricsCollector>,
        check_interval_secs: u64,
        socket: Arc<UdpSocket>,
        #[cfg(feature = "neural")] dpi_gate: Arc<crate::dpi_gate::DpiGate>,
    ) {
        let interval = Duration::from_secs(check_interval_secs);

        loop {
            tokio::time::sleep(interval).await;

            // Collect session IDs and their ACTIVE mask profiles. Capturing the
            // full profile (not just the id) lets the loop bake an encoder
            // on-demand for per-session bootstrap/polymorphic masks whose dynamic
            // mask_id is absent from the static startup-baked encoders.
            let session_checks: Vec<([u8; 16], MaskProfile)> = sessions
                .iter_sessions()
                .filter_map(|entry| {
                    let sess = entry.value().lock();
                    sess.mask.as_ref().map(|m| (sess.session_id, m.clone()))
                })
                .collect();

            if session_checks.is_empty() {
                continue;
            }

            // Collect mask update packets to send AFTER releasing the neural lock
            // (parking_lot::MutexGuard is !Send, cannot hold across .await)
            let mut pending_sends: Vec<(Vec<u8>, std::net::SocketAddr, [u8; 16], MaskProfile)> =
                Vec::new();

            {
                let mut neural_guard = neural.lock();

                for (session_id, mask) in &session_checks {
                    let mask_id = &mask.mask_id;
                    // Bake an encoder for this session's active mask if the static
                    // startup set didn't cover it (bootstrap/polymorphic variants).
                    // A short/empty signature_vector legitimately has no encoder
                    // (neural inactive for that mask) — ignore that error.
                    let _ = neural_guard.ensure_encoder(mask);
                    // Check neural resonance (Patent 1: Signal Reconstruction Resonance)
                    match neural_guard.check_resonance(*session_id, mask_id) {
                        Ok(result) => {
                            debug!(
                                "neural check: mask='{}' status={:?} mse={:.6} msg={:?}",
                                mask_id, result.status, result.mse, result.message
                            );
                            metrics
                                .record_neural_check(result.status == ResonanceStatus::Compromised);

                            match result.status {
                                ResonanceStatus::Compromised => {
                                    if !neural_guard.can_rotate(mask_id) {
                                        debug!(
                                            "Mask '{}' compromised (MSE={:.4}) but rotation on cooldown — skipping",
                                            mask_id, result.mse
                                        );
                                        continue;
                                    }
                                    warn!(
                                        "Mask '{}' compromised (MSE={:.4}) — triggering rotation (Patent 3)",
                                        mask_id, result.mse
                                    );

                                    neural_guard.record_rotation(mask_id);

                                    // Mark mask as compromised in catalog
                                    catalog.mark_compromised(mask_id);

                                    // Select fallback mask
                                    if let Some(new_mask) = catalog.select_fallback(mask_id) {
                                        info!(
                                            "Auto-rotating to mask '{}' ({} masks remaining)",
                                            new_mask.mask_id,
                                            catalog.available_count()
                                        );

                                        if let Some(session) = sessions.get_session(session_id) {
                                            let client_addr = session.lock().client_addr;
                                            match sessions
                                                .build_mask_update_packet(&session, &new_mask)
                                            {
                                                Ok(packet) => {
                                                    pending_sends.push((
                                                        packet,
                                                        client_addr,
                                                        *session_id,
                                                        new_mask.clone(),
                                                    ));
                                                }
                                                Err(e) => {
                                                    warn!(
                                                        "Failed to build MaskUpdate packet: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }

                                        metrics.record_mask_rotation();
                                        // Skip the anomaly check below — one MaskUpdate per
                                        // iteration is enough (prevents double rotation).
                                        continue;
                                    } else {
                                        error!(
                                            "No fallback masks available! All masks compromised."
                                        );
                                    }
                                }
                                ResonanceStatus::Warning => {
                                    debug!(
                                        "Mask '{}' warning (MSE={:.4}) — monitoring",
                                        mask_id, result.mse
                                    );
                                }
                                ResonanceStatus::Healthy => {
                                    // All good
                                }
                                ResonanceStatus::Skip => {
                                    // Not enough data or model not loaded
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Resonance check error for session: {}", e);
                        }
                    }

                    // R2 Phase D — inline ML-DPI gate (SIBLING to the neural MSE
                    // check above). Neural resonance detects drift from the
                    // mask's own fingerprint; this detects drift toward a
                    // tunnel/Unknown DPI classification. Same rotate action, same
                    // cooldown. Reached only when the neural branch did NOT
                    // already rotate (Compromised `continue`s), so the two never
                    // double-fire on one session in one pass.
                    // verdict() runs a full GBDT inference over the window, so
                    // compute it ONCE and reuse for both the debug line and the
                    // rotation decision.
                    #[cfg(feature = "neural")]
                    let dpi_verdict = dpi_gate.verdict(session_id);
                    #[cfg(feature = "neural")]
                    match &dpi_verdict {
                        Some(v) => debug!(
                            "dpi_gate verdict: mask='{}' reads_as_tunnel={} p={:.4}",
                            mask_id, v.reads_as_tunnel, v.tunnel_prob
                        ),
                        None => debug!(
                            "dpi_gate verdict: mask='{}' abstain (ring not full)",
                            mask_id
                        ),
                    }
                    #[cfg(feature = "neural")]
                    if let Some(verdict) = dpi_verdict {
                        if verdict.reads_as_tunnel && neural_guard.can_rotate(mask_id) {
                            warn!(
                                "ML-DPI gate: mask '{}' reads as tunnel (p={:.3}) — triggering rotation (R2 Phase D)",
                                mask_id, verdict.tunnel_prob
                            );
                            neural_guard.record_rotation(mask_id);
                            catalog.mark_compromised(mask_id);
                            if let Some(new_mask) = catalog.select_fallback(mask_id) {
                                info!(
                                    "ML-DPI-triggered rotation to mask '{}' ({} masks remaining)",
                                    new_mask.mask_id,
                                    catalog.available_count()
                                );
                                if let Some(session) = sessions.get_session(session_id) {
                                    let client_addr = session.lock().client_addr;
                                    if let Ok(packet) =
                                        sessions.build_mask_update_packet(&session, &new_mask)
                                    {
                                        pending_sends.push((
                                            packet,
                                            client_addr,
                                            *session_id,
                                            new_mask.clone(),
                                        ));
                                    }
                                }
                                metrics.record_mask_rotation();
                                // One MaskUpdate per iteration — skip the anomaly
                                // check to avoid double rotation.
                                continue;
                            } else {
                                error!("No fallback masks available! All masks compromised.");
                            }
                        }
                    }

                    // Check anomaly detection (DPI blocking indicators)
                    if neural_guard.is_mask_anomalous(mask_id) {
                        warn!(
                            "Anomaly detected for mask '{}' (packet loss / RTT spike)",
                            mask_id
                        );
                        metrics.record_dpi_attack();
                        catalog.mark_compromised(mask_id);

                        if let Some(new_mask) = catalog.select_fallback(mask_id) {
                            info!("Anomaly-triggered rotation to mask '{}'", new_mask.mask_id);
                            if let Some(session) = sessions.get_session(session_id) {
                                let client_addr = session.lock().client_addr;
                                if let Ok(packet) =
                                    sessions.build_mask_update_packet(&session, &new_mask)
                                {
                                    pending_sends.push((
                                        packet,
                                        client_addr,
                                        *session_id,
                                        new_mask.clone(),
                                    ));
                                }
                            }
                            metrics.record_mask_rotation();
                        }
                    }
                }
            } // neural_guard dropped here

            // Send collected MaskUpdate packets (async, safe now)
            for (packet, client_addr, session_id, new_mask) in pending_sends {
                if let Err(e) = socket.send_to(&packet, client_addr).await {
                    warn!("Failed to send MaskUpdate to {}: {}", client_addr, e);
                } else {
                    sessions.update_session_mask(&session_id, new_mask);
                    info!("MaskUpdate control message sent to {}", client_addr);
                }
            }
        }
    }

    /// TUN read loop: reads packets from TUN device and routes them back to clients
    async fn tun_read_loop(
        mut tun_reader: tun::DeviceReader,
        tun_writer: tokio::sync::mpsc::Sender<Vec<u8>>,
        sessions: Arc<SessionManager>,
        socket: Arc<UdpSocket>,
        mask: MaskProfile,
        server_vpn_ip: Ipv4Addr,
        recorder: Option<Arc<RecordingManager>>,
        client_db: Option<Arc<ClientDatabase>>,
        qos_enforcer: Arc<crate::qos::QosEnforcer>,
        allow_peer_routing: bool,
        downlink_shaping: bool,
    ) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let server_ip = server_vpn_ip;

        // A1: shard the downlink across workers by destination VPN IP so
        // encryption for different clients runs in parallel. One dst IP always
        // maps to the same worker (one session per VPN IP), so per-client
        // packet order — and thus per-session nonce/seq monotonicity on the
        // wire — is preserved. Mirrors the uplink sharding in
        // process_packets_concurrent.
        let worker_count = Self::receive_worker_count();
        let mut worker_txs = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(4096);
            worker_txs.push(tx);
            tokio::spawn(Self::downlink_worker(
                rx,
                worker_id,
                sessions.clone(),
                socket.clone(),
                mask.clone(),
                recorder.clone(),
                client_db.clone(),
                qos_enforcer.clone(),
                downlink_shaping,
            ));
        }
        info!("Downlink sharded across {} workers", worker_count);

        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => continue,
                Ok(n) => {
                    let packet = &buf[..n];

                    // Parse destination IP from IP header
                    if packet.len() < 20 || (packet[0] >> 4) != 4 {
                        continue; // Not IPv4
                    }
                    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                    // Handle ICMP echo request to server's own IP (ping to gateway)
                    if dst_ip == server_ip && packet.len() >= 28 && packet[9] == 1 {
                        // ICMP packet to server — generate echo reply
                        if let Some(reply) = Self::build_icmp_echo_reply(packet, &server_ip) {
                            let _ = tun_writer.send(reply).await;
                        }
                        continue;
                    }

                    // Guard client-to-client relay (0.9.0+).
                    // If the packet's source IP belongs to a VPN client session,
                    // this is intra-VPN (peer-to-peer) traffic — only forward when
                    // allow_peer_routing is enabled.
                    if !allow_peer_routing {
                        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                        if sessions.get_session_by_vpn_ip(&src_ip).is_some() {
                            debug!(
                                "TUN: dropping peer packet {}->{} (allow_peer_routing=false)",
                                src_ip, dst_ip
                            );
                            continue;
                        }
                    }

                    let worker_idx = (u32::from(dst_ip) as usize) % worker_count;
                    if worker_txs[worker_idx].send(packet.to_vec()).await.is_err() {
                        warn!(
                            "Downlink worker {} channel closed — dropping packet for {}",
                            worker_idx, dst_ip
                        );
                    }
                }
                Err(e) => {
                    error!("TUN read error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Per-worker downlink processing (A1): session lookup, QoS, encryption
    /// and UDP send for every packet whose dst VPN IP shards to this worker.
    #[allow(clippy::too_many_arguments)]
    async fn downlink_worker(
        mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        worker_id: usize,
        sessions: Arc<SessionManager>,
        socket: Arc<UdpSocket>,
        mask: MaskProfile,
        recorder: Option<Arc<RecordingManager>>,
        client_db: Option<Arc<ClientDatabase>>,
        qos_enforcer: Arc<crate::qos::QosEnforcer>,
        downlink_shaping: bool,
    ) {
        // A7: RNG for downlink padding size sampling + filler bytes. Per-worker
        // (not per-packet) to avoid re-seeding on the hot path.
        let mut rng = rand::rngs::StdRng::from_entropy();

        // Reusable per-packet scratch buffers, hoisted out of the loop to kill
        // per-datagram heap allocations on the downlink hot path (A3). Each is
        // `.clear()`ed and refilled every iteration instead of being allocated
        // fresh. `plaintext_buf` holds cleartext (pad_len || inner_header ||
        // IP packet || padding) and is zeroized after use so no VPN payload
        // lingers in the pooled allocation.
        let mut plaintext_buf: Vec<u8> = Vec::with_capacity(MAX_PACKET_SIZE);
        let mut ciphertext_buf: Vec<u8> =
            Vec::with_capacity(MAX_PACKET_SIZE + aivpn_common::crypto::POLY1305_TAG_SIZE);

        // A2: drain up to MAX_BATCH queued packets per wakeup, encrypt them
        // all into per-slot wire buffers, then push the whole batch out with
        // one sendmmsg. Order within the worker — and therefore per client —
        // is unchanged. Wire buffers are reused across batches.
        let batch_io = crate::batch_io::BatchIo::new(socket.clone());
        let mut wire_bufs: Vec<Vec<u8>> = (0..crate::batch_io::MAX_BATCH)
            .map(|_| Vec::with_capacity(MAX_PACKET_SIZE))
            .collect();
        let mut drained: Vec<Vec<u8>> = Vec::with_capacity(crate::batch_io::MAX_BATCH);
        #[allow(clippy::type_complexity)]
        let mut sends: Vec<(
            SocketAddr,
            Option<([u8; 16], aivpn_common::recording::PacketMetadata)>,
        )> = Vec::with_capacity(crate::batch_io::MAX_BATCH);

        while let Some(first) = rx.recv().await {
            drained.clear();
            drained.push(first);
            while drained.len() < crate::batch_io::MAX_BATCH {
                match rx.try_recv() {
                    Ok(p) => drained.push(p),
                    Err(_) => break,
                }
            }

            sends.clear();
            for packet_vec in drained.drain(..) {
                let packet = packet_vec.as_slice();
                let n = packet.len();
                // Reader already validated this is an IPv4 header of >= 20 bytes.
                let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                // Find session by VPN IP
                let session = match sessions.get_session_by_vpn_ip(&dst_ip) {
                    Some(s) => s,
                    None => {
                        debug!("TUN: no session for VPN IP {}", dst_ip);
                        continue;
                    }
                };

                // QoS: enforce downstream rate limit before expensive encryption
                let qos_cid = { session.lock().client_id.clone() };
                if let Some(ref cid) = qos_cid {
                    if !qos_enforcer.check_downstream(cid, n as u64) {
                        debug!("QoS: downstream rate limited, dropping packet for {}", cid);
                        continue;
                    }
                }

                // Build encrypted response packet
                // Minimize lock duration: extract only what we need under lock, then encrypt outside
                let (session_id, client_addr, downlink_iat_ms, tag, mdh) = {
                    let mut sess = session.lock();
                    // Commit deferred mask switch if grace period has elapsed
                    sess.commit_pending_mask();
                    let session_id = sess.session_id;
                    let client_addr = sess.client_addr;
                    let seq_num = sess.next_seq() as u16;
                    let (nonce, counter) = sess.next_send_nonce();
                    // Downlink (server→client) uses the S2C key so it never
                    // shares a (key, nonce) with the client's uplink packets.
                    let key = sess.keys.session_key_s2c.clone();
                    let tag_secret = sess.keys.tag_secret;
                    let downlink_iat_ms = sess.last_server_send.elapsed().as_secs_f64() * 1000.0;
                    sess.last_server_send = Instant::now();
                    // Use the session's own mask for MDH so the client can
                    // decode with the mask it currently expects (bootstrap
                    // or runtime after MaskUpdate is processed).
                    let session_mdh = sess
                        .mask
                        .as_ref()
                        .map(packet_mdh_bytes_for_mask)
                        .unwrap_or_else(|| mask.header_template.clone());

                    // A7: size downlink padding from the SESSION mask's own size
                    // distribution — the same distribution + padding strategy the
                    // client applies to uplink — so both directions share one size
                    // signature on the 5-tuple. Computed under the lock while the
                    // mask is borrowed; the filler bytes are written after the lock
                    // is dropped. Legacy downlink framing: base overhead carries the
                    // TAG_SIZE prefix, the 2-byte pad_len field, and the AEAD tag.
                    let pad_len: u16 = if downlink_shaping {
                        if let Some(ref m) = sess.mask {
                            let base_overhead = TAG_SIZE
                                + session_mdh.len()
                                + 2
                                + n
                                + aivpn_common::crypto::POLY1305_TAG_SIZE;
                            let target = m.size_distribution.sample(&mut rng);
                            let requested =
                                m.padding_strategy
                                    .calc_padding(base_overhead, target, &mut rng);
                            let max_pad = SAFE_DOWNLINK_BUDGET.saturating_sub(base_overhead) as u16;
                            requested.min(max_pad)
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    // Pre-accumulate downlink bytes estimate (IP packet + overhead)
                    // This avoids a second lock after send_to
                    let estimated_out = (n + 64) as u64; // packet + AIVPN overhead
                    sess.pending_bytes_out = sess.pending_bytes_out.saturating_add(estimated_out);
                    // Flush downlink-only traffic to client_db when threshold reached
                    let flush_out = if sess.pending_bytes_out >= 64 * 1024 {
                        let bytes = sess.pending_bytes_out;
                        let cid = sess.client_id.clone();
                        sess.pending_bytes_out = 0;
                        cid.map(|c| (c, bytes))
                    } else {
                        None
                    };
                    drop(sess); // Release lock BEFORE expensive encryption
                                // Flush outside lock
                    if let (Some(ref db), Some((cid, bytes))) = (&client_db, flush_out) {
                        db.record_traffic(&cid, 0, bytes);
                    }

                    // Build inner payload: Data type + IP packet
                    let inner_header = InnerHeader {
                        inner_type: InnerType::Data,
                        seq_num,
                    };

                    // Build MDH using session mask (not global runtime mask)
                    let mdh = session_mdh;

                    // Assemble cleartext into the reused scratch buffer:
                    //   pad_len(LE u16) || inner_header || IP packet || padding
                    // Identical framing to the client's uplink `build_packet`
                    // (`pad_len || plaintext || random_pad`) so the client's
                    // `parse_downlink_inner` strips exactly `pad_len` trailing
                    // bytes. With A7 shaping off, pad_len is 0 and the layout is
                    // byte-identical to the pre-A7 downlink.
                    plaintext_buf.clear();
                    plaintext_buf.extend_from_slice(&pad_len.to_le_bytes());
                    plaintext_buf.extend_from_slice(&inner_header.encode());
                    plaintext_buf.extend_from_slice(packet);
                    if pad_len > 0 {
                        let pad_start = plaintext_buf.len();
                        plaintext_buf.resize(pad_start + pad_len as usize, 0);
                        rng.fill_bytes(&mut plaintext_buf[pad_start..]);
                    }

                    // Encrypt in place into the reused ciphertext buffer
                    // (outside lock). Produces the same bytes as
                    // encrypt_payload(&key, &nonce, &padded) did.
                    if let Err(e) =
                        encrypt_payload_into(&key, &nonce, &plaintext_buf, &mut ciphertext_buf)
                    {
                        debug!("TUN: encrypt error: {}", e);
                        plaintext_buf.zeroize();
                        continue;
                    }
                    // Cleartext VPN payload no longer needed — wipe before
                    // the buffer is reused on the next iteration.
                    plaintext_buf.zeroize();

                    // Generate tag (outside lock)
                    let time_window = crypto::compute_time_window(
                        crypto::current_timestamp_ms(),
                        aivpn_common::crypto::DEFAULT_WINDOW_MS,
                    );
                    let tag = crypto::generate_resonance_tag(&tag_secret, counter, time_window);

                    (session_id, client_addr, downlink_iat_ms, tag, mdh)
                };

                // Assemble: TAG | MDH | ciphertext into this packet's wire slot.
                let wire_buf = &mut wire_bufs[sends.len()];
                wire_buf.clear();
                wire_buf.extend_from_slice(&tag);
                wire_buf.extend_from_slice(&mdh);
                wire_buf.extend_from_slice(&ciphertext_buf);

                // bytes_out already tracked inside the earlier lock scope.
                // Recorder metadata is captured now (entropy needs this
                // packet's ciphertext before the scratch buffer is reused)
                // and emitted after the batch send below.
                let rec_meta = match recorder {
                    Some(ref r) if r.is_recording(&session_id) => Some((
                        session_id,
                        aivpn_common::recording::PacketMetadata {
                            direction: aivpn_common::recording::Direction::Downlink,
                            size: wire_buf.len() as u16,
                            iat_ms: downlink_iat_ms,
                            entropy: Self::compute_entropy(&ciphertext_buf) as f32,
                            // Learn the app header from the cleartext inner IP
                            // packet (`packet`), NOT the encrypted wire framing
                            // — see inner_l7_prefix.
                            header_prefix: inner_l7_prefix(packet),
                            timestamp_ns: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos() as u64,
                        },
                    )),
                    _ => None,
                };
                sends.push((client_addr, rec_meta));
            }

            if sends.is_empty() {
                continue;
            }
            let msgs: Vec<(&[u8], SocketAddr)> = sends
                .iter()
                .enumerate()
                .map(|(i, (addr, _))| (wire_bufs[i].as_slice(), *addr))
                .collect();
            match batch_io.send_batch(&msgs).await {
                Err(e) => debug!("TUN: batched send failed: {}", e),
                Ok(()) => {
                    if let Some(ref recorder) = recorder {
                        drop(msgs);
                        for (_, rec) in sends.drain(..) {
                            if let Some((sid, meta)) = rec {
                                recorder.record_packet(sid, meta);
                            }
                        }
                    }
                }
            }
        }
        warn!("Downlink worker {} ended — channel closed", worker_id);
    }

    /// Build ICMP Echo Reply from Echo Request
    fn build_icmp_echo_reply(request: &[u8], server_ip: &Ipv4Addr) -> Option<Vec<u8>> {
        if request.len() < 28 {
            return None;
        }

        // Parse source IP
        let src_ip = Ipv4Addr::new(request[12], request[13], request[14], request[15]);

        // Parse ICMP type and code
        let icmp_type = request[20];
        if icmp_type != 8 {
            return None; // Not echo request
        }

        // Build reply: swap src/dst IP, change ICMP type to 0 (echo reply)
        let mut reply = Vec::with_capacity(request.len());

        // IP header
        reply.push(0x45); // Version 4, IHL 5
        reply.push(0x00); // DSCP/ECN
        let total_len = (request.len() as u16).to_be_bytes();
        reply.extend_from_slice(&total_len);
        reply.extend_from_slice(&request[4..6]); // Identification
        reply.extend_from_slice(&request[6..8]); // Flags/Fragment
        reply.push(64); // TTL
        reply.push(1); // Protocol: ICMP
        reply.push(0); // Header checksum (will be computed by kernel)
        reply.push(0);
        reply.extend_from_slice(&server_ip.octets()); // Source IP (server)
        reply.extend_from_slice(&src_ip.octets()); // Dest IP (client)

        // ICMP header
        reply.push(0); // Type: Echo Reply
        reply.push(request[21]); // Code
        reply.push(0); // Checksum placeholder
        reply.push(0);
        reply.extend_from_slice(&request[24..28]); // ID + Sequence
        reply.extend_from_slice(&request[28..]); // Data

        // Compute ICMP checksum
        let checksum = Self::compute_checksum(&reply[20..]);
        reply[22] = (checksum >> 8) as u8;
        reply[23] = (checksum & 0xFF) as u8;

        Some(reply)
    }

    /// Compute Internet checksum (RFC 1071)
    fn compute_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        // Process 16-bit words
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }

        // Add remaining byte
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Dedicated TUN writer task — owns the DeviceWriter, no Mutex contention
    async fn tun_write_loop(mut writer: tun::DeviceWriter, mut rx: mpsc::Receiver<Vec<u8>>) {
        while let Some(packet) = rx.recv().await {
            if let Err(e) = writer.write_all(&packet).await {
                error!("TUN write error: {}", e);
            }
            // No flush() — let the OS buffer writes for throughput
        }
        warn!("TUN write loop ended — channel closed");
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

    /// Candidate resonance tags for a packet — one per distinct layout offset
    /// that fits in the packet. `candidates[0]` is always the legacy offset-0
    /// tag.
    fn candidate_tags(&self, packet_data: &[u8]) -> Vec<[u8; TAG_SIZE]> {
        self.distinct_tag_offsets()
            .into_iter()
            .filter_map(|off| {
                let end = off.checked_add(TAG_SIZE)?;
                if packet_data.len() < end {
                    return None;
                }
                let mut tag = [0u8; TAG_SIZE];
                tag.copy_from_slice(&packet_data[off..end]);
                Some(tag)
            })
            .collect()
    }

    /// Resolve an incoming packet to an existing session, trying the resonance
    /// tag at every layout offset (legacy prefix at 0 plus each embedded mask
    /// offset). Returns the matched session, its validated counter, whether the
    /// matched tag was a ratcheted-key tag, and the resolved 8-byte tag (needed
    /// by the caller for downstream bookkeeping).
    ///
    /// Cheap O(1) `tag_map` probes run first and cover the common in-window case
    /// for BOTH layouts — critical, because an embedded-layout data packet never
    /// matches at offset 0, so relying on the gated scan would drop it under
    /// load or misroute it into the handshake path. Only if every fast probe
    /// misses AND the global fallback budget allows do the expensive
    /// drift-recovery scans run: `refresh_and_find_by_tag` refreshes stale
    /// entries in the `tag_map` (so we re-probe every offset afterwards to
    /// also recover embedded sessions), then `recover_session_by_tag`
    /// brute-forces counter drift per offset.
    ///
    /// A positive `tag_map` hit whose `validate_tag` fails is a replay / out-of
    /// -window packet for a KNOWN session and is dropped (`Err`), exactly like
    /// the original single-offset fast path — it never falls through to
    /// speculative handshake.
    fn find_existing_session(
        &self,
        packet_data: &[u8],
        client_ip: &IpAddr,
    ) -> Result<Option<(Arc<parking_lot::Mutex<Session>>, u64, bool, [u8; TAG_SIZE])>> {
        let tags = self.candidate_tags(packet_data);

        // 1) Fast O(1) path across all layout offsets — no scan.
        for tag in &tags {
            if let Some(session) = self.session_manager.get_session_by_tag(tag) {
                // Drop the lock guard before moving `session` into the result.
                let validated = session.lock().validate_tag(tag);
                return match validated {
                    Some((counter, is_ratcheted)) => {
                        Ok(Some((session, counter, is_ratcheted, *tag)))
                    }
                    None => Err(Error::InvalidPacket("Invalid tag")),
                };
            }
        }

        if !self.fallback_scan_allowed() {
            return Ok(None);
        }

        // 2) Window-drift refresh. `refresh_and_find_by_tag` rebuilds STALE
        //    sessions' tag windows (skipping already-current ones) and
        //    re-inserts current-window tags into `tag_map` as a side effect,
        //    so run it once with the legacy-offset tag, then re-probe every
        //    offset against the freshly refreshed map to also catch
        //    embedded-layout (and roamed-IP) sessions.
        if let Some(first) = tags.first() {
            if let Some((session, counter, is_ratcheted)) = self
                .session_manager
                .refresh_and_find_by_tag(first, client_ip)
            {
                return Ok(Some((session, counter, is_ratcheted, *first)));
            }
        }
        for tag in &tags {
            if let Some(session) = self.session_manager.get_session_by_tag(tag) {
                // Drop the lock guard before moving `session` into the result.
                let validated = session.lock().validate_tag(tag);
                return match validated {
                    Some((counter, is_ratcheted)) => {
                        Ok(Some((session, counter, is_ratcheted, *tag)))
                    }
                    None => Err(Error::InvalidPacket("Invalid tag")),
                };
            }
        }

        // 3) Counter-drift recovery across every offset.
        for tag in &tags {
            if let Some((session, counter, is_ratcheted)) =
                self.session_manager.recover_session_by_tag(tag, client_ip)
            {
                return Ok(Some((session, counter, is_ratcheted, *tag)));
            }
        }

        Ok(None)
    }

    fn receive_worker_count() -> usize {
        std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(4)
            .clamp(2, 16)
    }

    fn worker_index_for_packet(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
        worker_count: usize,
    ) -> usize {
        if worker_count <= 1 {
            return 0;
        }

        let mut shard_addr = client_addr;

        // Resolve the session by trying the resonance tag at every layout
        // offset (legacy prefix at 0 plus each embedded mask offset) so an
        // embedded-layout packet still shards onto its session's worker. A miss
        // falls back to hashing the client address, which is stable per client.
        for tag in self.candidate_tags(packet_data) {
            if let Some(session) = self.session_manager.get_session_by_tag(&tag) {
                shard_addr = session.lock().client_addr;
                break;
            }
        }

        let key = match shard_addr.ip() {
            IpAddr::V4(ip) => ((u32::from(ip) as u64) << 16) | shard_addr.port() as u64,
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                u64::from_le_bytes(octets[..8].try_into().unwrap()) ^ shard_addr.port() as u64
            }
        };

        (key as usize) % worker_count
    }

    /// Concurrent packet processing loop with shard workers.
    /// Packets for the same session stay on the same worker and preserve order,
    /// while different sessions can be processed in parallel.
    async fn process_packets_concurrent(gateway: Arc<Self>) -> Result<()> {
        let socket = gateway.udp_socket.as_ref().unwrap().clone();
        let worker_count = Self::receive_worker_count();
        let queue_depth = 4096;
        let mut worker_txs = Vec::with_capacity(worker_count);

        for worker_id in 0..worker_count {
            let (tx, mut rx) = mpsc::channel::<QueuedPacket>(queue_depth);
            worker_txs.push(tx);

            let gw = gateway.clone();
            tokio::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if let Err(e) = gw
                        .handle_packet(&packet.packet_data, packet.client_addr)
                        .await
                    {
                        debug!(
                            "Worker {} packet error from {}: {}",
                            worker_id,
                            hash_addr(&packet.client_addr),
                            e
                        );
                    }
                }
                warn!("Receive worker {} ended — channel closed", worker_id);
            });
        }

        // A2: pull datagrams in batches (recvmmsg on Linux) — one syscall per
        // up-to-64 packets instead of one per packet. Buffers are reused
        // across iterations; only the per-worker handoff copies.
        let batch_io = crate::batch_io::BatchIo::new(socket.clone());
        let mut slots: Vec<crate::batch_io::RecvSlot> = (0..crate::batch_io::MAX_BATCH)
            .map(|_| crate::batch_io::RecvSlot::new(MAX_PACKET_SIZE))
            .collect();

        loop {
            match batch_io.recv_batch(&mut slots).await {
                Ok(filled) => {
                    for slot in &slots[..filled] {
                        let Some(client_addr) = slot.addr else {
                            continue;
                        };
                        // Per-IP rate limiting (fast, stays in recv task)
                        {
                            let now = Instant::now();
                            let mut entry = gateway
                                .rate_limits
                                .entry(client_addr.ip())
                                .or_insert((0, now));
                            if entry.1.elapsed() > Duration::from_secs(1) {
                                entry.0 = 0;
                                entry.1 = now;
                            }
                            entry.0 += 1;
                            if entry.0 > gateway.config.per_ip_pps_limit {
                                continue;
                            }
                        }

                        let packet_data = slot.packet().to_vec();
                        let worker_idx = gateway.worker_index_for_packet(
                            &packet_data,
                            client_addr,
                            worker_count,
                        );
                        let packet = QueuedPacket {
                            packet_data,
                            client_addr,
                        };

                        if worker_txs[worker_idx].send(packet).await.is_err() {
                            warn!(
                                "Receive worker {} channel closed — dropping packet from {}",
                                worker_idx, client_addr
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Main packet processing loop (legacy sequential — unused, kept for reference)
    #[allow(dead_code)]
    async fn process_packets(&self) -> Result<()> {
        let socket = self.udp_socket.as_ref().unwrap();
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    // Per-IP rate limiting.
                    {
                        let now = Instant::now();
                        let mut entry =
                            self.rate_limits.entry(client_addr.ip()).or_insert((0, now));
                        if entry.1.elapsed() > Duration::from_secs(1) {
                            entry.0 = 0;
                            entry.1 = now;
                        }
                        entry.0 += 1;
                        if entry.0 > self.config.per_ip_pps_limit {
                            continue;
                        }
                    }

                    let packet_data = &buf[..len];

                    // Process packet
                    if let Err(e) = self.handle_packet(packet_data, client_addr).await {
                        debug!("Packet error from {}: {}", hash_addr(&client_addr), e);
                        // Silent drop - no response for invalid packets
                    }
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Handle incoming packet
    async fn handle_packet(&self, packet_data: &[u8], client_addr: SocketAddr) -> Result<()> {
        // Minimum packet size check
        if packet_data.len() < TAG_SIZE + 2 {
            return Err(Error::InvalidPacket("Too short"));
        }

        // Extract the legacy-offset resonance tag. For a new-layout (embedded)
        // packet this is the real protocol header rather than the tag — the
        // actual tag is resolved layout-aware by `find_existing_session` (data
        // path) or per candidate mask in the handshake path below, and `tag` is
        // reassigned to the resolved value there.
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&packet_data[0..TAG_SIZE]);

        // Default layout from runtime primary mask (used for handshake fallback).
        let (catalog_mdh_len, catalog_hs_mdh_len, _eph_offset, _eph_len) =
            self.mask_catalog.packet_layout();
        let catalog_tag_offset = self
            .mask_catalog
            .primary_mask()
            .map(|m| m.tag_offset)
            .unwrap_or(u16::MAX);
        let mut is_new_session = false;
        // Existing-session lookup — layout-aware across every tag offset (legacy
        // prefix at 0 plus each embedded mask offset). Returns Err on a replay /
        // out-of-window packet for a known session (dropped, not handshaked).
        let existing = self.find_existing_session(packet_data, &client_addr.ip())?;
        let (session, counter, is_ratcheted_tag) = if let Some((
            session,
            counter,
            is_ratcheted,
            _resolved_tag,
        )) = existing
        {
            // `tag` (offset-0 bytes) is not read again on the existing-session
            // path — the layout-resolved tag was already validated inside
            // `find_existing_session`. It is only reassigned on the handshake
            // path below, where the post-loop re-validation reads it.
            (session, counter, is_ratcheted)
        } else {
            // NOTE: We intentionally do NOT drop packets from the same public IP
            // on a different port. Multiple clients behind the same NAT must be
            // able to handshake independently (different PSKs → different sessions).
            // Mobile carriers (MTS, etc.) change source ports on reconnect — we must
            // not block new handshakes based on port mismatch with an existing session.
            // The handshake_locks mutex below serializes concurrent handshakes from
            // the same IP, preventing the duplicate-session race without blocking
            // legitimate reconnects from a new port.

            // Serialize concurrent handshakes from the same source IP.
            // When a client reconnects rapidly, multiple shard workers may receive
            // init packets on different source ports simultaneously and each enter
            // this branch before any session is registered in tag_map. Without
            // serialization both complete PSK-matching, create sessions for the same
            // VPN IP, and the last cleanup_old_sessions_for_vpn_ip call removes the
            // session the client already ratcheted to, causing aead::Error on all
            // subsequent data packets. try_lock_owned is non-blocking: if another
            // handshake is in progress for this IP we drop the packet silently;
            // the client retransmits naturally and hits the existing-session path.
            let _handshake_guard = {
                let lock = {
                    let entry = self
                        .handshake_locks
                        .entry(client_addr.ip())
                        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())));
                    entry.value().clone()
                };
                match lock.try_lock_owned() {
                    Ok(guard) => guard,
                    Err(_) => return Ok(()),
                }
            };

            // Guard against session pool exhaustion: the handshake path calls
            // create_session() speculatively for every (client × bootstrap_mask)
            // combination before tag validation confirms which one is correct.
            // An attacker spoofing many source IPs can fill the pool with temporary
            // sessions and block legitimate clients. Reserve 10 slots so ratchet
            // renewals for existing sessions always have capacity.
            if self.session_manager.session_count() + 10 >= MAX_SESSIONS {
                debug!("Session pool near capacity ({}/{}), dropping unauthenticated handshake from {}",
                    self.session_manager.session_count(), MAX_SESSIONS, hash_addr(&client_addr));
                return Ok(());
            }

            // No session found — try handshake
            // Rate-limit failed handshake attempts to prevent rapid session-creation loops.
            // After mask rotation or session timeout, stale clients may flood the server
            // with packets that consistently fail tag validation (issue #21, #42).
            {
                let ip = client_addr.ip();
                if let Some(entry) = self.handshake_cooldowns.get(&ip) {
                    let (fail_count, last_fail) = *entry;
                    // Exponential cooldown: 2s → 4s → 8s → 16s (max)
                    let cooldown = Duration::from_millis((2000 * (1 << fail_count.min(3))) as u64);
                    if last_fail.elapsed() < cooldown {
                        debug!("Handshake cooldown active for {}: fail_count={}, elapsed={:?}, cooldown={:?}",
                            hash_addr(&client_addr), fail_count, last_fail.elapsed(), cooldown);
                        return Err(Error::InvalidPacket("Handshake cooldown active"));
                    }
                }
            }

            // Global, source-IP-independent budget on the candidate scan below.
            // The per-IP cooldown is spoof-defeatable; this bounds the aggregate
            // rate of the (clients × masks) DH+tag scan so a spoofed-IP flood
            // can't pin CPU. Legitimate new connections are well under the cap.
            if !self.handshake_scan_allowed() {
                debug!(
                    "Handshake scan budget exhausted this second, dropping unauthenticated handshake from {}",
                    hash_addr(&client_addr)
                );
                return Err(Error::InvalidPacket("Handshake scan budget exhausted"));
            }

            // Try to establish a new session using one of the built-in bootstrap masks.
            // Runtime masks can be server-generated, but bootstrap must remain compatible
            // with clients that only know the shipped presets.
            // If client_db is configured, iterate registered clients and try
            // DH + PSK to find one whose derived tags match.
            // Falls back to no-PSK for backward compatibility.
            let builtin_bootstrap_masks = aivpn_common::mask::preset_masks::all();
            let (session, matched_client_id, bootstrap_mask) = if let Some(ref db) = self.client_db
            {
                let clients = db.list_clients();
                let mut found = None;
                // Two passes over the same candidates. The first speaks the
                // current embedded-tag layout; the second re-reads the packet in
                // the pre-Variant-A layout (8-byte tag PREFIX at offset 0, then
                // the MDH, then the ephemeral key), which is all a client older
                // than that change can send. Without the second pass, upgrading
                // a server silently locks out every user who has not updated
                // their app — their handshakes look like noise and the app
                // reconnects forever.
                //
                // Ordering matters for cost: a current client still matches in
                // pass 1, so its handshake does exactly the work it did before.
                // Only a handshake that no modern candidate explains — already
                // rate-limited by the per-IP cooldown — pays for the second pass.
                'bootstrap: for legacy_framing in [false, true] {
                    for client_cfg in &clients {
                        if !client_cfg.enabled {
                            continue;
                        }
                        if client_cfg
                            .expires_at
                            .is_some_and(|t| t <= chrono::Utc::now())
                        {
                            continue;
                        }

                        let psk = client_cfg.psk;
                        let candidate_masks = self
                            .bootstrap_descriptors
                            .read()
                            .iter()
                            .flat_map(|descriptor| {
                                derive_bootstrap_candidates(descriptor, Some(&psk))
                            })
                            .chain(builtin_bootstrap_masks.clone().into_iter())
                            .collect::<Vec<_>>();

                        for bootstrap_mask in candidate_masks {
                            let (
                                _,
                                candidate_handshake_mdh_len,
                                candidate_eph_offset,
                                candidate_eph_len,
                            ) = packet_layout_for_mask(&bootstrap_mask);
                            // Layout-aware handshake parse: an embedded mask has NO
                            // tag prefix, so the eph and tag live at their raw MDH
                            // offsets; a legacy mask keeps the TAG_SIZE prefix.
                            // Client and server agree per mask (both key off
                            // `mask.tag_offset`), so a wrong layout simply yields a
                            // wrong eph → wrong keys → tag mismatch → rollback.
                            //
                            // In the legacy pass every candidate is re-read in the
                            // tag-prefix layout regardless of what its profile says.
                            // A mask that is already legacy was fully covered by
                            // pass 1, so skip it instead of testing it twice.
                            let cand_tag_offset = if legacy_framing {
                                LEGACY_TAG_OFFSET
                            } else {
                                bootstrap_mask.tag_offset
                            };
                            if legacy_framing && bootstrap_mask.tag_offset == LEGACY_TAG_OFFSET {
                                continue;
                            }
                            let prefix = tag_prefix_len(cand_tag_offset);
                            if packet_data.len() < prefix + candidate_handshake_mdh_len {
                                continue;
                            }
                            let eph_start = prefix + candidate_eph_offset;
                            if packet_data.len() < eph_start + candidate_eph_len {
                                continue;
                            }
                            let cand_tag =
                                match extract_tag_for_layout(packet_data, cand_tag_offset) {
                                    Some(t) => t,
                                    None => continue,
                                };

                            let mut eph_pub = [0u8; 32];
                            eph_pub.copy_from_slice(
                                &packet_data[eph_start..eph_start + candidate_eph_len],
                            );
                            crypto::obfuscate_eph_pub(
                                &mut eph_pub,
                                &self.session_manager.server_public_key(),
                            );

                            // DoS hardening: cheaply reject non-matching (client, mask)
                            // candidates BEFORE the expensive create_session (2 DH +
                            // Ed25519 sign + full tag windows + session-table scans).
                            // Only a genuine match proceeds to session creation.
                            if !self.session_manager.handshake_tag_precheck(
                                &eph_pub,
                                Some(psk),
                                &cand_tag,
                            ) {
                                continue;
                            }

                            match self.session_manager.create_session(
                                client_addr,
                                eph_pub,
                                Some(psk),
                                Some(client_cfg.vpn_ip),
                            ) {
                                Ok(sess) => {
                                    let validation = sess.lock().validate_handshake_tag(&cand_tag);
                                    if validation.is_some() {
                                        // `mask_id` is `bootstrap:epoch-<N>:<base>:<slot>:<hex>`
                                        // for a covert descriptor mask, or a bare preset
                                        // name for the public-preset fallback. Surfacing
                                        // which one matched (and thus which epoch, or that
                                        // it fell through to a preset) makes epoch-skew
                                        // diagnosable from the server log alone.
                                        let matched_epoch = bootstrap_mask
                                            .mask_id
                                            .strip_prefix("bootstrap:epoch-")
                                            .and_then(|rest| rest.split(':').next());
                                        match matched_epoch {
                                        Some(ep) => debug!(
                                            "Tag validation SUCCESS for client {} via covert descriptor mask {} (epoch {}, current {})",
                                            client_cfg.id,
                                            bootstrap_mask.mask_id,
                                            ep,
                                            bootstrap_epoch(current_unix_secs())
                                        ),
                                        None => debug!(
                                            "Tag validation SUCCESS for client {} via preset-fallback mask {} (no covert descriptor matched)",
                                            client_cfg.id, bootstrap_mask.mask_id
                                        ),
                                    }
                                        tag = cand_tag;
                                        // A peer that only speaks the legacy layout
                                        // also predates the directional key split:
                                        // it derives ONE session key and expects the
                                        // downlink encrypted with it. Collapse the
                                        // split for this session so the existing
                                        // downlink path (which always uses the S2C
                                        // key) produces what that client can read.
                                        // Modern sessions are untouched and keep the
                                        // separation that stops a reflected uplink
                                        // packet from authenticating as downlink.
                                        //
                                        // The session mask is pinned to the legacy
                                        // layout too, so the DATA plane reads the
                                        // ciphertext after the tag prefix.
                                        let mut session_mask = bootstrap_mask;
                                        if legacy_framing {
                                            session_mask.tag_offset = LEGACY_TAG_OFFSET;
                                            let mut s = sess.lock();
                                            s.keys.session_key_s2c = s.keys.session_key;
                                            if let Some(rk) = s.ratcheted_keys.as_mut() {
                                                rk.session_key_s2c = rk.session_key;
                                            }
                                            debug!(
                                            "Client {} handshaked with the pre-Variant-A layout — \
                                             serving it in legacy compatibility mode",
                                            client_cfg.id
                                        );
                                        }
                                        found =
                                            Some((sess, Some(client_cfg.id.clone()), session_mask));
                                        break 'bootstrap;
                                    }
                                    let sid = sess.lock().session_id;
                                    self.session_manager.rollback_failed_session(&sid);
                                }
                                Err(e) => {
                                    debug!("create_session failed: {}", e);
                                    continue;
                                }
                            }
                        }
                    }
                }
                match found {
                    Some(f) => f,
                    None => {
                        // Track failed handshake for cooldown
                        let ip = client_addr.ip();
                        let fail_count =
                            self.handshake_cooldowns.get(&ip).map(|e| e.0).unwrap_or(0);
                        self.handshake_cooldowns
                            .insert(ip, (fail_count + 1, Instant::now()));
                        warn!(
                            "Handshake failed for {} (attempt #{}) — tag mismatch for all {} registered clients",
                            hash_addr(&client_addr),
                            fail_count + 1,
                            clients.len()
                        );
                        return Err(Error::InvalidPacket(
                            "No registered client matches this handshake",
                        ));
                    }
                }
            } else {
                // No client DB — legacy mode without PSK
                let mut found = None;
                let candidate_masks = self
                    .bootstrap_descriptors
                    .read()
                    .iter()
                    .flat_map(|descriptor| derive_bootstrap_candidates(descriptor, None))
                    .chain(builtin_bootstrap_masks.clone().into_iter())
                    .collect::<Vec<_>>();
                for bootstrap_mask in candidate_masks {
                    let (_, candidate_handshake_mdh_len, candidate_eph_offset, candidate_eph_len) =
                        packet_layout_for_mask(&bootstrap_mask);
                    // Layout-aware handshake parse (see the client_db branch
                    // above): embedded masks drop the TAG_SIZE prefix.
                    let prefix = tag_prefix_len(bootstrap_mask.tag_offset);
                    if packet_data.len() < prefix + candidate_handshake_mdh_len {
                        continue;
                    }
                    let eph_start = prefix + candidate_eph_offset;
                    if packet_data.len() < eph_start + candidate_eph_len {
                        continue;
                    }
                    let cand_tag =
                        match extract_tag_for_layout(packet_data, bootstrap_mask.tag_offset) {
                            Some(t) => t,
                            None => continue,
                        };

                    let mut eph_pub = [0u8; 32];
                    eph_pub.copy_from_slice(&packet_data[eph_start..eph_start + candidate_eph_len]);
                    crypto::obfuscate_eph_pub(
                        &mut eph_pub,
                        &self.session_manager.server_public_key(),
                    );

                    // DoS hardening: cheap tag pre-check before create_session
                    // (see the client_db branch above).
                    if !self
                        .session_manager
                        .handshake_tag_precheck(&eph_pub, None, &cand_tag)
                    {
                        continue;
                    }

                    let sess =
                        self.session_manager
                            .create_session(client_addr, eph_pub, None, None)?;
                    let validation = sess.lock().validate_handshake_tag(&cand_tag);
                    if validation.is_some() {
                        tag = cand_tag;
                        found = Some((sess, None, bootstrap_mask));
                        break;
                    }
                    let sid = sess.lock().session_id;
                    self.session_manager.rollback_failed_session(&sid);
                }

                found.ok_or_else(|| {
                    Error::InvalidPacket("No bootstrap mask matched this handshake")
                })?
            };

            // Validate the tag against the session.
            let validation = {
                let sess = session.lock();
                sess.validate_tag(&tag)
            };
            let (counter, is_ratcheted) = match validation {
                Some(result) => result,
                None => {
                    let session_id = session.lock().session_id;
                    self.session_manager.rollback_failed_session(&session_id);
                    return Err(Error::InvalidPacket("Tag mismatch on new session"));
                }
            };

            // Tag is valid — this is a real handshake.
            // Clean up old sessions for the SAME CLIENT (by VPN IP), not
            // all sessions from this source IP — different clients behind
            // the same NAT must coexist.
            {
                let (session_id, vpn_ip) = {
                    let sess_lock = session.lock();
                    (sess_lock.session_id, sess_lock.vpn_ip)
                };
                if let Some(vpn_ip) = vpn_ip {
                    let removed = self
                        .session_manager
                        .cleanup_old_sessions_for_vpn_ip(&vpn_ip, &session_id);
                    // Re-assert the downlink mapping for the winning session.
                    // create_session inserts vpn_ip_map BEFORE tag validation, so a
                    // concurrent duplicate/reconnect handshake for the same static
                    // VPN IP could have overwritten it (and its own rollback would
                    // not restore THIS session). Without this the client uploads
                    // fine but downlink is a permanent blackhole ("no session for
                    // VPN IP"). Making the validated winner authoritative here
                    // closes that race deterministically.
                    self.session_manager.bind_vpn_ip(&vpn_ip, &session_id);
                    // Stop active recordings for removed stale sessions
                    if let Some(ref recorder) = self.recording_manager {
                        let socket = self.udp_socket.as_ref().unwrap().clone();
                        let store = recorder.store();
                        let mdh = self.mask_catalog.packet_mdh_bytes();
                        for sid in removed {
                            let outcome = recorder.stop_for_session_end(sid);
                            Self::handle_recording_outcome(
                                &socket,
                                &self.session_manager,
                                &store,
                                &mdh,
                                outcome,
                                None,
                            )
                            .await;
                        }
                    }
                }
            }

            // Successful handshake — clear cooldown for this IP
            self.handshake_cooldowns.remove(&client_addr.ip());

            {
                let mut sess = session.lock();
                sess.mask = Some(bootstrap_mask.clone());
            }

            // Record handshake in client DB
            if let (Some(ref db), Some(ref cid)) = (&self.client_db, &matched_client_id) {
                db.record_handshake(cid);
                // Store client_id in session for traffic accounting
                session.lock().client_id = Some(cid.clone());
                debug!("Client '{}' authenticated via PSK", cid);
            }

            // Clean up any stale sessions for the same authenticated client
            // (handles WiFi→cellular reconnect where source IP changes but PSK is the same).
            if let Some(ref cid) = matched_client_id {
                let session_id = session.lock().session_id;
                let removed_cid = self
                    .session_manager
                    .cleanup_old_sessions_for_client_id(cid, &session_id);
                if let Some(ref recorder) = self.recording_manager {
                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    for sid in removed_cid {
                        let outcome = recorder.stop_for_session_end(sid);
                        Self::handle_recording_outcome(
                            &socket,
                            &self.session_manager,
                            &store,
                            &mdh,
                            outcome,
                            None,
                        )
                        .await;
                    }
                }
            }

            self.send_server_hello(&session, client_addr).await?;
            self.send_bootstrap_descriptors(&session).await?;

            // NOTE: the eager initial runtime-mask auto-switch (added earlier this
            // session to un-inert the neural check) is intentionally NOT performed
            // here. Committing the session onto a runtime mask whose MDH length
            // differs from the bootstrap layout re-frames BOTH directions of the
            // wire — the server then decodes uplink and encodes downlink at the
            // runtime mdh_len while the client, which never adopted the mask, is
            // still on the bootstrap layout — desyncing the ciphertext boundary
            // (server: aead::Error on uplink; client: no MDH length authenticates)
            // and stranding the tunnel into an RX-silence reconnect loop. The
            // session stays on its bootstrap mask for the whole wire path; explicit
            // client-driven switches (MaskPreference) and polymorphic variants still
            // work because the client adopts those before the server reframes.
            // Neural evaluation against the catalog's runtime mask must be decoupled
            // from the wire-framing mask — tracked as a follow-up, not gated on this
            // data-plane fix.
            let _ = &bootstrap_mask;

            // §3.2 "every session polymorphic" server policy: when enabled,
            // derive and push a polymorphic variant for EVERY session right
            // after handshake, without waiting for the client to opt in via
            // `MaskPreference`. Base is the configured preset
            // (`polymorphic_base_mask`) if set, else the session's own
            // just-assigned bootstrap mask.
            //
            // Reuses the exact idempotency (`polymorphic_variant_already_active`)
            // and throttle (`mask_preference_throttle` /
            // `try_claim_mask_preference_slot`) guards as the client-driven
            // `MaskPreference` arm below, so:
            //   - a session that already carries this exact variant is not
            //     re-pushed (idempotent — e.g. reconnect races reusing the
            //     same prng_seed-derived variant id), and
            //   - a client-requested `MaskPreference` still wins: if the
            //     client sends one immediately after ServerHello (processed
            //     concurrently with this handshake-completion code by a
            //     different `tokio::spawn`ed task — see
            //     `process_packets_concurrent`), whichever reaches the
            //     shared per-session throttle slot first proceeds and the
            //     other is silently dropped. In practice this code runs
            //     synchronously moments after session creation, well before
            //     a client could have received ServerHello and replied, so
            //     it wins that race in the overwhelmingly common case — and
            //     a genuinely later, out-of-window client `MaskPreference`
            //     is never throttled by this (see `MASK_PREFERENCE_THROTTLE`'s
            //     doc comment), so it always applies and correctly overrides
            //     the policy-pushed variant.
            if self.config.polymorphic_all_sessions {
                let (poly_session_id, poly_prng_seed, poly_current_mask_id, poly_base) = {
                    let sess = session.lock();
                    let current = sess
                        .pending_mask
                        .as_ref()
                        .map(|(m, _)| m.mask_id.clone())
                        .or_else(|| sess.mask.as_ref().map(|m| m.mask_id.clone()));
                    let base = self
                        .config
                        .polymorphic_base_mask
                        .as_deref()
                        .and_then(aivpn_common::mask::preset_masks::by_id)
                        .or_else(|| sess.mask.clone());
                    (sess.session_id, sess.keys.prng_seed, current, base)
                };

                if let Some(base) = poly_base {
                    let variant = base.to_polymorphic(&poly_prng_seed);
                    if !polymorphic_variant_already_active(
                        poly_current_mask_id.as_deref(),
                        &variant.mask_id,
                    ) {
                        let now = Instant::now();
                        if try_claim_mask_preference_slot(
                            &self.mask_preference_throttle,
                            poly_session_id,
                            now,
                        ) {
                            match self
                                .session_manager
                                .build_mask_update_packet(&session, &variant)
                            {
                                Ok(packet) => {
                                    // FIX L: `udp_socket` is `None` until
                                    // `run()` binds it — a handshake racing
                                    // that startup window (or a future caller
                                    // that constructs a `Gateway` without ever
                                    // calling `run()`, e.g. tests) must not
                                    // panic here.
                                    if let Some(sock) = self.udp_socket.as_ref() {
                                        if let Err(e) = sock.send_to(&packet, client_addr).await {
                                            warn!(
                                                "Failed to send policy-driven polymorphic MaskUpdate to {}: {}",
                                                client_addr, e
                                            );
                                        } else {
                                            self.session_manager
                                                .update_session_mask(&poly_session_id, variant);
                                            self.metrics.record_polymorphic_variant_pushed();
                                        }
                                    } else {
                                        warn!(
                                            "Dropping policy-driven polymorphic MaskUpdate for {} — UDP socket not bound",
                                            hash_addr(&client_addr)
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to build policy-driven polymorphic MaskUpdate packet: {}",
                                        e
                                    );
                                }
                            }
                        } else {
                            debug!(
                                "Polymorphic-all policy push for {} raced with a concurrent MaskPreference — skipping",
                                hash_addr(&client_addr)
                            );
                        }
                    }
                }
            }

            // NOTE: PFS ratchet is deferred until AFTER decrypting the init packet,
            // which was encrypted with pre-ratchet keys.

            is_new_session = true;
            // When mTLS is required, block Data until the client sends a valid ClientCert.
            // SAFETY: process_inner_payload is skipped for is_new_session packets (see below),
            // so mtls_ok=false is guaranteed to be visible before any Data is processed.
            if self.config.mtls.as_ref().map_or(false, |c| c.required) {
                session.lock().mtls_ok = false;
            }
            debug!(
                "New session from {} (ServerHello sent)",
                hash_addr(&client_addr)
            );
            (session, counter, is_ratcheted)
        };

        // Parse packet — pad_len is inside encrypted area (CRIT-5 fix).
        // Use the session's own mask layout for decryption. This is critical
        // because the client may still be using its bootstrap mask before
        // receiving and applying a MaskUpdate from the server.
        // We try both the session mask layout AND the catalog (runtime) layout
        // to handle the transition window.
        let (session_mdh_len, session_hs_mdh_len, session_tag_offset) = {
            let sess = session.lock();
            if sess.is_pool_peer || sess.is_site_peer {
                // Cluster (pool/site/chain) traffic uses a FIXED, mask-
                // independent framing: [8-byte tag prefix][CLUSTER_MDH_LEN
                // random bytes][ciphertext]. It must NOT follow the catalog's
                // primary mask: that mask differs across nodes and over time,
                // and an embedded-tag primary (tag_offset != u16::MAX) would
                // shift the expected ciphertext offset, failing AEAD on every
                // peer packet even though the tag matched.
                (
                    crate::pool_sync::CLUSTER_MDH_LEN,
                    crate::pool_sync::CLUSTER_MDH_LEN,
                    u16::MAX,
                )
            } else if let Some(ref mask) = sess.mask {
                let (p, h, _, _) = packet_layout_for_mask(mask);
                (p, h, mask.tag_offset)
            } else {
                (catalog_mdh_len, catalog_hs_mdh_len, catalog_tag_offset)
            }
        };
        let packet_mdh_len = session_mdh_len;
        let handshake_mdh_len = session_hs_mdh_len;
        // Layout-aware ciphertext start (Variant A). Legacy masks carry an
        // 8-byte tag prefix before the MDH; embedded masks do not (the tag hides
        // inside the MDH), so the ciphertext begins `prefix + mdh_len` in.
        let session_prefix = tag_prefix_len(session_tag_offset);
        // Android retransmits the initial handshake packet with the client
        // eph_pub still embedded inside the MDH. Once a session already exists,
        // those retries validate against the existing tag window, so the
        // ciphertext still starts immediately after the full MDH.
        let is_pre_ratchet_retry = !is_new_session && !is_ratcheted_tag && {
            let sess = session.lock();
            !sess.is_ratcheted && packet_data.len() >= session_prefix + handshake_mdh_len + 16
        };
        let mut payload_offsets: Vec<usize> = if is_new_session {
            vec![session_prefix + handshake_mdh_len]
        } else if is_pre_ratchet_retry && handshake_mdh_len != packet_mdh_len {
            vec![
                session_prefix + packet_mdh_len,
                session_prefix + handshake_mdh_len,
            ]
        } else {
            vec![session_prefix + packet_mdh_len]
        };
        // During mask transition (bootstrap → runtime), also try the catalog
        // (runtime) layout in case the client already applied MaskUpdate — using
        // the catalog mask's OWN prefix, which may differ from the session's.
        {
            let catalog_offset = tag_prefix_len(catalog_tag_offset) + catalog_mdh_len;
            if !payload_offsets.contains(&catalog_offset) {
                payload_offsets.push(catalog_offset);
            }
        }
        // QUIC-Initial mimic (coalesced datagram): a QUIC-masked DATA packet is
        // a genuine RFC 9001 v1 Initial (DCID carries the resonance tag) with
        // aivpn's real ciphertext appended after the Initial's Length field. The
        // tag was already extracted at DCID offset 6 by the normal layout-aware
        // lookup; here we add the trailing ciphertext offset as a decrypt
        // candidate. The parse is strict (0xC0 long header, version 1, 8-byte
        // DCID) so STUN/legacy packets never match — those paths are unchanged.
        if let Some(layout) = aivpn_common::quic_initial::parse_quic_initial(packet_data) {
            if !payload_offsets.contains(&layout.payload_offset) {
                payload_offsets.insert(0, layout.payload_offset);
            }
        }

        let (payload_offset, padded_plaintext) = {
            let sess = session.lock();
            let nonce = self.compute_nonce(counter);
            // For new sessions, always use initial keys for decryption since the
            // client hasn't received ServerHello yet and is still sending with
            // initial keys. Only use ratcheted keys when the client proves it
            // has switched by sending a ratcheted tag on an existing session.
            let key = if is_new_session {
                &sess.keys.session_key
            } else if is_ratcheted_tag {
                &sess
                    .ratcheted_keys
                    .as_ref()
                    .ok_or(Error::InvalidPacket("Ratcheted keys missing"))?
                    .session_key
            } else {
                &sess.keys.session_key
            };

            let mut decrypted = None;
            let mut last_error = None;
            for payload_offset in payload_offsets {
                if packet_data.len() <= payload_offset {
                    continue;
                }
                let encrypted_payload = &packet_data[payload_offset..];
                match decrypt_payload(key, &nonce, encrypted_payload) {
                    Ok(padded_plaintext) => {
                        decrypted = Some((payload_offset, padded_plaintext));
                        break;
                    }
                    Err(err) => last_error = Some(err),
                }
            }

            match decrypted {
                Some(result) => result,
                None => {
                    // A tag that validated pins the counter (and with it the
                    // nonce and key), so reaching here means every candidate
                    // ciphertext offset was wrong — a client/server disagreement
                    // about how this session's mask frames the packet. Name the
                    // mask and the offsets: the failure is otherwise a bare
                    // "aead::Error" repeated thousands of times.
                    // `sess` above still holds the session lock for this whole
                    // block — `session.lock()` here would deadlock the worker
                    // (parking_lot mutexes are not reentrant) and, with the lock
                    // never released, wedge the packet loop for every session.
                    debug!(
                        "uplink decrypt failed for {}: mask={:?} packet_len={} counter={} \
                         ratcheted={} session_offset={} catalog_offset={}",
                        hash_addr(&client_addr),
                        sess.mask.as_ref().map(|m| m.mask_id.as_str()),
                        packet_data.len(),
                        counter,
                        is_ratcheted_tag,
                        session_prefix + packet_mdh_len,
                        tag_prefix_len(catalog_tag_offset) + catalog_mdh_len,
                    );
                    return Err(
                        last_error.unwrap_or_else(|| Error::InvalidPacket("Invalid length"))
                    );
                }
            }
        };
        let encrypted_payload = &packet_data[payload_offset..];

        // Complete PFS ratchet only when the CLIENT proves it has ratcheted
        // by sending a packet with ratcheted-key tags.
        // Do NOT ratchet on is_new_session — the client hasn't received
        // ServerHello yet and will keep sending packets with initial keys.
        if is_ratcheted_tag {
            let session_id = session.lock().session_id;
            self.session_manager.complete_session_ratchet(&session_id);
            // Install session into kernel accelerator now that keys are stable.
            if let Some(ref ka) = self.kernel_accel {
                let mut sess = session.lock();
                info!(
                    "PFS ratchet complete for {} — send_counter={}, counter={}",
                    hash_addr(&client_addr),
                    sess.send_counter,
                    sess.counter
                );
                let add =
                    make_kernel_session_add(&sess, catalog_tag_offset, catalog_mdh_len as u16);
                let upd = make_kernel_update_tags(&sess);
                if let Err(e) = ka.session_add(&add) {
                    warn!("kernel session_add failed: {e}");
                } else {
                    // Record the installed signature so the refresh path only
                    // re-installs once the mask or keys actually change.
                    sess.kernel_install_sig =
                        kernel_session_sig(&sess, catalog_tag_offset, catalog_mdh_len as u16);
                }
                if let Err(e) = ka.session_update_tags(&upd) {
                    warn!("kernel session_update_tags failed: {e}");
                }
                // Arm the kernel downlink fast path with a reserved counter block.
                if let Some(dl) = make_kernel_downlink(&mut sess) {
                    if let Err(e) = ka.session_downlink(&dl) {
                        warn!("kernel session_downlink failed: {e}");
                    }
                }
            } else {
                let sess = session.lock();
                info!(
                    "PFS ratchet complete for {} — send_counter={}, counter={}",
                    hash_addr(&client_addr),
                    sess.send_counter,
                    sess.counter
                );
            }
        }

        // Extract pad_len from inside decrypted data and strip padding
        if padded_plaintext.len() < 2 {
            return Err(Error::InvalidPacket("Decrypted payload too short"));
        }
        let pad_len = u16::from_le_bytes([padded_plaintext[0], padded_plaintext[1]]) as usize;
        if 2 + pad_len > padded_plaintext.len() {
            return Err(Error::InvalidPacket("Invalid padding length"));
        }
        let plaintext = &padded_plaintext[2..padded_plaintext.len() - pad_len];

        // Update session state. Avoid expensive O(window) tag-map rebuild on every packet.
        let mut client_db_flush: Option<(String, u64, u64)> = None;
        let (session_id, refresh_tags, iat_ms) = {
            let mut sess = session.lock();
            sess.mark_tag_received(counter);
            // C-S-2: if this packet matched a pre-ratchet (old-key) tag, mark
            // it in the pre_ratchet_bitmap to prevent replay within the grace window.
            if sess.is_pre_ratchet_counter(counter) {
                sess.mark_pre_ratchet_received(counter);
            }
            // Inter-arrival time = gap since the PREVIOUS validated packet. This
            // MUST be measured before overwriting `last_seen`; the neural and
            // recording readers below would otherwise observe ~0 (the value we
            // just wrote), which collapsed recorded IAT distributions to a
            // degenerate near-zero spike.
            let now = std::time::Instant::now();
            let iat_ms = now.duration_since(sess.last_seen).as_secs_f64() * 1000.0;
            sess.last_seen = now;

            // IP migration: update stored client address when a validated packet
            // arrives from a different endpoint (e.g. WiFi → cellular switchover).
            // Safe because the packet passed full cryptographic validation.
            if !is_new_session && sess.client_addr != client_addr {
                info!(
                    "Client endpoint migrated: {} → {} (session keepalive active)",
                    hash_addr(&sess.client_addr),
                    hash_addr(&client_addr)
                );
                sess.client_addr = client_addr;
            }

            // Refresh precomputed tag window only when we've moved far enough.
            // Window size is 512; refreshing every 128 packets keeps ~4× headroom
            // over the refresh stride while reducing CPU spent in HashMap/tag_map
            // maintenance. Stride scales with the window so per-packet precompute
            // and tag_map churn stay flat versus the old 256-window/64-stride.
            let refresh_tags = counter.saturating_sub(sess.tag_window_base) >= 128;
            if refresh_tags {
                sess.update_tag_window();
            }

            // Batch client stats updates to avoid taking a global write lock per packet.
            sess.pending_bytes_in = sess
                .pending_bytes_in
                .saturating_add(packet_data.len() as u64);
            sess.bytes_since_rekey = sess
                .bytes_since_rekey
                .saturating_add(packet_data.len() as u64);
            if sess.pending_bytes_in >= 16 * 1024 || sess.pending_bytes_out >= 16 * 1024 {
                if let Some(cid) = sess.client_id.clone() {
                    client_db_flush = Some((cid, sess.pending_bytes_in, sess.pending_bytes_out));
                }
                sess.pending_bytes_in = 0;
                sess.pending_bytes_out = 0;
            }

            sess.update_fsm();
            (sess.session_id, refresh_tags, iat_ms)
        };

        // Refresh tag_map only when the precomputed window moves.
        if refresh_tags {
            self.session_manager.refresh_session_tags(&session_id);
            if let Some(ref ka) = self.kernel_accel {
                let mut sess = session.lock();
                // Re-install the kernel session so its wire offsets and keys
                // track the session's CURRENT state. The client switches from
                // the bootstrap mask to the runtime mask shortly after connect
                // (different tag_offset/mdh_len) and rotates keys on rekey; the
                // offsets/keys frozen at the initial install would otherwise
                // make every kernel decrypt fail silently. session_add is
                // idempotent (replaces the existing entry). Re-install only when
                // the relevant state changed, so a steady session pays nothing.
                let sig = kernel_session_sig(&sess, catalog_tag_offset, catalog_mdh_len as u16);
                let reinstall = sess.kernel_install_sig != sig;
                let add = reinstall.then(|| {
                    make_kernel_session_add(&sess, catalog_tag_offset, catalog_mdh_len as u16)
                });
                let upd = make_kernel_update_tags(&sess);
                // Refresh the downlink reserved counter block on the same cadence
                // so its pre-computed resonance tags stay inside the client's
                // current time window and its counters stay near the client's
                // highest-seen downlink counter.
                let dl = make_kernel_downlink(&mut sess);
                drop(sess);
                if let Some(add) = add {
                    if let Err(e) = ka.session_add(&add) {
                        warn!("kernel session_add (refresh) failed: {e}");
                    } else {
                        session.lock().kernel_install_sig = sig;
                    }
                }
                if let Err(e) = ka.session_update_tags(&upd) {
                    warn!("kernel session_update_tags (refresh) failed: {e}");
                }
                if let Some(dl) = dl {
                    if let Err(e) = ka.session_downlink(&dl) {
                        warn!("kernel session_downlink (refresh) failed: {e}");
                    }
                }
            }
        }

        // Keep the kernel-downlink reservation's pre-computed resonance tags
        // fresh against wall-clock time. The signature/`refresh_tags` cadence
        // above only fires on mask/key changes or every 128 uplink packets — but
        // during a pure download the uplink is nearly idle (a few TCP ACKs /
        // keepalives), so it can go a long time without moving. Meanwhile the
        // client only accepts a downlink tag whose time window is within ±1 of
        // its own (≈±10 s), so a reservation armed one or more windows ago has
        // every packet rejected as "Invalid resonance tag" and downlink stalls.
        // Re-arm the instant the wall-clock window advances past the one the
        // reservation was built for. Keepalives (~8 s) run through this path, so
        // the kernel's tags are never more than one window stale. Cheap: a
        // window compare per packet, real work only on a window boundary.
        if let Some(ref ka) = self.kernel_accel {
            let now_window = crypto::compute_time_window(
                crypto::current_timestamp_ms(),
                aivpn_common::crypto::DEFAULT_WINDOW_MS,
            );
            let mut sess = session.lock();
            if sess.kernel_dl_window != 0 && sess.kernel_dl_window != now_window {
                let dl = make_kernel_downlink(&mut sess);
                drop(sess);
                if let Some(dl) = dl {
                    if let Err(e) = ka.session_downlink(&dl) {
                        warn!("kernel session_downlink (window re-arm) failed: {e}");
                    }
                }
            }
        }

        // Record traffic stats for neural resonance (Patent 1)
        if self.config.enable_neural {
            let packet_size = packet_data.len() as u16;
            // Compute byte-level entropy of the encrypted payload
            let entropy = Self::compute_entropy(encrypted_payload);
            // Real inter-arrival gap, measured above before last_seen was updated.
            // Neural model update is expensive under lock. Sampling every 16th packet
            // preserves trends while reducing lock contention in the receive hot path.
            if counter & 0x0f == 0 {
                self.neural_module
                    .lock()
                    // is_rx=true: packet from client → server (uplink direction)
                    .record_traffic(session_id, packet_size, iat_ms, entropy, true);
                // R2 Phase D — feed the same sampled packet's WIRE bytes to the
                // inline ML-DPI gate. `packet_data` is the full UDP datagram a DPI
                // box observes (mask header/tag bytes + ciphertext); the gate's
                // features (STUN/QUIC header form, size, entropy) are computed
                // from exactly these bytes. Lock-free (DashMap), one entropy pass.
                #[cfg(feature = "neural")]
                self.dpi_gate.record_wire(session_id, packet_data);
            }
            self.metrics.record_packet_received(packet_data.len());
        }

        // Record uplink packet metadata for auto mask recording
        if let Some(ref recorder) = self.recording_manager {
            let session_id = session.lock().session_id;
            if recorder.is_recording(&session_id) {
                // Real inter-arrival gap, measured above before last_seen was updated.
                let meta = aivpn_common::recording::PacketMetadata {
                    direction: aivpn_common::recording::Direction::Uplink,
                    size: packet_data.len() as u16,
                    iat_ms,
                    entropy: Self::compute_entropy(encrypted_payload) as f32,
                    // Learn the app header from the DECRYPTED inner packet, not the
                    // encrypted wire packet (`packet_data`, which is near-random
                    // ciphertext). `plaintext` is [InnerHeader(4)][inner IP packet];
                    // skip the 4-byte inner header to reach the IP packet, then
                    // inner_l7_prefix pulls the cleartext L7 app header. Non-Data /
                    // non-IP packets yield an empty prefix (ignored by the fitter).
                    header_prefix: inner_l7_prefix(plaintext.get(4..).unwrap_or(&[])),
                    timestamp_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                };
                recorder.record_packet(session_id, meta);
            }
        }

        // Record traffic in client DB in batches (see pending_bytes_in/out above).
        if let (Some(ref db), Some((cid, bytes_in, bytes_out))) = (&self.client_db, client_db_flush)
        {
            db.record_traffic(&cid, bytes_in, bytes_out);
        }

        // Process inner payload (skip for new sessions — ServerHello is already the response,
        // and any ControlAck sent here would use pre-ratchet keys that the client can't validate)
        if !is_new_session {
            self.process_inner_payload(plaintext, &session, client_addr)
                .await?;
        }

        Ok(())
    }

    /// Compute nonce from counter
    fn compute_nonce(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Process decrypted inner payload
    async fn process_inner_payload(
        &self,
        plaintext: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        if plaintext.len() < 4 {
            return Err(Error::InvalidPacket("Inner payload too short"));
        }

        let inner_header = InnerHeader::decode(plaintext)?;
        let payload = &plaintext[4..];

        match inner_header.inner_type {
            InnerType::Data => {
                // mTLS gate: drop Data packets until cert is verified (when required).
                if !session.lock().mtls_ok {
                    warn!(
                        "mtls: Data from {} rejected — certificate not yet verified",
                        hash_addr(&client_addr)
                    );
                    return Ok(());
                }

                // Anti-spoof + peer routing gate (authoritative, at ingress).
                // Only IPv4 is routed through the VPN; reject everything else to
                // prevent clients from injecting arbitrary layer-3 traffic that
                // bypasses the source-address check.
                if payload.len() < 20 || (payload[0] >> 4) != 4 {
                    debug!(
                        "Anti-spoof: dropping non-IPv4 payload (len={} ver={})",
                        payload.len(),
                        payload.first().map(|b| b >> 4).unwrap_or(0)
                    );
                    return Ok(());
                }
                {
                    let inner_src =
                        std::net::Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
                    let inner_dst =
                        std::net::Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
                    let session_vpn_ip = session.lock().vpn_ip;
                    if let Some(svpn) = session_vpn_ip {
                        if inner_src != svpn {
                            warn!(
                                "Anti-spoof: dropping packet src={} from session owning vpn_ip={}",
                                inner_src, svpn
                            );
                            return Ok(());
                        }
                    }
                    // Block intra-VPN routing at ingress when not opted in.
                    if !self.config.allow_peer_routing
                        && self
                            .session_manager
                            .get_session_by_vpn_ip(&inner_dst)
                            .is_some()
                    {
                        debug!(
                            "Peer routing disabled — dropping {}->{} at ingress",
                            inner_src, inner_dst
                        );
                        return Ok(());
                    }
                }

                // Forward to NAT/internet via TUN write channel (lock-free)
                debug!(
                    "DATA packet from {} ({} bytes)",
                    hash_addr(&client_addr),
                    payload.len()
                );

                // QoS: enforce upstream rate limit before forwarding to TUN
                let upstream_cid = session.lock().client_id.clone();
                if let Some(ref c) = upstream_cid {
                    if !self.qos_enforcer.check_upstream(c, payload.len() as u64) {
                        debug!("QoS: upstream rate limited, dropping packet for {}", c);
                        return Ok(());
                    }
                }

                // Site peers send subnet traffic — never relay to the exit node.
                let use_chain_forward =
                    self.chain_forwarder.is_some() && !session.lock().is_site_peer;
                if use_chain_forward {
                    if let Some(ref cf) = self.chain_forwarder {
                        // Multi-hop: relay to exit node instead of local NAT
                        cf.forward(payload.to_vec()).await;
                    }
                } else if let Some(ref tx) = self.tun_write_tx {
                    if tx.send(payload.to_vec()).await.is_err() {
                        debug!("TUN write channel closed, dropping packet");
                    }
                } else if let Some(ref nat) = self.nat_forwarder {
                    nat.forward_packet(payload).await?;
                } else {
                    debug!("NAT disabled, dropping packet");
                }

                // Accumulate payload into FEC XOR buffer for server-side recovery.
                // When FecRepair arrives we can reconstruct exactly one missing packet.
                {
                    let mut sess = session.lock();
                    let len = payload.len().min(1500);
                    if sess.fec_xor_buf.len() < len {
                        sess.fec_xor_buf.resize(len, 0);
                    }
                    for (a, b) in sess.fec_xor_buf[..len].iter_mut().zip(&payload[..len]) {
                        *a ^= b;
                    }
                    if len > sess.fec_xor_len {
                        sess.fec_xor_len = len;
                    }
                    sess.fec_recv_count = sess.fec_recv_count.saturating_add(1);
                }
            }
            InnerType::Control => {
                self.handle_control_message(payload, session, client_addr)
                    .await?;
            }
            InnerType::Fragment => {
                // TODO: Implement fragmentation
                debug!("FRAGMENT packet (not implemented)");
            }
            InnerType::Ack => {
                // Handle ACK
                debug!("ACK packet received");
            }
            InnerType::FecRepair => {
                if let Some(repair) = FecRepair::decode(payload) {
                    if repair.group_size > 0 {
                        let recovered_opt = {
                            let mut sess = session.lock();
                            let recv = sess.fec_recv_count;
                            let seq_ok = repair.group_seq == sess.fec_pending_seq;
                            // Recover only when group_seq matches (XOR buffer is for this
                            // exact group) and exactly one packet is missing.
                            let result = if seq_ok && recv == repair.group_size.saturating_sub(1) {
                                let xor_len = sess.fec_xor_len.max(repair.xor_data.len());
                                let mut out = vec![0u8; xor_len];
                                for i in 0..xor_len {
                                    out[i] = repair.xor_data.get(i).copied().unwrap_or(0)
                                        ^ sess.fec_xor_buf.get(i).copied().unwrap_or(0);
                                }
                                debug!(
                                    "FEC: recovered {} bytes from {} (group seq={} size={})",
                                    out.len(),
                                    hash_addr(&client_addr),
                                    repair.group_seq,
                                    repair.group_size
                                );
                                Some(out)
                            } else {
                                debug!(
                                    "FEC: group seq={} size={} recv={} seq_ok={} — no recovery",
                                    repair.group_seq, repair.group_size, recv, seq_ok
                                );
                                None
                            };
                            // Reset accumulator; advance expected seq to the next group.
                            sess.fec_recv_count = 0;
                            sess.fec_xor_buf.iter_mut().for_each(|b| *b = 0);
                            sess.fec_xor_len = 0;
                            sess.fec_pending_seq = repair.group_seq.wrapping_add(1);
                            result
                        };

                        if let Some(recovered) = recovered_opt {
                            // Validate recovered packet with the same anti-spoof and
                            // peer-routing checks applied to normal Data packets.
                            if recovered.len() < 20 || (recovered[0] >> 4) != 4 {
                                debug!(
                                    "FEC anti-spoof: dropping non-IPv4 recovered packet \
                                     (len={} ver={})",
                                    recovered.len(),
                                    recovered.first().map(|b| b >> 4).unwrap_or(0)
                                );
                            } else {
                                let inner_src = std::net::Ipv4Addr::new(
                                    recovered[12],
                                    recovered[13],
                                    recovered[14],
                                    recovered[15],
                                );
                                let inner_dst = std::net::Ipv4Addr::new(
                                    recovered[16],
                                    recovered[17],
                                    recovered[18],
                                    recovered[19],
                                );
                                let (session_vpn_ip, is_site_peer) = {
                                    let sess = session.lock();
                                    (sess.vpn_ip, sess.is_site_peer)
                                };
                                let spoof = session_vpn_ip
                                    .map(|svpn| inner_src != svpn)
                                    .unwrap_or(false);
                                if spoof {
                                    warn!(
                                        "FEC anti-spoof: dropping recovered packet \
                                         src={} from session owning vpn_ip={:?}",
                                        inner_src, session_vpn_ip
                                    );
                                } else if !self.config.allow_peer_routing
                                    && self
                                        .session_manager
                                        .get_session_by_vpn_ip(&inner_dst)
                                        .is_some()
                                {
                                    debug!(
                                        "FEC: peer routing disabled — dropping \
                                         {}->{} at ingress",
                                        inner_src, inner_dst
                                    );
                                } else {
                                    let use_chain = self.chain_forwarder.is_some() && !is_site_peer;
                                    if use_chain {
                                        if let Some(ref cf) = self.chain_forwarder {
                                            cf.forward(recovered).await;
                                        }
                                    } else if let Some(ref tx) = self.tun_write_tx {
                                        let _ = tx.send(recovered).await;
                                    } else if let Some(ref nat) = self.nat_forwarder {
                                        nat.forward_packet(&recovered).await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle control message
    async fn handle_control_message(
        &self,
        payload: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let control = ControlPayload::decode(payload)?;

        match control {
            ControlPayload::KeyRotate { new_eph_pub } => {
                let (session_id, has_pending) = {
                    let sess = session.lock();
                    (sess.session_id, sess.pending_rekey_keypair.is_some())
                };
                if has_pending {
                    info!(
                        "Inline rekey response from {} — committing new keys",
                        hash_addr(&client_addr)
                    );
                    self.session_manager
                        .commit_session_rekey(&session_id, &new_eph_pub);
                    // refresh_session_tags is redundant — commit_session_rekey already updates tag_map
                } else {
                    debug!(
                        "KeyRotate from {} ignored — no pending rekey",
                        hash_addr(&client_addr)
                    );
                }
            }
            ControlPayload::MaskUpdate { .. } => {
                warn!("Unexpected MASK_UPDATE from client");
            }
            ControlPayload::Keepalive { send_ts } => {
                debug!("Keepalive from {}", hash_addr(&client_addr));
                if !session.lock().is_ratcheted {
                    // The client is still retrying the initial handshake. If the
                    // first ServerHello was lost, replying with a normal pre-ratchet
                    // ControlAck leaves the client stuck forever.
                    self.send_server_hello(session, client_addr).await?;
                    return Ok(());
                }
                // Echo the client's own send_ts so it can measure RTT without
                // clock-skew between client and server.
                self.send_control_message(
                    &ControlPayload::KeepaliveAck { echo_ts: send_ts },
                    session,
                )
                .await?;
                // Piggyback the mask catalog on keepalives: send it only when the
                // global catalog version has moved past what this session last
                // received. Keepalives are always post-ratchet (guarded above),
                // so this never races the PFS key switch, and it self-heals if a
                // push is lost — the next keepalive retries until versions match.
                let current_ver = self
                    .mask_store
                    .as_ref()
                    .map(|s| s.catalog_version())
                    .unwrap_or(1);
                if session.lock().mask_catalog_version_sent != current_ver {
                    match self.send_mask_catalog(session).await {
                        Ok(()) => session.lock().mask_catalog_version_sent = current_ver,
                        Err(e) => debug!("MaskCatalog send failed: {}", e),
                    }
                }
            }
            ControlPayload::TelemetryRequest { metric_flags: _ } => {
                debug!("Telemetry request from {}", hash_addr(&client_addr));
                // Send response
                let response = ControlPayload::TelemetryResponse {
                    packet_loss: 0,
                    rtt_ms: 10,
                    jitter_ms: 2,
                    buffer_pct: 25,
                };
                self.send_control_message(&response, session).await?;
            }
            ControlPayload::TelemetryResponse {
                packet_loss,
                rtt_ms,
                ..
            } => {
                let (mask_id, reporter) = {
                    let sess = session.lock();
                    (
                        sess.mask.as_ref().map(|m| m.mask_id.clone()),
                        sess.session_id,
                    )
                };
                if let Some(ref mid) = mask_id {
                    // Pass the authenticated session id as the reporter so the
                    // anomaly detector can require multi-reporter corroboration
                    // before believing a client-reported compromise (anti-DoS).
                    self.neural_module.lock().record_telemetry(
                        mid,
                        reporter,
                        packet_loss as f64,
                        rtt_ms as f64,
                    );
                }
                debug!("Telemetry response received — recorded to anomaly detector");
            }
            ControlPayload::TimeSync { .. } => {
                debug!("Time sync request");
            }
            ControlPayload::Shutdown { reason } => {
                info!(
                    "Shutdown request from {} (reason: {})",
                    hash_addr(&client_addr),
                    reason
                );
                // Close session and stop active recording if any
                let session_id = session.lock().session_id;
                self.session_manager.remove_session(&session_id);
                self.neural_module.lock().cleanup_stats(session_id);
                #[cfg(feature = "neural")]
                self.dpi_gate.cleanup(&session_id);
                if let Some(ref ka) = self.kernel_accel {
                    let _ = ka.session_remove(&session_id);
                }
                if let Some(ref recorder) = self.recording_manager {
                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    let outcome = recorder.stop_for_session_end(session_id);
                    Self::handle_recording_outcome(
                        &socket,
                        &self.session_manager,
                        &store,
                        &mdh,
                        outcome,
                        None,
                    )
                    .await;
                }
            }
            ControlPayload::ControlAck { .. } => {
                // ACK received, nothing to do
            }
            ControlPayload::ServerHello { .. } => {
                warn!(
                    "Unexpected ServerHello from client {}",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::RecordingStart { service } => {
                // Only allow from admin sessions (check client_id)
                let admin_key_id = {
                    let sess = session.lock();
                    sess.client_id.clone()
                };
                if !self.can_start_recording(admin_key_id.as_deref()) {
                    warn!(
                        "Recording rejected: unauthenticated client {}",
                        hash_addr(&client_addr)
                    );
                    let failed = ControlPayload::RecordingFailed {
                        reason: "Recording requires a recording-admin key".into(),
                    };
                    self.send_control_message(&failed, session).await?;
                    return Ok(());
                }
                if let Some(ref recorder) = self.recording_manager {
                    let session_id = session.lock().session_id;
                    recorder.start(
                        session_id,
                        service.clone(),
                        admin_key_id.unwrap_or_else(|| "admin".into()),
                    );
                    let ack = ControlPayload::RecordingAck {
                        session_id,
                        status: "started".into(),
                    };
                    self.send_control_message(&ack, session).await?;
                    info!(
                        "Recording started for '{}' from {}",
                        service,
                        hash_addr(&client_addr)
                    );
                    self.audit_log.log(
                        AuditActor::System,
                        "RecordingStart",
                        &format!("service={} peer={}", service, hash_addr(&client_addr)),
                        "ok",
                    );
                }
            }
            ControlPayload::RecordingStop {
                session_id: rec_session_id,
            } => {
                if let Some(ref recorder) = self.recording_manager {
                    let owner_session_id = session.lock().session_id;
                    if rec_session_id != owner_session_id {
                        let failed = ControlPayload::RecordingFailed {
                            reason: "Recording session does not belong to this client".into(),
                        };
                        self.send_control_message(&failed, session).await?;
                        return Ok(());
                    }

                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    let outcome = recorder.stop(owner_session_id);
                    Self::handle_recording_outcome(
                        &socket,
                        &self.session_manager,
                        &store,
                        &mdh,
                        outcome,
                        Some(session.clone()),
                    )
                    .await;
                    self.audit_log.log(
                        AuditActor::System,
                        "RecordingStop",
                        &hash_addr(&client_addr),
                        "ok",
                    );
                }
            }
            ControlPayload::RecordingStatusRequest => {
                let client_id = {
                    let sess = session.lock();
                    sess.client_id.clone()
                };
                let can_record = self.can_start_recording(client_id.as_deref());
                let active_service = self
                    .recording_manager
                    .as_ref()
                    .and_then(|recorder| recorder.status(&session.lock().session_id))
                    .map(|status| status.service);
                let response = ControlPayload::RecordingStatus {
                    can_record,
                    active_service,
                };
                self.send_control_message(&response, session).await?;
            }
            ControlPayload::RecordingAck { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingComplete { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingFailed { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingStatus { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::BootstrapDescriptorUpdate { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::PoolSync { clients_json } => {
                // Only accept PoolSync from sessions registered as pool peers.
                // A regular VPN client sending PoolSync would be able to inject
                // or overwrite arbitrary client records in the database.
                let is_pool = session.lock().is_pool_peer;
                if !is_pool {
                    warn!(
                        "pool_sync: rejected from non-pool session {}",
                        hash_addr(&client_addr)
                    );
                    self.audit_log.log(
                        AuditActor::System,
                        "PoolSync",
                        &hash_addr(&client_addr),
                        "rejected: not a pool peer",
                    );
                } else if let Some(ref db) = self.client_db {
                    let json_str = String::from_utf8_lossy(&clients_json);
                    match db.merge_from_json(&json_str) {
                        Ok(n) => info!(
                            "pool_sync: merged {} clients from peer {}",
                            n,
                            hash_addr(&client_addr)
                        ),
                        Err(e) => warn!(
                            "pool_sync: merge failed from {}: {}",
                            hash_addr(&client_addr),
                            e
                        ),
                    }
                }
            }
            ControlPayload::RouteSync { subnets_json } => {
                if session.lock().is_site_peer {
                    crate::site_sync::handle_route_sync(&subnets_json, &client_addr.to_string());
                } else {
                    warn!(
                        "site_sync: RouteSync from non-peer session {} — dropping",
                        hash_addr(&client_addr)
                    );
                }
            }
            ControlPayload::ChainForward { payload } => {
                if self.config.exit_node_enabled {
                    let ip_version = payload.first().map(|b| b >> 4);
                    let min_len = match ip_version {
                        Some(4) => 20,
                        Some(6) => 40,
                        _ => usize::MAX,
                    };
                    if payload.len() < min_len {
                        warn!(
                            "chain_forward: invalid IP payload from {} (version={:?} len={}) — dropping",
                            hash_addr(&client_addr),
                            ip_version,
                            payload.len()
                        );
                    } else {
                        // C-S-4: Validate that the injected packet's source IP
                        // matches the session's assigned VPN IP to prevent
                        // IP spoofing through the exit-node relay path.
                        let src_ip_ok = {
                            let sess = session.lock();
                            match ip_version {
                                Some(4) => {
                                    if payload.len() >= 20 {
                                        let src: [u8; 4] = payload[12..16].try_into().unwrap();
                                        let pkt_src = std::net::Ipv4Addr::from(src);
                                        sess.vpn_ip.map_or(false, |vpn| vpn == pkt_src)
                                    } else {
                                        false
                                    }
                                }
                                // IPv6: no per-session IPv6 address assigned — reject
                                _ => false,
                            }
                        };
                        if !src_ip_ok {
                            warn!(
                                "chain_forward: source IP mismatch from {} — dropping",
                                hash_addr(&client_addr)
                            );
                        } else if let Some(ref tx) = self.tun_write_tx {
                            let _ = tx.send(payload).await;
                        }
                    }
                } else {
                    warn!(
                        "chain_forward: ChainForward from {} rejected — exit_node_enabled is false",
                        hash_addr(&client_addr)
                    );
                }
            }
            ControlPayload::ClientCert { cert_bytes } => {
                if let Some(ref mtls_cfg) = self.config.mtls {
                    let session_eph_pub = session.lock().eph_pub;
                    let ok = crate::mtls::SimpleCert::from_bytes(&cert_bytes)
                        .map(|c| {
                            c.client_pub_key == session_eph_pub
                                && crate::mtls::verify_cert(&c, mtls_cfg)
                        })
                        .unwrap_or(false);
                    session.lock().mtls_ok = ok;
                    if ok {
                        debug!("mtls: client {} cert accepted", hash_addr(&client_addr));
                        self.audit_log.log(
                            AuditActor::System,
                            "ClientCert",
                            &hash_addr(&client_addr),
                            "accepted",
                        );
                    } else {
                        warn!(
                            "mtls: client {} cert rejected — Data will be dropped",
                            hash_addr(&client_addr)
                        );
                        self.audit_log.log(
                            AuditActor::System,
                            "ClientCert",
                            &hash_addr(&client_addr),
                            "rejected",
                        );
                        // Notify client so it can re-provision rather than inferring failure from Data drops.
                        let _ = self
                            .send_control_message(
                                &aivpn_common::protocol::ControlPayload::CertRejected {},
                                session,
                            )
                            .await;
                    }
                }
            }
            ControlPayload::CertRejected {} => {
                // Server-to-client only; the server never receives this from clients.
                debug!(
                    "Unexpected CertRejected from client {}",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::DeviceEnrollment {
                static_pub,
                dh_proof,
            } => {
                let client_id = { session.lock().client_id.clone() };
                if let (Some(ref db), Some(ref cid)) = (&self.client_db, &client_id) {
                    // Verify DH proof: X25519(static_priv, server_static_pub) == dh_proof
                    let server_kp =
                        crypto::KeyPair::from_private_key(self.config.server_private_key);
                    let expected_dh = match server_kp.compute_shared(&static_pub) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(
                                "DeviceEnrollment from {}: DH error: {}",
                                hash_addr(&client_addr),
                                e
                            );
                            return Ok(());
                        }
                    };
                    use subtle::ConstantTimeEq;
                    if expected_dh.ct_eq(&dh_proof).unwrap_u8() == 0 {
                        warn!(
                            "DeviceEnrollment from {}: invalid DH proof — rejecting",
                            hash_addr(&client_addr)
                        );
                        self.audit_log.log(
                            AuditActor::System,
                            "device_enrollment_rejected",
                            cid,
                            "denied",
                        );
                        let shutdown = ControlPayload::Shutdown { reason: 3 };
                        let _ = self.send_control_message(&shutdown, session).await;
                        let session_id = session.lock().session_id;
                        self.session_manager.remove_session(&session_id);
                        return Ok(());
                    }
                    match db.enroll_device(cid, &static_pub) {
                        Ok(true) => info!("Device enrolled and bound for client {}", cid),
                        Ok(false) => debug!("Device binding verified for client {}", cid),
                        Err(e) => {
                            warn!("Device binding mismatch for {}: {}", cid, e);
                            self.audit_log.log(
                                AuditActor::System,
                                "device_binding_mismatch",
                                cid,
                                "denied",
                            );
                            let shutdown = ControlPayload::Shutdown { reason: 4 };
                            let _ = self.send_control_message(&shutdown, session).await;
                            let session_id = session.lock().session_id;
                            self.session_manager.remove_session(&session_id);
                        }
                    }
                }
            }
            ControlPayload::KeepaliveAck { echo_ts } => {
                debug!(
                    "KeepaliveAck from {} echo_ts={}",
                    hash_addr(&client_addr),
                    echo_ts
                );
            }
            ControlPayload::QualityReport {
                quality,
                rtt_ms,
                loss_ppm,
                jitter_ms,
            } => {
                info!(
                    "QualityReport from {}: quality={} rtt={}ms loss={}ppm jitter={}ms",
                    hash_addr(&client_addr),
                    quality,
                    rtt_ms,
                    loss_ppm,
                    jitter_ms
                );
                // Persist quality score on the session for monitoring/metrics,
                // and fold the RTT sample into the smoothed estimate that scales
                // the rekey/ratchet grace window (A5).
                {
                    let mut s = session.lock();
                    s.client_quality = quality;
                    s.observe_client_rtt(rtt_ms as u32);
                }
                // Push adaptive hint back so client adjusts keepalive + FEC immediately.
                let level = aivpn_common::quality::AdaptiveLevel::suggest(quality);
                if let Err(e) = self
                    .send_control_message(
                        &ControlPayload::AdaptiveHint { level: level as u8 },
                        session,
                    )
                    .await
                {
                    debug!("AdaptiveHint send failed: {}", e);
                }
            }
            ControlPayload::AdaptiveHint { .. } => {
                debug!(
                    "AdaptiveHint from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::MaskPreference { base_mask_id } => {
                self.metrics.record_mask_preference_request();
                let Some(base) = aivpn_common::mask::preset_masks::by_id(&base_mask_id) else {
                    debug!(
                        "MaskPreference from {} references unknown base mask '{}' — ignoring",
                        hash_addr(&client_addr),
                        base_mask_id
                    );
                    return Ok(());
                };

                let (session_id, prng_seed, current_mask_id) = {
                    let sess = session.lock();
                    // Prefer the pending (already-scheduled) mask id if a switch
                    // is in flight, else the active mask id.
                    let current = sess
                        .pending_mask
                        .as_ref()
                        .map(|(m, _)| m.mask_id.clone())
                        .or_else(|| sess.mask.as_ref().map(|m| m.mask_id.clone()));
                    (sess.session_id, sess.keys.prng_seed, current)
                };
                let variant = base.to_polymorphic(&prng_seed);

                // §3 F idempotency: MaskPreference is retried by the client for
                // reliability (a single lost packet must not disable polymorphic
                // masks). If the session already has this exact polymorphic
                // variant (active or pending), do NOT re-push a MaskUpdate —
                // re-pushing would reset the mimicry FSM mid-connection, an
                // observable disruption to the very fingerprint §3 protects.
                if polymorphic_variant_already_active(current_mask_id.as_deref(), &variant.mask_id)
                {
                    debug!(
                        "MaskPreference from {}: variant '{}' already active/pending — skipping re-push (idempotent)",
                        hash_addr(&client_addr),
                        variant.mask_id
                    );
                    return Ok(());
                }

                // Per-session rate limit on the expensive (sign + encrypt)
                // path below — see `MASK_PREFERENCE_THROTTLE`'s doc comment
                // for why this cannot interfere with the client's legitimate
                // same-id retry loop (those are already caught by the
                // idempotency check above, before ever reaching this point).
                // Uses `try_claim_mask_preference_slot` (atomic check-and-claim
                // via `DashMap::entry()`, not a separate get()+insert()) so two
                // MaskPreference packets for the same session processed by two
                // genuinely concurrent `tokio::spawn`ed tasks (see
                // `process_packets_concurrent`) cannot both slip past the
                // throttle before either has claimed it.
                let now = Instant::now();
                if !try_claim_mask_preference_slot(&self.mask_preference_throttle, session_id, now)
                {
                    debug!(
                        "MaskPreference from {}: throttled (processed one within the last {:?}) — dropping",
                        hash_addr(&client_addr),
                        MASK_PREFERENCE_THROTTLE
                    );
                    return Ok(());
                }

                info!(
                    "MaskPreference from {}: deriving polymorphic variant '{}' from base '{}'",
                    hash_addr(&client_addr),
                    variant.mask_id,
                    base_mask_id
                );

                match self
                    .session_manager
                    .build_mask_update_packet(session, &variant)
                {
                    Ok(packet) => {
                        // FIX L: `udp_socket` is `None` until `run()` binds
                        // it — don't panic if a control message races that
                        // window (or a `Gateway` is driven without `run()`,
                        // e.g. tests).
                        if let Some(sock) = self.udp_socket.as_ref() {
                            if let Err(e) = sock.send_to(&packet, client_addr).await {
                                warn!(
                                    "Failed to send polymorphic MaskUpdate to {}: {}",
                                    client_addr, e
                                );
                            } else {
                                self.session_manager
                                    .update_session_mask(&session_id, variant);
                                self.metrics.record_polymorphic_variant_pushed();
                            }
                        } else {
                            warn!(
                                "Dropping polymorphic MaskUpdate for {} — UDP socket not bound",
                                hash_addr(&client_addr)
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Failed to build polymorphic MaskUpdate packet: {}", e);
                    }
                }
            }
            ControlPayload::MaskFeedback {
                entries,
                country_code,
            } => {
                // §2 M1 independent opt-in: an EMPTY MaskFeedback is a
                // receive-only client's hints probe — it shares no outcome data
                // but still carries a country code so the server can reply with
                // RegionalMaskHints. So empty entries are NOT ignored; we simply
                // skip the record step and fall through to the reply below.
                if !entries.is_empty() {
                    let client_id = {
                        let sess = session.lock();
                        sess.client_id.clone()
                    };
                    // k-anonymity requires a *stable* authenticated reporter
                    // identity. Without `client_id` (e.g. `client_db` unset, or
                    // an unauthenticated session) the only available fallback
                    // would be the ephemeral `session_id`, which lets a single
                    // client fake unlimited "distinct reporters" simply by
                    // reconnecting — degrading k-anonymity to "distinct
                    // sessions". Skip recording in that case rather than
                    // silently weakening the guarantee (still reply with hints).
                    match client_id {
                        Some(client_id) => {
                            // Reporter token: hashed stable client identity,
                            // never the raw identity. Fed only into the
                            // HyperLogLog sketch, which discards it immediately
                            // after updating one register — no raw or hashed
                            // reporter identity is ever persisted server-side.
                            let reporter_token = blake3::hash(client_id.as_bytes());
                            let entry_count = entries.len().min(64);
                            info!(
                                "MaskFeedback from {} ({} entries, country={})",
                                hash_addr(&client_addr),
                                entry_count,
                                crate::mask_feedback::sanitize_country_code_for_log(&country_code)
                            );
                            self.mask_feedback.record_feedback(
                                country_code,
                                reporter_token.as_bytes(),
                                &entries,
                            );
                            self.metrics.record_mask_feedback_received();
                            // Refresh the store-size gauges immediately after a
                            // write — cheap (O(1), see `bucket_count`/
                            // `region_count`) and keeps the live dashboard from
                            // lagging behind the 300s periodic sweep refresh
                            // (see the sweep task in `run()`, which re-syncs
                            // these same gauges after evictions).
                            self.metrics
                                .set_feedback_buckets(self.mask_feedback.bucket_count());
                            self.metrics
                                .set_feedback_regions(self.mask_feedback.region_count());
                        }
                        None => {
                            debug!(
                                "MaskFeedback outcomes from {} not recorded — no authenticated client_id (k-anonymity requires a stable identity); still replying with hints",
                                hash_addr(&client_addr)
                            );
                        }
                    }
                } else {
                    debug!(
                        "Hints-only MaskFeedback probe from {} (country={})",
                        hash_addr(&client_addr),
                        crate::mask_feedback::sanitize_country_code_for_log(&country_code)
                    );
                }

                // FIX F.1 (MEDIUM, §2 amplification): per-session throttle on
                // the scan+reply path below — see `MASK_FEEDBACK_THROTTLE`'s
                // doc comment. Deliberately placed AFTER the recording block
                // above: real outcome recording (cheap, O(1) HLL update,
                // already bounded by MAX_BUCKETS/MAX_BUCKETS_PER_COUNTRY) is
                // never dropped by this throttle, only the expensive
                // `top_masks_for_region` scan and its up-to-two encrypted
                // replies. Uses the same atomic check-and-claim primitive as
                // `MaskPreference` so two genuinely concurrent MaskFeedback
                // packets for the same session cannot both slip past it.
                let feedback_session_id = session.lock().session_id;
                if !try_claim_mask_feedback_slot(
                    &self.mask_feedback_throttle,
                    feedback_session_id,
                    Instant::now(),
                ) {
                    debug!(
                        "MaskFeedback from {}: hints/reply path throttled (one served within the last {:?}) — skipping scan+reply",
                        hash_addr(&client_addr),
                        MASK_FEEDBACK_THROTTLE
                    );
                    return Ok(());
                }

                // Close the loop immediately: the server does not know the
                // client's region ahead of time, so hints are only ever sent
                // right after a MaskFeedback (which carries the country code).
                // If the region's aggregates clear the k-anonymity gate, push
                // them back. Fires for both real reports and empty hints probes.
                let top = self.mask_feedback.top_masks_for_region(country_code);
                if !top.is_empty() {
                    match self
                        .send_control_message(
                            &ControlPayload::RegionalMaskHints {
                                country_code,
                                masks: top,
                            },
                            session,
                        )
                        .await
                    {
                        Ok(()) => self.metrics.record_regional_hints_sent(),
                        Err(e) => debug!("RegionalMaskHints send failed: {}", e),
                    }
                }

                // §2 M3 server-pushed config: tell the opted-in client how to
                // tune its reporting (failure threshold + report interval).
                // Only opted-in clients ever send MaskFeedback, so this reaches
                // exactly the right audience without extra gating.
                if let Err(e) = self
                    .send_control_message(
                        &ControlPayload::FeedbackConfig {
                            report_failure_threshold: self.config.feedback_report_failure_threshold,
                            report_interval_secs: self.config.feedback_report_interval_secs,
                        },
                        session,
                    )
                    .await
                {
                    debug!("FeedbackConfig send failed: {}", e);
                }
            }
            ControlPayload::RegionalMaskHints { .. } => {
                debug!(
                    "Unexpected RegionalMaskHints from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::MaskCatalog { .. } => {
                // Server→client only; a client should never send this. Ignore.
                debug!(
                    "Unexpected MaskCatalog from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::FeedbackConfig { .. } => {
                // Server→client only; a client should never send this. Ignore.
                debug!(
                    "Unexpected FeedbackConfig from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
        }

        Ok(())
    }

    /// Send control message to client
    async fn send_control_message(
        &self,
        payload: &ControlPayload,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let socket = self.udp_socket.as_ref().unwrap();
        let mdh = {
            let mut sess = session.lock();
            sess.commit_pending_mask();
            sess.mask
                .as_ref()
                .map(packet_mdh_bytes_for_mask)
                .unwrap_or_else(|| self.mask_catalog.packet_mdh_bytes())
        };
        Self::send_control_message_via(socket, &mdh, payload, session).await
    }

    async fn send_control_message_via(
        socket: &UdpSocket,
        mdh: &[u8],
        payload: &ControlPayload,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let encoded = payload.encode()?;
        let (mut inner_payload, nonce, counter, keys, client_addr) = {
            let mut sess = session.lock();
            let inner_header = InnerHeader {
                inner_type: InnerType::Control,
                seq_num: sess.next_seq() as u16,
            };
            let inner_payload = inner_header.encode().to_vec();
            let (nonce, counter) = sess.next_send_nonce();
            let keys = sess.keys.clone();
            let client_addr = sess.client_addr;
            (inner_payload, nonce, counter, keys, client_addr)
        };
        inner_payload.extend_from_slice(&encoded);
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
        let ciphertext = encrypt_payload(&keys.session_key_s2c, &nonce, &padded)?; // downlink → S2C key
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&keys.tag_secret, counter, time_window);
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(mdh);
        packet.extend_from_slice(&ciphertext);
        socket.send_to(&packet, client_addr).await?;
        Ok(())
    }

    async fn send_server_hello(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let (server_eph_pub, signature, network_config) = {
            let sess = session.lock();
            match (sess.server_eph_pub, sess.server_hello_signature) {
                (Some(pub_key), Some(sig)) => {
                    let network_config = sess
                        .vpn_ip
                        .and_then(|vpn_ip| self.config.network_config.client_config(vpn_ip).ok());
                    (pub_key, sig, network_config)
                }
                _ => return Err(Error::Session("Missing ratchet data".into())),
            }
        };

        let hello = ControlPayload::ServerHello {
            server_eph_pub,
            signature,
            network_config,
        };
        let encoded = hello.encode()?;
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: 0,
        };
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);
        let packet = self.build_packet(&inner_payload, session)?;
        let socket = self.udp_socket.as_ref().unwrap();
        let sent = socket.send_to(&packet, client_addr).await?;
        debug!("ServerHello sent: {} bytes to {}", sent, client_addr);
        Ok(())
    }

    /// Build the client-facing mask catalog: every mask a client may select,
    /// each tagged with whether the server auto-generated it (mask_gen). Built-in
    /// presets come first in their stable order, then auto-generated masks from
    /// the store; deduped by id. Drives the client picker + its "(авто)" marker.
    fn build_mask_catalog_payload(&self) -> ControlPayload {
        let mut masks: Vec<(String, String, bool)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for preset in aivpn_common::mask::preset_masks::all().iter() {
            if seen.insert(preset.mask_id.clone()) {
                masks.push((
                    preset.mask_id.clone(),
                    preset.mask_id.clone(),
                    preset.generated,
                ));
            }
        }
        if let Some(ref store) = self.mask_store {
            for entry in store.list_masks() {
                let id = entry.profile.mask_id.clone();
                if seen.insert(id.clone()) {
                    masks.push((id.clone(), id, entry.profile.generated));
                }
            }
        }
        ControlPayload::MaskCatalog { masks }
    }

    /// Push the current mask catalog to one session over the control plane.
    async fn send_mask_catalog(&self, session: &Arc<parking_lot::Mutex<Session>>) -> Result<()> {
        let payload = self.build_mask_catalog_payload();
        self.send_control_message(&payload, session).await
    }

    /// Build AIVPN packet
    /// Wire format: TAG | MDH | encrypt(pad_len_u16 || plaintext || random_padding)
    fn build_packet(
        &self,
        plaintext: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<Vec<u8>> {
        let mut sess = session.lock();

        // Use unified counter for both nonce and tag
        let (nonce, counter) = sess.next_send_nonce();

        // Build padded plaintext: pad_len(u16) || plaintext || random_padding
        // pad_len is inside encryption — invisible to DPI (CRIT-5 fix)
        let pad_len = 16u16;
        let mut padded = Vec::with_capacity(2 + plaintext.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(plaintext);
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..pad_len {
            padded.push(rng.gen::<u8>());
        }

        let ciphertext = encrypt_payload(&sess.keys.session_key_s2c, &nonce, &padded)?; // downlink → S2C key

        // Generate tag
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&sess.keys.tag_secret, counter, time_window);
        let current_mask = sess.mask.clone();
        drop(sess);

        // Build MDH using the session's current packet mask so the peer can
        // decode bootstrap traffic before any runtime MaskUpdate arrives.
        let mdh = current_mask
            .as_ref()
            .map(packet_mdh_bytes_for_mask)
            .unwrap_or_else(|| self.mask_catalog.packet_mdh_bytes());

        // Assemble packet: TAG | MDH | ciphertext (no cleartext padding)
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// Compute Shannon entropy of a byte slice (0.0 = uniform, 8.0 = max)
    fn compute_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
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

/// Build the kernel session-install payload. `tag_offset`/`mdh_len` describe the
/// wire layout the CLIENT uses for its uplink — the runtime primary mask it
/// converges to via the MaskCatalog, NOT the session's (possibly still
/// bootstrap) mask, which can lag with a different MDH length and make the
/// kernel slice the ciphertext at the wrong offset.
fn make_kernel_session_add(
    sess: &crate::session::Session,
    tag_offset: u16,
    mdh_len: u16,
) -> SessionAdd {
    // The kernel indexes this session in its IP hash-table by `client_ip` and the
    // downlink egress hook looks it up by the packet's INNER destination
    // (`iph->daddr` = the client's VPN/tunnel IP). It must therefore be the
    // client's VPN IP — NOT the outer transport source address — and in network
    // byte order to match `__be32 iph->daddr`. Using the transport IP (or host
    // byte order) made every egress lookup miss, so K5 downlink never engaged.
    let client_ip = match sess.vpn_ip {
        Some(ip) => u32::from_ne_bytes(ip.octets()),
        None => 0,
    };
    let mut ca = [0u8; 28];
    match sess.client_addr {
        SocketAddr::V4(ref v4) => {
            ca[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            ca[2..4].copy_from_slice(&v4.port().to_be_bytes());
            ca[4..8].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(ref v6) => {
            ca[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            ca[2..4].copy_from_slice(&v6.port().to_be_bytes());
            ca[8..24].copy_from_slice(&v6.ip().octets());
        }
    }
    SessionAdd {
        session_id: sess.session_id,
        // Directional keys: session_key (c2s) decrypts the client uplink the
        // kernel handles; session_key_s2c (s2c) is used by kernel downlink
        // encryption. Matches the userspace data path's directional keys.
        session_key: sess.keys.session_key,
        session_key_s2c: sess.keys.session_key_s2c,
        tag_secret: sess.keys.tag_secret,
        // The AIVPN nonce is counter_LE(8) || zeros(4): both the client
        // (client_wire::counter_to_nonce) and the server (compute_nonce) leave
        // bytes 8..12 zero — there is no per-session nonce suffix. Passing a
        // non-zero suffix here (previously prng_seed[..4]) made the kernel build
        // a different nonce and fail every AEAD auth. Must stay all-zero.
        nonce_suffix: [0u8; 4],
        tag_offset,
        mdh_len,
        _reserved: [0u8; 24],
        counter_base: sess.counter,
        client_ip,
        client_addr: ca,
        window_ms: DEFAULT_WINDOW_MS,
    }
}

/// Cheap change-detector over the kernel-relevant session state: the c2s key
/// (rotates on rekey/ratchet) and the wire layout (tag_offset/mdh_len, which
/// change when the client switches from the bootstrap mask to the runtime mask).
/// When this differs from the last value pushed to the kernel, the kernel
/// session must be re-installed so its frozen key/offsets don't silently fail
/// every decrypt.
fn kernel_session_sig(sess: &crate::session::Session, tag_offset: u16, mdh_len: u16) -> u64 {
    let mut k = [0u8; 8];
    k.copy_from_slice(&sess.keys.session_key[..8]);
    u64::from_le_bytes(k) ^ ((tag_offset as u64) << 48) ^ ((mdh_len as u64) << 32)
}

/// Number of downlink send-counters reserved per kernel-downlink arming. Kept
/// below the client's 256-entry reorder window so the reserved counters stay
/// acceptable relative to the highest downlink counter the client has seen, and
/// small enough that the pre-computed resonance tags remain inside the client's
/// current time window (DEFAULT_WINDOW_MS) between refreshes.
const KERNEL_DOWNLINK_BLOCK: u32 = 128;

/// True once the kernel downlink egress hook has been successfully enabled.
/// Reserving downlink counters advances `send_counter`; doing that when the
/// kernel is NOT actually transmitting downlink (egress off) would waste counter
/// space and could push user-space downlink counters past the client's forward
/// search window. So the reservation only runs once this is set.
static KERNEL_DOWNLINK_ARMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Reserve a fresh block of downlink send-counters for the kernel and build the
/// AIVPN_IOC_SESSION_DOWNLINK payload (reserved (tag,counter) pairs + MDH).
///
/// COUNTER SAFETY: the block `[base, base+N)` is claimed by advancing
/// `sess.send_counter` past it under the session lock, so the user-space
/// downlink path can never emit any counter in the block. Each counter is used
/// at most once (the kernel consumes them strictly in order), so no
/// (s2c-key, nonce) pair is ever reused. Returns `None` — leaving the session
/// on the user-space downlink path — if the session has no mask yet or its MDH
/// is larger than the kernel inline limit.
fn make_kernel_downlink(sess: &mut crate::session::Session) -> Option<SessionDownlink> {
    // Only reserve counters when the kernel is actually transmitting downlink.
    if !KERNEL_DOWNLINK_ARMED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let mdh = sess.mask.as_ref().map(packet_mdh_bytes_for_mask)?;
    if mdh.is_empty() || mdh.len() > DL_MDH_MAX {
        return None;
    }
    let count = KERNEL_DOWNLINK_BLOCK;
    let base = sess.send_counter;
    let tag_secret = sess.keys.tag_secret;
    let time_window = crypto::compute_time_window(
        crypto::current_timestamp_ms(),
        aivpn_common::crypto::DEFAULT_WINDOW_MS,
    );

    // Safety: SessionDownlink is a plain C struct of integers and byte arrays;
    // an all-zero value is valid for every field.
    let mut dl: SessionDownlink = unsafe { std::mem::zeroed() };
    dl.session_id = sess.session_id;
    dl.mdh_len = mdh.len() as u16;
    dl.mdh[..mdh.len()].copy_from_slice(&mdh);
    dl.seq_base = sess.send_seq as u16;
    for i in 0..count as u64 {
        let counter = base + i;
        let tag = crypto::generate_resonance_tag(&tag_secret, counter, time_window);
        dl.entries[i as usize] = TagWindowEntry { tag, counter };
    }
    dl.count = count;

    // Claim the block: user-space will never emit a counter below this value.
    sess.send_counter = base + count as u64;
    sess.send_seq = sess.send_seq.wrapping_add(count);
    // Record the time window these tags were derived for so the receive path can
    // re-arm the moment the wall-clock window advances (keeping the kernel's
    // frozen tags inside the client's ±1-window acceptance range).
    sess.kernel_dl_window = time_window;
    Some(dl)
}

fn make_kernel_update_tags(sess: &crate::session::Session) -> UpdateTagsPayload {
    // Safety: UpdateTagsPayload is a plain C struct of integers and byte arrays;
    // zeroed is valid for all fields.
    let mut payload: UpdateTagsPayload = unsafe { std::mem::zeroed() };
    payload.session_id = sess.session_id;

    // NOTE: the kernel window holds only AIVPN_TAG_WINDOW_SLOTS (256) tags while
    // `expected_tags` spans ~1023 counters ([base-511, base+511]), so only a
    // subset is pushed and many uplink packets currently miss the kernel and
    // fall back to user-space. Tracking the kernel's own recv_counter to keep
    // the pushed window centred ahead of it is a K7 throughput task; do not
    // narrow the subset heuristically here — the arriving counters run ahead of
    // the server's last refreshed base by an unknown amount, so any fixed slice
    // (lowest-256 / highest-256) can sit entirely off the incoming range.
    let mut count = 0usize;
    for (&counter, tag) in sess.expected_tags.iter().take(256) {
        payload.entries[count] = TagWindowEntry { tag: *tag, counter };
        count += 1;
    }
    payload.count = count as u32;
    payload
}

#[cfg(test)]
mod tests {
    use super::inner_l7_prefix;
    use super::mask_feedback_throttled;
    use super::mask_preference_throttled;
    use super::polymorphic_variant_already_active;
    use super::try_claim_mask_feedback_slot;
    use super::try_claim_mask_preference_slot;
    use super::Gateway;
    use super::GatewayConfig;
    use super::MaskCatalog;
    use super::MASK_FEEDBACK_THROTTLE;
    use super::MASK_PREFERENCE_THROTTLE;
    use aivpn_common::crypto::TAG_SIZE;
    use aivpn_common::mask::preset_masks::webrtc_zoom_v3;
    use dashmap::DashMap;
    use std::time::{Duration, Instant};

    /// The handshake candidate scan must derive descriptors for a WINDOW of
    /// recent epochs so a client on a slightly stale (but still legitimately
    /// cached) covert descriptor keeps matching a rotated mask instead of being
    /// forced onto a public preset or into a reconnect loop. This pins the
    /// window to `[epoch-2, epoch-1, epoch, epoch+1]` (see BOOTSTRAP_EPOCH_WINDOW):
    /// widening the previous ±1 (24h) window to tolerate a client up to ~48h
    /// behind, without ever emitting a static/known shape (every descriptor is
    /// still epoch-rotated).
    #[test]
    fn bootstrap_descriptor_window_covers_recent_epochs() {
        use super::{
            bootstrap_epoch, build_bootstrap_descriptors, current_unix_secs,
            derive_server_signing_key, BOOTSTRAP_EPOCH_WINDOW,
        };
        let seed = [7u8; 32];
        let signing_key = derive_server_signing_key(&seed);
        let masks = [webrtc_zoom_v3()];
        let descriptors = build_bootstrap_descriptors(&seed, &signing_key, &masks);

        let epoch = bootstrap_epoch(current_unix_secs());
        let expected: Vec<String> = BOOTSTRAP_EPOCH_WINDOW
            .iter()
            .map(|delta| {
                let value = if *delta < 0 {
                    epoch.saturating_sub(delta.unsigned_abs())
                } else {
                    epoch.saturating_add(*delta as u64)
                };
                format!("epoch-{}", value)
            })
            .collect();
        let got: Vec<String> = descriptors
            .iter()
            .map(|d| d.descriptor_id.clone())
            .collect();

        assert_eq!(got, expected, "descriptor window must be epoch-2..=epoch+1");
        assert_eq!(descriptors.len(), 4);
        // Two epochs back is now covered (it was NOT under the old ±1 window).
        assert!(got.contains(&format!("epoch-{}", epoch.saturating_sub(2))));
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

    #[test]
    fn mask_preference_throttle_blocks_within_window() {
        let now = Instant::now();
        // No prior processed request — never throttled.
        assert!(!mask_preference_throttled(None, now));

        // Processed "just now" (elapsed ~0) — must throttle.
        assert!(mask_preference_throttled(Some(now), now));

        // Still within the window a moment later.
        let later = now + Duration::from_millis(500);
        assert!(mask_preference_throttled(Some(now), later));
    }

    #[test]
    fn mask_preference_throttle_allows_after_window_elapses() {
        let now = Instant::now();
        let after_window = now + MASK_PREFERENCE_THROTTLE + Duration::from_millis(1);
        assert!(!mask_preference_throttled(Some(now), after_window));
    }

    #[test]
    fn mask_preference_throttle_window_covers_client_retry_gap_but_retries_are_idempotent_not_throttled(
    ) {
        // Documents why the throttle is safe against the client's retry loop
        // (see `aivpn-client/src/client.rs`'s polymorphic_base resend task):
        // it resends the SAME base_mask_id at cumulative offsets of 0ms,
        // 500ms, 1500ms, 3000ms, 5000ms. Every resend after the first hits
        // the pre-existing idempotency check (the variant is already
        // active/pending) and returns before ever consuming this throttle —
        // so whether this predicate would say "throttled" for those later
        // timestamps is moot. This test just pins down that the 2s window
        // does span most of that retry burst, to make the interaction
        // explicit rather than implicit.
        let first_processed = Instant::now();
        let retry_offsets_ms = [500u64, 1500, 3000, 5000];
        let within_window: Vec<bool> = retry_offsets_ms
            .iter()
            .map(|&ms| {
                let t = first_processed + Duration::from_millis(ms);
                mask_preference_throttled(Some(first_processed), t)
            })
            .collect();
        // The first two retries (500ms, 1500ms) fall inside the 2s window;
        // the last two (3s, 5s) do not. Irrelevant in practice (idempotency
        // catches all of them first) but documented here for clarity.
        assert_eq!(within_window, vec![true, true, false, false]);
    }

    /// §3 F sign-amplification (LOW #3): proves the atomic
    /// `try_claim_mask_preference_slot` check-and-claim means at most one of
    /// two "concurrent" `MaskPreference` packets for the same session can
    /// ever reach the sign+encrypt path — i.e. a retry storm signs once, not
    /// once per packet. True thread-level concurrency isn't reliably
    /// unit-testable, but calling the exact production claim function twice
    /// back-to-back for the same `(session_id, now)` exercises the same
    /// code path two racing tasks would hit (both see the same `now`, only
    /// one can win the DashMap shard lock first) and is what the old
    /// get()-then-insert() sequence could fail on.
    #[test]
    fn try_claim_mask_preference_slot_first_racer_wins_second_is_suppressed() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_id = [7u8; 16];
        let now = Instant::now();

        // First packet for this session claims the slot and must proceed.
        assert!(try_claim_mask_preference_slot(&throttle, session_id, now));

        // A second packet for the *same* session and the *same* instant —
        // simulating a genuinely concurrent racer arriving at the same
        // `now` — must observe the slot already claimed and be suppressed.
        assert!(!try_claim_mask_preference_slot(&throttle, session_id, now));

        // A third, later call for the same session while still inside the
        // window must also be suppressed (ordinary throttle behaviour).
        let still_within = now + Duration::from_millis(1);
        assert!(!try_claim_mask_preference_slot(
            &throttle,
            session_id,
            still_within
        ));
    }

    #[test]
    fn try_claim_mask_preference_slot_allows_again_after_window_elapses() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_id = [8u8; 16];
        let now = Instant::now();
        assert!(try_claim_mask_preference_slot(&throttle, session_id, now));

        let after_window = now + MASK_PREFERENCE_THROTTLE + Duration::from_millis(1);
        assert!(try_claim_mask_preference_slot(
            &throttle,
            session_id,
            after_window
        ));
    }

    #[test]
    fn try_claim_mask_preference_slot_is_independent_per_session() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let now = Instant::now();
        // One session claiming its slot must not throttle an unrelated
        // session's claim at the same instant.
        assert!(try_claim_mask_preference_slot(&throttle, [1u8; 16], now));
        assert!(try_claim_mask_preference_slot(&throttle, [2u8; 16], now));
    }

    #[test]
    fn packet_layout_extracts_embedded_eph_pub_from_mdh() {
        let catalog = MaskCatalog::new();
        let mask = webrtc_zoom_v3();
        catalog.register_mask(mask.clone());
        catalog.set_primary_mask_id(mask.mask_id.clone());
        let (packet_mdh_len, handshake_mdh_len, eph_offset, eph_len) = catalog.packet_layout();

        let mut mdh = mask.header_template.clone();
        if mdh.len() < handshake_mdh_len {
            mdh.resize(handshake_mdh_len, 0);
        }

        let expected_eph = [0x5au8; 32];
        mdh[eph_offset..eph_offset + eph_len].copy_from_slice(&expected_eph);

        let mut packet = vec![0u8; TAG_SIZE];
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&[0xabu8; 24]);

        let eph_start = TAG_SIZE + eph_offset;
        let payload_start = TAG_SIZE + handshake_mdh_len;

        assert_eq!(
            packet_mdh_len, 20,
            "regular STUN packet MDH length must stay at 20 bytes"
        );
        assert_eq!(
            handshake_mdh_len, 52,
            "handshake MDH length must include embedded eph_pub"
        );
        assert_eq!(&packet[eph_start..eph_start + eph_len], &expected_eph);
        assert_eq!(&packet[payload_start..], &[0xabu8; 24]);
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

    // ========================================================================
    // FIX F: MaskFeedback per-session throttle (§2 amplification)
    // ========================================================================

    /// Same shape as `mask_preference_throttle_blocks_within_window` — the
    /// `MaskFeedback` throttle predicate must behave identically: no prior
    /// slot never throttles, a slot claimed just now throttles, and it stops
    /// throttling once `MASK_FEEDBACK_THROTTLE` has elapsed.
    #[test]
    fn mask_feedback_throttle_blocks_within_window() {
        let now = Instant::now();
        assert!(!mask_feedback_throttled(None, now));
        assert!(mask_feedback_throttled(Some(now), now));

        let later = now + Duration::from_millis(500);
        assert!(mask_feedback_throttled(Some(now), later));

        let after_window = now + MASK_FEEDBACK_THROTTLE + Duration::from_millis(1);
        assert!(!mask_feedback_throttled(Some(now), after_window));
    }

    /// `try_claim_mask_feedback_slot` must give the same atomic
    /// check-and-claim guarantee as `try_claim_mask_preference_slot`: the
    /// first caller for a session claims the slot; a second caller for the
    /// SAME session within the window is throttled; after the window
    /// elapses, the slot can be claimed again.
    #[test]
    fn try_claim_mask_feedback_slot_is_atomic_check_and_claim() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_id = [7u8; 16];
        let t0 = Instant::now();

        assert!(
            try_claim_mask_feedback_slot(&throttle, session_id, t0),
            "first claim for a fresh session must succeed"
        );
        assert!(
            !try_claim_mask_feedback_slot(&throttle, session_id, t0),
            "second claim within the window must be throttled"
        );

        let t1 = t0 + MASK_FEEDBACK_THROTTLE + Duration::from_millis(1);
        assert!(
            try_claim_mask_feedback_slot(&throttle, session_id, t1),
            "claim after the window has elapsed must succeed again"
        );
    }

    /// Two DIFFERENT sessions must never interfere with each other's
    /// throttle slot — a flood from one session cannot suppress a
    /// legitimate MaskFeedback reply for a different, unrelated session.
    #[test]
    fn mask_feedback_throttle_is_scoped_per_session() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_a = [1u8; 16];
        let session_b = [2u8; 16];
        let now = Instant::now();

        assert!(try_claim_mask_feedback_slot(&throttle, session_a, now));
        // session_a is now throttled, but session_b must be entirely
        // unaffected.
        assert!(try_claim_mask_feedback_slot(&throttle, session_b, now));
        assert!(!try_claim_mask_feedback_slot(&throttle, session_a, now));
        assert!(!try_claim_mask_feedback_slot(&throttle, session_b, now));
    }

    /// `MASK_PREFERENCE_THROTTLE` and `MASK_FEEDBACK_THROTTLE` are
    /// independent windows — sanity check that they're not accidentally
    /// aliased to the same constant (which would make the two throttle maps
    /// redundant and defeat the point of having a dedicated, documented
    /// window for each control message type).
    #[test]
    fn mask_feedback_and_mask_preference_throttles_are_independent_constants() {
        assert_ne!(MASK_FEEDBACK_THROTTLE, MASK_PREFERENCE_THROTTLE);
    }

    #[test]
    fn inner_l7_prefix_extracts_udp_payload() {
        // IPv4 (IHL=5, proto=17 UDP) + 8-byte UDP header + STUN-shaped L7:
        // type@0, len@2, magic cookie 0x2112A442 @4 — what detect_mimic_protocol
        // keys off. inner_l7_prefix must return the L7 payload starting at
        // ip[20+8], i.e. the STUN bytes, NOT the IP/UDP header.
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, IHL 5
        ip[9] = 17; // UDP
        ip.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // UDP header (8B)
        let stun = [0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4];
        ip.extend_from_slice(&stun);
        let l7 = inner_l7_prefix(&ip);
        assert_eq!(&l7[..], &stun[..]);
        assert_eq!(&l7[4..8], &[0x21, 0x12, 0xA4, 0x42]); // magic cookie at offset 4
    }

    #[test]
    fn inner_l7_prefix_handles_tcp_and_caps_at_16() {
        // IPv4 + TCP (data offset 5 words = 20B header) + 20B payload → capped 16.
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6; // TCP
        let mut tcp = vec![0u8; 20];
        tcp[12] = 0x50; // data offset = 5 words (20 bytes)
        ip.extend_from_slice(&tcp);
        ip.extend_from_slice(&[0xAB; 20]);
        let l7 = inner_l7_prefix(&ip);
        assert_eq!(l7.len(), 16);
        assert!(l7.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn inner_l7_prefix_rejects_non_ipv4_and_ciphertext() {
        assert!(inner_l7_prefix(&[]).is_empty());
        assert!(inner_l7_prefix(&[0x60; 40]).is_empty()); // IPv6
        assert!(inner_l7_prefix(&[0x45, 0, 0, 0]).is_empty()); // truncated
                                                               // A raw encrypted wire prefix (random high bytes, first nibble != 4)
                                                               // must yield nothing — this is the exact regression the fix prevents.
        assert!(inner_l7_prefix(&[0x9f, 0x3c, 0xa1, 0x00, 0xde, 0xad, 0xbe, 0xef]).is_empty());
    }
}
