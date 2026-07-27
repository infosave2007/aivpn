//! AIVPN Client - Full Implementation
//!
//! Complete VPN client with:
//! - Real TUN device integration
//! - Mimicry Engine for traffic shaping
//! - Key exchange and session management
//! - Control plane handling

mod config;
mod control_handler;
mod kernel_offload;
mod reject;
mod session;

pub use config::{ClientConfig, ClientState};
pub use reject::handshake_reject_message;
use reject::handshake_reject_token;

use bytes::Bytes;
use portable_atomic::AtomicU64;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use aivpn_common::client_wire::{
    build_inner_packet, decode_downlink_any_mdh_len, obfuscate_client_eph_pub, DecodedPacket,
    RecvWindow,
};
use aivpn_common::crypto::{self, KeyPair, SessionKeys, X25519_PUBLIC_KEY_SIZE};
use aivpn_common::error::{Error, Result};
use aivpn_common::mask::{current_unix_secs, BootstrapDescriptor, MaskProfile};
use aivpn_common::mgmt::MgmtClient;
use aivpn_common::network_config::ClientNetworkConfig;
use aivpn_common::protocol::{
    ControlPayload, InnerType, MaskOutcome, MAX_PACKET_SIZE, UDP_RECV_BUF_SIZE,
};
use aivpn_common::quality::{AdaptiveLevel, QualityTracker};
use aivpn_common::upload_pipeline::{self, PacketEncryptor, UploadConfig};

use crate::bootstrap_cache;
use crate::mask_feedback_log::{MaskFeedbackLog, RegionalHintsStore};
use crate::tunnel::{Tunnel, TunnelConfig};
#[cfg(target_os = "linux")]
use aivpn_common::kernel_accel::{
    xdp_detach, KernelAccel, SessionAdd, TagWindowEntry, UpdateTagsPayload,
};
use aivpn_common::mimicry::MimicryEngine;

/// RAII guard that aborts a spawned task when dropped.
/// Used to ensure the admin IPC socket task is cancelled when run() returns,
/// so the next reconnect iteration can bind 127.0.0.1:44301 without
/// "Address already in use".
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A4: NAT-safe upper bound for the keepalive interval. Consumer CGNAT UDP
/// mappings commonly expire after ~30 s of silence; capping at 25 s keeps the
/// mapping warm with margin while staying battery-friendly on mobile.
/// `AdaptiveLevel::Satellite` is exempt — satellite links have deliberately
/// different timing (15 s default, possibly longer from the server) and the
/// server-chosen interval is authoritative there.
const KEEPALIVE_NAT_CAP: Duration = Duration::from_secs(25);

/// A4: if nothing has been SENT for this long, the CGNAT mapping is close to
/// expiry — fire the proactive warmup burst before it dies instead of paying
/// a full reconnect after it. Only reachable when the keepalive loop stalls
/// (mobile doze, event-loop backpressure) or the server pushed an interval
/// above the cap, since normal keepalives fire well under 20 s.
const NAT_WARMUP_AFTER: Duration = Duration::from_secs(20);

// ── Post-freeze/suspend liveness probe ──
// System suspend (laptop lid close) or an outside freeze (SIGSTOP, cgroup
// freezer) stops this process entirely; the first watchdog tick after wake
// sees a gap far beyond the 5 s watchdog cadence. A session whose server-side
// state died during the gap would otherwise linger dead for up to the
// RX-silence net: keepalives resume unanswered, and the data watchdog needs
// ≥TX_WITHOUT_RX_MIN_BYTES of uplink to condemn. After a gap this large,
// demand ANY decodable RX within the probe window instead. Same
// constants/semantics as android_tunnel.rs.
const WAKE_GAP_THRESHOLD: Duration = Duration::from_secs(15);
/// Probe window bounds: max(2×keepalive interval, MIN) capped at MAX — at
/// least two keepalives (sent immediately after wake) must have a chance to
/// be answered before the session is condemned.
const WAKE_PROBE_WINDOW_MIN: Duration = Duration::from_secs(10);
const WAKE_PROBE_WINDOW_MAX: Duration = Duration::from_secs(60);

/// How long the client keeps the PREVIOUS session keys accepting inbound
/// packets after an inline rekey. Must cover the server's KeyRotate
/// retransmit horizon (`MAX_REKEY_SEND_ATTEMPTS` = 5 sends spread over ~16 s
/// on a ~3–4 s cadence, server `session.rs`): if the client's rekey RESPONSE
/// is lost, the server stays on the OLD keys and retransmits KeyRotate under
/// them — the client must still be able to decode those retransmits (and the
/// old-key downlink flowing in between) to re-send its response and
/// self-heal with ZERO reconnects. The former 2 s window expired before the
/// first retransmit (~4 s) could arrive, so every lost response cost a full
/// RX-silence reconnect.
const REKEY_TRANSITION_GRACE: Duration = Duration::from_secs(20);

/// Absolute ceiling on how long the old-key fallback decode can stay armed
/// after a single inline rekey, counted from the moment the client switched to
/// the new keys. Each in-grace KeyRotate retransmit re-arms the 20 s grace;
/// without this cap a rekey that never converges (every response re-send lost
/// on the same flaky uplink) kept re-arming the transition window — and with
/// it deferred every recovery path — indefinitely. 2× the grace comfortably
/// covers the server's full retransmit horizon (~12 s, session.rs
/// MAX_REKEY_SEND_ATTEMPTS × REKEY_RETRANSMIT_SECS) plus one final grace; past
/// it the session either healed or must fall through to the data watchdog and
/// a clean full reconnect (mirrors ios_tunnel.rs / android_tunnel.rs).
const REKEY_TRANSITION_HARD_CAP: Duration = Duration::from_secs(40);

// Data-plane watchdogs (see `data_watchdog_verdict`): clocked on DATA actually
// delivered to the TUN/proxy, never on "any decode" — keepalive-acks and
// in-grace KeyRotate retransmits must not mask a dead data downlink. Same
// constants/semantics as ios_tunnel.rs / android_tunnel.rs.
const TX_WITHOUT_RX_TIMEOUT: Duration = Duration::from_secs(20);
// 4 KiB, not 512 B: legitimate upload-only flows with no downlink at all
// (fire-and-forget UDP telemetry, one-way media, chatty mDNS/SSDP at
// ~18+ B/s) could cross 512 B inside one 30 s stall window and be condemned
// even though the tunnel was healthy. 4 KiB needs ~135+ B/s of sustained
// unanswered uplink DATA — beyond any junk/telemetry pattern — while a dead
// downlink under real use (TCP/QUIC upload whose ACKs stopped coming back)
// accumulates 4 KiB within seconds.
const TX_WITHOUT_RX_MIN_BYTES: u64 = 4096;
// A stall window that never accumulates TX_WITHOUT_RX_MIN_BYTES of uplink
// data is unanswerable background junk (ICMPv6 ND, mDNS, telemetry beacons to
// dead hosts — observed live: ~48 B every ~7 s on an idle TUN), not a dead
// downlink. The window is WASHED (byte base + stall anchor reset) so idle
// trickle can never accumulate into a false-positive reconnect over hours,
// while a dead downlink under real use (≥4 KiB of unanswered uplink data in
// one 30 s window) still reconnects in ~25–35 s even when the control plane
// keeps decoding (keepalive-acks / rekey retransmits).
const DATA_STALL_WINDOW: Duration = Duration::from_secs(30);
/// Consecutive 5 s watchdog ticks the stall verdict must hold before the
/// session is condemned (see `data_stall_confirmed`). One extra tick gives a
/// slow-but-alive downlink (delayed ACKs, bufferbloat spike) a last chance to
/// stamp `last_data_rx` and clear the verdict, pushing the false-fire class
/// further away from healthy upload-heavy flows. A genuinely dead downlink
/// still fires on the second consecutive tick — ~25–35 s after the stall
/// armed, nowhere near the old 120 s-only absolute net.
const DATA_STALL_STRIKES_TO_FIRE: u32 = 2;

/// Data-plane liveness verdict, driven ONLY by authenticated DATA actually
/// delivered to the TUN — never by control traffic. Keepalive-acks and
/// in-grace KeyRotate retransmits used to keep advancing the RX watchdog while
/// ZERO data reached the TUN: after an unconverged inline rekey (client
/// switched to new recv keys, server still sending downlink under old) the
/// data downlink was permanently dead yet the tunnel stayed "connected" for
/// minutes. `stalled_for` is how long uplink DATA has been flowing with no
/// DATA coming back (None = no uplink data since the last downlink data, or
/// data plane not yet proven — an idle tunnel must never trip). The caller
/// washes the stall window at DATA_STALL_WINDOW if the byte threshold was
/// never reached (junk trickle immunity). Identical across desktop client.rs
/// / ios_tunnel.rs / android_tunnel.rs.
fn data_watchdog_verdict(
    stalled_for: Option<Duration>,
    data_uploaded_since_data_rx: u64,
) -> Option<&'static str> {
    let stalled = stalled_for?;
    if stalled > TX_WITHOUT_RX_TIMEOUT && data_uploaded_since_data_rx >= TX_WITHOUT_RX_MIN_BYTES {
        return Some("TX without data RX");
    }
    None
}

/// Two-strike confirmation on top of `data_watchdog_verdict`: the stall
/// verdict must persist for DATA_STALL_STRIKES_TO_FIRE consecutive watchdog
/// ticks before the session is condemned. Any tick where the verdict clears
/// (downlink DATA arrived and reset the stall, or the byte threshold was
/// never met) resets the strike counter, so an upload-only-but-healthy flow
/// that gets even one answering DATA packet never fires. Identical across
/// desktop client.rs / ios_tunnel.rs / android_tunnel.rs.
fn data_stall_confirmed(strikes: &mut u32, verdict: Option<&'static str>) -> Option<&'static str> {
    match verdict {
        Some(reason) => {
            *strikes += 1;
            if *strikes >= DATA_STALL_STRIKES_TO_FIRE {
                Some(reason)
            } else {
                None
            }
        }
        None => {
            *strikes = 0;
            None
        }
    }
}

/// Upper bound on the rekey-ack rendezvous wait. The ack normally fires
/// sub-millisecond (it is a local oneshot fired by the upload task right
/// after encrypting the KeyRotate response), so 5 s can only elapse if the
/// upload task died between dequeuing the KeyRotate and firing the ack
/// (e.g. an encrypt error propagated by `?`). Without the bound, the
/// stranded `oneshot::Sender` kept alive inside the shared
/// `Arc<Mutex<VecDeque>>` would make `ack_rx.await` pend forever inside a
/// select arm, freezing the receive loop (watchdog, stop signal and all).
const REKEY_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply the NAT-safe keepalive cap (A4) for every adaptive level except
/// Satellite.
fn keepalive_with_nat_cap(level: AdaptiveLevel, requested: Duration) -> Duration {
    if level == AdaptiveLevel::Satellite {
        requested
    } else {
        requested.min(KEEPALIVE_NAT_CAP)
    }
}

/// K6: number of (tag, counter) entries pushed per kernel tag-window update.
/// Kept at the kernel's AIVPN_TAG_WINDOW_SLOTS so a full window is always
/// installed, and — critically — kept BELOW user-space's bounded forward tag
/// search (`RECV_FUTURE_SEARCH_SYNCED` = 512 in client_wire.rs): a downlink
/// packet that overruns the kernel window falls back to user-space with a
/// counter at most `base + 256 + in-flight` while user-space's own window base
/// lags at most 256 behind (the kernel consumed those counters), so the
/// fallback counter is always inside user-space's forward search and the
/// control plane / overflow data can never be stranded.
#[cfg(target_os = "linux")]
const KERNEL_TAG_WINDOW: usize = 256;

/// K6: re-push the kernel tag window once the user-space-observed downlink
/// counter has advanced this far past the last pushed base (mirrors the
/// server's 128-packet refresh stride at half scale, since the client's
/// counter observations are sparser — only fallback packets advance them).
#[cfg(target_os = "linux")]
const KERNEL_TAG_REFRESH_STRIDE: u64 = 64;

/// Upper bound on the SOCKS proxy downlink queue (`ProxyHandle::rx_queue`).
/// A stalled SOCKS consumer must not grow client RSS without limit: past this
/// cap the oldest queued IP packet is dropped and the inner TCP retransmit
/// recovers it. 2048 × ~1.5 KB ≈ 3 MB worst case.
const PROXY_RX_QUEUE_MAX: usize = 2048;

/// B2/D2 fix: freshness window for the `NodeEnrollment` proof this client
/// signs on behalf of the embedded pool-peer dialer. MUST match
/// `aivpn-server`'s `node_registry::NODE_ENROLL_WINDOW_MS` (both 60_000,
/// private to that module) — a mismatch would make every enrollment this
/// node sends look stale (or not-yet-valid) to a peer's
/// `NodeRegistry::authenticate`.
const NODE_ENROLLMENT_WINDOW_MS: u64 = 60_000;

/// B2/D2 fix: how often `spawn_node_enrollment_resend` re-signs and resends
/// the `NodeEnrollment` proof over an established pool-peer dialer session.
/// Well under `NODE_ENROLLMENT_WINDOW_MS`'s ~2-minute freshness bound, so a
/// peer's registry is never left without a fresh-enough proof between ticks.
const NODE_ENROLLMENT_RESEND_INTERVAL: Duration = Duration::from_secs(60);

/// Current unix time in milliseconds.
fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Path A proactive carrier-change detection for the platforms that have NO
/// native network-path monitor wired into this core: iOS (the NetworkExtension
/// never forwards `defaultPath` changes into Rust), Windows and Linux (no
/// NWPath equivalent). Android and macOS are deliberately excluded — they drive
/// their own OS callbacks (`registerNetworkCallback` / `NWPathMonitor`) and
/// adding a second trigger here would double-fire against already-tuned logic.
///
/// Returns the local source IP the kernel currently selects to reach `server`
/// — i.e. the address of the PHYSICAL interface the tunnel's underlying UDP
/// socket rides. A freshly `connect()`ed UDP socket only performs a route
/// lookup and source-address selection; NO datagram leaves the host, so this is
/// cheap and radio-silent (safe to call on a metered mobile link every few
/// seconds). Because the kernel returns the source of the DEFAULT route to the
/// server, a secondary interface that is not the default route never appears
/// here: this cannot flap on standby-SIM / hotspot / dock-ethernet churn — the
/// exact false-positive class fixed on Android (82aee70) and macOS (561daeb).
#[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
fn probe_underlying_source_ip(server: SocketAddr) -> Option<std::net::IpAddr> {
    let domain = if server.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock =
        socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)).ok()?;
    sock.connect(&server.into()).ok()?;
    sock.local_addr().ok()?.as_socket().map(|a| a.ip())
}

/// Collapse a per-session mask id to its base protocol-family preset id for
/// §2 crowdsourced feedback. See `aivpn_common::mask::base_mask_family` for
/// the shared implementation (single source of truth for the desktop client
/// and both mobile cores). Re-exported here so existing callers/tests that
/// use `aivpn_client::client::base_mask_family` keep working unchanged.
pub use aivpn_common::mask::base_mask_family;

fn packet_mdh_len_for_mask(mask: &MaskProfile) -> usize {
    mask.header_spec
        .as_ref()
        .map(|spec| spec.min_length())
        .unwrap_or_else(|| mask.header_template.len())
}

/// B2/D2 fix: build a fresh, SESSION-BOUND `ControlPayload::NodeEnrollment`
/// proof. `time_window` is recomputed from the current wall-clock time on
/// every call (using [`NODE_ENROLLMENT_WINDOW_MS`]), so both the initial send
/// and every periodic resend carry a current window. `server_eph_pub`/
/// `client_eph_pub` bind the proof to one specific masked pool-peer session's
/// ephemeral transcript — see [`ClientConfig::node_identity`]'s doc comment
/// for why that binding is what closes the cross-session-replay hole this
/// fix addresses.
fn build_node_enrollment_payload(
    node_identity: &ed25519_dalek::SigningKey,
    node_id: &str,
    node_pub: &[u8; 32],
    server_eph_pub: &[u8; 32],
    client_eph_pub: &[u8; 32],
) -> ControlPayload {
    let time_window =
        crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLLMENT_WINDOW_MS);
    let msg = crypto::node_enrollment_signing_bytes(
        node_id,
        node_pub,
        time_window,
        server_eph_pub,
        client_eph_pub,
    );
    let signature = {
        use ed25519_dalek::Signer;
        node_identity.sign(&msg).to_bytes()
    };
    ControlPayload::NodeEnrollment {
        node_id: node_id.to_string(),
        node_pub: *node_pub,
        time_window,
        signature,
    }
}

struct UploadCryptoState {
    keys: SessionKeys,
    counter: u64,
    seq: u16,
    /// Rendezvous senders for in-flight `KeyRotate` responses. The inline-rekey
    /// handler pushes a sender here before enqueueing its `KeyRotate` response
    /// onto `control_tx`, then blocks on the paired receiver until the upload
    /// task actually encrypts that specific response (see `encrypt_control`
    /// below). This guarantees the response is encrypted with the pre-ratchet
    /// keys even though it travels through a separate task via an mpsc queue —
    /// without it, the handler could overwrite `keys` (switching to the new,
    /// server-unrecognized key) before the upload task ever dequeues the
    /// response, permanently desyncing the ratchet from the server.
    rekey_ack: VecDeque<oneshot::Sender<()>>,
}

/// AIVPN Client instance
pub struct AivpnClient {
    config: ClientConfig,
    state: ClientState,
    tunnel: Tunnel,
    udp_socket: Option<Arc<UdpSocket>>,
    mimicry_engine: Option<MimicryEngine>,
    pub control_tx: Option<mpsc::Sender<ControlPayload>>,
    /// Receiver half preset by `control_handle()`, consumed by `run()` in
    /// place of the receiver it would otherwise create itself. Lets an
    /// embedder (e.g. the server running this client as a pool-peer dialer
    /// in `control_only` mode) obtain a `Sender<ControlPayload>` handle
    /// BEFORE `run(&mut self, ..)` takes `&mut self` for the duration of the
    /// session, so it can keep pushing payloads (pool DB-sync beacons/
    /// snapshots) through the masked session while `run()` is executing.
    preset_control_rx: Option<mpsc::Receiver<ControlPayload>>,
    pending_mask: Arc<Mutex<Option<aivpn_common::mask::MaskProfile>>>,
    session_keys: Option<SessionKeys>,
    upload_state: Option<Arc<Mutex<UploadCryptoState>>>,
    transition_recv_keys: Option<SessionKeys>,
    transition_recv_deadline: Option<Instant>,
    /// Hard ceiling on rekey-grace re-arms (see REKEY_TRANSITION_HARD_CAP).
    /// Armed once per inline rekey at the key switch; never extended.
    transition_grace_hard: Option<Instant>,
    /// DATA-plane liveness (see `data_watchdog_verdict`): stamped ONLY when an
    /// authenticated DATA payload is delivered to the TUN/proxy. Control
    /// traffic (keepalive-acks, KeyRotate retransmits) must not mask a dead
    /// data downlink.
    last_data_rx: Instant,
    /// `bytes_sent` (data-only uplink counter) snapshot at `last_data_rx`.
    upload_at_last_data_rx: u64,
    /// Anchors the stall clock at the FIRST uplink data observed after the
    /// last downlink data, so a long-idle tunnel isn't condemned the moment an
    /// app sends a single packet.
    data_stall_started: Option<Instant>,
    /// Consecutive watchdog ticks the stall verdict has held (see
    /// `data_stall_confirmed`); fires at DATA_STALL_STRIKES_TO_FIRE.
    data_stall_strikes: u32,
    /// The data watchdog arms only once THIS session has delivered at least
    /// one downlink DATA packet. An idle TUN still emits unanswerable junk
    /// (ICMPv6 ND, IGMP, telemetry beacons to dead hosts) that counts as
    /// uplink data with no possible response — without this gate, a perfectly
    /// healthy idle tunnel reconnected every DATA_RX_SILENCE seconds (observed
    /// live on the netns stand). A never-proven data plane stays covered by
    /// the handshake first-contact and RX-silence nets, exactly as before.
    data_plane_proven: bool,
    /// server_eph_pub the current `session_keys` were PFS-ratcheted from.
    /// The server retransmits ServerHello whenever it observes a
    /// non-ratcheted Keepalive while it still thinks the client hasn't
    /// switched (gateway.rs `handle_control_message`'s `Keepalive` arm) — a
    /// reliability measure for a lost first ServerHello. If the client HAD
    /// already ratcheted (its own confirmation packet was what got lost, not
    /// the original ServerHello) and this resend arrives within the
    /// `transition_recv_deadline`, it decodes fine via `transition_recv_keys`
    /// and reaches the ServerHello handler a second time. Re-deriving the
    /// ratchet there would use the already-ratcheted `session_keys` as PSK
    /// input instead of the original pre-ratchet key, permanently diverging
    /// from the server's (single) ratchet and breaking all resonance-tag
    /// validation from then on. Tracking the eph_pub we last ratcheted to
    /// makes the handler idempotent: a duplicate for the same eph_pub only
    /// re-sends the confirmation traffic, it never re-ratchets.
    ratcheted_server_eph_pub: Option<[u8; 32]>,
    /// Same idempotency problem as `ratcheted_server_eph_pub`, but for the
    /// server-initiated inline rekey: `ControlPayload::KeyRotate { new_eph_pub }`
    /// is reused for both the server's rekey request and the client's own
    /// response, and this handler had no guard against reprocessing a
    /// duplicate/redelivered request. Reprocessing generates a FRESH random
    /// client keypair and re-derives new_keys from the already-once-rotated
    /// current key, producing a key the server never agreed to and never
    /// commits — a permanent desync indistinguishable from the ServerHello
    /// bug, just triggered by a duplicated KeyRotate request instead of a
    /// duplicated ServerHello. Tracks which server new_eph_pub we already
    /// ratcheted for so a duplicate request is a no-op.
    ratcheted_rekey_eph_pub: Option<[u8; 32]>,
    /// The client eph pub we RESPONDED with for `ratcheted_rekey_eph_pub`.
    /// If the response is lost, the server retransmits KeyRotate (fresh
    /// transport packet, OLD keys) — the handler re-sends this SAME response
    /// (never a fresh keypair: whichever copy the server commits must yield
    /// the keys we already switched to) encrypted with the old keys the
    /// server can still read, so a lost response self-heals in-band.
    rekey_response_eph: Option<[u8; 32]>,
    keypair: KeyPair,
    counter: u64,
    send_seq: u32,
    _recv_seq: u32,
    recv_window: RecvWindow,
    transition_recv_window: RecvWindow,
    recv_mdh_len: usize,
    /// Every distinct downlink MDH length this session has used, most-recent
    /// first. The server can frame different downlink packets with different
    /// masks (per-session bootstrap for early DATA, runtime/catalog for control
    /// and rekey, a polymorphic variant later), so the receive path must try
    /// them all — assuming a single length strands the tunnel on the first
    /// rekey/mask rotation. Seeded with the bootstrap length; extended on every
    /// mask update.
    recv_mdh_candidates: Vec<usize>,
    // Traffic counters
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    /// Client's currently-effective VPN IP (the `client_ip` half of the last
    /// applied `ClientNetworkConfig`). Seeded from the static key's `i` field
    /// at construction and updated live by `apply_server_network_override` on
    /// every server-confirmed network change, including a pool re-home that
    /// assigns a different IP than the key's. Shared with the stats-writer
    /// task (below) so file-based GUIs (Windows, whose child stdout is piped
    /// to `Stdio::null()`) can observe the re-home the same way Linux's
    /// stdout `AIVPN-STATUS` line does.
    current_vpn_ip: Arc<Mutex<String>>,
    // Pre-allocated buffers for zero-copy I/O (OPTIMIZATION)
    _send_buf: Vec<u8>,
    _recv_buf: Vec<u8>,
    proxy_handle: Option<crate::proxy::ProxyHandle>,
    // Recording tracking
    active_recording_session: Option<[u8; 16]>,
    keepalive_interval: Duration,
    /// Shared keepalive interval in milliseconds with the upload task for dynamic updates.
    keepalive_interval_ms: Arc<AtomicU64>,
    /// Local UDP port used on last successful connect — reused on reconnect to
    /// preserve CGNAT inbound mapping (port-preserving carriers like MTS).
    last_local_port: Option<u16>,
    /// Static X25519 keypair — persisted across reconnects for device binding (0.9.0+).
    static_keypair: Option<KeyPair>,
    /// Connection quality tracker — RTT, jitter, loss → 0–100 score (0.9.0+).
    quality_tracker: QualityTracker,
    /// Current adaptive mode level — adjusted from quality score (0.9.0+).
    adaptive_level: AdaptiveLevel,
    /// Epoch-ms timestamp of last outbound keepalive — shared with upload task for RTT.
    keepalive_sent_ms: Arc<AtomicU64>,
    /// Epoch-ms timestamp of the last outbound packet of ANY kind (data,
    /// control, keepalive) — updated by the upload task's encryptor. Used by
    /// the RX watchdog for asymmetric silence detection and proactive CGNAT
    /// warmup (A4): "uplink active but downlink silent" means a dead path.
    last_tx_ms: Arc<AtomicU64>,
    /// §2 crowdsourced blocking feedback — persistent per-mask outcome log
    /// (base mask family, success/fail, hour-rounded timestamp). Persisted to
    /// `~/.config/aivpn/mask_feedback.json` (see `mask_feedback_log`) so failure
    /// history survives the client re-creation that every reconnect performs.
    /// Only appended to when `config.share_mask_feedback` is true.
    feedback_log: MaskFeedbackLog,
    /// Set once this connection has already reported its batched mask
    /// feedback, so reconnect-heavy sessions don't spam the server.
    mask_feedback_sent: bool,
    /// Set once this connection has already recorded its §2 success outcome.
    /// The ServerHello handler runs on every real (non-duplicate) ratchet,
    /// including legitimate mid-session re-ratchets that carry a fresh
    /// `server_eph_pub`; gating on this flag keeps the success recorded exactly
    /// once per connection rather than once per ratchet.
    mask_success_recorded: bool,
    /// §2 crowdsourced blocking feedback — most recent `RegionalMaskHints`
    /// received from the server, stored only when `config.receive_mask_hints`
    /// is true. Also persisted per-region (see `RegionalHintsStore`) so the
    /// reconnect loop can bias mask selection on the next attempt.
    regional_mask_hints: Option<Vec<(String, f32)>>,
    /// True once this connection reached the `Connected` state at least once.
    /// Shared with `main.rs`'s reconnect loop (via `ever_connected()`) so a
    /// connection attempt that never completed the handshake can be attributed
    /// as a mask FAILURE (§2 L2 failure attribution).
    ever_connected: Arc<AtomicBool>,
    /// §3 polymorphic masks — set true once a `MaskUpdate` whose `mask_id`
    /// starts with `polymorphic:` has been applied. The `MaskPreference` retry
    /// task polls this to know when to stop resending (see the ServerHello
    /// handler's retry spawn).
    polymorphic_confirmed: Arc<AtomicBool>,
    /// 3f: set true when the server sent an authenticated `HandshakeReject`
    /// (subtype 0x20) — a terminal, PSK-proven refusal (one-time key already
    /// used / client expired / client disabled). `main.rs`'s reconnect loop
    /// checks this after `run()` returns and stops retrying instead of
    /// backing off and reconnecting, since retrying against a definitive
    /// refusal would only hammer the server forever.
    terminal_rejected: bool,
    /// Reason code from the `HandshakeReject` that set `terminal_rejected`
    /// (see `handshake_reject_message` for the mapping). Meaningless while
    /// `terminal_rejected` is false.
    reject_reason: u8,
    /// Kernel-module accelerator (Linux only, auto-detected via /dev/aivpn).
    #[cfg(target_os = "linux")]
    kernel_accel: Option<Arc<KernelAccel>>,
    /// Local handle identifying this client's single in-kernel session (K6).
    /// Constant for the lifetime of the client instance so `session_add` on
    /// rekey REPLACES the kernel entry (session_add is idempotent by id)
    /// instead of leaking a stale session with the old key.
    #[cfg(target_os = "linux")]
    kernel_session_id: [u8; 16],
    /// True once the in-kernel downlink session has been installed (K6).
    #[cfg(target_os = "linux")]
    kernel_installed: bool,
    /// True once IOC_SET_UDP_SOCK hooked this connection's UDP socket. The
    /// kernel hook install is NOT idempotent (a second install on the same
    /// socket would capture the hook itself as `orig_data_ready` and recurse),
    /// so it must run exactly once per socket.
    #[cfg(target_os = "linux")]
    kernel_hooked: bool,
    /// True once IOC_SET_TUN pointed the module at this client's TUN device.
    #[cfg(target_os = "linux")]
    kernel_tun_set: bool,
    /// Downlink MDH length the kernel session was installed with; a MaskUpdate
    /// that changes the primary downlink MDH length triggers a re-install so
    /// the kernel's frozen ciphertext offset doesn't go permanently stale.
    #[cfg(target_os = "linux")]
    kernel_installed_mdh_len: usize,
    /// Base counter of the last (tag,counter) window pushed to the kernel.
    #[cfg(target_os = "linux")]
    kernel_tags_base: u64,
    /// Resonance time window the last pushed tags were generated for; a tag is
    /// only valid within its 10 s window, so a rotation forces a re-push.
    #[cfg(target_os = "linux")]
    kernel_tags_tw: u64,
    /// Interface on which the XDP early-filter was attached (Linux only).
    #[cfg(target_os = "linux")]
    xdp_iface: Option<String>,
    /// P2.1/P2.R: in-tunnel mgmt client (`MgmtRequest`/`MgmtResponse`
    /// correlation + cached server-assigned role). Hoisted into
    /// `aivpn_common::mgmt::MgmtClient` so mobile FFI cores
    /// (`aivpn-ios-core`, `aivpn-android-core`), which depend on
    /// `aivpn-common` but not on this crate, share the identical
    /// implementation instead of re-implementing it. Cheaply cloneable
    /// (internally `Arc`-wrapped) so `mgmt_call`/`cached_role` can take
    /// `&self` and still be called concurrently from multiple embedders
    /// (FFI, admin-socket bridge).
    mgmt: MgmtClient,
}

impl AivpnClient {
    /// Create new client
    pub fn new(config: ClientConfig) -> Result<Self> {
        let keypair = KeyPair::generate();
        let tunnel = Tunnel::new(config.tun_config.clone());
        let recv_mdh_len = packet_mdh_len_for_mask(&config.initial_mask);
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let bytes_received = Arc::new(AtomicU64::new(0));
        let initial_vpn_ip = config.tun_config.tun_addr.clone();

        let static_keypair = load_or_generate_static_keypair();
        let initial_adaptive_level = config.initial_adaptive_level;
        let initial_keepalive = keepalive_with_nat_cap(
            initial_adaptive_level,
            Duration::from_secs(initial_adaptive_level.keepalive_secs()),
        );

        Ok(Self {
            config,
            state: ClientState::Provisioned,
            tunnel,
            udp_socket: None,
            mimicry_engine: None,
            control_tx: None,
            preset_control_rx: None,
            pending_mask: Arc::new(Mutex::new(None)),
            session_keys: None,
            #[cfg(target_os = "linux")]
            kernel_accel: None,
            #[cfg(target_os = "linux")]
            kernel_session_id: rand::random::<[u8; 16]>(),
            #[cfg(target_os = "linux")]
            kernel_installed: false,
            #[cfg(target_os = "linux")]
            kernel_hooked: false,
            #[cfg(target_os = "linux")]
            kernel_tun_set: false,
            #[cfg(target_os = "linux")]
            kernel_installed_mdh_len: 0,
            #[cfg(target_os = "linux")]
            kernel_tags_base: 0,
            #[cfg(target_os = "linux")]
            kernel_tags_tw: 0,
            #[cfg(target_os = "linux")]
            xdp_iface: None,
            upload_state: None,
            transition_recv_keys: None,
            transition_recv_deadline: None,
            transition_grace_hard: None,
            last_data_rx: Instant::now(),
            upload_at_last_data_rx: 0,
            data_stall_started: None,
            data_stall_strikes: 0,
            data_plane_proven: false,
            ratcheted_server_eph_pub: None,
            ratcheted_rekey_eph_pub: None,
            rekey_response_eph: None,
            keypair,
            counter: 0,
            send_seq: 0,
            _recv_seq: 0,
            recv_window: RecvWindow::new(),
            transition_recv_window: RecvWindow::new(),
            recv_mdh_len,
            recv_mdh_candidates: vec![recv_mdh_len],
            bytes_sent: bytes_sent.clone(),
            bytes_received: bytes_received.clone(),
            current_vpn_ip: Arc::new(Mutex::new(initial_vpn_ip)),
            // Pre-allocate buffers to MAX_PACKET_SIZE to avoid reallocations
            _send_buf: Vec::with_capacity(MAX_PACKET_SIZE),
            _recv_buf: Vec::with_capacity(MAX_PACKET_SIZE),
            proxy_handle: None,
            active_recording_session: None,
            keepalive_interval: initial_keepalive,
            keepalive_interval_ms: Arc::new(AtomicU64::new(initial_keepalive.as_millis() as u64)),
            last_local_port: None,
            static_keypair,
            quality_tracker: QualityTracker::new(),
            adaptive_level: initial_adaptive_level,
            keepalive_sent_ms: Arc::new(AtomicU64::new(0)),
            last_tx_ms: Arc::new(AtomicU64::new(0)),
            feedback_log: MaskFeedbackLog::load_default(),
            mask_feedback_sent: false,
            mask_success_recorded: false,
            regional_mask_hints: None,
            ever_connected: Arc::new(AtomicBool::new(false)),
            polymorphic_confirmed: Arc::new(AtomicBool::new(false)),
            terminal_rejected: false,
            reject_reason: 0,
            mgmt: MgmtClient::new(),
        })
    }

    /// Set the keepalive interval, applying the NAT-safe cap (A4) for every
    /// adaptive level except Satellite, and propagate it to the running
    /// upload task via the shared `keepalive_interval_ms` atomic.
    fn set_keepalive_interval(&mut self, requested: Duration) {
        let effective = keepalive_with_nat_cap(self.adaptive_level, requested);
        if effective < requested {
            debug!(
                "Keepalive {}s capped to {}s (NAT-safe bound, level {:?})",
                requested.as_secs(),
                effective.as_secs(),
                self.adaptive_level
            );
        }
        self.keepalive_interval = effective;
        self.keepalive_interval_ms
            .store(effective.as_millis() as u64, Ordering::Relaxed);
    }

    /// Fire-and-forget CGNAT warmup burst: 4 keepalives 100 ms apart, sent via
    /// the control channel so they go through the normal encrypted path.
    /// Spawned (not awaited) so the ~400 ms sequence never stalls the caller.
    fn spawn_warmup_burst(tx: mpsc::Sender<ControlPayload>) {
        tokio::spawn(async move {
            for _ in 0..4u8 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                // Stamp the real send time: the server acks EVERY keepalive,
                // and an ack with echo_ts=0 makes the RTT handler fall back to
                // the last periodic keepalive's timestamp — each warmup ack
                // then measured as 100..400 ms of fake RTT, poisoning the
                // quality EWMA (and the server's adaptive hint) right at
                // session start.
                let _ = tx
                    .send(ControlPayload::Keepalive {
                        send_ts: epoch_ms(),
                    })
                    .await;
            }
        });
    }

    /// B2/D2 fix: periodic `NodeEnrollment` resend for the embedded
    /// `control_only` pool-peer dialer (see `ClientConfig::node_identity`'s
    /// doc comment). Spawned once per real ratchet from the `ServerHello`
    /// handler, after the initial send. Rebuilds the proof with a fresh
    /// `time_window` on every tick but the SAME `server_eph_pub`/
    /// `client_eph_pub` — both fixed for the life of this session — so a
    /// peer whose `NodeRegistry` restarted (or that missed our initial
    /// enrollment) re-learns/re-verifies us without waiting for a fresh
    /// dial. Exits as soon as `tx.send` fails (the session ended — the
    /// caller's `AivpnClient`/task is gone, no separate shutdown signal
    /// needed).
    fn spawn_node_enrollment_resend(
        tx: mpsc::Sender<ControlPayload>,
        node_identity: ed25519_dalek::SigningKey,
        node_id: String,
        node_pub: [u8; 32],
        server_eph_pub: [u8; 32],
        client_eph_pub: [u8; 32],
    ) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(NODE_ENROLLMENT_RESEND_INTERVAL);
            // The first tick fires immediately; skip it here since the
            // caller already sent one right before spawning this task.
            interval.tick().await;
            loop {
                interval.tick().await;
                let enrollment = build_node_enrollment_payload(
                    &node_identity,
                    &node_id,
                    &node_pub,
                    &server_eph_pub,
                    &client_eph_pub,
                );
                if tx.send(enrollment).await.is_err() {
                    // Session gone — nothing left to resend to.
                    break;
                }
            }
        });
    }

    /// Connect to server
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to AIVPN server...");
        self.state = ClientState::Connecting;

        // Create TUN device first (skipped in proxy mode and in headless
        // control-only mode, where there is no OS network stack to route).
        if self.config.proxy_listen.is_none() && !self.config.control_only {
            self.tunnel.create().await?;
        }

        // Resolve the server address with a hard 10 s timeout so a hung DNS
        // server cannot stall the reconnect loop indefinitely.
        let server_addr = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host(&self.config.server_addr),
        )
        .await
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("DNS lookup timed out for {}", self.config.server_addr),
            ))
        })?
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "failed to resolve server address: {}",
                    self.config.server_addr
                ),
            ))
        })?;

        // Create UDP socket with 4MB OS buffers (OPTIMIZATION)
        let domain = if server_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket2_sock =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
                .map_err(Error::Io)?;

        socket2_sock.set_nonblocking(true).map_err(Error::Io)?;
        let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);

        // Try to reuse the previous local port so port-preserving CGNAT carriers
        // (MTS, Beeline) don't need to update their inbound routing table on
        // reconnect — the old mapping already points to the right port.
        let hint_port = self.last_local_port.unwrap_or(0);
        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                hint_port,
            )
        } else {
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                hint_port,
            )
        };
        if socket2_sock.bind(&bind_addr.into()).is_err() && hint_port != 0 {
            // Saved port unavailable — fall back to OS-assigned ephemeral.
            let fallback: SocketAddr = if server_addr.is_ipv4() {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            };
            socket2_sock.bind(&fallback.into()).map_err(Error::Io)?;
        }

        // Connect UDP socket
        socket2_sock
            .connect(&server_addr.into())
            .map_err(Error::Io)?;

        // Persist the local port for the next reconnect.
        self.last_local_port = socket2_sock
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .map(|a| a.port());

        let std_sock: std::net::UdpSocket = socket2_sock.into();
        let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;

        self.udp_socket = Some(Arc::new(socket));

        // Auto-detect kernel acceleration (Linux only).
        #[cfg(target_os = "linux")]
        {
            // K6: client-side in-kernel DOWNLINK session. The aivpn.ko RX data
            // path (udp_hook → tag lookup → anti-replay → decrypt → TUN inject)
            // is direction-agnostic: it decrypts whatever key/tags a session
            // was installed with. The server uses it for uplink (c2s); the
            // client reuses it unchanged for downlink by installing a session
            // whose decrypt key is the S2C key and whose tag window is the
            // client's expected downlink tags (see `kernel_install_session`).
            //
            // Strictly gated on FULL-TUNNEL mode: the kernel path injects
            // decrypted packets into a TUN device, so in SOCKS/proxy mode
            // (`--proxy-listen`, no TUN exists) it is impossible and the
            // user-space path is used as before. The session (+ UDP hook) is
            // only armed AFTER the PFS ratchet completes (ServerHello handler)
            // — hooking the socket with no installed session would send every
            // packet through the softirq fallback path for zero benefit, the
            // exact regression removed in 13984c5.
            //
            // OPT-IN and OFF by default (AIVPN_CLIENT_KERNEL_RX=1 to enable).
            // Client-side kernel downlink RX offloads only in full-tunnel mode,
            // but a tag-window miss drops the packet into the softirq fallback
            // queue, and on the server the equivalent fallback-regime tag churn
            // was observed to starve the downlink and stall the tunnel (the
            // 13984c5 bug family). Client acceleration also has little upside —
            // the client is not CPU-bound like a multi-client server — so it
            // ships disabled and is enabled explicitly for testing/opt-in only.
            self.kernel_installed = false;
            self.kernel_hooked = false;
            self.kernel_tun_set = false;
            let kernel_rx_enabled = std::env::var("AIVPN_CLIENT_KERNEL_RX")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if self.config.proxy_listen.is_some() || self.config.control_only || !kernel_rx_enabled
            {
                // Proxy mode (no TUN to inject into) or not opted in: user-space
                // data path exactly as before.
                self.kernel_accel = None;
            } else {
                self.kernel_accel = KernelAccel::try_open().map(Arc::new);
                if self.kernel_accel.is_some() {
                    info!(
                        "Kernel acceleration: aivpn.ko detected (AIVPN_CLIENT_KERNEL_RX=1) \
                         — downlink decrypt will be offloaded after the PFS ratchet"
                    );
                } else {
                    info!(
                        "Kernel acceleration: requested but aivpn.ko not available \
                         — using built-in user-space data path"
                    );
                }
            }

            // Deliberately do NOT attach the XDP early-filter on the client.
            // It exists to shed inbound DDoS on a server; a single-flow client
            // gains nothing from it, and its 10 s local-clock acceptance window
            // would blackhole ALL inbound (before the socket, with no user-space
            // fallback) on a client with >10 s clock skew — a dead tunnel the
            // RX-silence watchdog can only reconnect back into. Server-only.
            debug_assert!(self.xdp_iface.is_none());
        }

        if self.config.proxy_listen.is_none() && !self.config.control_only {
            self.tunnel.set_server_ip(server_addr.ip().to_string());
            // Enable full tunnel only after the server UDP path is established.
            if self.config.tun_config.full_tunnel {
                self.tunnel.enable_full_tunnel()?;
            }
            if !self.config.tun_config.include_routes.is_empty()
                || !self.config.tun_config.exclude_routes.is_empty()
            {
                self.tunnel.apply_split_routes()?;
            }
            if self.config.tun_config.kill_switch {
                self.tunnel.activate_kill_switch()?;
            }
        }

        // Initialize mimicry engine
        self.mimicry_engine = Some(MimicryEngine::new(self.config.initial_mask.clone()));

        // Derive session keys (Zero-RTT)
        let dh_result = self
            .keypair
            .compute_shared(&self.config.server_public_key)?;
        debug!("DH complete");
        debug!(
            "PSK: {}",
            if self.config.preshared_key.is_some() {
                "present"
            } else {
                "absent"
            }
        );
        self.session_keys = Some(crypto::derive_session_keys(
            &dh_result,
            self.config.preshared_key.as_ref(),
            &self.keypair.public_key_bytes(),
        ));
        // Fresh zero-RTT keys mean any prior PFS ratchet no longer applies —
        // the next ServerHello (for this new connection) must be allowed to
        // ratchet again.
        self.ratcheted_server_eph_pub = None;
        self.ratcheted_rekey_eph_pub = None;
        self.rekey_response_eph = None;
        if self.session_keys.is_none() {
            return Err(Error::Session("session_keys not set after derive".into()));
        }
        // Do NOT log tag_secret (or any session key material): RUST_LOG=debug is a
        // supported runtime mode, and the resonance-tag secret is what keeps a
        // session unlinkable to a passive observer. Leaking it to a log file /
        // support bundle defeats that. Keep only a non-sensitive breadcrumb.
        debug!("Session keys derived");

        self.state = ClientState::Connected;
        // NOTE: `ever_connected` is deliberately NOT set here. This is the
        // optimistic zero-RTT transition — no server packet has been received
        // yet (UDP connect() does not round-trip), so a DPI-blocked server that
        // never answers would still reach this point. `ever_connected` is set in
        // the ServerHello handler, which is real proof of server contact, so §2
        // failure attribution correctly records blocked masks.
        info!("Connected to server at {}", self.config.server_addr);
        info!("TUN device: {}", self.tunnel.name());

        Ok(())
    }

    /// §2 L2 failure attribution — whether this connection ever reached the
    /// `Connected` state. Consulted by `main.rs`'s reconnect loop after
    /// `run()` returns: an attempt that never connected is attributed as a
    /// FAILURE outcome for the mask it tried to use.
    pub fn ever_connected(&self) -> bool {
        self.ever_connected.load(Ordering::Relaxed)
    }

    /// 3f: true when the server sent an authenticated `HandshakeReject`
    /// during this run. `main.rs`'s reconnect loop checks this after
    /// `run()` returns and, when true, stops the reconnect loop instead of
    /// backing off and retrying — see `handshake_reject_message` for the
    /// human-readable reason (via `reject_reason()`).
    pub fn terminal_rejected(&self) -> bool {
        self.terminal_rejected
    }

    /// Reason code the server sent with the terminal `HandshakeReject` (only
    /// meaningful when `terminal_rejected()` is true). See
    /// `handshake_reject_message` for the mapping.
    pub fn reject_reason(&self) -> u8 {
        self.reject_reason
    }

    /// Latest observed round-trip time in milliseconds (0 if never measured).
    /// Consulted by `main.rs`'s reconnect loop to feed `ServerPool::update_rtt`
    /// for `PoolMode::LatencyBased` selection.
    pub fn last_rtt_ms(&self) -> u16 {
        self.quality_tracker.rtt_ms()
    }

    async fn apply_server_network_override(
        &mut self,
        network_config: ClientNetworkConfig,
    ) -> Result<()> {
        let current_config = self.config.tun_config.client_network_config()?;
        if current_config == network_config {
            return Ok(());
        }

        info!(
            "Applying server-confirmed network override: client {} gateway {} /{} mtu {}",
            network_config.client_ip,
            network_config.server_vpn_ip,
            network_config.prefix_len,
            network_config.mtu,
        );

        let tun_name = self.config.tun_config.tun_name.clone();
        let full_tunnel = self.config.tun_config.full_tunnel;
        if self.config.proxy_listen.is_none() {
            self.tunnel
                .apply_network_config(network_config.clone())
                .await?;
        }
        // Ipv4Addr is Copy — capture before `network_config` moves into
        // `from_network_config` below.
        let new_client_ip = network_config.client_ip;
        self.config.tun_config =
            TunnelConfig::from_network_config(tun_name, network_config, full_tunnel);

        // HIGH #2 (client parity): this override just applied a genuinely
        // different network config — either the first server confirmation of
        // this session, or a pool re-home to a different server-assigned VPN
        // IP than the one derived from the static key. Publish the new IP on
        // both channels the GUIs consume: the shared value read by the
        // stats-writer task's traffic.stats `ip:` field (Windows pipes the
        // child's stdout to Stdio::null(), so it can only observe this via
        // the stats file), and the "AIVPN-STATUS connected <ip>" stdout line
        // the Linux GUI already parses (previously never emitted — it only
        // had an unreachable doc comment describing this exact protocol).
        *self
            .current_vpn_ip
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = new_client_ip.to_string();
        println!("AIVPN-STATUS connected {}", new_client_ip);

        Ok(())
    }

    /// Disconnect from server
    pub async fn disconnect(&mut self) {
        info!("Disconnecting...");

        // Send shutdown message if connected
        if self.state == ClientState::Connected {
            if self.session_keys.is_some() {
                let shutdown = ControlPayload::Shutdown { reason: 0 };
                let _ = self.send_control(&shutdown).await;
            }
        }

        self.state = ClientState::Disconnected;

        // K6: tear down the in-kernel downlink session BEFORE dropping the UDP
        // socket. Removing the session (and, via the KernelAccel handle drop,
        // flushing the table) leaves the hook — which dies with the socket —
        // passing everything to user-space in the meantime.
        #[cfg(target_os = "linux")]
        {
            if let Some(ka) = self.kernel_accel.take() {
                if self.kernel_installed {
                    let _ = ka.session_remove(&self.kernel_session_id);
                }
                // KernelAccel::drop → IOC_FLUSH.
            }
            self.kernel_installed = false;
            self.kernel_hooked = false;
            self.kernel_tun_set = false;
        }

        self.udp_socket = None;

        // Detach XDP filter (Linux only, best-effort)
        #[cfg(target_os = "linux")]
        if let Some(ref iface) = self.xdp_iface.take() {
            xdp_detach(iface);
        }

        // Zeroize keys
        self.session_keys = None;
        self.upload_state = None;
        self.transition_recv_keys = None;
        self.transition_recv_deadline = None;
        self.transition_grace_hard = None;
    }

    /// Obtain an outbound control-channel handle, usable to push
    /// `ControlPayload`s (e.g. `PoolStateDigest`, `PoolSync`) through this
    /// client's masked session while `run(&mut self, ..)` is executing.
    ///
    /// MUST be called BEFORE `run()`: once `run()` starts it holds `&mut
    /// self` for the life of the session, so an embedder (the aivpn server,
    /// running this client as a pool-peer dialer in `control_only` mode)
    /// cannot otherwise reach `control_tx` concurrently. Calling this first
    /// presets the receiver `run()` will pick up, and shares the same sender
    /// clone the client's own internal `send_control` uses — so embedder
    /// sends and the client's own control traffic are interleaved onto one
    /// upload task via one channel.
    ///
    /// Calling this more than once returns clones of the same sender; it
    /// does not create additional channels.
    pub fn control_handle(&mut self) -> mpsc::Sender<ControlPayload> {
        if self.preset_control_rx.is_none() {
            // BUG C2 mitigation: this channel also carries the masked exit's
            // per-packet data plane (the server multiplexes every forwarded
            // client IP packet onto it as `ControlPayload::ChainForward` via
            // `pool_dialer.rs`'s `send_to_peer` -> `try_send`), not just the
            // low-rate pool-sync control beacons a plain client sends. A
            // capacity of 32 overflows under load and `try_send` silently
            // drops data packets. 1024 is a cheap, low-risk bump to absorb
            // bursts; an operator-chosen mimicry-vs-throughput tradeoff. The
            // fuller fix would be a dedicated data channel separate from
            // control traffic.
            let (tx, rx) = mpsc::channel::<ControlPayload>(1024);
            self.preset_control_rx = Some(rx);
            self.control_tx = Some(tx.clone());
            tx
        } else {
            self.control_tx
                .clone()
                .expect("control_tx set alongside preset_control_rx")
        }
    }

    /// Send initial handshake packet with eph_pub to establish server-side session
    async fn send_init(&mut self) -> Result<()> {
        let keys = self
            .session_keys
            .as_ref()
            .ok_or(Error::Session("No session keys".into()))?;

        let mimicry = self
            .mimicry_engine
            .as_mut()
            .ok_or(Error::Session("No mimicry engine".into()))?;

        // Build keepalive control as init payload
        let keepalive = ControlPayload::Keepalive { send_ts: 0 };
        let encoded = keepalive.encode()?;
        let seq_num = self.send_seq as u16;
        self.send_seq = self.send_seq.wrapping_add(1);
        let inner_payload = build_inner_packet(InnerType::Control, seq_num, &encoded);

        // Include eph_pub (obfuscated) in the init packet
        let obf = obfuscate_client_eph_pub(&self.keypair, &self.config.server_public_key);
        debug!("eph_pub obfuscated for init packet");

        let aivpn_packet =
            mimicry.build_packet(&inner_payload, keys, &mut self.counter, Some(&obf))?;

        let socket = self.udp_socket.as_ref().ok_or(Error::Session(
            "UDP socket not initialized before send_init".into(),
        ))?;
        socket.send(&aivpn_packet).await?;

        info!("Sent init handshake ({} bytes)", aivpn_packet.len());
        Ok(())
    }

    async fn send_control(&mut self, payload: &ControlPayload) -> Result<()> {
        if let Some(tx) = &self.control_tx {
            tx.send(payload.clone())
                .await
                .map_err(|e| Error::Channel(e.to_string()))?;
            Ok(())
        } else {
            Err(Error::Session("control_tx not initialized".into()))
        }
    }

    /// Current server-assigned role (0=User, 1=Viewer, 2=Admin), cached from
    /// the last `Capabilities` control message. Defaults to 0 (User) until
    /// one arrives (i.e. before the post-ratchet `Capabilities` push, or for
    /// a server build that predates it). Delegates to the shared
    /// `aivpn_common::mgmt::MgmtClient` (P2.R).
    pub fn cached_role(&self) -> u8 {
        self.mgmt.cached_role()
    }

    /// P2.1/P2.R: issue an in-tunnel management API call and await the
    /// correlated `MgmtResponse`. `method`: 0=GET, 1=POST, 2=PATCH, 3=DELETE,
    /// 4=PUT (see `ControlPayload::MgmtRequest`). `path` is a curated
    /// REST-shaped path (e.g. "/api/v1/clients"); `body` is an optional JSON
    /// payload.
    ///
    /// Takes `&self` (not `&mut self`) so it can be called concurrently and
    /// from an embedder holding only a shared reference (FFI, admin-socket
    /// bridge) while `run()` holds the exclusive `&mut self` borrow for the
    /// session loop — this is exactly why the outbound sender
    /// (`control_tx`, a plain cloneable `mpsc::Sender`) and the correlation
    /// state (`self.mgmt`, an `aivpn_common::mgmt::MgmtClient`) are
    /// `Arc`-wrapped / cheaply cloneable rather than requiring exclusive
    /// access. Works on a normal (non-`control_only`) session: it uses the
    /// same `control_tx` that `run()`'s upload task drains for every other
    /// outbound control payload (keepalives, MaskFeedback, ...), so
    /// `MgmtRequest` rides the identical encrypted path.
    ///
    /// Resolves to `(status, body)` on a timely response. Returns an error
    /// if the outbound control channel isn't initialized yet, the channel is
    /// closed, or no response arrives within 10s — on timeout the pending
    /// entry is removed so a very late/duplicate response is dropped by
    /// `MgmtClient::on_mgmt_response` instead of being misdelivered.
    pub async fn mgmt_call(&self, method: u8, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        let Some(tx) = self.control_tx.as_ref() else {
            return Err(Error::Session("control_tx not initialized".into()));
        };
        self.mgmt
            .mgmt_call(tx, method, path, body, Duration::from_secs(10))
            .await
    }

    /// Update mask profile
    pub fn update_mask(&mut self, new_mask: MaskProfile) {
        let new_mdh_len = packet_mdh_len_for_mask(&new_mask);
        self.recv_mdh_len = new_mdh_len;
        // Keep the new length as the primary (front) candidate but retain every
        // prior length: the server may still send in-flight or control/rekey
        // packets framed with an earlier mask, and we must keep decoding them.
        self.recv_mdh_candidates.retain(|&l| l != new_mdh_len);
        self.recv_mdh_candidates.insert(0, new_mdh_len);
        info!(
            "Updating mask to {} (mdh_len: {})",
            new_mask.mask_id, new_mdh_len
        );
        // K6: the kernel session's ciphertext offset is frozen at install time;
        // if the primary downlink MDH length changed, re-install so kernel
        // offload keeps hitting (stale offset is safe — -EBADMSG falls back to
        // user-space — but accelerates nothing).
        #[cfg(target_os = "linux")]
        if self.kernel_installed && self.kernel_installed_mdh_len != new_mdh_len {
            self.kernel_install_session();
        }
        if let Some(ref mut engine) = self.mimicry_engine {
            engine.update_mask(new_mask.clone());
        }
        let mut pending = self.pending_mask.lock().unwrap_or_else(|e| e.into_inner());
        *pending = Some(new_mask);
    }

    /// §2 crowdsourced blocking feedback — record a mask outcome into the
    /// persistent log. Timestamp is rounded to the hour, never finer-grained,
    /// per the privacy design (the module enforces this). No-op unless
    /// `config.share_mask_feedback` is enabled — the log is never appended to
    /// (and therefore never sent) otherwise.
    ///
    /// Successes are recorded here once a session is confirmed connected (see
    /// the ServerHello handler). Failures are recorded by `main.rs`'s reconnect
    /// loop (an attempt that never reached `Connected`) directly into the same
    /// persisted log, so a later successful connection reports both.
    fn record_mask_outcome(&mut self, mask_id: String, success: bool) {
        if !self.config.share_mask_feedback {
            return;
        }
        self.feedback_log.append(mask_id, success);
    }

    /// The mask family to attribute this connection's §2 feedback outcome to.
    ///
    /// FIX A: in polymorphic mode (`--polymorphic-base`) the session actually
    /// runs a server-pushed per-session variant of the configured base, while
    /// `initial_mask` is deliberately the bootstrap-fallback family (so the
    /// opening burst isn't a fingerprintable named preset). Attributing feedback
    /// to that fallback family would silently blame the wrong family for every
    /// §3 session. So report the base being exercised when polymorphic mode is
    /// on; otherwise fall back to the bootstrap/initial mask family. Mirrors the
    /// failure-attribution path in `main.rs`.
    fn active_feedback_family(&self) -> String {
        match &self.config.polymorphic_base {
            Some(base) => base_mask_family(base),
            None => base_mask_family(&self.config.initial_mask.mask_id),
        }
    }

    /// §2 crowdsourced blocking feedback — emit a `MaskFeedback` message.
    ///
    /// Emits when EITHER:
    /// - `share_mask_feedback` is on and the persisted log has unreported
    ///   outcomes (in which case the aggregated success/fail entries are
    ///   included), OR
    /// - `receive_mask_hints` is on (in which case the entries are EMPTY — the
    ///   message carries only the country code so the server can reply with
    ///   `RegionalMaskHints` without the client sharing any outcome data). This
    ///   is the independent opt-in path (§2 M1): a receive-only user still gets
    ///   hints.
    ///
    /// A `country_code` is required in both cases (the server aggregates per
    /// region). Sent at most once per connection (`mask_feedback_sent`) and no
    /// more often than the server-pushed `report_interval_secs` across
    /// reconnects. On a share send, the reported entries are marked reported and
    /// pruned from the persisted log.
    ///
    /// Returns the `JoinHandle` of the detached jittered-send task when a send
    /// was scheduled (production callers ignore it; tests await it to assert the
    /// success-gated clear). `None` when nothing was scheduled.
    async fn maybe_send_mask_feedback(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        if self.mask_feedback_sent {
            return None;
        }
        let country_code = self.config.country_code?;

        let want_share = self.config.share_mask_feedback && self.feedback_log.has_unreported();
        let want_hints = self.config.receive_mask_hints;
        if !want_share && !want_hints {
            return None;
        }

        // Honor the server-pushed minimum spacing between sends (persisted
        // across reconnects). A hints-only probe is cheap, but we still respect
        // the interval so a reconnect storm cannot spam the server.
        let now_unix = current_unix_secs();
        if !self.feedback_log.interval_elapsed(now_unix) {
            debug!("MaskFeedback suppressed — report interval not yet elapsed");
            return None;
        }

        // Need a live control channel to send on at all — bail out (without
        // touching any state) exactly like the old inline `send_control`
        // path did when `control_tx` was unset, so a later call can still
        // retry once the channel exists.
        let Some(tx) = self.control_tx.clone() else {
            warn!("MaskFeedback send failed: control_tx not initialized");
            return None;
        };

        // Snapshot the outcome entries to report BEFORE the jitter delay so the
        // reported set is fixed at decision time. Include entries ONLY when
        // sharing is enabled (a hints-only probe sends an empty entry list).
        let entries: Vec<MaskOutcome> = if want_share {
            self.feedback_log.aggregate_unreported()
        } else {
            Vec::new()
        };

        // Gate re-entry now so the "sent at most once per connection" guarantee
        // (`mask_feedback_sent`) holds even though the actual send is deferred
        // below.
        //
        // CRITICAL (data-loss fix): do NOT drain / mark-reported the persisted
        // log here. The send is jittered (0-3000 ms) and detached, and the
        // connection can drop in that window before the message ever reaches the
        // wire. Clearing the buffer up front would silently discard outcomes
        // that were never reported. Instead, the destructive `mark_reported`
        // (clear + advance `last_report_unix` + persist) runs INSIDE the spawned
        // task and ONLY after the send succeeds; a failed send leaves the
        // on-disk buffer intact so the next successful connection retries it.
        //
        // The task operates on a CLONE of the log (which retains its persistence
        // `path`), so a successful send clears the authoritative on-disk state.
        // `self.feedback_log` stays in memory as-is, but it is never consulted
        // for sending again this connection (`mask_feedback_sent` is now set) and
        // the next reconnect reloads the authoritative state from disk.
        self.mask_feedback_sent = true;
        let mut feedback_log = self.feedback_log.clone();

        // Privacy jitter: this message otherwise goes out at a fully
        // deterministic offset after the PFS ratchet completes, which would
        // be a usable timing fingerprint for the MaskFeedback control
        // message even though its *contents* are already hidden inside the
        // encrypted mimicry channel. Add a small random pre-send delay
        // (0-3000 ms) so the send time itself isn't a fixed, observable
        // offset. Spawned so it never blocks the packet-receive loop; the
        // control channel `Sender` is cheap to clone and 'static, so the
        // delayed send can run fully detached from `self`. If `run()` returns in
        // the meantime it aborts the upload task, dropping the control receiver,
        // so the send below fails fast and the buffer is preserved.
        Some(tokio::spawn(async move {
            let jitter_ms = rand::random::<u16>() % 3001;
            tokio::time::sleep(Duration::from_millis(jitter_ms as u64)).await;
            match tx
                .send(ControlPayload::MaskFeedback {
                    entries,
                    country_code,
                })
                .await
            {
                Ok(()) => {
                    // Send confirmed queued to the upload task — now (and only
                    // now) commit the destructive clear + interval advance and
                    // persist it, so a drop before this point can't lose data.
                    feedback_log.mark_reported(now_unix);
                }
                Err(e) => {
                    // Receiver gone (run() returned / control channel closed) —
                    // leave the persisted buffer untouched for the next attempt.
                    warn!("MaskFeedback delayed send failed: {}", e);
                }
            }
        }))
    }

    /// §2 crowdsourced blocking feedback — most recent region hints received
    /// from the server (only populated when `receive_mask_hints` is on).
    /// TODO(v1): mask selection does not yet consult this; it is stored here
    /// as the integration point for a future selection-preference pass.
    pub fn regional_mask_hints(&self) -> Option<&[(String, f32)]> {
        self.regional_mask_hints.as_deref()
    }

    /// Get current state
    pub fn state(&self) -> ClientState {
        self.state.clone()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected
    }

    /// Get traffic statistics
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    fn write_quality_file(score: u8, rtt_ms: u16, jitter_ms: u16, adaptive_level: u8) {
        let content = format!(
            r#"{{"quality":{},"rtt_ms":{},"jitter_ms":{},"adaptive":{}}}"#,
            score, rtt_ms, jitter_ms, adaptive_level
        );
        // O_NOFOLLOW/create_new-hardened atomic write (secure_write.rs): this
        // falls back to a predictable world-writable /tmp path, which a
        // local attacker could pre-plant as a symlink to a file this
        // (possibly root-run) process can write.
        #[cfg(windows)]
        {
            let path = std::env::temp_dir().join("aivpn-quality.json");
            if !crate::secure_write::write_status_best_effort(&path, content.as_bytes()) {
                debug!("quality file write failed");
            }
        }
        #[cfg(not(windows))]
        {
            let primary = std::path::PathBuf::from("/var/run/aivpn/quality.json");
            let fallback = std::path::PathBuf::from("/tmp/aivpn-quality.json");
            let dir_ok = primary
                .parent()
                .map(std::fs::create_dir_all)
                .map(|r| r.is_ok())
                .unwrap_or(false);
            let wrote = dir_ok
                && crate::secure_write::write_status_best_effort(&primary, content.as_bytes());
            if !wrote
                && !crate::secure_write::write_status_best_effort(&fallback, content.as_bytes())
            {
                debug!("quality file write failed");
            }
        }
    }

    /// Deactivate the kill-switch on intentional exit. Do NOT call during reconnects.
    pub fn deactivate_kill_switch(&mut self) {
        self.tunnel.deactivate_kill_switch();
    }
}

impl Drop for AivpnClient {
    fn drop(&mut self) {
        // Zeroize sensitive data
        self.session_keys = None;
    }
}

/// Load static X25519 keypair from `~/.config/aivpn/device.key` or generate and save a new one.
/// Returns None when HOME is unset or on unrecoverable I/O errors — device binding is optional.
fn load_or_generate_static_keypair() -> Option<KeyPair> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let home = dirs_home()?; // skip persistence when HOME is unset
    let dir = home.join(".config").join("aivpn");
    let path = dir.join("device.key");

    if path.exists() {
        match fs::read(&path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Some(KeyPair::from_private_key(arr));
            }
            Ok(_) => {
                warn!("device.key has wrong size — regenerating");
            }
            Err(e) => {
                warn!("Cannot read device.key: {}", e);
                return None;
            }
        }
    }

    // Generate new keypair and persist atomically with correct permissions from the start.
    let kp = KeyPair::generate();
    let mut priv_bytes = kp.export_private_key();

    if let Err(e) = fs::create_dir_all(&dir) {
        warn!("Cannot create ~/.config/aivpn: {}", e);
        return Some(kp); // proceed without persistence
    }
    // Tighten directory to owner-only (700) so siblings are not enumerable.
    #[cfg(unix)]
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));

    // Write to a temp sibling atomically, then rename.
    let tmp_path = path.with_extension("tmp");
    let write_result = (|| -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(&priv_bytes)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        fs::write(&tmp_path, &priv_bytes)?;
        fs::rename(&tmp_path, &path)
    })();

    // Zeroize key bytes regardless of write outcome before they leave scope.
    priv_bytes.iter_mut().for_each(|b| *b = 0);

    match write_result {
        Ok(()) => info!("New device keypair generated and saved to {:?}", path),
        Err(e) => {
            warn!("Cannot write device.key: {}", e);
            let _ = fs::remove_file(&tmp_path);
        }
    }
    Some(kp)
}

fn dirs_home() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    return std::env::var_os("USERPROFILE").map(std::path::PathBuf::from);
    #[cfg(not(windows))]
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::mask::preset_masks;

    fn make_test_config() -> ClientConfig {
        let mask = preset_masks::bootstrap_default();
        ClientConfig {
            server_addr: "127.0.0.1:443".to_string(),
            server_public_key: [0u8; 32],
            server_signing_key: None,
            preshared_key: None,
            initial_mask: mask,
            tun_config: crate::tunnel::TunnelConfig::default(),
            proxy_listen: None,
            mtls_cert: None,
            initial_adaptive_level: AdaptiveLevel::Off,
            polymorphic_base: None,
            share_mask_feedback: false,
            receive_mask_hints: false,
            country_code: None,
            mask_operator_pubkey: None,
            mask_verify_mode: aivpn_common::mask::MaskVerifyMode::default(),
            network_change_notify: None,
            is_bootstrap_fallback: false,
            control_only: false,
            inbound_control_tap: None,
            node_identity: None,
            pool_node_id: None,
        }
    }

    // ── initial state ─────────────────────────────────────────────────────────

    #[test]
    fn test_new_client_initial_state_is_provisioned() {
        let config = make_test_config();
        let client = AivpnClient::new(config).expect("new() must not fail");
        assert_eq!(client.state(), ClientState::Provisioned);
    }

    #[test]
    fn test_new_client_is_not_connected() {
        let config = make_test_config();
        let client = AivpnClient::new(config).expect("new() must not fail");
        assert!(!client.is_connected());
    }

    // ── traffic counters start at zero ───────────────────────────────────────

    #[test]
    fn test_new_client_bytes_sent_starts_at_zero() {
        let config = make_test_config();
        let client = AivpnClient::new(config).expect("new() must not fail");
        assert_eq!(client.bytes_sent(), 0);
    }

    #[test]
    fn data_watchdog_verdict_data_based_liveness() {
        // The data watchdog must trip on a dead DATA downlink (uplink data
        // flowing, nothing written to the TUN) and must NEVER trip on an idle
        // tunnel whose liveness is control-only (keepalive-acks, rekey
        // retransmits). Identical semantics on desktop/iOS/Android.
        //
        // Genuinely idle: no uplink data since the last downlink data.
        assert_eq!(data_watchdog_verdict(None, 0), None);
        // Control-only liveness with zero uplink data: never trips,
        // regardless of how long ago the last downlink data was.
        assert_eq!(
            data_watchdog_verdict(Some(Duration::from_secs(3600)), 0),
            None
        );
        // Active sender, dead downlink: >20 s with ≥4 KiB unanswered.
        assert_eq!(
            data_watchdog_verdict(Some(Duration::from_secs(21)), 8192),
            Some("TX without data RX")
        );
        // Not yet: heavy uplink but under the stall timeout.
        assert_eq!(
            data_watchdog_verdict(Some(Duration::from_secs(19)), 1 << 20),
            None
        );
        // Junk trickle (ICMPv6 ND / mDNS / beacons): never enough bytes,
        // never trips — the caller washes the window at DATA_STALL_WINDOW.
        assert_eq!(
            data_watchdog_verdict(Some(Duration::from_secs(29)), 200),
            None
        );
        // Upload-only false-positive class: fire-and-forget UDP telemetry /
        // one-way media / chatty mDNS at ~18 B/s could cross the old 512 B
        // threshold inside one 30 s window while perfectly healthy. Under
        // 4 KiB it must never trip.
        assert_eq!(
            data_watchdog_verdict(Some(Duration::from_secs(29)), 540),
            None
        );
        assert_eq!(
            data_watchdog_verdict(Some(Duration::from_secs(3600)), 4095),
            None
        );
        // Real unanswered uplink volume past the timeout: trips.
        assert_eq!(
            data_watchdog_verdict(Some(Duration::from_secs(25)), 4096),
            Some("TX without data RX")
        );
    }

    #[test]
    fn data_watchdog_two_strike_confirmation() {
        // The stall verdict must persist for two consecutive watchdog ticks
        // before firing; any clean tick resets the strikes. Identical
        // semantics on desktop/iOS/Android.
        let fire = Some("TX without data RX");

        // Genuinely dead downlink: verdict holds tick after tick — fires on
        // the second consecutive strike (~25–35 s), NOT deferred to the
        // 120 s absolute net.
        let mut strikes = 0u32;
        assert_eq!(data_stall_confirmed(&mut strikes, fire), None);
        assert_eq!(data_stall_confirmed(&mut strikes, fire), fire);

        // Transient one-tick stall: downlink DATA lands before the next tick
        // (stall reset → verdict clears) — never fires, strikes reset.
        let mut strikes = 0u32;
        assert_eq!(data_stall_confirmed(&mut strikes, fire), None);
        assert_eq!(data_stall_confirmed(&mut strikes, None), None);
        assert_eq!(strikes, 0);
        // …and a later fresh stall needs two full strikes again.
        assert_eq!(data_stall_confirmed(&mut strikes, fire), None);
        assert_eq!(data_stall_confirmed(&mut strikes, fire), fire);

        // Upload-only flow below the byte threshold: verdict is never Some,
        // so no amount of ticks fires.
        let mut strikes = 0u32;
        for _ in 0..100 {
            assert_eq!(data_stall_confirmed(&mut strikes, None), None);
        }
        assert_eq!(strikes, 0);
    }

    #[test]
    fn test_new_client_bytes_received_starts_at_zero() {
        let config = make_test_config();
        let client = AivpnClient::new(config).expect("new() must not fail");
        assert_eq!(client.bytes_received(), 0);
    }

    // ── P2.1/P2.R: in-tunnel mgmt client (MgmtRequest/Response correlation) ────
    // Low-level correlation behavior (pending-map insert/remove, timeout
    // race, unknown req_id) is exercised directly against
    // `aivpn_common::mgmt::MgmtClient` in `aivpn-common/src/mgmt.rs`'s own
    // tests now that P2.R hoisted the implementation there. These tests stay
    // to prove `AivpnClient` still delegates correctly end-to-end.

    #[test]
    fn cached_role_defaults_to_user_before_any_capabilities_message() {
        let config = make_test_config();
        let client = AivpnClient::new(config).expect("new() must not fail");
        assert_eq!(client.cached_role(), 0);
    }

    #[tokio::test]
    async fn capabilities_control_message_updates_cached_role() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        assert_eq!(client.cached_role(), 0);

        client
            .handle_server_control(ControlPayload::Capabilities {
                role: 2,
                features: 0,
            })
            .await
            .expect("handle_server_control must not fail on Capabilities");

        assert_eq!(client.cached_role(), 2);
    }

    #[tokio::test]
    async fn mgmt_call_sends_request_and_resolves_on_matching_response() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);

        // Stand in for the server: receive the MgmtRequest and immediately
        // hand a MgmtResponse back through the same shared `MgmtClient`
        // (cloned — internally `Arc`-wrapped) that `handle_server_control`
        // would deliver a real inbound `MgmtResponse` through.
        let mgmt = client.mgmt.clone();
        let responder = tokio::spawn(async move {
            let sent = control_rx.recv().await.expect("MgmtRequest must be sent");
            match sent {
                ControlPayload::MgmtRequest {
                    req_id,
                    method,
                    path,
                    body,
                } => {
                    assert_eq!(method, 0);
                    assert_eq!(path, "/api/v1/clients");
                    assert!(body.is_empty());
                    mgmt.on_mgmt_response(req_id, 200, b"[]".to_vec());
                }
                other => panic!("expected MgmtRequest, got {:?}", other),
            }
        });

        let (status, body) = client
            .mgmt_call(0, "/api/v1/clients", vec![])
            .await
            .expect("mgmt_call must resolve once the response is delivered");

        responder.await.expect("responder task must not panic");
        assert_eq!(status, 200);
        assert_eq!(body, b"[]".to_vec());
    }

    #[tokio::test]
    async fn mgmt_call_times_out_when_no_response_arrives() {
        // Paused virtual time: `mgmt_call`'s internal 10s
        // `tokio::time::timeout` auto-advances past its deadline as soon as
        // the runtime is idle, instead of the test waiting 10 real seconds
        // (same pattern used by the mask-feedback jitter tests above).
        tokio::time::pause();
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);
        // Drain the outbound MgmtRequest so the bounded channel never fills,
        // but never send a MgmtResponse back.
        let _drainer = tokio::spawn(async move {
            let _ = control_rx.recv().await;
        });

        let result = client.mgmt_call(0, "/api/v1/clients", vec![]).await;

        assert!(
            result.is_err(),
            "mgmt_call must return an error when no MgmtResponse arrives within the timeout"
        );
    }

    #[tokio::test]
    async fn mgmt_call_errors_immediately_without_control_tx() {
        let config = make_test_config();
        let client = AivpnClient::new(config).expect("new() must not fail");
        // control_tx is None until control_handle()/run() sets it.
        let result = client.mgmt_call(0, "/api/v1/clients", vec![]).await;
        assert!(result.is_err());
    }

    // ── packet_mdh_len_for_mask ───────────────────────────────────────────────

    #[test]
    fn test_packet_mdh_len_falls_back_to_header_template_len() {
        let mut mask = preset_masks::bootstrap_default();
        // Force no header_spec so we exercise the fallback path.
        mask.header_spec = None;
        mask.header_template = vec![0u8; 17];
        assert_eq!(packet_mdh_len_for_mask(&mask), 17);
    }

    #[test]
    fn test_packet_mdh_len_uses_header_spec_min_length_when_present() {
        let mask = preset_masks::bootstrap_default();
        // When header_spec is Some, the result must equal spec.min_length(),
        // which is always >= 0.  We just verify the function returns a value
        // consistent with the spec rather than the raw template length.
        let len = packet_mdh_len_for_mask(&mask);
        if let Some(ref spec) = mask.header_spec {
            assert_eq!(len, spec.min_length());
        } else {
            assert_eq!(len, mask.header_template.len());
        }
    }

    // ── update_mask ───────────────────────────────────────────────────────────

    #[test]
    fn test_update_mask_changes_recv_mdh_len() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        // Build a mask with a known header_template length and no header_spec.
        let mut new_mask = preset_masks::bootstrap_default();
        new_mask.header_spec = None;
        new_mask.header_template = vec![0xAAu8; 42];

        client.update_mask(new_mask);
        assert_eq!(client.recv_mdh_len, 42);
    }

    #[test]
    fn test_update_mask_retains_prior_mdh_len_as_candidate() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        let original_len = client.recv_mdh_len;

        let mut new_mask = preset_masks::bootstrap_default();
        new_mask.header_spec = None;
        // Choose a length guaranteed to differ from the current one.
        let different_len = if original_len == 99 { 100 } else { 99 };
        new_mask.header_template = vec![0u8; different_len];

        client.update_mask(new_mask);
        // New length is primary (front); the original stays as a candidate so
        // in-flight/control packets framed with the old mask still decode.
        assert_eq!(client.recv_mdh_len, different_len);
        assert_eq!(client.recv_mdh_candidates.first(), Some(&different_len));
        assert!(client.recv_mdh_candidates.contains(&original_len));
    }

    // ── §2 crowdsourced blocking feedback ─────────────────────────────────────

    #[test]
    fn test_record_mask_outcome_noop_when_share_disabled() {
        let config = make_test_config(); // share_mask_feedback: false by default
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        client.feedback_log = MaskFeedbackLog::default(); // in-memory, no disk
        client.record_mask_outcome("webrtc_zoom_v3".to_string(), true);
        assert!(client.feedback_log.is_empty());
    }

    #[test]
    fn test_record_mask_outcome_logs_when_enabled() {
        let mut config = make_test_config();
        config.share_mask_feedback = true;
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        client.feedback_log = MaskFeedbackLog::default();
        client.record_mask_outcome("webrtc_zoom_v3".to_string(), true);
        assert_eq!(client.feedback_log.len(), 1);
        let agg = client.feedback_log.aggregate_unreported();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].mask_id, "webrtc_zoom_v3");
        assert_eq!(agg[0].success, 1);
    }

    #[tokio::test]
    async fn test_maybe_send_mask_feedback_noop_without_country_code() {
        let mut config = make_test_config();
        config.share_mask_feedback = true;
        config.country_code = None;
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        client.feedback_log = MaskFeedbackLog::default();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);

        client.record_mask_outcome("webrtc_zoom_v3".to_string(), true);
        client.maybe_send_mask_feedback().await;

        assert!(control_rx.try_recv().is_err(), "no message should be sent");
    }

    #[tokio::test]
    async fn test_maybe_send_mask_feedback_noop_when_nothing_to_do() {
        // share on but log empty, and receive_mask_hints off → nothing to send.
        let mut config = make_test_config();
        config.share_mask_feedback = true;
        config.receive_mask_hints = false;
        config.country_code = Some(*b"US");
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        client.feedback_log = MaskFeedbackLog::default();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);

        client.maybe_send_mask_feedback().await;

        assert!(control_rx.try_recv().is_err(), "no message should be sent");
    }

    #[tokio::test]
    async fn test_maybe_send_mask_feedback_independent_hints_empty_entries() {
        // §2 M1: receive_mask_hints on, share OFF, country set → send a
        // MaskFeedback with EMPTY entries so the server can reply with hints
        // WITHOUT the client sharing any outcome data.
        //
        // The send is now jittered by a random 0-3000ms delay (see
        // `maybe_send_mask_feedback` — privacy fix against fixed-offset
        // timing fingerprinting), so pause the tokio clock: with time
        // paused, `.recv().await` auto-advances past the spawned task's
        // `sleep` instead of the test needing to wait in real time.
        tokio::time::pause();
        let mut config = make_test_config();
        config.share_mask_feedback = false;
        config.receive_mask_hints = true;
        config.country_code = Some(*b"FR");
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        client.feedback_log = MaskFeedbackLog::default();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);

        client.maybe_send_mask_feedback().await;

        let sent = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("hints-probe should arrive before the timeout")
            .expect("hints-probe should be sent");
        match sent {
            ControlPayload::MaskFeedback {
                entries,
                country_code,
            } => {
                assert_eq!(&country_code, b"FR");
                assert!(entries.is_empty(), "share off → entries must be empty");
            }
            other => panic!("expected empty MaskFeedback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_maybe_send_mask_feedback_aggregates_and_sends_once() {
        // Time paused — see the comment in
        // `test_maybe_send_mask_feedback_independent_hints_empty_entries`
        // for why: the send is now jittered by 0-3000ms.
        tokio::time::pause();
        let mut config = make_test_config();
        config.share_mask_feedback = true;
        config.country_code = Some(*b"DE");
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        client.feedback_log = MaskFeedbackLog::default();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);

        client.record_mask_outcome("webrtc_zoom_v3".to_string(), true);
        client.record_mask_outcome("webrtc_zoom_v3".to_string(), true);
        client.record_mask_outcome("webrtc_zoom_v3".to_string(), false);
        client.record_mask_outcome("quic_https".to_string(), true);

        let handle = client
            .maybe_send_mask_feedback()
            .await
            .expect("a send should have been scheduled");

        let sent = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("MaskFeedback should arrive before the timeout")
            .expect("MaskFeedback should be sent");
        match sent {
            ControlPayload::MaskFeedback {
                entries,
                country_code,
            } => {
                assert_eq!(&country_code, b"DE");
                assert_eq!(entries.len(), 2);
                let zoom = entries
                    .iter()
                    .find(|e| e.mask_id == "webrtc_zoom_v3")
                    .expect("webrtc_zoom_v3 entry present");
                assert_eq!(zoom.success, 2);
                assert_eq!(zoom.fail, 1);
                let quic = entries
                    .iter()
                    .find(|e| e.mask_id == "quic_https")
                    .expect("quic_https entry present");
                assert_eq!(quic.success, 1);
                assert_eq!(quic.fail, 0);
            }
            other => panic!("expected MaskFeedback, got {:?}", other),
        }
        // FIX B: the destructive clear is now success-gated and happens inside
        // the spawned task on a persisted CLONE of the log, so it no longer
        // touches this in-memory `feedback_log`. Await the task to confirm it
        // completes cleanly; the "sent once per connection" guarantee is asserted
        // by the second-call check below.
        handle.await.expect("delayed send task should complete");
        assert!(client.mask_feedback_sent);

        // A second call must not send again (once per connection).
        client.record_mask_outcome("quic_https".to_string(), true);
        assert!(client.maybe_send_mask_feedback().await.is_none());
        assert!(control_rx.try_recv().is_err());
    }

    // ── FIX A: §2 attribution to the correct mask family ─────────────────────

    #[test]
    fn test_active_feedback_family_prefers_polymorphic_base() {
        // A polymorphic session actually runs a variant of `polymorphic_base`,
        // NOT the bootstrap-fallback `initial_mask`. Feedback must be attributed
        // to the base being tested, not the fallback family.
        //
        // Use a base guaranteed distinct from the bootstrap-fallback family so
        // "uses the base" is provable rather than coincidental (the default
        // bootstrap mask collapses to `webrtc_zoom_v3`, so a webrtc base alone
        // wouldn't distinguish the two paths).
        let mut config = make_test_config();
        config.polymorphic_base = Some("quic_masque_v2".to_string());
        let fallback_family = base_mask_family(&config.initial_mask.mask_id);
        assert_ne!(
            "quic_masque_v2", fallback_family,
            "test precondition: base must differ from the fallback family"
        );
        let client = AivpnClient::new(config).expect("new() must not fail");
        assert_eq!(client.active_feedback_family(), "quic_masque_v2");
        assert_ne!(
            client.active_feedback_family(),
            fallback_family,
            "polymorphic mode must not attribute to the bootstrap-fallback family"
        );

        // Literal case from the review: a webrtc_zoom_v3 base reports itself.
        let mut config2 = make_test_config();
        config2.polymorphic_base = Some("webrtc_zoom_v3".to_string());
        let client2 = AivpnClient::new(config2).expect("new() must not fail");
        assert_eq!(client2.active_feedback_family(), "webrtc_zoom_v3");
    }

    #[test]
    fn test_active_feedback_family_falls_back_to_initial_mask() {
        // Without polymorphic mode, attribution uses the initial mask family.
        let config = make_test_config(); // polymorphic_base: None
        let expected = base_mask_family(&config.initial_mask.mask_id);
        let client = AivpnClient::new(config).expect("new() must not fail");
        assert_eq!(client.active_feedback_family(), expected);
    }

    #[test]
    fn test_polymorphic_base_records_correct_family_once_per_connection() {
        // End-to-end of the ServerHello success path: a polymorphic client
        // records the polymorphic base family (distinct from the fallback)
        // exactly once, not once per ratchet.
        let mut config = make_test_config();
        config.share_mask_feedback = true;
        config.polymorphic_base = Some("quic_masque_v2".to_string());
        let fallback_family = base_mask_family(&config.initial_mask.mask_id);
        assert_ne!("quic_masque_v2", fallback_family, "test precondition");
        let mut client = AivpnClient::new(config).expect("new() must not fail");
        client.feedback_log = MaskFeedbackLog::default(); // in-memory, no disk

        // Mirror the guarded record in the ServerHello handler.
        if !client.mask_success_recorded {
            let fam = client.active_feedback_family();
            client.record_mask_outcome(fam, true);
            client.mask_success_recorded = true;
        }
        // A re-ratchet would re-enter the block; the guard must suppress it.
        if !client.mask_success_recorded {
            let fam = client.active_feedback_family();
            client.record_mask_outcome(fam, true);
            client.mask_success_recorded = true;
        }

        let agg = client.feedback_log.aggregate_unreported();
        assert_eq!(
            agg.len(),
            1,
            "recorded once per connection, not per ratchet"
        );
        assert_eq!(agg[0].mask_id, "quic_masque_v2");
        assert_eq!(agg[0].success, 1);
    }

    // ── FIX B: success-gated buffer clear ────────────────────────────────────

    fn feedback_temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aivpn_client_feedback_test_{}_{}.json",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[tokio::test]
    async fn test_mask_feedback_failed_send_preserves_buffer() {
        // A send that never reaches the wire (control receiver gone) must NOT
        // clear the persisted buffer, so the next successful connection retries.
        tokio::time::pause();
        let path = feedback_temp_path("failed_send");

        let mut config = make_test_config();
        config.share_mask_feedback = true;
        config.country_code = Some(*b"US");
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        let mut log = MaskFeedbackLog::load(path.clone());
        log.append("webrtc_zoom_v3".to_string(), false); // persisted to disk
        client.feedback_log = log;

        // Receiver dropped → the delayed send will fail.
        let (control_tx, control_rx) = mpsc::channel::<ControlPayload>(4);
        drop(control_rx);
        client.control_tx = Some(control_tx);

        let handle = client
            .maybe_send_mask_feedback()
            .await
            .expect("a send should have been scheduled");
        handle.await.expect("delayed send task should complete");

        // On-disk buffer is intact (failed send did NOT clear it).
        let reloaded = MaskFeedbackLog::load(path.clone());
        assert_eq!(
            reloaded.len(),
            1,
            "a failed send must leave the on-disk buffer intact"
        );
        // The in-memory buffer was likewise never cleared synchronously.
        assert!(client.feedback_log.has_unreported());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_mask_feedback_successful_send_clears_buffer() {
        // A confirmed send clears + advances the persisted buffer (success-gated).
        tokio::time::pause();
        let path = feedback_temp_path("success_send");

        let mut config = make_test_config();
        config.share_mask_feedback = true;
        config.country_code = Some(*b"US");
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        let mut log = MaskFeedbackLog::load(path.clone());
        log.append("webrtc_zoom_v3".to_string(), true);
        client.feedback_log = log;

        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);

        let handle = client
            .maybe_send_mask_feedback()
            .await
            .expect("a send should have been scheduled");

        // Receiving the message drives the task's send to Ok; then the task
        // commits the clear. Await the handle to observe the persisted result.
        let _ = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("MaskFeedback should arrive before the timeout")
            .expect("MaskFeedback should be sent");
        handle.await.expect("delayed send task should complete");

        let reloaded = MaskFeedbackLog::load(path.clone());
        assert!(
            reloaded.is_empty(),
            "a successful send must clear the on-disk buffer"
        );
        // Interval advanced → an immediate resend is throttled across reconnects.
        assert!(!reloaded.interval_elapsed(current_unix_secs()));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_regional_mask_hints_stored_when_enabled() {
        let mut config = make_test_config();
        config.receive_mask_hints = true;
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        assert!(client.regional_mask_hints().is_none());
        client
            .handle_server_control(ControlPayload::RegionalMaskHints {
                country_code: *b"JP",
                masks: vec![("webrtc_zoom_v3".to_string(), 0.9)],
            })
            .await
            .expect("handle_server_control must not fail");

        let hints = client.regional_mask_hints().expect("hints stored");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].0, "webrtc_zoom_v3");
    }

    #[tokio::test]
    async fn test_regional_mask_hints_ignored_when_disabled() {
        let config = make_test_config(); // receive_mask_hints: false by default
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        client
            .handle_server_control(ControlPayload::RegionalMaskHints {
                country_code: *b"JP",
                masks: vec![("webrtc_zoom_v3".to_string(), 0.9)],
            })
            .await
            .expect("handle_server_control must not fail");

        assert!(client.regional_mask_hints().is_none());
    }

    // ── ServerHello re-processing (PFS ratchet idempotency) ──────────────────

    /// Root-cause reproduction: the server resends ServerHello (same
    /// server_eph_pub, fresh counter) whenever it sees a non-ratcheted
    /// Keepalive while `!session.is_ratcheted` — a real reliability path in
    /// gateway.rs (`handle_control_message`'s `Keepalive` arm) meant to
    /// recover from a lost first ServerHello. But if the CLIENT already
    /// ratcheted (e.g. its own confirmation packet was the one that got lost,
    /// not the original ServerHello) and this resend arrives within the
    /// client's 2-second `transition_recv_deadline`, the client decodes it
    /// via the `transition_recv_keys` fallback and re-enters the ServerHello
    /// handler a SECOND time. That handler is not idempotent: it derives the
    /// "ratcheted" key using `self.session_keys` (now already the ratcheted
    /// key from the first pass) as the PSK, instead of the original
    /// pre-ratchet key the server used. This test proves the resulting key
    /// diverges from what a real server (which only ratchets once) holds —
    /// i.e. reprocessing ServerHello silently and permanently desyncs the
    /// session, which then manifests as every subsequent downlink packet
    /// failing resonance-tag validation.
    #[tokio::test]
    async fn test_reprocessing_server_hello_desyncs_from_server_ratchet() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        // Give the client a deterministic ephemeral keypair so we can compute
        // the exact same DH the real server would.
        let client_kp = crypto::KeyPair::generate();
        client.keypair = client_kp.clone();

        // Simulate the zero-RTT initial keys (as connect() would derive them).
        let server_static_kp = crypto::KeyPair::generate();
        let dh1 = client_kp
            .compute_shared(&server_static_kp.public_key_bytes())
            .unwrap();
        let mut initial_keys =
            crypto::derive_session_keys(&dh1, None, &client_kp.public_key_bytes());
        initial_keys.session_key_s2c = initial_keys.session_key;
        client.session_keys = Some(initial_keys.clone());
        client.transition_recv_keys = None;
        client.transition_recv_deadline = None;

        // Simulate the server's PFS ephemeral key and its ONE-TIME ratchet
        // derivation (mirrors aivpn-server session.rs create_session()).
        let server_eph_kp = crypto::KeyPair::generate();
        let dh2 = server_eph_kp
            .compute_shared(&client_kp.public_key_bytes())
            .unwrap();
        let mut server_ratcheted_keys = crypto::derive_session_keys(
            &dh2,
            Some(&initial_keys.session_key),
            &client_kp.public_key_bytes(),
        );
        server_ratcheted_keys.session_key_s2c = server_ratcheted_keys.session_key;

        let hello = ControlPayload::ServerHello {
            server_eph_pub: server_eph_kp.public_key_bytes(),
            signature: [0u8; 64], // server_signing_key is None in make_test_config()
            network_config: None,
        };
        let encoded = hello.encode().unwrap();
        let inner = build_inner_packet(InnerType::Control, 0, &encoded);

        let mdh_len = client.recv_mdh_len;
        let mut send_counter = 0u64;
        // First delivery: the server's ORIGINAL ServerHello, encrypted with
        // the pre-ratchet (initial) keys.
        let packet1 = aivpn_common::client_wire::build_random_mdh_packet(
            &initial_keys,
            &mut send_counter,
            &inner,
            None,
            mdh_len,
        )
        .unwrap();
        client
            .receive_and_write_packet(&packet1)
            .await
            .expect("first ServerHello must decode");

        // After a single, correct ratchet the client must match the server.
        assert_eq!(
            client.session_keys.as_ref().unwrap().session_key,
            server_ratcheted_keys.session_key,
            "client must match server after ONE ratchet"
        );

        // Second delivery: the server resends the SAME ServerHello (still
        // encrypted with the pre-ratchet keys, since server-side is_ratcheted
        // is false until it sees a ratcheted-tag packet from the client) —
        // this models gateway.rs's Keepalive-triggered resend path. It must
        // arrive within the client's transition_recv_deadline to be
        // decodable at all (otherwise it would just be dropped/warned).
        let packet2 = aivpn_common::client_wire::build_random_mdh_packet(
            &initial_keys,
            &mut send_counter,
            &inner,
            None,
            mdh_len,
        )
        .unwrap();
        client
            .receive_and_write_packet(&packet2)
            .await
            .expect("resent ServerHello must still decode via transition_recv_keys fallback");

        // BUG: reprocessing ServerHello re-derives "ratcheted" keys using the
        // client's CURRENT (already-ratcheted) session key as PSK, producing
        // a key the server never computed and will never hold.
        assert_eq!(
            client.session_keys.as_ref().unwrap().session_key,
            server_ratcheted_keys.session_key,
            "BUG REPRODUCED: client key diverged from the server's single-ratchet key \
             after a duplicate/resent ServerHello was reprocessed"
        );
    }

    // ── receive_and_write_packet / mask-transition fallback ─────────────────

    /// Empirical check: does the candidate-length fallback recover a packet
    /// encrypted with the OLD mdh length while the client has already switched
    /// `recv_mdh_len` to a NEW value (the exact situation during a mask
    /// transition, since the server keeps sending with the old mask for up to
    /// 500ms after MaskUpdate while the client applies the new mdh_len
    /// immediately)?
    #[tokio::test]
    async fn test_receive_packet_decodes_via_candidate_mdh_len_fallback() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        let mut keys = crypto::derive_session_keys(&[7u8; 32], None, &[0u8; 32]);
        keys.session_key_s2c = keys.session_key;
        // Simulated server-downlink packet built with the C2S encode helper and
        // decoded client-side (S2C); equalise so the wire format round-trips.
        keys.session_key_s2c = keys.session_key;
        client.session_keys = Some(keys.clone());

        let old_mdh_len = 8usize;
        let new_mdh_len = 20usize;
        client.recv_mdh_len = new_mdh_len;
        // New length is primary; the old length is retained as a candidate.
        client.recv_mdh_candidates = vec![new_mdh_len, old_mdh_len];

        // Build a Control(Keepalive) packet using the OLD mdh_len — simulating
        // a server packet still in the pre-switch mask format.
        let control = ControlPayload::Keepalive { send_ts: 0 };
        let encoded = control.encode().unwrap();
        let inner = build_inner_packet(InnerType::Control, 0, &encoded);
        let mut send_counter = 0u64;
        let packet = aivpn_common::client_wire::build_random_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            None,
            old_mdh_len,
        )
        .unwrap();

        let result = client.receive_and_write_packet(&packet).await;
        assert!(
            result.is_ok(),
            "expected success via candidate-length fallback, got {:?}",
            result
        );
    }

    /// Control: same setup but WITHOUT the old length among the candidates.
    /// After a valid tag, a Data/Control packet whose MDH length is NOT among the
    /// learned candidates is recovered by the self-healing MDH-length scan
    /// (commit 5fc601c): a bounded 0..=64 probe finds the length that
    /// authenticates, decodes the packet, and caches the discovered length so the
    /// fast path serves subsequent packets. This proves the self-heal closes the
    /// gap that a stale candidate list would otherwise open.
    #[tokio::test]
    async fn test_self_healing_recovers_unlisted_mdh_len() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        let mut keys = crypto::derive_session_keys(&[7u8; 32], None, &[0u8; 32]);
        // Simulated server-downlink packet built with the C2S encode helper and
        // decoded client-side (S2C); equalise so the wire format round-trips.
        keys.session_key_s2c = keys.session_key;
        client.session_keys = Some(keys.clone());

        let old_mdh_len = 8usize;
        let new_mdh_len = 20usize;
        client.recv_mdh_len = new_mdh_len;
        client.recv_mdh_candidates = vec![new_mdh_len]; // old length not tracked

        let control = ControlPayload::Keepalive { send_ts: 0 };
        let encoded = control.encode().unwrap();
        let inner = build_inner_packet(InnerType::Control, 0, &encoded);
        let mut send_counter = 0u64;
        let packet = aivpn_common::client_wire::build_random_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            None,
            old_mdh_len,
        )
        .unwrap();

        let result = client.receive_and_write_packet(&packet).await;
        assert!(
            result.is_ok(),
            "the self-healing MDH scan must recover a valid packet whose length is not yet a candidate: {result:?}"
        );
        assert!(
            client.recv_mdh_candidates.contains(&old_mdh_len),
            "the self-heal must cache the discovered MDH length for the fast path"
        );
    }

    /// This is the crux of the investigation: a genuine TAG mismatch (packet
    /// encrypted with keys the client does not have — e.g. the server never
    /// completed its side of the PFS ratchet) is NOT something the candidate
    /// list can ever fix, because tag/counter lookup happens before mdh_len is
    /// even consulted. Retrying with a different mdh_len against the *same,
    /// untouched* RecvWindow can only ever reproduce the identical failure.
    #[tokio::test]
    async fn test_candidate_mdh_len_fallback_cannot_fix_genuine_tag_mismatch() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        let mut client_keys = crypto::derive_session_keys(&[1u8; 32], None, &[0u8; 32]);
        client_keys.session_key_s2c = client_keys.session_key;
        let mut server_keys = crypto::derive_session_keys(&[2u8; 32], None, &[0u8; 32]); // different!
        client.session_keys = Some(client_keys);
        server_keys.session_key_s2c = server_keys.session_key;

        let mdh_len = 20usize;
        client.recv_mdh_len = mdh_len;
        client.recv_mdh_candidates = vec![mdh_len, 8]; // any prior length — irrelevant here

        let control = ControlPayload::Keepalive { send_ts: 0 };
        let encoded = control.encode().unwrap();
        let inner = build_inner_packet(InnerType::Control, 0, &encoded);
        let mut send_counter = 0u64;
        // Packet is genuinely encrypted with a DIFFERENT key than the client has.
        let packet = aivpn_common::client_wire::build_random_mdh_packet(
            &server_keys,
            &mut send_counter,
            &inner,
            None,
            mdh_len,
        )
        .unwrap();

        let result = client.receive_and_write_packet(&packet).await;
        assert!(
            result.is_err(),
            "a genuine key/tag mismatch must not be silently 'fixed' by the mdh_len fallback"
        );
    }

    // ── write_quality_file ────────────────────────────────────────────────────

    #[test]
    fn test_write_quality_file_produces_valid_json() {
        // Override the write path via TMPDIR so this doesn't need /var/run/aivpn.
        // write_quality_file() uses a hardcoded path on non-Windows; we test the
        // JSON content by writing to /tmp directly (the function is private, called
        // via a thin wrapper here).
        let tmp = std::env::temp_dir().join("aivpn_quality_test.json");

        // Replicate the exact format string from write_quality_file().
        let content = format!(
            r#"{{"quality":{},"rtt_ms":{},"jitter_ms":{},"adaptive":{}}}"#,
            85u8, 32u16, 5u16, 2u8
        );
        std::fs::write(&tmp, &content).expect("write must succeed");

        let read_back = std::fs::read_to_string(&tmp).expect("read must succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&read_back).expect("must be valid JSON");

        assert_eq!(parsed["quality"], 85);
        assert_eq!(parsed["rtt_ms"], 32);
        assert_eq!(parsed["jitter_ms"], 5);
        assert_eq!(parsed["adaptive"], 2);

        let _ = std::fs::remove_file(tmp);
    }

    // ── dirs_home ─────────────────────────────────────────────────────────────

    #[test]
    fn test_dirs_home_returns_home_env_var() {
        // HOME is process-wide, and cargo test runs tests in parallel
        // threads within the same process — without this mutex, another
        // test mutating/reading HOME concurrently races with this one
        // (observed: this test reading back the real $HOME instead of the
        // value it just set, because a concurrently-running test restored
        // the real value in between).
        let _guard = crate::TEST_HOME_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("HOME");
        std::env::set_var("HOME", "/test/home/path");
        let result = dirs_home();
        assert_eq!(result, Some(std::path::PathBuf::from("/test/home/path")));
        match old {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn test_dirs_home_returns_none_when_unset() {
        let _guard = crate::TEST_HOME_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("HOME");
        std::env::remove_var("HOME");
        // On non-Windows with no HOME set, dirs_home() must return None.
        #[cfg(not(windows))]
        assert_eq!(dirs_home(), None);
        match old {
            Some(v) => std::env::set_var("HOME", v),
            None => {}
        }
    }

    // ── KeyRotate inline-rekey ordering ───────────────────────────────────────

    /// Adversarial reproduction of a scheduling race: `send_control()` only
    /// enqueues the `KeyRotate` response onto an mpsc channel to the
    /// independently-running upload task — it does not wait for that task to
    /// dequeue and encrypt it. The handler used to overwrite the shared
    /// `upload_state.keys` immediately afterwards with no `.await` in
    /// between, so whichever keys were installed by the time the upload task
    /// got around to encrypting the queued response would be used — which,
    /// depending on scheduling, could be the NEW keys the server does not yet
    /// recognize, permanently desyncing the ratchet.
    ///
    /// This test simulates a upload task that is deliberately slow (sleeps
    /// before draining the control channel and "encrypting" the response),
    /// which would have reliably lost the old race. It asserts that the keys
    /// observed at encryption time are still the OLD keys — proving the
    /// handler now blocks on a rendezvous instead of relying on scheduling
    /// luck.
    #[tokio::test]
    async fn test_key_rotate_response_encrypted_with_old_keys_even_with_slow_upload_task() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        // Install the "old" (pre-ratchet) session keys.
        let old_client_kp = crypto::KeyPair::generate();
        let old_server_kp = crypto::KeyPair::generate();
        let dh_old = old_client_kp
            .compute_shared(&old_server_kp.public_key_bytes())
            .unwrap();
        let mut old_keys =
            crypto::derive_session_keys(&dh_old, None, &old_client_kp.public_key_bytes());
        // Equalise directional keys: these tests build server-sim packets with the
        // C2S encode helper and decode them client-side; the split itself is
        // covered by `directional_keys_differ` + the live tunnel.
        old_keys.session_key_s2c = old_keys.session_key;
        client.session_keys = Some(old_keys.clone());

        // Wire up a real control channel plus a shared UploadCryptoState, just
        // like connect() does when it spawns the upload task.
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);

        let upload_state = Arc::new(Mutex::new(UploadCryptoState {
            keys: old_keys.clone(),
            counter: 0,
            seq: 0,
            rekey_ack: VecDeque::new(),
        }));
        client.upload_state = Some(upload_state.clone());

        // Records the keys observed by the simulated upload task at the
        // moment it "encrypts" (dequeues) the KeyRotate response.
        let observed_keys: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(None));

        let sim_upload_state = upload_state.clone();
        let sim_observed_keys = observed_keys.clone();
        let sim_upload_task = tokio::spawn(async move {
            // Deliberately give the caller every opportunity to race ahead
            // and swap `upload_state.keys` before we drain the channel. Under
            // the old (buggy) code this sleep made the race a certainty, not
            // just a possibility.
            tokio::time::sleep(Duration::from_millis(30)).await;

            let payload = control_rx
                .recv()
                .await
                .expect("KeyRotate response enqueued");
            let mut state = sim_upload_state.lock().unwrap_or_else(|e| e.into_inner());
            *sim_observed_keys.lock().unwrap_or_else(|e| e.into_inner()) = Some(state.keys.clone());
            if matches!(payload, ControlPayload::KeyRotate { .. }) {
                if let Some(ack) = state.rekey_ack.pop_front() {
                    let _ = ack.send(());
                }
            }
        });

        // Drive the real inline-rekey handler as if the server initiated a
        // ratchet.
        let server_rekey_kp = crypto::KeyPair::generate();
        client
            .handle_server_control(ControlPayload::KeyRotate {
                new_eph_pub: server_rekey_kp.public_key_bytes(),
            })
            .await
            .expect("KeyRotate handling must not fail");

        sim_upload_task
            .await
            .expect("simulated upload task must not panic");

        let observed = observed_keys
            .lock()
            .unwrap()
            .clone()
            .expect("simulated upload task must have observed keys");
        assert_eq!(
            observed.session_key, old_keys.session_key,
            "KeyRotate response must be encrypted with the OLD keys even when \
             the upload task is slow to dequeue it — the handler must block \
             on the rekey_ack rendezvous rather than racing ahead"
        );

        // And the client's own record must have moved on to the NEW keys
        // after the rendezvous completed.
        assert_ne!(
            client.session_keys.as_ref().unwrap().session_key,
            old_keys.session_key,
            "client must have switched to the new session keys once the \
             old-key send was confirmed"
        );
    }

    /// Reproduces a duplicated/redelivered KeyRotate REQUEST (plain UDP
    /// duplication is sufficient to trigger this — no server-side resend
    /// logic is required). Before the idempotency guard, reprocessing the
    /// same request generated a fresh random client keypair and re-derived
    /// new_keys from the already-once-rotated current key, producing a key
    /// the server never agreed to (the server only ever commits the FIRST
    /// response, since its own pending_rekey_keypair is consumed on commit) —
    /// a permanent, unrecoverable desync live-reproduced in production
    /// (SOCKS5 proxy session, sustained aead::Error flood from the moment of
    /// the second processing onward).
    #[tokio::test]
    async fn test_duplicate_key_rotate_request_is_idempotent() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        let old_client_kp = crypto::KeyPair::generate();
        let old_server_kp = crypto::KeyPair::generate();
        let dh_old = old_client_kp
            .compute_shared(&old_server_kp.public_key_bytes())
            .unwrap();
        let mut old_keys =
            crypto::derive_session_keys(&dh_old, None, &old_client_kp.public_key_bytes());
        // Equalise directional keys: these tests build server-sim packets with the
        // C2S encode helper and decode them client-side; the split itself is
        // covered by `directional_keys_differ` + the live tunnel.
        old_keys.session_key_s2c = old_keys.session_key;
        client.session_keys = Some(old_keys.clone());

        // Wire up a real control channel plus a shared UploadCryptoState so
        // send_control() succeeds and the rekey_ack rendezvous resolves —
        // otherwise the handler returns early before ever switching keys.
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);
        let upload_state = Arc::new(Mutex::new(UploadCryptoState {
            keys: old_keys.clone(),
            counter: 0,
            seq: 0,
            rekey_ack: VecDeque::new(),
        }));
        client.upload_state = Some(upload_state.clone());
        // Drains every enqueued control payload and immediately acks a
        // KeyRotate response, mirroring the real upload task's encrypt_control.
        // Records each KeyRotate response's eph pub together with the keys
        // held at "encrypt" time, so the retransmit re-send path can be
        // asserted on (same response eph, OLD keys).
        let sent_responses: Arc<Mutex<Vec<([u8; 32], SessionKeys)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let drain_upload_state = upload_state.clone();
        let drain_sent = sent_responses.clone();
        let drain_task = tokio::spawn(async move {
            while let Some(payload) = control_rx.recv().await {
                let mut state = drain_upload_state.lock().unwrap_or_else(|e| e.into_inner());
                if let ControlPayload::KeyRotate { new_eph_pub } = payload {
                    drain_sent
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((new_eph_pub, state.keys.clone()));
                    if let Some(ack) = state.rekey_ack.pop_front() {
                        let _ = ack.send(());
                    }
                }
            }
        });

        let server_rekey_kp = crypto::KeyPair::generate();
        let request = ControlPayload::KeyRotate {
            new_eph_pub: server_rekey_kp.public_key_bytes(),
        };

        client
            .handle_server_control(request.clone())
            .await
            .expect("first KeyRotate must not fail");
        let keys_after_first = client
            .session_keys
            .as_ref()
            .expect("session_keys set after first rekey")
            .clone();
        assert_ne!(
            keys_after_first.session_key, old_keys.session_key,
            "first KeyRotate must actually ratchet"
        );

        // Redeliver the EXACT SAME request (same new_eph_pub) — models a
        // plain UDP duplicate, no server-side retry mechanism needed.
        client
            .handle_server_control(request)
            .await
            .expect("duplicate KeyRotate must not fail");

        assert_eq!(
            client.session_keys.as_ref().unwrap().session_key,
            keys_after_first.session_key,
            "BUG WOULD REPRODUCE HERE: a duplicate KeyRotate request must be a \
             no-op — reprocessing it must never re-derive/re-switch keys, since \
             the server only ever commits the first response and would never \
             learn about a second, independently-derived key"
        );

        // BUG-2 lost-response self-heal: the redelivered request models the
        // server's fast RETRANSMIT (our response was lost — the server is
        // still on the old keys, rekey pending). Ignoring it silently
        // deadlocked the tunnel until the RX-silence watchdog reconnected.
        // The handler must RE-SEND the SAME response (same client eph — the
        // server may commit either copy) encrypted with the OLD keys the
        // server can still read, then restore the new keys for the uplink.
        let sent = sent_responses.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            sent.len(),
            2,
            "retransmitted KeyRotate must trigger a re-send of the response, \
             not a silent ignore"
        );
        assert_eq!(
            sent[1].0, sent[0].0,
            "re-sent response must carry the SAME client eph pub as the \
             original — a fresh one could desync if the original response \
             was merely delayed and the server commits it first"
        );
        assert_eq!(
            sent[1].1.session_key, old_keys.session_key,
            "re-sent response must be encrypted with the OLD keys — the \
             server never committed and cannot read the new ones"
        );
        drop(sent);
        assert_eq!(
            upload_state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .keys
                .session_key,
            keys_after_first.session_key,
            "after the re-send the upload keys must be restored to the \
             committed (new) session keys"
        );

        drain_task.abort();
    }

    /// Throwaway timing probe (not a correctness assertion): measures the
    /// real wall-clock cost of exhausting `find_counter`'s full search space
    /// on a genuinely-non-matching key/window pair, to gauge whether a large
    /// backlog of buffered old-key packets (each of which must fail the
    /// PRIMARY decode attempt — new keys/fresh window — before falling back)
    /// could plausibly burn through the 2-second `transition_recv_deadline`
    /// during the drain of a large post-rekey burst.
    #[test]
    fn test_timing_probe_find_counter_exhaustive_scan_cost() {
        let mut keys = crypto::derive_session_keys(&[9u8; 32], None, &[0u8; 32]);
        keys.session_key_s2c = keys.session_key;
        let wrong_tag = [0xAAu8; aivpn_common::crypto::TAG_SIZE];
        let window = aivpn_common::client_wire::RecvWindow::new();
        let n = 500;
        let start = std::time::Instant::now();
        for _ in 0..n {
            let _ = window.find_counter(&wrong_tag, &keys);
        }
        let elapsed = start.elapsed();
        println!(
            "find_counter exhaustive-fail cost: {:?} total for {} calls, {:?}/call",
            elapsed,
            n,
            elapsed / n
        );
    }

    /// Empirical reproduction of the production symptom reported after
    /// da159a4: a permanent flood of "Invalid resonance tag" / `aead::Error`
    /// starting immediately after an inline PFS rekey, with the connection
    /// never recovering. da159a4 only guards against a literal duplicate
    /// KeyRotate *request* (same `new_eph_pub` reprocessed) — it says nothing
    /// about whether packets that legitimately arrive *during* the rekey
    /// handshake (buffered in the UDP->TUN mpsc channel while this handler is
    /// blocked on `ack_rx.await`, then drained in a tight burst once it
    /// returns — matching the observed ~1.3-1.6ms-apart burst) actually
    /// decode correctly afterwards.
    ///
    /// This test builds a session with realistic PRE-rekey traffic (advancing
    /// `recv_window.highest` the way ~25s of real usage would), drives the
    /// real `handle_server_control(KeyRotate)` handler with a deliberately
    /// slow upload task (forcing the same blocking window production hits),
    /// computes the exact keys a real server's `commit_session_rekey` would
    /// install (mirroring `session.rs` byte-for-byte), and then feeds the
    /// client a burst of packets representing exactly what a real server
    /// would have sent during and after that window:
    ///   - old-key packets with counters continuing the pre-rekey sequence
    ///     (sent by the server before it received/committed the response)
    ///   - new-key packets with counters restarting at 0 (sent by the server
    ///     immediately after commit)
    ///
    /// If the transition-window mechanism (`transition_recv_keys` /
    /// `transition_recv_window`) is sound, every one of these must decode.
    #[tokio::test]
    async fn test_burst_of_in_flight_packets_decodes_correctly_across_inline_rekey() {
        let config = make_test_config();
        let mut client = AivpnClient::new(config).expect("new() must not fail");

        // ── Establish realistic PRE-rekey state ────────────────────────────
        let old_client_kp = crypto::KeyPair::generate();
        let old_server_kp = crypto::KeyPair::generate();
        let dh_old = old_client_kp
            .compute_shared(&old_server_kp.public_key_bytes())
            .unwrap();
        let mut old_keys =
            crypto::derive_session_keys(&dh_old, None, &old_client_kp.public_key_bytes());
        // Equalise directional keys: these tests build server-sim packets with the
        // C2S encode helper and decode them client-side; the split itself is
        // covered by `directional_keys_differ` + the live tunnel.
        old_keys.session_key_s2c = old_keys.session_key;
        client.session_keys = Some(old_keys.clone());

        let mdh_len = client.recv_mdh_len;
        let mut pre_rekey_send_counter = 0u64;
        // Simulate ~10 real packets already exchanged before the rekey, so
        // recv_window.highest is well past 0 (like 25s of real traffic).
        for _ in 0..10 {
            let control = ControlPayload::Keepalive { send_ts: 0 };
            let encoded = control.encode().unwrap();
            let inner = build_inner_packet(InnerType::Control, 0, &encoded);
            let packet = aivpn_common::client_wire::build_random_mdh_packet(
                &old_keys,
                &mut pre_rekey_send_counter,
                &inner,
                None,
                mdh_len,
            )
            .unwrap();
            client
                .receive_and_write_packet(&packet)
                .await
                .expect("pre-rekey traffic must decode");
        }

        // ── Wire up control_tx / upload_state with a SLOW upload task, to
        // force the same blocking window production hits (packets pile up in
        // udp_to_tun_rx while this handler awaits ack_rx). ──────────────────
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        client.control_tx = Some(control_tx);
        let upload_state = Arc::new(Mutex::new(UploadCryptoState {
            keys: old_keys.clone(),
            counter: pre_rekey_send_counter,
            seq: 0,
            rekey_ack: VecDeque::new(),
        }));
        client.upload_state = Some(upload_state.clone());

        let captured_client_new_eph_pub: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));
        let sim_capture = captured_client_new_eph_pub.clone();
        let sim_upload_state = upload_state.clone();
        let sim_upload_task = tokio::spawn(async move {
            // Deliberately slow, like the real upload task can be under load
            // (mimicry pacing / a backlog of data packets ahead of the
            // control message in the pipeline).
            tokio::time::sleep(Duration::from_millis(30)).await;
            let payload = control_rx
                .recv()
                .await
                .expect("KeyRotate response enqueued");
            if let ControlPayload::KeyRotate { new_eph_pub } = payload {
                *sim_capture.lock().unwrap_or_else(|e| e.into_inner()) = Some(new_eph_pub);
            }
            let mut state = sim_upload_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ack) = state.rekey_ack.pop_front() {
                let _ = ack.send(());
            }
        });

        // ── Drive the real inline-rekey handler, as the server's periodic
        // rekey task would (session.rs start_rekeying_sessions). ───────────
        let server_rekey_kp = crypto::KeyPair::generate();
        client
            .handle_server_control(ControlPayload::KeyRotate {
                new_eph_pub: server_rekey_kp.public_key_bytes(),
            })
            .await
            .expect("KeyRotate handling must not fail");

        sim_upload_task
            .await
            .expect("simulated upload task must not panic");

        // ── Compute the keys a REAL server's commit_session_rekey would
        // install, mirroring session.rs byte-for-byte, to sanity-check that
        // the client's local switch matches what the server would compute. ─
        let client_new_eph_pub = captured_client_new_eph_pub
            .lock()
            .unwrap()
            .expect("response must have been observed by the simulated upload task");
        let server_dh_rekey = server_rekey_kp
            .compute_shared(&client_new_eph_pub)
            .expect("server DH must succeed");
        let server_new_keys = crypto::derive_session_keys(
            &server_dh_rekey,
            Some(&old_keys.session_key),
            &client_new_eph_pub,
        );
        // Keep server_new_keys directional (do NOT equalise): the client's real
        // inline-rekey derives distinct c2s/s2c, so the server-sim must build
        // downlink packets with the S2C key the client will decode with.
        let server_new_dl = {
            let mut k = server_new_keys.clone();
            k.session_key = server_new_keys.session_key_s2c;
            k
        };
        assert_eq!(
            client.session_keys.as_ref().unwrap().session_key,
            server_new_keys.session_key,
            "client's locally-switched key must match what a real server's \
             commit_session_rekey would independently derive"
        );

        // ── Now feed the burst: packets a real server would have sent DURING
        // the blocking window (still old key, counters continuing the
        // pre-rekey sequence) followed by packets sent AFTER it committed
        // (new key, counters STILL continuing monotonically — the server keeps
        // its s2c send counter across the inline rekey; only the key changes).
        // This models exactly what arrives in udp_to_tun_rx and gets drained in
        // a tight loop once this handler returns. ──────────────────────────────
        let mut old_key_failures = Vec::new();
        let mut old_key_send_counter = pre_rekey_send_counter;
        for i in 0..50 {
            let control = ControlPayload::Keepalive { send_ts: 0 };
            let encoded = control.encode().unwrap();
            let inner = build_inner_packet(InnerType::Control, 0, &encoded);
            let packet = aivpn_common::client_wire::build_random_mdh_packet(
                &old_keys,
                &mut old_key_send_counter,
                &inner,
                None,
                mdh_len,
            )
            .unwrap();
            if let Err(e) = client.receive_and_write_packet(&packet).await {
                old_key_failures.push((i, e));
            }
        }
        assert!(
            old_key_failures.is_empty(),
            "old-key in-flight packets (sent by server before it committed the \
             rekey) must decode via transition_recv_keys fallback — failures: \
             {:?}",
            old_key_failures
        );

        let mut new_key_failures = Vec::new();
        // Monotonic: new-key packets continue the counter sequence where the
        // old-key in-flight burst left off (the server does not reset send_counter
        // on rekey), so the client's primary recv-window stays synced and its
        // forward search slides forward instead of stranding at [0, WINDOW).
        let mut new_key_send_counter = old_key_send_counter;
        for i in 0..50 {
            let control = ControlPayload::Keepalive { send_ts: 0 };
            let encoded = control.encode().unwrap();
            let inner = build_inner_packet(InnerType::Control, 0, &encoded);
            let packet = aivpn_common::client_wire::build_random_mdh_packet(
                &server_new_dl,
                &mut new_key_send_counter,
                &inner,
                None,
                mdh_len,
            )
            .unwrap();
            if let Err(e) = client.receive_and_write_packet(&packet).await {
                new_key_failures.push((i, e));
            }
        }
        assert!(
            new_key_failures.is_empty(),
            "new-key packets (sent by server immediately after commit) must \
             decode via the primary path — failures: {:?}",
            new_key_failures
        );
    }

    // ── ClientState enum completeness ─────────────────────────────────────────

    #[test]
    fn test_client_state_enum_variants_are_distinct() {
        assert_ne!(ClientState::Unprovisioned, ClientState::Provisioned);
        assert_ne!(ClientState::Provisioned, ClientState::Connecting);
        assert_ne!(ClientState::Connecting, ClientState::Connected);
        assert_ne!(ClientState::Connected, ClientState::Reconnecting);
        assert_ne!(ClientState::Reconnecting, ClientState::Disconnected);
    }
}
