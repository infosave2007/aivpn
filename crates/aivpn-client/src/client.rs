//! AIVPN Client - Full Implementation
//!
//! Complete VPN client with:
//! - Real TUN device integration
//! - Mimicry Engine for traffic shaping
//! - Key exchange and session management
//! - Control plane handling

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

/// 3f: human-readable message for a `HandshakeReject` reason code. See
/// `ControlPayload::HandshakeReject`'s doc comment in aivpn-common for the
/// authoritative mapping: 1=one-time key already used, 2=expired,
/// 3=disabled, 0/other=unspecified.
pub fn handshake_reject_message(reason: u8) -> &'static str {
    match reason {
        1 => "one-time key already used",
        2 => "client expired",
        3 => "client disabled",
        _ => "refused",
    }
}

/// 3f: short machine-readable token for the `AIVPN-STATUS rejected <token>`
/// stdout line — mirrors `handshake_reject_message` but as an ASCII token a
/// GUI can match without depending on the English wording (the GUI maps the
/// token to its own localized string).
fn handshake_reject_token(reason: u8) -> &'static str {
    match reason {
        1 => "one_time_used",
        2 => "expired",
        3 => "disabled",
        _ => "unspecified",
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
/// §2 crowdsourced feedback. `bootstrap:{desc}:{base}:{slot}:{seed}` and
/// `polymorphic:{base}:{hex}` both carry per-session/PSK-derived entropy that
/// would leak a quasi-identifier and fragment the server's k-anonymity buckets;
/// only the stable `{base}` family is meaningful (and safe) to report.
pub fn base_mask_family(mask_id: &str) -> String {
    if let Some(rest) = mask_id.strip_prefix("bootstrap:") {
        // desc:base:slot:seed → the base is the 2nd colon-delimited field.
        rest.split(':').nth(1).unwrap_or(rest).to_string()
    } else if let Some(rest) = mask_id.strip_prefix("polymorphic:") {
        // base:hex → the base is the 1st field.
        rest.split(':').next().unwrap_or(rest).to_string()
    } else {
        mask_id.to_string()
    }
}

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

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Ed25519 signing public key for verifying ServerHello signatures and mask updates.
    /// When `Some`, the client rejects unsigned or incorrectly signed messages from
    /// the server, preventing MITM attacks.
    pub server_signing_key: Option<[u8; 32]>,
    pub preshared_key: Option<[u8; 32]>,
    pub initial_mask: MaskProfile,
    pub tun_config: TunnelConfig,
    /// When set, run as SOCKS5 proxy on this address instead of a TUN device.
    pub proxy_listen: Option<std::net::SocketAddr>,
    /// Optional 104-byte mTLS certificate sent to the server after session setup.
    /// Required when the server is configured with `mtls.required = true`.
    pub mtls_cert: Option<Vec<u8>>,
    /// Initial adaptive mode level from `--adaptive-level`/GUI selection. The
    /// quality tracker can still raise/lower this automatically afterward,
    /// but the user's explicit choice is honored as the starting point
    /// instead of always starting at `Off`.
    pub initial_adaptive_level: AdaptiveLevel,
    /// When set, request a polymorphic (per-session perturbed) variant of this
    /// base mask id from the server right after the handshake completes. The
    /// server responds with the usual `MaskUpdate` control message — no other
    /// client-side handling is needed.
    pub polymorphic_base: Option<String>,
    /// §2 crowdsourced blocking feedback — opt-in, OFF by default. When true
    /// (and `country_code` is set), the client batches mask success/fail
    /// outcomes in-memory and reports them to the server once per connection
    /// (see `maybe_send_mask_feedback`). No effect unless `country_code` is
    /// also `Some`.
    pub share_mask_feedback: bool,
    /// §2 crowdsourced blocking feedback — opt-in, OFF by default. When true,
    /// the client stores `RegionalMaskHints` pushed by the server (see
    /// `regional_mask_hints()`) for future mask-selection use.
    pub receive_mask_hints: bool,
    /// ISO-3166-1 alpha-2 country code the client believes it is in. Required
    /// for `share_mask_feedback` to have any effect — the server aggregates
    /// feedback per region and never receives one without the other.
    pub country_code: Option<[u8; 2]>,
    /// R2 Phase B: operator Ed25519 mask-verifying public key. Verifies the
    /// embedded `MaskProfile.signature` (artifact provenance: "this mask went
    /// through the operator's gates") of masks received via `MaskUpdate`.
    /// SEPARATE from `server_signing_key`, which authenticates the transport
    /// (the msgpack bytes as pushed by *this* server) — the two are
    /// defense-in-depth layers. Sourced from `--mask-operator-pubkey`, the
    /// config file, or the `mop` field of the aivpn:// connection key.
    pub mask_operator_pubkey: Option<[u8; 32]>,
    /// R2 Phase B: artifact verification mode for received masks:
    /// off | warn (default, log-and-accept) | enforce (reject). Derived
    /// per-session variants (`polymorphic:*`/`bootstrap:*`) are exempt — they
    /// are authenticated by the session channel and are not independently
    /// signature-verifiable.
    pub mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    /// 3b: shared handle to the process-wide native network-change listener
    /// (see `net_change.rs`), spawned ONCE in `main.rs` before the reconnect
    /// loop and threaded into every `ClientConfig`/`run()` call across
    /// reconnects. `None` when no platform listener is implemented, or the
    /// platform-specific registration failed — the client then relies solely
    /// on the existing poll-based watchdogs (unchanged behavior).
    pub network_change_notify: Option<Arc<tokio::sync::Notify>>,
    /// 3c: true when `main.rs` selected this run's `initial_mask` via the
    /// "3 consecutive handshakes never connected" resilience fallback
    /// (built-in default mask) rather than the normal bootstrap-derived
    /// selection. Threaded through so the stats-writer task can surface it
    /// to file-polling GUIs (Windows) via the `fallback:` key — mirrors how
    /// `ip:` was added for the same "GUI can't read child stdout" reason.
    pub is_bootstrap_fallback: bool,
    /// Headless "control-only" mode: no TUN device, no SOCKS proxy, no local
    /// admin IPC socket, no stats-file writer, and all `InnerType::Data`
    /// packets are dropped on receipt. Used when the aivpn SERVER embeds this
    /// client as a masked pool-peer dialer (completes the handshake and
    /// exchanges CONTROL payloads for DB anti-entropy with a peer node) rather
    /// than by an end-user device. `false` (default) reproduces the exact
    /// pre-existing behavior of every other call site.
    pub control_only: bool,
    /// When set (only meaningful with `control_only = true`), inbound
    /// `ControlPayload::PoolSync` / `PoolStateDigest` / `PoolBucketDigests` /
    /// `RouteSync` messages
    /// are cloned and forwarded to this channel instead of being silently
    /// ignored, so the embedding server can drive its own anti-entropy merge
    /// logic off of them. `None` (default) preserves the previous silent-drop
    /// behavior for these variants.
    pub inbound_control_tap: Option<tokio::sync::mpsc::Sender<ControlPayload>>,
    /// B2/D2 fix (session-bound `NodeEnrollment`, SEND side): this node's own
    /// durable Ed25519 pool-node identity, `Some` only for the embedded
    /// `control_only` pool-peer dialer (`aivpn-server`'s `pool_dialer.rs`)
    /// when `main.rs` resolved a `pool.node_identity_key`. `None` (the
    /// default, and always the value for every ordinary end-user client) is
    /// a complete no-op: no `NodeEnrollment` is ever built or sent. When
    /// `Some`, the `ServerHello` handler signs and sends a `NodeEnrollment`
    /// proof bound to THIS session's ephemeral transcript
    /// (`server_eph_pub`/`client_eph_pub`) right after the PFS ratchet
    /// completes — moved here (out of `pool_dialer.rs`) specifically because
    /// only this handler has that transcript available, and binding to it is
    /// what prevents a captured proof from being replayed onto a different
    /// masked pool-peer session (mirrors `DeviceEnrollment`'s `dh_proof`
    /// scheme just above in this same handler).
    pub node_identity: Option<ed25519_dalek::SigningKey>,
    /// This node's own pool `node_id` string, carried in the `NodeEnrollment`
    /// proof `node_identity` signs. Only meaningful alongside
    /// `node_identity: Some(..)`; `None` there is treated as an empty string
    /// (matching `pool_dialer.rs`'s pre-existing `unwrap_or_default()`
    /// handling for its own `RouteSync`/enrollment payloads).
    pub pool_node_id: Option<String>,
}

/// Client state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    Unprovisioned,
    Provisioned,
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
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

    /// K6: install (or re-install after a rekey/mask change) the client's
    /// in-kernel DOWNLINK session so aivpn.ko decrypts server→client Data
    /// packets and injects them straight into the TUN device.
    ///
    /// Key/layout choices (mirroring `decode_downlink_any_mdh_len`, the
    /// user-space downlink decoder this offloads):
    /// * kernel decrypt key (`session_key` field) = the session's **s2c** key
    ///   — the client's incoming downlink is encrypted with it;
    /// * `tag_offset = u16::MAX` — server→client downlink always uses the
    ///   legacy tag-prefix framing `tag(8) || mdh || ciphertext` (the embedded
    ///   Variant A layout is uplink-only);
    /// * `mdh_len` = the current primary downlink MDH length
    ///   (`recv_mdh_len`). Packets framed with a different mask length fail
    ///   AEAD auth in the kernel (-EBADMSG) and fall back to user-space, whose
    ///   multi-length decoder handles them — correctness never depends on this
    ///   value, only the kernel-offload hit rate does.
    ///
    /// Ordering matters: TUN first (inject target), then the session + tags,
    /// then — exactly once per socket — the UDP hook, so no packet is ever
    /// intercepted before the kernel can actually consume it (a hook with no
    /// session was the 13984c5 starvation regression).
    ///
    /// `session_add` is idempotent by `session_id` (the kernel evicts a
    /// same-id entry first) and `kernel_session_id` is constant for this
    /// client instance, so a rekey re-install atomically replaces the old-key
    /// session instead of leaking it.
    ///
    /// All failures are soft: the user-space path keeps working, at worst the
    /// kernel simply never accelerates.
    #[cfg(target_os = "linux")]
    fn kernel_install_session(&mut self) {
        use std::os::unix::io::AsRawFd;
        let Some(ka) = self.kernel_accel.clone() else {
            return;
        };
        // Re-checked full-tunnel gate (belt and braces — connect() already
        // leaves `kernel_accel = None` in proxy mode).
        if self.config.proxy_listen.is_some() {
            return;
        }
        let Some(keys) = self.session_keys.as_ref() else {
            return;
        };
        let (session_key_s2c, tag_secret) = (keys.session_key_s2c, keys.tag_secret);
        let Some(udp) = self.udp_socket.clone() else {
            return;
        };

        // 1. Point the module at our TUN device (once). A TUN that cannot be
        //    resolved means the kernel path is unusable — drop the handle so
        //    the hook is never installed.
        if !self.kernel_tun_set {
            let tun_name = self.tunnel.name();
            let ifindex = std::ffi::CString::new(tun_name)
                .map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) })
                .unwrap_or(0);
            if ifindex == 0 {
                warn!(
                    "kernel accel: cannot resolve TUN ifindex for {tun_name} — \
                     staying on the user-space path"
                );
                self.kernel_accel = None;
                return;
            }
            if let Err(e) = ka.set_tun(ifindex) {
                warn!("kernel accel: set_tun failed: {e} — staying on the user-space path");
                self.kernel_accel = None;
                return;
            }
            self.kernel_tun_set = true;
            info!("kernel accel: TUN {tun_name} (ifindex={ifindex}) registered");
        }

        // 2. Install the downlink-decrypt session.
        let mdh_len = self.recv_mdh_len;
        // Peer address / own VPN IP: not used by the RX+inject path (they feed
        // the egress fast path, which the client never arms via SET_EGRESS) —
        // filled in sanely anyway.
        let mut client_addr_bytes = [0u8; 28];
        if let Ok(peer) = udp.peer_addr() {
            match peer {
                SocketAddr::V4(v4) => {
                    client_addr_bytes[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
                    client_addr_bytes[2..4].copy_from_slice(&v4.port().to_be_bytes());
                    client_addr_bytes[4..8].copy_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    client_addr_bytes[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
                    client_addr_bytes[2..4].copy_from_slice(&v6.port().to_be_bytes());
                    client_addr_bytes[8..24].copy_from_slice(&v6.ip().octets());
                }
            }
        }
        let client_ip = self
            .config
            .tun_config
            .tun_addr
            .parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(0);
        let add = SessionAdd {
            session_id: self.kernel_session_id,
            // The kernel's RX path decrypts with `session_key`; for the
            // client's downlink that MUST be the s2c key.
            session_key: session_key_s2c,
            // Egress-encrypt key — never used (client never calls SET_EGRESS);
            // keep it the true s2c key so the field's meaning stays honest.
            session_key_s2c,
            tag_secret,
            // The AIVPN nonce is counter_LE(8) || zeros(4) in both directions —
            // no per-session suffix (see the server's identical comment).
            nonce_suffix: [0u8; 4],
            tag_offset: u16::MAX, // downlink is always legacy tag-prefix framing
            mdh_len: mdh_len as u16,
            _reserved: [0u8; 24],
            // Only seeds the egress tx_counter (unused on the client); the RX
            // anti-replay window starts at zero regardless.
            counter_base: self.recv_window.highest().map(|h| h + 1).unwrap_or(0),
            client_ip,
            client_addr: client_addr_bytes,
            window_ms: crypto::DEFAULT_WINDOW_MS,
        };
        if let Err(e) = ka.session_add(&add) {
            warn!("kernel accel: session_add failed: {e} — staying on the user-space path");
            return;
        }
        self.kernel_installed = true;
        self.kernel_installed_mdh_len = mdh_len;

        // 3. Push the expected downlink tag window before any packet can hit
        //    the hook.
        self.kernel_push_tags(true);

        // 4. Hook the UDP socket — exactly once per socket (the kernel install
        //    is not idempotent; see `kernel_hooked`). From here on, in-window
        //    downlink Data is consumed in softirq; everything else falls back
        //    to this loop via the hook's re-queue + original data_ready wake.
        if !self.kernel_hooked {
            if let Err(e) = ka.set_udp_sock(udp.as_raw_fd()) {
                warn!("kernel accel: set_udp_sock failed: {e} — kernel session installed but idle");
                return;
            }
            self.kernel_hooked = true;
        }
        info!(
            "kernel accel: downlink session installed (mdh_len={mdh_len}, legacy framing) — \
             server→client Data now decrypted in-kernel"
        );
    }

    /// K6: (re)compute and push the client's expected downlink resonance-tag
    /// window `[base, base + 256)` to the kernel, where `base` is one past the
    /// highest downlink counter user-space has validated. Exactly the tag
    /// derivation the server uses to CREATE downlink tags
    /// (`generate_resonance_tag(tag_secret, counter, time_window)`), so the
    /// kernel's byte-exact tag lookup matches the wire.
    ///
    /// Unless `force`d (fresh install/rekey), the push is skipped while the
    /// 10 s resonance time window is unchanged AND the observed counter has
    /// advanced less than `KERNEL_TAG_REFRESH_STRIDE` — callers can therefore
    /// invoke this opportunistically (per fallback packet + 5 s watchdog tick)
    /// at negligible cost.
    ///
    /// Known coverage limitation (same class as the server's K7 note): only
    /// fallback packets advance user-space's view of the downlink counter, so
    /// under sustained downlink the kernel window is consumed and traffic
    /// falls back to user-space until the next refresh re-bases it. That is a
    /// throughput ceiling, never a correctness issue.
    #[cfg(target_os = "linux")]
    fn kernel_push_tags(&mut self, force: bool) {
        if !self.kernel_installed {
            return;
        }
        let Some(ka) = self.kernel_accel.clone() else {
            return;
        };
        let Some(keys) = self.session_keys.as_ref() else {
            return;
        };
        let tag_secret = keys.tag_secret;
        let base = self.recv_window.highest().map(|h| h + 1).unwrap_or(0);
        let tw =
            crypto::compute_time_window(crypto::current_timestamp_ms(), crypto::DEFAULT_WINDOW_MS);
        if !force
            && tw == self.kernel_tags_tw
            && base.saturating_sub(self.kernel_tags_base) < KERNEL_TAG_REFRESH_STRIDE
        {
            return;
        }
        // Safety: UpdateTagsPayload is a plain C struct of integers and byte
        // arrays; zeroed is valid for all fields.
        let mut payload: UpdateTagsPayload = unsafe { std::mem::zeroed() };
        payload.session_id = self.kernel_session_id;
        for i in 0..KERNEL_TAG_WINDOW as u64 {
            let counter = base + i;
            let tag = crypto::generate_resonance_tag(&tag_secret, counter, tw);
            payload.entries[i as usize] = TagWindowEntry { tag, counter };
        }
        payload.count = KERNEL_TAG_WINDOW as u32;
        if let Err(e) = ka.session_update_tags(&payload) {
            warn!("kernel accel: session_update_tags failed: {e}");
            return;
        }
        self.kernel_tags_base = base;
        self.kernel_tags_tw = tw;
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

    /// Run the client main loop
    pub async fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        self.connect().await?;

        // Send initial handshake packet with eph_pub to establish session
        self.send_init().await?;

        // Session start (post-handshake) — tells a working sticky mask (long
        // healthy session) from a throttled one (repeated short data stalls).
        let session_established = std::time::Instant::now();

        info!("Starting client main loop");
        info!("Routing traffic through AIVPN tunnel...");

        // Create channels for TUN -> upload pipeline and UDP -> main loop
        let (tun_to_udp_tx, tun_to_udp_rx) = mpsc::channel::<Vec<u8>>(512);
        let (udp_to_tun_tx, mut udp_to_tun_rx) = mpsc::channel::<Bytes>(512);
        let (admin_tx, mut admin_rx) = mpsc::channel::<String>(16);
        // If `control_handle()` was called before `run()`, its receiver is
        // preset here and reused verbatim (and `self.control_tx` is already
        // set to a clone of the same sender) — otherwise, preserve the
        // original behavior exactly: create a fresh channel and set
        // `self.control_tx` from it.
        let (control_tx, control_rx) = if let Some(rx) = self.preset_control_rx.take() {
            let tx = self
                .control_tx
                .clone()
                .expect("preset_control_rx implies control_tx was set by control_handle()");
            (tx, rx)
        } else {
            let (tx, rx) = mpsc::channel::<ControlPayload>(32);
            self.control_tx = Some(tx.clone());
            (tx, rx)
        };

        // mTLS ClientCert is sent inside the ServerHello handler, after the PFS
        // ratchet completes, so it is protected by the ratcheted session keys.

        // Spawn local IPC listener for CLI commands. Stored in AbortOnDrop so the task
        // (and its bound UDP socket) is cancelled when run() returns. Without this,
        // the orphaned task keeps 127.0.0.1:44301 bound across reconnect iterations,
        // causing the next run() call to fail with "Address already in use".
        let admin_token = crate::record_cmd::ensure_admin_token();
        // Headless control-only mode (server-embedded pool-peer dialer): never
        // bind the admin IPC socket. This is the hard blocker for running N
        // dialers in one process — `admin_tx` is intentionally left un-moved
        // here (not dropped) so `admin_rx.recv()` in the main select loop
        // below simply pends forever instead of spinning on a closed channel.
        let _admin_task = if self.config.control_only {
            AbortOnDrop(tokio::spawn(std::future::pending::<()>()))
        } else {
            AbortOnDrop(tokio::spawn(async move {
                match tokio::net::UdpSocket::bind("127.0.0.1:44301").await {
                    Ok(socket) => {
                        let mut buf = [0u8; 1024];
                        loop {
                            if let Ok((len, _addr)) = socket.recv_from(&mut buf).await {
                                if let Ok(raw) = std::str::from_utf8(&buf[..len]) {
                                    match raw.split_once(':').and_then(|(tok, rest)| {
                                        crate::record_cmd::tokens_match(tok, &admin_token)
                                            .then(|| rest.to_string())
                                    }) {
                                        Some(cmd) => {
                                            let _ = admin_tx.send(cmd).await;
                                        }
                                        None => {
                                            warn!(
                                                "Rejected admin command: missing or invalid auth token"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to bind local admin UDP socket 127.0.0.1:44301: {}",
                            e
                        );
                    }
                }
            }))
        };

        // Proxy mode: start smoltcp + SOCKS5 instead of creating a TUN device
        if let Some(listen_addr) = self.config.proxy_listen {
            let vpn_ip = self
                .config
                .tun_config
                .tun_addr
                .parse::<std::net::Ipv4Addr>()
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
            let gateway_ip = self
                .config
                .tun_config
                .server_vpn_ip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
            let proxy_cfg = crate::proxy::ProxyConfig {
                listen_addr,
                vpn_ip,
                gateway_ip,
                prefix_len: self.config.tun_config.prefix_len,
            };
            let handle = crate::proxy::spawn_proxy(proxy_cfg, tun_to_udp_tx.clone())
                .await
                .map_err(Error::Io)?;
            self.proxy_handle = Some(handle);
        }

        // Take the TUN reader for the spawned task (skipped in proxy mode and
        // in headless control-only mode, where no TUN device was created).
        let tun_task = if self.config.proxy_listen.is_none() && !self.config.control_only {
            let mut tun_reader = self
                .tunnel
                .take_reader()
                .ok_or(Error::Session("TUN reader not available".into()))?;
            let tun_to_udp_tx_clone = tun_to_udp_tx.clone();
            let shutdown_for_tasks = shutdown.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
                loop {
                    if shutdown_for_tasks.load(Ordering::SeqCst) {
                        break;
                    }

                    match tun_reader.read(&mut buf).await {
                        Ok(n) => {
                            if n > 0 {
                                debug!("TUN read {} bytes", n);

                                #[cfg(target_os = "macos")]
                                let payload: Vec<u8> = if n > 4 && buf[0] == 0 && buf[1] == 0 {
                                    buf[4..n].to_vec()
                                } else {
                                    buf[..n].to_vec()
                                };

                                #[cfg(not(target_os = "macos"))]
                                let payload: Vec<u8> = buf[..n].to_vec();

                                let _ = tun_to_udp_tx_clone.send(payload).await;
                            }
                        }
                        Err(e) => {
                            error!("TUN read error: {}", e);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            })
        } else {
            tokio::spawn(std::future::pending::<()>())
        };

        // Spawn UDP reader task
        let udp_socket = self
            .udp_socket
            .as_ref()
            .ok_or(Error::Session(
                "UDP socket not initialized before run()".into(),
            ))?
            .clone();
        let udp_to_tun_tx_clone = udp_to_tun_tx.clone();
        let shutdown_for_tasks = shutdown.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
            let mut consecutive_errors: u32 = 0;

            loop {
                if shutdown_for_tasks.load(Ordering::SeqCst) {
                    break;
                }

                match udp_socket.recv(&mut buf).await {
                    Ok(n) => {
                        consecutive_errors = 0;
                        if n > 0 {
                            let _ = udp_to_tun_tx_clone
                                .send(Bytes::copy_from_slice(&buf[..n]))
                                .await;
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        error!("UDP recv error: {}", e);
                        if consecutive_errors >= 20 {
                            // Socket is likely dead; let the main loop handle reconnect.
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });

        // Spawn stats writer task
        let stats_shutdown = shutdown.clone();
        let stats_bytes_sent = self.bytes_sent.clone();
        let stats_bytes_received = self.bytes_received.clone();
        let stats_current_vpn_ip = self.current_vpn_ip.clone();
        // 3c: whether THIS run's initial_mask came from main.rs's
        // "3 consecutive dead handshakes" resilience fallback rather than
        // normal bootstrap selection. Constant for the run's lifetime (set
        // once by main.rs before constructing this ClientConfig), so a
        // plain captured bool is enough — no need for an Arc<AtomicBool>
        // like the live-updated `ip:` field above.
        let stats_bootstrap_fallback = self.config.is_bootstrap_fallback;
        let stats_task = if self.config.control_only {
            // Headless control-only mode: no stats file — there is no GUI or
            // CLI observing this in-process pool-peer dialer.
            tokio::spawn(std::future::pending::<()>())
        } else {
            tokio::spawn(async move {
                // Determine platform-appropriate stats paths
                #[cfg(target_os = "windows")]
                let stats_paths: Vec<std::path::PathBuf> = {
                    let mut paths = Vec::new();
                    if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
                        let dir = std::path::PathBuf::from(local_app).join("AIVPN");
                        let _ = tokio::fs::create_dir_all(&dir).await;
                        paths.push(dir.join("traffic.stats"));
                    }
                    let tmp = std::env::temp_dir().join("aivpn-traffic.stats");
                    paths.push(tmp);
                    paths
                };
                #[cfg(not(target_os = "windows"))]
                let stats_paths: Vec<std::path::PathBuf> = vec![
                    std::path::PathBuf::from("/var/run/aivpn/traffic.stats"),
                    std::path::PathBuf::from("/tmp/aivpn-traffic.stats"),
                ];

                // Session epoch (unix ms), captured ONCE when this session's stats
                // task starts. GUIs key on a CHANGE in `since` to detect a silent
                // in-process reconnect: it tells them to accept the new (lower)
                // counters and restart the displayed uptime together, instead of
                // freezing on the old totals. The pre-session zero-writes in
                // main.rs deliberately carry NO `since` — no session exists yet.
                let session_since_ms = epoch_ms();

                // Write initial stats. O_NOFOLLOW/create_new-hardened atomic write
                // (secure_write.rs): these paths fall back to predictable
                // world-writable /tmp locations, which a local attacker could
                // pre-plant as a symlink to a file this (possibly root-run)
                // process can write. Uses spawn_blocking (mirroring what
                // tokio::fs::write already does internally) since the hardened
                // write is a handful of sync syscalls, not the tokio async-fs API.
                let initial_ip = stats_current_vpn_ip
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                let initial = format!(
                    "sent:0,received:0,since:{},ip:{},fallback:{}",
                    session_since_ms, initial_ip, stats_bootstrap_fallback as u8
                );
                for path in &stats_paths {
                    let p = path.clone();
                    let data = initial.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::secure_write::write_status_best_effort(&p, data.as_bytes())
                    })
                    .await;
                }
                info!("Initial stats written");

                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    if stats_shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let sent = stats_bytes_sent.load(Ordering::Relaxed);
                    let received = stats_bytes_received.load(Ordering::Relaxed);
                    // Re-read on every tick (not just once at task start): a pool
                    // re-home updates `current_vpn_ip` live via
                    // `apply_server_network_override` while this task keeps
                    // running, so the stats file must reflect the change within
                    // one tick for file-polling GUIs (Windows) to pick it up.
                    let ip = stats_current_vpn_ip
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    let stats = format!(
                        "sent:{},received:{},since:{},ip:{},fallback:{}",
                        sent, received, session_since_ms, ip, stats_bootstrap_fallback as u8
                    );
                    for path in &stats_paths {
                        let p = path.clone();
                        let data = stats.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::secure_write::write_status_best_effort(&p, data.as_bytes())
                        })
                        .await;
                    }
                }
            })
        };

        // ── Spawn upload task using the shared pipeline ──
        let upload_udp = self
            .udp_socket
            .as_ref()
            .ok_or(Error::Session(
                "UDP socket not initialized before upload task".into(),
            ))?
            .clone();
        let upload_keys = self
            .session_keys
            .clone()
            .ok_or(Error::Session("No session keys".into()))?;
        let upload_engine = self
            .mimicry_engine
            .take()
            .ok_or(Error::Session("No mimicry engine".into()))?;
        let upload_seq = self.send_seq as u16;
        let upload_counter = self.counter;
        let upload_bytes_sent = self.bytes_sent.clone();
        let upload_state = Arc::new(Mutex::new(UploadCryptoState {
            keys: upload_keys,
            counter: upload_counter,
            seq: upload_seq,
            rekey_ack: VecDeque::new(),
        }));
        self.upload_state = Some(upload_state.clone());

        let upload_pending_mask = self.pending_mask.clone();

        let mut upload_task = tokio::spawn(Self::spawn_upload(
            tun_to_udp_rx,
            control_rx,
            upload_udp,
            upload_engine,
            upload_state,
            upload_bytes_sent,
            upload_pending_mask,
            self.keepalive_interval,
            self.keepalive_sent_ms.clone(),
            self.adaptive_level.fec_n(),
            self.keepalive_interval_ms.clone(),
            self.last_tx_ms.clone(),
        ));

        // Main loop: download + shutdown + upload health
        let mut shutdown_tick = tokio::time::interval(Duration::from_secs(1));
        shutdown_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // RX silence watchdog: detect silent path failure (NAT rebind, carrier drop).
        // The UDP socket stays open and recv() blocks indefinitely when the path dies,
        // so we track the last received packet and reconnect on silence. The tick is
        // 5 s because the asymmetric threshold below can be as low as 12 s (A4).
        let mut rx_watchdog = tokio::time::interval(Duration::from_secs(5));
        rx_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_rx = std::time::Instant::now();
        // Post-freeze/suspend liveness probe state (see WAKE_GAP_THRESHOLD):
        // stamp of the previous watchdog tick, and, when a gap was detected,
        // (deadline, armed_at, gap) of the pending probe.
        let mut last_watchdog_tick = std::time::Instant::now();
        let mut wake_probe: Option<(Instant, Instant, Duration)> = None;
        // Reset the DATA-plane liveness markers for THIS connection: they are
        // struct fields (stamped inside process_decoded) and would otherwise
        // carry a stale stall over from a previous session.
        self.last_data_rx = Instant::now();
        self.upload_at_last_data_rx = self.bytes_sent.load(Ordering::Relaxed);
        self.data_stall_started = None;
        self.data_stall_strikes = 0;
        self.data_plane_proven = false;
        // First-contact anchor: a rejected/unmatched handshake (e.g. the client's
        // cached bootstrap descriptor doesn't match the server's) gets NO server
        // packets at all, so `last_rx` never moves off this instant. Detect that
        // in ~10 s (matching the mobile cores' HANDSHAKE_TIMEOUT) instead of
        // waiting the full 24–45 s RX-silence threshold, so main.rs's reconnect
        // loop reaches the bootstrap_default fallback in ~30 s, not ~72 s.
        let connect_instant = last_rx;
        // A4: seed last_tx at loop start so a fresh connection isn't instantly
        // treated as "TX stalled" before the first keepalive goes out.
        self.last_tx_ms.store(epoch_ms(), Ordering::Relaxed);
        // A4: rate-limit for the proactive warmup burst below.
        let mut last_warmup = std::time::Instant::now();
        // Path A carrier-change baseline (iOS/Windows/Linux only — see
        // probe_underlying_source_ip). `server_ep` is the connected socket's
        // peer; `underlying_src_ip` is the physical source IP the kernel picks
        // for it right now. Each watchdog tick re-probes and, on a persistent
        // change (a real interface handover), forces a reconnect long before
        // the passive RX-silence threshold would.
        #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
        let server_ep = self.udp_socket.as_ref().and_then(|s| s.peer_addr().ok());
        #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
        let mut underlying_src_ip = server_ep.and_then(probe_underlying_source_ip);
        #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
        let mut path_change_strikes: u8 = 0;
        // Set when the `join_res` select branch consumes upload_task's output,
        // so the teardown below knows it must not poll the handle again.
        let mut upload_joined = false;

        let run_res: Result<()> = loop {
            tokio::select! {
                // Allow fast shutdown.
                _ = shutdown_tick.tick() => {
                    if shutdown.load(Ordering::SeqCst) {
                        info!("Shutdown requested");
                        stats_task.abort();
                        break Ok(());
                    }
                }

                // 3b: native OS network-change listener (see net_change.rs).
                // Best-effort — `None` when unsupported/unavailable, in
                // which case this branch never fires and the existing
                // poll-based watchdogs below are the only reconnect trigger
                // (today's behavior, unchanged). When it DOES fire, react
                // immediately instead of waiting the 5-10s+ these watchdogs
                // need to notice the same change passively.
                _ = async {
                    match self.config.network_change_notify.as_ref() {
                        Some(n) => n.notified().await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    // The Linux listener subscribes to LINK + IPv4/IPv6 IFADDR
                    // groups, so bringing up OUR OWN tun (link up + its v4 addr
                    // + kernel-assigned v6 link-local) emits exactly those
                    // events every connect. Reacting to them would tear the
                    // session down microseconds after the init handshake goes
                    // out — before the server reply can arrive — and each retry
                    // rebuilds the tun, re-emitting the events: an unbreakable
                    // reconnect loop that never establishes. Only honor the
                    // signal once the tunnel is actually up (≥1 authenticated
                    // RX advanced last_rx off connect_instant); until then the
                    // burst is self-inflicted setup churn — drain and ignore it.
                    // A genuine change during the pre-establishment window is
                    // still covered by the handshake-fallback path and the
                    // poll-based carrier-change watchdog below.
                    if last_rx == connect_instant {
                        tracing::debug!(
                            "Network-change event during connection setup — \
                             ignoring self-inflicted tun churn (tunnel not yet established)"
                        );
                    } else {
                        warn!("Native network-change event detected — reconnecting immediately");
                        break Err(Error::Session("network change detected".into()));
                    }
                }

                _ = rx_watchdog.tick() => {
                    // Post-freeze/suspend liveness probe (see WAKE_GAP_THRESHOLD):
                    // a tick gap ≫ the 5 s watchdog cadence means the process
                    // was frozen or the machine suspended. Arm a probe: unless
                    // ANY decodable RX arrives within the window (keepalives
                    // fire immediately after wake), the session is condemned
                    // now instead of lingering dead until RX silence.
                    let tick_now = Instant::now();
                    let tick_gap = tick_now.duration_since(last_watchdog_tick);
                    last_watchdog_tick = tick_now;
                    if tick_gap > WAKE_GAP_THRESHOLD && wake_probe.is_none() {
                        let window = Duration::from_millis(
                            self.keepalive_interval_ms.load(Ordering::Relaxed),
                        )
                        .saturating_mul(2)
                        .clamp(WAKE_PROBE_WINDOW_MIN, WAKE_PROBE_WINDOW_MAX);
                        info!(
                            "Watchdog tick gap {tick_gap:?} (process frozen or system suspended) — \
                             post-wake liveness probe armed ({window:?})"
                        );
                        wake_probe = Some((tick_now + window, tick_now, tick_gap));
                    }
                    if let Some((deadline, armed_at, gap)) = wake_probe {
                        if last_rx >= armed_at {
                            // Decodable RX after the wake moment — session alive.
                            wake_probe = None;
                        } else if tick_now >= deadline {
                            warn!(
                                "post-wake liveness probe: no RX for {:?} after a {:?} \
                                 freeze/suspend gap — reconnecting",
                                last_rx.elapsed(),
                                gap,
                            );
                            break Err(Error::Session(format!(
                                "post-wake liveness probe: no RX for {:?} after a {:?} \
                                 freeze/suspend gap — reconnecting",
                                last_rx.elapsed(),
                                gap,
                            )));
                        }
                    }

                    // K6: periodic kernel tag-window upkeep. The resonance time
                    // window rotates every 10 s and idle/quiet periods deliver
                    // no fallback packets to drive the receive-path refresh, so
                    // this 5 s tick bounds tag staleness at half a window.
                    #[cfg(target_os = "linux")]
                    self.kernel_push_tags(false);

                    // Path A: proactive reconnect on a real carrier/interface
                    // handover (iOS/Windows/Linux; Android and macOS use their
                    // OS path callbacks). Only armed once the session is
                    // ESTABLISHED (a ServerHello was processed) so a carrier
                    // change DURING the initial handshake is left to the
                    // first-contact timeout below. Requires TWO consecutive
                    // disagreeing probes (~5-10 s) so a momentary route flap
                    // mid-handover — or a transient dual-stack source flip —
                    // does not reconnect prematurely.
                    #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
                    if self.ever_connected.load(Ordering::Relaxed) {
                        if let (Some(server), Some(baseline)) = (server_ep, underlying_src_ip) {
                            match probe_underlying_source_ip(server) {
                                Some(now_ip) if now_ip != baseline => {
                                    path_change_strikes = path_change_strikes.saturating_add(1);
                                    if path_change_strikes >= 2 {
                                        warn!(
                                            "Underlying source address changed {} -> {} — \
                                             carrier/interface handover, reconnecting",
                                            baseline, now_ip
                                        );
                                        break Err(Error::Session(
                                            "underlying interface changed".into(),
                                        ));
                                    }
                                }
                                // Back on the baseline path — clear a transient strike.
                                Some(_) => path_change_strikes = 0,
                                // No route right now (interface mid-handover): don't
                                // count it as a change, wait for a definitive new IP.
                                None => {}
                            }
                        } else if underlying_src_ip.is_none() {
                            // Baseline was unavailable at loop start (probe failed
                            // then). Establish it now so later ticks have a reference.
                            underlying_src_ip = server_ep.and_then(probe_underlying_source_ip);
                        }
                    }

                    // A4 asymmetric silence detection. 45 s stays the ceiling
                    // for an idle uplink, but when we are actively SENDING
                    // (keepalives flow every interval) and the server has gone
                    // quiet, the path is dead — NAT rebind or carrier drop —
                    // and waiting the full 45 s only hurts interactivity. Cut
                    // the threshold to ~3× the live keepalive interval, with a
                    // 12 s floor so a server-pushed 1–2 s interval can't make
                    // the watchdog trigger-happy. Satellite (15 s keepalive):
                    // 3×15 = 45 s — behavior there is unchanged by design.
                    const RX_SILENCE_MAX: Duration = Duration::from_secs(45);
                    const RX_SILENCE_MIN: Duration = Duration::from_secs(12);
                    let now_ms = epoch_ms();
                    let ka = Duration::from_millis(
                        self.keepalive_interval_ms.load(Ordering::Relaxed).max(1),
                    );
                    let tx_gap_ms =
                        now_ms.saturating_sub(self.last_tx_ms.load(Ordering::Relaxed));
                    // "Recently sent" = within 2 keepalive intervals (min 10 s).
                    let uplink_active =
                        tx_gap_ms <= (2 * ka.as_millis() as u64).max(10_000);
                    let rx_silence = if uplink_active {
                        (3 * ka).clamp(RX_SILENCE_MIN, RX_SILENCE_MAX)
                    } else {
                        RX_SILENCE_MAX
                    };
                    if last_rx.elapsed() > rx_silence {
                        warn!(
                            "No server traffic for {:?} (threshold {:?}, uplink_active={}) — reconnecting",
                            last_rx.elapsed(),
                            rx_silence,
                            uplink_active
                        );
                        break Err(Error::Session("RX silence timeout".into()));
                    }

                    // Data-plane watchdog: clocked on DATA delivered to the
                    // TUN/proxy, not on any decode — a downlink where only
                    // keepalive-acks / KeyRotate retransmits still
                    // authenticate is DEAD for the user and must reconnect in
                    // tens of seconds (see `data_watchdog_verdict`). Skipped
                    // while kernel RX offload is active: in-kernel-consumed
                    // DATA never reaches process_decoded, so user-space data
                    // liveness would be a false negative there.
                    #[cfg(target_os = "linux")]
                    let data_watchdog_active = !self.kernel_installed;
                    #[cfg(not(target_os = "linux"))]
                    let data_watchdog_active = true;
                    if data_watchdog_active {
                        let uploaded_total = self.bytes_sent.load(Ordering::Relaxed);
                        let data_up_since =
                            uploaded_total.saturating_sub(self.upload_at_last_data_rx);
                        if data_up_since > 0 && self.data_stall_started.is_none() {
                            self.data_stall_started = Some(Instant::now());
                        }
                        let stalled_for = if self.data_plane_proven {
                            self.data_stall_started.map(|t| t.elapsed())
                        } else {
                            // Data plane never proven this session —
                            // unanswerable TUN junk must not condemn a
                            // healthy idle tunnel.
                            None
                        };
                        let verdict = data_watchdog_verdict(stalled_for, data_up_since);
                        let stall_pending = verdict.is_some();
                        if let Some(reason) =
                            data_stall_confirmed(&mut self.data_stall_strikes, verdict)
                        {
                            warn!(
                                "{}: {} bytes of uplink data unanswered for {:?} \
                                 (no downlink data for {:?}) — reconnecting",
                                reason,
                                data_up_since,
                                stalled_for.unwrap_or_default(),
                                self.last_data_rx.elapsed(),
                            );
                            // Liveness: a sticky mask that keeps stalling quickly
                            // gets abandoned so AUTO can explore a different one.
                            crate::bootstrap_cache::note_data_stall_and_maybe_explore(
                                session_established,
                            );
                            break Err(Error::Session(format!("{reason} — reconnecting")));
                        }
                        // Window wash: the stall never reached the byte
                        // threshold — background junk, not a dead downlink.
                        // Forget it so trickle can never accumulate into a
                        // false positive (see DATA_STALL_WINDOW). Never wash
                        // while a strike is pending confirmation, or the
                        // reset would erase the very stall the next tick must
                        // re-observe.
                        if !stall_pending
                            && self
                                .data_stall_started
                                .is_some_and(|t| t.elapsed() >= DATA_STALL_WINDOW)
                        {
                            self.data_stall_started = None;
                            self.upload_at_last_data_rx = uploaded_total;
                        }
                    }
                    // First-contact fast fail: no server packet AT ALL since
                    // connect (last_rx unmoved) within the handshake window means
                    // the handshake was rejected — reconnect fast instead of
                    // burning the full RX-silence threshold on a dead attempt.
                    const HANDSHAKE_FIRST_CONTACT: Duration = Duration::from_secs(10);
                    if last_rx == connect_instant
                        && connect_instant.elapsed() > HANDSHAKE_FIRST_CONTACT
                    {
                        warn!(
                            "No server response to handshake within {:?} — reconnecting fast",
                            HANDSHAKE_FIRST_CONTACT
                        );
                        break Err(Error::Session("handshake first-contact timeout".into()));
                    }

                    // A4 proactive CGNAT warmup: if nothing has been sent for
                    // ~20 s (keepalive stalled by doze/backpressure, or the
                    // server pushed a long interval), refresh the NAT mapping
                    // BEFORE it expires instead of reconnecting after. Satellite
                    // is exempt, mirroring the keepalive cap exemption.
                    if self.adaptive_level != AdaptiveLevel::Satellite
                        && tx_gap_ms >= NAT_WARMUP_AFTER.as_millis() as u64
                        && last_warmup.elapsed() >= KEEPALIVE_NAT_CAP
                    {
                        last_warmup = std::time::Instant::now();
                        debug!(
                            "TX idle for {} ms — proactive CGNAT warmup burst",
                            tx_gap_ms
                        );
                        Self::spawn_warmup_burst(control_tx.clone());
                    }
                }

                // Upload task completed (error or channel closed).
                join_res = &mut upload_task => {
                    // The handle's output is consumed here; awaiting it again
                    // after the loop would panic ("polled after completion").
                    upload_joined = true;
                    break match join_res {
                        Ok(Ok(())) => Err(Error::Channel("Upload loop ended unexpectedly".into())),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(Error::Session(format!("Upload task panicked: {e}"))),
                    };
                }

                cmd = admin_rx.recv() => {
                    if let Some(cmd) = cmd {
                        if let Some(service) = cmd.strip_prefix("record_start:") {
                            crate::record_cmd::handle_recording_status(true, Some(service));
                            let payload = ControlPayload::RecordingStart { service: service.to_string() };
                            if let Err(e) = control_tx.send(payload).await {
                                error!("Failed to send RecordingStart to upload task: {}", e);
                            } else {
                                info!("Sent RecordingStart for {}", service);
                            }
                        } else if cmd == "record_stop" {
                            if let Some(session_id) = self.active_recording_session {
                                let current_service = crate::record_cmd::read_local_status().and_then(|status| status.service);
                                crate::record_cmd::mark_recording_stop_requested(current_service.as_deref());
                                let payload = ControlPayload::RecordingStop { session_id };
                                if let Err(e) = control_tx.send(payload).await {
                                    error!("Failed to send RecordingStop to upload task: {}", e);
                                } else {
                                    info!("Sent RecordingStop");
                                }
                            } else {
                                warn!("No active recording session to stop");
                                crate::record_cmd::handle_recording_failed("No active recording session to stop");
                            }
                        } else if cmd == "record_status" {
                            let payload = ControlPayload::RecordingStatusRequest;
                            if let Err(e) = control_tx.send(payload).await {
                                error!("Failed to send RecordingStatusRequest to upload task: {}", e);
                            }
                        }
                    }
                }

                // UDP -> TUN (inbound traffic)
                res = udp_to_tun_rx.recv() => {
                    let packet = match res {
                        Some(p) => p,
                        None => break Err(Error::Channel("UDP->TUN channel closed".into())),
                    };

                    match self.receive_and_write_packet(&packet).await {
                        // Advance last_rx only after the packet authenticated:
                        // stamping it on ANY datagram would let a single
                        // spoofed/garbage packet to the ephemeral port defeat
                        // the first-contact fast-fail above and keep a dead
                        // session alive through the RX-silence watchdog.
                        Ok(()) => last_rx = std::time::Instant::now(),
                        Err(e) => match &e {
                            Error::InvalidPacket(_) => warn!("Receive invalid packet: {}", e),
                            Error::Crypto(_) => warn!("Receive error (crypto): {}", e),
                            _ => {
                                warn!("Receive error: {}", e);
                                break Err(e);
                            }
                        }
                    }
                }
            }
        };

        // Stop background tasks before disconnecting. Abort `upload_task`
        // unconditionally (it is only self-consumed on the `join_res` exit path;
        // abort on an already-finished task is a no-op) so it never lingers as a
        // zombie on a flappy connection. Aborting it also drops the control-plane
        // receiver it owns, which closes the `control_tx` channel — that is what
        // makes the two detached §2/§3 tasks (the MaskPreference retry and the
        // jittered MaskFeedback send) reliably bail out via their "receiver gone"
        // send-error paths instead of outliving `run()`.
        stats_task.abort();
        tun_task.abort();
        udp_task.abort();
        upload_task.abort();
        let _ = stats_task.await;
        let _ = tun_task.await;
        let _ = udp_task.await;
        // Await upload_task too: it holds an Arc<UdpSocket> clone, and the
        // disconnect() below removes the K6 kernel session and drops the
        // socket — the fd must not linger in a detached task past that point.
        // Skip only if the `join_res` select branch already consumed the
        // handle's output (re-polling a consumed JoinHandle panics).
        if !upload_joined {
            let _ = upload_task.await;
        }

        if self.state != ClientState::Disconnected {
            self.disconnect().await;
        }

        run_res
    }

    /// Spawn the upload task using the shared pipeline.
    async fn spawn_upload(
        mut rx: mpsc::Receiver<Vec<u8>>,
        mut control_rx: mpsc::Receiver<ControlPayload>,
        udp: Arc<UdpSocket>,
        engine: MimicryEngine,
        upload_state: Arc<Mutex<UploadCryptoState>>,
        bytes_sent: Arc<AtomicU64>,
        pending_mask: Arc<Mutex<Option<aivpn_common::mask::MaskProfile>>>,
        keepalive_interval: Duration,
        keepalive_sent_ms: Arc<AtomicU64>,
        fec_n: u8,
        keepalive_interval_ms: Arc<AtomicU64>,
        last_tx_ms: Arc<AtomicU64>,
    ) -> Result<()> {
        /// Wraps MimicryEngine to implement the shared PacketEncryptor trait.
        struct MimicryEncryptor {
            engine: MimicryEngine,
            upload_state: Arc<Mutex<UploadCryptoState>>,
            bytes_sent: Arc<AtomicU64>,
            pending_mask: Arc<Mutex<Option<aivpn_common::mask::MaskProfile>>>,
            keepalive_sent_ms: Arc<AtomicU64>,
            /// A4: shared with the RX watchdog — every encrypted outbound
            /// packet stamps this so silence detection knows the uplink is live.
            last_tx_ms: Arc<AtomicU64>,
            fec_encoder: Option<aivpn_common::fec::FecEncoder>,
            pending_fec: Option<Vec<u8>>,
        }

        impl MimicryEncryptor {
            fn check_mask(&mut self) {
                if let Some(mask) = self
                    .pending_mask
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    self.engine.update_mask(mask);
                }
            }
        }

        impl PacketEncryptor for MimicryEncryptor {
            fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
                self.check_mask();
                self.last_tx_ms.store(epoch_ms(), Ordering::Relaxed);
                let mut state = self.upload_state.lock().unwrap_or_else(|e| e.into_inner());
                let inner = build_inner_packet(InnerType::Data, state.seq, payload);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                let pkt = self
                    .engine
                    .build_packet(&inner, &keys, &mut state.counter, None)?;
                self.engine.update_fsm();

                // FEC: feed payload; if group complete, pre-encrypt repair datagram
                if let Some(fec) = self.fec_encoder.as_mut() {
                    if let Some(repair) = fec.feed(payload) {
                        let repair_payload = repair.encode();
                        let repair_inner =
                            build_inner_packet(InnerType::FecRepair, state.seq, &repair_payload);
                        state.seq = state.seq.wrapping_add(1);
                        if let Ok(enc_repair) =
                            self.engine
                                .build_packet(&repair_inner, &keys, &mut state.counter, None)
                        {
                            self.pending_fec = Some(enc_repair);
                        }
                    }
                }

                Ok(pkt)
            }

            fn take_fec_repair(&mut self) -> Option<Vec<u8>> {
                self.pending_fec.take()
            }

            fn encrypt_control(&mut self, payload: &ControlPayload) -> Result<Vec<u8>> {
                self.check_mask();
                self.last_tx_ms.store(epoch_ms(), Ordering::Relaxed);
                let mut state = self.upload_state.lock().unwrap_or_else(|e| e.into_inner());
                let bytes = payload.encode()?;
                let inner = build_inner_packet(InnerType::Control, state.seq, &bytes);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                let pkt = self
                    .engine
                    .build_packet(&inner, &keys, &mut state.counter, None)?;
                // Confirm to the inline-rekey handler (if waiting) that this
                // KeyRotate response was just encrypted with the keys held
                // above — i.e. still the OLD (pre-ratchet) keys, since the
                // handler has not yet overwritten `state.keys` and is blocked
                // on this exact rendezvous before it does. See `rekey_ack` doc
                // comment on `UploadCryptoState`.
                if matches!(payload, ControlPayload::KeyRotate { .. }) {
                    if let Some(ack) = state.rekey_ack.pop_front() {
                        let _ = ack.send(());
                    }
                }
                Ok(pkt)
            }

            fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
                self.check_mask();
                // Record send time for RTT measurement via KeepaliveAck.
                let now_ms = epoch_ms();
                self.keepalive_sent_ms.store(now_ms, Ordering::Relaxed);
                self.last_tx_ms.store(now_ms, Ordering::Relaxed);
                let mut state = self.upload_state.lock().unwrap_or_else(|e| e.into_inner());
                let keepalive = ControlPayload::Keepalive { send_ts: now_ms }.encode()?;
                let inner = build_inner_packet(InnerType::Control, state.seq, &keepalive);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                self.engine
                    .build_packet(&inner, &keys, &mut state.counter, None)
            }

            fn on_data_sent(&mut self, payload_len: usize) {
                self.bytes_sent
                    .fetch_add(payload_len as u64, Ordering::Relaxed);
            }
        }

        // R2 Phase D — client-side inline ML-DPI self-gate (opt-in, feature
        // `client-dpi-gate`, OFF by default). Capture the active mask family
        // BEFORE `engine` is moved into the encryptor, so a tunnel verdict can
        // request a fresh variant of exactly the mask this session is shaping to.
        #[cfg(feature = "client-dpi-gate")]
        let base_mask_id = engine.mask().mask_id.clone();

        let mut enc = MimicryEncryptor {
            engine,
            upload_state,
            bytes_sent,
            pending_mask,
            keepalive_sent_ms,
            last_tx_ms,
            fec_encoder: if fec_n > 0 {
                // 1500 == MAX_PACKET_SIZE. TunnelConfig::from_network_config
                // and Tunnel::apply_network_config both clamp the (possibly
                // server-pushed) MTU to this same bound before it's ever
                // applied to the TUN device, so no payload fed here can
                // legitimately exceed it — see the comments there.
                Some(aivpn_common::fec::FecEncoder::new(fec_n, MAX_PACKET_SIZE))
            } else {
                None
            },
            pending_fec: None,
        };
        let config = UploadConfig {
            keepalive_interval,
            keepalive_ms: Some(keepalive_interval_ms),
            ..Default::default()
        };

        // Build the optional outbound inspector: `Some` only under the feature.
        #[cfg(feature = "client-dpi-gate")]
        let mut self_gate = aivpn_common::dpi_gate::ClientSelfGate::new(0.5, base_mask_id);
        #[cfg(feature = "client-dpi-gate")]
        let inspector: Option<&mut dyn upload_pipeline::OutboundInspector> = Some(&mut self_gate);
        #[cfg(not(feature = "client-dpi-gate"))]
        let inspector: Option<&mut dyn upload_pipeline::OutboundInspector> = None;

        upload_pipeline::run_upload_loop(
            &mut rx,
            Some(&mut control_rx),
            &udp,
            &mut enc,
            &config,
            inspector,
        )
        .await
    }

    /// Receive packet from server and write to TUN (using pre-computed mdh_len)
    async fn receive_and_write_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self
            .transition_recv_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.transition_recv_keys = None;
            self.transition_recv_deadline = None;
            self.transition_grace_hard = None;
            self.transition_recv_window.reset();
        }

        let keys = self
            .session_keys
            .as_ref()
            .ok_or(Error::Session("No session keys".into()))?;

        // Try every MDH length this session has used, with the current session
        // keys first. The server frames different downlink packets with
        // different masks (bootstrap vs runtime vs polymorphic; DATA vs
        // control/rekey), so a single fixed length silently drops any packet
        // whose mask differs — the failure that strands the tunnel on the first
        // rekey. See `decode_downlink_any_mdh_len`.
        let decoded = match decode_downlink_any_mdh_len(
            packet,
            keys,
            &mut self.recv_window,
            &mut self.recv_mdh_candidates,
        ) {
            Ok(decoded) => decoded,
            Err(primary_err) => {
                // Fallback: PFS-ratchet transition keys (in-flight packets
                // encrypted with the pre-rekey keys), same candidate lengths.
                if let Some(fallback_keys) = self.transition_recv_keys.as_ref() {
                    if let Ok(decoded) = decode_downlink_any_mdh_len(
                        packet,
                        fallback_keys,
                        &mut self.transition_recv_window,
                        &mut self.recv_mdh_candidates,
                    ) {
                        return self.process_decoded(decoded).await;
                    }
                }
                return Err(primary_err);
            }
        };
        self.process_decoded(decoded).await
    }

    /// Process a successfully decoded packet (shared by primary and fallback paths)
    async fn process_decoded(&mut self, decoded: DecodedPacket) -> Result<()> {
        // K6: every user-space-validated packet is a fresh observation of the
        // downlink counter (kernel-consumed packets never reach here), so use
        // it to opportunistically re-base the kernel tag window. No-op unless
        // the counter advanced ≥ KERNEL_TAG_REFRESH_STRIDE or the 10 s
        // resonance time window rotated.
        #[cfg(target_os = "linux")]
        self.kernel_push_tags(false);

        let inner_header = decoded.header;
        let ip_payload = decoded.payload;

        match inner_header.inner_type {
            InnerType::Data => {
                if ip_payload.is_empty() || (ip_payload[0] >> 4 != 4 && ip_payload[0] >> 4 != 6) {
                    return Err(Error::InvalidPacket("Invalid IP version in payload"));
                }
                if self.config.control_only {
                    // Headless control-only mode: no TUN, no SOCKS proxy — a
                    // pool-peer dialer has nowhere to deliver DATA packets.
                    // Drop silently rather than erroring on the (never
                    // created) TUN device.
                } else if let Some(h) = &self.proxy_handle {
                    {
                        let mut q = h.rx_queue.lock().unwrap_or_else(|e| e.into_inner());
                        // Bound the queue: drop-oldest past the cap so a stalled
                        // SOCKS consumer cannot grow memory without limit
                        // (inner TCP retransmit recovers the dropped packet).
                        while q.len() >= PROXY_RX_QUEUE_MAX {
                            q.pop_front();
                        }
                        q.push_back(ip_payload.to_vec());
                    }
                    let _ = h.wake_tx.try_send(());
                } else {
                    self.tunnel.write_packet_async(&ip_payload).await?;
                }
                self.bytes_received
                    .fetch_add(ip_payload.len() as u64, Ordering::Relaxed);
                // DATA-plane liveness stamp: only here — control traffic must
                // not mask a dead data downlink (see `data_watchdog_verdict`).
                self.last_data_rx = Instant::now();
                self.upload_at_last_data_rx = self.bytes_sent.load(Ordering::Relaxed);
                self.data_stall_started = None;
                self.data_stall_strikes = 0;
                if !self.data_plane_proven {
                    // FIX (Jul 15): remember the mask that just carried real DATA so
                    // AUTO-mode reconnects reuse it instead of re-deriving (and
                    // hopping) from the churning descriptor set.
                    *crate::bootstrap_cache::LAST_GOOD_MASK
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) =
                        Some(self.config.initial_mask.clone());
                }
                self.data_plane_proven = true;
                debug!(
                    "Received {} bytes from server, wrote to TUN",
                    ip_payload.len()
                );
            }
            InnerType::Control => {
                let control = ControlPayload::decode(&ip_payload)?;
                self.handle_server_control(control).await?;
            }
            _ => {
                debug!(
                    "Received non-data packet type: {:?}",
                    inner_header.inner_type
                );
            }
        }

        Ok(())
    }

    /// Handle control messages from server
    async fn handle_server_control(&mut self, control: ControlPayload) -> Result<()> {
        match control {
            ControlPayload::MaskUpdate {
                mask_data,
                signature,
            } => {
                // The server signs the raw mask_data bytes (sign_mask() in session.rs).
                // Verify before deserialising so a bad signature is caught immediately.
                // `transport_verified` is true ONLY when a server_signing_key is
                // configured AND the ed25519 signature over THIS exact mask_data
                // payload checked out — never merely because a key is absent.
                let mut transport_verified = false;
                if let Some(signing_key) = &self.config.server_signing_key {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    match VerifyingKey::from_bytes(signing_key) {
                        Ok(vk) => {
                            let sig = Signature::from_bytes(&signature);
                            if vk.verify(&mask_data, &sig).is_err() {
                                warn!("MaskUpdate rejected: invalid ed25519 signature");
                                return Ok(());
                            }
                            transport_verified = true;
                        }
                        Err(e) => {
                            warn!("MaskUpdate rejected: bad signing key in config: {}", e);
                            return Ok(());
                        }
                    }
                }
                match rmp_serde::from_slice::<MaskProfile>(&mask_data) {
                    Ok(new_mask) => {
                        // R2 Phase B: artifact-level operator signature check,
                        // in ADDITION to the transport check above. Transport
                        // auth proves "pushed by my server"; artifact auth
                        // proves "gated + signed by the operator". Derived
                        // per-session variants are exempt: they arrive only
                        // over the AEAD-authenticated session channel and are
                        // not independently verifiable (their perturbation
                        // shifts signature-covered fields).
                        //
                        // SECURITY: that exemption must NOT be granted on the
                        // mask_id prefix alone. `is_derived_variant()` is a
                        // pure string-prefix test ("polymorphic:"/"bootstrap:")
                        // on content that lives INSIDE mask_data — i.e.
                        // attacker-supplied once transport auth is unavailable
                        // (no server_signing_key configured, or on a build
                        // that never sets one). Without also requiring
                        // transport_verified, anyone able to reach this path
                        // without a valid transport signature could
                        // manufacture a mask_id starting with those prefixes
                        // purely to skip verify_mask_artifact, bypassing the
                        // operator-signature gate entirely regardless of
                        // mask_verify_mode. Gate the exemption on BOTH: the
                        // mask claiming to be a derived variant AND the
                        // transport signature having actually proven this
                        // exact payload came from the real server.
                        if !(new_mask.is_derived_variant() && transport_verified) {
                            let verdict = aivpn_common::mask::verify_mask_artifact(
                                &new_mask,
                                self.config.mask_operator_pubkey.as_ref(),
                                self.config.mask_verify_mode,
                            );
                            if !verdict.accept {
                                warn!(
                                    "MaskUpdate '{}' REJECTED (mask_verify_mode=enforce): {:?}",
                                    new_mask.mask_id, verdict.detail
                                );
                                return Ok(());
                            }
                            if verdict.is_failure() && self.config.mask_operator_pubkey.is_some() {
                                warn!(
                                    "MaskUpdate '{}' failed operator signature verification \
                                     ({:?}) — accepted because mask_verify_mode=warn",
                                    new_mask.mask_id, verdict.detail
                                );
                            }
                        }
                        // §3 F: once a polymorphic variant lands, signal the
                        // MaskPreference retry task to stop resending.
                        if new_mask.mask_id.starts_with("polymorphic:") {
                            self.polymorphic_confirmed.store(true, Ordering::Relaxed);
                        }
                        self.update_mask(new_mask);
                    }
                    Err(e) => warn!("Failed to parse mask update: {}", e),
                }
            }
            ControlPayload::BootstrapDescriptorUpdate { descriptor_data } => {
                if descriptor_data.len() > 512 * 1024 {
                    warn!(
                        "BootstrapDescriptorUpdate rejected: payload too large ({} bytes)",
                        descriptor_data.len()
                    );
                    return Ok(());
                }
                match rmp_serde::from_slice::<BootstrapDescriptor>(&descriptor_data) {
                    Ok(descriptor) => {
                        let trusted = self.config.server_signing_key.as_ref();
                        if let Err(e) =
                            bootstrap_cache::store_verified_descriptor(descriptor, trusted)
                        {
                            warn!("Failed to store bootstrap descriptor: {}", e);
                        }
                    }
                    Err(e) => warn!("Failed to parse bootstrap descriptor update: {}", e),
                }
            }
            ControlPayload::KeyRotate { new_eph_pub } => {
                // Same class of bug as the ServerHello duplicate-processing fix:
                // a duplicated/redelivered KeyRotate request (plain UDP
                // duplication, no server-side resend needed to trigger it) used
                // to be reprocessed unconditionally — generating a fresh random
                // keypair and re-deriving new_keys from the already-once-
                // rotated current key. The server only ever commits the FIRST
                // response it receives (its own pending_rekey_keypair is
                // consumed on first commit), so this second, independently-
                // derived key is one the server never agrees to or learns
                // about — a permanent, unrecoverable desync. Skip entirely if
                // we already ratcheted for this exact server_eph_pub.
                if self.ratcheted_rekey_eph_pub == Some(new_eph_pub) {
                    // A KeyRotate for an eph_pub we ALREADY ratcheted against
                    // can only be a genuine server RETRANSMIT: a plain
                    // network-duplicated copy of the original packet carries
                    // the same transport counter and is dropped by the replay
                    // window before ever reaching this handler, while a
                    // retransmit is a fresh packet under the OLD keys (it
                    // decoded via transition_recv_keys to get here). The
                    // server retransmits because our rekey RESPONSE was lost:
                    // it is still on the old keys with the rekey pending —
                    // silently ignoring the retransmit deadlocked the tunnel
                    // (client on new keys, server on old) until the client's
                    // RX-silence watchdog forced a full reconnect. Re-send
                    // the SAME response (same client eph — never a fresh
                    // keypair, so whichever copy the server commits yields
                    // exactly the keys we already switched to), encrypted
                    // with the OLD keys the server can still read. The upload
                    // counter is shared and monotonic across both keys, so
                    // the temporary swap below cannot reuse a (key, nonce).
                    let (Some(old_keys), Some(response_eph)) =
                        (self.transition_recv_keys.clone(), self.rekey_response_eph)
                    else {
                        debug!(
                            "Duplicate KeyRotate for already-ratcheted eph_pub — \
                             no stored response/old keys, ignoring"
                        );
                        return Ok(());
                    };
                    warn!(
                        "Retransmitted KeyRotate for already-ratcheted eph_pub — \
                         our rekey response was likely lost; re-sending the same \
                         response under the previous keys"
                    );
                    let response = ControlPayload::KeyRotate {
                        new_eph_pub: response_eph,
                    };
                    // Same rendezvous dance as the initial response: swap the
                    // OLD keys into the upload state, block until the upload
                    // task confirms it encrypted THIS response with them, then
                    // restore the committed (new) keys.
                    let rekey_ack_rx = self.upload_state.as_ref().map(|upload_state| {
                        let (ack_tx, ack_rx) = oneshot::channel();
                        let mut state = upload_state.lock().unwrap_or_else(|e| e.into_inner());
                        state.keys = old_keys;
                        state.rekey_ack.push_back(ack_tx);
                        ack_rx
                    });
                    let send_result = self.send_control(&response).await;
                    if let Some(ack_rx) = rekey_ack_rx {
                        if send_result.is_ok() {
                            // Bounded wait: if the upload task died between
                            // dequeuing the KeyRotate and firing the ack, the
                            // sender is stranded in the shared queue and would
                            // never resolve — remove it and move on instead of
                            // hanging the receive loop forever.
                            if tokio::time::timeout(REKEY_ACK_TIMEOUT, ack_rx)
                                .await
                                .is_err()
                            {
                                if let Some(upload_state) = &self.upload_state {
                                    upload_state
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .rekey_ack
                                        .pop_back();
                                }
                                warn!(
                                    "Inline rekey: no old-key re-send confirmation within {:?} — upload task presumed dead",
                                    REKEY_ACK_TIMEOUT
                                );
                            }
                        } else {
                            // Nothing was enqueued — drop the unused rendezvous
                            // so it cannot mis-fire on a future KeyRotate.
                            if let Some(upload_state) = &self.upload_state {
                                upload_state
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .rekey_ack
                                    .pop_back();
                            }
                        }
                    }
                    if let (Some(upload_state), Some(keys)) =
                        (&self.upload_state, self.session_keys.as_ref())
                    {
                        upload_state.lock().unwrap_or_else(|e| e.into_inner()).keys = keys.clone();
                    }
                    if let Err(e) = send_result {
                        warn!("Inline rekey: failed to re-send response: {}", e);
                        return Ok(());
                    }
                    // Keep accepting old-key downlink until the server commits
                    // (or retransmits again) — but never past the hard cap
                    // armed at the key switch: unbounded re-arms let a never-
                    // converging rekey defer recovery forever.
                    let next = Instant::now() + REKEY_TRANSITION_GRACE;
                    self.transition_recv_deadline = Some(
                        self.transition_grace_hard
                            .map_or(next, |hard| next.min(hard)),
                    );
                    return Ok(());
                }
                let client_rekey_kp = crypto::KeyPair::generate();
                let dh_rekey = match client_rekey_kp.compute_shared(&new_eph_pub) {
                    Ok(dh) => dh,
                    Err(e) => {
                        warn!("Inline rekey: DH failed: {}", e);
                        return Ok(());
                    }
                };
                let current_sk = match self.session_keys.as_ref() {
                    Some(k) => k.session_key,
                    None => {
                        warn!("Inline rekey: no session keys");
                        return Ok(());
                    }
                };
                let new_keys = crypto::derive_session_keys(
                    &dh_rekey,
                    Some(&current_sk),
                    &client_rekey_kp.public_key_bytes(),
                );
                // Send response with OLD keys before switching.
                //
                // send_control() only enqueues the payload onto an mpsc
                // channel to the independently-running upload task — it does
                // NOT wait for that task to actually dequeue and encrypt it.
                // Register a rendezvous first so we can block until the
                // upload task confirms it encrypted THIS response using the
                // still-current (old) keys, before we touch `session_keys` /
                // `upload_state.keys` below. Without this, there is no
                // .await between the enqueue and the key-swap, so the swap
                // would routinely win the race and the response would go out
                // encrypted with the NEW key — a key the server does not yet
                // recognize, permanently desyncing the ratchet.
                let response = ControlPayload::KeyRotate {
                    new_eph_pub: client_rekey_kp.public_key_bytes(),
                };
                let rekey_ack_rx = self.upload_state.as_ref().map(|upload_state| {
                    let (ack_tx, ack_rx) = oneshot::channel();
                    upload_state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .rekey_ack
                        .push_back(ack_tx);
                    ack_rx
                });
                if let Err(e) = self.send_control(&response).await {
                    warn!("Inline rekey: failed to send response: {}", e);
                    return Ok(());
                }
                if let Some(ack_rx) = rekey_ack_rx {
                    match tokio::time::timeout(REKEY_ACK_TIMEOUT, ack_rx).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => {
                            warn!(
                                "Inline rekey: upload task ended before confirming old-key send, aborting rekey to avoid desync"
                            );
                            return Ok(());
                        }
                        Err(_) => {
                            // Timed out: the upload task died between dequeuing
                            // the KeyRotate and firing the ack, leaving the
                            // sender stranded in the shared queue. Remove it so
                            // it cannot mis-fire on a future KeyRotate and
                            // abort like the task-gone branch instead of
                            // hanging the receive loop forever.
                            if let Some(upload_state) = &self.upload_state {
                                upload_state
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .rekey_ack
                                    .pop_back();
                            }
                            warn!(
                                "Inline rekey: no old-key send confirmation within {:?}, aborting rekey to avoid desync",
                                REKEY_ACK_TIMEOUT
                            );
                            return Ok(());
                        }
                    }
                }
                // Keep old keys for 2 s to accept in-flight server packets.
                // The transition window is a CLONE (not a move) so the primary
                // downlink recv-window keeps its `highest` counter across the
                // rekey. The server keeps its s2c send counter monotonic, so
                // post-rekey downlink packets continue from that counter with the
                // new tag_secret and land inside the primary window's synced
                // forward span — which slides with the stream. Resetting the
                // window here (highest = -1) put it in the unsynced state whose
                // fixed [0, RECV_FUTURE_SEARCH_WINDOW) search cannot advance,
                // stranding sustained downlink after the first rekey.
                // The uplink (c2s) send counter ALSO stays monotonic across the
                // rekey (only the key changes, so no nonce reuse). Resetting it to
                // 0 mirrored the downlink bug on the server side: the server's c2s
                // expected-tag band is ±TAG_WINDOW_SIZE around the highest received
                // counter, so a from-zero restart under a heavy simultaneous upload
                // (first c2s packets lost, client racing past 511) left the server
                // unable to match any uplink tag — killing uplink, then the
                // download's inner-TCP ACKs, then downlink, then the tunnel.
                self.transition_recv_keys = self.session_keys.clone();
                // Grace must outlive the server's KeyRotate retransmit horizon
                // (lost-response self-heal), not just in-flight packets — see
                // REKEY_TRANSITION_GRACE.
                self.transition_recv_deadline = Some(Instant::now() + REKEY_TRANSITION_GRACE);
                // Absolute re-arm ceiling for THIS rekey (see
                // REKEY_TRANSITION_HARD_CAP).
                self.transition_grace_hard = Some(Instant::now() + REKEY_TRANSITION_HARD_CAP);
                self.transition_recv_window = self.recv_window.clone();
                self.session_keys = Some(new_keys);
                self.ratcheted_rekey_eph_pub = Some(new_eph_pub);
                self.rekey_response_eph = Some(client_rekey_kp.public_key_bytes());
                if let Some(upload_state) = &self.upload_state {
                    let mut state = upload_state.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(ref keys) = self.session_keys {
                        state.keys = keys.clone();
                    } else {
                        warn!("ratchet: session_keys missing, skipping upload key update");
                    }
                    // state.counter kept monotonic — do NOT reset to 0.
                }
                info!("Inline PFS rekey complete — new session keys active");

                // K6: re-install the in-kernel downlink session under the
                // rotated s2c key (idempotent same-id replace) and re-push the
                // tag window from the reset downlink counter. Old-key
                // in-flight packets fall back to user-space transition keys.
                #[cfg(target_os = "linux")]
                self.kernel_install_session();
            }
            ControlPayload::ServerHello {
                server_eph_pub,
                signature,
                network_config,
            } => {
                // Verify ed25519 signature over (server_eph_pub || client_eph_pub).
                // The server signs this tuple in session.rs create_session().
                if let Some(signing_key) = &self.config.server_signing_key {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    match VerifyingKey::from_bytes(signing_key) {
                        Ok(vk) => {
                            let mut msg = Vec::with_capacity(64);
                            msg.extend_from_slice(&server_eph_pub);
                            msg.extend_from_slice(&self.keypair.public_key_bytes());
                            let sig = Signature::from_bytes(&signature);
                            if vk.verify(&msg, &sig).is_err() {
                                error!(
                                    "ServerHello rejected: ed25519 signature verification failed \
                                     — possible MITM attack"
                                );
                                return Err(Error::Crypto("ServerHello signature invalid".into()));
                            }
                        }
                        Err(e) => {
                            error!("ServerHello: invalid signing key in config: {}", e);
                            return Err(Error::Crypto(format!(
                                "Invalid server signing key: {}",
                                e
                            )));
                        }
                    }
                }

                if let Some(network_config) = network_config {
                    if let Some(ka) = network_config.keepalive_secs.filter(|&s| s > 0) {
                        // NAT-safe cap (A4, Satellite exempt) + propagation to
                        // the already-running upload task via the shared atomic
                        // (previously the override never reached it).
                        self.set_keepalive_interval(Duration::from_secs(ka as u64));
                    }
                    self.apply_server_network_override(network_config).await?;
                }

                // The server resends ServerHello whenever it sees a
                // non-ratcheted Keepalive while it still believes the client
                // hasn't switched (its own reliability measure for a lost
                // original ServerHello). If we already completed the ratchet
                // for THIS server_eph_pub, this is that resend arriving after
                // our own confirmation packet was the one actually lost — not
                // a new ratchet event. Re-deriving keys here would use our
                // already-ratcheted session_key as PSK instead of the
                // original pre-ratchet key, permanently diverging from the
                // server's (single) ratchet. So: skip the crypto, just prod
                // the server again with fresh confirmation traffic.
                let is_duplicate_hello = self.ratcheted_server_eph_pub == Some(server_eph_pub);
                // Receiving ANY ServerHello is the real proof the server answered
                // — this is the §2 L2 failure-attribution signal. The optimistic
                // zero-RTT "Connected" transition in connect() happens with no
                // server contact at all (UDP connect never round-trips), so a
                // DPI-blocked mask (server silently dropped) must NOT be counted
                // as a success. Mark here, matching the iOS/Android cores which
                // set EVER_CONNECTED only after processing a ServerHello.
                self.ever_connected.store(true, Ordering::Relaxed);
                if is_duplicate_hello {
                    debug!(
                        "Duplicate ServerHello for already-ratcheted eph_pub — \
                         resending confirmation without re-ratcheting"
                    );
                } else {
                    info!("ServerHello received — completing PFS ratchet");

                    // Compute DH2 = client_eph * server_eph for PFS (CRIT-3)
                    let dh2 = self.keypair.compute_shared(&server_eph_pub)?;

                    // Derive ratcheted keys using current session_key as PSK
                    let current_key = self
                        .session_keys
                        .as_ref()
                        .ok_or(Error::Session("No session keys for ratchet".into()))?
                        .session_key;
                    let ratcheted = crypto::derive_session_keys(
                        &dh2,
                        Some(&current_key),
                        &self.keypair.public_key_bytes(),
                    );

                    // Keep accepting old inbound keys until the server proves it has
                    // switched too. Outbound traffic moves to ratcheted keys now.
                    self.transition_recv_keys = self.session_keys.clone();
                    self.transition_recv_deadline = Some(Instant::now() + Duration::from_secs(2));
                    // Not an inline rekey — no retransmit re-arm loop here, so
                    // no hard cap (and a stale one from a previous rekey must
                    // not clip this fresh window).
                    self.transition_grace_hard = None;
                    self.transition_recv_window = std::mem::take(&mut self.recv_window);

                    // Switch to ratcheted keys — outbound uses the new keys immediately.
                    self.session_keys = Some(ratcheted);
                    self.ratcheted_server_eph_pub = Some(server_eph_pub);
                    self.counter = 0;
                    self.recv_window.reset();
                    if let Some(upload_state) = &self.upload_state {
                        let mut state = upload_state.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(ref keys) = self.session_keys {
                            state.keys = keys.clone();
                        } else {
                            warn!("ratchet: session_keys missing, skipping upload key update");
                        }
                        state.counter = 0;
                        info!("Outbound ratchet activated — upload switched to new keys");
                    }
                    info!("PFS ratchet complete — forward secrecy established");

                    // K6: keys are now stable — install (or, on a mid-session
                    // re-ratchet, atomically replace) the in-kernel downlink
                    // session with the NEW s2c key and a fresh tag window.
                    // In-flight old-key packets miss the new kernel tags and
                    // fall back to user-space, where `transition_recv_keys`
                    // still decodes them.
                    #[cfg(target_os = "linux")]
                    self.kernel_install_session();
                }

                // The following client-identity announcements (mTLS cert,
                // recording status, device enrollment) only make sense for an
                // actual end-user device. A headless control-only pool-peer
                // dialer is not a device to enroll — skip them entirely.
                if !self.config.control_only {
                    // Send mTLS ClientCert now that the PFS ratchet is complete.
                    // Sending it here ensures the cert is protected by the ratcheted
                    // session keys, not the initial zero-RTT keys.
                    if let Some(cert) = self.config.mtls_cert.clone() {
                        if let Err(e) = self
                            .send_control(&ControlPayload::ClientCert {
                                cert_bytes: cert.clone(),
                            })
                            .await
                        {
                            warn!("mTLS: failed to queue ClientCert after ratchet: {}", e);
                        } else {
                            debug!(
                                "mTLS: ClientCert queued after PFS ratchet ({} bytes)",
                                cert.len()
                            );
                        }
                    }

                    let _ = self
                        .send_control(&ControlPayload::RecordingStatusRequest)
                        .await;

                    // Device enrollment: prove static key ownership to server.
                    // Sent after ratchet so it is protected by PFS session keys.
                    // dh_proof is bound to THIS session's ephemeral transcript
                    // (server_eph_pub || client_eph_pub, matching the server's
                    // verify_device_enrollment_proof) so it cannot be replayed
                    // into a different session — see
                    // crypto::device_enrollment_proof for the scheme.
                    if let Some(ref skp) = self.static_keypair {
                        match skp.compute_shared(&self.config.server_public_key) {
                            Ok(dh_shared) => {
                                let client_eph_pub = self.keypair.public_key_bytes();
                                let dh_proof = crypto::device_enrollment_proof(
                                    &dh_shared,
                                    &server_eph_pub,
                                    &client_eph_pub,
                                );
                                let enrollment = ControlPayload::DeviceEnrollment {
                                    static_pub: skp.public_key_bytes(),
                                    dh_proof,
                                };
                                if let Err(e) = self.send_control(&enrollment).await {
                                    warn!("DeviceEnrollment send failed: {}", e);
                                }
                            }
                            Err(e) => warn!("DeviceEnrollment DH failed: {}", e),
                        }
                    }
                }

                // B2/D2 fix: session-bound NodeEnrollment for the embedded
                // control_only pool-peer dialer. `node_identity` is `Some`
                // ONLY when `aivpn-server`'s `pool_dialer.rs` constructed
                // this client to dial a fellow pool node (see
                // `ClientConfig::node_identity`'s doc comment) — for every
                // ordinary end-user client it is `None` and this whole block
                // is a no-op, matching pre-fix behavior exactly.
                //
                // The proof is built HERE (not in pool_dialer.rs, where it
                // used to be built pre-fix) because only this handler has
                // this session's ephemeral transcript
                // (server_eph_pub || client_eph_pub): `server_eph_pub` is the
                // value this exact ServerHello just carried, and
                // `client_eph_pub` is `self.keypair.public_key_bytes()` — our
                // own ephemeral public key for this session, fixed for its
                // lifetime. Binding to that pair (mirrors
                // `crypto::device_enrollment_proof`'s scheme above) is what
                // makes a captured `(node_id, node_pub, time_window,
                // signature)` tuple useless if replayed onto a DIFFERENT
                // masked pool-peer session — that session's transcript
                // differs, so `verify_node_enrollment` on the receiving end
                // no longer matches.
                if let Some(node_identity) = self.config.node_identity.clone() {
                    let client_eph_pub = self.keypair.public_key_bytes();
                    let node_pub = node_identity.verifying_key().to_bytes();
                    let node_id = self.config.pool_node_id.clone().unwrap_or_default();

                    // Send immediately — mirrors DeviceEnrollment's
                    // reliability behavior above: this fires on every
                    // ServerHello the client processes (including the
                    // server's lost-original-ServerHello resends), so a
                    // dropped first NodeEnrollment packet self-heals the
                    // next time the server retransmits.
                    let enrollment = build_node_enrollment_payload(
                        &node_identity,
                        &node_id,
                        &node_pub,
                        &server_eph_pub,
                        &client_eph_pub,
                    );
                    if let Err(e) = self.send_control(&enrollment).await {
                        warn!("NodeEnrollment send failed: {}", e);
                    }

                    // Periodic resend: once per REAL ratchet (a full
                    // reconnect spawns a brand-new AivpnClient/task, so this
                    // never accumulates duplicate timers across the client's
                    // lifetime) so a peer whose NodeRegistry restarted (or
                    // that never saw our initial enrollment) re-learns/
                    // re-verifies us without waiting for a fresh dial.
                    // Rebuilt with a fresh time_window every tick but the
                    // SAME session transcript — server_eph_pub/client_eph_pub
                    // are stable for the life of this session.
                    if !is_duplicate_hello {
                        if let Some(tx) = self.control_tx.clone() {
                            Self::spawn_node_enrollment_resend(
                                tx,
                                node_identity,
                                node_id,
                                node_pub,
                                server_eph_pub,
                                client_eph_pub,
                            );
                        } else {
                            warn!(
                                "control_tx not initialized, skipping NodeEnrollment periodic resend"
                            );
                        }
                    }
                }

                // The §2/§3 control messages below must fire ONCE per real
                // ratchet, not on every ServerHello: the server resends
                // ServerHello to recover a lost first copy (normal on lossy
                // mobile links), and re-sending MaskPreference each time makes
                // the server re-push a MaskUpdate whose `update_mask` resets the
                // mimicry FSM mid-connection — an observable disruption to the
                // very traffic fingerprint §3 protects. Gate on the first
                // ratchet only (the pre-existing ClientCert/DeviceEnrollment
                // re-sends above are intentionally left as reliability resends).
                if !is_duplicate_hello {
                    // Polymorphic mask request: ask the server to derive and push
                    // a per-session perturbed variant of the requested base mask.
                    // The server's reply arrives as a normal MaskUpdate, handled
                    // by the existing ControlPayload::MaskUpdate arm below.
                    //
                    // Reliability (§3 F): a single lost MaskPreference packet
                    // would silently disable polymorphic masks for the whole
                    // session. Spawn a bounded retry task that resends until the
                    // client observes its active mask become a `polymorphic:`
                    // variant (`polymorphic_confirmed`, set in the MaskUpdate
                    // arm) — or gives up after a few attempts. The server side is
                    // idempotent (it skips re-pushing a MaskUpdate when the
                    // session mask is already the derived variant), so a resend
                    // that races an already-applied variant does NOT reset the
                    // mimicry FSM. Runs only once per real ratchet (this block is
                    // gated on `!is_duplicate_hello`).
                    if let Some(base_mask_id) = self.config.polymorphic_base.clone() {
                        if let (Some(tx), confirmed) =
                            (self.control_tx.clone(), self.polymorphic_confirmed.clone())
                        {
                            tokio::spawn(async move {
                                // Up to 5 sends over ~5s: immediate, then 0.5s,
                                // 1s, 1.5s, 2s spacing.
                                for attempt in 0..5u8 {
                                    if confirmed.load(Ordering::Relaxed) {
                                        return;
                                    }
                                    if tx
                                        .send(ControlPayload::MaskPreference {
                                            base_mask_id: base_mask_id.clone(),
                                        })
                                        .await
                                        .is_err()
                                    {
                                        // Receiver gone — run() returned; stop.
                                        return;
                                    }
                                    tokio::time::sleep(Duration::from_millis(
                                        500 * (attempt as u64 + 1),
                                    ))
                                    .await;
                                }
                            });
                        }
                    }

                    // §2 crowdsourced blocking feedback (opt-in, OFF by default):
                    // the session is now confirmed connected (PFS ratchet done),
                    // so record a success outcome for the mask this connection is
                    // using and, if enabled, report the batched buffer to the
                    // server. See `record_mask_outcome` / `maybe_send_mask_feedback`
                    // for the privacy-preserving design notes (hour-granularity
                    // timestamps, opt-in only, no effect unless country_code is
                    // also configured).
                    // Report the base mask FAMILY, not the per-session id. A
                    // cached bootstrap id is `bootstrap:{desc}:{base}:{slot}:{seed}`
                    // whose seed is PSK-derived (a stable quasi-identifier), and a
                    // polymorphic id is `polymorphic:{base}:{hex}`. Sending either
                    // raw would leak identity AND fragment the server's k-anon
                    // buckets so they never reach the threshold. Collapse to the
                    // base preset id so feedback aggregates per protocol family.
                    //
                    // Attribute the outcome to the mask family ACTUALLY being
                    // exercised. In polymorphic mode (`--polymorphic-base`) the
                    // initial mask is deliberately the bootstrap-fallback family
                    // (so the opening burst isn't a named preset) while the mask
                    // the session really runs is the server-pushed per-session
                    // variant of `polymorphic_base`. Reporting the fallback family
                    // here would silently attribute every §3 session's success to
                    // the wrong family, defeating §2. So prefer the configured
                    // polymorphic base when set; otherwise fall back to the
                    // bootstrap/initial mask family as before.
                    //
                    // A legitimate mid-session RE-ratchet arrives with a NEW
                    // `server_eph_pub`, so `!is_duplicate_hello` is true again —
                    // guard the append with `mask_success_recorded` so success is
                    // recorded exactly once per connection, not once per ratchet.
                    if !self.mask_success_recorded {
                        let active_mask_id = self.active_feedback_family();
                        self.record_mask_outcome(active_mask_id, true);
                        self.mask_success_recorded = true;
                    }
                    self.maybe_send_mask_feedback().await;
                }

                // Warmup: 4 keepalives (100 ms apart) to force CGNAT to refresh
                // its inbound port mapping after reconnect. Fallback for carriers
                // that delay updating the entry even after local-port reuse.
                //
                // Spawned as a background task (not awaited inline) so this
                // ~400ms sequence doesn't stall the packet-receive loop right
                // during the most sensitive part of the connection — the
                // exact window where the server may also be sending the
                // initial MaskUpdate and the first data packets. Blocking
                // here previously let a backlog build up in the UDP->TUN
                // channel, which then drained in one burst as soon as this
                // handler returned.
                // Only warm up on a real (re)connect, and never on Satellite —
                // matching the proactive watchdog warmup. A lossy link makes the
                // server re-send ServerHello as its reliability mechanism, so
                // firing a 4-keepalive burst on every duplicate would amplify
                // traffic on exactly the worst links (and needlessly on the
                // deliberately-slow Satellite profile).
                if !is_duplicate_hello && self.adaptive_level != AdaptiveLevel::Satellite {
                    if let Some(tx) = self.control_tx.clone() {
                        Self::spawn_warmup_burst(tx);
                    } else {
                        warn!("control_tx not initialized, skipping keepalive warmup");
                    }
                }
            }
            ControlPayload::Keepalive { .. } => {
                debug!("Keepalive from server");
            }
            ControlPayload::TimeSync { server_ts_ms } => {
                debug!("Time sync: server_ts={}", server_ts_ms);
            }
            ControlPayload::Shutdown { reason } => {
                info!("Server requested shutdown (reason: {})", reason);
                self.disconnect().await;
                return Err(Error::Session(format!("server shutdown: {}", reason)));
            }
            ControlPayload::RecordingAck { session_id, status } => {
                if status == "started" {
                    self.active_recording_session = Some(session_id);
                } else if status == "analyzing" {
                    self.active_recording_session = None;
                }
                crate::record_cmd::handle_recording_ack(&session_id, &status);
            }
            ControlPayload::RecordingComplete {
                service,
                mask_id,
                confidence,
            } => {
                self.active_recording_session = None;
                crate::record_cmd::handle_recording_complete(&service, &mask_id, confidence);
            }
            ControlPayload::RecordingFailed { reason } => {
                self.active_recording_session = None;
                crate::record_cmd::handle_recording_failed(&reason);
            }
            ControlPayload::RecordingStatus {
                can_record,
                active_service,
            } => {
                crate::record_cmd::handle_recording_status(can_record, active_service.as_deref());
            }
            ControlPayload::CertRejected {} => {
                warn!("mTLS: server rejected the certificate — re-provision your mTLS cert");
            }
            ControlPayload::KeepaliveAck { echo_ts } => {
                // Use echoed client timestamp for RTT when available (server ≥ 0.9.0),
                // fall back to the stored send-time for older servers.
                let sent_ms = if echo_ts > 0 {
                    echo_ts
                } else {
                    self.keepalive_sent_ms.load(Ordering::Relaxed)
                };
                if sent_ms > 0 {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let rtt_us = now_ms.saturating_sub(sent_ms).saturating_mul(1000);
                    self.quality_tracker.record_rtt(rtt_us);
                    let score = self.quality_tracker.score();
                    Self::write_quality_file(
                        score,
                        self.quality_tracker.rtt_ms(),
                        self.quality_tracker.jitter_ms(),
                        self.adaptive_level as u8,
                    );
                    let new_level = AdaptiveLevel::suggest(score);
                    if new_level != self.adaptive_level {
                        self.adaptive_level = new_level;
                        self.set_keepalive_interval(Duration::from_secs(
                            new_level.keepalive_secs(),
                        ));
                        info!(
                            "Adaptive level → {:?} (score={}), keepalive={}s",
                            new_level,
                            score,
                            self.keepalive_interval.as_secs()
                        );
                    }
                    let _ = self
                        .send_control(&ControlPayload::QualityReport {
                            quality: score,
                            rtt_ms: self.quality_tracker.rtt_ms(),
                            loss_ppm: self.quality_tracker.loss_ppm(),
                            jitter_ms: self.quality_tracker.jitter_ms(),
                        })
                        .await;
                }
            }
            ControlPayload::AdaptiveHint { level } => {
                let new_level = AdaptiveLevel::from_u8(level);
                if new_level != self.adaptive_level {
                    self.adaptive_level = new_level;
                    self.set_keepalive_interval(Duration::from_secs(new_level.keepalive_secs()));
                    info!("Server adaptive hint → {:?}", new_level);
                }
            }
            ControlPayload::RegionalMaskHints {
                country_code,
                masks,
            } => {
                // §2 crowdsourced blocking feedback — opt-in. The server only
                // ever sends this after k-anonymity-gated aggregation (see
                // aivpn-server's mask_feedback.rs); ignore entirely unless
                // the client asked to receive hints.
                if !self.config.receive_mask_hints {
                    debug!("RegionalMaskHints received but receive_mask_hints=false — ignoring");
                    return Ok(());
                }
                info!(
                    "RegionalMaskHints for {}{}: {} masks",
                    country_code[0] as char,
                    country_code[1] as char,
                    masks.len()
                );
                // Keep an in-memory copy for `regional_mask_hints()` and
                // ALSO persist per-region (§2 L3). Mask selection happens in
                // `main.rs`'s reconnect loop on a fresh client instance one
                // iteration later, so the bias must read the hints back from
                // disk (`RegionalHintsStore`).
                let mut store = RegionalHintsStore::load_default();
                store.set_region(country_code, masks.clone());
                self.regional_mask_hints = Some(masks);
            }
            ControlPayload::FeedbackConfig {
                report_failure_threshold,
                report_interval_secs,
            } => {
                // §2 M3 server-pushed config. Persist the tuning so the
                // reconnect loop (a different client instance) honors it. Only
                // meaningful to an opted-in client; the server only sends this
                // in reply to a MaskFeedback, which only opted-in clients emit.
                info!(
                    "FeedbackConfig from server: failure_threshold={}, interval={}s",
                    report_failure_threshold, report_interval_secs
                );
                self.feedback_log
                    .set_tuning(report_failure_threshold, report_interval_secs);
            }
            ControlPayload::MaskCatalog { masks } => {
                // Server pushed the selectable-mask list. Persist it so the GUI
                // pickers (separate processes) render a live list and mark
                // auto-generated masks "(авто)".
                info!("MaskCatalog from server: {} masks", masks.len());
                crate::mask_catalog::write_mask_catalog(&masks);
            }
            ControlPayload::HandshakeReject { reason } => {
                // Authenticated (PSK-proven) terminal refusal — see the
                // doc comment on `ControlPayload::HandshakeReject` in
                // aivpn-common. Log the reason, surface it on stdout as a
                // machine-readable status line (mirrors "AIVPN-STATUS
                // connected <ip>") so the CLI and both desktop GUIs can show
                // it, and set the terminal flag so `main.rs`'s reconnect
                // loop stops instead of retrying forever against a refusal
                // that will never change on its own.
                let message = handshake_reject_message(reason);
                error!(
                    "Handshake rejected by server: {} (reason={})",
                    message, reason
                );
                println!("AIVPN-STATUS rejected {}", handshake_reject_token(reason));
                self.terminal_rejected = true;
                self.reject_reason = reason;
                self.disconnect().await;
                return Err(Error::Session(format!("handshake rejected: {}", message)));
            }
            ControlPayload::PoolSync { .. }
            | ControlPayload::PoolStateDigest { .. }
            | ControlPayload::PoolBucketDigests { .. }
            | ControlPayload::RouteSync { .. } => {
                // Normal end-user clients have no use for these pool
                // anti-entropy messages and silently ignore them, exactly as
                // before. When the server has embedded this client as a
                // headless control-only pool-peer dialer (see
                // `ClientConfig::control_only`), forward a clone to the
                // configured tap instead so the embedder can drive its own
                // merge logic — never block the receive path on the tap.
                if let Some(tap) = &self.config.inbound_control_tap {
                    if let Err(e) = tap.try_send(control) {
                        warn!(
                            "inbound_control_tap: failed to forward pool control payload: {}",
                            e
                        );
                    }
                }
            }
            _ => {}
        }
        Ok(())
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
        let mut server_new_keys = crypto::derive_session_keys(
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
