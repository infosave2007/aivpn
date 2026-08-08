//! Android VPN tunnel — runs on top of a TUN fd created by VpnService.Builder and a UDP
//! socket created here and exempted via VpnService.protect(int).
//!
//! Wire protocol is byte-for-byte identical to AivpnCrypto.kt so that both can talk to the
//! same Rust server without any server-side changes.

use aivpn_common::quality::{AdaptiveLevel, QualityTracker};
use std::collections::VecDeque;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jni::objects::GlobalRef;
use jni::JavaVM;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

use aivpn_common::client_wire::{
    build_inner_packet, build_shaped_mdh_packet, decode_downlink_any_mdh_len,
    obfuscate_client_eph_pub, process_server_hello_with_mdh_len, RecvWindow,
};
use aivpn_common::crypto::{derive_session_keys, KeyPair, SessionKeys};
use aivpn_common::error::{Error, Result};
use aivpn_common::mask::{
    current_unix_secs, decode_bootstrap_descriptor, resolve_handshake_mask_resilient,
    BootstrapDescriptor, MaskProfile, HANDSHAKE_FALLBACK_THRESHOLD, LEGACY_LAYOUT_THRESHOLD,
};
use aivpn_common::mimicry::MimicryEncryptor;
use aivpn_common::protocol::{ControlPayload, InnerType, MaskOutcome};
use aivpn_common::upload_pipeline::{self, PacketEncryptor, UploadConfig};

// ──────────── Constants ────────────

const BUF_SIZE: usize = 2048;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_millis(750);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(4); // below typical provider NAT UDP timeout (~10-15s)
/// NAT-safe keepalive ceiling — mirror of desktop client.rs `KEEPALIVE_NAT_CAP`.
/// An AdaptiveHint may relax the interval up to this bound (Satellite is
/// uncapped). The initial `keepalive_interval` derives from the tiny 4s
/// `base_keepalive`, so the re-arm must clamp against THIS ceiling, not that
/// floor — otherwise `base.min(level)` collapses every hint back to 4s.
const KEEPALIVE_NAT_CAP: Duration = Duration::from_secs(25);
const RX_SILENCE: Duration = Duration::from_secs(120); // absolute net: NOTHING decodes at all (control included)
const RX_CHECK_INTERVAL: Duration = Duration::from_secs(2);
// Data-plane watchdogs (see `data_watchdog_verdict`): clocked on DATA actually
// delivered to the TUN, never on "any decode" — keepalive-acks and in-grace
// KeyRotate retransmits must not mask a dead data downlink. The fast tier's
// former 64 KiB threshold was unreachable from post-stall probe traffic (TCP
// acks/DNS retries are tiny, and the counter was zeroed on every control
// decode), so a dead downlink slid past it to the 120 s absolute net.
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
// one 30 s window) still reconnects in ~25–35 s instead of the 120 s net.
const DATA_STALL_WINDOW: Duration = Duration::from_secs(30);
/// Consecutive watchdog ticks (RX_CHECK_INTERVAL apart) the stall verdict
/// must hold before the session is condemned (see `data_stall_confirmed`).
/// One extra tick gives a slow-but-alive downlink (delayed ACKs, bufferbloat
/// spike) a last chance to stamp `last_data_rx` and clear the verdict,
/// pushing the false-fire class further away from healthy upload-heavy
/// flows. A genuinely dead downlink still fires on the second consecutive
/// tick — seconds after the 20 s stall verdict, nowhere near the 120 s net.
const DATA_STALL_STRIKES_TO_FIRE: u32 = 2;
const CHANNEL_SIZE: usize = 8192;
/// How long the receive loop keeps the PREVIOUS session keys accepting inbound
/// packets after an inline rekey. Must cover the server's KeyRotate retransmit
/// horizon (5 sends spread over ~16 s on a ~3–4 s cadence, server session.rs):
/// if the client's rekey RESPONSE is lost, the server stays on the OLD keys and
/// retransmits KeyRotate under them — the client must still decode those
/// retransmits (and the old-key downlink flowing in between) to re-send its
/// response and self-heal with ZERO reconnects. The former 2 s window expired
/// before the first retransmit (~4 s) could arrive, so every lost response cost
/// a full RX-silence reconnect (mirrors desktop client.rs
/// REKEY_TRANSITION_GRACE).
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
/// a clean full reconnect (mirrors desktop client.rs / ios_tunnel.rs).
const REKEY_TRANSITION_HARD_CAP: Duration = Duration::from_secs(40);

/// Upper bound on the rekey-ack rendezvous wait. The ack normally fires
/// sub-millisecond (local oneshot fired by the upload task right after
/// encrypting the KeyRotate response), so 5 s can only elapse if the upload
/// task died between dequeuing the KeyRotate and firing the ack (e.g. an
/// encrypt error propagated by `?` before the ack pop). Without the bound,
/// the stranded `oneshot::Sender` kept alive inside the shared
/// `Arc<Mutex<VecDeque>>` would make `ack_rx.await` pend forever inside a
/// select arm — freezing the receive loop including the RX watchdog and the
/// stop signal (mirrors desktop client.rs REKEY_ACK_TIMEOUT).
const REKEY_ACK_TIMEOUT: Duration = Duration::from_secs(5);

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

// ──────────── Session runtime (read by JNI exports in lib.rs) ────────────

pub struct SessionRuntime {
    udp_control_fd: AtomicI32,
    stop_event_fd: AtomicI32,
    /// Rust's private duplicates of the Android-owned TUN fd — one for writing
    /// downlink, one for the reader task.
    ///
    /// The session OWNS them (the `AsyncFd`s below only borrow), because the
    /// kernel destroys a tun device only when its LAST fd closes. Kotlin closes
    /// its `ParcelFileDescriptor` on disconnect and gives the native call 3 s to
    /// unwind; if that call is slow to return, these duplicates outlive the
    /// interface and keep it alive as a zombie that still carries the VPN
    /// address. The next session then establishes a SECOND tun with the same
    /// address, app packets are routed into the dead one nobody reads, and the
    /// tunnel is "connected" with no traffic — issue #71, which is why only a
    /// process kill (force-stop, reinstall, clear-data) restored it.
    ///
    /// Closed by whichever of `stop_active_tunnel` / `ActiveSessionGuard::drop`
    /// runs first; both take ownership with `swap(-1)` so exactly one close
    /// happens and the fd number can never be closed twice.
    tun_write_fd: AtomicI32,
    tun_read_fd: AtomicI32,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    // Set by stop_active_tunnel() before eventfd/socket are ready so that early
    // init phases (DNS, socket creation) can check and bail out immediately.
    stop_requested: AtomicBool,
}

impl SessionRuntime {
    fn new() -> Self {
        Self {
            udp_control_fd: AtomicI32::new(-1),
            stop_event_fd: AtomicI32::new(-1),
            tun_write_fd: AtomicI32::new(-1),
            tun_read_fd: AtomicI32::new(-1),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            stop_requested: AtomicBool::new(false),
        }
    }
}

static ACTIVE_SESSION: Mutex<Option<Arc<SessionRuntime>>> = Mutex::new(None);

/// In-process store of bootstrap descriptors pushed by the server over the
/// authenticated in-session control channel (`BootstrapDescriptorUpdate`).
///
/// The Android core has no `bootstrap_cache` crate (that lives in
/// `aivpn-client`), so before this it discarded pushed descriptors and every
/// handshake fell back to a PSK-indexed PUBLIC preset — a fingerprintable shape
/// that defeats the point of the signed, epoch-rotated descriptors. Persisting
/// them here (for the lifetime of the VpnService process, which spans internal
/// reconnects) lets `resolve_handshake_mask` shape subsequent reconnect
/// handshakes with the COVERT rotated descriptor mask instead. The very first
/// handshake of a process still uses the PSK-preset bootstrap (there is no
/// descriptor yet), then upgrades to covert once the server pushes one.
static BOOTSTRAP_DESCRIPTORS: Mutex<Vec<BootstrapDescriptor>> = Mutex::new(Vec::new());

/// The `server_key` of the last session. The descriptor store above is
/// process-global and survives internal reconnects, but descriptors are
/// server-specific — so when the user switches to a DIFFERENT server/profile we
/// must clear the store, otherwise server A's rotated descriptors would shape
/// the handshake to server B (covertness inversion + possible opening-packet
/// mis-frame). See review M2.
static LAST_SERVER_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// Cap on retained pushed descriptors (a handful of epochs is plenty).
const MAX_BOOTSTRAP_DESCRIPTORS: usize = 8;

/// Snapshot the currently-valid stored descriptors, newest first.
fn current_bootstrap_descriptors() -> Vec<BootstrapDescriptor> {
    // Once a descriptor mask has been condemned, hide the whole store for the
    // rest of the process. Clearing it at condemn time is not enough: the server
    // re-pushes descriptors during EVERY session, including the preset-mask one
    // that recovers the tunnel, so the next connect would resolve a covert mask
    // again and break again. This is the single read path used both for mask
    // resolution and for the platform's persistence export.
    if DESCRIPTORS_DISTRUSTED.load(Ordering::Relaxed) {
        return Vec::new();
    }
    let now = current_unix_secs();
    let mut out: Vec<BootstrapDescriptor> = BOOTSTRAP_DESCRIPTORS
        .lock()
        .map(|g| g.iter().filter(|d| d.is_valid_at(now)).cloned().collect())
        .unwrap_or_default();
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    out
}

/// Store a server-pushed descriptor (deduped by `descriptor_id`, capped).
/// It arrived over the AEAD-authenticated session channel, so it is treated as
/// server-authenticated (same trust model as desktop `client.rs`'s no-trusted-
/// key store path); only expiry is checked here.
fn store_bootstrap_descriptor(descriptor: BootstrapDescriptor) {
    if !descriptor.is_valid_at(current_unix_secs()) {
        return;
    }
    if let Ok(mut g) = BOOTSTRAP_DESCRIPTORS.lock() {
        g.retain(|d| d.descriptor_id != descriptor.descriptor_id);
        g.push(descriptor);
        g.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        g.truncate(MAX_BOOTSTRAP_DESCRIPTORS);
    }
}

/// Serialize the currently-valid stored descriptors as a JSON array so the
/// platform (`AivpnService.kt`) can persist them across process restarts. The
/// descriptors are ed25519-signed and self-authenticating, so persisting the
/// raw blobs is safe; they are re-verified on load via
/// `preload_persisted_descriptors`. Returns `"[]"` when the store is empty.
///
/// Polled by JNI (`getBootstrapDescriptorsJson`) after a session so the very
/// next COLD START can shape its first handshake with a COVERT rotated
/// descriptor mask instead of a public preset.
pub fn bootstrap_descriptors_json() -> String {
    // Once a descriptor mask has been condemned (see
    // `condemn_descriptor_mask_after_watchdog`), stop handing descriptors back
    // for persistence for the rest of the process. The server re-pushes fresh
    // ones on every session, so without this the preset-mask session that
    // recovers the tunnel immediately re-persists a descriptor and the NEXT
    // connect breaks again — a working/broken ping-pong instead of a fix.
    if DESCRIPTORS_DISTRUSTED.load(Ordering::Relaxed) {
        return "[]".to_string();
    }
    let descriptors = current_bootstrap_descriptors();
    serde_json::to_string(&descriptors).unwrap_or_else(|_| "[]".to_string())
}

/// Sentinel the platform passes as `cachedDescriptorsJson` instead of a blob to
/// say "this server's descriptors were condemned in an earlier RUN of the app"
/// (see [`condemn_descriptor_mask_after_watchdog`]). A plain empty blob cannot
/// carry that: the store also fills from the server's in-session pushes, so
/// without a sticky verdict every app restart would break its first reconnect
/// again and heal ~50 s later, forever.
///
/// Passed through the existing parameter deliberately — the JNI signature is
/// shared with the iOS core and a new argument would be a wider change than the
/// verdict warrants.
pub const DESCRIPTORS_DISTRUSTED_SENTINEL: &str = "distrusted";

/// Re-populate the in-process descriptor store from app-persisted JSON BEFORE
/// the first handshake. Descriptors are signature-verified (when a trusted
/// operator key is available) and validity-filtered by
/// `accept_persisted_descriptors`, so a tampered/expired persisted blob is
/// rejected and the handshake simply falls back to the preset — never worse
/// than today. Returns how many descriptors were accepted into the store.
fn preload_persisted_descriptors(json: &str, trusted_key: Option<&[u8; 32]>) -> usize {
    // Sticky verdict from an earlier run: adopt it before anything can consult
    // the store, so this process never resolves a descriptor mask either.
    if json.trim() == DESCRIPTORS_DISTRUSTED_SENTINEL {
        DESCRIPTORS_DISTRUSTED.store(true, Ordering::Relaxed);
        return 0;
    }
    // A condemned descriptor must not come back through the platform's cached
    // blob: the delete is asynchronous (the platform performs it only after
    // `run_tunnel_android` returns), so an immediate retry would otherwise
    // re-preload the very descriptor that just killed the data plane.
    if DESCRIPTORS_DISTRUSTED.load(Ordering::Relaxed) {
        return 0;
    }
    let accepted = aivpn_common::mask::accept_persisted_descriptors(json, trusted_key);
    let mut stored = 0usize;
    for descriptor in accepted {
        store_bootstrap_descriptor(descriptor);
        stored += 1;
    }
    stored
}

// Last local UDP port used by a tunnel session.  On reconnect we try to bind
// to the same port so CGNAT carriers (MTS et al.) with port-preserving NAT
// don't need to update their inbound routing table — the old mapping already
// points to the right port and downlink arrives immediately.
static LAST_LOCAL_PORT: AtomicU16 = AtomicU16::new(0);

// Set by stop_active_tunnel() when called while no session is active (the gap
// between the old session's ActiveSessionGuard drop and the new session's
// activate_session() call).  activate_session() propagates this to the new
// session so it stops immediately.  clear_pending_stop() resets the flag
// when a new intentional connection is about to start (called from the
// restartJob in Kotlin after cancelAndJoin()).
static STOP_PENDING: AtomicBool = AtomicBool::new(false);

/// Last computed connection quality score (0–100). Updated on each KeepaliveAck.
/// Polled by JNI via getQualityScore().
pub static ACTIVE_QUALITY_SCORE: AtomicU8 = AtomicU8::new(0);

/// Suggested adaptive level from the last server AdaptiveHint (0–3). 0 = no hint yet.
/// Polled by JNI via getAdaptiveLevelHint(); takes effect on next reconnect.
pub static ACTIVE_ADAPTIVE_LEVEL: AtomicU8 = AtomicU8::new(0);

// §2 crowdsourced blocking feedback — process-global state polled by Kotlin
// via the JNI getters in `lib.rs`, following the same reset-at-session-start
// / poll-after-return idiom as `ACTIVE_QUALITY_SCORE` / `ACTIVE_ADAPTIVE_LEVEL`
// above. `run_tunnel_android` handles exactly one connection attempt per
// call, so the Kotlin reconnect loop (`AivpnService.kt`) polls these once the
// blocking JNI call returns to learn the outcome and any server-pushed
// tuning, then persists across attempts itself (mirrors desktop's
// `main.rs`/`mask_feedback_log.rs` split, adapted for the single-shot JNI).
//
/// Whether this attempt ever reached a connected (post-handshake, PFS
/// ratchet complete) state. `false` on any error/timeout before that point —
/// the platform layer attributes such attempts as a failure for the base
/// mask family it requested (see `AivpnService.kt`).
pub static EVER_CONNECTED: AtomicBool = AtomicBool::new(false);
/// Consecutive attempts that died on a handshake TIMEOUT without ever
/// connecting, carried across `run_tunnel_android` calls (the service process
/// stays alive across the Kotlin reconnect loop). At
/// `HANDSHAKE_FALLBACK_THRESHOLD` the handshake mask resolution abandons the
/// descriptor-derived covert mask for a builtin preset every server matches —
/// a cached descriptor this server cannot reproduce otherwise fails EVERY
/// handshake with a tag mismatch and reconnects forever (desktop main.rs has
/// the same net via its local `handshake_fail_streak`). Reset when the PFS
/// ratchet completes.
pub static HANDSHAKE_FAIL_STREAK: AtomicU32 = AtomicU32::new(0);
/// Set when a session that COMPLETED the handshake never carried a single
/// downlink DATA packet while handshaking with a descriptor-derived covert
/// mask. Polled by the platform (`getDiscardPersistedDescriptors`) so the
/// app-persisted descriptor blob is dropped too — clearing only the in-process
/// store would let the next COLD START reload the same unusable descriptor.
pub static DISCARD_PERSISTED_DESCRIPTORS: AtomicBool = AtomicBool::new(false);
/// Sticky for the process once a descriptor mask has been condemned. The
/// platform CONSUMES `DISCARD_PERSISTED_DESCRIPTORS` (one delete), so a second
/// flag is needed to keep suppressing descriptor use afterwards — the server
/// re-pushes descriptors every session, and re-adopting them would break the
/// very next connect again.
static DESCRIPTORS_DISTRUSTED: AtomicBool = AtomicBool::new(false);
/// Server-pushed `FeedbackConfig.report_failure_threshold` for this session,
/// coerced to >=1 on receipt. `0` means no `FeedbackConfig` was received this
/// session — the platform should keep its previously persisted value.
pub static ACTIVE_FEEDBACK_THRESHOLD: AtomicU8 = AtomicU8::new(0);
/// Server-pushed `FeedbackConfig.report_interval_secs` for this session,
/// coerced to the default when the server sends 0. `0` means no
/// `FeedbackConfig` was received this session.
pub static ACTIVE_FEEDBACK_INTERVAL: AtomicU32 = AtomicU32::new(0);
/// Whether a `MaskFeedback` control message was actually sent this session
/// (share entries or a hints-only probe). The platform uses this to decide
/// whether to clear its persisted outcome buffer and bump `last_report_unix`.
pub static MASK_FEEDBACK_SENT: AtomicBool = AtomicBool::new(false);
/// The base mask family this attempt requested (normalized via
/// `base_mask_family`), set as soon as the initial mask is chosen —
/// regardless of whether §2 reporting is enabled — so the platform layer can
/// attribute a failed (never-`EVER_CONNECTED`) attempt to the right family
/// even when the mask was chosen internally from the PSK-derived "auto"
/// fallback (the platform has no other way to observe it). Mirrors desktop
/// main.rs's `attempt_mask_family`, computed there in the same process/scope
/// right before `AivpnClient::new`; here it must cross the JNI boundary
/// because mask selection happens inside this one-shot call.
pub static ATTEMPTED_MASK_FAMILY: Mutex<Option<String>> = Mutex::new(None);
/// §2 crowdsourced blocking feedback — most recent `RegionalMaskHints`
/// received from the server this session, JSON-encoded
/// (`{"country_code":"US","masks":[["webrtc_zoom_v3",0.87],...]}`) for the
/// platform layer to parse, persist per-region, and use to softly bias mask
/// selection on the next reconnect attempt (mirrors desktop's
/// `RegionalHintsStore`, whose persistence lives in Kotlin here instead of
/// this standalone per-call Rust core). `None` until a hint arrives, which
/// requires `receive_mask_hints` opt-in. Reset at the top of every
/// `run_tunnel_android` call, same reset-at-session-start idiom as
/// `ACTIVE_RECORDING_FEEDBACK`.
pub static ACTIVE_REGIONAL_HINTS_JSON: Mutex<Option<String>> = Mutex::new(None);
/// Bumped every time a new `RegionalMaskHints` message is stored, so Kotlin
/// can detect a fresh message rather than re-reading a stale one every poll.
pub static REGIONAL_HINTS_SEQ: AtomicU64 = AtomicU64::new(0);

/// Most recent `MaskCatalog` pushed by the server this session, JSON-encoded
/// (`[{"mask_id":"auto_quic_v1","label":"QUIC","generated":true},...]`) for the
/// Kotlin mask spinner to render a live list and mark auto-generated masks
/// "(авто)". `None` until a catalog arrives. Reset at session start.
pub static ACTIVE_MASK_CATALOG_JSON: Mutex<Option<String>> = Mutex::new(None);
/// Bumped every time a fresh `MaskCatalog` is stored, so Kotlin can detect a new
/// list rather than re-reading a stale one on every poll tick.
pub static MASK_CATALOG_SEQ: AtomicU64 = AtomicU64::new(0);

/// Default `report_interval_secs` when no `FeedbackConfig` has been received
/// yet, or the server sends 0. Kept in sync with `aivpn-client`'s
/// `mask_feedback_log.rs`.
const DEFAULT_REPORT_INTERVAL_SECS: u32 = 3600;

/// §2 crowdsourced feedback. `bootstrap:{desc}:{base}:{slot}:{seed}` and
/// `polymorphic:{base}:{hex}` both carry per-session/PSK-derived entropy that
/// would leak a quasi-identifier and fragment the server's k-anonymity
/// buckets; only the stable `{base}` family is meaningful (and safe) to
/// report. Duplicated from desktop's `client.rs::base_mask_family` — the
/// Android core is a standalone crate with no dependency on aivpn-client, so
/// this must be kept in sync manually if the desktop format ever changes.
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

/// Parse a platform-supplied JSON array of prior (unreported) mask outcomes,
/// e.g. `[{"mask_id":"quic_https","success":2,"fail":1}]`. Best-effort:
/// missing/malformed JSON collapses to an empty batch rather than erroring —
/// feedback is never load-bearing for the tunnel connection itself.
fn parse_prior_outcomes(json: Option<&str>) -> Vec<MaskOutcome> {
    json.and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Merge the platform's batch of prior (unreported) outcomes with a single
/// success for `current_mask_id` (this attempt), summing counters per mask
/// id so a family already present in `prior` is not duplicated.
fn merge_mask_outcomes(prior: Vec<MaskOutcome>, current_mask_id: &str) -> Vec<MaskOutcome> {
    use std::collections::HashMap;
    let mut by_mask: HashMap<String, (u16, u16)> = HashMap::new();
    for o in prior {
        let counters = by_mask.entry(o.mask_id).or_insert((0, 0));
        counters.0 = counters.0.saturating_add(o.success);
        counters.1 = counters.1.saturating_add(o.fail);
    }
    let counters = by_mask.entry(current_mask_id.to_string()).or_insert((0, 0));
    counters.0 = counters.0.saturating_add(1);
    by_mask
        .into_iter()
        .map(|(mask_id, (success, fail))| MaskOutcome {
            mask_id,
            success,
            fail,
        })
        .collect()
}

/// Sender half of the control-payload channel to the active upload loop.
/// JNI uses this to inject RecordingStart / RecordingStop without a reconnect.
static ACTIVE_CONTROL_TX: Mutex<Option<mpsc::Sender<ControlPayload>>> = Mutex::new(None);

/// Snapshot of the most recent recording-related control message received
/// from the server (`RecordingAck` / `RecordingComplete` / `RecordingFailed` /
/// `RecordingStatus`). Exposed to JNI via `take_recording_feedback_json()` so
/// `MainActivity.kt`'s recording dialog can learn whether a started recording
/// succeeded, what mask_id it produced, or why it failed.
///
/// This mirrors the take()-once semantics of `key_rotate_slot` /
/// `mask_update_slot` below, but — like `ACTIVE_QUALITY_SCORE` and
/// `ACTIVE_ADAPTIVE_LEVEL` above — lives in a process-global static rather
/// than a per-session `Arc`, because JNI getters are called from arbitrary
/// Java threads that have no handle into the tunnel task's local variables.
#[derive(Debug, Clone)]
pub enum RecordingFeedback {
    /// RecordingAck: `status` is "started" or "analyzing".
    Ack { status: String },
    /// RecordingComplete: mask generation succeeded.
    Complete { mask_id: String, confidence: f32 },
    /// RecordingFailed: recording or mask generation failed.
    Failed { reason: String },
    /// RecordingStatus: capability/status query response.
    Status {
        can_record: bool,
        active_service: Option<String>,
    },
}

impl RecordingFeedback {
    /// Encodes as a small JSON object for the JNI getter. `AivpnJni.kt`'s
    /// callers already depend on `org.json.JSONObject` everywhere else in
    /// this codebase, so a single JSON-string getter fits the existing
    /// Kotlin-side idiom better than four separate typed getters.
    fn to_json(&self) -> String {
        match self {
            RecordingFeedback::Ack { status } => {
                serde_json::json!({ "type": "ack", "status": status }).to_string()
            }
            RecordingFeedback::Complete {
                mask_id,
                confidence,
            } => serde_json::json!({
                "type": "complete",
                "mask_id": mask_id,
                "confidence": confidence,
            })
            .to_string(),
            RecordingFeedback::Failed { reason } => {
                serde_json::json!({ "type": "failed", "reason": reason }).to_string()
            }
            RecordingFeedback::Status {
                can_record,
                active_service,
            } => serde_json::json!({
                "type": "status",
                "can_record": can_record,
                "active_service": active_service,
            })
            .to_string(),
        }
    }
}

/// Latest recording feedback from the server; consumed once by JNI's
/// `getRecordingFeedback()`. `None` once read (or if nothing has arrived yet
/// this session).
static ACTIVE_RECORDING_FEEDBACK: Mutex<Option<RecordingFeedback>> = Mutex::new(None);

/// Take (consume) the latest recording feedback as a JSON string, or `""`
/// if none is pending. Called by JNI's `getRecordingFeedback()`.
pub fn take_recording_feedback_json() -> String {
    ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .map(|f| f.to_json())
        .unwrap_or_default()
}

/// Queue a control payload to the active upload loop.
/// Returns true if the payload was accepted, false if there is no active session
/// or the channel is full.
pub fn send_control_payload(payload: ControlPayload) -> bool {
    let guard = ACTIVE_CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = guard.as_ref() {
        tx.try_send(payload).is_ok()
    } else {
        false
    }
}

/// Servers older than the directional-key split derive ONE session key and use
/// it in BOTH directions; `session_key_s2c` did not exist yet, so their downlink
/// is encrypted with `session_key`. Collapsing the split reproduces that
/// contract exactly, which lets every existing decode path work unchanged
/// instead of threading a mode flag through the wire API.
///
/// Applied ONLY once the handshake has fallen back to the legacy layout (see
/// `LEGACY_LAYOUT_THRESHOLD`), i.e. only for a peer that cannot speak the modern
/// protocol at all. Modern sessions keep strict directional separation, so the
/// property it buys — a reflected uplink packet can never authenticate as
/// downlink — is untouched for everyone else.
fn apply_legacy_key_scheme(keys: &mut SessionKeys, legacy_wire: bool) {
    if legacy_wire {
        keys.session_key_s2c = keys.session_key;
    }
}

/// A TUN fd that `AsyncFd` may poll but must never close. Ownership lives in
/// [`SessionRuntime`] so a disconnect can destroy the tun device immediately,
/// without waiting for the tokio tasks holding these views to be dropped.
struct TunFd(RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Close a session-owned fd exactly once. `swap(-1)` makes the winner the sole
/// closer, so the number can never be closed twice (and thus never closed after
/// the OS handed it to an unrelated open).
fn close_session_fd(slot: &AtomicI32) {
    let fd = slot.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

struct ActiveSessionGuard {
    session: Arc<SessionRuntime>,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        let udp_fd = self.session.udp_control_fd.swap(-1, Ordering::SeqCst);
        if udp_fd >= 0 {
            unsafe { libc::close(udp_fd) };
        }

        let stop_fd = self.session.stop_event_fd.swap(-1, Ordering::SeqCst);
        if stop_fd >= 0 {
            unsafe { libc::close(stop_fd) };
        }

        // Normal end of a session: release the TUN duplicates here if a
        // concurrent stop_active_tunnel() did not already take them.
        close_session_fd(&self.session.tun_read_fd);
        close_session_fd(&self.session.tun_write_fd);

        let mut guard = ACTIVE_SESSION.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = guard.as_ref() {
            if Arc::ptr_eq(current, &self.session) {
                *guard = None;
            }
        }
    }
}

fn activate_session(session: Arc<SessionRuntime>) -> Result<ActiveSessionGuard> {
    let mut guard = ACTIVE_SESSION
        .lock()
        .map_err(|_| Error::Session("Active session lock poisoned".into()))?;

    if let Some(existing) = guard.as_ref() {
        if !existing.stop_requested.load(Ordering::SeqCst) {
            return Err(Error::Session(
                "Another Android tunnel session is already active".into(),
            ));
        }
        // Previous session was told to stop but the Rust task has not yet
        // exited (service destroyed before JNI returned).  Evict it so the
        // new connection can proceed; the old ActiveSessionGuard will clear
        // ACTIVE_SESSION only if ptr_eq matches — it won't touch ours.
    }

    // Propagate any stop that arrived while no session was active.
    if STOP_PENDING.swap(false, Ordering::SeqCst) {
        session.stop_requested.store(true, Ordering::SeqCst);
    }

    *guard = Some(session.clone());
    Ok(ActiveSessionGuard { session })
}

pub fn stop_active_tunnel() {
    let (udp_fd, stop_fd) = {
        let guard = ACTIVE_SESSION.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .map(|s| {
                // Release the TUN duplicates NOW, not whenever the native call
                // finishes unwinding. Kotlin closes its ParcelFileDescriptor on
                // disconnect and waits only 3 s for that unwind; anything still
                // holding a duplicate past that point keeps the tun device alive
                // with the VPN address on it, and the next session's interface
                // then competes with a zombie for the app's packets (issue #71).
                close_session_fd(&s.tun_read_fd);
                close_session_fd(&s.tun_write_fd);
                // Set the flag FIRST so early init phases (DNS lookup, socket
                // creation) see it before the eventfd/UDP fd are available.
                s.stop_requested.store(true, Ordering::SeqCst);
                (
                    s.udp_control_fd.swap(-1, Ordering::SeqCst),
                    // swap(-1) takes OWNERSHIP of the eventfd, so a concurrent
                    // ActiveSessionGuard::drop (which also swaps) can never close
                    // it between our load and our write — the write below can't
                    // land on an unrelated reused fd.
                    s.stop_event_fd.swap(-1, Ordering::SeqCst),
                )
            })
            .unwrap_or_else(|| {
                // No active session in the window between the old session's
                // guard drop and the new session's activate_session() call.
                // Mark the flag so the next session inherits the stop.
                STOP_PENDING.store(true, Ordering::SeqCst);
                (-1, -1)
            })
    };

    if stop_fd >= 0 {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let value: u64 = 1;
            unsafe {
                let _ = libc::write(
                    stop_fd,
                    &value as *const u64 as *const libc::c_void,
                    std::mem::size_of::<u64>(),
                );
            };
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let v: u8 = 1;
            unsafe {
                let _ = libc::write(stop_fd, &v as *const u8 as *const libc::c_void, 1);
            };
        }
        // We took ownership via swap(-1) above, so we must close it here — the
        // ActiveSessionGuard will see -1 and skip it.
        unsafe { libc::close(stop_fd) };
    }

    if udp_fd >= 0 {
        unsafe {
            libc::shutdown(udp_fd, libc::SHUT_RDWR);
            libc::close(udp_fd);
        };
    }
}

/// A watchdog firing on a session that handshaked with a descriptor-derived
/// covert mask indicts that mask. A cached descriptor the server still ACCEPTS
/// for the handshake (the tag validates, the PFS ratchet completes, keepalives
/// flow) but disagrees with on the data plane leaves the tunnel permanently
/// "connected" with a dead data path: the server drops every uplink DATA packet
/// with an AEAD failure, the watchdog reconnects, and the next attempt resolves
/// the very same descriptor mask — forever. That is the shape behind issue #71,
/// where clearing app data (which drops the persisted descriptors) restores
/// traffic for exactly one connection.
///
/// The existing `HANDSHAKE_FAIL_STREAK` net only covers handshakes that never
/// complete, so it never fires here. Condemn the descriptor explicitly instead:
/// clear the in-process store, tell the platform to drop its persisted copy, and
/// pin the streak at the fallback threshold so the next attempt resolves a
/// builtin preset every server reproduces.
///
/// Scoped tightly so a HEALTHY covert session is never punished: descriptor
/// masks do work, and a watchdog can also fire for ordinary reasons (the phone
/// moved between networks, the carrier dropped the flow). Only a session that
/// carried NO downlink DATA at all — handshake and keepalives fine, data plane
/// never once alive — indicts the mask. A session that ran and then stalled
/// keeps its descriptors and simply reconnects, as before.
fn condemn_descriptor_mask_after_watchdog(mask_id: &str, reason: &str, data_plane_proven: bool) {
    if data_plane_proven || !mask_id.starts_with("bootstrap:") {
        return;
    }
    log::warn!(
        "aivpn: {reason} on a session handshaked with covert descriptor mask '{mask_id}' — \
         discarding cached descriptors and falling back to a builtin preset for the next attempt"
    );
    if let Ok(mut g) = BOOTSTRAP_DESCRIPTORS.lock() {
        g.clear();
    }
    DISCARD_PERSISTED_DESCRIPTORS.store(true, Ordering::Relaxed);
    DESCRIPTORS_DISTRUSTED.store(true, Ordering::Relaxed);
    HANDSHAKE_FAIL_STREAK.store(HANDSHAKE_FALLBACK_THRESHOLD, Ordering::Relaxed);
}

/// Polled by the platform after `run_tunnel_android` returns: `true` means the
/// app-persisted bootstrap descriptor blob for this server must be deleted (see
/// [`condemn_descriptor_mask_after_watchdog`]). Reading it clears the flag.
pub fn take_discard_persisted_descriptors() -> bool {
    DISCARD_PERSISTED_DESCRIPTORS.swap(false, Ordering::Relaxed)
}

/// Called by the Kotlin restartJob after cancelAndJoin() — clears any pending
/// stop that was set during the cleanup phase so the intentional new connection
/// is not immediately stopped by a stale flag.
pub fn clear_pending_stop() {
    STOP_PENDING.store(false, Ordering::SeqCst);
}

pub fn get_active_upload_bytes() -> u64 {
    ACTIVE_SESSION
        .lock()
        .ok()
        .and_then(|guard| {
            guard
                .as_ref()
                .map(|s| s.upload_bytes.load(Ordering::Relaxed))
        })
        .unwrap_or(0)
}

pub fn get_active_download_bytes() -> u64 {
    ACTIVE_SESSION
        .lock()
        .ok()
        .and_then(|guard| {
            guard
                .as_ref()
                .map(|s| s.download_bytes.load(Ordering::Relaxed))
        })
        .unwrap_or(0)
}

// ──────────── Upload-task packet encryptor ────────────

/// FIFO of one-shot acknowledgements for in-flight `KeyRotate` responses.
///
/// The receive-loop rekey handler pushes a sender here *before* enqueueing its
/// `KeyRotate` response on the upload control channel, then blocks on the paired
/// receiver until the upload task's single encryptor has actually encrypted that
/// response (see [`AndroidEncryptor::encrypt_control`]). Only after that ack does
/// the handler publish the new keys into `key_rotate_slot`, guaranteeing the
/// response is never encrypted with a key the server has not yet installed.
type RekeyAckQueue = Arc<Mutex<VecDeque<oneshot::Sender<()>>>>;

/// One-shot old-key override for a RE-SENT `KeyRotate` response.
///
/// When the server retransmits a KeyRotate (our first response was lost), the
/// receive loop stages `(old_keys, current_keys)` here before enqueueing the
/// SAME response again: `encrypt_control` swaps the OLD keys in for that one
/// packet — the server is still on them — then restores the current keys. The
/// send counter is shared and MONOTONIC across both keys, so the temporary
/// swap can never reuse a (key, nonce) pair. Consumed only by KeyRotate
/// payloads; the initial-response path never sets it (mirrors the desktop
/// client.rs upload-key swap/restore rendezvous).
type RekeyResendSlot = Arc<Mutex<Option<(SessionKeys, SessionKeys)>>>;

/// Upload-side [`PacketEncryptor`] for Android: wraps a [`MimicryEncryptor`] and
/// owns the single send counter for the session. All steady-state outbound
/// packets (data, keepalive, control) go through this one encryptor so no two
/// senders ever reuse a ChaCha20-Poly1305 nonce under the same session key.
struct AndroidEncryptor {
    inner: MimicryEncryptor,
    session: Arc<SessionRuntime>,
    keepalive_sent_ms: Arc<AtomicU64>,
    key_rotate_slot: Arc<Mutex<Option<SessionKeys>>>,
    rekey_ack: RekeyAckQueue,
    rekey_resend_keys: RekeyResendSlot,
}

impl AndroidEncryptor {
    fn check_key_rotation(&mut self) {
        if let Some(new_keys) = self
            .key_rotate_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            self.inner.update_keys(new_keys);
        }
    }
}

impl PacketEncryptor for AndroidEncryptor {
    fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.check_key_rotation();
        self.inner.encrypt_data(payload)
    }

    fn encrypt_control(&mut self, payload: &ControlPayload) -> Result<Vec<u8>> {
        // A KeyRotate response must go out under the pre-rotation keys, so a
        // pending rotation is deliberately NOT applied to it (the receive loop
        // only publishes the new keys into `key_rotate_slot` after we ack).
        // Every OTHER control packet applies the rotation like encrypt_data —
        // a data-idle session (only keepalives/quality reports flowing) must
        // still migrate the upload encryptor off the stale keys.
        let is_rotate = matches!(payload, ControlPayload::KeyRotate { .. });
        if !is_rotate {
            self.check_key_rotation();
        }
        // A RE-SENT response (server retransmitted KeyRotate because our first
        // response was lost) must go out under the PREVIOUS keys the server can
        // still read: swap them in for this one packet, then restore. The
        // shared monotonic send counter makes the old-key send nonce-safe.
        let restore = if is_rotate {
            self.rekey_resend_keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .map(|(old_keys, current_keys)| {
                    self.inner.update_keys(old_keys);
                    current_keys
                })
        } else {
            None
        };
        let pkt = self.inner.encrypt_control(payload);
        if let Some(current_keys) = restore {
            self.inner.update_keys(current_keys);
        }
        let pkt = pkt?;
        if is_rotate {
            if let Some(ack) = self
                .rekey_ack
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
            {
                let _ = ack.send(());
            }
        }
        Ok(pkt)
    }

    fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
        // Apply a pending rotation here too: a session sending ONLY keepalives
        // otherwise strands the upload encryptor on pre-rekey keys until the
        // next data packet.
        self.check_key_rotation();
        let now_ms = aivpn_common::crypto::current_timestamp_ms();
        self.keepalive_sent_ms.store(now_ms, Ordering::Relaxed);
        self.inner.encrypt_keepalive_ts(now_ms)
    }

    fn on_data_sent(&mut self, payload_len: usize) {
        self.session
            .upload_bytes
            .fetch_add(payload_len as u64, Ordering::Relaxed);
    }

    fn take_fec_repair(&mut self) -> Option<Vec<u8>> {
        self.inner.take_fec_repair()
    }
}

// ──────────── Entry point ────────────

/// Blocking async function that runs the whole tunnel session.
/// Returns Err on any tunnel failure (causes the Kotlin reconnect loop to kick in).
pub async fn run_tunnel_android(
    vm: JavaVM,
    vpn_service: GlobalRef,
    tun_fd_int: RawFd,
    server_host: String,
    server_port: u16,
    server_key: [u8; 32],
    psk: Option<[u8; 32]>,
    mtls_cert: Option<Vec<u8>>,
    mdh_len: usize,
    adaptive_level: u8,
    static_privkey: Option<[u8; 32]>,
    preferred_mask: Option<String>,
    server_signing_key: Option<[u8; 32]>,
    // §3 Polymorphic masks: when set, request a per-session perturbed variant of
    // this base mask id from the server right after the handshake completes.
    polymorphic_base: Option<String>,
    // §2 crowdsourced blocking feedback — opt-in, OFF by default. When true (and
    // `country_code` is set), reports a single success outcome for the mask this
    // connection used, once per session.
    share_mask_feedback: bool,
    // §2 crowdsourced blocking feedback — opt-in, OFF by default. When true, the
    // tunnel logs `RegionalMaskHints` pushed by the server (mask selection does not
    // yet consult them — same v1 scope as the desktop client).
    receive_mask_hints: bool,
    // ISO-3166-1 alpha-2 country code the client believes it is in. Required for
    // `share_mask_feedback` to have any effect.
    country_code: Option<[u8; 2]>,
    // §2 crowdsourced blocking feedback — JSON-encoded `Vec<MaskOutcome>` of
    // outcomes the platform accumulated across PRIOR failed/succeeded attempts
    // (not including this one) and has not yet reported, or `None`/unparsable
    // for an empty batch. Merged with a success entry for this attempt's mask
    // and sent as a single `MaskFeedback` on success (mirrors desktop's
    // persisted `MaskFeedbackLog::aggregate_unreported`, adapted to the
    // single-shot JNI: the platform owns persistence across reconnects).
    prior_outcomes_json: Option<String>,
    // App-persisted bootstrap descriptors (JSON array of signed
    // `BootstrapDescriptor`s, or `None`/empty for none) that the platform saved
    // from a PRIOR session's `BootstrapDescriptorUpdate`s. Signature-verified
    // (against `server_signing_key` when set) and validity-filtered, then loaded
    // into the descriptor store BEFORE the handshake so the very first packet of
    // this process can be shaped with a COVERT rotated descriptor mask rather
    // than a fingerprintable public preset (mirrors desktop
    // `bootstrap_cache::select_initial_mask`). A truly-first-ever connect (no
    // persisted descriptor yet) still uses the preset — acceptable residual.
    cached_descriptors_json: Option<String>,
) -> Result<()> {
    let level = AdaptiveLevel::from_u8(adaptive_level);
    let session = Arc::new(SessionRuntime::new());
    let _active_session_guard = activate_session(session.clone())?;

    // §2 crowdsourced blocking feedback — reset per-session state so a prior
    // attempt's outcome/FeedbackConfig is never misattributed to this one.
    // Done up front (before the handshake) since `EVER_CONNECTED` is set to
    // `true` as soon as the PFS ratchet completes, well before the
    // "Main forwarding loop" section further down where the other
    // per-session statics (`ACTIVE_ADAPTIVE_LEVEL`, recording feedback) are
    // reset.
    EVER_CONNECTED.store(false, Ordering::Relaxed);
    ACTIVE_FEEDBACK_THRESHOLD.store(0, Ordering::Relaxed);
    ACTIVE_FEEDBACK_INTERVAL.store(0, Ordering::Relaxed);
    MASK_FEEDBACK_SENT.store(false, Ordering::Relaxed);
    *ATTEMPTED_MASK_FAMILY
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    MASK_CATALOG_SEQ.store(0, Ordering::Relaxed);
    *ACTIVE_MASK_CATALOG_JSON
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    REGIONAL_HINTS_SEQ.store(0, Ordering::Relaxed);
    *ACTIVE_REGIONAL_HINTS_JSON
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;

    // §M2 per-server descriptor isolation: if the user switched to a DIFFERENT
    // server/profile since the last session, clear the process-global descriptor
    // store so server A's rotated descriptors never shape server B's handshake.
    // Same server → keep the store so an internal reconnect stays covert. Done
    // BEFORE the preload/handshake-mask resolution below.
    {
        let mut last = LAST_SERVER_KEY.lock().unwrap_or_else(|e| e.into_inner());
        if last.as_ref() != Some(&server_key) {
            if let Ok(mut g) = BOOTSTRAP_DESCRIPTORS.lock() {
                g.clear();
            }
            *last = Some(server_key);
        }
    }

    // Re-populate the descriptor store from app-persisted descriptors BEFORE the
    // handshake so a COLD-START first handshake resolves a COVERT rotated
    // descriptor mask instead of a public preset. Idempotent (deduped by
    // descriptor_id), so re-running it on each reconnect is harmless.
    if let Some(json) = cached_descriptors_json.as_deref() {
        if !json.trim().is_empty() {
            let loaded = preload_persisted_descriptors(json, server_signing_key.as_ref());
            if loaded > 0 {
                log::info!(
                    "aivpn: preloaded {} persisted bootstrap descriptor(s) for covert first handshake",
                    loaded
                );
            }
        }
    }

    // Snapshot the streak ONCE: it selects both the handshake mask (below) and
    // the wire layout, and the two must not disagree mid-setup.
    let handshake_fail_streak = HANDSHAKE_FAIL_STREAK.load(Ordering::Relaxed);
    // Past LEGACY_LAYOUT_THRESHOLD we are talking to a pre-Variant-A server (see
    // that constant): tag-prefix framing AND a single, non-directional session
    // key. Both sides of that contract are applied from here on.
    let legacy_wire = handshake_fail_streak >= LEGACY_LAYOUT_THRESHOLD;
    if legacy_wire {
        log::warn!(
            "aivpn: {} handshakes never connected — retrying with the pre-Variant-A wire layout \
             (tag prefix + single session key) for compatibility with an older server",
            handshake_fail_streak
        );
    }

    // ── 1. Ephemeral keypair + initial session keys ──
    let mut keypair = KeyPair::generate();
    let mut dh = keypair.compute_shared(&server_key)?;
    let mut keys = derive_session_keys(&dh, psk.as_ref(), &keypair.public_key_bytes());
    apply_legacy_key_scheme(&mut keys, legacy_wire);

    // ── 2. Create stop signal immediately — before DNS — so a disconnect press
    //    during a slow/hung cellular DNS is handled instantly, not after a 5 s wait.
    let stop_signal = create_stop_signal(&session)?;

    // Resolve host; race against stop signal so disconnect is always responsive.
    let dest_str = format!("{}:{}", server_host, server_port);
    let dest: SocketAddr = tokio::select! {
        biased;
        _ = wait_for_stop_signal(&stop_signal) => {
            return Ok(());
        }
        result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host(&dest_str),
        ) => {
            result
                .map_err(|_| Error::Session("DNS lookup timeout (5 s)".into()))?
                .map_err(Error::Io)?
                .find(|a| a.is_ipv4())
                .ok_or_else(|| Error::Session("Cannot resolve server host to IPv4".into()))?
        }
    };

    if session.stop_requested.load(Ordering::SeqCst) {
        return Ok(());
    }

    let raw_udp_fd = create_protected_udp_socket(&vm, &vpn_service, dest, &session)?;
    // Own the UDP fd immediately so the dup/fcntl/AsyncFd failure paths below
    // (each an early `return Err`) close it via Drop instead of leaking one fd
    // per attempt in a tight reconnect loop (LOW-1). Consumed by `UdpSocket::from`
    // once all fallible setup has succeeded.
    // SAFETY: create_protected_udp_socket returns a fresh, exclusively-owned fd.
    let owned_udp = unsafe { OwnedFd::from_raw_fd(raw_udp_fd) };

    if session.stop_requested.load(Ordering::SeqCst) {
        return Ok(());
    }

    // ── 3. Set TUN fd to non-blocking for AsyncFd ──
    let owned_tun_fd = unsafe { libc::dup(tun_fd_int) };
    if owned_tun_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    let fcntl_ret = unsafe { libc::fcntl(owned_tun_fd, libc::F_SETFL, libc::O_NONBLOCK) };
    if fcntl_ret < 0 {
        unsafe { libc::close(owned_tun_fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    // Hand the duplicate to the session, which owns it from here on; `tun` only
    // borrows it (see `TunFd`) so a disconnect can close it immediately.
    session.tun_write_fd.store(owned_tun_fd, Ordering::SeqCst);
    let tun = match AsyncFd::new(TunFd(owned_tun_fd)) {
        Ok(tun) => tun,
        Err(e) => {
            close_session_fd(&session.tun_write_fd);
            return Err(Error::Io(e));
        }
    };

    // Convert the owned UDP fd to a tokio UdpSocket (already connected to server).
    let std_udp = std::net::UdpSocket::from(owned_udp);
    std_udp.set_nonblocking(true)?;
    let udp = Arc::new(UdpSocket::from_std(std_udp)?);

    // ── 4. Send init handshake (Control/Keepalive + obfuscated eph_pub) ──
    let mut send_counter: u64 = 0;
    let mut send_seq: u16 = 0;
    // Tracks which server-provided new_eph_pub we already ratcheted for, so a
    // duplicated/redelivered KeyRotate request (plain UDP duplication is
    // sufficient, no server-side resend needed) is a no-op instead of
    // generating a fresh keypair and re-deriving from the already-once-
    // rotated key — a key the server would never learn about. Same class of
    // bug as the ServerHello duplicate-processing fix, mirrored here.
    let mut ratcheted_rekey_eph_pub: Option<[u8; 32]> = None;
    // The client eph pub we RESPONDED with for `ratcheted_rekey_eph_pub`. If
    // the response is lost, the server retransmits KeyRotate (fresh transport
    // packet, OLD keys) — the handler re-sends this SAME response (never a
    // fresh keypair: whichever copy the server commits must yield the keys we
    // already switched to) encrypted with the old keys the server can still
    // read, so a lost response self-heals in-band. Function-local, so a
    // reconnect (fresh run_tunnel_android call) resets it.
    let mut rekey_response_eph: Option<[u8; 32]> = None;
    // Variant A wire layout: the handshake + control plane speak the initial
    // (bootstrap) mask's layout. A new-layout preset embeds the resonance tag
    // inside its protocol header (webrtc tag_offset=8, quic=6) instead of a
    // separate offset-0 prefix; the server extracts the tag/eph per that mask's
    // native layout, so client and server MUST agree here. The FULL mask is
    // kept (not just its tag_offset) so `build_shaped_mdh_packet` can shape the
    // handshake/control MDH from the mask's `header_spec` (FIX 3: DPI-shaped
    // opening packets instead of pure-random noise). Resolved the same way as
    // `initial_mask` below (`preferred_mask` + PSK are stable → identical mask).
    // Resilience net: after HANDSHAKE_FALLBACK_THRESHOLD consecutive handshake
    // timeouts, resolve WITHOUT the (possibly unmatchable) cached descriptors so
    // the attempt uses a builtin preset every server matches. Snapshot the
    // streak once so `initial_mask` below resolves identically.
    if handshake_fail_streak >= HANDSHAKE_FALLBACK_THRESHOLD {
        log::warn!(
            "aivpn: {} consecutive handshakes never connected — falling back to a builtin preset mask (a cached bootstrap descriptor may be unmatchable by this server)",
            handshake_fail_streak
        );
    }
    let handshake_mask = resolve_handshake_mask_resilient(
        preferred_mask.as_deref(),
        &current_bootstrap_descriptors(),
        psk.as_ref(),
        handshake_fail_streak,
    );
    // §2 crowdsourced blocking feedback: publish the attempted mask family HERE —
    // as soon as the handshake mask is resolved and BEFORE the ServerHello wait —
    // so the platform can attribute a handshake TIMEOUT (the blocked-mask case) to
    // the right family. Setting it only after `EVER_CONNECTED` (further down) left
    // it `None` on a failed handshake, so `recordFeedbackOutcome` recorded nothing
    // and the consecutive-fail/blocked-mask counter never fired. `initial_mask`
    // below resolves identically, so the value is unchanged.
    *ATTEMPTED_MASK_FAMILY
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(base_mask_family(&handshake_mask.mask_id));
    // The handshake and every control packet MUST be framed at the handshake
    // mask's OWN header length, not the protocol default. The server reads the
    // embedded ephemeral key at that mask's `eph_pub_offset`, which for a
    // 14-byte-header mask (quic_https_v2 and anything derived from it) is 14 —
    // framing at 20 puts the key six bytes past where the server looks, so it
    // derives the wrong session keys and rejects every candidate as a tag
    // mismatch, forever. The PSK picks the preset, so this bricked roughly one
    // client in five: `--show-client` handed out a key that could never connect.
    // Masks with a 20-byte header are unaffected — the two values are equal —
    // which is why it stayed hidden.
    let hs_mdh_len = handshake_mask.mdh_len();

    // Every distinct downlink MDH length this session may see, current first.
    // The server frames different downlink packets with different masks
    // (bootstrap for early DATA, runtime/catalog for control and rekey, a
    // polymorphic variant later); decoding with a single fixed length silently
    // drops any packet whose mask differs and strands the tunnel on the first
    // rekey. Seeded with the fixed handshake/control length plus the bootstrap
    // mask's own length; extended when MaskUpdate arrives.
    let mut recv_mdh_candidates: Vec<usize> = vec![mdh_len];
    let hs_mdh = handshake_mask.mdh_len();
    if !recv_mdh_candidates.contains(&hs_mdh) {
        recv_mdh_candidates.push(hs_mdh);
    }
    let keepalive = ControlPayload::Keepalive { send_ts: 0 }.encode()?;
    {
        let obf_pub = obfuscate_client_eph_pub(&keypair, &server_key);
        let inner = build_inner_packet(InnerType::Control, send_seq, &keepalive);
        let pkt = build_shaped_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            Some(&obf_pub),
            hs_mdh_len,
            &handshake_mask,
        )?;
        send_seq = send_seq.wrapping_add(1);
        udp.send(&pkt).await?;
    }

    // ── 5. Wait for ServerHello with timeout ──
    let mut recv_buf = vec![0u8; BUF_SIZE];
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut retry_count: u32 = 0;
    let mut recv_win = RecvWindow::new();
    let server_network_cfg = loop {
        let now = Instant::now();
        if now >= handshake_deadline {
            // Feed the resilience net: a timeout here is the signature of an
            // unmatchable handshake mask (tag mismatch server-side is silent).
            HANDSHAKE_FAIL_STREAK.fetch_add(1, Ordering::Relaxed);
            return Err(Error::Session("Handshake timeout (10 s)".into()));
        }

        let wait = std::cmp::min(
            HANDSHAKE_RETRY_INTERVAL,
            handshake_deadline.saturating_duration_since(now),
        );
        let retry = time::sleep(wait);
        tokio::pin!(retry);

        tokio::select! {
            _ = wait_for_stop_signal(&stop_signal) => {
                return Ok(());
            }

            res = udp.recv(&mut recv_buf) => {
                match res {
                    Ok(n) => {
                        // Tolerate a reordered early control push (or an
                        // undecodable datagram) instead of failing the whole
                        // attempt on the first packet — keep waiting for the
                        // real ServerHello until the handshake deadline
                        // (desktop's dispatch loop just skips it).
                        // The ServerHello comes framed at the length of the mask the server
                        // matched. Probe on throwaway clones so a 14-byte-header session is
                        // not discarded as a timeout; the real decode below then runs once
                        // with the length that actually parses.
                        let hello_mdh_len = if hs_mdh_len != mdh_len {
                            let (mut k, mut w, mut c) = (keys.clone(), recv_win.clone(), send_counter);
                            if process_server_hello_with_mdh_len(
                                &recv_buf[..n], &mut k, &keypair, &mut w, &mut c, hs_mdh_len,
                                server_signing_key.as_ref(),
                            )
                            .is_ok()
                            {
                                hs_mdh_len
                            } else {
                                mdh_len
                            }
                        } else {
                            mdh_len
                        };
                        match process_server_hello_with_mdh_len(
                            &recv_buf[..n],
                            &mut keys,
                            &keypair,
                            &mut recv_win,
                            &mut send_counter,
                            hello_mdh_len,
                            server_signing_key.as_ref(),
                        ) {
                            Ok(cfg) => {
                                // The ratchet re-derived `keys`; re-apply the
                                // legacy contract before anything uses them.
                                apply_legacy_key_scheme(&mut keys, legacy_wire);
                                break cfg;
                            }
                            Err(e) => {
                                log::debug!(
                                    "aivpn: non-ServerHello datagram during handshake — ignoring: {e}"
                                );
                            }
                        }
                    }
                    Err(_) if session.stop_requested.load(Ordering::SeqCst) => {
                        return Ok(());
                    }
                    Err(e) => return Err(Error::Io(e)),
                }
            }
            _ = &mut retry => {
                if session.stop_requested.load(Ordering::SeqCst) {
                    return Ok(());
                }
                retry_count += 1;
                // Rotate keypair only once, on the 2nd retry (~1.5 s after first send).
                // Rotating on every retry created a new server session per 750 ms (~13
                // ghost sessions per 10 s timeout), which caused CGNAT per-IP cap (5)
                // to be hit on the 2nd handshake attempt.  A single rotation at retry 2
                // limits server ghost sessions to 2 max while still forcing a fresh
                // handshake if the server lost the original one.
                if retry_count == 2 {
                    keypair = KeyPair::generate();
                    dh = keypair.compute_shared(&server_key)?;
                    keys = derive_session_keys(&dh, psk.as_ref(), &keypair.public_key_bytes());
                    apply_legacy_key_scheme(&mut keys, legacy_wire);
                    send_counter = 0;
                    send_seq = 0;
                    // Counters recorded from any pre-rotation datagram no longer
                    // apply to the fresh session the server will create.
                    recv_win.reset();
                }
                let obf_pub = obfuscate_client_eph_pub(&keypair, &server_key);
                let inner = build_inner_packet(InnerType::Control, send_seq, &keepalive);
                let pkt = build_shaped_mdh_packet(&keys, &mut send_counter, &inner, Some(&obf_pub), hs_mdh_len, &handshake_mask)?;
                send_seq = send_seq.wrapping_add(1);
                udp.send(&pkt).await?;
            }
        }
    };
    let base_keepalive = server_network_cfg
        .as_ref()
        .and_then(|c| c.keepalive_secs)
        .filter(|&s| s > 0)
        .map(|s| Duration::from_secs(s as u64))
        .unwrap_or(KEEPALIVE_INTERVAL);
    let keepalive_interval = if level == AdaptiveLevel::Off {
        base_keepalive
    } else {
        base_keepalive.min(Duration::from_secs(level.keepalive_secs()))
    };
    // Shared keepalive interval (ms) the upload loop polls each tick and re-arms
    // from when it changes (see upload_pipeline::run_upload_loop). Seeded with the
    // initial interval above; the AdaptiveHint handler updates it live so a
    // server-hinted level change actually re-times keepalives without a reconnect
    // — parity with desktop client.rs's `keepalive_interval_ms` atomic.
    let keepalive_ms = Arc::new(portable_atomic::AtomicU64::new(
        keepalive_interval.as_millis() as u64,
    ));
    let mut transition_recv_keys: Option<SessionKeys> = Some({
        let mut pre_ratchet = derive_session_keys(&dh, psk.as_ref(), &keypair.public_key_bytes());
        apply_legacy_key_scheme(&mut pre_ratchet, legacy_wire);
        pre_ratchet
    });
    let mut transition_recv_deadline = Some(Instant::now() + Duration::from_secs(2));
    let mut transition_recv_win = std::mem::take(&mut recv_win);
    // Hard ceiling on rekey-grace re-arms (see REKEY_TRANSITION_HARD_CAP).
    // Armed once per inline rekey at the key switch; never extended.
    let mut transition_grace_hard: Option<Instant> = None;
    if let Some(cert) = mtls_cert {
        let cert_len_debug = cert.len();
        let cert_payload = ControlPayload::ClientCert { cert_bytes: cert }.encode()?;
        let inner = build_inner_packet(InnerType::Control, send_seq, &cert_payload);
        let pkt = build_shaped_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            None,
            hs_mdh_len,
            &handshake_mask,
        )?;
        send_seq = send_seq.wrapping_add(1);
        udp.send(&pkt).await?;
        log::debug!("mTLS: ClientCert sent ({} bytes)", cert_len_debug);
    }
    // Immediately send a keepalive to prevent CGNAT outbound mapping expiry.
    // Megafon/MTS CGNAT can expire the outbound UDP binding in the gap between the
    // last handshake packet and the upload pipeline's first keepalive tick (which is
    // intentionally skipped). One early packet keeps the NAT entry alive.
    {
        let ka = ControlPayload::Keepalive { send_ts: 0 }.encode()?;
        let inner = build_inner_packet(InnerType::Control, send_seq, &ka);
        if let Ok(pkt) = build_shaped_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            None,
            hs_mdh_len,
            &handshake_mask,
        ) {
            send_seq = send_seq.wrapping_add(1);
            let _ = udp.send(&pkt).await;
        }
    }
    // §2 L2 failure attribution — the handshake + PFS ratchet above completed
    // successfully, so this attempt is "connected" in the same sense as
    // desktop client.rs's `ClientState::Connected` (set right after the same
    // ratchet step). The platform polls this after `run_tunnel_android`
    // returns to decide whether to attribute a failure to this attempt's
    // mask family.
    EVER_CONNECTED.store(true, Ordering::Relaxed);
    HANDSHAKE_FAIL_STREAK.store(0, Ordering::Relaxed);
    notify_tunnel_ready(&vm, &vpn_service, &server_host);
    log::info!("aivpn: handshake + PFS ratchet complete");

    // Warmup: 4 keepalives spaced 100 ms apart after the handshake.
    // Primary fix is local-port reuse (see LAST_LOCAL_PORT above); this is
    // the fallback for carriers that have a brief delay before updating their
    // inbound CGNAT entry even after the outbound mapping was refreshed.
    // Each outbound packet nudges the CGNAT to route subsequent downlink to
    // the current socket rather than the previous (closed) one.
    for _ in 0..4u8 {
        tokio::select! {
            biased;
            _ = wait_for_stop_signal(&stop_signal) => {
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if let Ok(ka) = (ControlPayload::Keepalive { send_ts: 0 }).encode() {
                    let inner = build_inner_packet(InnerType::Control, send_seq, &ka);
                    if let Ok(pkt) = build_shaped_mdh_packet(&keys, &mut send_counter, &inner, None, hs_mdh_len, &handshake_mask) {
                        send_seq = send_seq.wrapping_add(1);
                        let _ = udp.send(&pkt).await;
                    }
                }
            }
        }
    }

    // Device enrollment: send static key proof after ratchet (PFS-protected).
    if let Some(priv_bytes) = static_privkey {
        let static_kp = KeyPair::from_private_key(priv_bytes);
        if let Ok(dh_proof) = static_kp.compute_shared(&server_key) {
            let enrollment = ControlPayload::DeviceEnrollment {
                static_pub: static_kp.public_key_bytes(),
                dh_proof,
            };
            if let Ok(encoded) = enrollment.encode() {
                let inner = build_inner_packet(InnerType::Control, send_seq, &encoded);
                if let Ok(pkt) = build_shaped_mdh_packet(
                    &keys,
                    &mut send_counter,
                    &inner,
                    None,
                    hs_mdh_len,
                    &handshake_mask,
                ) {
                    send_seq = send_seq.wrapping_add(1);
                    let _ = udp.send(&pkt).await;
                }
            }
        }
    }

    // ── 6. Main forwarding loop ──
    let mut udp_buf = vec![0u8; aivpn_common::protocol::UDP_RECV_BUF_SIZE];
    let mut last_rx = Instant::now();
    // DATA-plane liveness (see `data_watchdog_verdict`): stamped ONLY when an
    // authenticated DATA payload is written to the TUN. `data_stall_started`
    // anchors the stall clock at the FIRST uplink data observed after the last
    // downlink data, so a long-idle tunnel isn't condemned the moment an app
    // sends a single packet.
    let mut last_data_rx = Instant::now();
    let mut upload_at_last_data_rx = session.upload_bytes.load(Ordering::Relaxed);
    let mut data_stall_started: Option<Instant> = None;
    let mut data_stall_strikes: u32 = 0;
    // The data watchdog arms only once THIS session has delivered at least one
    // downlink DATA packet. An idle TUN still emits unanswerable junk (ICMPv6
    // ND, IGMP, telemetry beacons to dead hosts) that counts as uplink data
    // with no possible response — without this gate, a perfectly healthy idle
    // tunnel reconnected every DATA_RX_SILENCE seconds (observed live on the
    // netns stand). A never-proven data plane stays covered by the handshake
    // first-contact and RX_SILENCE nets, exactly as before this watchdog.
    let mut data_plane_proven = false;

    // Split upload into a dedicated pipeline:
    // TUN reader task -> channel -> UDP sender/encrypt task.
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_SIZE);
    let (err_tx, mut err_rx) = mpsc::channel::<String>(16);
    let tun_err_tx = err_tx.clone();
    let sender_err_tx = err_tx.clone();

    let read_fd = unsafe { libc::dup(tun.as_raw_fd()) };
    if read_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    session.tun_read_fd.store(read_fd, Ordering::SeqCst);
    let tun_read = match AsyncFd::new(TunFd(read_fd)) {
        Ok(tun_read) => tun_read,
        Err(e) => {
            close_session_fd(&session.tun_read_fd);
            return Err(Error::Io(e));
        }
    };

    let tun_reader_task = tokio::spawn(async move {
        let mut tun_buf = vec![0u8; BUF_SIZE];
        loop {
            match tun_async_read(&tun_read, &mut tun_buf).await {
                Ok(n) => {
                    if n == 0 {
                        continue;
                    }
                    if tun_buf[0] >> 4 != 4 {
                        continue;
                    }
                    if tun_tx.send(tun_buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tun_err_tx.send(format!("TUN read failed: {e}")).await;
                    break;
                }
            }
        }
    });

    let keepalive_sent_ms = Arc::new(AtomicU64::new(0));
    let mut quality_tracker = QualityTracker::new();

    // Reset per-session hint so getAdaptiveLevelHint() returns 0 ("no hint yet") for this session.
    ACTIVE_ADAPTIVE_LEVEL.store(0, Ordering::Relaxed);
    // Reset per-session recording feedback so a stale message from a previous
    // session is never surfaced to a new one.
    *ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;

    // Control-payload channel: lets JNI send RecordingStart/Stop without reconnecting.
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<ControlPayload>(8);
    // Sender clone for control payloads that originate in the receive loop below
    // (e.g. QualityReport). They MUST be encrypted by the single upload-task
    // encryptor: building them here with the receive loop's own `send_counter`
    // reuses ChaCha20-Poly1305 nonces (nonce == counter) already consumed by the
    // upload task under the same session key — leaking keystream and making the
    // server drop them as replays. Matches the desktop client, which routes
    // QualityReport through its control channel (client.rs `send_control`).
    let ctrl_tx_recv_loop = ctrl_tx.clone();
    {
        let mut guard = ACTIVE_CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(ctrl_tx);
    }
    // RAII guard: clears ACTIVE_CONTROL_TX when run_tunnel_android returns (any path).
    struct CtrlTxGuard;
    impl Drop for CtrlTxGuard {
        fn drop(&mut self) {
            let mut g = ACTIVE_CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner());
            *g = None;
        }
    }
    let _ctrl_tx_guard = CtrlTxGuard;

    // The data plane MUST use the very mask the handshake was accepted with: the
    // server pins the session to that mask and reads the ciphertext at its
    // header length. Re-resolving here used to look equivalent — same inputs,
    // same function — but it is not: the server pushes fresh
    // BootstrapDescriptorUpdates as soon as the session is up, so by this point
    // `current_bootstrap_descriptors()` can return a NEWER descriptor than the
    // one that shaped the handshake. The resolver then picks a different
    // candidate, and if its header length differs the server decrypts every
    // uplink DATA packet at the wrong offset: the tag still matches (it does not
    // depend on the mask), so the session looks alive — keepalives and quality
    // reports flow — while not one data packet gets through. Observed against a
    // live server as a continuous `aead::Error` stream at `session_offset=20`.
    let initial_mask = handshake_mask.clone();

    // (ATTEMPTED_MASK_FAMILY is published earlier, right after `handshake_mask`
    // resolves, so a handshake TIMEOUT is still attributed to the right family.
    // `initial_mask` resolves identically, so no second publish is needed here.)

    // §3 Polymorphic masks: ask the server to derive and push a per-session
    // perturbed variant of the requested base mask. Sent once, right after the
    // PFS ratchet (mirrors desktop's ClientConfig.polymorphic_base handling in
    // client.rs). The reply arrives as a normal MaskUpdate, handled by the
    // existing ControlPayload::MaskUpdate arm in the receive loop below.
    if let Some(base_mask_id) = polymorphic_base.clone() {
        if let Ok(encoded) = (ControlPayload::MaskPreference { base_mask_id }).encode() {
            let inner = build_inner_packet(InnerType::Control, send_seq, &encoded);
            if let Ok(pkt) = build_shaped_mdh_packet(
                &keys,
                &mut send_counter,
                &inner,
                None,
                hs_mdh_len,
                &handshake_mask,
            ) {
                send_seq = send_seq.wrapping_add(1);
                let _ = udp.send(&pkt).await;
            }
        }
    }

    // §2 crowdsourced blocking feedback (opt-in, OFF by default). Mirrors
    // desktop's `record_mask_outcome` + `maybe_send_mask_feedback` (client.rs),
    // collapsed to a single-shot send since `run_tunnel_android` handles
    // exactly one connection per call — Android reconnects by re-invoking
    // this function from scratch, so "once per connection" is just "once
    // here". The platform (`AivpnService.kt`) owns cross-reconnect
    // persistence and passes in `prior_outcomes_json`.
    //
    // Emits when EITHER:
    // - `share_mask_feedback` is on, in which case the entries are the
    //   platform's prior unreported outcomes merged with a success for this
    //   attempt's mask, OR
    // - `receive_mask_hints` is on, in which case entries are EMPTY — the
    //   message carries only the country code so the server can reply with
    //   `RegionalMaskHints` without the client sharing any outcome data
    //   (independent opt-in — a receive-only user still gets hints).
    //
    // A `country_code` is required in both cases (the server aggregates per
    // region).
    if let Some(country_code) = country_code {
        let want_share = share_mask_feedback;
        let want_hints = receive_mask_hints;
        if want_share || want_hints {
            let entries = if want_share {
                // Collapse to the base preset family before reporting — a raw
                // `bootstrap:{desc}:{base}:{slot}:{seed}` or
                // `polymorphic:{base}:{hex}` id carries per-session/PSK-derived
                // entropy that would leak a quasi-identifier and fragment the
                // server's k-anonymity buckets (mirrors desktop client.rs's
                // `record_mask_outcome` comment).
                let mask_family = base_mask_family(&initial_mask.mask_id);
                merge_mask_outcomes(
                    parse_prior_outcomes(prior_outcomes_json.as_deref()),
                    &mask_family,
                )
            } else {
                Vec::new()
            };
            if let Ok(encoded) = (ControlPayload::MaskFeedback {
                entries,
                country_code,
            })
            .encode()
            {
                let inner = build_inner_packet(InnerType::Control, send_seq, &encoded);
                if let Ok(pkt) = build_shaped_mdh_packet(
                    &keys,
                    &mut send_counter,
                    &inner,
                    None,
                    hs_mdh_len,
                    &handshake_mask,
                ) {
                    // The packet is fully built (and the send counter/seq
                    // already advanced) synchronously above so downstream
                    // code that continues to use `send_counter`/`send_seq`
                    // is unaffected. Only the actual send is deferred: this
                    // control message otherwise goes out at a fully
                    // deterministic offset after connection setup, which
                    // would be a usable timing fingerprint even though its
                    // contents are already hidden by the encrypted mimicry
                    // channel. A small random pre-send delay (0-3000ms),
                    // spawned so it never blocks the rest of tunnel setup,
                    // removes that fixed offset.
                    send_seq = send_seq.wrapping_add(1);
                    let udp_feedback = udp.clone();
                    tokio::spawn(async move {
                        let jitter_ms = rand::random::<u16>() % 3001;
                        time::sleep(Duration::from_millis(jitter_ms as u64)).await;
                        if udp_feedback.send(&pkt).await.is_ok() {
                            MASK_FEEDBACK_SENT.store(true, Ordering::Relaxed);
                        }
                    });
                }
            }
        }
    }

    let mask_update_slot: Arc<Mutex<Option<MaskProfile>>> = Arc::new(Mutex::new(None));
    let mask_update_for_enc = Arc::clone(&mask_update_slot);
    let key_rotate_slot: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(None));
    let key_rotate_for_enc = Arc::clone(&key_rotate_slot);
    let rekey_ack_slot: RekeyAckQueue = Arc::new(Mutex::new(VecDeque::new()));
    let rekey_ack_for_enc = Arc::clone(&rekey_ack_slot);
    let rekey_resend_slot: RekeyResendSlot = Arc::new(Mutex::new(None));
    let rekey_resend_for_enc = Arc::clone(&rekey_resend_slot);

    let udp_tx = udp.clone();
    let keys_tx = keys.clone();
    let session_for_upload = session.clone();
    let keepalive_ms_upload = keepalive_ms.clone();
    let upload_sender_task = tokio::spawn(async move {
        // R2 Phase D — client-side ML-DPI self-gate (feature `client-dpi-gate`,
        // OFF by default). Capture the mask family before `initial_mask` moves.
        #[cfg(feature = "client-dpi-gate")]
        let base_mask_id = initial_mask.mask_id.clone();

        let mut enc = AndroidEncryptor {
            inner: MimicryEncryptor::new(
                keys_tx,
                send_counter,
                send_seq,
                initial_mask,
                mask_update_for_enc,
            ),
            session: session_for_upload,
            keepalive_sent_ms,
            key_rotate_slot: key_rotate_for_enc,
            rekey_ack: rekey_ack_for_enc,
            rekey_resend_keys: rekey_resend_for_enc,
        };
        enc.inner.set_fec_group(level.fec_n());
        let config = UploadConfig {
            keepalive_interval,
            keepalive_ms: Some(keepalive_ms_upload),
            ..Default::default()
        };

        #[cfg(feature = "client-dpi-gate")]
        let mut self_gate = aivpn_common::dpi_gate::ClientSelfGate::new(0.5, base_mask_id);
        #[cfg(feature = "client-dpi-gate")]
        let inspector: Option<&mut dyn upload_pipeline::OutboundInspector> = Some(&mut self_gate);
        #[cfg(not(feature = "client-dpi-gate"))]
        let inspector: Option<&mut dyn upload_pipeline::OutboundInspector> = None;

        if let Err(e) = upload_pipeline::run_upload_loop(
            &mut tun_rx,
            Some(&mut ctrl_rx),
            &udp_tx,
            &mut enc,
            &config,
            inspector,
        )
        .await
        {
            let _ = sender_err_tx.send(format!("Upload pipeline: {e}")).await;
        }
    });
    // Periodic check for RX silence — uses a proper Interval so it's not
    // recreated every select! iteration (which would reset the timer).
    let mut rx_check = time::interval(RX_CHECK_INTERVAL);
    rx_check.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            _ = wait_for_stop_signal(&stop_signal) => {
                // Send Shutdown 3× (50 ms apart) so the server drops the session
                // immediately even if one UDP packet is lost on the mobile path.
                // Route Shutdown through the upload task's single encryptor so it
                // uses that encryptor's own counter — building it here with the
                // receive loop's separate `send_counter` would reuse a (key, nonce)
                // pair the upload task already consumed. Enqueue 3x so the server
                // drops the session even if a packet is lost, then give the upload
                // task a brief moment to flush before aborting it.
                for _ in 0..3u8 {
                    if ctrl_tx_recv_loop
                        .try_send(ControlPayload::Shutdown { reason: 0 })
                        .is_err()
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(120)).await;
                tun_reader_task.abort();
                upload_sender_task.abort();
                return Ok(());
            }

            // ── UDP → TUN (inbound from server) ──
            r = udp.recv(&mut udp_buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(_) if session.stop_requested.load(Ordering::SeqCst) => {
                        tun_reader_task.abort();
                        upload_sender_task.abort();
                        return Ok(());
                    }
                    Err(e) => return Err(Error::Io(e)),
                };
                log::debug!("aivpn: udp.recv() → {} bytes", n);
                if transition_recv_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    transition_recv_keys = None;
                    transition_recv_deadline = None;
                    transition_grace_hard = None;
                    transition_recv_win.reset();
                }
                let decoded = match decode_downlink_any_mdh_len(
                    &udp_buf[..n],
                    &keys,
                    &mut recv_win,
                    &mut recv_mdh_candidates,
                ) {
                    Ok(decoded) => {
                        Some(decoded)
                    }
                    Err(e) => {
                        log::debug!("aivpn: decode failed (primary keys): {}", e);
                        if let Some(fallback_keys) = transition_recv_keys.as_ref() {
                            let r = decode_downlink_any_mdh_len(
                                &udp_buf[..n],
                                fallback_keys,
                                &mut transition_recv_win,
                                &mut recv_mdh_candidates,
                            );
                            if r.is_err() {
                                log::debug!("aivpn: decode failed (fallback keys) — packet dropped");
                            }
                            r.ok()
                        } else {
                            None
                        }
                    }
                };

                if let Some(decoded) = decoded {
                    // Only a successfully authenticated packet proves the link is
                    // alive — advancing the watchdog on raw recv() would let
                    // undecodable (e.g. spoofed) datagrams mask a dead downlink.
                    // NOTE: `last_rx` feeds only the 120 s absolute net. Data-
                    // plane liveness is stamped in the Data arm below — control
                    // traffic (keepalive-acks, KeyRotate retransmits) must not
                    // mask a dead data downlink.
                    last_rx = Instant::now();
                    log::debug!("aivpn: decoded inner_type={:?} payload={} bytes",
                        decoded.header.inner_type, decoded.payload.len());
                    if decoded.header.inner_type == InnerType::Data && !decoded.payload.is_empty() {
                        tun_async_write(&tun, &decoded.payload).await?;
                        session
                            .download_bytes
                            .fetch_add(decoded.payload.len() as u64, Ordering::Relaxed);
                        last_data_rx = Instant::now();
                        upload_at_last_data_rx =
                            session.upload_bytes.load(Ordering::Relaxed);
                        data_stall_started = None;
                        data_stall_strikes = 0;
                        data_plane_proven = true;
                        log::debug!("aivpn: wrote {} bytes to TUN (rx total={})",
                            decoded.payload.len(),
                            session.download_bytes.load(Ordering::Relaxed));
                    }
                    // Any successfully decoded packet (including keepalive responses)
                    // proves the link is alive.
                    // Handle server-initiated inline rekey (PFS without reconnect).
                    if decoded.header.inner_type == InnerType::Control {
                        if let Ok(ctrl) = ControlPayload::decode(&decoded.payload) {
                            match ctrl {
                                ControlPayload::KeyRotate { new_eph_pub } => {
                                    if ratcheted_rekey_eph_pub == Some(new_eph_pub) {
                                        // A KeyRotate for an eph_pub we ALREADY ratcheted
                                        // against can only be a genuine server RETRANSMIT:
                                        // a network-duplicated copy carries the same
                                        // transport counter and dies at the replay window,
                                        // while a retransmit is a fresh packet under the
                                        // OLD keys (it decoded via transition_recv_keys to
                                        // get here). The server retransmits because our
                                        // rekey RESPONSE was lost — silently ignoring it
                                        // deadlocked the tunnel (client on new keys,
                                        // server on old) until the RX-silence watchdog
                                        // forced a full reconnect. Re-send the SAME
                                        // response (same client eph — never a fresh
                                        // keypair, so whichever copy the server commits
                                        // yields exactly the keys we already switched to)
                                        // under the OLD keys the server can still read
                                        // (mirrors the desktop client.rs self-heal).
                                        let (Some(old_keys), Some(response_eph)) =
                                            (transition_recv_keys.clone(), rekey_response_eph)
                                        else {
                                            log::debug!(
                                                "aivpn: duplicate KeyRotate for already-ratcheted eph_pub — no stored response/old keys, ignoring"
                                            );
                                            continue;
                                        };
                                        log::warn!(
                                            "aivpn: retransmitted KeyRotate for already-ratcheted eph_pub — rekey response likely lost; re-sending the same response under the previous keys"
                                        );
                                        // Stage the one-shot old-key override, then the
                                        // usual rendezvous so we block until THIS response
                                        // was encrypted (with the old keys swapped in).
                                        *rekey_resend_slot
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner()) =
                                            Some((old_keys, keys.clone()));
                                        let (ack_tx, ack_rx) = oneshot::channel();
                                        rekey_ack_slot
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .push_back(ack_tx);
                                        let response = ControlPayload::KeyRotate {
                                            new_eph_pub: response_eph,
                                        };
                                        if ctrl_tx_recv_loop.send(response).await.is_err() {
                                            // Nothing was enqueued — drop the unused
                                            // rendezvous and override so they cannot
                                            // mis-fire on a future KeyRotate.
                                            rekey_ack_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .pop_back();
                                            *rekey_resend_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner()) = None;
                                            log::warn!(
                                                "aivpn: rekey response re-send aborted — upload channel closed"
                                            );
                                        } else if !matches!(
                                            time::timeout(REKEY_ACK_TIMEOUT, ack_rx).await,
                                            Ok(Ok(()))
                                        ) {
                                            // Upload task gone — either it dropped the
                                            // sender, or (timeout) it died between
                                            // dequeuing the KeyRotate and firing the
                                            // ack, stranding the sender in the shared
                                            // queue. Remove the stale registration and
                                            // the unused override so they cannot
                                            // mis-fire, instead of hanging the recv
                                            // loop forever.
                                            rekey_ack_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .pop_back();
                                            *rekey_resend_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner()) = None;
                                            log::warn!(
                                                "aivpn: rekey response re-send aborted — upload task ended before old-key send"
                                            );
                                        } else {
                                            // Keep accepting old-key downlink until the
                                            // server commits (or retransmits again) — but
                                            // never past the hard cap armed at the key
                                            // switch: unbounded re-arms let a never-
                                            // converging rekey defer recovery forever.
                                            let next =
                                                Instant::now() + REKEY_TRANSITION_GRACE;
                                            transition_recv_deadline =
                                                Some(transition_grace_hard
                                                    .map_or(next, |hard| next.min(hard)));
                                        }
                                        continue;
                                    }
                                    let rekey_kp = KeyPair::generate();
                                    if let Ok(dh) = rekey_kp.compute_shared(&new_eph_pub) {
                                        let new_keys = {
                                            let mut k = derive_session_keys(
                                                &dh,
                                                Some(&keys.session_key),
                                                &rekey_kp.public_key_bytes(),
                                            );
                                            apply_legacy_key_scheme(&mut k, legacy_wire);
                                            k
                                        };
                                        // Route the KeyRotate response through the upload task's
                                        // single encryptor instead of building it here with the
                                        // receive loop's separate `send_counter`. Two counters
                                        // over one session key reuse ChaCha20-Poly1305 nonces
                                        // (nonce == counter), leaking keystream and making the
                                        // server drop the response as a stale-counter replay —
                                        // which leaves the server's ratchet half-finished and
                                        // desyncs the session permanently. Register a rendezvous
                                        // first so we switch to the new keys only AFTER the upload
                                        // task confirms it encrypted the response with the still-
                                        // current (old) keys; otherwise a data packet racing
                                        // through encrypt_data could apply the queued rotation and
                                        // the response would go out under a key the server cannot
                                        // yet recognise. Mirrors the desktop inline-rekey
                                        // rendezvous (client.rs).
                                        let (ack_tx, ack_rx) = oneshot::channel();
                                        rekey_ack_slot
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .push_back(ack_tx);
                                        let response = ControlPayload::KeyRotate {
                                            new_eph_pub: rekey_kp.public_key_bytes(),
                                        };
                                        if ctrl_tx_recv_loop.send(response).await.is_err() {
                                            // Upload task gone — drop the ack we just registered.
                                            rekey_ack_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .pop_back();
                                            log::warn!(
                                                "aivpn: inline rekey aborted — upload channel closed"
                                            );
                                        } else if !matches!(
                                            time::timeout(REKEY_ACK_TIMEOUT, ack_rx).await,
                                            Ok(Ok(()))
                                        ) {
                                            // Upload task gone — either it dropped the
                                            // sender, or (timeout) it died between
                                            // dequeuing the KeyRotate and firing the
                                            // ack, stranding the sender in the shared
                                            // queue. Remove the stale registration so
                                            // it cannot mis-fire, instead of hanging
                                            // the recv loop forever.
                                            rekey_ack_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .pop_back();
                                            log::warn!(
                                                "aivpn: inline rekey aborted — upload task ended before old-key send"
                                            );
                                        } else {
                                            // Transition window is a CLONE so the
                                            // primary downlink recv-window keeps its
                                            // `highest` counter across the rekey. The
                                            // server keeps its s2c send counter
                                            // monotonic, so post-rekey downlink lands
                                            // inside the synced forward span (which
                                            // slides). A move/reset here stranded
                                            // sustained downlink after the first rekey:
                                            // the unsynced [0, RECV_FUTURE_SEARCH_WINDOW)
                                            // search cannot advance under load.
                                            transition_recv_keys = Some(keys.clone());
                                            // Grace must outlive the server's KeyRotate
                                            // retransmit horizon (lost-response
                                            // self-heal), not just in-flight packets —
                                            // see REKEY_TRANSITION_GRACE.
                                            transition_recv_deadline =
                                                Some(Instant::now() + REKEY_TRANSITION_GRACE);
                                            // Absolute re-arm ceiling for THIS rekey (see
                                            // REKEY_TRANSITION_HARD_CAP).
                                            transition_grace_hard = Some(
                                                Instant::now() + REKEY_TRANSITION_HARD_CAP,
                                            );
                                            transition_recv_win = recv_win.clone();
                                            keys = new_keys;
                                            *key_rotate_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner()) =
                                                Some(keys.clone());
                                            ratcheted_rekey_eph_pub = Some(new_eph_pub);
                                            rekey_response_eph =
                                                Some(rekey_kp.public_key_bytes());
                                            log::info!("aivpn: inline PFS rekey complete");
                                        }
                                    }
                                }
                                ControlPayload::KeepaliveAck { echo_ts } => {
                                    if echo_ts > 0 {
                                        let now_ms = aivpn_common::crypto::current_timestamp_ms();
                                        if now_ms >= echo_ts {
                                            let rtt_us = (now_ms - echo_ts) * 1_000;
                                            quality_tracker.record_rtt(rtt_us);
                                            quality_tracker.record_received();
                                            let score = quality_tracker.score();
                                            ACTIVE_QUALITY_SCORE.store(score, Ordering::Relaxed);
                                            // Enqueue to the upload task's encryptor rather than
                                            // building a packet here with a second `send_counter`,
                                            // which would reuse a nonce already used by the upload
                                            // task under the same key (see ctrl_tx_recv_loop above).
                                            let _ = ctrl_tx_recv_loop.try_send(
                                                ControlPayload::QualityReport {
                                                    quality: score,
                                                    rtt_ms: quality_tracker.rtt_ms(),
                                                    loss_ppm: quality_tracker.loss_ppm(),
                                                    jitter_ms: quality_tracker.jitter_ms(),
                                                },
                                            );
                                            log::debug!(
                                                "aivpn: KeepaliveAck rtt={}ms quality={}/100",
                                                quality_tracker.rtt_ms(), score
                                            );
                                        }
                                    }
                                }
                                ControlPayload::AdaptiveHint { level } => {
                                    ACTIVE_ADAPTIVE_LEVEL.store(level.min(3), Ordering::Relaxed);
                                    // Re-arm the running upload loop's keepalive interval to the
                                    // server-hinted level, mirroring desktop client.rs's
                                    // keepalive_with_nat_cap: take the level's own keepalive_secs()
                                    // clamped to the NAT-safe ceiling (Satellite uncapped). Clamping
                                    // against base_keepalive (the 4s initial floor) instead would
                                    // collapse every level to 4s and make the hint a silent no-op.
                                    let hinted = AdaptiveLevel::from_u8(level);
                                    let requested = Duration::from_secs(hinted.keepalive_secs());
                                    let new_ka = if hinted == AdaptiveLevel::Satellite {
                                        requested
                                    } else {
                                        requested.min(KEEPALIVE_NAT_CAP)
                                    };
                                    keepalive_ms.store(new_ka.as_millis() as u64, Ordering::Relaxed);
                                    log::info!(
                                        "aivpn: AdaptiveHint level={} → keepalive={}ms",
                                        level, new_ka.as_millis()
                                    );
                                }
                                ControlPayload::RecordingAck { status, .. } => {
                                    log::info!("aivpn: RecordingAck status={}", status);
                                    *ACTIVE_RECORDING_FEEDBACK
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner()) =
                                        Some(RecordingFeedback::Ack { status });
                                }
                                ControlPayload::RecordingComplete {
                                    mask_id,
                                    confidence,
                                    ..
                                } => {
                                    log::info!(
                                        "aivpn: RecordingComplete mask_id={} confidence={}",
                                        mask_id, confidence
                                    );
                                    *ACTIVE_RECORDING_FEEDBACK
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner()) =
                                        Some(RecordingFeedback::Complete { mask_id, confidence });
                                }
                                ControlPayload::RecordingFailed { reason } => {
                                    log::warn!("aivpn: RecordingFailed reason={}", reason);
                                    *ACTIVE_RECORDING_FEEDBACK
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner()) =
                                        Some(RecordingFeedback::Failed { reason });
                                }
                                ControlPayload::RecordingStatus {
                                    can_record,
                                    active_service,
                                } => {
                                    log::info!(
                                        "aivpn: RecordingStatus can_record={} active_service={:?}",
                                        can_record, active_service
                                    );
                                    *ACTIVE_RECORDING_FEEDBACK
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner()) =
                                        Some(RecordingFeedback::Status {
                                            can_record,
                                            active_service,
                                        });
                                }
                                ControlPayload::RegionalMaskHints { country_code, masks } => {
                                    // §2 crowdsourced blocking feedback — opt-in. The server
                                    // only ever sends this after k-anonymity-gated aggregation
                                    // (see aivpn-server's mask_feedback.rs); ignore entirely
                                    // unless the client asked to receive hints (mirrors desktop
                                    // client.rs's RegionalMaskHints handling).
                                    if receive_mask_hints {
                                        log::info!(
                                            "aivpn: RegionalMaskHints for {}{}: {} masks",
                                            country_code[0] as char,
                                            country_code[1] as char,
                                            masks.len()
                                        );
                                        // Hand the hints to the platform as JSON so it can
                                        // persist them per-region (mirrors desktop's
                                        // `RegionalHintsStore`) and softly bias the NEXT
                                        // reconnect attempt's mask selection — this Rust
                                        // instance is dropped before that attempt starts.
                                        let payload = serde_json::json!({
                                            "country_code": format!(
                                                "{}{}",
                                                country_code[0] as char,
                                                country_code[1] as char
                                            ),
                                            "masks": masks,
                                        });
                                        if let Ok(json) = serde_json::to_string(&payload) {
                                            *ACTIVE_REGIONAL_HINTS_JSON
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner()) = Some(json);
                                            REGIONAL_HINTS_SEQ.fetch_add(1, Ordering::Relaxed);
                                        }
                                    } else {
                                        log::debug!(
                                            "aivpn: RegionalMaskHints received but receive_mask_hints=false — ignoring"
                                        );
                                    }
                                }
                                ControlPayload::MaskCatalog { masks } => {
                                    // Server pushed the selectable-mask list. Store it as
                                    // JSON so the Kotlin spinner renders a live list and
                                    // marks auto-generated masks "(авто)".
                                    log::info!("aivpn: MaskCatalog received: {} masks", masks.len());
                                    let entries: Vec<serde_json::Value> = masks
                                        .iter()
                                        .map(|(mask_id, label, generated)| {
                                            serde_json::json!({
                                                "mask_id": mask_id,
                                                "label": label,
                                                "generated": generated,
                                            })
                                        })
                                        .collect();
                                    if let Ok(json) = serde_json::to_string(&entries) {
                                        *ACTIVE_MASK_CATALOG_JSON
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner()) = Some(json);
                                        MASK_CATALOG_SEQ.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                ControlPayload::FeedbackConfig { report_failure_threshold, report_interval_secs } => {
                                    // §2 M3 server-pushed config. Only meaningful to an
                                    // opted-in client; the server only sends this in reply
                                    // to a MaskFeedback, which only opted-in clients emit.
                                    // Stored in a process-global so the platform layer can
                                    // poll it after `run_tunnel_android` returns and persist
                                    // it for the next reconnect attempt (mirrors desktop's
                                    // `MaskFeedbackLog::set_tuning`, adapted to the
                                    // single-shot JNI where this Rust instance is dropped
                                    // before the next attempt starts).
                                    // Clamp server-pushed tuning to the same bounds as
                                    // desktop's set_tuning: a malicious server pushing
                                    // interval=1 would restore the fixed-offset timing
                                    // fingerprint the interval+jitter design removes, and a
                                    // huge value would silently disable reporting.
                                    let threshold = report_failure_threshold.clamp(1, 10);
                                    let interval = if report_interval_secs == 0 {
                                        DEFAULT_REPORT_INTERVAL_SECS
                                    } else {
                                        report_interval_secs.clamp(60, 7 * 24 * 3600)
                                    };
                                    ACTIVE_FEEDBACK_THRESHOLD.store(threshold, Ordering::Relaxed);
                                    ACTIVE_FEEDBACK_INTERVAL.store(interval, Ordering::Relaxed);
                                    log::info!(
                                        "aivpn: FeedbackConfig from server: failure_threshold={} interval={}s",
                                        threshold, interval
                                    );
                                }
                                ControlPayload::MaskUpdate { mask_data, .. } => {
                                    if let Some(mask) = aivpn_common::mimicry::decode_mask_update(&mask_data) {
                                        // R2 Phase B: shared artifact verification hook. The
                                        // operator pubkey is not yet plumbed through the JNI
                                        // config surface, so this runs as (None, warn) — a
                                        // silent no-op today. Once the pubkey/mode params are
                                        // added to the FFI, only these two arguments change and
                                        // Android inherits the same semantics as desktop.
                                        // Derived variants are exempt (channel-authenticated).
                                        let artifact_ok = mask.is_derived_variant() || {
                                            let verdict = aivpn_common::mask::verify_mask_artifact(
                                                &mask,
                                                None,
                                                aivpn_common::mask::MaskVerifyMode::Warn,
                                            );
                                            if !verdict.accept {
                                                log::warn!("aivpn: MaskUpdate '{}' rejected: {:?}", mask.mask_id, verdict.detail);
                                            }
                                            verdict.accept
                                        };
                                        if artifact_ok {
                                            // Track the new mask's downlink length so subsequent
                                            // server DATA/control packets framed with it decode.
                                            let new_mdh = mask.mdh_len();
                                            if !recv_mdh_candidates.contains(&new_mdh) {
                                                recv_mdh_candidates.insert(0, new_mdh);
                                            }
                                            *mask_update_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(mask);
                                            log::info!("aivpn: MaskUpdate received — mask queued for mimicry engine");
                                        }
                                    } else {
                                        log::warn!("aivpn: MaskUpdate decode failed — ignoring");
                                    }
                                }
                                ControlPayload::Shutdown { reason } => {
                                    // Server-initiated teardown — mirror desktop client.rs's
                                    // Shutdown handler: log it and end the session with an error so
                                    // the Kotlin reconnect loop (AivpnService.kt) kicks in, the same
                                    // way any other unrecoverable server event does.
                                    log::info!("aivpn: server requested shutdown (reason: {})", reason);
                                    tun_reader_task.abort();
                                    upload_sender_task.abort();
                                    return Err(Error::Session(format!("server shutdown: {reason}")));
                                }
                                ControlPayload::BootstrapDescriptorUpdate { descriptor_data } => {
                                    // Apply desktop client.rs's size guard (reject >512 KiB), then
                                    // parse and persist into the in-process descriptor store so a
                                    // subsequent reconnect can shape its handshake with the COVERT
                                    // rotated descriptor mask (see BOOTSTRAP_DESCRIPTORS). The
                                    // payload arrived over the AEAD-authenticated session channel,
                                    // so it is server-authenticated; only expiry is checked.
                                    if descriptor_data.len() > 512 * 1024 {
                                        log::warn!(
                                            "aivpn: BootstrapDescriptorUpdate rejected: payload too large ({} bytes)",
                                            descriptor_data.len()
                                        );
                                    } else if let Some(descriptor) =
                                        decode_bootstrap_descriptor(&descriptor_data)
                                    {
                                        let id = descriptor.descriptor_id.clone();
                                        store_bootstrap_descriptor(descriptor);
                                        log::info!(
                                            "aivpn: BootstrapDescriptorUpdate stored ({} bytes, descriptor {}) — \
                                             covert mask available for next reconnect",
                                            descriptor_data.len(),
                                            id
                                        );
                                    } else {
                                        log::warn!(
                                            "aivpn: BootstrapDescriptorUpdate received ({} bytes) but failed to parse",
                                            descriptor_data.len()
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            maybe_err = err_rx.recv() => {
                if let Some(msg) = maybe_err {
                    tun_reader_task.abort();
                    upload_sender_task.abort();
                    return Err(Error::Session(msg));
                }
            }

            // ── RX silence detector (proper interval, not recreated each iteration) ──
            _ = rx_check.tick() => {
                // Data-plane watchdog: clocked on DATA delivered to the TUN,
                // not on any decode — a downlink where only keepalive-acks /
                // KeyRotate retransmits still authenticate is DEAD for the
                // user and must reconnect in tens of seconds, not after the
                // 120 s absolute net (see `data_watchdog_verdict`).
                let uploaded_total = session.upload_bytes.load(Ordering::Relaxed);
                let data_up_since = uploaded_total.saturating_sub(upload_at_last_data_rx);
                if data_up_since > 0 && data_stall_started.is_none() {
                    data_stall_started = Some(Instant::now());
                }
                let stalled_for = if data_plane_proven {
                    data_stall_started.map(|t| t.elapsed())
                } else {
                    // Data plane never proven this session — unanswerable TUN
                    // junk must not condemn a healthy idle tunnel.
                    None
                };
                let verdict = data_watchdog_verdict(stalled_for, data_up_since);
                let stall_pending = verdict.is_some();
                if let Some(reason) = data_stall_confirmed(&mut data_stall_strikes, verdict) {
                    condemn_descriptor_mask_after_watchdog(
                        &handshake_mask.mask_id,
                        reason,
                        data_plane_proven,
                    );
                    tun_reader_task.abort();
                    upload_sender_task.abort();
                    return Err(Error::Session(format!(
                        "{}: {} bytes of uplink data unanswered for {:?} \
                         (no downlink data for {:?}) — reconnecting",
                        reason,
                        data_up_since,
                        stalled_for.unwrap_or_default(),
                        last_data_rx.elapsed(),
                    )));
                }
                // Window wash: the stall never reached the byte threshold —
                // background junk, not a dead downlink. Forget it so trickle
                // can never accumulate into a false positive (see
                // DATA_STALL_WINDOW). Never wash while a strike is pending
                // confirmation, or the reset would erase the very stall the
                // next tick must re-observe.
                if !stall_pending
                    && data_stall_started.is_some_and(|t| t.elapsed() >= DATA_STALL_WINDOW)
                {
                    data_stall_started = None;
                    upload_at_last_data_rx = uploaded_total;
                }

                // Absolute net: nothing decodable AT ALL (control included).
                let silence = last_rx.elapsed();
                if silence > RX_SILENCE {
                    condemn_descriptor_mask_after_watchdog(
                        &handshake_mask.mask_id,
                        "RX silence",
                        data_plane_proven,
                    );
                    tun_reader_task.abort();
                    upload_sender_task.abort();
                    return Err(Error::Session(
                        format!("No RX for {:?} — reconnecting", silence)
                    ));
                }
            }
        }
    }
}

fn notify_tunnel_ready(vm: &JavaVM, vpn_service: &GlobalRef, host: &str) {
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(e) => {
            log::warn!("aivpn: JNI attach failed for onTunnelReady callback: {e}");
            return;
        }
    };

    let host_j = match env.new_string(host) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("aivpn: JNI new_string failed for onTunnelReady callback: {e}");
            return;
        }
    };

    let host_obj = jni::objects::JObject::from(host_j);

    if let Err(e) = env.call_method(
        vpn_service,
        "onTunnelReady",
        "(Ljava/lang/String;)V",
        &[jni::objects::JValue::Object(&host_obj)],
    ) {
        log::warn!("aivpn: onTunnelReady callback failed: {e}");
        return;
    }

    match env.exception_check() {
        Ok(true) => {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            log::warn!("aivpn: onTunnelReady callback threw Java exception");
        }
        Ok(false) => {}
        Err(e) => {
            log::warn!("aivpn: exception_check failed after onTunnelReady callback: {e}");
        }
    }
}

// ──────────── Protected UDP socket creation ────────────

fn create_protected_udp_socket(
    vm: &JavaVM,
    vpn_service: &GlobalRef,
    dest: SocketAddr,
    session: &Arc<SessionRuntime>,
) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Call Android VpnService.protect(int) to exempt this socket from the VPN.
    let mut guard = vm
        .attach_current_thread()
        .map_err(|e| Error::Session(format!("JNI attach: {}", e)))?;

    let protect_result = guard
        .call_method(
            vpn_service,
            "protect",
            "(I)Z",
            &[jni::objects::JValue::Int(fd)],
        )
        .and_then(|v| v.z());

    if matches!(guard.exception_check(), Ok(true)) {
        let _ = guard.exception_clear();
    }

    let protected = protect_result.unwrap_or(false);

    if !protected {
        unsafe { libc::close(fd) };
        return Err(Error::Session("VpnService.protect() returned false".into()));
    }

    // Increase OS socket buffers to reduce drops/backpressure on high-throughput links.
    // Ignore errors: kernels may cap/override values.
    let sock_buf: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sock_buf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sock_buf) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &sock_buf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sock_buf) as libc::socklen_t,
        );
    }

    // Try to reuse the same local port as the previous session.  When a
    // port-preserving CGNAT (MTS, Beeline, etc.) is in use, the carrier's
    // inbound routing table still maps the old external port back to this
    // phone.  Binding to the same internal port means no CGNAT update is
    // needed and downlink arrives immediately without a stale-mapping delay.
    // Falls back to OS-assigned ephemeral port if the saved port is
    // unavailable (first connect, or port taken by another socket).
    let port_hint = LAST_LOCAL_PORT.load(Ordering::Relaxed);
    unsafe {
        let mut any: libc::sockaddr_in = std::mem::zeroed();
        any.sin_family = libc::AF_INET as libc::sa_family_t;
        if port_hint != 0 {
            any.sin_port = port_hint.to_be();
            if libc::bind(
                fd,
                &any as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) < 0
            {
                // Port unavailable — fall back to OS-assigned ephemeral.
                any.sin_port = 0;
                let _ = libc::bind(
                    fd,
                    &any as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
            }
        } else {
            let _ = libc::bind(
                fd,
                &any as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
        }
    }

    // Connect to server (sets default destination for send/recv, non-blocking for UDP).
    let SocketAddr::V4(v4) = dest else {
        unsafe { libc::close(fd) };
        return Err(Error::Session(
            "Only IPv4 server addresses are supported".into(),
        ));
    };
    let sa = to_sockaddr_in(&v4);
    let rc = unsafe {
        libc::connect(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Persist the local port for the next reconnect attempt.
    unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockname(
            fd,
            &mut sa as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut len,
        ) == 0
        {
            LAST_LOCAL_PORT.store(u16::from_be(sa.sin_port), Ordering::Relaxed);
        }
    }

    let control_fd = unsafe { libc::dup(fd) };
    if control_fd < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    session.udp_control_fd.store(control_fd, Ordering::SeqCst);

    Ok(fd)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn create_stop_signal(session: &Arc<SessionRuntime>) -> Result<AsyncFd<OwnedFd>> {
    let stop_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if stop_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    let control_fd = unsafe { libc::dup(stop_fd) };
    if control_fd < 0 {
        unsafe { libc::close(stop_fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    session.stop_event_fd.store(control_fd, Ordering::SeqCst);

    // If stop_active_tunnel() fired in the race window between the last
    // stop_requested check and this function, the eventfd was never written
    // to (stop_event_fd was -1 at that point). Arm it now so the main loop
    // exits on its first poll instead of hanging forever.
    if session.stop_requested.load(Ordering::SeqCst) {
        let v: u64 = 1;
        unsafe {
            let _ = libc::write(
                stop_fd,
                &v as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }

    let owned_stop_fd = unsafe { OwnedFd::from_raw_fd(stop_fd) };
    Ok(AsyncFd::new(owned_stop_fd)?)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn create_stop_signal(session: &Arc<SessionRuntime>) -> Result<AsyncFd<OwnedFd>> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    unsafe { libc::fcntl(read_fd, libc::F_SETFL, libc::O_NONBLOCK) };
    let dup_write = unsafe { libc::dup(write_fd) };
    if dup_write < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    session.stop_event_fd.store(dup_write, Ordering::SeqCst);
    unsafe { libc::close(write_fd) };
    Ok(AsyncFd::new(unsafe { OwnedFd::from_raw_fd(read_fd) })?)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
async fn wait_for_stop_signal(stop_signal: &AsyncFd<OwnedFd>) -> std::io::Result<()> {
    loop {
        let mut guard = stop_signal.readable().await?;
        match guard.try_io(|inner| {
            let mut value: u64 = 0;
            let n = unsafe {
                libc::read(
                    inner.as_raw_fd(),
                    &mut value as *mut u64 as *mut libc::c_void,
                    std::mem::size_of::<u64>(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
async fn wait_for_stop_signal(stop_signal: &AsyncFd<OwnedFd>) -> std::io::Result<()> {
    loop {
        let mut guard = stop_signal.readable().await?;
        match guard.try_io(|inner| {
            let mut b = [0u8; 1];
            let n =
                unsafe { libc::read(inner.as_raw_fd(), b.as_mut_ptr() as *mut libc::c_void, 1) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

fn to_sockaddr_in(addr: &SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

// ──────────── Async TUN I/O ────────────

async fn tun_async_read(tun: &AsyncFd<TunFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = tun.readable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

async fn tun_async_write(tun: &AsyncFd<TunFd>, data: &[u8]) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let mut guard = tun.writable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::write(
                    inner.as_raw_fd(),
                    data[written..].as_ptr() as *const libc::c_void,
                    data.len() - written,
                )
            };

            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                } else {
                    Err(err)
                }
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "TUN write returned 0",
                ));
            }
            Ok(Ok(n)) => {
                written += n;
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data watchdog must trip on a dead DATA downlink (uplink data
    /// flowing, nothing written to the TUN) and must NEVER trip on an idle
    /// tunnel whose liveness is control-only (keepalive-acks, rekey
    /// retransmits). Identical semantics on desktop/iOS/Android.
    #[test]
    fn data_watchdog_verdict_data_based_liveness() {
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
        // the second consecutive strike, NOT deferred to the 120 s absolute
        // net.
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

    fn make_keys(tag: u8) -> SessionKeys {
        let ckp = KeyPair::generate();
        let skp = KeyPair::generate();
        let dh = ckp.compute_shared(&skp.public_key_bytes()).unwrap();
        derive_session_keys(&dh, Some(&[tag; 32]), &ckp.public_key_bytes())
    }

    fn make_encryptor(
        old_keys: SessionKeys,
        slot: Arc<Mutex<Option<SessionKeys>>>,
        ack: RekeyAckQueue,
    ) -> AndroidEncryptor {
        AndroidEncryptor {
            inner: MimicryEncryptor::new(
                old_keys,
                0,
                0,
                aivpn_common::mimicry::bootstrap_mask_for_psk(None),
                Arc::new(Mutex::new(None)),
            ),
            session: Arc::new(SessionRuntime::new()),
            keepalive_sent_ms: Arc::new(AtomicU64::new(0)),
            key_rotate_slot: slot,
            rekey_ack: ack,
            rekey_resend_keys: Arc::new(Mutex::new(None)),
        }
    }

    /// Regression: a `KeyRotate` response must be encrypted with the PRE-rotation
    /// keys and must fire the rekey ack, even when a rotation is already queued in
    /// `key_rotate_slot`. `encrypt_control` must NOT consume that pending rotation
    /// (proving the response used the old keys); only a later `encrypt_data` applies
    /// it. This is the invariant that lets the receive-loop handler safely switch
    /// keys only after the ack.
    #[tokio::test]
    async fn key_rotate_response_uses_pre_rotation_keys_and_acks() {
        let old_keys = make_keys(1);
        let new_keys = make_keys(2);
        let slot: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(Some(new_keys)));
        let ack_q: RekeyAckQueue = Arc::new(Mutex::new(VecDeque::new()));
        let (ack_tx, ack_rx) = oneshot::channel();
        ack_q.lock().unwrap().push_back(ack_tx);

        let mut enc = make_encryptor(old_keys, slot.clone(), ack_q.clone());

        let resp = ControlPayload::KeyRotate {
            new_eph_pub: [7u8; 32],
        };
        let _pkt = enc.encrypt_control(&resp).expect("encrypt_control");

        assert!(
            ack_rx.await.is_ok(),
            "encrypt_control must fire the rekey ack so the handler can proceed"
        );
        assert!(
            slot.lock().unwrap().is_some(),
            "encrypt_control must NOT apply the pending key rotation (response used old keys)"
        );

        let _ = enc.encrypt_data(b"hello world").expect("encrypt_data");
        assert!(
            slot.lock().unwrap().is_none(),
            "encrypt_data must apply the pending key rotation"
        );
    }

    /// A re-sent `KeyRotate` response must consume the one-shot old-key override
    /// (so it is encrypted under the PREVIOUS keys the server can still read)
    /// and still fire the rekey ack; a non-KeyRotate control payload must leave
    /// the override untouched.
    #[tokio::test]
    async fn keyrotate_resend_consumes_old_key_override_and_acks() {
        let old_keys = make_keys(1);
        let current_keys = make_keys(2);
        let slot: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(None));
        let ack_q: RekeyAckQueue = Arc::new(Mutex::new(VecDeque::new()));
        let (ack_tx, ack_rx) = oneshot::channel();
        ack_q.lock().unwrap().push_back(ack_tx);

        let mut enc = make_encryptor(current_keys.clone(), slot, ack_q.clone());
        *enc.rekey_resend_keys.lock().unwrap() = Some((old_keys, current_keys));

        // A non-KeyRotate control payload must NOT consume the override.
        let qr = ControlPayload::QualityReport {
            quality: 90,
            rtt_ms: 10,
            loss_ppm: 0,
            jitter_ms: 1,
        };
        let _ = enc.encrypt_control(&qr).expect("encrypt_control");
        assert!(
            enc.rekey_resend_keys.lock().unwrap().is_some(),
            "non-KeyRotate control must leave the old-key override staged"
        );

        let resp = ControlPayload::KeyRotate {
            new_eph_pub: [7u8; 32],
        };
        let _ = enc.encrypt_control(&resp).expect("encrypt_control");
        assert!(
            enc.rekey_resend_keys.lock().unwrap().is_none(),
            "KeyRotate must consume the one-shot old-key override"
        );
        assert!(
            ack_rx.await.is_ok(),
            "the re-sent response must still fire the rekey ack"
        );
    }

    /// A non-`KeyRotate` control payload (e.g. `QualityReport`) must never consume
    /// a queued rekey ack — otherwise a QualityReport riding the same control
    /// channel would spuriously unblock a rekey handler.
    #[test]
    fn non_keyrotate_control_does_not_fire_ack() {
        let old_keys = make_keys(1);
        let slot: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(None));
        let ack_q: RekeyAckQueue = Arc::new(Mutex::new(VecDeque::new()));
        let (ack_tx, mut ack_rx) = oneshot::channel();
        ack_q.lock().unwrap().push_back(ack_tx);

        let mut enc = make_encryptor(old_keys, slot, ack_q.clone());
        let qr = ControlPayload::QualityReport {
            quality: 90,
            rtt_ms: 10,
            loss_ppm: 0,
            jitter_ms: 1,
        };
        let _ = enc.encrypt_control(&qr).expect("encrypt_control");

        assert_eq!(
            ack_q.lock().unwrap().len(),
            1,
            "non-KeyRotate control must leave the rekey ack queued"
        );
        assert!(matches!(
            ack_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
}
