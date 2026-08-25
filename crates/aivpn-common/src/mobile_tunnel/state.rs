//! Shared mobile tunnel state — constants, process-global statics, session
//! runtime and lifecycle helpers used by both `aivpn-ios-core` and
//! `aivpn-android-core`. Hoisted verbatim from `android_tunnel.rs` (the base
//! text with the latest fixes); iOS-only additions are noted inline.

use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::mask::{
    current_unix_secs, resolve_handshake_mask_resilient, BootstrapDescriptor, MaskProfile,
    HANDSHAKE_FALLBACK_THRESHOLD,
};
use crate::protocol::{ControlPayload, MaskOutcome};

// ──────────── Constants ────────────

pub const BUF_SIZE: usize = 2048;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_millis(750);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(4); // below typical provider NAT UDP timeout (~10-15s)
/// NAT-safe keepalive ceiling — mirror of desktop client.rs `KEEPALIVE_NAT_CAP`.
/// An AdaptiveHint may relax the interval up to this bound (Satellite is
/// uncapped). The initial `keepalive_interval` derives from the tiny 4s
/// `base_keepalive`, so the re-arm must clamp against THIS ceiling, not that
/// floor — otherwise `base.min(level)` collapses every hint back to 4s.
pub const KEEPALIVE_NAT_CAP: Duration = Duration::from_secs(25);
pub const RX_SILENCE: Duration = Duration::from_secs(120); // absolute net: NOTHING decodes at all (control included)
pub const RX_CHECK_INTERVAL: Duration = Duration::from_secs(2);
// ── Post-freeze/suspend liveness probe ──
// An OEM background freezer (cgroup freeze) or device suspend stops this
// process entirely. CLOCK_MONOTONIC (Rust `Instant`) keeps counting through a
// process freeze but does NOT advance during device suspend (that would be
// CLOCK_BOOTTIME, which `Instant` does not use on Linux/Android) — so the
// watchdog measures the tick gap on BOTH `Instant` and `SystemTime` (wall
// clock, advances through suspend) and takes the larger, making the first
// tick after either kind of gap see a value far beyond RX_CHECK_INTERVAL.
// A session whose server-side state died during the gap would otherwise
// linger dead for up to RX_SILENCE: keepalives resume unanswered, and the
// data watchdog needs ≥TX_WITHOUT_RX_MIN_BYTES of uplink to condemn. After a
// gap this large, demand ANY decodable RX within the probe window instead.
pub const WAKE_GAP_THRESHOLD: Duration = Duration::from_secs(15);
/// Probe window bounds: max(2×keepalive interval, MIN) capped at MAX — at
/// least two keepalives (sent immediately after unfreeze) must have a chance
/// to be answered before the session is condemned.
pub const WAKE_PROBE_WINDOW_MIN: Duration = Duration::from_secs(10);
pub const WAKE_PROBE_WINDOW_MAX: Duration = Duration::from_secs(60);
// Data-plane watchdogs (see `data_watchdog_verdict`): clocked on DATA actually
// delivered to the TUN, never on "any decode" — keepalive-acks and in-grace
// KeyRotate retransmits must not mask a dead data downlink. The fast tier's
// former 64 KiB threshold was unreachable from post-stall probe traffic (TCP
// acks/DNS retries are tiny, and the counter was zeroed on every control
// decode), so a dead downlink slid past it to the 120 s absolute net.
pub const TX_WITHOUT_RX_TIMEOUT: Duration = Duration::from_secs(20);
// 4 KiB, not 512 B: legitimate upload-only flows with no downlink at all
// (fire-and-forget UDP telemetry, one-way media, chatty mDNS/SSDP at
// ~18+ B/s) could cross 512 B inside one 30 s stall window and be condemned
// even though the tunnel was healthy. 4 KiB needs ~135+ B/s of sustained
// unanswered uplink DATA — beyond any junk/telemetry pattern — while a dead
// downlink under real use (TCP/QUIC upload whose ACKs stopped coming back)
// accumulates 4 KiB within seconds.
pub const TX_WITHOUT_RX_MIN_BYTES: u64 = 4096;
// A stall window that never accumulates TX_WITHOUT_RX_MIN_BYTES of uplink
// data is unanswerable background junk (ICMPv6 ND, mDNS, telemetry beacons to
// dead hosts — observed live: ~48 B every ~7 s on an idle TUN), not a dead
// downlink. The window is WASHED (byte base + stall anchor reset) so idle
// trickle can never accumulate into a false-positive reconnect over hours,
// while a dead downlink under real use (≥4 KiB of unanswered uplink data in
// one 30 s window) still reconnects in ~25–35 s instead of the 120 s net.
pub const DATA_STALL_WINDOW: Duration = Duration::from_secs(30);
/// Consecutive watchdog ticks (RX_CHECK_INTERVAL apart) the stall verdict
/// must hold before the session is condemned (see `data_stall_confirmed`).
/// One extra tick gives a slow-but-alive downlink (delayed ACKs, bufferbloat
/// spike) a last chance to stamp `last_data_rx` and clear the verdict,
/// pushing the false-fire class further away from healthy upload-heavy
/// flows. A genuinely dead downlink still fires on the second consecutive
/// tick — seconds after the 20 s stall verdict, nowhere near the 120 s net.
pub const DATA_STALL_STRIKES_TO_FIRE: u32 = 2;
pub const CHANNEL_SIZE: usize = 8192;
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
pub const REKEY_TRANSITION_GRACE: Duration = Duration::from_secs(20);

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
pub const REKEY_TRANSITION_HARD_CAP: Duration = Duration::from_secs(40);

/// Upper bound on the rekey-ack rendezvous wait. The ack normally fires
/// sub-millisecond (local oneshot fired by the upload task right after
/// encrypting the KeyRotate response), so 5 s can only elapse if the upload
/// task died between dequeuing the KeyRotate and firing the ack (e.g. an
/// encrypt error propagated by `?` before the ack pop). Without the bound,
/// the stranded `oneshot::Sender` kept alive inside the shared
/// `Arc<Mutex<VecDeque>>` would make `ack_rx.await` pend forever inside a
/// select arm — freezing the receive loop including the RX watchdog and the
/// stop signal (mirrors desktop client.rs REKEY_ACK_TIMEOUT).
pub const REKEY_ACK_TIMEOUT: Duration = Duration::from_secs(5);

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
pub fn data_watchdog_verdict(
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
pub fn data_stall_confirmed(
    strikes: &mut u32,
    verdict: Option<&'static str>,
) -> Option<&'static str> {
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
    pub udp_control_fd: AtomicI32,
    pub stop_signal_fd: AtomicI32,
    /// Rust's private duplicates of the platform-owned TUN fd — one for writing
    /// downlink, one for the reader task.
    ///
    /// The session OWNS them (the `AsyncFd`s only borrow via [`TunFd`]) because
    /// the kernel destroys a tun device only when its LAST fd closes. Android's
    /// Kotlin layer closes its `ParcelFileDescriptor` on disconnect and gives
    /// the native call ~3 s to unwind; a slower unwind used to leave these
    /// duplicates alive past the interface, keeping a zombie tun that still
    /// carried the VPN address. The next session then established a SECOND tun
    /// with the same address, the app's packets were routed into the dead one
    /// nobody reads, and the tunnel was "connected" with no traffic — only a
    /// process kill (force-stop / clear-data) broke the loop.
    ///
    /// Released in two phases, see [`neutralize_session_fd`] and
    /// [`close_session_fd`]: `stop_active_tunnel` drops the *tun reference*
    /// immediately, session teardown releases the fd *number* once nothing
    /// polls it any more.
    pub tun_write_fd: AtomicI32,
    pub tun_read_fd: AtomicI32,
    pub upload_bytes: AtomicU64,
    pub download_bytes: AtomicU64,
    // Wall-clock epoch ms at which this session completed its handshake, 0
    // until then. Same session scope as the byte counters so the UI stopwatch
    // can never desync from them (the app's self-rolled Date() reset on every
    // relaunch/jetsam while the counters kept running).
    pub connected_at_unix_ms: AtomicU64,
    // Set by stop_active_tunnel() before eventfd/socket are ready so that early
    // init phases (DNS, socket creation) can check and bail out immediately.
    pub stop_requested: AtomicBool,
}

impl SessionRuntime {
    pub fn new() -> Self {
        Self {
            udp_control_fd: AtomicI32::new(-1),
            stop_signal_fd: AtomicI32::new(-1),
            tun_write_fd: AtomicI32::new(-1),
            tun_read_fd: AtomicI32::new(-1),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            connected_at_unix_ms: AtomicU64::new(0),
            stop_requested: AtomicBool::new(false),
        }
    }
}

pub static ACTIVE_SESSION: Mutex<Option<Arc<SessionRuntime>>> = Mutex::new(None);

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
pub static BOOTSTRAP_DESCRIPTORS: Mutex<Vec<BootstrapDescriptor>> = Mutex::new(Vec::new());

/// The `server_key` of the last session. The descriptor store above is
/// process-global and survives internal reconnects, but descriptors are
/// server-specific — so when the user switches to a DIFFERENT server/profile we
/// must clear the store, otherwise server A's rotated descriptors would shape
/// the handshake to server B (covertness inversion + possible opening-packet
/// mis-frame). See review M2.
pub static LAST_SERVER_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// Cap on retained pushed descriptors (a handful of epochs is plenty).
pub const MAX_BOOTSTRAP_DESCRIPTORS: usize = 8;

/// Set when a session that COMPLETED the handshake never carried a single
/// downlink DATA packet while handshaking with a descriptor-derived covert
/// mask. Polled by the platform (Android `getDiscardPersistedDescriptors`, iOS
/// `aivpn_take_discard_persisted_descriptors`) so the app-persisted descriptor
/// blob is dropped too — clearing only the in-process store would let the next
/// COLD START reload the same unusable descriptor.
pub static DISCARD_PERSISTED_DESCRIPTORS: AtomicBool = AtomicBool::new(false);

/// Sticky for the process once a descriptor mask has been condemned. The
/// platform CONSUMES `DISCARD_PERSISTED_DESCRIPTORS` (one delete), so a second
/// flag is needed to keep suppressing descriptor use afterwards — the server
/// re-pushes descriptors every session, and re-adopting them would break the
/// very next connect again.
static DESCRIPTORS_DISTRUSTED: AtomicBool = AtomicBool::new(false);

/// Sentinel the platform passes instead of a cached-descriptor blob to say
/// "this server's descriptors were condemned in an earlier RUN of the app" (see
/// [`condemn_descriptor_mask_after_watchdog`]). An empty blob cannot carry that
/// verdict: the store also fills from the server's in-session pushes, so without
/// a sticky marker every app restart would break its first reconnect again and
/// heal ~50 s later, forever.
pub const DESCRIPTORS_DISTRUSTED_SENTINEL: &str = "distrusted";

/// A watchdog firing on a session that handshaked with a descriptor-derived
/// covert mask indicts that mask. A cached descriptor the server still ACCEPTS
/// for the handshake (the tag validates, the PFS ratchet completes, keepalives
/// flow) but disagrees with on the data plane leaves the tunnel permanently
/// "connected" with a dead data path: the server drops every uplink DATA packet
/// with an AEAD failure, the watchdog reconnects, and the next attempt resolves
/// the very same descriptor mask — forever. Clearing app data (which drops the
/// persisted descriptors) restores traffic for exactly one connection, which is
/// the reporter-visible signature of this loop.
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
pub fn condemn_descriptor_mask_after_watchdog(
    mask_id: &str,
    reason: &str,
    data_plane_proven: bool,
) {
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

/// Polled by the platform after the tunnel call returns: `true` means the
/// app-persisted bootstrap descriptor blob for this server must be deleted (see
/// [`condemn_descriptor_mask_after_watchdog`]). Reading it clears the flag.
pub fn take_discard_persisted_descriptors() -> bool {
    DISCARD_PERSISTED_DESCRIPTORS.swap(false, Ordering::Relaxed)
}

/// Mark this server's descriptors as condemned by a PREVIOUS run of the app,
/// from the platform's persisted verdict. See
/// [`DESCRIPTORS_DISTRUSTED_SENTINEL`].
pub fn mark_descriptors_distrusted() {
    DESCRIPTORS_DISTRUSTED.store(true, Ordering::Relaxed);
}

/// Drop the distrust verdict when the session targets a DIFFERENT server.
///
/// The verdict is deliberately sticky for the whole process (see
/// [`condemn_descriptor_mask_after_watchdog`]) but it is a statement about ONE
/// server's descriptors. Carrying it across a profile switch would pin every
/// later server in this process to public presets — the exact covertness loss
/// descriptors exist to avoid. The per-server verdict survives regardless: the
/// platform re-supplies it as [`DESCRIPTORS_DISTRUSTED_SENTINEL`] when the user
/// switches back.
pub fn clear_descriptor_distrust() {
    DESCRIPTORS_DISTRUSTED.store(false, Ordering::Relaxed);
    DISCARD_PERSISTED_DESCRIPTORS.store(false, Ordering::Relaxed);
}

/// Snapshot the currently-valid stored descriptors, newest first.
pub fn current_bootstrap_descriptors() -> Vec<BootstrapDescriptor> {
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
pub fn store_bootstrap_descriptor(descriptor: BootstrapDescriptor) {
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
    // Once condemned, stop handing descriptors back for persistence for the rest
    // of the process (`current_bootstrap_descriptors` already hides them, this
    // is the explicit statement of intent for the export path). The server
    // re-pushes fresh ones on every session, so without the distrust gate the
    // preset-mask session that recovers the tunnel would immediately re-persist
    // a descriptor and the NEXT connect would break again — a working/broken
    // ping-pong instead of a fix.
    let descriptors = current_bootstrap_descriptors();
    serde_json::to_string(&descriptors).unwrap_or_else(|_| "[]".to_string())
}

/// Re-populate the in-process descriptor store from app-persisted JSON BEFORE
/// the first handshake. Descriptors are signature-verified (when a trusted
/// operator key is available) and validity-filtered by
/// `accept_persisted_descriptors`, so a tampered/expired persisted blob is
/// rejected and the handshake simply falls back to the preset — never worse
/// than today. Returns how many descriptors were accepted into the store.
pub fn preload_persisted_descriptors(json: &str, trusted_key: Option<&[u8; 32]>) -> usize {
    // The platform's sticky verdict from an earlier RUN of the app.
    if json.trim() == DESCRIPTORS_DISTRUSTED_SENTINEL {
        mark_descriptors_distrusted();
        return 0;
    }
    // A condemned descriptor must not come back through the platform's cached
    // blob: the delete is asynchronous (the platform performs it only after the
    // tunnel call returns), so an immediate retry would otherwise re-preload the
    // very descriptor that just killed the data plane.
    if DESCRIPTORS_DISTRUSTED.load(Ordering::Relaxed) {
        return 0;
    }
    let accepted = crate::mask::accept_persisted_descriptors(json, trusted_key);
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
pub static LAST_LOCAL_PORT: AtomicU16 = AtomicU16::new(0);

// Set by stop_active_tunnel() when called while no session is active (the gap
// between the old session's ActiveSessionGuard drop and the new session's
// activate_session() call).  activate_session() propagates this to the new
// session so it stops immediately.  clear_pending_stop() resets the flag
// when a new intentional connection is about to start (called from the
// restartJob in Kotlin after cancelAndJoin()).
pub static STOP_PENDING: AtomicBool = AtomicBool::new(false);

/// Last computed connection quality score (0–100). Updated on each KeepaliveAck.
/// Polled by JNI via getQualityScore().
pub static ACTIVE_QUALITY_SCORE: AtomicU8 = AtomicU8::new(0);

/// Suggested adaptive level from the last server AdaptiveHint, stored as
/// `level + 1` (1–4) so that 0 still means "no hint yet this session". The
/// shift lets a server hint of Off(0) reach Kotlin as a real downgrade
/// instead of being indistinguishable from "no hint" — before this, a level
/// persisted in prefs could only ever ratchet UP (a session that improved
/// back to Off never cleared the sticky FEC/Aggressive setting).
/// Polled by JNI via getAdaptiveLevelHint() (which undoes the +1 shift);
/// takes effect on next reconnect.
pub static ACTIVE_ADAPTIVE_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Server-assigned VPN IPv4 from the ServerHello network config, as a
/// big-endian u32 (0 = none received this session). When the pool re-homes a
/// client onto a new vpn_ip, the IP embedded in the connection key goes
/// stale and every uplink data packet is silently dropped by the server's
/// anti-spoof check — the platform polls this via getAssignedVpnIp() and
/// rebuilds the TUN with the server's address when it differs.
pub static ASSIGNED_VPN_IP: AtomicU32 = AtomicU32::new(0);

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
/// Set when the server sends `CertRejected` (mTLS client certificate
/// rejected) during this session. Previously this control message fell
/// through the mid-session dispatch wildcard and was silently dropped — the
/// tunnel kept retrying forever under a certificate the server will never
/// accept, with no signal to the user. The platform polls and clears this
/// (see `AivpnJni.certRejected()`/`AivpnService.kt`) to prompt re-provisioning.
pub static CERT_REJECTED: AtomicBool = AtomicBool::new(false);
/// Set when the server sends `HandshakeReject` — an AUTHENTICATED refusal
/// (the peer already proved PSK knowledge during the handshake; see the doc
/// comment on `ControlPayload::HandshakeReject` in aivpn-common/protocol.rs).
/// Unlike a transient network error or handshake timeout, retrying can never
/// succeed here, so the receive loop returns `Err` immediately after
/// recording this flag+reason. The platform (`AivpnJni.handshakeRejectReason()`
/// / `AivpnService.kt`) polls it right after `runTunnel()` returns and must
/// STOP its reconnect loop instead of backing off and retrying forever —
/// mirrors the `FatalConfigException` terminal-stop path already used there
/// for permanently-invalid config.
pub static HANDSHAKE_REJECTED: AtomicBool = AtomicBool::new(false);
/// Reason code accompanying `HANDSHAKE_REJECTED` (only meaningful once that
/// flag is observed true). 1=one-time key already used, 2=client expired,
/// 3=client disabled, 0=unspecified — see `ControlPayload::HandshakeReject`.
pub static HANDSHAKE_REJECT_REASON: AtomicU8 = AtomicU8::new(0);
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
/// Sticky last-known-good mask. Set on the first real DATA RX of a session and
/// reused verbatim on every subsequent AUTO-mode reconnect (see
/// `resolve_sticky_handshake_mask`). FIX (Jul 15): a data-plane stall drives
/// the data watchdog to reconnect while the handshake keeps succeeding, so
/// `HANDSHAKE_FAIL_STREAK` (which only counts never-connected handshakes) never
/// trips — and the old resolver re-derived the mask from the churning
/// bootstrap-descriptor set, hopping to a different mask each reconnect and
/// never letting the data plane settle. Reusing the mask that last carried real
/// data ends the hop (the client converges on a working mask, as a user does by
/// manually pinning one). Process-global so it survives the platform reconnect
/// loop; a stale entry (e.g. after a server switch) self-corrects because a mask
/// that stops matching drives `HANDSHAKE_FAIL_STREAK` past the fallback
/// threshold, which bypasses stickiness.
pub static LAST_GOOD_MASK: Mutex<Option<MaskProfile>> = Mutex::new(None);

/// Liveness half of the sticky-mask fix. Counts consecutive SHORT sessions that
/// ended on the data watchdog while a sticky mask was in use. A mask that keeps
/// getting throttled — it handshakes fine and carries a little data, then its
/// data is quickly killed — must be abandoned, not reused forever, so after
/// `DATA_STALL_EXPLORE_THRESHOLD` such sessions the sticky mask is cleared and
/// AUTO resolution explores a different one.
pub static DATA_STALL_STREAK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// A session that carried data and stayed up at least this long is a working
/// mask; a later stall is a transient hiccup, not throttling, so the streak
/// resets and the mask stays sticky.
pub const HEALTHY_SESSION_MIN: Duration = Duration::from_secs(45);
/// Abandon the sticky mask after this many consecutive short data-stall sessions.
pub const DATA_STALL_EXPLORE_THRESHOLD: u32 = 4;

/// Called when a session ends on the data watchdog. A healthy-length session
/// resets the stall streak (the sticky mask works); repeated short stalls clear
/// the sticky mask so AUTO can explore alternatives.
pub fn note_data_stall_and_maybe_explore(established: Instant) {
    use std::sync::atomic::Ordering;
    if established.elapsed() >= HEALTHY_SESSION_MIN {
        DATA_STALL_STREAK.store(0, Ordering::Relaxed);
        return;
    }
    let n = DATA_STALL_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
    if n >= DATA_STALL_EXPLORE_THRESHOLD {
        *LAST_GOOD_MASK.lock().unwrap_or_else(|e| e.into_inner()) = None;
        DATA_STALL_STREAK.store(0, Ordering::Relaxed);
        log::warn!(
            "aivpn: sticky mask produced {n} short data-stall sessions — clearing it so auto-mask can try a different mask"
        );
    }
}

/// AUTO-mode mask resolution with the sticky net: once a mask has carried real
/// DATA this process (`LAST_GOOD_MASK`), reuse it instead of re-deriving from
/// the (churning) descriptor set. Yields to an explicit user mask choice and to
/// the handshake-fallback threshold (so a no-longer-matchable sticky mask can't
/// wedge the client).
pub fn resolve_sticky_handshake_mask(
    preferred: Option<&str>,
    descriptors: &[BootstrapDescriptor],
    psk: Option<&[u8; 32]>,
    fail_streak: u32,
) -> MaskProfile {
    let is_auto = preferred
        .map(str::trim)
        .map_or(true, |s| s.is_empty() || s == "auto");
    if is_auto && fail_streak < HANDSHAKE_FALLBACK_THRESHOLD {
        if let Some(m) = LAST_GOOD_MASK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return m;
        }
    }
    resolve_handshake_mask_resilient(preferred, descriptors, psk, fail_streak)
}
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
pub const DEFAULT_REPORT_INTERVAL_SECS: u32 = 3600;

/// §2 crowdsourced feedback base-mask-family collapse — shared implementation,
/// see `crate::mask::base_mask_family` (previously duplicated here).
pub use crate::mask::base_mask_family;

/// Parse a platform-supplied JSON array of prior (unreported) mask outcomes,
/// e.g. `[{"mask_id":"quic_https","success":2,"fail":1}]`. Best-effort:
/// missing/malformed JSON collapses to an empty batch rather than erroring —
/// feedback is never load-bearing for the tunnel connection itself.
pub fn parse_prior_outcomes(json: Option<&str>) -> Vec<MaskOutcome> {
    json.and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Merge the platform's batch of prior (unreported) outcomes with a single
/// success for `current_mask_id` (this attempt), summing counters per mask
/// id so a family already present in `prior` is not duplicated.
pub fn merge_mask_outcomes(prior: Vec<MaskOutcome>, current_mask_id: &str) -> Vec<MaskOutcome> {
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
pub static ACTIVE_CONTROL_TX: Mutex<Option<mpsc::Sender<ControlPayload>>> = Mutex::new(None);

/// In-tunnel management-API correlation state (P2.3-Android), shared between
/// the session loop (feeds it inbound `Capabilities` / `MgmtResponse` control
/// messages) and `lib.rs`'s `mgmtRequest`/`getRole` JNI exports (issue calls,
/// read the cached role). `crate::mgmt::MgmtClient` is internally
/// `Arc`-wrapped and cheaply `Clone`, but a process-global static is used here
/// (mirroring `ACTIVE_CONTROL_TX` / `ACTIVE_QUALITY_SCORE` above) because JNI
/// calls arrive on arbitrary Java threads with no handle into the tunnel
/// task's local variables. `Mutex` only guards construction; reads/writes
/// after `get_or_init` go through `MgmtClient`'s own interior `Arc<Mutex<_>>`
/// / atomics, so this is never held across an `.await`.
pub static ACTIVE_MGMT: std::sync::OnceLock<crate::mgmt::MgmtClient> = std::sync::OnceLock::new();

/// Returns the process-global `MgmtClient`, creating it on first use.
pub fn active_mgmt() -> &'static crate::mgmt::MgmtClient {
    ACTIVE_MGMT.get_or_init(crate::mgmt::MgmtClient::new)
}

/// Clone of the active session's outbound control-channel sender, for JNI
/// callers (`mgmtRequest`) that need to pass it directly into
/// `MgmtClient::mgmt_call` rather than routing through the fire-and-forget
/// `send_control_payload`. Returns `None` when no tunnel session is active
/// (mirrors `send_control_payload`'s no-session handling).
pub fn active_control_tx() -> Option<mpsc::Sender<ControlPayload>> {
    ACTIVE_CONTROL_TX
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
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

/// A TUN fd that an `AsyncFd` may poll but must never close: ownership lives in
/// [`SessionRuntime`] so a disconnect can drop the tun device immediately,
/// without waiting for the tokio tasks holding these views to be dropped.
pub struct TunFd(pub RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Phase 1 of releasing a session-owned TUN fd: drop the *reference to the tun
/// device* while keeping the fd NUMBER reserved.
///
/// Plain `close()` here would be a use-after-close hazard rather than a fix.
/// The reader task may still be parked on this fd, and the number is freed the
/// instant we close it — on Android the platform reconnects within
/// milliseconds, so the very next session can be handed the SAME number for its
/// own tun. The stale task would then read the NEW session's uplink packets and
/// push them into the OLD session's (dead) channel: the same "connected, no
/// traffic" symptom this whole path exists to prevent, just one reconnect later.
///
/// `dup2()` avoids that entirely. It atomically closes the old file description
/// — releasing the tun reference, so the device dies as soon as the platform
/// closes its own fd — and rebinds the number to `/dev/null`. Anything still
/// polling sees a valid fd: reads fail with `EBADF` (it is write-only) and the
/// task exits on its own, writes are discarded. The number cannot be recycled
/// behind our back because we still hold it.
///
/// Idempotent. Falls back to a plain close only if `/dev/null` cannot be opened,
/// which on Android/iOS means the process is already out of descriptors.
pub fn neutralize_session_fd(slot: &AtomicI32) {
    let fd = slot.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    let devnull = unsafe {
        libc::open(
            b"/dev/null\0".as_ptr() as *const libc::c_char,
            libc::O_WRONLY | libc::O_CLOEXEC,
        )
    };
    if devnull < 0 {
        if slot.swap(-1, Ordering::SeqCst) >= 0 {
            unsafe { libc::close(fd) };
        }
        return;
    }
    unsafe {
        libc::dup2(devnull, fd);
        libc::close(devnull);
    }
}

/// Phase 2: release the fd number itself, once the session is over and nothing
/// polls it any more. `swap(-1)` makes the caller the sole closer, so the number
/// can never be closed twice (and thus never closed after the OS handed it to an
/// unrelated `open`).
pub fn close_session_fd(slot: &AtomicI32) {
    let fd = slot.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

pub struct ActiveSessionGuard {
    session: Arc<SessionRuntime>,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        let udp_fd = self.session.udp_control_fd.swap(-1, Ordering::SeqCst);
        if udp_fd >= 0 {
            unsafe { libc::close(udp_fd) };
        }

        let stop_fd = self.session.stop_signal_fd.swap(-1, Ordering::SeqCst);
        if stop_fd >= 0 {
            unsafe { libc::close(stop_fd) };
        }

        let mut guard = ACTIVE_SESSION.lock().unwrap_or_else(|e| e.into_inner());
        // Normal end of a session: the run loop has returned, so both TUN views
        // are dead and the numbers can finally be given back. Taken under the
        // ACTIVE_SESSION lock so this can never interleave with a concurrent
        // `stop_active_tunnel` neutralising the same slots.
        close_session_fd(&self.session.tun_read_fd);
        close_session_fd(&self.session.tun_write_fd);
        if let Some(current) = guard.as_ref() {
            if Arc::ptr_eq(current, &self.session) {
                *guard = None;
            }
        }
    }
}

pub fn activate_session(session: Arc<SessionRuntime>) -> Result<ActiveSessionGuard> {
    let mut guard = ACTIVE_SESSION
        .lock()
        .map_err(|_| Error::Session("Active session lock poisoned".into()))?;

    if let Some(existing) = guard.as_ref() {
        if !existing.stop_requested.load(Ordering::SeqCst) {
            return Err(Error::Session(
                "Another tunnel session is already active".into(),
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
                // Set the flag FIRST so early init phases (DNS lookup, socket
                // creation) see it before the eventfd/UDP fd are available.
                s.stop_requested.store(true, Ordering::SeqCst);
                // Drop the tun references NOW, not whenever the native call
                // finishes unwinding. Android's Kotlin layer closes its
                // ParcelFileDescriptor on disconnect and waits only ~3 s for
                // that unwind; anything still holding a duplicate past that
                // point keeps the tun device alive with the VPN address on it,
                // and the next session's interface then competes with a zombie
                // for the app's packets. The fd numbers stay ours until the
                // session guard drops — see `neutralize_session_fd`.
                neutralize_session_fd(&s.tun_read_fd);
                neutralize_session_fd(&s.tun_write_fd);
                (
                    s.udp_control_fd.swap(-1, Ordering::SeqCst),
                    // swap(-1) takes OWNERSHIP of the eventfd, so a concurrent
                    // ActiveSessionGuard::drop (which also swaps) can never close
                    // it between our load and our write — the write below can't
                    // land on an unrelated reused fd.
                    s.stop_signal_fd.swap(-1, Ordering::SeqCst),
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

/// Wall-clock epoch ms at which the active session completed its handshake —
/// same session scope as the byte counters. Returns 0 when no session is
/// active or the session has not established yet.
pub fn get_active_connected_since_ms() -> u64 {
    ACTIVE_SESSION
        .lock()
        .ok()
        .and_then(|g| {
            g.as_ref()
                .map(|s| s.connected_at_unix_ms.load(Ordering::Relaxed))
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sticky-mask liveness: after DATA_STALL_EXPLORE_THRESHOLD consecutive
    /// SHORT data-stall sessions the sticky mask is cleared so AUTO can explore
    /// alternatives; a healthy-length session resets the streak so an occasional
    /// stall on a working mask never triggers exploration.
    #[test]
    fn sticky_mask_explores_after_repeated_short_stalls() {
        use std::sync::atomic::Ordering;
        let mask = crate::mask::preset_masks::all().into_iter().next().unwrap();
        let past = |secs: u64| {
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .unwrap()
        };

        // Seed a sticky mask + clean streak.
        *LAST_GOOD_MASK.lock().unwrap() = Some(mask.clone());
        DATA_STALL_STREAK.store(0, Ordering::Relaxed);

        // THRESHOLD-1 short stalls: mask stays sticky.
        for _ in 0..DATA_STALL_EXPLORE_THRESHOLD - 1 {
            note_data_stall_and_maybe_explore(past(5)); // 5 s session = short
        }
        assert!(
            LAST_GOOD_MASK.lock().unwrap().is_some(),
            "kept below threshold"
        );

        // One more short stall reaches the threshold: cleared → explore.
        note_data_stall_and_maybe_explore(past(5));
        assert!(
            LAST_GOOD_MASK.lock().unwrap().is_none(),
            "cleared at threshold"
        );

        // A healthy-length session resets the streak: subsequent short stalls
        // below the threshold do NOT clear the (re-seeded) sticky mask.
        *LAST_GOOD_MASK.lock().unwrap() = Some(mask.clone());
        DATA_STALL_STREAK.store(0, Ordering::Relaxed);
        note_data_stall_and_maybe_explore(past(5));
        note_data_stall_and_maybe_explore(past(HEALTHY_SESSION_MIN.as_secs() + 5)); // healthy → reset
        for _ in 0..DATA_STALL_EXPLORE_THRESHOLD - 1 {
            note_data_stall_and_maybe_explore(past(5));
        }
        assert!(
            LAST_GOOD_MASK.lock().unwrap().is_some(),
            "healthy session reset the streak"
        );
    }

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
}
