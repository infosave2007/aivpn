//! iOS VPN tunnel — runs on top of an AF_UNIX SOCK_DGRAM socketpair fd passed from
//! the NEPacketTunnelProvider extension. The protocol is byte-for-byte identical to the
//! Android and macOS clients; only the TUN I/O and stop-signal mechanisms differ.
//!
//! Key differences from android_tunnel.rs:
//!  - No JNI: protect() is unnecessary (NEPacketTunnelProvider is automatically outside VPN)
//!  - Stop signal uses pipe() instead of eventfd() (not available on iOS/macOS)
//!  - on_ready notification via C callback instead of JNI method call

#![allow(clippy::too_many_arguments)]

use std::collections::VecDeque;
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

use aivpn_common::client_wire::{
    build_inner_packet, build_shaped_mdh_packet, decode_downlink_any_mdh_len,
    decode_packet_with_mdh_len, obfuscate_client_eph_pub, process_server_hello_with_mdh_len,
    RecvWindow, DEFAULT_MDH_LEN,
};
use aivpn_common::crypto::{derive_session_keys, device_enrollment_proof, KeyPair, SessionKeys};
use aivpn_common::error::{Error, Result};
use aivpn_common::mask::{decode_bootstrap_descriptor, MaskProfile, HANDSHAKE_FALLBACK_THRESHOLD};
use aivpn_common::mimicry::MimicryEncryptor;
use aivpn_common::protocol::{ControlPayload, InnerType};
use aivpn_common::quality::{AdaptiveLevel, QualityTracker};
use aivpn_common::upload_pipeline::{self, UploadConfig};

// Shared mobile tunnel core: constants, session state/lifecycle, the upload
// encryptor (MobileEncryptor) and low-level socket/TUN/stop-signal I/O all
// live in aivpn-common::mobile_tunnel now (hoisted from android_tunnel.rs,
// which was logic-identical to this file for all of them). Re-exported so
// lib.rs keeps importing them from this module unchanged.
pub use aivpn_common::mobile_tunnel::*;

/// Server feedback about an in-progress/completed mask-recording session.
/// Mirrors the desktop client's handling of `ControlPayload::RecordingAck` /
/// `RecordingComplete` / `RecordingFailed` / `RecordingStatus` (see
/// aivpn-client's `client.rs`), field-for-field with the wire protocol in
/// `aivpn_common::protocol`. Populated by the main receive loop below and
/// polled from Swift via the FFI getters in `lib.rs`, following the same
/// shared-state idiom as `ACTIVE_QUALITY_SCORE` / `ACTIVE_ADAPTIVE_LEVEL`.
#[derive(Clone, Debug)]
pub enum RecordingFeedback {
    Ack {
        session_id: [u8; 16],
        status: String,
    },
    Complete {
        service: String,
        mask_id: String,
        confidence: f32,
    },
    Failed {
        reason: String,
    },
    Status {
        can_record: bool,
        active_service: Option<String>,
    },
}

pub static ACTIVE_RECORDING_FEEDBACK: Mutex<Option<RecordingFeedback>> = Mutex::new(None);
/// Bumped every time a new `RecordingFeedback` is stored, so Swift can detect
/// a fresh message by comparing against the last-seen sequence number rather
/// than re-reacting to a stale value every poll tick.
pub static RECORDING_FEEDBACK_SEQ: AtomicU64 = AtomicU64::new(0);

fn store_recording_feedback(fb: RecordingFeedback) {
    *ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(fb);
    RECORDING_FEEDBACK_SEQ.fetch_add(1, Ordering::Relaxed);
}

// ──────────── C callback type ────────────

pub type OnReadyFn = unsafe extern "C" fn(host: *const libc::c_char, ctx: *mut libc::c_void);

// Wrap the raw ctx pointer so the Future can be Send.
pub struct SendCtx(pub *mut libc::c_void);
unsafe impl Send for SendCtx {}

// ──────────── Entry point ────────────

pub async fn run_tunnel_ios(
    tun_fd: RawFd,
    server_host: String,
    server_port: u16,
    server_key: [u8; 32],
    psk: Option<[u8; 32]>,
    mtls_cert: Option<Vec<u8>>,
    on_ready: Option<OnReadyFn>,
    ctx: SendCtx,
    static_privkey: Option<[u8; 32]>,
    adaptive_level: u8,
    server_signing_key: Option<[u8; 32]>,
    // §3 Polymorphic masks: when set, ask the server to derive and push a
    // per-session perturbed variant of this base mask id right after the
    // handshake (mirrors desktop client.rs's `ClientConfig::polymorphic_base`).
    polymorphic_base: Option<String>,
    // §2 crowdsourced blocking feedback — both opt-in, OFF by default, mirroring
    // desktop client.rs's `ClientConfig::share_mask_feedback` / `receive_mask_hints`.
    share_mask_feedback: bool,
    receive_mask_hints: bool,
    // ISO-3166-1 alpha-2 country code the client believes it is in. Required for
    // `share_mask_feedback` to have any effect (mirrors desktop's `country_code`).
    country_code: Option<[u8; 2]>,
    // §2 crowdsourced blocking feedback — JSON-encoded `Vec<MaskOutcome>` of
    // outcomes the platform accumulated across PRIOR failed/succeeded attempts
    // (not including this one) and has not yet reported, or `None`/unparsable
    // for an empty batch. Merged with a success entry for this attempt's mask
    // and sent as a single `MaskFeedback` on success (mirrors desktop's
    // persisted `MaskFeedbackLog::aggregate_unreported`, adapted to the
    // single-shot FFI: the platform owns persistence across reconnects).
    prior_outcomes_json: Option<String>,
    // iOS mask-picker selection (mirrors Android's `preferred_mask`). Empty/`None`
    // or "auto" → PSK-derived bootstrap mask. Shapes the handshake + initial
    // opening burst so the SwiftUI mask Picker can steer the opening fingerprint.
    preferred_mask: Option<String>,
    // App-persisted bootstrap descriptors (JSON array of signed
    // `BootstrapDescriptor`s, or `None`/empty for none) that the platform saved
    // from a PRIOR session's `BootstrapDescriptorUpdate`s. Signature-verified
    // (against `server_signing_key` when set) and validity-filtered, then loaded
    // into the descriptor store BEFORE the handshake so the first packet of this
    // process can be shaped with a COVERT rotated descriptor mask rather than a
    // fingerprintable public preset (mirrors desktop
    // `bootstrap_cache::select_initial_mask`). A truly-first-ever connect (no
    // persisted descriptor yet) still uses the preset — acceptable residual.
    cached_descriptors_json: Option<String>,
    // R2 Phase B: operator's ed25519 mask-verifying public key (mirrors
    // desktop's `ClientConfig::mask_operator_pubkey`, sourced from the same
    // connection-key `mop` field via `ConnectionKey.maskOperatorPubkey` on the
    // Swift side). `None` when not configured — `verify_mask_artifact` then
    // resolves to `NoOperatorKey`/accept under `Warn`, exactly like desktop
    // with no `--mask-operator-pubkey` set.
    mask_operator_pubkey: Option<[u8; 32]>,
    // R2 Phase B: config-gated enforcement level for the check above (mirrors
    // desktop's `ClientConfig::mask_verify_mode`). Defaults to `Warn` when the
    // platform layer passes no override, matching desktop's own default.
    mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
) -> Result<()> {
    let session = Arc::new(SessionRuntime::new());
    let _guard = activate_session(session.clone())?;

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
            // H3: the sticky last-good mask, its stall streak and the
            // handshake-fail streak are just as server-specific as the
            // descriptors — carrying them across a server switch would pin
            // server B to server A's mask (or start B at A's fallback
            // threshold). Clear all three together with the store.
            *LAST_GOOD_MASK.lock().unwrap_or_else(|e| e.into_inner()) = None;
            DATA_STALL_STREAK.store(0, Ordering::Relaxed);
            HANDSHAKE_FAIL_STREAK.store(0, Ordering::Relaxed);
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

    // Reset per-session shared state that Swift polls via the FFI getters.
    // The NetworkExtension process (and thus these process-global statics)
    // can be reused across connect/disconnect cycles, so without this a new
    // session would surface the previous session's quality score and — worse
    // — its last recording-feedback message: Swift's `lastSeenRecordingFeedbackSeq`
    // resets to 0 in the fresh provider instance while RECORDING_FEEDBACK_SEQ
    // did not, so a stale RecordingAck/Complete/Failed would be re-applied on
    // the very first poll and spuriously drive the recording UI.
    ACTIVE_QUALITY_SCORE.store(0, Ordering::Relaxed);
    ACTIVE_ADAPTIVE_LEVEL.store(0, Ordering::Relaxed);
    // Clear last session's server-assigned VPN IP; this attempt's ServerHello
    // will re-populate it (or leave it 0 for old servers).
    ASSIGNED_VPN_IP.store(0, Ordering::Relaxed);
    RECORDING_FEEDBACK_SEQ.store(0, Ordering::Relaxed);
    *ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    // §2 crowdsourced blocking feedback — reset per-session state so a prior
    // attempt's outcome/FeedbackConfig is never misattributed to this one.
    EVER_CONNECTED.store(false, Ordering::Relaxed);
    CERT_REJECTED.store(false, Ordering::Relaxed);
    HANDSHAKE_REJECTED.store(false, Ordering::Relaxed);
    HANDSHAKE_REJECT_REASON.store(0, Ordering::Relaxed);
    ACTIVE_FEEDBACK_THRESHOLD.store(0, Ordering::Relaxed);
    ACTIVE_FEEDBACK_INTERVAL.store(0, Ordering::Relaxed);
    MASK_FEEDBACK_SENT.store(false, Ordering::Relaxed);
    *ATTEMPTED_MASK_FAMILY
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    REGIONAL_HINTS_SEQ.store(0, Ordering::Relaxed);
    *ACTIVE_REGIONAL_HINTS_JSON
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    MASK_CATALOG_SEQ.store(0, Ordering::Relaxed);
    *ACTIVE_MASK_CATALOG_JSON
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    // In-tunnel management-API client (P2.3-iOS): clear any pending
    // MgmtRequest correlation state and the cached role from a previous
    // session — a reconnect must re-learn the role from a fresh
    // Capabilities push, and stale pending req_ids can never be resolved
    // by the new session's MgmtResponses.
    active_mgmt().reset();

    let level = AdaptiveLevel::from_u8(adaptive_level);

    // 1. Ephemeral keypair + Zero-RTT session keys
    let mut keypair = KeyPair::generate();
    let mut dh = keypair.compute_shared(&server_key)?;
    let mut keys = derive_session_keys(&dh, psk.as_ref(), &keypair.public_key_bytes());

    // 2. Create the stop signal immediately — BEFORE DNS — so a disconnect
    //    press during a slow/hung cellular DNS is handled instantly, and race
    //    the lookup against it with a 5 s timeout (mirrors android_tunnel.rs).
    let stop_signal = create_stop_signal(&session)?;

    // UDP socket — no protect() needed: extension runs outside VPN routing
    let dest_str = format!("{}:{}", server_host, server_port);
    let dest: SocketAddr = tokio::select! {
        biased;
        _ = wait_for_stop(&stop_signal) => {
            return Err(Error::Session("Tunnel stop requested".into()));
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
        return Err(Error::Session("Tunnel stop requested".into()));
    }

    let raw_udp_fd = create_udp_socket(dest, &session, &|_fd| Ok(()))?;

    if session.stop_requested.load(Ordering::SeqCst) {
        unsafe { libc::close(raw_udp_fd) };
        return Err(Error::Session("Tunnel stop requested".into()));
    }

    // 3. TUN fd (socketpair end; Swift bridges packetFlow <-> this fd)
    let owned_tun_fd = unsafe { libc::dup(tun_fd) };
    if owned_tun_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    unsafe { libc::fcntl(owned_tun_fd, libc::F_SETFL, libc::O_NONBLOCK) };
    let owned_tun = unsafe { OwnedFd::from_raw_fd(owned_tun_fd) };
    let tun = AsyncFd::new(owned_tun)?;

    let std_udp = unsafe { std::net::UdpSocket::from_raw_fd(raw_udp_fd) };
    std_udp.set_nonblocking(true)?;
    let udp = Arc::new(UdpSocket::from_std(std_udp)?);

    // 4. Send init handshake
    let mdh_len = DEFAULT_MDH_LEN;
    // Variant A wire layout: the handshake + control plane speak the initial
    // (bootstrap) mask's layout. A new-layout preset embeds the resonance tag
    // inside its protocol header (webrtc tag_offset=8, quic=6) instead of a
    // separate offset-0 prefix; the server extracts the tag/eph per that mask's
    // native layout, so client and server MUST agree here. The FULL mask is
    // kept (not just its tag_offset) so `build_shaped_mdh_packet` can shape the
    // handshake/control MDH from the mask's `header_spec` (FIX 3: DPI-shaped
    // opening packets instead of pure-random noise). Resolved the same way as
    // `initial_mask` below (env + PSK are stable → identical mask).
    // Resilience net: after HANDSHAKE_FALLBACK_THRESHOLD consecutive handshake
    // timeouts, resolve WITHOUT the (possibly unmatchable) cached descriptors so
    // the attempt uses a builtin preset every server matches. Snapshot the
    // streak once so `initial_mask` below resolves identically.
    let handshake_fail_streak = HANDSHAKE_FAIL_STREAK.load(Ordering::Relaxed);
    if handshake_fail_streak >= HANDSHAKE_FALLBACK_THRESHOLD {
        log::warn!(
            "aivpn: {} consecutive handshakes never connected — falling back to a builtin preset mask (a cached bootstrap descriptor may be unmatchable by this server)",
            handshake_fail_streak
        );
    }
    let handshake_mask = resolve_sticky_handshake_mask(
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
    // Every distinct downlink MDH length this session may see, current first.
    // The server frames different downlink packets with different masks
    // (bootstrap for early DATA, runtime/catalog for control and rekey, a
    // polymorphic variant later); decoding with a single fixed length silently
    // drops any packet whose mask differs and strands the tunnel on the first
    // rekey. Seeded with the fixed handshake/control length plus the bootstrap
    // mask's own length; extended when MaskUpdate/MaskCatalog arrive.
    let mut recv_mdh_candidates: Vec<usize> = vec![mdh_len];
    let hs_mdh = handshake_mask.mdh_len();
    if !recv_mdh_candidates.contains(&hs_mdh) {
        recv_mdh_candidates.push(hs_mdh);
    }
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
    // reconnect (fresh run_tunnel_ios call) resets it.
    let mut rekey_response_eph: Option<[u8; 32]> = None;
    // Real send timestamp (mirrors desktop client.rs's warmup-burst fix):
    // send_ts=0 made every early RTT sample the server could compute from
    // this packet meaningless. Encoded once and resent verbatim on each
    // handshake retry below, so the timestamp is accurate for the first send
    // and slightly stale on a retry — still strictly better than always 0,
    // and no client-side quality tracking reads it during the handshake wait
    // anyway (the reply here is a ServerHello, not a KeepaliveAck).
    let keepalive = ControlPayload::Keepalive {
        send_ts: aivpn_common::crypto::current_timestamp_ms(),
    }
    .encode()?;
    {
        let obf_pub = obfuscate_client_eph_pub(&keypair, &server_key);
        let inner = build_inner_packet(InnerType::Control, send_seq, &keepalive);
        let pkt = build_shaped_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            Some(&obf_pub),
            mdh_len,
            &handshake_mask,
        )?;
        send_seq = send_seq.wrapping_add(1);
        udp.send(&pkt).await?;
    }

    // 5. Wait for ServerHello
    let mut recv_buf = vec![0u8; BUF_SIZE];
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut retry_count: u32 = 0;
    let mut recv_win = RecvWindow::new();
    let (server_network_cfg, server_eph_pub) = loop {
        let now = Instant::now();
        if now >= deadline {
            // Feed the resilience net: a timeout here is the signature of an
            // unmatchable handshake mask (tag mismatch server-side is silent).
            HANDSHAKE_FAIL_STREAK.fetch_add(1, Ordering::Relaxed);
            return Err(Error::Session("Handshake timeout (10 s)".into()));
        }
        let wait = std::cmp::min(
            HANDSHAKE_RETRY_INTERVAL,
            deadline.saturating_duration_since(now),
        );
        let retry = time::sleep(wait);
        tokio::pin!(retry);
        tokio::select! {
            _ = wait_for_stop(&stop_signal) => {
                return Err(Error::Session("Tunnel stop requested".into()));
            }
            r = udp.recv(&mut recv_buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(_) if session.stop_requested.load(Ordering::SeqCst) => {
                        return Err(Error::Session("Tunnel stop requested".into()));
                    }
                    Err(e) => return Err(Error::Io(e)),
                };
                // Peek for a terminal `HandshakeReject` BEFORE handing the datagram
                // to process_server_hello_with_mdh_len, which only understands
                // ServerHello and would otherwise discard a reject as just another
                // "non-ServerHello datagram — ignoring" and keep retrying handshake
                // resends until the 10 s deadline (then the platform's own backoff
                // loop retries again) — exactly the "keep hammering an authenticated
                // refusal" bug this feature exists to fix. Decoded with a scratch
                // clone of recv_win (RecvWindow: Clone) so a miss here — the common
                // case, a real ServerHello or noise — leaves the real recv_win
                // untouched and process_server_hello_with_mdh_len below behaves
                // exactly as before.
                let mut reject_peek_win = recv_win.clone();
                if let Ok(peeked) = decode_packet_with_mdh_len(
                    &recv_buf[..n],
                    &keys,
                    &mut reject_peek_win,
                    mdh_len,
                ) {
                    if peeked.header.inner_type == InnerType::Control {
                        if let Ok(ControlPayload::HandshakeReject { reason }) =
                            ControlPayload::decode(&peeked.payload)
                        {
                            log::warn!(
                                "aivpn: server sent HandshakeReject (reason={}) during handshake — authenticated refusal, not retrying",
                                reason
                            );
                            HANDSHAKE_REJECTED.store(true, Ordering::Relaxed);
                            HANDSHAKE_REJECT_REASON.store(reason, Ordering::Relaxed);
                            return Err(Error::Session(format!(
                                "HandshakeReject: reason={}",
                                reason
                            )));
                        }
                    }
                }
                // Tolerate a reordered early control push (or an undecodable
                // datagram) instead of failing the whole attempt on the first
                // packet — keep waiting for the real ServerHello until the
                // handshake deadline (desktop's dispatch loop just skips it).
                match process_server_hello_with_mdh_len(
                    &recv_buf[..n],
                    &mut keys,
                    &keypair,
                    &mut recv_win,
                    &mut send_counter,
                    mdh_len,
                    server_signing_key.as_ref(),
                ) {
                    Ok((cfg, server_eph_pub)) => break (cfg, server_eph_pub),
                    Err(e) => {
                        log::debug!("aivpn: non-ServerHello datagram during handshake — ignoring: {e}");
                    }
                }
            }
            _ = &mut retry => {
                if session.stop_requested.load(Ordering::SeqCst) {
                    return Err(Error::Session("Tunnel stop requested".into()));
                }
                retry_count += 1;
                // Rotate keypair only once (at 2nd retry, ~1.5 s after first send).
                // Rotating every retry creates a ghost session per 750 ms —
                // on reconnect the CGNAT per-IP cap (5) is hit within seconds.
                if retry_count == 2 {
                    keypair = KeyPair::generate();
                    dh = keypair.compute_shared(&server_key)?;
                    keys = derive_session_keys(&dh, psk.as_ref(), &keypair.public_key_bytes());
                    send_counter = 0;
                    send_seq = 0;
                    // Counters recorded from any pre-rotation datagram no longer
                    // apply to the fresh session the server will create.
                    recv_win.reset();
                }
                let obf_pub = obfuscate_client_eph_pub(&keypair, &server_key);
                let inner = build_inner_packet(InnerType::Control, send_seq, &keepalive);
                let pkt = build_shaped_mdh_packet(&keys, &mut send_counter, &inner, Some(&obf_pub), mdh_len, &handshake_mask)?;
                send_seq = send_seq.wrapping_add(1);
                udp.send(&pkt).await?;
            }
        }
    };

    // Publish the server-assigned VPN IP for Swift's re-home mismatch check
    // (see the ASSIGNED_VPN_IP doc comment).
    if let Some(cfg) = server_network_cfg.as_ref() {
        ASSIGNED_VPN_IP.store(u32::from(cfg.client_ip), Ordering::Relaxed);
    }
    // The server_eph_pub this session ratcheted against, so a mid-session
    // ServerHello resend (see the ServerHello arm in the main receive loop
    // below) can tell a genuine ratchet event from the server's own
    // reliability retransmit apart — gateway.rs resends ServerHello,
    // reusing the SAME server_eph_pub, whenever it sees a Keepalive from a
    // session it still considers un-ratcheted (its measure for a lost
    // post-ratchet confirmation packet). Mirrors desktop client.rs's
    // `ratcheted_server_eph_pub` field.
    let mut ratcheted_server_eph_pub: Option<[u8; 32]> = Some(server_eph_pub);
    // Server-derived base keepalive from the ServerHello network config
    // (mirrors android_tunnel.rs / desktop client.rs): the operator's
    // `keepalive_secs` must reach iOS too, not be silently discarded.
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
    let mut tr_keys: Option<SessionKeys> = Some(derive_session_keys(
        &dh,
        psk.as_ref(),
        &keypair.public_key_bytes(),
    ));
    let mut tr_deadline = Some(Instant::now() + Duration::from_secs(2));
    let mut tr_win = std::mem::take(&mut recv_win);
    // Hard ceiling on rekey-grace re-arms (see REKEY_TRANSITION_HARD_CAP).
    // Armed once per inline rekey at the key switch; never extended.
    let mut tr_hard: Option<Instant> = None;

    if let Some(cert) = mtls_cert {
        let cert_len_debug = cert.len();
        let cert_payload = ControlPayload::ClientCert { cert_bytes: cert }.encode()?;
        let inner = build_inner_packet(InnerType::Control, send_seq, &cert_payload);
        let pkt = build_shaped_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            None,
            mdh_len,
            &handshake_mask,
        )?;
        send_seq = send_seq.wrapping_add(1);
        udp.send(&pkt).await?;
        log::debug!("mTLS: ClientCert sent ({} bytes)", cert_len_debug);
    }

    // Early keepalive: prevent CGNAT outbound mapping expiry between last
    // handshake packet and the first upload pipeline tick.
    {
        let ka = ControlPayload::Keepalive {
            send_ts: aivpn_common::crypto::current_timestamp_ms(),
        }
        .encode()?;
        let inner = build_inner_packet(InnerType::Control, send_seq, &ka);
        if let Ok(pkt) = build_shaped_mdh_packet(
            &keys,
            &mut send_counter,
            &inner,
            None,
            mdh_len,
            &handshake_mask,
        ) {
            send_seq = send_seq.wrapping_add(1);
            let _ = udp.send(&pkt).await;
        }
    }

    // §2 L2 failure attribution — the handshake + PFS ratchet above completed
    // successfully, so this attempt is "connected" in the same sense as
    // desktop client.rs's `ClientState::Connected` (set right after the same
    // ratchet step). The platform polls this after `run_tunnel_ios` returns
    // to decide whether to attribute a failure to this attempt's mask family.
    EVER_CONNECTED.store(true, Ordering::Relaxed);
    // Stamp the session's connected-since (wall clock, same scope as the byte
    // counters) so the app's stopwatch survives UI relaunch/jetsam.
    session.connected_at_unix_ms.store(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        Ordering::Relaxed,
    );
    // Session start (post-handshake) — tells a working sticky mask (long healthy
    // session) from a throttled one (repeated short data stalls).
    let session_established = Instant::now();
    HANDSHAKE_FAIL_STREAK.store(0, Ordering::Relaxed);

    // Notify tunnel ready via C callback (after ClientCert so app UI opens after auth)
    if let Some(cb) = on_ready {
        if let Ok(c_host) = CString::new(server_host.as_str()) {
            unsafe { cb(c_host.as_ptr(), ctx.0) };
        }
    }

    // Warmup: 4 keepalives (100 ms apart) to force CGNAT to refresh the
    // inbound port mapping — fallback for when port reuse alone isn't enough.
    for _ in 0..4u8 {
        tokio::select! {
            biased;
            _ = wait_for_stop(&stop_signal) => {
                return Err(Error::Session("Tunnel stop requested".into()));
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Real send time (mirrors desktop client.rs's spawn_warmup_burst
                // fix): the server acks EVERY keepalive, and an echo_ts=0 reply
                // made the RTT handler fall back to the last periodic keepalive's
                // timestamp, poisoning the quality EWMA with 100..400 ms of fake
                // RTT right at session start.
                if let Ok(ka) = (ControlPayload::Keepalive {
                    send_ts: aivpn_common::crypto::current_timestamp_ms(),
                })
                .encode() {
                    let inner = build_inner_packet(InnerType::Control, send_seq, &ka);
                    if let Ok(pkt) = build_shaped_mdh_packet(&keys, &mut send_counter, &inner, None, mdh_len, &handshake_mask) {
                        send_seq = send_seq.wrapping_add(1);
                        let _ = udp.send(&pkt).await;
                    }
                }
            }
        }
    }

    // Device enrollment: send static key proof after ratchet (PFS-protected).
    // dh_proof is bound to THIS session's ephemeral transcript
    // (server_eph_pub || client_eph_pub, matching the server's
    // verify_device_enrollment_proof) so it cannot be replayed into a
    // different session.
    if let Some(priv_bytes) = static_privkey {
        let static_kp = KeyPair::from_private_key(priv_bytes);
        if let Ok(dh_shared) = static_kp.compute_shared(&server_key) {
            let client_eph_pub = keypair.public_key_bytes();
            let dh_proof = device_enrollment_proof(&dh_shared, &server_eph_pub, &client_eph_pub);
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
                    mdh_len,
                    &handshake_mask,
                ) {
                    send_seq = send_seq.wrapping_add(1);
                    let _ = udp.send(&pkt).await;
                }
            }
        }
    }

    // 6. Main forwarding loop
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

    let keepalive_sent_ms = Arc::new(AtomicU64::new(0));
    let mut quality_tracker = QualityTracker::new();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<ControlPayload>(8);
    // Clone for control payloads that originate in the receive loop below (the
    // inline-rekey KeyRotate response). They MUST be encrypted by the single
    // upload-task encryptor: building them here with the receive loop's own
    // `send_counter` reuses a ChaCha20-Poly1305 nonce (nonce == counter) already
    // consumed by the upload task under the same session key, leaking keystream
    // and making the server drop the response as a stale-counter replay (mirrors
    // desktop client.rs `send_control` and Android `ctrl_tx_recv_loop`).
    let ctrl_tx_recv_loop = ctrl_tx.clone();
    {
        let mut guard = ACTIVE_CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(ctrl_tx);
    }
    struct CtrlTxGuard;
    impl Drop for CtrlTxGuard {
        fn drop(&mut self) {
            let mut g = ACTIVE_CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner());
            *g = None;
        }
    }
    let _ctrl_tx_guard = CtrlTxGuard;

    // §3 F: whether a `polymorphic:`-prefixed `MaskUpdate` has been observed,
    // set by the MaskUpdate arm in the receive loop below. Used to stop the
    // MaskPreference retry task early once the server's push is confirmed.
    let polymorphic_confirmed = Arc::new(AtomicBool::new(false));

    // Polymorphic mask request (§3): ask the server to derive and push a
    // per-session perturbed variant of the requested base mask, riding on
    // the confirmed session keys — mirrors desktop client.rs's post-ratchet
    // `MaskPreference` send. Reliability (§3 F): a single lost MaskPreference
    // packet would silently disable polymorphic masks for the whole session,
    // so resend via the control channel (NOT a direct one-shot UDP send —
    // this task outlives the pre-upload-task window, and the upload task's
    // encryptor owns the only counter/keys safe to encrypt with once it
    // starts) up to 5 times over ~5s, stopping early once `MaskUpdate` with a
    // `polymorphic:` mask id is observed. The server side is idempotent (it
    // skips re-pushing a MaskUpdate when the session mask is already the
    // derived variant), so a resend racing an already-applied variant is
    // harmless (mirrors desktop client.rs's bounded retry task).
    if let Some(base_mask_id) = polymorphic_base.clone() {
        let tx = ctrl_tx_recv_loop.clone();
        let confirmed = polymorphic_confirmed.clone();
        tokio::spawn(async move {
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
                    // Receiver gone — run_tunnel_ios returned; stop.
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
            }
        });
    }

    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_SIZE);
    let (err_tx, mut err_rx) = mpsc::channel::<String>(16);
    let tun_err_tx = err_tx.clone();
    let sender_err_tx = err_tx.clone();

    let read_fd = unsafe { libc::dup(tun.as_raw_fd()) };
    if read_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let owned_tun_read = unsafe { OwnedFd::from_raw_fd(read_fd) };
    let tun_read = AsyncFd::new(owned_tun_read)?;

    let tun_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match tun_async_read(&tun_read, &mut buf).await {
                Ok(0) => continue,
                Ok(n) => {
                    if buf[0] >> 4 != 4 {
                        continue;
                    } // IPv4 only
                    if tun_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tun_err_tx.send(format!("TUN read: {e}")).await;
                    break;
                }
            }
        }
    });

    // Initial mimicry mask: the `preferred_mask` FFI argument (mirrors Android's
    // `preferred_mask`), or the PSK-derived bootstrap mask when unset/"auto".
    // Resolved identically to `handshake_mask` above so both planes agree.
    let initial_mask = resolve_sticky_handshake_mask(
        preferred_mask.as_deref(),
        &current_bootstrap_descriptors(),
        psk.as_ref(),
        handshake_fail_streak,
    );

    // (ATTEMPTED_MASK_FAMILY is published earlier, right after `handshake_mask`
    // resolves, so a handshake TIMEOUT is still attributed to the right family.
    // `initial_mask` resolves identically, so no second publish is needed here.)

    // §2 crowdsourced blocking feedback (opt-in, OFF by default). Mirrors
    // desktop client.rs's `record_mask_outcome` + `maybe_send_mask_feedback`,
    // collapsed to a single-shot send since `run_tunnel_ios` handles exactly
    // one connection per call — iOS reconnects by re-invoking this function
    // from scratch, so "once per connection" is just "once here". The
    // platform (`PacketTunnelProvider.swift`) owns cross-reconnect
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
                    mdh_len,
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
    // Rendezvous for in-flight KeyRotate responses. The receive loop pushes a
    // oneshot sender here before enqueueing its KeyRotate response onto
    // `ctrl_tx_recv_loop`, then blocks on the paired receiver until the upload
    // task actually encrypts that response (see MobileEncryptor::encrypt_control).
    // This guarantees the response is encrypted with the pre-ratchet keys before
    // the handler publishes the new keys into `key_rotate_slot`; without it the
    // upload task could pick up the new keys (via check_key_rotation on a data
    // packet) and encrypt the response with a key the server has not installed
    // yet, permanently desyncing the ratchet (mirrors desktop client.rs e6c3100).
    let rekey_ack: Arc<Mutex<VecDeque<oneshot::Sender<()>>>> =
        Arc::new(Mutex::new(VecDeque::new()));
    let rekey_ack_for_enc = Arc::clone(&rekey_ack);
    // One-shot old-key override for a RE-SENT KeyRotate response. When the
    // server retransmits a KeyRotate (our first response was lost), the receive
    // loop stages `(old_keys, current_keys)` here before enqueueing the SAME
    // response again: `encrypt_control` swaps the OLD keys in for that one
    // packet — the server is still on them — then restores the current keys.
    // The send counter is shared and MONOTONIC across both keys, so the
    // temporary swap can never reuse a (key, nonce) pair. Consumed only by
    // KeyRotate payloads; the initial-response path never sets it (mirrors the
    // desktop client.rs upload-key swap/restore rendezvous).
    let rekey_resend_keys: Arc<Mutex<Option<(SessionKeys, SessionKeys)>>> =
        Arc::new(Mutex::new(None));
    let rekey_resend_for_enc = Arc::clone(&rekey_resend_keys);

    let udp_tx = udp.clone();
    let keys_tx = keys.clone();
    let session_up = session.clone();
    let keepalive_ms_upload = keepalive_ms.clone();
    let upload_task = tokio::spawn(async move {
        // R2 Phase D — client-side ML-DPI self-gate (feature `client-dpi-gate`,
        // OFF by default). Capture the active mask family before `initial_mask`
        // is moved into the encryptor.
        #[cfg(feature = "client-dpi-gate")]
        let base_mask_id = initial_mask.mask_id.clone();

        let mut enc = MobileEncryptor {
            inner: MimicryEncryptor::new(
                keys_tx,
                send_counter,
                send_seq,
                initial_mask,
                mask_update_for_enc,
            ),
            session: session_up,
            keepalive_sent_ms,
            key_rotate_slot: key_rotate_for_enc,
            rekey_ack: rekey_ack_for_enc,
            rekey_resend_keys: rekey_resend_for_enc,
        };
        enc.inner.set_fec_group(level.fec_n());
        let cfg = UploadConfig {
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
            &cfg,
            inspector,
        )
        .await
        {
            let _ = sender_err_tx.send(format!("Upload: {e}")).await;
        }
    });

    let mut rx_check = time::interval(RX_CHECK_INTERVAL);
    rx_check.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    // Post-freeze/suspend liveness probe state (see WAKE_GAP_THRESHOLD):
    // stamp of the previous watchdog tick — BOTH clocks, because on Darwin
    // `Instant` (CLOCK_UPTIME_RAW) stops during device sleep while
    // `SystemTime` keeps advancing — and, when a gap was detected,
    // (deadline, armed_at, gap) of the pending probe.
    let mut last_watchdog_tick = Instant::now();
    let mut last_watchdog_wall = std::time::SystemTime::now();
    let mut wake_probe: Option<(Instant, Instant, Duration)> = None;

    loop {
        tokio::select! {
            biased;

            _ = wait_for_stop(&stop_signal) => {
                // Send Shutdown 3× so the server drops the session immediately
                // even if one UDP packet is lost on the mobile path. Route it
                // through the upload task's single encryptor so it uses that
                // encryptor's own counter — building it here with the receive
                // loop's frozen `send_counter` would reuse a (key, nonce) pair
                // the upload task already consumed (ChaCha20-Poly1305 keystream
                // leak) AND be dropped by the server as a stale-counter replay,
                // leaving a ghost session behind (mirrors android_tunnel.rs).
                for _ in 0..3u8 {
                    if ctrl_tx_recv_loop
                        .try_send(ControlPayload::Shutdown { reason: 0 })
                        .is_err()
                    {
                        break;
                    }
                }
                // Give the upload task a brief moment to flush before aborting.
                tokio::time::sleep(Duration::from_millis(120)).await;
                tun_reader.abort(); upload_task.abort();
                return Err(Error::Session("Stop requested".into()));
            }

            r = udp.recv(&mut udp_buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(_) if session.stop_requested.load(Ordering::SeqCst) => {
                        tun_reader.abort(); upload_task.abort();
                        return Err(Error::Session("Stop requested".into()));
                    }
                    Err(e) => return Err(Error::Io(e)),
                };
                if tr_deadline.is_some_and(|d| Instant::now() >= d) {
                    tr_keys = None;
                    tr_deadline = None;
                    tr_hard = None;
                    tr_win.reset();
                }
                let decoded = match decode_downlink_any_mdh_len(
                    &udp_buf[..n],
                    &keys,
                    &mut recv_win,
                    &mut recv_mdh_candidates,
                ) {
                    Ok(d) => Some(d),
                    Err(_) => tr_keys.as_ref().and_then(|tk| {
                        decode_downlink_any_mdh_len(&udp_buf[..n], tk, &mut tr_win, &mut recv_mdh_candidates)
                            .ok()
                    }),
                };
                if let Some(d) = decoded {
                    // Only a successfully authenticated packet proves the link is
                    // alive — advancing the watchdog on raw recv() would let
                    // undecodable (e.g. spoofed) datagrams mask a dead downlink.
                    // NOTE: `last_rx` feeds only the 120 s absolute net. Data-
                    // plane liveness is stamped in the Data arm below — control
                    // traffic (keepalive-acks, KeyRotate retransmits) must not
                    // mask a dead data downlink.
                    last_rx = Instant::now();
                    if d.header.inner_type == InnerType::Data && !d.payload.is_empty() {
                        tun_async_write(&tun, &d.payload).await?;
                        session.download_bytes.fetch_add(d.payload.len() as u64, Ordering::Relaxed);
                        last_data_rx = Instant::now();
                        upload_at_last_data_rx = session.upload_bytes.load(Ordering::Relaxed);
                        data_stall_started = None;
                        data_stall_strikes = 0;
                        if !data_plane_proven {
                            data_plane_proven = true;
                            // FIX (Jul 15): remember the mask that just carried real
                            // DATA so AUTO-mode reconnects reuse it instead of
                            // re-deriving (and hopping) from the churning descriptor
                            // set. See `resolve_sticky_handshake_mask`.
                            *LAST_GOOD_MASK.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(handshake_mask.clone());
                        }
                    }
                    if d.header.inner_type == InnerType::Control {
                        if let Ok(ctrl) = aivpn_common::protocol::ControlPayload::decode(&d.payload) {
                            match ctrl {
                                aivpn_common::protocol::ControlPayload::KeyRotate { new_eph_pub } => {
                                    if ratcheted_rekey_eph_pub == Some(new_eph_pub) {
                                        // A KeyRotate for an eph_pub we ALREADY ratcheted
                                        // against can only be a genuine server RETRANSMIT:
                                        // a network-duplicated copy carries the same
                                        // transport counter and dies at the replay window,
                                        // while a retransmit is a fresh packet under the
                                        // OLD keys (it decoded via `tr_keys` to get here).
                                        // The server retransmits because our rekey
                                        // RESPONSE was lost — silently ignoring it
                                        // deadlocked the tunnel (client on new keys,
                                        // server on old) until the RX-silence watchdog
                                        // forced a full reconnect. Re-send the SAME
                                        // response (same client eph — never a fresh
                                        // keypair, so whichever copy the server commits
                                        // yields exactly the keys we already switched to)
                                        // under the OLD keys the server can still read
                                        // (mirrors the desktop client.rs self-heal).
                                        let (Some(old_keys), Some(response_eph)) =
                                            (tr_keys.clone(), rekey_response_eph)
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
                                        *rekey_resend_keys
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner()) =
                                            Some((old_keys, keys.clone()));
                                        let (ack_tx, ack_rx) = oneshot::channel();
                                        rekey_ack
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .push_back(ack_tx);
                                        let response =
                                            aivpn_common::protocol::ControlPayload::KeyRotate {
                                                new_eph_pub: response_eph,
                                            };
                                        let sent =
                                            ctrl_tx_recv_loop.send(response).await.is_ok();
                                        // Bounded wait: a timeout means the upload
                                        // task died between dequeuing the KeyRotate
                                        // and firing the ack (sender stranded in the
                                        // shared queue) — fall into the failure
                                        // branch instead of hanging the recv loop.
                                        let confirmed = sent
                                            && matches!(
                                                time::timeout(REKEY_ACK_TIMEOUT, ack_rx)
                                                    .await,
                                                Ok(Ok(()))
                                            );
                                        if confirmed {
                                            // Keep accepting old-key downlink until the
                                            // server commits (or retransmits again) — but
                                            // never past the hard cap armed at the key
                                            // switch: unbounded re-arms let a never-
                                            // converging rekey defer recovery forever.
                                            let next =
                                                Instant::now() + REKEY_TRANSITION_GRACE;
                                            tr_deadline = Some(tr_hard
                                                .map_or(next, |hard| next.min(hard)));
                                        } else {
                                            // Upload task gone — the session is finished.
                                            // Drop the stale ack registration and the
                                            // unused override so they cannot mis-fire.
                                            rekey_ack
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .clear();
                                            *rekey_resend_keys
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner()) = None;
                                            log::warn!(
                                                "aivpn: rekey response re-send aborted — upload task gone before old-key send"
                                            );
                                        }
                                        continue;
                                    }
                                    log::info!("aivpn: inline rekey — KeyRotate received");
                                    let client_rekey_kp = aivpn_common::crypto::KeyPair::generate();
                                    let client_rekey_pub = client_rekey_kp.public_key_bytes();
                                    if let Ok(dh_rekey) = client_rekey_kp.compute_shared(&new_eph_pub) {
                                        let current_key = keys.session_key;
                                        let new_keys = aivpn_common::crypto::derive_session_keys(
                                            &dh_rekey,
                                            Some(&current_key),
                                            &client_rekey_pub,
                                        );
                                        let response_payload = aivpn_common::protocol::ControlPayload::KeyRotate {
                                            new_eph_pub: client_rekey_pub,
                                        };
                                        // Hand the response to the single upload-task encryptor
                                        // instead of building it here with `send_counter`, whose
                                        // value collides with the upload task's independent counter
                                        // under the same session key (nonce == counter → keystream
                                        // reuse, and the server drops the duplicate-counter response
                                        // as a replay). Register a rendezvous first: the upload task
                                        // fires `ack_tx` right after encrypting this response with its
                                        // CURRENT (pre-ratchet) keys; we block on it before publishing
                                        // the new keys into `key_rotate_slot`, so the response is
                                        // guaranteed to leave under the OLD key the server still
                                        // recognizes (mirrors desktop client.rs e6c3100 /
                                        // Android 69e4cbf).
                                        let (ack_tx, ack_rx) = oneshot::channel();
                                        rekey_ack
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .push_back(ack_tx);
                                        let sent = ctrl_tx_recv_loop.send(response_payload).await.is_ok();
                                        // Bounded wait: a timeout means the upload task died
                                        // between dequeuing the KeyRotate and firing the ack
                                        // (sender stranded in the shared queue) — fall into the
                                        // failure branch (which clears the queue) instead of
                                        // hanging the recv loop and the NE stop path forever.
                                        let confirmed = sent
                                            && matches!(
                                                time::timeout(REKEY_ACK_TIMEOUT, ack_rx).await,
                                                Ok(Ok(()))
                                            );
                                        if confirmed {
                                            // BOTH counters stay monotonic across the
                                            // rekey (only the key changes, so no nonce
                                            // reuse). The transition window is a CLONE
                                            // so the downlink recv-window keeps its
                                            // `highest`, staying inside the synced
                                            // forward span; and `send_counter` (uplink)
                                            // is NOT reset so the server's ±window c2s
                                            // matcher stays synced. Resetting either to
                                            // 0 stranded sustained transfer after the
                                            // first rekey under load (the from-zero
                                            // search/window cannot jump a loss burst).
                                            tr_keys = Some(keys.clone());
                                            // Grace must outlive the server's KeyRotate
                                            // retransmit horizon (lost-response
                                            // self-heal), not just in-flight packets —
                                            // see REKEY_TRANSITION_GRACE.
                                            tr_deadline = Some(Instant::now() + REKEY_TRANSITION_GRACE);
                                            // Absolute re-arm ceiling for THIS rekey
                                            // (see REKEY_TRANSITION_HARD_CAP).
                                            tr_hard = Some(
                                                Instant::now() + REKEY_TRANSITION_HARD_CAP,
                                            );
                                            tr_win = recv_win.clone();
                                            keys = new_keys;
                                            *key_rotate_slot
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner()) =
                                                Some(keys.clone());
                                            ratcheted_rekey_eph_pub = Some(new_eph_pub);
                                            rekey_response_eph = Some(client_rekey_pub);
                                            log::info!("aivpn: inline rekey complete");
                                        } else {
                                            // Upload task ended before confirming the old-key send.
                                            // The session is finished; drop the stale ack registration
                                            // and skip the key switch to avoid a one-sided ratchet.
                                            rekey_ack
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .clear();
                                            log::warn!(
                                                "aivpn: inline rekey — upload task gone before old-key send; aborting rekey to avoid desync"
                                            );
                                        }
                                    }
                                }
                                aivpn_common::protocol::ControlPayload::KeepaliveAck { echo_ts } => {
                                    if echo_ts > 0 {
                                        let now_ms = aivpn_common::crypto::current_timestamp_ms();
                                        if now_ms >= echo_ts {
                                            let rtt_us = (now_ms - echo_ts) * 1_000;
                                            quality_tracker.record_rtt(rtt_us);
                                        }
                                    }
                                    quality_tracker.record_received();
                                    let score = quality_tracker.score();
                                    ACTIVE_QUALITY_SCORE.store(score, Ordering::Relaxed);
                                    // Report live quality to the server for adaptive tuning /
                                    // telemetry (parity with Android + desktop). Enqueue to the
                                    // upload task's single encryptor rather than building a packet
                                    // here with a second `send_counter`, which would reuse a nonce
                                    // already consumed by the upload task under the same key
                                    // (see ctrl_tx_recv_loop above).
                                    let _ = ctrl_tx_recv_loop.try_send(
                                        ControlPayload::QualityReport {
                                            quality: score,
                                            rtt_ms: quality_tracker.rtt_ms(),
                                            loss_ppm: quality_tracker.loss_ppm(),
                                            jitter_ms: quality_tracker.jitter_ms(),
                                        },
                                    );
                                    log::debug!("aivpn: KeepaliveAck rtt={}ms quality={}/100",
                                        quality_tracker.rtt_ms(), score);
                                }
                                aivpn_common::protocol::ControlPayload::AdaptiveHint { level } => {
                                    ACTIVE_ADAPTIVE_LEVEL.store(level.min(3), Ordering::Relaxed);
                                    // Re-arm the running upload loop's keepalive interval to the
                                    // server-hinted level, mirroring desktop client.rs's
                                    // keepalive_with_nat_cap: take the level's own keepalive_secs()
                                    // clamped to the NAT-safe ceiling (Satellite uncapped). Clamping
                                    // against the initial interval instead would silently cap any
                                    // level above it and make the hint a no-op (see android_tunnel.rs).
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
                                aivpn_common::protocol::ControlPayload::MaskUpdate { mask_data, signature } => {
                                    // Transport-level signature: the server signs the raw
                                    // `mask_data` bytes with its ed25519 identity key
                                    // (`server_signing_key`) — same field/scheme as desktop
                                    // client.rs's handle_server_control MaskUpdate arm.
                                    // Verify BEFORE deserialising, and BEFORE this exact
                                    // payload can be treated as "channel-authenticated" for
                                    // any purpose below. `server_signing_key` being absent
                                    // (not configured) mirrors desktop's opt-in default —
                                    // transport_verified simply stays false and callers fall
                                    // through to the artifact-level check instead.
                                    let transport_verified = match server_signing_key.as_ref() {
                                        Some(signing_key) => {
                                            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                                            match VerifyingKey::from_bytes(signing_key) {
                                                Ok(vk) => {
                                                    let sig = Signature::from_bytes(&signature);
                                                    if vk.verify(&mask_data, &sig).is_err() {
                                                        log::warn!("aivpn: MaskUpdate rejected: invalid ed25519 transport signature");
                                                        false
                                                    } else {
                                                        true
                                                    }
                                                }
                                                Err(e) => {
                                                    log::warn!("aivpn: MaskUpdate rejected: bad server signing key in config: {}", e);
                                                    false
                                                }
                                            }
                                        }
                                        None => false,
                                    };
                                    // A configured signing key that failed to verify THIS
                                    // payload is a hard reject — do not fall through to the
                                    // artifact check below (mirrors desktop).
                                    if server_signing_key.is_some() && !transport_verified {
                                        continue;
                                    }
                                    if let Some(mask) = aivpn_common::mimicry::decode_mask_update(&mask_data) {
                                        // R2 Phase B: shared artifact verification hook, now
                                        // fed the real operator pubkey/mode plumbed through the
                                        // C FFI (`mask_operator_pubkey`/`mask_verify_mode`
                                        // params above) — iOS inherits the same semantics as
                                        // desktop's `handle_server_control` MaskUpdate arm.
                                        //
                                        // Derived variants (`polymorphic:`/`bootstrap:` mask_id
                                        // prefix) are exempt from the artifact check ONLY when
                                        // `transport_verified` is true for THIS exact payload —
                                        // i.e. the server's ed25519 signing key actually signed
                                        // these `mask_data` bytes. The mask_id prefix itself is
                                        // attacker-controlled (it arrives over the wire) and must
                                        // never be trusted on its own to skip verification: a
                                        // rogue/MITM server with no valid signing key could
                                        // otherwise fabricate any mask_id it likes and bypass the
                                        // artifact gate entirely.
                                        let artifact_ok = (mask.is_derived_variant() && transport_verified) || {
                                            let verdict = aivpn_common::mask::verify_mask_artifact(
                                                &mask,
                                                mask_operator_pubkey.as_ref(),
                                                mask_verify_mode,
                                            );
                                            if !verdict.accept {
                                                log::warn!("aivpn: MaskUpdate '{}' rejected (mask_verify_mode={:?}): {:?}", mask.mask_id, mask_verify_mode, verdict.detail);
                                            } else if verdict.is_failure() && mask_operator_pubkey.is_some() {
                                                log::warn!("aivpn: MaskUpdate '{}' failed operator signature verification ({:?}) — accepted because mask_verify_mode=warn", mask.mask_id, verdict.detail);
                                            }
                                            verdict.accept
                                        };
                                        if artifact_ok {
                                            // §3 F: once a polymorphic variant lands, signal the
                                            // MaskPreference retry task to stop resending.
                                            if mask.mask_id.starts_with("polymorphic:") {
                                                polymorphic_confirmed.store(true, Ordering::Relaxed);
                                            }
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
                                aivpn_common::protocol::ControlPayload::ServerHello {
                                    server_eph_pub: resent_eph_pub,
                                    signature,
                                    network_config,
                                } => {
                                    // The server resends ServerHello (reusing the SAME
                                    // server_eph_pub) whenever it sees a Keepalive from a
                                    // session it still considers un-ratcheted — its own
                                    // reliability measure for a lost post-ratchet confirmation
                                    // packet (gateway.rs's `!session.is_ratcheted` Keepalive
                                    // handler). Previously ServerHello had no arm here and fell
                                    // through to the wildcard below: the client (already
                                    // ratcheted from the pre-loop wait) never proved its ratchet
                                    // to the server, which kept resending until the session
                                    // either self-healed by luck or the RX-silence watchdog
                                    // forced a full reconnect. Mirrors desktop client.rs's
                                    // mid-session ServerHello handling.
                                    if let Some(signing_key) = server_signing_key.as_ref() {
                                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                                        let sig_ok = match VerifyingKey::from_bytes(signing_key) {
                                            Ok(vk) => {
                                                let mut msg = Vec::with_capacity(64);
                                                msg.extend_from_slice(&resent_eph_pub);
                                                msg.extend_from_slice(&keypair.public_key_bytes());
                                                let sig = Signature::from_bytes(&signature);
                                                vk.verify(&msg, &sig).is_ok()
                                            }
                                            Err(_) => false,
                                        };
                                        if !sig_ok {
                                            log::warn!("aivpn: mid-session ServerHello rejected: ed25519 signature invalid — possible MITM attack");
                                            continue;
                                        }
                                    }

                                    // Dedup against the eph_pub this session already ratcheted
                                    // for: the server always resends the SAME eph_pub (it never
                                    // creates a new ratchet event this way), so this is expected
                                    // to be a duplicate — skip the crypto and just re-confirm.
                                    let is_duplicate = ratcheted_server_eph_pub == Some(resent_eph_pub);
                                    if is_duplicate {
                                        log::debug!("aivpn: duplicate mid-session ServerHello for already-ratcheted eph_pub — re-confirming without re-ratcheting");
                                    } else {
                                        // Defensive parity with desktop's own dedup check: a
                                        // server that ever behaves differently (new eph_pub) must
                                        // not silently desync the client. Route the new keys
                                        // through the same key_rotate_slot handoff the inline
                                        // KeyRotate rekey above uses, so the upload task adopts
                                        // them too — not just this receive loop's local `keys`.
                                        match keypair.compute_shared(&resent_eph_pub) {
                                            Ok(dh2) => {
                                                log::info!("aivpn: mid-session ServerHello with a NEW server_eph_pub — completing PFS ratchet");
                                                let current_key = keys.session_key;
                                                let ratcheted = derive_session_keys(
                                                    &dh2,
                                                    Some(&current_key),
                                                    &keypair.public_key_bytes(),
                                                );
                                                // Keep decoding old-key downlink for a grace
                                                // window in case in-flight packets under the
                                                // previous keys are still arriving (mirrors the
                                                // inline-rekey transition window above).
                                                tr_keys = Some(keys.clone());
                                                tr_deadline = Some(Instant::now() + REKEY_TRANSITION_GRACE);
                                                tr_hard = Some(Instant::now() + REKEY_TRANSITION_HARD_CAP);
                                                tr_win = recv_win.clone();
                                                keys = ratcheted;
                                                recv_win.reset();
                                                *key_rotate_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                                                    Some(keys.clone());
                                                ratcheted_server_eph_pub = Some(resent_eph_pub);
                                            }
                                            Err(e) => {
                                                log::warn!("aivpn: mid-session ServerHello DH failed: {e} — ignoring");
                                                continue;
                                            }
                                        }
                                    }

                                    // Re-apply network config (VPN IP / keepalive) exactly like
                                    // the pre-loop handler — the server may push an updated
                                    // pool-assigned IP or keepalive interval on this resend too.
                                    if let Some(cfg) = network_config.as_ref() {
                                        ASSIGNED_VPN_IP.store(u32::from(cfg.client_ip), Ordering::Relaxed);
                                        if let Some(ka) = cfg.keepalive_secs.filter(|&s| s > 0) {
                                            let requested = Duration::from_secs(ka as u64);
                                            let capped = requested.min(KEEPALIVE_NAT_CAP);
                                            keepalive_ms.store(capped.as_millis() as u64, Ordering::Relaxed);
                                        }
                                    }

                                    // Prod the server with fresh confirmation traffic under the
                                    // (now) ratcheted keys so it observes the ratchet and stops
                                    // retrying — mirrors desktop's ClientCert/DeviceEnrollment
                                    // resend after every ServerHello (dup or not).
                                    let _ = ctrl_tx_recv_loop.try_send(ControlPayload::Keepalive {
                                        send_ts: aivpn_common::crypto::current_timestamp_ms(),
                                    });
                                }
                                aivpn_common::protocol::ControlPayload::CertRejected {} => {
                                    log::warn!("aivpn: mTLS certificate rejected by server — re-provision your mTLS cert");
                                    // Surface to Swift (aivpn_cert_was_rejected()) so the UI can
                                    // prompt for re-provisioning instead of retrying forever in
                                    // silence — desktop only logs this; mobile has no console the
                                    // user will ever see.
                                    CERT_REJECTED.store(true, Ordering::Relaxed);
                                }
                                aivpn_common::protocol::ControlPayload::HandshakeReject { reason } => {
                                    // AEAD-authenticated terminal refusal arriving mid-session
                                    // (e.g. a one-time key/expiry/disable state change the
                                    // server discovers after the initial handshake already
                                    // completed). Same handling as the handshake-wait loop's
                                    // peek above: surface the reason and end the session with
                                    // an error so the platform reconnect loop can inspect
                                    // HANDSHAKE_REJECTED and stop retrying instead of treating
                                    // this like any other recoverable disconnect.
                                    log::warn!(
                                        "aivpn: server sent HandshakeReject (reason={}) — authenticated refusal, not retrying",
                                        reason
                                    );
                                    HANDSHAKE_REJECTED.store(true, Ordering::Relaxed);
                                    HANDSHAKE_REJECT_REASON.store(reason, Ordering::Relaxed);
                                    tun_reader.abort();
                                    upload_task.abort();
                                    return Err(Error::Session(format!(
                                        "HandshakeReject: reason={}",
                                        reason
                                    )));
                                }
                                aivpn_common::protocol::ControlPayload::RecordingAck { session_id, status } => {
                                    log::info!("aivpn: RecordingAck status={}", status);
                                    store_recording_feedback(RecordingFeedback::Ack { session_id, status });
                                }
                                aivpn_common::protocol::ControlPayload::RecordingComplete { service, mask_id, confidence } => {
                                    log::info!("aivpn: RecordingComplete mask_id={} confidence={:.2}", mask_id, confidence);
                                    store_recording_feedback(RecordingFeedback::Complete { service, mask_id, confidence });
                                }
                                aivpn_common::protocol::ControlPayload::RecordingFailed { reason } => {
                                    log::warn!("aivpn: RecordingFailed reason={}", reason);
                                    store_recording_feedback(RecordingFeedback::Failed { reason });
                                }
                                aivpn_common::protocol::ControlPayload::RecordingStatus { can_record, active_service } => {
                                    log::info!("aivpn: RecordingStatus can_record={} active_service={:?}", can_record, active_service);
                                    store_recording_feedback(RecordingFeedback::Status { can_record, active_service });
                                }
                                aivpn_common::protocol::ControlPayload::RegionalMaskHints { country_code, masks } => {
                                    // §2 crowdsourced blocking feedback — opt-in. The server
                                    // only ever sends this after k-anonymity-gated aggregation
                                    // (see aivpn-server's mask_feedback.rs); ignore entirely
                                    // unless the client asked to receive hints (mirrors desktop
                                    // client.rs's RegionalMaskHints handling).
                                    if !receive_mask_hints {
                                        log::debug!("aivpn: RegionalMaskHints received but receive_mask_hints=false — ignoring");
                                    } else {
                                        log::info!(
                                            "aivpn: RegionalMaskHints for {}{}: {} masks",
                                            country_code[0] as char, country_code[1] as char, masks.len()
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
                                    }
                                }
                                aivpn_common::protocol::ControlPayload::MaskCatalog { masks } => {
                                    // Server pushed the selectable-mask list. Store it as
                                    // JSON so the SwiftUI Picker renders a live list and
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
                                aivpn_common::protocol::ControlPayload::FeedbackConfig { report_failure_threshold, report_interval_secs } => {
                                    // §2 M3 server-pushed config. Only meaningful to an
                                    // opted-in client; the server only sends this in reply
                                    // to a MaskFeedback, which only opted-in clients emit.
                                    // Stored in a process-global so the platform layer can
                                    // poll it after `run_tunnel_ios` returns and persist it
                                    // for the next reconnect attempt (mirrors desktop's
                                    // `MaskFeedbackLog::set_tuning`, adapted to the
                                    // single-shot FFI where this Rust instance is dropped
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
                                aivpn_common::protocol::ControlPayload::Shutdown { reason } => {
                                    // Server-initiated teardown — mirror desktop client.rs's
                                    // Shutdown handler: log it and end the session with an error so
                                    // the platform reconnect loop (PacketTunnelProvider.swift) kicks
                                    // in, the same way any other unrecoverable server event does.
                                    log::info!("aivpn: server requested shutdown (reason: {})", reason);
                                    tun_reader.abort();
                                    upload_task.abort();
                                    return Err(Error::Session(format!("server shutdown: {reason}")));
                                }
                                aivpn_common::protocol::ControlPayload::BootstrapDescriptorUpdate { descriptor_data } => {
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
                                aivpn_common::protocol::ControlPayload::Capabilities {
                                    role,
                                    ..
                                } => {
                                    log::debug!("aivpn: Capabilities role={}", role);
                                    active_mgmt().on_capabilities(role);
                                }
                                aivpn_common::protocol::ControlPayload::MgmtResponse {
                                    req_id,
                                    status,
                                    body,
                                } => {
                                    log::debug!(
                                        "aivpn: MgmtResponse req_id={} status={} body_len={}",
                                        req_id,
                                        status,
                                        body.len()
                                    );
                                    active_mgmt().on_mgmt_response(req_id, status, body);
                                }
                                aivpn_common::protocol::ControlPayload::TimeSync { .. }
                                | aivpn_common::protocol::ControlPayload::PoolSync { .. }
                                | aivpn_common::protocol::ControlPayload::PoolStateDigest { .. }
                                | aivpn_common::protocol::ControlPayload::PoolBucketDigests { .. }
                                | aivpn_common::protocol::ControlPayload::RouteSync { .. }
                                | aivpn_common::protocol::ControlPayload::ChainForward { .. }
                                | aivpn_common::protocol::ControlPayload::PartitionAnnounce { .. }
                                | aivpn_common::protocol::ControlPayload::NodeEnrollment { .. }
                                | aivpn_common::protocol::ControlPayload::MgmtRequest { .. }
                                | aivpn_common::protocol::ControlPayload::RecordingStatusRequest
                                | aivpn_common::protocol::ControlPayload::RecordingStart { .. }
                                | aivpn_common::protocol::ControlPayload::RecordingStop { .. } => {
                                    // Intentionally ignored on the iOS core: pool-sync/
                                    // node-enrollment/mgmt-request/recording-admin family
                                    // this mobile core never participates in at all (not a
                                    // pool node or dialer, and admin-initiated recording is
                                    // desktop-only) — never sent NOR received here.
                                }
                                aivpn_common::protocol::ControlPayload::Keepalive { .. }
                                | aivpn_common::protocol::ControlPayload::ClientCert { .. }
                                | aivpn_common::protocol::ControlPayload::DeviceEnrollment { .. }
                                | aivpn_common::protocol::ControlPayload::QualityReport { .. }
                                | aivpn_common::protocol::ControlPayload::MaskPreference { .. }
                                | aivpn_common::protocol::ControlPayload::MaskFeedback { .. } => {
                                    // Intentionally ignored on the iOS core: this core only
                                    // ever SENDS these to the server; there is no inbound
                                    // handling because the server never sends them back.
                                }
                                aivpn_common::protocol::ControlPayload::TelemetryRequest { .. }
                                | aivpn_common::protocol::ControlPayload::TelemetryResponse { .. }
                                | aivpn_common::protocol::ControlPayload::ControlAck { .. } => {
                                    // Intentionally ignored on the iOS core: reserved
                                    // telemetry-request/ack subtypes only the server side
                                    // (`aivpn-server/src/gateway.rs`) currently exercises;
                                    // this mobile core neither sends nor needs to act on them.
                                }
                            }
                        }
                    }
                }
            }

            maybe_err = err_rx.recv() => {
                if let Some(msg) = maybe_err {
                    tun_reader.abort(); upload_task.abort();
                    return Err(Error::Session(msg));
                }
            }

            _ = rx_check.tick() => {
                // Post-freeze/suspend liveness probe (see WAKE_GAP_THRESHOLD):
                // a tick gap ≫ RX_CHECK_INTERVAL means the NE process was
                // frozen or the device suspended. Arm a probe: unless ANY
                // decodable RX arrives within the window (keepalives fire
                // immediately after wake), the session is condemned within
                // the probe window instead of lingering dead until
                // RX_SILENCE.
                //
                // Scope: the probe matters for gaps SHORTER than RX_SILENCE.
                // For a PROCESS-freeze gap > RX_SILENCE, `last_rx` (Instant,
                // which kept counting through the freeze) already exceeds the
                // absolute net below on this same tick, so the session
                // reconnects immediately — acceptable and desired after a
                // >120 s freeze. A DEVICE-sleep gap is invisible to Instant
                // (`last_rx` excludes the sleep), so sleep gaps of ANY length
                // are covered by this probe via the wall-clock measurement.
                //
                // Gap measurement: max of both clocks. Instant catches
                // process freezes; the wall clock catches device sleep. A
                // wall-clock STEP (NTP correction, manual set) can produce a
                // negative diff — collapsed to zero by `unwrap_or` — or a
                // spurious forward jump, which at worst arms a probe that the
                // next decodable RX immediately disarms.
                let tick_now = Instant::now();
                let wall_now = std::time::SystemTime::now();
                let instant_gap = tick_now.duration_since(last_watchdog_tick);
                let wall_gap = wall_now
                    .duration_since(last_watchdog_wall)
                    .unwrap_or(Duration::ZERO);
                let tick_gap = instant_gap.max(wall_gap);
                last_watchdog_tick = tick_now;
                last_watchdog_wall = wall_now;
                if tick_gap > WAKE_GAP_THRESHOLD && wake_probe.is_none() {
                    let window = Duration::from_millis(keepalive_ms.load(Ordering::Relaxed))
                        .saturating_mul(2)
                        .clamp(WAKE_PROBE_WINDOW_MIN, WAKE_PROBE_WINDOW_MAX);
                    log::info!(
                        "aivpn: watchdog tick gap {tick_gap:?} (process frozen or device suspended) — \
                         post-wake liveness probe armed ({window:?})"
                    );
                    wake_probe = Some((tick_now + window, tick_now, tick_gap));
                }
                if let Some((deadline, armed_at, gap)) = wake_probe {
                    if last_rx >= armed_at {
                        // Decodable RX after the wake moment — session alive.
                        wake_probe = None;
                    } else if tick_now >= deadline {
                        tun_reader.abort(); upload_task.abort();
                        return Err(Error::Session(format!(
                            "post-wake liveness probe: no RX for {:?} after a {:?} \
                             freeze/suspend gap — reconnecting",
                            last_rx.elapsed(),
                            gap,
                        )));
                    }
                }
                // Data-plane watchdog: clocked on DATA delivered to the TUN,
                // not on any decode — a downlink where only keepalive-acks /
                // KeyRotate retransmits still authenticate is DEAD for the
                // user and must reconnect in tens of seconds, not after the
                // 120 s absolute net (see `data_watchdog_verdict`).
                let uploaded = session.upload_bytes.load(Ordering::Relaxed);
                let data_up_since = uploaded.saturating_sub(upload_at_last_data_rx);
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
                    tun_reader.abort(); upload_task.abort();
                    // Liveness: a sticky mask that keeps stalling quickly gets
                    // abandoned so AUTO can explore a different one.
                    note_data_stall_and_maybe_explore(session_established);
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
                    upload_at_last_data_rx = uploaded;
                }
                // Absolute net: nothing decodable AT ALL (control included).
                let silence = last_rx.elapsed();
                if silence > RX_SILENCE {
                    tun_reader.abort(); upload_task.abort();
                    return Err(Error::Session(format!("No RX for {silence:?} — reconnecting")));
                }
            }
        }
    }
}
