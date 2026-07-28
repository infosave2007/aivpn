//! Shared mobile tunnel run loop.
//!
//! `run_tunnel_generic` is the former `run_tunnel_android` text (the merge
//! base — it carried the later fixes), with the enumerated iOS-side
//! improvements folded in and the three platform-specific operations routed
//! through [`PlatformIo`]. `run_tunnel_ios` / `run_tunnel_android` are now
//! thin adapters over it, each preserving its own FFI/JNI signature and
//! return convention.

use std::collections::VecDeque;
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

use crate::client_wire::{
    build_inner_packet, build_shaped_mdh_packet, decode_downlink_any_mdh_len,
    decode_packet_with_mdh_len, obfuscate_client_eph_pub, process_server_hello_with_mdh_len,
    RecvWindow,
};
use crate::crypto::{derive_session_keys, device_enrollment_proof, KeyPair, SessionKeys};
use crate::error::{Error, Result};
use crate::mask::{decode_bootstrap_descriptor, MaskProfile, HANDSHAKE_FALLBACK_THRESHOLD};
use crate::mimicry::MimicryEncryptor;
use crate::protocol::{ControlPayload, InnerType};
use crate::quality::{AdaptiveLevel, QualityTracker};
use crate::upload_pipeline::{self, UploadConfig};

use super::encryptor::{MobileEncryptor, RekeyAckQueue, RekeyResendSlot};
use super::io::{
    create_stop_signal, create_udp_socket, tun_async_read, tun_async_write, wait_for_stop,
};
use super::platform::{PlatformIo, RecordingFeedback};
use super::state::*;

/// Runs one whole tunnel session (exactly one connection attempt) on the
/// calling task.
///
/// Returns `Err` on any tunnel failure, so the platform's reconnect loop
/// kicks in. A STOP (user disconnect) returns `Ok(())` — the Android
/// convention; `run_tunnel_ios` re-maps that to `Err` in its adapter so the
/// Swift side keeps seeing -1 on stop exactly as before.
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_generic<P: PlatformIo>(
    platform: P,
    tun_fd: RawFd,
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
    // R2 Phase B: operator mask-verifying public key for artifact-level mask
    // signature verification, sourced from the `mop` field of the connection
    // key (mirrors desktop's `ClientConfig::mask_operator_pubkey`, itself
    // sourced from --mask-operator-pubkey / the config file / the same `mop`
    // field). Distinct from `server_signing_key` ("sk"): that authenticates
    // "pushed by my server" (transport); this authenticates "gated + signed
    // by the operator" (artifact) — see `verify_mask_artifact`.
    mask_operator_pubkey: Option<[u8; 32]>,
    // Matching verification strictness (mirrors desktop's `mask_verify_mode`).
    // Android has no CLI/config-file surface yet, so the platform layer
    // currently always passes `MaskVerifyMode::Warn` (the same default
    // desktop uses absent an explicit override) — this parameter exists so
    // wiring in a future settings toggle only touches the JNI call site.
    mask_verify_mode: crate::mask::MaskVerifyMode,
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
    // Clear last session's quality so the diagnostics UI doesn't show a stale
    // score between reconnect and the first KeepaliveAck of the new session.
    ACTIVE_QUALITY_SCORE.store(0, Ordering::Relaxed);
    // Clear last session's server-assigned VPN IP; this attempt's ServerHello
    // will re-populate it (or leave it 0 for old servers).
    ASSIGNED_VPN_IP.store(0, Ordering::Relaxed);
    ACTIVE_FEEDBACK_THRESHOLD.store(0, Ordering::Relaxed);
    ACTIVE_FEEDBACK_INTERVAL.store(0, Ordering::Relaxed);
    MASK_FEEDBACK_SENT.store(false, Ordering::Relaxed);
    CERT_REJECTED.store(false, Ordering::Relaxed);
    HANDSHAKE_REJECTED.store(false, Ordering::Relaxed);
    HANDSHAKE_REJECT_REASON.store(0, Ordering::Relaxed);
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
    // P2.3: clear in-flight mgmt-API correlation state and the
    // cached role from any prior session before this attempt's handshake.
    active_mgmt().reset();

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
            // §M1: the sticky-mask state is just as server-scoped as the
            // descriptors — a mask proven to pass DATA against server A (and
            // its stall / handshake-fail streaks) says nothing about server B.
            // Leaking it across a profile switch made the first attempts on
            // the new server reuse the old server's mask instead of resolving
            // fresh, and let stale streaks trip the fallback/abandon logic.
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

    // ── 1. Ephemeral keypair + initial session keys ──
    let mut keypair = KeyPair::generate();
    let mut dh = keypair.compute_shared(&server_key)?;
    let mut keys = derive_session_keys(&dh, psk.as_ref(), &keypair.public_key_bytes());

    // ── 2. Create stop signal immediately — before DNS — so a disconnect press
    //    during a slow/hung cellular DNS is handled instantly, not after a 5 s wait.
    let stop_signal = create_stop_signal(&session)?;

    // Resolve host; race against stop signal so disconnect is always responsive.
    let dest_str = format!("{}:{}", server_host, server_port);
    let dest: SocketAddr = tokio::select! {
        biased;
        _ = wait_for_stop(&stop_signal) => {
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

    // Exempt the socket from the VPN before any traffic flows: Android calls
    // VpnService.protect(int) through JNI, iOS is a no-op. On failure the fd
    // is closed by create_udp_socket itself.
    let raw_udp_fd = create_udp_socket(dest, &session, &|fd| platform.protect_socket(fd))?;
    // Own the UDP fd immediately so the dup/fcntl/AsyncFd failure paths below
    // (each an early `return Err`) close it via Drop instead of leaking one fd
    // per attempt in a tight reconnect loop (LOW-1). Consumed by `UdpSocket::from`
    // once all fallible setup has succeeded.
    // SAFETY: create_udp_socket returns a fresh, exclusively-owned fd.
    let owned_udp = unsafe { OwnedFd::from_raw_fd(raw_udp_fd) };

    if session.stop_requested.load(Ordering::SeqCst) {
        return Ok(());
    }

    // ── 3. Set TUN fd to non-blocking for AsyncFd ──
    let owned_tun_fd = unsafe { libc::dup(tun_fd) };
    if owned_tun_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    let fcntl_ret = unsafe { libc::fcntl(owned_tun_fd, libc::F_SETFL, libc::O_NONBLOCK) };
    if fcntl_ret < 0 {
        unsafe { libc::close(owned_tun_fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: this is Rust's private duplicate of the Android-owned TUN fd.
    let owned_tun = unsafe { OwnedFd::from_raw_fd(owned_tun_fd) };
    let tun = AsyncFd::new(owned_tun)?;

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
    // reconnect (fresh session) resets it.
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
    // mask's own length; extended when MaskUpdate arrives.
    let mut recv_mdh_candidates: Vec<usize> = vec![mdh_len];
    let hs_mdh = handshake_mask.mdh_len();
    if !recv_mdh_candidates.contains(&hs_mdh) {
        recv_mdh_candidates.push(hs_mdh);
    }
    // Real send timestamp (not 0) so any ack the server sends back yields a
    // usable RTT sample instead of poisoning the quality EWMA — mirrors
    // desktop client.rs's `epoch_ms()` stamping on its warmup burst.
    let keepalive = ControlPayload::Keepalive {
        send_ts: crate::crypto::current_timestamp_ms(),
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

    // ── 5. Wait for ServerHello with timeout ──
    let mut recv_buf = vec![0u8; BUF_SIZE];
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut retry_count: u32 = 0;
    let mut recv_win = RecvWindow::new();
    let (server_network_cfg, server_eph_pub) = loop {
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
            _ = wait_for_stop(&stop_signal) => {
                return Ok(());
            }

            res = udp.recv(&mut recv_buf) => {
                match res {
                    Ok(n) => {
                        // Peek for a terminal `HandshakeReject` BEFORE handing the
                        // datagram to process_server_hello_with_mdh_len, which only
                        // understands ServerHello and would otherwise discard a reject
                        // as just another "non-ServerHello datagram — ignoring" and keep
                        // retrying handshake resends until the 10 s deadline (then the
                        // platform's own backoff loop retries again) — exactly the "keep
                        // hammering an authenticated refusal" bug this feature exists to
                        // fix. Decoded with a scratch clone of recv_win (RecvWindow:
                        // Clone) so a miss here — the common case, a real ServerHello or
                        // noise — leaves the real recv_win untouched and
                        // process_server_hello_with_mdh_len below behaves exactly as
                        // before.
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
                                        "aivpn: HandshakeReject from server during handshake: reason={} — session terminal, not retrying this credential",
                                        reason
                                    );
                                    // Reason BEFORE the flag: the platform polls the
                                    // flag and then reads the reason, so publishing the
                                    // flag first could expose a stale reason.
                                    HANDSHAKE_REJECT_REASON.store(reason, Ordering::Relaxed);
                                    HANDSHAKE_REJECTED.store(true, Ordering::Relaxed);
                                    return Err(Error::Session(format!(
                                        "HandshakeReject: reason={reason}"
                                    )));
                                }
                            }
                        }
                        // Tolerate a reordered early control push (or an
                        // undecodable datagram) instead of failing the whole
                        // attempt on the first packet — keep waiting for the
                        // real ServerHello until the handshake deadline
                        // (desktop's dispatch loop just skips it).
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
                                // A terminal HandshakeReject was already surfaced by the
                                // cloned-window peek above, so anything reaching here is
                                // a reordered early control push or plain noise.
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
    // Idempotency tracker for a mid-session ServerHello resend (see the
    // ControlPayload::ServerHello arm in the main dispatch loop below): the
    // server re-sends ServerHello — instead of a plain KeepaliveAck —
    // whenever it receives a Keepalive from a session it still considers
    // un-ratcheted (its own reliability measure for a lost original
    // ServerHello / lost first post-ratchet confirmation packet). This eph_pub
    // is the one we just ratcheted against in the wait loop above, so any
    // later ServerHello carrying the SAME eph_pub is that resend, not a fresh
    // ratchet event — mirrors desktop client.rs's `ratcheted_server_eph_pub`.
    let mut ratcheted_server_eph_pub: Option<[u8; 32]> = Some(server_eph_pub);
    // Publish the server-assigned VPN IP for the platform's mismatch check
    // (see the ASSIGNED_VPN_IP doc comment: a pool re-home leaves the
    // key-embedded IP stale and the anti-spoof check kills all uplink data).
    if let Some(cfg) = server_network_cfg.as_ref() {
        ASSIGNED_VPN_IP.store(u32::from(cfg.client_ip), Ordering::Relaxed);
    }
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
    let mut transition_recv_keys: Option<SessionKeys> = Some(derive_session_keys(
        &dh,
        psk.as_ref(),
        &keypair.public_key_bytes(),
    ));
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
            mdh_len,
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
        // Real send timestamp — see the handshake keepalive comment above.
        let ka = ControlPayload::Keepalive {
            send_ts: crate::crypto::current_timestamp_ms(),
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
    // ratchet step). The platform polls this after the session
    // returns to decide whether to attribute a failure to this attempt's
    // mask family.
    EVER_CONNECTED.store(true, Ordering::Relaxed);
    // Stamp the session's connected-since (wall clock, same scope as the byte
    // counters) so the app's stopwatch survives UI relaunch/jetsam. Read only
    // by the iOS FFI today (`get_active_connected_since_ms`); stamped
    // unconditionally so Android gets the same tracking for free.
    session.connected_at_unix_ms.store(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        Ordering::Relaxed,
    );
    // Session start (post-handshake) — used to tell a working sticky mask (long
    // healthy session) from a throttled one (repeated short data stalls).
    let session_established = Instant::now();
    HANDSHAKE_FAIL_STREAK.store(0, Ordering::Relaxed);
    // H1: a disconnect that raced in while the handshake was completing must
    // not announce "ready" — the platform's stopVpn() has already rendered
    // DISCONNECTED and removed the foreground notification, so a late
    // onTunnelReady would flip the UI back to CONNECTED and re-post a zombie
    // ongoing notification for a session that is about to unwind.
    if session.stop_requested.load(Ordering::SeqCst) {
        return Ok(());
    }
    platform.notify_ready(&server_host);
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
            _ = wait_for_stop(&stop_signal) => {
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Stamp the real send time on each warmup keepalive (not 0):
                // the server acks every keepalive, and an ack with echo_ts=0
                // makes the RTT handler fall back to a stale timestamp, so
                // each warmup ack would otherwise measure 100..400 ms of fake
                // RTT and poison the quality EWMA right at session start —
                // mirrors desktop client.rs's `spawn_warmup_burst`.
                let send_ts = crate::crypto::current_timestamp_ms();
                if let Ok(ka) = (ControlPayload::Keepalive { send_ts }).encode() {
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

    // ── 6. Main forwarding loop ──
    let mut udp_buf = vec![0u8; crate::protocol::UDP_RECV_BUF_SIZE];
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
    let owned_tun_read = unsafe { OwnedFd::from_raw_fd(read_fd) };
    let tun_read = AsyncFd::new(owned_tun_read)?;

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

    // Reset the per-session adaptive hint so the platform getter reports
    // "no hint yet" (0 in the stored +1 encoding) for this session.
    ACTIVE_ADAPTIVE_LEVEL.store(0, Ordering::Relaxed);
    // NOTE: the per-session recording-feedback reset lives in each platform
    // adapter, since the static it clears (and its take-once vs. sequence
    // -counter semantics) is platform-owned. Nothing can publish feedback
    // before the handshake completes, so the adapters clear it up front.

    // Control-payload channel: lets the platform send RecordingStart/Stop
    // without reconnecting.
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
    // RAII guard: clears ACTIVE_CONTROL_TX when the session returns (any path).
    struct CtrlTxGuard;
    impl Drop for CtrlTxGuard {
        fn drop(&mut self) {
            let mut g = ACTIVE_CONTROL_TX.lock().unwrap_or_else(|e| e.into_inner());
            *g = None;
        }
    }
    let _ctrl_tx_guard = CtrlTxGuard;

    let initial_mask = resolve_sticky_handshake_mask(
        preferred_mask.as_deref(),
        &current_bootstrap_descriptors(),
        psk.as_ref(),
        handshake_fail_streak,
    );

    // (ATTEMPTED_MASK_FAMILY is published earlier, right after `handshake_mask`
    // resolves, so a handshake TIMEOUT is still attributed to the right family.
    // `initial_mask` resolves identically, so no second publish is needed here.)

    // §3 F: whether a `polymorphic:`-prefixed `MaskUpdate` has been observed,
    // set by the MaskUpdate arm in the receive loop below. Used to stop the
    // MaskPreference retry task early once the server's push is confirmed.
    let polymorphic_confirmed = Arc::new(AtomicBool::new(false));

    // §3 Polymorphic masks: ask the server to derive and push a per-session
    // perturbed variant of the requested base mask, riding on the confirmed
    // session keys — mirrors desktop client.rs's post-ratchet `MaskPreference`
    // send. Reliability (§3 F): a single lost MaskPreference packet would
    // silently disable polymorphic masks for the whole session, so resend via
    // the control channel (NOT a direct one-shot UDP send — this task outlives
    // the pre-upload-task window, and the upload task's encryptor owns the only
    // counter/keys safe to encrypt with once it starts) up to 5 times over ~5s,
    // stopping early once `MaskUpdate` with a `polymorphic:` mask id is
    // observed. The server side is idempotent (it skips re-pushing a MaskUpdate
    // when the session mask is already the derived variant), so a resend racing
    // an already-applied variant is harmless (mirrors desktop client.rs's
    // bounded retry task). The reply arrives as a normal MaskUpdate, handled by
    // the existing ControlPayload::MaskUpdate arm in the receive loop below.
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
                    // Receiver gone — the session returned; stop.
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
            }
        });
    }

    // §2 crowdsourced blocking feedback (opt-in, OFF by default). Mirrors
    // desktop's `record_mask_outcome` + `maybe_send_mask_feedback` (client.rs),
    // collapsed to a single-shot send since each session handles
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

        let mut enc = MobileEncryptor {
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
        let mut self_gate = crate::dpi_gate::ClientSelfGate::new(0.5, base_mask_id);
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
    // Post-freeze/suspend liveness probe state (see WAKE_GAP_THRESHOLD):
    // stamp of the previous watchdog tick (both clocks — see the gap
    // computation in the tick handler), and, when a gap was detected,
    // (deadline, armed_at, gap) of the pending probe.
    let mut last_watchdog_tick = Instant::now();
    let mut last_watchdog_wall = std::time::SystemTime::now();
    let mut wake_probe: Option<(Instant, Instant, Duration)> = None;

    loop {
        tokio::select! {
            biased;

            _ = wait_for_stop(&stop_signal) => {
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
                    Err(e) => {
                        // Abort both spawned tasks like every other exit path:
                        // `upload_sender_task` owns tun_rx/ctrl_rx and a socket
                        // clone, `tun_reader_task` a dup()'d TUN fd, so leaving
                        // them detached leaks a task + fd per failed session
                        // while the platform immediately reconnects.
                        tun_reader_task.abort();
                        upload_sender_task.abort();
                        return Err(Error::Io(e));
                    }
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
                        // Same reasoning as the UDP-recv error path: abort both
                        // tasks before propagating, or a TUN write failure
                        // (EIO/ENOBUFS from a torn-down VpnService /
                        // NEPacketTunnelProvider) leaks them across reconnects.
                        if let Err(e) = tun_async_write(&tun, &decoded.payload).await {
                            tun_reader_task.abort();
                            upload_sender_task.abort();
                            return Err(e.into());
                        }
                        session
                            .download_bytes
                            .fetch_add(decoded.payload.len() as u64, Ordering::Relaxed);
                        last_data_rx = Instant::now();
                        upload_at_last_data_rx =
                            session.upload_bytes.load(Ordering::Relaxed);
                        data_stall_started = None;
                        data_stall_strikes = 0;
                        if !data_plane_proven {
                            data_plane_proven = true;
                            // FIX (Jul 15): this mask just carried real DATA — record it
                            // as last-known-good so AUTO-mode reconnects reuse it instead
                            // of re-deriving (and hopping) from the churning bootstrap-
                            // descriptor set. See `resolve_sticky_handshake_mask`.
                            *LAST_GOOD_MASK.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(handshake_mask.clone());
                        }
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
                                        let new_keys = derive_session_keys(
                                            &dh,
                                            Some(&keys.session_key),
                                            &rekey_kp.public_key_bytes(),
                                        );
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
                                    // BUGFIX (2c): this used to gate the whole update on
                                    // `now_ms >= echo_ts` and silently drop the sample — not
                                    // just clamp the RTT — whenever that failed. Unlike a
                                    // desktop/server clock, a phone's wall clock
                                    // (`current_timestamp_ms()` is `SystemTime::now()`, not
                                    // monotonic) routinely steps backward mid-session: NTP/
                                    // carrier network-time correction, doze-exit clock
                                    // resync, or a user-visible time change. Any such step
                                    // between sending the keepalive and receiving its ack
                                    // made `now_ms < echo_ts` and threw the entire sample
                                    // away — repeat that on every keepalive for the rest of
                                    // the session (plausible once the clock has settled into
                                    // a state that keeps failing the check) and
                                    // ACTIVE_QUALITY_SCORE never leaves its initial 0, i.e.
                                    // the observed "quality stuck at 0/100". Desktop
                                    // client.rs never had this failure mode because its
                                    // equivalent handler already uses `saturating_sub` (see
                                    // its `KeepaliveAck` arm) instead of a drop-the-sample
                                    // guard — mirror that here for parity.
                                    // An RTT sample needs a usable echo; `saturating_sub`
                                    // (never a `now_ms >= echo_ts` guard) because a phone's
                                    // wall clock steps BACKWARD mid-session and the old
                                    // guard threw the sample away instead of clamping it.
                                    if echo_ts > 0 {
                                        let now_ms = crate::crypto::current_timestamp_ms();
                                        let rtt_us =
                                            now_ms.saturating_sub(echo_ts).saturating_mul(1_000);
                                        quality_tracker.record_rtt(rtt_us);
                                    }
                                    // Delivery accounting is UNCONDITIONAL: an ack with
                                    // echo_ts == 0 carries no RTT but is still proof the
                                    // packet arrived, so it must count for loss/jitter and
                                    // refresh the published score.
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
                                ControlPayload::AdaptiveHint { level } => {
                                    // +1 shift: 0 is reserved for "no hint yet", so a
                                    // server hint of Off(0) still reaches the platform
                                    // as a downgrade (see the static's doc comment).
                                    ACTIVE_ADAPTIVE_LEVEL.store(level.min(3) + 1, Ordering::Relaxed);
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
                                ControlPayload::RecordingAck { session_id, status } => {
                                    log::info!("aivpn: RecordingAck status={}", status);
                                    platform.publish_recording_feedback(
                                        RecordingFeedback::Ack { session_id, status },
                                    );
                                }
                                ControlPayload::RecordingComplete {
                                    service,
                                    mask_id,
                                    confidence,
                                } => {
                                    log::info!(
                                        "aivpn: RecordingComplete mask_id={} confidence={}",
                                        mask_id, confidence
                                    );
                                    platform.publish_recording_feedback(
                                        RecordingFeedback::Complete {
                                            service,
                                            mask_id,
                                            confidence,
                                        },
                                    );
                                }
                                ControlPayload::RecordingFailed { reason } => {
                                    log::warn!("aivpn: RecordingFailed reason={}", reason);
                                    platform.publish_recording_feedback(
                                        RecordingFeedback::Failed { reason },
                                    );
                                }
                                ControlPayload::RecordingStatus {
                                    can_record,
                                    active_service,
                                } => {
                                    log::info!(
                                        "aivpn: RecordingStatus can_record={} active_service={:?}",
                                        can_record, active_service
                                    );
                                    platform.publish_recording_feedback(
                                        RecordingFeedback::Status {
                                            can_record,
                                            active_service,
                                        },
                                    );
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
                                    // JSON so the platform mask picker renders a live list and
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
                                    // poll it after the session returns and persist
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
                                ControlPayload::MaskUpdate { mask_data, signature } => {
                                    // Transport-level check: verify the server's ed25519
                                    // signature over the raw `mask_data` bytes when a signing
                                    // key is configured — mirrors desktop client.rs's
                                    // `handle_server_control` (the server signs via
                                    // `sign_mask()` in session.rs). This authenticates that
                                    // THIS EXACT payload was pushed by the configured server.
                                    //
                                    // `None` = no signing key configured (can't check
                                    // transport auth either way); `Some(false)` = a key IS
                                    // configured and the signature failed to verify against
                                    // it, so the payload is dropped before even being decoded.
                                    let transport_verified: Option<bool> =
                                        server_signing_key.map(|signing_key| {
                                            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                                            match VerifyingKey::from_bytes(&signing_key) {
                                                Ok(vk) => {
                                                    let sig = Signature::from_bytes(&signature);
                                                    vk.verify(&mask_data, &sig).is_ok()
                                                }
                                                Err(_) => false,
                                            }
                                        });
                                    if transport_verified == Some(false) {
                                        log::warn!(
                                            "aivpn: MaskUpdate rejected: invalid ed25519 signature"
                                        );
                                    } else if let Some(mask) =
                                        crate::mimicry::decode_mask_update(&mask_data)
                                    {
                                        // R2 Phase B: shared artifact verification hook, now
                                        // fed the real operator pubkey/mode plumbed through the
                                        // JNI config surface (see `mask_operator_pubkey` /
                                        // `mask_verify_mode` params) — Android inherits the same
                                        // semantics as desktop's `verify_mask_artifact` call in
                                        // client.rs.
                                        //
                                        // SECURITY: derived variants (`polymorphic:`/
                                        // `bootstrap:` mask_id prefix) are exempt from the
                                        // artifact check ONLY when the transport-level ed25519
                                        // signature above has verified THIS EXACT payload —
                                        // never on the strength of the mask_id prefix string
                                        // alone, since mask_id is attacker-controlled (server-
                                        // sourced / MITM-able) content. Without a configured
                                        // signing key, `transport_verified` can never be
                                        // `Some(true)`, so every mask — derived or not — falls
                                        // through to the artifact check.
                                        let artifact_ok = (mask.is_derived_variant()
                                            && transport_verified == Some(true))
                                            || {
                                                let verdict = crate::mask::verify_mask_artifact(
                                                    &mask,
                                                    mask_operator_pubkey.as_ref(),
                                                    mask_verify_mode,
                                                );
                                                if !verdict.accept {
                                                    log::warn!("aivpn: MaskUpdate '{}' rejected: {:?}", mask.mask_id, verdict.detail);
                                                }
                                                verdict.accept
                                            };
                                        if artifact_ok {
                                            // §3 F: once a polymorphic variant lands, signal the
                                            // MaskPreference retry task to stop resending.
                                            if mask.mask_id.starts_with("polymorphic:") {
                                                polymorphic_confirmed
                                                    .store(true, Ordering::Relaxed);
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
                                ControlPayload::Shutdown { reason } => {
                                    // Server-initiated teardown — mirror desktop client.rs's
                                    // Shutdown handler: log it and end the session with an error so
                                    // the platform reconnect loop kicks in, the same
                                    // way any other unrecoverable server event does.
                                    log::info!("aivpn: server requested shutdown (reason: {})", reason);
                                    tun_reader_task.abort();
                                    upload_sender_task.abort();
                                    return Err(Error::Session(format!("server shutdown: {reason}")));
                                }
                                ControlPayload::HandshakeReject { reason } => {
                                    // 3f — authenticated, TERMINAL refusal. The server only ever
                                    // sends this to a peer that already proved PSK knowledge
                                    // during the handshake (see the doc comment on
                                    // `ControlPayload::HandshakeReject`), so — unlike a timeout
                                    // or a transient network error — retrying this exact
                                    // credential can never succeed. Record the reason for the
                                    // platform (see HANDSHAKE_REJECTED doc comment) BEFORE
                                    // returning, so `AivpnJni.handshakeRejectReason()` observes
                                    // it as soon as the tunnel call returns and the platform
                                    // reconnect loop can stop hammering instead of backing off
                                    // and retrying forever under the same rejected credential.
                                    log::warn!(
                                        "aivpn: HandshakeReject from server: reason={} — session terminal, not retrying this credential",
                                        reason
                                    );
                                    HANDSHAKE_REJECT_REASON.store(reason, Ordering::Relaxed);
                                    HANDSHAKE_REJECTED.store(true, Ordering::Relaxed);
                                    tun_reader_task.abort();
                                    upload_sender_task.abort();
                                    return Err(Error::Session(format!(
                                        "HandshakeReject: reason={reason}"
                                    )));
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
                                ControlPayload::ServerHello {
                                    server_eph_pub,
                                    signature,
                                    network_config,
                                } => {
                                    // MEDIUM-HIGH: the server resends ServerHello (instead of a
                                    // plain KeepaliveAck) whenever it gets a Keepalive from a
                                    // session it still considers un-ratcheted — its own
                                    // reliability measure for a lost original ServerHello / lost
                                    // first post-ratchet confirmation packet (gateway.rs).
                                    // Previously this fell through the wildcard arm below and was
                                    // silently dropped: we were correctly ratcheted, but the
                                    // server never learned that and kept resending until it gave
                                    // up on the session — stranding a healthy tunnel. Mirrors
                                    // desktop client.rs's unified ServerHello handler.
                                    if let Some(signing_key) = server_signing_key.as_ref() {
                                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                                        let verified = VerifyingKey::from_bytes(signing_key)
                                            .ok()
                                            .map(|vk| {
                                                let mut msg = Vec::with_capacity(64);
                                                msg.extend_from_slice(&server_eph_pub);
                                                msg.extend_from_slice(&keypair.public_key_bytes());
                                                let sig = Signature::from_bytes(&signature);
                                                vk.verify(&msg, &sig).is_ok()
                                            })
                                            .unwrap_or(false);
                                        if !verified {
                                            // Warn and IGNORE — never tear the session down.
                                            // This packet is unauthenticated by definition,
                                            // so ending the session here would hand any
                                            // off-path spoofer a one-datagram session kill
                                            // (a trivially reachable DoS). Dropping it costs
                                            // nothing: a genuine resend arrives again.
                                            log::warn!(
                                                "aivpn: mid-session ServerHello rejected: ed25519 signature verification failed — possible MITM attack, ignoring"
                                            );
                                            continue;
                                        }
                                    }

                                    let is_duplicate_hello =
                                        ratcheted_server_eph_pub == Some(server_eph_pub);
                                    if is_duplicate_hello {
                                        // A resend for an eph_pub we already ratcheted against.
                                        // Re-deriving here would use our already-ratcheted
                                        // session_key as PSK instead of the original pre-ratchet
                                        // key, permanently diverging from the server's (single)
                                        // ratchet — mirrors the desktop comment. The
                                        // confirmation prod below (sent on BOTH paths) is
                                        // exactly what clears the server's "un-ratcheted" flag.
                                        log::debug!(
                                            "aivpn: duplicate mid-session ServerHello for already-ratcheted eph_pub — re-confirming without re-ratcheting"
                                        );
                                    } else {
                                        log::info!(
                                            "aivpn: mid-session ServerHello — completing PFS ratchet"
                                        );
                                        match keypair.compute_shared(&server_eph_pub) {
                                            Ok(dh2) => {
                                                let ratcheted = derive_session_keys(
                                                    &dh2,
                                                    Some(&keys.session_key),
                                                    &keypair.public_key_bytes(),
                                                );
                                                // Keep accepting old inbound keys until the server
                                                // proves it has switched too. Same transition
                                                // parameters as the inline-KeyRotate rekey path
                                                // above: the full REKEY_TRANSITION_GRACE (the old
                                                // 2 s window expired before the server's first
                                                // retransmit could arrive), a hard re-arm ceiling,
                                                // and a CLONE of the recv window so the primary
                                                // keeps its `highest` counter across the switch.
                                                transition_recv_keys = Some(keys.clone());
                                                transition_recv_deadline =
                                                    Some(Instant::now() + REKEY_TRANSITION_GRACE);
                                                transition_grace_hard = Some(
                                                    Instant::now() + REKEY_TRANSITION_HARD_CAP,
                                                );
                                                transition_recv_win = recv_win.clone();
                                                keys = ratcheted;
                                                ratcheted_server_eph_pub = Some(server_eph_pub);
                                                recv_win.reset();
                                                // Publish to the upload task so outbound traffic
                                                // switches too. Unlike the initial handshake ratchet
                                                // (which starts the upload encryptor fresh at
                                                // counter 0), this goes through the key-rotate slot,
                                                // which keeps the send counter MONOTONIC by design
                                                // (see mimicry.rs's `update_keys` doc comment) rather
                                                // than resetting it — safe because the key changed,
                                                // so no (key, nonce) pair is ever reused.
                                                *key_rotate_slot
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner()) =
                                                    Some(keys.clone());
                                                log::info!("aivpn: mid-session PFS ratchet complete");
                                            }
                                            Err(e) => {
                                                log::warn!(
                                                    "aivpn: mid-session ServerHello DH failed: {e}"
                                                );
                                            }
                                        }
                                    }

                                    // Re-apply network_config the same way the pre-loop handler
                                    // does (ASSIGNED_VPN_IP for the pool re-home mismatch check,
                                    // keepalive interval for the NAT-safe/adaptive-level combo).
                                    if let Some(cfg) = network_config.as_ref() {
                                        ASSIGNED_VPN_IP.store(
                                            u32::from(cfg.client_ip),
                                            Ordering::Relaxed,
                                        );
                                        if let Some(ka) = cfg.keepalive_secs.filter(|&s| s > 0) {
                                            let requested = Duration::from_secs(ka as u64);
                                            let new_ka = if level == AdaptiveLevel::Off {
                                                requested
                                            } else {
                                                requested.min(Duration::from_secs(
                                                    level.keepalive_secs(),
                                                ))
                                            };
                                            keepalive_ms.store(
                                                new_ka.as_millis() as u64,
                                                Ordering::Relaxed,
                                            );
                                        }
                                    }

                                    // Prod the server with fresh confirmation traffic under
                                    // the (now) ratcheted keys so it observes the ratchet and
                                    // stops resending — sent on BOTH paths, duplicate or not:
                                    // the new-eph path needs the confirmation just as much as
                                    // the duplicate one, and skipping it there left the server
                                    // resending until it gave up on the session.
                                    let _ = ctrl_tx_recv_loop.try_send(ControlPayload::Keepalive {
                                        send_ts: crate::crypto::current_timestamp_ms(),
                                    });
                                }
                                ControlPayload::CertRejected {} => {
                                    // MEDIUM: server rejected our mTLS client certificate.
                                    // Previously this fell through the wildcard arm below and
                                    // was silently dropped — the tunnel kept "connecting" under
                                    // a certificate the server will never accept, retrying
                                    // forever with no signal to the user. Surface it via a
                                    // polled flag (see CERT_REJECTED doc comment) so the platform
                                    // layer can prompt re-provisioning instead of looping
                                    // silently (mirrors desktop client.rs's warning, plus the
                                    // mobile-specific UI callback surface desktop doesn't need).
                                    log::warn!(
                                        "aivpn: mTLS: server rejected the certificate — re-provision required"
                                    );
                                    CERT_REJECTED.store(true, Ordering::Relaxed);
                                }
                                ControlPayload::Capabilities { role, features } => {
                                    // P2.3: server-assigned role, sent once per
                                    // session after ratchet. `features` is reserved
                                    // (always 0 today) — mirrors desktop client.rs and
                                    // crate::mgmt::MgmtClient's own doc comment.
                                    log::debug!(
                                        "aivpn: Capabilities from server: role={} features={}",
                                        role, features
                                    );
                                    active_mgmt().on_capabilities(role);
                                }
                                ControlPayload::MgmtResponse {
                                    req_id,
                                    status,
                                    body,
                                } => {
                                    log::debug!(
                                        "aivpn: MgmtResponse req_id={} status={} body_len={}",
                                        req_id, status, body.len()
                                    );
                                    active_mgmt().on_mgmt_response(req_id, status, body);
                                }
                                ControlPayload::TimeSync { .. }
                                | ControlPayload::PoolSync { .. }
                                | ControlPayload::PoolStateDigest { .. }
                                | ControlPayload::PoolBucketDigests { .. }
                                | ControlPayload::RouteSync { .. }
                                | ControlPayload::ChainForward { .. }
                                | ControlPayload::PartitionAnnounce { .. }
                                | ControlPayload::NodeEnrollment { .. }
                                | ControlPayload::MgmtRequest { .. }
                                | ControlPayload::RecordingStatusRequest
                                | ControlPayload::RecordingStart { .. }
                                | ControlPayload::RecordingStop { .. } => {
                                    // Intentionally ignored on the mobile cores: pool-sync/
                                    // node-enrollment/mgmt-request/recording-admin family
                                    // this mobile core never participates in at all (not a
                                    // pool node or dialer, and admin-initiated recording is
                                    // desktop-only) — never sent NOR received here.
                                }
                                ControlPayload::Keepalive { .. }
                                | ControlPayload::ClientCert { .. }
                                | ControlPayload::DeviceEnrollment { .. }
                                | ControlPayload::QualityReport { .. }
                                | ControlPayload::MaskPreference { .. }
                                | ControlPayload::MaskFeedback { .. } => {
                                    // Intentionally ignored on the mobile cores: this core
                                    // only ever SENDS these to the server; there is no
                                    // inbound handling because the server never sends them
                                    // back.
                                }
                                ControlPayload::TelemetryRequest { .. }
                                | ControlPayload::TelemetryResponse { .. }
                                | ControlPayload::ControlAck { .. } => {
                                    // Intentionally ignored on the mobile cores: reserved
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
                    tun_reader_task.abort();
                    upload_sender_task.abort();
                    return Err(Error::Session(msg));
                }
            }

            // ── RX silence detector (proper interval, not recreated each iteration) ──
            _ = rx_check.tick() => {
                // Post-freeze/suspend liveness probe (see WAKE_GAP_THRESHOLD):
                // a tick gap ≫ RX_CHECK_INTERVAL means the process was frozen
                // (OEM freezer) or the device suspended. Arm a probe: unless
                // ANY decodable RX arrives within the window (keepalives fire
                // immediately after unfreeze), the session is condemned now
                // instead of lingering dead until RX_SILENCE.
                let tick_now = Instant::now();
                let wall_now = std::time::SystemTime::now();
                // Two clocks, because they miss different gaps: Instant
                // (CLOCK_MONOTONIC) keeps counting through an OEM process
                // freeze but STOPS during device suspend, while SystemTime
                // (wall clock) advances through suspend. Take the larger gap
                // so both a freeze and a deep-sleep suspend arm the probe.
                // A negative wall diff (NTP step back) is treated as 0.
                let mono_gap = tick_now.duration_since(last_watchdog_tick);
                let wall_gap = wall_now
                    .duration_since(last_watchdog_wall)
                    .unwrap_or(Duration::ZERO);
                let tick_gap = mono_gap.max(wall_gap);
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
                        tun_reader_task.abort();
                        upload_sender_task.abort();
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
                    tun_reader_task.abort();
                    upload_sender_task.abort();
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
                    upload_at_last_data_rx = uploaded_total;
                }

                // Absolute net: nothing decodable AT ALL (control included).
                let silence = last_rx.elapsed();
                if silence > RX_SILENCE {
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
