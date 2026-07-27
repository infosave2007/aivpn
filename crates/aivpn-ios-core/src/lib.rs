//! C FFI entry points for the iOS Network Extension (NEPacketTunnelProvider).
//!
//! The AivpnTunnel extension links against libaivpn_core.a (this crate compiled for
//! aarch64-apple-ios / x86_64-apple-ios-simulator) and calls these functions directly.

#![allow(non_snake_case)]

mod ios_tunnel;

use std::sync::atomic::Ordering;

use aivpn_common::mask::BootstrapDescriptor;
use aivpn_common::protocol::ControlPayload;
use ios_tunnel::{
    clear_pending_stop, get_active_connected_since_ms, get_active_download_bytes,
    get_active_upload_bytes, run_tunnel_ios, send_control_payload, stop_active_tunnel, OnReadyFn,
    RecordingFeedback, SendCtx, ACTIVE_ADAPTIVE_LEVEL, ACTIVE_FEEDBACK_INTERVAL,
    ACTIVE_FEEDBACK_THRESHOLD, ACTIVE_QUALITY_SCORE, ACTIVE_RECORDING_FEEDBACK,
    ACTIVE_REGIONAL_HINTS_JSON, ASSIGNED_VPN_IP, ATTEMPTED_MASK_FAMILY, EVER_CONNECTED,
    HANDSHAKE_FAIL_STREAK, MASK_FEEDBACK_SENT, RECORDING_FEEDBACK_SEQ, REGIONAL_HINTS_SEQ,
};

/// Runs the full VPN tunnel session on the calling thread.
/// Returns 0 on clean rekey-triggered exit, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn aivpn_run_tunnel(
    tun_fd: libc::c_int,
    server_host: *const libc::c_char,
    server_port: libc::c_int,
    server_key: *const u8,
    psk: *const u8,
    cert_bytes: *const u8,
    cert_len: libc::c_int,
    static_privkey: *const u8,
    static_privkey_len: libc::c_int,
    adaptive_level: libc::c_int,
    on_ready: Option<OnReadyFn>,
    ctx: *mut libc::c_void,
    // Optional 32-byte ed25519 verifying key used to authenticate the
    // server's ServerHello signature (mirrors desktop's
    // --server-signing-key). Pass NULL to skip verification — the same
    // opt-in behavior desktop has when no signing key is configured.
    server_signing_key: *const u8,
    // §3 Polymorphic masks: NUL-terminated base mask id (e.g. "webrtc_zoom_v3")
    // to request a per-session polymorphic variant of, or NULL to disable
    // (mirrors desktop's --polymorphic-base / ClientConfig::polymorphic_base).
    polymorphic_base: *const libc::c_char,
    // §2 crowdsourced blocking feedback — opt-in, OFF by default. Non-zero
    // enables reporting mask success/fail outcomes to the server (mirrors
    // desktop's ClientConfig::share_mask_feedback). No effect unless
    // `country_code` is also non-NULL.
    share_mask_feedback: libc::c_int,
    // §2 crowdsourced blocking feedback — opt-in, OFF by default. Non-zero
    // enables accepting RegionalMaskHints pushed by the server (mirrors
    // desktop's ClientConfig::receive_mask_hints).
    receive_mask_hints: libc::c_int,
    // NUL-terminated ISO-3166-1 alpha-2 country code (e.g. "US"), or NULL.
    // Parsed and validated as exactly 2 ASCII letters on the Rust side;
    // anything else is treated as not set (mirrors desktop's --country-code
    // validation in main.rs).
    country_code: *const libc::c_char,
    // §2 crowdsourced blocking feedback — NUL-terminated JSON array of prior
    // (unreported) mask outcomes the platform has persisted across earlier
    // failed/succeeded attempts, e.g.
    // `[{"mask_id":"quic_https","success":2,"fail":1}]`, or NULL/empty for
    // none. Merged with a success entry for THIS attempt's mask family and
    // reported as one `MaskFeedback` on success (mirrors desktop's
    // `MaskFeedbackLog::aggregate_unreported`; persistence itself lives in
    // the platform layer, not this standalone per-call Rust core). Malformed
    // JSON collapses to an empty batch — never an error.
    prior_outcomes_json: *const libc::c_char,
    // iOS mask-picker selection: NUL-terminated preset mask id (e.g.
    // "webrtc_zoom_v3"), or NULL/empty/"auto" for the PSK-derived bootstrap mask.
    // Mirrors Android's `preferred_mask` JNI argument; shapes the opening burst.
    preferred_mask: *const libc::c_char,
    // App-persisted signed bootstrap descriptors (NUL-terminated JSON array), or
    // NULL/empty for none. Loaded into the descriptor store before the handshake
    // so a cold-start first handshake can be shaped with a COVERT rotated
    // descriptor mask instead of a public preset. Mirrors Android's
    // `cachedDescriptorsJson`; persistence lives in the Swift App Group layer.
    cached_descriptors_json: *const libc::c_char,
    // R2 Phase B: operator's ed25519 mask-verifying public key (32 bytes), or
    // NULL to leave mask artifact verification unconfigured (mirrors
    // desktop's --mask-operator-pubkey / config-file / connection-key `mop`
    // field precedence — the Swift layer resolves which one wins before this
    // call). NULL means `verify_mask_artifact` sees `NoOperatorKey`, matching
    // desktop's own behavior with no operator key configured.
    mask_operator_pubkey: *const u8,
    // R2 Phase B: NUL-terminated verification mode string ("off"|"warn"|
    // "enforce", case-insensitive), or NULL/empty/unrecognized for the
    // default ("warn" — mirrors `MaskVerifyMode::default()`, the same
    // default desktop uses with no --mask-verify-mode/config override).
    mask_verify_mode: *const libc::c_char,
) -> libc::c_int {
    if server_host.is_null() || server_key.is_null() {
        return -1;
    }

    // SAFETY: server_host is a NUL-terminated C string from Swift.
    let host = unsafe {
        match std::ffi::CStr::from_ptr(server_host).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return -1,
        }
    };

    // SAFETY: server_key points to 32 bytes passed by Swift; null checked above.
    let key_bytes = unsafe {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(std::slice::from_raw_parts(server_key, 32));
        arr
    };

    let psk_opt: Option<[u8; 32]> = if psk.is_null() {
        None
    } else {
        // SAFETY: psk points to 32 bytes passed by Swift.
        let mut arr = [0u8; 32];
        unsafe { arr.copy_from_slice(std::slice::from_raw_parts(psk, 32)) };
        Some(arr)
    };

    let mtls_cert: Option<Vec<u8>> = if cert_bytes.is_null() || cert_len != 104 {
        None
    } else {
        // SAFETY: cert_bytes points to exactly 104 bytes confirmed above.
        Some(unsafe { std::slice::from_raw_parts(cert_bytes, 104).to_vec() })
    };

    let static_privkey_opt: Option<[u8; 32]> =
        if static_privkey.is_null() || static_privkey_len != 32 {
            None
        } else {
            // SAFETY: static_privkey_len == 32 verified above; pointer is non-null.
            let mut arr = [0u8; 32];
            unsafe { arr.copy_from_slice(std::slice::from_raw_parts(static_privkey, 32)) };
            Some(arr)
        };

    let server_signing_key_opt: Option<[u8; 32]> = if server_signing_key.is_null() {
        None
    } else {
        // SAFETY: server_signing_key points to 32 bytes passed by Swift.
        let mut arr = [0u8; 32];
        unsafe { arr.copy_from_slice(std::slice::from_raw_parts(server_signing_key, 32)) };
        Some(arr)
    };

    let polymorphic_base_opt: Option<String> = if polymorphic_base.is_null() {
        None
    } else {
        // SAFETY: polymorphic_base is a NUL-terminated C string from Swift.
        unsafe { std::ffi::CStr::from_ptr(polymorphic_base) }
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    // Validated exactly like desktop's `--country-code` handling in main.rs:
    // trim, require exactly 2 bytes, uppercase both. Anything else collapses
    // to `None` rather than erroring — the FFI boundary never panics.
    let country_code_opt: Option<[u8; 2]> = if country_code.is_null() {
        None
    } else {
        // SAFETY: country_code is a NUL-terminated C string from Swift.
        unsafe { std::ffi::CStr::from_ptr(country_code) }
            .to_str()
            .ok()
            .and_then(|s| {
                let b = s.trim().as_bytes();
                if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
                    Some([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
                } else {
                    None
                }
            })
    };

    let prior_outcomes_json_opt: Option<String> = if prior_outcomes_json.is_null() {
        None
    } else {
        // SAFETY: prior_outcomes_json is a NUL-terminated C string from Swift.
        unsafe { std::ffi::CStr::from_ptr(prior_outcomes_json) }
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    let preferred_mask_opt: Option<String> = if preferred_mask.is_null() {
        None
    } else {
        // SAFETY: preferred_mask is a NUL-terminated C string from Swift.
        unsafe { std::ffi::CStr::from_ptr(preferred_mask) }
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    let cached_descriptors_json_opt: Option<String> = if cached_descriptors_json.is_null() {
        None
    } else {
        // SAFETY: cached_descriptors_json is a NUL-terminated C string from Swift.
        unsafe { std::ffi::CStr::from_ptr(cached_descriptors_json) }
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    // R2 Phase B: mirrors server_signing_key_opt above — 32 raw bytes, no
    // encoding to worry about.
    let mask_operator_pubkey_opt: Option<[u8; 32]> = if mask_operator_pubkey.is_null() {
        None
    } else {
        // SAFETY: mask_operator_pubkey points to 32 bytes passed by Swift.
        let mut arr = [0u8; 32];
        unsafe { arr.copy_from_slice(std::slice::from_raw_parts(mask_operator_pubkey, 32)) };
        Some(arr)
    };

    // R2 Phase B: parse the mode string the same way desktop's
    // `MaskVerifyMode::from_str` does (off|warn|enforce, case-insensitive);
    // NULL/empty/unrecognized all collapse to the default (`Warn`) rather
    // than erroring — this FFI boundary must never fail closed on a typo.
    let mask_verify_mode_val: aivpn_common::mask::MaskVerifyMode = if mask_verify_mode.is_null() {
        aivpn_common::mask::MaskVerifyMode::default()
    } else {
        // SAFETY: mask_verify_mode is a NUL-terminated C string from Swift.
        unsafe { std::ffi::CStr::from_ptr(mask_verify_mode) }
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return -1,
    };

    // Catch any panic in the tunnel/decode path so it cannot unwind across the
    // extern "C" boundary and abort the whole Network Extension process — a
    // single malformed control message must fail only this one connection.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(run_tunnel_ios(
            tun_fd,
            host,
            server_port as u16,
            key_bytes,
            psk_opt,
            mtls_cert,
            on_ready,
            SendCtx(ctx),
            static_privkey_opt,
            adaptive_level.clamp(0, 3) as u8,
            server_signing_key_opt,
            polymorphic_base_opt,
            share_mask_feedback != 0,
            receive_mask_hints != 0,
            country_code_opt,
            prior_outcomes_json_opt,
            preferred_mask_opt,
            cached_descriptors_json_opt,
            mask_operator_pubkey_opt,
            mask_verify_mode_val,
        ))
    }));
    match outcome {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -1, // panic caught — do not unwind into Swift
    }
}

/// Close the active UDP socket so the tunnel loop exits immediately.
#[no_mangle]
pub extern "C" fn aivpn_stop_tunnel() {
    stop_active_tunnel();
}

/// Clear a stop that arrived while no session was active (STOP_PENDING), so an
/// intentional new connection is not immediately stopped by a stale flag. Call
/// from the Swift reconnect/restart path right before starting a new tunnel
/// (mirrors Android's clearPendingStop JNI export).
#[no_mangle]
pub extern "C" fn aivpn_clear_pending_stop() {
    clear_pending_stop();
}

/// Total bytes sent to the server in the current session.
#[no_mangle]
pub extern "C" fn aivpn_get_upload_bytes() -> i64 {
    get_active_upload_bytes() as i64
}

/// Total bytes received from the server in the current session.
#[no_mangle]
pub extern "C" fn aivpn_get_download_bytes() -> i64 {
    get_active_download_bytes() as i64
}

/// Wall-clock epoch milliseconds at which the current session became
/// established, or 0 when no session is active. Same session scope as the
/// byte counters, so the UI stopwatch can never desync from them.
#[no_mangle]
pub extern "C" fn aivpn_get_connected_since_ms() -> i64 {
    get_active_connected_since_ms() as i64
}

/// Current connection quality score (0–100). Returns 0 when no session is active.
#[no_mangle]
pub extern "C" fn aivpn_get_quality_score() -> libc::c_int {
    ACTIVE_QUALITY_SCORE.load(Ordering::Relaxed) as libc::c_int
}

/// Most recent AdaptiveHint level received from the server (0–3).
#[no_mangle]
pub extern "C" fn aivpn_get_adaptive_level_hint() -> libc::c_int {
    ACTIVE_ADAPTIVE_LEVEL.load(Ordering::Relaxed) as libc::c_int
}

/// VPN IPv4 the server assigned to this session in its ServerHello network
/// config, as a host-order u32 (e.g. 10.0.0.3 = 0x0A000003), or 0 when the
/// current session has not received one. When it differs from the
/// connection-key IP the server re-homed this client (pool IP-collision
/// resolution) and the tunnel network settings must be re-applied with this
/// address — otherwise the server's anti-spoof check silently drops all
/// uplink data while keepalives keep flowing.
#[no_mangle]
pub extern "C" fn aivpn_get_assigned_vpn_ip() -> libc::c_uint {
    ASSIGNED_VPN_IP.load(Ordering::Relaxed) as libc::c_uint
}

/// Seed the process-global consecutive handshake-fail streak from a
/// platform-persisted value. The streak drives the descriptor→builtin-preset
/// fallback at `HANDSHAKE_FALLBACK_THRESHOLD`; it lives in a process-global
/// static, but iOS tears the Network Extension process down between failed
/// starts, so without re-seeding it the threshold could never be reached and
/// a poisoned cached descriptor would block connecting until it expires.
/// Call ONCE per extension process, before the first `aivpn_run_tunnel`
/// attempt, with the value previously read via
/// `aivpn_get_handshake_fail_streak` and persisted per server (App Group).
/// Clamped to a sane bound so a corrupted persisted value cannot wedge the
/// counter near overflow.
#[no_mangle]
pub extern "C" fn aivpn_seed_handshake_fail_streak(streak: libc::c_uint) {
    HANDSHAKE_FAIL_STREAK.store(streak.min(1_000), Ordering::Relaxed);
}

/// Current consecutive handshake-fail streak (see
/// `aivpn_seed_handshake_fail_streak`). Read after each `aivpn_run_tunnel`
/// return and persist per server; reset to 0 internally when a session's PFS
/// ratchet completes and when the server key changes.
#[no_mangle]
pub extern "C" fn aivpn_get_handshake_fail_streak() -> libc::c_uint {
    HANDSHAKE_FAIL_STREAK.load(Ordering::Relaxed)
}

/// §2 crowdsourced blocking feedback — whether the most recently completed
/// `aivpn_run_tunnel` call ever reached a connected (post-handshake, PFS
/// ratchet complete) state. The platform should read this immediately after
/// the call returns: `0` means the attempt never connected, so the platform
/// should count it toward `aivpn_get_feedback_threshold()` consecutive
/// failures for `aivpn_get_attempted_mask_family()` (mirrors desktop
/// main.rs's `client.ever_connected()` check in the reconnect loop).
#[no_mangle]
pub extern "C" fn aivpn_ever_connected() -> libc::c_int {
    EVER_CONNECTED.load(Ordering::Relaxed) as libc::c_int
}

/// Whether the server sent `CertRejected` (mTLS certificate rejected) during
/// the most recently completed `aivpn_run_tunnel` call. `0` = not rejected
/// (or no mTLS cert was configured). The platform should poll this alongside
/// `get_traffic` and, when `1`, prompt the user to re-provision their mTLS
/// cert instead of silently retrying forever — desktop only logs this
/// server-pushed signal (client.rs); mobile has no console the user will
/// ever see it in.
#[no_mangle]
pub extern "C" fn aivpn_cert_was_rejected() -> libc::c_int {
    crate::ios_tunnel::CERT_REJECTED.load(Ordering::Relaxed) as libc::c_int
}

/// Whether the server sent `HandshakeReject` — an AEAD-authenticated,
/// handshake-time refusal sent only to a peer that already proved knowledge
/// of the PSK — during the most recently completed `aivpn_run_tunnel` call.
/// `0` = not rejected. Unlike a timeout or a transient disconnect, this is a
/// TERMINAL refusal: the platform must stop its reconnect loop instead of
/// retrying (see `aivpn_get_handshake_reject_reason` for why).
#[no_mangle]
pub extern "C" fn aivpn_handshake_was_rejected() -> libc::c_int {
    crate::ios_tunnel::HANDSHAKE_REJECTED.load(Ordering::Relaxed) as libc::c_int
}

/// Reason code for the most recent `HandshakeReject` (only meaningful when
/// `aivpn_handshake_was_rejected` returns non-zero). `0` = unspecified,
/// `1` = one-time key already used, `2` = client expired, `3` = client
/// disabled — matches `ControlPayload::HandshakeReject`'s `reason` field in
/// aivpn-common's protocol.rs.
#[no_mangle]
pub extern "C" fn aivpn_get_handshake_reject_reason() -> libc::c_int {
    crate::ios_tunnel::HANDSHAKE_REJECT_REASON.load(Ordering::Relaxed) as libc::c_int
}

/// §2 crowdsourced blocking feedback — whether a `MaskFeedback` control
/// message was actually sent during the most recently completed
/// `aivpn_run_tunnel` call (a share send or a hints-only probe). The platform
/// uses this to decide whether to clear its persisted outcome buffer and
/// record a new `last_report_unix` (mirrors desktop's
/// `MaskFeedbackLog::mark_reported`, called after a successful send).
#[no_mangle]
pub extern "C" fn aivpn_mask_feedback_sent() -> libc::c_int {
    MASK_FEEDBACK_SENT.load(Ordering::Relaxed) as libc::c_int
}

/// §2 crowdsourced blocking feedback — server-pushed
/// `FeedbackConfig.report_failure_threshold` received during the most
/// recently completed `aivpn_run_tunnel` call. Returns `0` if no
/// `FeedbackConfig` was received this session — the platform should keep
/// whichever value it had previously persisted (defaulting to 3 if none).
#[no_mangle]
pub extern "C" fn aivpn_get_feedback_threshold() -> libc::c_int {
    ACTIVE_FEEDBACK_THRESHOLD.load(Ordering::Relaxed) as libc::c_int
}

/// §2 crowdsourced blocking feedback — server-pushed
/// `FeedbackConfig.report_interval_secs` received during the most recently
/// completed `aivpn_run_tunnel` call. Returns `0` if no `FeedbackConfig` was
/// received this session — the platform should keep whichever value it had
/// previously persisted (defaulting to 3600 if none).
#[no_mangle]
pub extern "C" fn aivpn_get_feedback_interval_secs() -> i64 {
    ACTIVE_FEEDBACK_INTERVAL.load(Ordering::Relaxed) as i64
}

/// §2 crowdsourced blocking feedback — copies the base mask family (already
/// normalized via `base_mask_family`, e.g. `"webrtc_zoom_v3"`) that the most
/// recently completed `aivpn_run_tunnel` call attempted, into `buf` as a
/// NUL-terminated UTF-8 string, truncated to fit. Set as soon as the mask is
/// chosen — before the handshake — so it is populated even when the attempt
/// never reaches `aivpn_ever_connected()`. Needed because mask selection
/// (including the `AIVPN_PREFERRED_MASK=auto` PSK-derived pick) happens
/// inside this one-shot call; the platform has no other way to learn which
/// family a failed "auto" attempt used.
///
/// Returns the number of bytes written excluding the NUL terminator, or -1 if
/// `buf` is NULL, `buf_len` <= 0, or no attempt has run yet.
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aivpn_get_attempted_mask_family(
    buf: *mut libc::c_char,
    buf_len: libc::c_int,
) -> libc::c_int {
    copy_string_getter(
        ATTEMPTED_MASK_FAMILY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref(),
        buf,
        buf_len,
    )
}

/// §2 crowdsourced blocking feedback — monotonically increasing counter,
/// bumped each time a new `RegionalMaskHints` message is received (only when
/// `receive_mask_hints` was enabled for that call). Compare against the
/// last-seen value before re-reading via `aivpn_get_regional_hints_json`.
#[no_mangle]
pub extern "C" fn aivpn_get_regional_hints_seq() -> i64 {
    REGIONAL_HINTS_SEQ.load(Ordering::Relaxed) as i64
}

/// §2 crowdsourced blocking feedback — copies the most recently received
/// `RegionalMaskHints` as a JSON object
/// (`{"country_code":"US","masks":[["webrtc_zoom_v3",0.87],...]}`) into `buf`
/// as a NUL-terminated UTF-8 string, truncated to fit. The platform should
/// persist this per-region and use it to softly bias mask selection
/// (`AIVPN_PREFERRED_MASK`) on the next reconnect attempt, never overriding
/// an explicit user mask choice (mirrors desktop's `HINT_BIAS_MIN_SCORE`
/// gate in main.rs).
///
/// Returns the number of bytes written excluding the NUL terminator, or -1 if
/// `buf` is NULL, `buf_len` <= 0, or no hints have been received yet.
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aivpn_get_regional_hints_json(
    buf: *mut libc::c_char,
    buf_len: libc::c_int,
) -> libc::c_int {
    copy_string_getter(
        ACTIVE_REGIONAL_HINTS_JSON
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref(),
        buf,
        buf_len,
    )
}

/// Monotonic counter bumped each time a fresh `MaskCatalog` is received from the
/// server. Swift compares this against its last-seen value to detect a new mask
/// list before re-reading `aivpn_get_mask_catalog_json`.
#[no_mangle]
pub extern "C" fn aivpn_get_mask_catalog_seq() -> i64 {
    crate::ios_tunnel::MASK_CATALOG_SEQ.load(Ordering::Relaxed) as i64
}

/// Copies the most recent `MaskCatalog` as a JSON array
/// (`[{"mask_id":"auto_quic_v1","label":"QUIC","generated":true},...]`) into
/// `buf` as a NUL-terminated UTF-8 string, truncated to fit. The SwiftUI Picker
/// renders this list and appends "(авто)" to entries with `generated:true`.
///
/// Returns bytes written excluding the NUL, or -1 if `buf` is NULL,
/// `buf_len` <= 0, or no catalog has been received yet.
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aivpn_get_mask_catalog_json(
    buf: *mut libc::c_char,
    buf_len: libc::c_int,
) -> libc::c_int {
    copy_string_getter(
        crate::ios_tunnel::ACTIVE_MASK_CATALOG_JSON
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref(),
        buf,
        buf_len,
    )
}

/// Copies the currently-stored bootstrap descriptors as a JSON array into `buf`
/// as a NUL-terminated UTF-8 string, truncated to fit. Swift persists this into
/// the shared App Group so the very next COLD START can pass it back into
/// `aivpn_run_tunnel(cached_descriptors_json=…)` and shape its first handshake
/// with a COVERT rotated descriptor mask instead of a public preset. The blobs
/// are ed25519-signed and self-authenticating and are re-verified on load.
///
/// Poll after `aivpn_run_tunnel` returns — the descriptor store is
/// process-global and survives the call. Returns bytes written excluding the
/// NUL, or -1 if `buf` is NULL or `buf_len` <= 0. Writes `"[]"` when the store
/// is empty (never returns -1 solely because no descriptor has arrived).
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aivpn_get_bootstrap_descriptors_json(
    buf: *mut libc::c_char,
    buf_len: libc::c_int,
) -> libc::c_int {
    let json = crate::ios_tunnel::bootstrap_descriptors_json();
    copy_string_getter(Some(json.as_str()), buf, buf_len)
}

/// Shared helper for the `Option<String>`-backed string getters above:
/// copies `value` (if any) into `buf` as a NUL-terminated UTF-8 string,
/// truncated to fit. Returns the number of bytes written excluding the NUL
/// terminator, or -1 if `buf` is NULL, `buf_len` <= 0, or `value` is `None`.
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes.
unsafe fn copy_string_getter(
    value: Option<&str>,
    buf: *mut libc::c_char,
    buf_len: libc::c_int,
) -> libc::c_int {
    if buf.is_null() || buf_len <= 0 {
        return -1;
    }
    let Some(s) = value else {
        return -1;
    };
    let bytes = s.as_bytes();
    let cap = (buf_len as usize).saturating_sub(1);
    let n = bytes.len().min(cap);
    // SAFETY: caller guarantees `buf` points to `buf_len` writable bytes
    // (checked non-null and > 0 above); `n <= buf_len - 1`, so writing `n`
    // bytes followed by a NUL at offset `n` stays within `buf_len` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
        *buf.add(n) = 0;
    }
    n as libc::c_int
}

/// Monotonically increasing counter, bumped each time new mask-recording
/// feedback (RecordingAck/RecordingComplete/RecordingFailed/RecordingStatus)
/// arrives from the server. Swift should compare this against the
/// last-seen value to detect a fresh message before re-reading
/// kind/confidence/message, rather than reacting to a stale value on every
/// poll tick.
#[no_mangle]
pub extern "C" fn aivpn_get_recording_feedback_seq() -> i64 {
    RECORDING_FEEDBACK_SEQ.load(Ordering::Relaxed) as i64
}

/// Kind of the most recent mask-recording feedback message received from the
/// server. 0 = none received yet, 1 = RecordingAck, 2 = RecordingComplete,
/// 3 = RecordingFailed, 4 = RecordingStatus.
#[no_mangle]
pub extern "C" fn aivpn_get_recording_feedback_kind() -> libc::c_int {
    let guard = ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        None => 0,
        Some(RecordingFeedback::Ack { .. }) => 1,
        Some(RecordingFeedback::Complete { .. }) => 2,
        Some(RecordingFeedback::Failed { .. }) => 3,
        Some(RecordingFeedback::Status { .. }) => 4,
    }
}

/// Confidence score (0.0-1.0) from the most recent RecordingComplete message.
/// Returns 0.0 if the current feedback is not a RecordingComplete.
#[no_mangle]
pub extern "C" fn aivpn_get_recording_confidence() -> f32 {
    let guard = ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(RecordingFeedback::Complete { confidence, .. }) => *confidence,
        _ => 0.0,
    }
}

/// Whether the current authenticated session may record masks, from the most
/// recent RecordingStatus message. Returns 0 (false) if no RecordingStatus
/// has been received yet.
#[no_mangle]
pub extern "C" fn aivpn_recording_can_record() -> libc::c_int {
    let guard = ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(RecordingFeedback::Status { can_record, .. }) => *can_record as libc::c_int,
        _ => 0,
    }
}

/// Copies the 16-byte recording session id from the most recent RecordingAck
/// message into `out16`. Returns 1 if the current feedback is a
/// RecordingAck (buffer populated), 0 otherwise (buffer left untouched).
///
/// # Safety
/// `out16` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aivpn_get_recording_session_id(out16: *mut u8) -> libc::c_int {
    if out16.is_null() {
        return 0;
    }
    let guard = ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(RecordingFeedback::Ack { session_id, .. }) => {
            // SAFETY: caller guarantees out16 points to 16 writable bytes;
            // session_id is always exactly 16 bytes.
            unsafe { std::ptr::copy_nonoverlapping(session_id.as_ptr(), out16, 16) };
            1
        }
        _ => 0,
    }
}

/// Copies the service name associated with the most recent recording
/// feedback into `buf` as a NUL-terminated UTF-8 string, truncated to fit:
/// the service that finished recording (RecordingComplete), or the service
/// currently being recorded, if any (RecordingStatus). Returns an empty
/// string (and 0) for RecordingAck/RecordingFailed.
///
/// Returns the number of bytes written excluding the NUL terminator, or -1
/// if `buf` is NULL, `buf_len` <= 0, or no feedback has been received yet.
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aivpn_get_recording_service(
    buf: *mut libc::c_char,
    buf_len: libc::c_int,
) -> libc::c_int {
    if buf.is_null() || buf_len <= 0 {
        return -1;
    }
    let guard = ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let svc: String = match guard.as_ref() {
        Some(RecordingFeedback::Complete { service, .. }) => service.clone(),
        Some(RecordingFeedback::Status { active_service, .. }) => {
            active_service.clone().unwrap_or_default()
        }
        Some(RecordingFeedback::Ack { .. }) | Some(RecordingFeedback::Failed { .. }) => {
            String::new()
        }
        None => return -1,
    };
    drop(guard);

    let bytes = svc.as_bytes();
    let cap = (buf_len as usize).saturating_sub(1);
    let n = bytes.len().min(cap);
    // SAFETY: caller guarantees `buf` points to `buf_len` writable bytes
    // (checked non-null and > 0 above); `n <= buf_len - 1`, so writing `n`
    // bytes followed by a NUL at offset `n` stays within `buf_len` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
        *buf.add(n) = 0;
    }
    n as libc::c_int
}

/// Copies a human-readable message for the most recent recording feedback
/// into `buf` as a NUL-terminated UTF-8 string, truncated to fit:
/// - RecordingAck      -> the status string ("started", "analyzing", ...)
/// - RecordingComplete -> the mask_id
/// - RecordingFailed   -> the failure reason
/// - RecordingStatus   -> the active_service name, or an empty string if None
///
/// Returns the number of bytes written excluding the NUL terminator, or -1
/// if `buf` is NULL, `buf_len` <= 0, or no feedback has been received yet.
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes, valid for the
/// duration of this call.
#[no_mangle]
pub unsafe extern "C" fn aivpn_get_recording_message(
    buf: *mut libc::c_char,
    buf_len: libc::c_int,
) -> libc::c_int {
    if buf.is_null() || buf_len <= 0 {
        return -1;
    }
    let guard = ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let msg: String = match guard.as_ref() {
        Some(RecordingFeedback::Ack { status, .. }) => status.clone(),
        Some(RecordingFeedback::Complete { mask_id, .. }) => mask_id.clone(),
        Some(RecordingFeedback::Failed { reason }) => reason.clone(),
        Some(RecordingFeedback::Status { active_service, .. }) => {
            active_service.clone().unwrap_or_default()
        }
        None => return -1,
    };
    drop(guard);

    let bytes = msg.as_bytes();
    let cap = (buf_len as usize).saturating_sub(1); // reserve room for the NUL terminator
    let n = bytes.len().min(cap);
    // SAFETY: caller guarantees `buf` points to `buf_len` writable bytes
    // (checked non-null and > 0 above); `n <= buf_len - 1`, so writing `n`
    // bytes followed by a NUL at offset `n` stays within `buf_len` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
        *buf.add(n) = 0;
    }
    n as libc::c_int
}

/// Send a RecordingStart control payload to the active tunnel.
/// Returns 1 on success, 0 if no tunnel is active or `service` is NULL.
#[no_mangle]
pub unsafe extern "C" fn aivpn_start_recording(service: *const libc::c_char) -> libc::c_int {
    if service.is_null() {
        return 0;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(service) }
        .to_string_lossy()
        .chars()
        .take(128)
        .collect::<String>();
    send_control_payload(ControlPayload::RecordingStart { service: s }) as libc::c_int
}

/// Send a RecordingStop control payload to the active tunnel.
#[no_mangle]
pub extern "C" fn aivpn_stop_recording() {
    send_control_payload(ControlPayload::RecordingStop {
        session_id: [0u8; 16],
    });
}

/// Verify a bootstrap descriptor fetched by the iOS *app* process's
/// multi-channel discovery flow (see `BootstrapDiscovery.swift`).
///
/// Unlike every other function in this file, this one is called from the
/// main app, not the tunnel extension — bootstrap discovery deliberately
/// happens outside the `NEPacketTunnelProvider` so a slow/racing HTTP fetch
/// can never delay tunnel startup. It has no dependency on any active
/// tunnel/session state, so it is safe to call at any time, from any thread.
///
/// Reuses `aivpn_common::mask::BootstrapDescriptor::verify_signature` — the
/// same ed25519 verification already used for descriptors received over an
/// established session — instead of reimplementing crypto in Swift.
///
/// # Parameters
/// - `descriptor_json_ptr` / `descriptor_json_len`: a single JSON-encoded
///   `BootstrapDescriptor` object (NOT a JSON array — the fetched channel
///   payload is a `Vec<BootstrapDescriptor>`; callers must iterate and call
///   this once per element).
/// - `signing_pubkey_ptr`: pointer to exactly 32 bytes, the operator's
///   ed25519 verifying key (the same key an operator would pass in the CLI
///   client as `--server-signing-key`).
///
/// # Returns
/// `1` if the descriptor's JSON parses, it is not expired (checked against
/// device wall-clock time), and its signature verifies against
/// `signing_pubkey_ptr`. `0` for any failure — malformed JSON, null/invalid
/// pointers, an invalid public key, an invalid signature, or an
/// expired/not-yet-valid descriptor. Never panics across the FFI boundary.
///
/// # Safety
/// `descriptor_json_ptr` must point to `descriptor_json_len` readable bytes
/// and `signing_pubkey_ptr` must point to 32 readable bytes; both need only
/// remain valid for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn aivpn_verify_bootstrap_descriptor(
    descriptor_json_ptr: *const u8,
    descriptor_json_len: usize,
    signing_pubkey_ptr: *const u8,
) -> libc::c_int {
    if descriptor_json_ptr.is_null() || signing_pubkey_ptr.is_null() || descriptor_json_len == 0 {
        return 0;
    }

    // SAFETY: caller (Swift) guarantees descriptor_json_ptr points to
    // descriptor_json_len readable bytes and signing_pubkey_ptr points to 32
    // readable bytes for the duration of this call. Data is copied into owned
    // buffers immediately so nothing borrows the raw pointers past this point.
    let json_bytes =
        unsafe { std::slice::from_raw_parts(descriptor_json_ptr, descriptor_json_len) }.to_vec();
    let mut pubkey = [0u8; 32];
    unsafe {
        pubkey.copy_from_slice(std::slice::from_raw_parts(signing_pubkey_ptr, 32));
    }

    // Extra safety net on top of the already-panic-free logic below: a
    // malformed/adversarial descriptor must never be able to crash the host
    // app via an FFI-boundary panic.
    match std::panic::catch_unwind(move || verify_bootstrap_descriptor_bytes(&json_bytes, &pubkey))
    {
        Ok(true) => 1,
        _ => 0,
    }
}

/// Current server-assigned role (0=User, 1=Viewer, 2=Admin) cached from the
/// most recent `Capabilities` control message this session, or 0 (User)
/// before one has arrived. Backed by the shared `MgmtClient` in
/// `ios_tunnel`, reset at the start of each `aivpn_run_tunnel` attempt.
#[no_mangle]
pub extern "C" fn aivpn_get_role() -> u8 {
    crate::ios_tunnel::active_mgmt().cached_role()
}

/// Issue an in-tunnel management API call (Phase A in-app admin) and block
/// until the correlated response arrives or `path` — a curated REST-shaped
/// path (e.g. "/api/v1/clients") — this call times out (10s).
///
/// `method`: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT. `body`/`body_len` is an
/// optional JSON request payload (pass NULL/0 for none).
///
/// Blocking convention: the async `MgmtClient::mgmt_call` response is
/// awaited by spinning up a private single-thread Tokio runtime local to
/// this call and calling `block_on` on it — NOT the tunnel's own runtime.
/// The `MgmtRequest` is sent over the tunnel's control channel and the
/// matching `MgmtResponse` resolves the shared `MgmtClient`'s oneshot from
/// the tunnel's own task; this call's private runtime only drives the
/// `mgmt_call` future itself (the timeout timer + awaiting that oneshot),
/// so blocking a synchronous FFI thread here never blocks the tunnel.
///
/// Response-buffer convention (shared with `aivpn_qr_png`): on success,
/// `*out_status` receives the response status code and the return value is
/// the number of response-body bytes written into `out_buf`. If the
/// response body is larger than `out_cap`, `out_buf` is left untouched and
/// the return value is the *needed* length instead — always `> out_cap` in
/// that case, so the caller distinguishes "written N bytes" from "need a
/// bigger buffer" by comparing the return value against the `out_cap` it
/// passed in, then retries with a buffer of at least that size. Returns -1
/// on any error: NULL/invalid `path`, no active tunnel session, the control
/// channel is closed, or the call times out awaiting a response.
///
/// # Safety
/// `path` must be a NUL-terminated, valid-UTF-8 C string. `body` (if
/// non-NULL) must point to at least `body_len` readable bytes. `out_status`
/// must point to a writable `u16`. `out_buf` must point to at least
/// `out_cap` writable bytes (may be NULL only if `out_cap` is 0).
#[no_mangle]
pub unsafe extern "C" fn aivpn_mgmt_request(
    method: u8,
    path: *const libc::c_char,
    body: *const u8,
    body_len: usize,
    out_status: *mut u16,
    out_buf: *mut u8,
    out_cap: usize,
) -> isize {
    if path.is_null() || out_status.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees `path` is a NUL-terminated C string valid for
    // the duration of this call.
    let path_str = match unsafe { std::ffi::CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // SAFETY: caller guarantees `body` points to `body_len` readable bytes
    // when non-NULL; copied into an owned Vec immediately.
    let body_vec: Vec<u8> = if body.is_null() || body_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(body, body_len) }.to_vec()
    };

    let Some(control_tx) = crate::ios_tunnel::active_control_tx() else {
        return -1; // not connected
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return -1,
    };

    let result = rt.block_on(crate::ios_tunnel::active_mgmt().mgmt_call(
        &control_tx,
        method,
        path_str,
        body_vec,
        std::time::Duration::from_secs(10),
    ));

    match result {
        Ok((status, resp_body)) => {
            // SAFETY: caller guarantees out_status points to a writable u16.
            unsafe {
                *out_status = status;
            }
            unsafe { copy_bytes_getter(&resp_body, out_buf, out_cap) }
        }
        Err(_) => -1,
    }
}

/// Render `text` (typically an `aivpn://...` connection key) as a QR code
/// PNG and copy the encoded bytes into `out_buf`.
///
/// Uses the same written-len-or-needed-len buffer convention as
/// `aivpn_mgmt_request` (see its doc comment): the return value is the
/// number of PNG bytes written when `out_cap` was large enough, or the
/// needed length (always `> out_cap`, `out_buf` left untouched) otherwise.
/// Returns -1 if `text` is NULL/not valid UTF-8/empty, or PNG encoding
/// fails.
///
/// # Safety
/// `text` must be a NUL-terminated, valid-UTF-8 C string. `out_buf` must
/// point to at least `out_cap` writable bytes (may be NULL only if
/// `out_cap` is 0).
#[no_mangle]
pub unsafe extern "C" fn aivpn_qr_png(
    text: *const libc::c_char,
    out_buf: *mut u8,
    out_cap: usize,
) -> isize {
    if text.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees `text` is a NUL-terminated C string valid for
    // the duration of this call.
    let text_str = match unsafe { std::ffi::CStr::from_ptr(text) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match aivpn_common::qr::png_for(text_str) {
        Ok(bytes) => unsafe { copy_bytes_getter(&bytes, out_buf, out_cap) },
        Err(_) => -1,
    }
}

/// Shared helper for raw-byte FFI getters that use the
/// written-len-or-needed-len convention (see `aivpn_mgmt_request` /
/// `aivpn_qr_png` doc comments): if `data` fits in `out_cap` bytes, copies
/// it into `out_buf` and returns `data.len()` (always `<= out_cap`, so
/// unambiguous "bytes written"); otherwise leaves `out_buf` untouched and
/// returns `data.len()` anyway (in this branch always `> out_cap`, so the
/// caller recognizes it as "needed length, retry with a bigger buffer").
/// Never returns a negative value; NULL `out_buf` is only tolerated when
/// nothing needs to be written (`out_cap` too small, or `data` empty).
///
/// # Safety
/// `out_buf` must point to at least `out_cap` writable bytes whenever a
/// non-empty copy is about to happen (i.e. whenever this returns a value
/// `<= out_cap` and `data` is non-empty).
unsafe fn copy_bytes_getter(data: &[u8], out_buf: *mut u8, out_cap: usize) -> isize {
    if data.len() > out_cap {
        return data.len() as isize;
    }
    if !data.is_empty() {
        if out_buf.is_null() {
            return -1;
        }
        // SAFETY: caller guarantees out_buf points to out_cap writable bytes
        // when a copy is needed; data.len() <= out_cap was just checked.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, data.len());
        }
    }
    data.len() as isize
}

/// Pure, allocation-owning verification helper with no raw pointers, so it's
/// trivially testable and `UnwindSafe`. Parses `json` as a single
/// `BootstrapDescriptor`, rejects it if expired/not-yet-valid, then checks
/// its ed25519 signature against `pubkey`. Any parse or verification failure
/// collapses to `false` — never panics.
fn verify_bootstrap_descriptor_bytes(json: &[u8], pubkey: &[u8; 32]) -> bool {
    let descriptor: BootstrapDescriptor = match serde_json::from_slice(json) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let now = aivpn_common::mask::current_unix_secs();
    if !descriptor.is_valid_at(now) {
        return false;
    }
    matches!(descriptor.verify_signature(pubkey), Ok(true))
}

#[cfg(test)]
mod bootstrap_verify_tests {
    use super::verify_bootstrap_descriptor_bytes;

    #[test]
    fn rejects_malformed_json() {
        assert!(!verify_bootstrap_descriptor_bytes(b"not json", &[0u8; 32]));
    }

    #[test]
    fn rejects_expired_descriptor() {
        let json = br#"{
            "descriptor_id": "test",
            "version": 1,
            "created_at": 0,
            "expires_at": 1,
            "base_mask_ids": [],
            "embedded_masks": [],
            "candidate_count": 1,
            "kdf_salt": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }"#;
        // expires_at = 1 (1970-01-01) is always in the past, and the zero
        // signature would fail verification anyway, but expiry is checked first.
        assert!(!verify_bootstrap_descriptor_bytes(json, &[0u8; 32]));
    }

    #[test]
    fn rejects_bad_public_key() {
        // All-zero bytes are not a valid ed25519 point in most cases, and even
        // if VerifyingKey::from_bytes accepted it, the zero signature would
        // still fail to verify against real signing bytes — either way this
        // must return false, not panic.
        let json = br#"{
            "descriptor_id": "test",
            "version": 1,
            "created_at": 0,
            "expires_at": 9999999999,
            "base_mask_ids": [],
            "embedded_masks": [],
            "candidate_count": 1,
            "kdf_salt": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "signature": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]
        }"#;
        assert!(!verify_bootstrap_descriptor_bytes(json, &[0u8; 32]));
    }
}
