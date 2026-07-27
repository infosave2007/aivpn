//! JNI entry points for the Android VPN service.
//!
//! Kotlin class: com.aivpn.client.AivpnJni
//!
//! The JNI function names encode class + method:
//!   Java_com_aivpn_client_AivpnJni_<method>

#![allow(non_snake_case)]

mod android_tunnel;

use aivpn_common::client_wire::DEFAULT_MDH_LEN;
use aivpn_common::protocol::ControlPayload;
use android_tunnel::{
    bootstrap_descriptors_json, clear_pending_stop, get_active_download_bytes,
    get_active_upload_bytes, run_tunnel_android, send_control_payload, stop_active_tunnel,
    take_recording_feedback_json, ACTIVE_ADAPTIVE_LEVEL, ACTIVE_FEEDBACK_INTERVAL,
    ACTIVE_FEEDBACK_THRESHOLD, ACTIVE_MASK_CATALOG_JSON, ACTIVE_QUALITY_SCORE,
    ACTIVE_REGIONAL_HINTS_JSON, ASSIGNED_VPN_IP, ATTEMPTED_MASK_FAMILY, CERT_REJECTED,
    EVER_CONNECTED, MASK_CATALOG_SEQ, MASK_FEEDBACK_SENT, REGIONAL_HINTS_SEQ,
};

use std::sync::atomic::Ordering;

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;

// ──────────────────────────────────────────────────────────
// runTunnel — blocking call; returns when tunnel stops/errors
// ──────────────────────────────────────────────────────────

/// Runs the full VPN tunnel session on the calling thread.
///
/// Parameters (Kotlin):
/// ```kotlin
/// external fun runTunnel(
///     vpnService: VpnService,
///     tunFd: Int,          // borrowed fd from ParcelFileDescriptor; Rust duplicates it
///     serverHost: String,
///     serverPort: Int,
///     serverKey: ByteArray, // 32 bytes
///     psk: ByteArray?,      // 32 bytes or null
///     serverSigningKey: ByteArray?, // 32 bytes ed25519 verifying key, or null to skip
///                                   // ServerHello signature verification (opt-in,
///                                   // matching desktop's --server-signing-key)
///     maskOperatorPubkey: ByteArray?, // 32 bytes ed25519 verifying key for
///                                   // artifact-level MaskUpdate signature
///                                   // verification (the "mop" connection-key
///                                   // field), or null to skip — matching
///                                   // desktop's --mask-operator-pubkey
///     maskVerifyMode: Int,          // 0=off, 1=warn, 2=enforce; matches desktop's
///                                   // --mask-verify-mode (any other value is
///                                   // treated as warn, the same default desktop
///                                   // uses absent an explicit override)
///     polymorphicBase: String?,     // §3 base mask id to request a per-session
///                                   // polymorphic variant of, or null to disable
///     shareMaskFeedback: Boolean,   // §2 opt-in: report mask success/fail outcomes
///     receiveMaskHints: Boolean,    // §2 opt-in: accept server regional mask hints
///     countryCode: String?,         // §2 2-letter ISO-3166-1 country code, or null
///     priorOutcomesJson: String?,   // §2 JSON array of prior (unreported) MaskOutcome
///                                   // entries the platform persisted across earlier
///                                   // attempts, e.g. `[{"mask_id":"quic_https",
///                                   // "success":2,"fail":1}]`, or null/empty for none
/// ): String               // "" on clean exit, error message otherwise
/// ```
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_runTunnel<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    vpn_service: JObject<'local>,
    tun_fd: jint,
    server_host: JString<'local>,
    server_port: jint,
    server_key_arr: JByteArray<'local>,
    psk_obj: JObject<'local>,       // nullable JByteArray
    mtls_cert_obj: JObject<'local>, // nullable JByteArray
    adaptive_level: jint,
    static_privkey_obj: JObject<'local>, // nullable JByteArray — device binding key
    mask_name_obj: JObject<'local>,      // nullable JString — preferred mask profile name
    server_signing_key_obj: JObject<'local>, // nullable JByteArray — ed25519 verifying key
    mask_operator_pubkey_obj: JObject<'local>, // nullable JByteArray — mask-operator ed25519 verifying key ("mop")
    mask_verify_mode_int: jint,                // 0=off, 1=warn (default), 2=enforce
    polymorphic_base_obj: JObject<'local>,     // nullable JString — §3 polymorphic base mask id
    share_mask_feedback: jni::sys::jboolean,   // §2 opt-in: report mask outcomes
    receive_mask_hints: jni::sys::jboolean,    // §2 opt-in: accept server region hints
    country_code_obj: JObject<'local>,         // nullable JString — 2-letter ISO-3166-1 code
    prior_outcomes_json_obj: JObject<'local>, // nullable JString — §2 prior unreported outcomes (JSON)
    cached_descriptors_json_obj: JObject<'local>, // nullable JString — app-persisted signed bootstrap descriptors (JSON array)
) -> jstring {
    // ── Initialize Android logcat logger once per process lifetime ──
    static LOG_INIT: std::sync::Once = std::sync::Once::new();
    LOG_INIT.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("aivpn"),
        );
    });

    // ── Unpack arguments ──
    let host = match env.get_string(&server_host) {
        Ok(s) => String::from(s),
        Err(e) => return make_str(&mut env, &format!("bad server_host: {e}")),
    };

    let key_bytes = match env.convert_byte_array(&server_key_arr) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            return make_str(
                &mut env,
                &format!("server_key must be 32 bytes, got {}", b.len()),
            )
        }
        Err(e) => return make_str(&mut env, &format!("bad server_key: {e}")),
    };

    let psk: Option<[u8; 32]> = if psk_obj.is_null() {
        None
    } else {
        // Verify the JObject is a byte array before the unsafe cast.
        // An incorrect caller passing a non-byte-array would produce JVM type
        // confusion; reject early with a clear error instead.
        match env.is_instance_of(&psk_obj, "[B") {
            Ok(true) => {}
            Ok(false) => return make_str(&mut env, "psk must be a byte array (byte[])"),
            Err(e) => return make_str(&mut env, &format!("psk type check failed: {e}")),
        }
        let arr: JByteArray<'local> = unsafe { JByteArray::from_raw(psk_obj.as_raw()) };
        match env.convert_byte_array(&arr) {
            Ok(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Some(out)
            }
            Ok(b) => return make_str(&mut env, &format!("psk must be 32 bytes, got {}", b.len())),
            Err(e) => return make_str(&mut env, &format!("bad psk: {e}")),
        }
    };

    let mtls_cert: Option<Vec<u8>> = if mtls_cert_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&mtls_cert_obj, "[B") {
            Ok(true) => {}
            Ok(false) => return make_str(&mut env, "mtls_cert must be a byte array (byte[])"),
            Err(e) => return make_str(&mut env, &format!("mtls_cert type check failed: {e}")),
        }
        let arr: JByteArray<'local> = unsafe { JByteArray::from_raw(mtls_cert_obj.as_raw()) };
        match env.convert_byte_array(&arr) {
            Ok(b) if b.len() == 104 => Some(b),
            Ok(b) => {
                return make_str(
                    &mut env,
                    &format!("mtls_cert must be 104 bytes, got {}", b.len()),
                )
            }
            Err(e) => return make_str(&mut env, &format!("bad mtls_cert: {e}")),
        }
    };

    let static_privkey: Option<[u8; 32]> = if static_privkey_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&static_privkey_obj, "[B") {
            Ok(true) => {}
            Ok(false) => return make_str(&mut env, "static_privkey must be a byte array (byte[])"),
            Err(e) => return make_str(&mut env, &format!("static_privkey type check failed: {e}")),
        }
        let arr: JByteArray<'local> = unsafe { JByteArray::from_raw(static_privkey_obj.as_raw()) };
        match env.convert_byte_array(&arr) {
            Ok(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Some(out)
            }
            Ok(b) => {
                return make_str(
                    &mut env,
                    &format!("static_privkey must be 32 bytes, got {}", b.len()),
                )
            }
            Err(e) => return make_str(&mut env, &format!("bad static_privkey: {e}")),
        }
    };

    let server_signing_key: Option<[u8; 32]> = if server_signing_key_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&server_signing_key_obj, "[B") {
            Ok(true) => {}
            Ok(false) => {
                return make_str(&mut env, "server_signing_key must be a byte array (byte[])")
            }
            Err(e) => {
                return make_str(
                    &mut env,
                    &format!("server_signing_key type check failed: {e}"),
                )
            }
        }
        let arr: JByteArray<'local> =
            unsafe { JByteArray::from_raw(server_signing_key_obj.as_raw()) };
        match env.convert_byte_array(&arr) {
            Ok(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Some(out)
            }
            Ok(b) => {
                return make_str(
                    &mut env,
                    &format!("server_signing_key must be 32 bytes, got {}", b.len()),
                )
            }
            Err(e) => return make_str(&mut env, &format!("bad server_signing_key: {e}")),
        }
    };

    // R2 Phase B: operator mask-verifying public key ("mop" connection-key
    // field) — same 32-byte-optional-byte-array shape as server_signing_key
    // above, but feeds `verify_mask_artifact` instead of ServerHello/transport
    // signature checks (see android_tunnel.rs's `mask_operator_pubkey` doc).
    let mask_operator_pubkey: Option<[u8; 32]> = if mask_operator_pubkey_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&mask_operator_pubkey_obj, "[B") {
            Ok(true) => {}
            Ok(false) => {
                return make_str(
                    &mut env,
                    "mask_operator_pubkey must be a byte array (byte[])",
                )
            }
            Err(e) => {
                return make_str(
                    &mut env,
                    &format!("mask_operator_pubkey type check failed: {e}"),
                )
            }
        }
        let arr: JByteArray<'local> =
            unsafe { JByteArray::from_raw(mask_operator_pubkey_obj.as_raw()) };
        match env.convert_byte_array(&arr) {
            Ok(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Some(out)
            }
            Ok(b) => {
                return make_str(
                    &mut env,
                    &format!("mask_operator_pubkey must be 32 bytes, got {}", b.len()),
                )
            }
            Err(e) => return make_str(&mut env, &format!("bad mask_operator_pubkey: {e}")),
        }
    };
    let mask_verify_mode: aivpn_common::mask::MaskVerifyMode = match mask_verify_mode_int {
        0 => aivpn_common::mask::MaskVerifyMode::Off,
        2 => aivpn_common::mask::MaskVerifyMode::Enforce,
        _ => aivpn_common::mask::MaskVerifyMode::Warn,
    };

    let preferred_mask: Option<String> = if mask_name_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&mask_name_obj, "java/lang/String") {
            Ok(true) => {
                let js: JString<'local> = unsafe { JString::from_raw(mask_name_obj.as_raw()) };
                env.get_string(&js)
                    .ok()
                    .map(|s| String::from(s))
                    .filter(|s| !s.is_empty() && s != "auto")
            }
            _ => None,
        }
    };

    let polymorphic_base: Option<String> = if polymorphic_base_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&polymorphic_base_obj, "java/lang/String") {
            Ok(true) => {
                let js: JString<'local> =
                    unsafe { JString::from_raw(polymorphic_base_obj.as_raw()) };
                env.get_string(&js)
                    .ok()
                    .map(|s| String::from(s))
                    .filter(|s| !s.is_empty())
            }
            _ => None,
        }
    };

    // §2 crowdsourced blocking feedback: 2-letter ISO-3166-1 alpha-2 country code.
    // Only accepted when exactly 2 ASCII letters; anything else is treated as unset
    // (matches desktop's `--country-code` CLI validation in aivpn-client/main.rs).
    let country_code: Option<[u8; 2]> = if country_code_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&country_code_obj, "java/lang/String") {
            Ok(true) => {
                let js: JString<'local> = unsafe { JString::from_raw(country_code_obj.as_raw()) };
                env.get_string(&js).ok().map(String::from).and_then(|s| {
                    let upper = s.to_ascii_uppercase();
                    let bytes = upper.as_bytes();
                    if bytes.len() == 2 && bytes.iter().all(|b| b.is_ascii_alphabetic()) {
                        Some([bytes[0], bytes[1]])
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    };

    let share_mask_feedback = share_mask_feedback != 0;
    let receive_mask_hints = receive_mask_hints != 0;

    // §2 crowdsourced blocking feedback — JSON array of prior (unreported)
    // mask outcomes the platform has persisted across earlier attempts.
    // Malformed/absent JSON is handled inside `run_tunnel_android` (collapses
    // to an empty batch), so no validation is needed here beyond extracting
    // the raw string.
    let prior_outcomes_json: Option<String> = if prior_outcomes_json_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&prior_outcomes_json_obj, "java/lang/String") {
            Ok(true) => {
                let js: JString<'local> =
                    unsafe { JString::from_raw(prior_outcomes_json_obj.as_raw()) };
                env.get_string(&js)
                    .ok()
                    .map(|s| String::from(s))
                    .filter(|s| !s.is_empty())
            }
            _ => None,
        }
    };

    // App-persisted signed bootstrap descriptors (JSON array). Loaded into the
    // descriptor store before the handshake so a cold-start first handshake can
    // be COVERT. Malformed/empty is handled inside run_tunnel_android.
    let cached_descriptors_json: Option<String> = if cached_descriptors_json_obj.is_null() {
        None
    } else {
        match env.is_instance_of(&cached_descriptors_json_obj, "java/lang/String") {
            Ok(true) => {
                let js: JString<'local> =
                    unsafe { JString::from_raw(cached_descriptors_json_obj.as_raw()) };
                env.get_string(&js)
                    .ok()
                    .map(|s| String::from(s))
                    .filter(|s| !s.is_empty())
            }
            _ => None,
        }
    };

    // ── Get JavaVM for use inside the tokio runtime ──
    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => return make_str(&mut env, &format!("get_java_vm: {e}")),
    };
    let vpn_global = match env.new_global_ref(&vpn_service) {
        Ok(g) => g,
        Err(e) => return make_str(&mut env, &format!("global_ref: {e}")),
    };

    // ── Run on a current-thread tokio runtime (we ARE an IO thread already) ──
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return make_str(&mut env, &format!("tokio runtime: {e}")),
    };

    // Catch any panic in the tunnel/decode path so it cannot unwind across the
    // extern "system" JNI boundary and abort the entire Android app process — a
    // single malformed control message must fail only this one connection.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(run_tunnel_android(
            vm,
            vpn_global,
            tun_fd,
            host,
            server_port as u16,
            key_bytes,
            psk,
            mtls_cert,
            DEFAULT_MDH_LEN,
            adaptive_level.clamp(0, 3) as u8,
            static_privkey,
            preferred_mask,
            server_signing_key,
            mask_operator_pubkey,
            mask_verify_mode,
            polymorphic_base,
            share_mask_feedback,
            receive_mask_hints,
            country_code,
            prior_outcomes_json,
            cached_descriptors_json,
        ))
    }));

    // Zero sensitive key material after use so it does not linger in heap memory.
    let mut key_bytes_z = key_bytes;
    unsafe { std::ptr::write_volatile(&mut key_bytes_z as *mut [u8; 32], [0u8; 32]) };
    if let Some(mut p) = psk {
        unsafe { std::ptr::write_volatile(&mut p as *mut [u8; 32], [0u8; 32]) };
    }
    if let Some(mut k) = static_privkey {
        unsafe { std::ptr::write_volatile(&mut k as *mut [u8; 32], [0u8; 32]) };
    }

    match outcome {
        Ok(Ok(())) => make_str(&mut env, ""),
        Ok(Err(e)) => make_str(&mut env, &e.to_string()),
        Err(_) => make_str(&mut env, "internal error: tunnel panicked (caught)"),
    }
}

// ──────────────────────────────────────────────────────────
// stopTunnel — closes the protected UDP socket so recv() fails
// and the tunnel loop exits immediately.
// ──────────────────────────────────────────────────────────

#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_stopTunnel(_env: JNIEnv, _class: JClass) {
    stop_active_tunnel();
}

// clearPendingStop — called by the Kotlin restartJob right before launching a
// new intentional connection so the STOP_PENDING flag from the cleanup-phase
// stopTunnel() call does not propagate into the new session.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_clearPendingStop(
    _env: JNIEnv,
    _class: JClass,
) {
    clear_pending_stop();
}

// ──────────────────────────────────────────────────────────
// Traffic counters (polled by Kotlin every ~1 s)
// ──────────────────────────────────────────────────────────

/// Returns the last connection quality score (0–100) computed from KeepaliveAck RTT.
/// Returns 0 if no keepalive round-trip has been observed yet this session.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getQualityScore(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ACTIVE_QUALITY_SCORE.load(Ordering::Relaxed) as jint
}

#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getUploadBytes(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    get_active_upload_bytes() as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getDownloadBytes(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    get_active_download_bytes() as jlong
}

/// Returns the last adaptive level hint received from the server via
/// AdaptiveHint: 0–3 (0 = server says adaptive Off — a real downgrade), or
/// -1 when no hint has been received yet this session. The static stores
/// `level + 1` so 0 can keep meaning "no hint".
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getAdaptiveLevelHint(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ACTIVE_ADAPTIVE_LEVEL.load(Ordering::Relaxed) as jint - 1
}

/// Returns the VPN IPv4 address the server assigned to this session in its
/// ServerHello network config (dotted quad), or an empty string when the
/// current session has not received one. When this differs from the IP
/// embedded in the connection key, the server has re-homed the client (pool
/// IP-conflict resolution) and the TUN must be rebuilt with this address —
/// otherwise the server's anti-spoof check silently drops all uplink data.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getAssignedVpnIp(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let raw = ASSIGNED_VPN_IP.load(Ordering::Relaxed);
    let s = if raw == 0 {
        String::new()
    } else {
        std::net::Ipv4Addr::from(raw).to_string()
    };
    // L8: route through make_str so an extreme JNI failure degrades to an
    // empty string (after clearing the pending exception) instead of handing
    // a null jstring to a Kotlin `external fun` declared non-null String.
    make_str(&mut env, &s)
}

/// Returns `true` (and atomically clears the flag) if the server sent
/// `CertRejected` (mTLS client certificate rejected) at any point since the
/// last call — poll this live during a session (like `getAssignedVpnIp`), not
/// just after `runTunnel` returns, since the server keeps the tunnel up while
/// rejecting the cert rather than tearing it down. A `true` result means the
/// current certificate will never be accepted by this server; the caller
/// should prompt the user to re-provision instead of waiting for a timeout.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_certRejected(
    _env: JNIEnv,
    _class: JClass,
) -> jni::sys::jboolean {
    CERT_REJECTED.swap(false, Ordering::Relaxed) as jni::sys::jboolean
}

// ──────────────────────────────────────────────────────────
// §2 crowdsourced blocking feedback getters
// ──────────────────────────────────────────────────────────
//
// `runTunnel` handles exactly one connection attempt per call, so the
// platform (`AivpnService.kt`), which owns the reconnect loop and
// cross-attempt persistence, polls these once the blocking JNI call returns
// to learn the outcome, then persists across attempts itself.

/// Whether the most recently completed `runTunnel` call ever reached a
/// connected (post-handshake, PFS ratchet complete) state. `false` means the
/// attempt never connected, so the platform should count it toward
/// `getFeedbackThreshold()` consecutive failures for
/// `getAttemptedMaskFamily()` (mirrors desktop main.rs's
/// `client.ever_connected()` check in the reconnect loop).
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_everConnected(
    _env: JNIEnv,
    _class: JClass,
) -> jni::sys::jboolean {
    EVER_CONNECTED.load(Ordering::Relaxed) as jni::sys::jboolean
}

/// Whether a `MaskFeedback` control message (share entries or a hints-only
/// probe) was actually sent during the most recently completed `runTunnel`
/// call. The platform uses this to decide whether to clear its persisted
/// outcome buffer and record a new `last_report_unix` (mirrors desktop's
/// `MaskFeedbackLog::mark_reported`, called after a successful send).
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_wasMaskFeedbackSent(
    _env: JNIEnv,
    _class: JClass,
) -> jni::sys::jboolean {
    MASK_FEEDBACK_SENT.load(Ordering::Relaxed) as jni::sys::jboolean
}

/// Server-pushed `FeedbackConfig.report_failure_threshold` received during
/// the most recently completed `runTunnel` call. Returns 0 if no
/// `FeedbackConfig` was received this session — the platform should keep
/// whichever value it had previously persisted (defaulting to 3 if none).
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getFeedbackThreshold(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ACTIVE_FEEDBACK_THRESHOLD.load(Ordering::Relaxed) as jint
}

/// Server-pushed `FeedbackConfig.report_interval_secs` received during the
/// most recently completed `runTunnel` call. Returns 0 if no
/// `FeedbackConfig` was received this session — the platform should keep
/// whichever value it had previously persisted (defaulting to 3600 if none).
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getFeedbackIntervalSecs(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    ACTIVE_FEEDBACK_INTERVAL.load(Ordering::Relaxed) as jlong
}

/// Base mask family (already normalized via `base_mask_family`, e.g.
/// `"webrtc_zoom_v3"`) that the most recently completed `runTunnel` call
/// attempted, or `""` if no attempt has run yet. Set as soon as the mask is
/// chosen — before the handshake — so it is populated even when the attempt
/// never reaches `everConnected()`. Needed because mask selection (including
/// the preferred-mask-unset PSK-derived pick) happens inside this one-shot
/// call; the platform has no other way to learn which family a failed
/// attempt used.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getAttemptedMaskFamily(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    // catch_unwind so a future panic in the lock/clone can never abort the whole
    // app process across the FFI boundary (LOW-2); degrade to "" on panic.
    let family = std::panic::catch_unwind(|| {
        ATTEMPTED_MASK_FAMILY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_default()
    })
    .unwrap_or_default();
    make_str(&mut env, &family)
}

/// Monotonically increasing counter, bumped each time a new
/// `RegionalMaskHints` message is received (only when `receiveMaskHints` was
/// enabled for that call). Compare against the last-seen value before
/// re-reading via `getRegionalHintsJson()`.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getRegionalHintsSeq(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    REGIONAL_HINTS_SEQ.load(Ordering::Relaxed) as jlong
}

/// Returns the most recently received `RegionalMaskHints` as a JSON object
/// (`{"country_code":"US","masks":[["webrtc_zoom_v3",0.87],...]}`), or `""`
/// if no hints have been received yet. The platform should persist this
/// per-region and use it to softly bias mask selection on the next reconnect
/// attempt, never overriding an explicit user mask choice (mirrors
/// desktop's `HINT_BIAS_MIN_SCORE` gate in main.rs).
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getRegionalHintsJson(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    // catch_unwind so a panic never aborts the app process across FFI (LOW-2).
    let json = std::panic::catch_unwind(|| {
        ACTIVE_REGIONAL_HINTS_JSON
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_default()
    })
    .unwrap_or_default();
    make_str(&mut env, &json)
}

/// Monotonic counter bumped each time a fresh `MaskCatalog` is received from the
/// server. Kotlin compares this against its last-seen value to detect a new mask
/// list before re-reading `getMaskCatalogJson()`.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getMaskCatalogSeq(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    MASK_CATALOG_SEQ.load(Ordering::Relaxed) as jlong
}

/// Returns the most recent `MaskCatalog` as a JSON array
/// (`[{"mask_id":"auto_quic_v1","label":"QUIC","generated":true},...]`), or `""`
/// if no catalog has been received yet. The mask spinner renders this list and
/// appends "(авто)" to entries with `generated:true`.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getMaskCatalogJson(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    // catch_unwind so a panic never aborts the app process across FFI (LOW-2).
    let json = std::panic::catch_unwind(|| {
        ACTIVE_MASK_CATALOG_JSON
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_default()
    })
    .unwrap_or_default();
    make_str(&mut env, &json)
}

/// Send a RecordingStart control message to the server. Returns 1 if queued, 0 if no session.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_startRecording<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    service_name: JString<'local>,
) -> jint {
    let service = match env.get_string(&service_name) {
        Ok(s) => String::from(s).chars().take(128).collect::<String>(),
        Err(_) => return 0,
    };
    send_control_payload(ControlPayload::RecordingStart { service }) as jint
}

/// Send a RecordingStop control message to the server.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_stopRecording(_env: JNIEnv, _class: JClass) {
    send_control_payload(ControlPayload::RecordingStop {
        session_id: [0u8; 16],
    });
}

/// Returns (and clears) the most recent recording-related feedback message
/// from the server as a JSON string, or `""` if nothing is pending.
///
/// JSON shapes (matched on the `"type"` field):
/// ```text
/// {"type":"ack","status":"started"|"analyzing"}
/// {"type":"complete","mask_id":"...","confidence":0.87}
/// {"type":"failed","reason":"..."}
/// {"type":"status","can_record":true,"active_service":"zoom"|null}
/// ```
/// Consuming (rather than sticky-storing) matches the one-shot nature of
/// these server events — same idea as the desktop client's `record_cmd.rs`
/// handlers, just polled instead of pushed.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getRecordingFeedback(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    // catch_unwind so a panic never aborts the app process across FFI (LOW-2).
    let json = std::panic::catch_unwind(take_recording_feedback_json).unwrap_or_default();
    make_str(&mut env, &json)
}

/// Returns the currently-stored bootstrap descriptors as a JSON array so the
/// platform can persist them across process restarts (see AivpnService.kt). The
/// blobs are ed25519-signed and self-authenticating; the platform stores them
/// raw and passes them back into `runTunnel(cachedDescriptorsJson=…)` on the
/// next connect, where they are re-verified before use. Returns `"[]"` when the
/// store is empty (e.g. before the server has pushed any descriptor).
///
/// Poll this after `runTunnel` returns — the descriptor store is process-global
/// and survives the call, so a session that received `BootstrapDescriptorUpdate`
/// messages leaves them available here for persistence.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_getBootstrapDescriptorsJson(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    // catch_unwind so a panic in serialization never aborts the app process
    // across the FFI boundary (LOW-2); degrade to "" on panic.
    let json = std::panic::catch_unwind(bootstrap_descriptors_json).unwrap_or_default();
    make_str(&mut env, &json)
}

// ──────────────────────────────────────────────────────────
// verifyBootstrapDescriptor — bootstrap descriptor discovery
// ──────────────────────────────────────────────────────────

/// Verifies the ed25519 signature and validity window of a single bootstrap
/// descriptor fetched from a CDN/GitHub/Telegram channel by
/// `BootstrapDiscovery.kt`. Reuses `BootstrapDescriptor::verify_signature`
/// from aivpn-common instead of reimplementing ed25519 verification in
/// Kotlin.
///
/// Parameters (Kotlin):
/// ```kotlin
/// external fun verifyBootstrapDescriptor(
///     descriptorJson: String, // one BootstrapDescriptor, JSON-encoded
///     signingPublicKey: ByteArray, // 32 bytes
///     nowUnixSecs: Long,
/// ): Boolean
/// ```
/// Returns false on any parse error, signature mismatch, or expired descriptor.
/// Never panics across the FFI boundary.
#[no_mangle]
pub extern "system" fn Java_com_aivpn_client_AivpnJni_verifyBootstrapDescriptor<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    descriptor_json: JString<'local>,
    signing_public_key: JByteArray<'local>,
    now_unix_secs: jlong,
) -> jni::sys::jboolean {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_bootstrap_descriptor_impl(
            &mut env,
            &descriptor_json,
            &signing_public_key,
            now_unix_secs,
        )
    }));
    matches!(result, Ok(true)) as jni::sys::jboolean
}

fn verify_bootstrap_descriptor_impl(
    env: &mut JNIEnv,
    descriptor_json: &JString,
    signing_public_key: &JByteArray,
    now_unix_secs: jlong,
) -> bool {
    let json = match env.get_string(descriptor_json) {
        Ok(s) => String::from(s),
        Err(_) => return false,
    };
    let key_bytes = match env.convert_byte_array(signing_public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&key_bytes);

    let descriptor: aivpn_common::mask::BootstrapDescriptor = match serde_json::from_str(&json) {
        Ok(d) => d,
        Err(_) => return false,
    };

    if now_unix_secs < 0 || !descriptor.is_valid_at(now_unix_secs as u64) {
        return false;
    }

    matches!(descriptor.verify_signature(&public_key), Ok(true))
}

// ──────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────

fn make_str(env: &mut JNIEnv, s: &str) -> jstring {
    if let Ok(js) = env.new_string(s) {
        return js.into_raw();
    }
    // JVM may have a pending exception — clear it and retry rather than
    // calling .expect() which would panic-abort the process.
    let _ = env.exception_clear();
    env.new_string("")
        .map(|js| js.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
