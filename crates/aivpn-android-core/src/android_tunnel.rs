//! Android VPN tunnel — runs on top of a TUN fd created by VpnService.Builder and a UDP
//! socket created here and exempted via VpnService.protect(int).
//!
//! Wire protocol is byte-for-byte identical to AivpnCrypto.kt so that both can talk to the
//! same Rust server without any server-side changes.

use std::os::unix::io::RawFd;
use std::sync::Mutex;

use jni::objects::GlobalRef;
use jni::JavaVM;

use aivpn_common::error::{Error, Result};

// Shared mobile tunnel core: constants, session state/lifecycle, the upload
// encryptor (MobileEncryptor) and low-level socket/TUN/stop-signal I/O all
// live in aivpn-common::mobile_tunnel now (hoisted verbatim from this file).
// Re-exported so lib.rs keeps importing them from this module unchanged.
pub use aivpn_common::mobile_tunnel::*;

use aivpn_common::mobile_tunnel::{run_tunnel_generic, PlatformIo, RecordingFeedback};

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

// ──────────── Platform adapter ────────────

/// Android's [`PlatformIo`]: JNI socket protection, the `onTunnelReady`
/// callback, and the take-once recording-feedback static polled from Kotlin.
struct AndroidPlatform {
    vm: JavaVM,
    vpn_service: GlobalRef,
}

impl PlatformIo for AndroidPlatform {
    fn protect_socket(&self, fd: RawFd) -> Result<()> {
        // Call Android VpnService.protect(int) to exempt this socket from the
        // VPN. On failure the fd is closed by `create_udp_socket` — never here.
        let mut guard = self
            .vm
            .attach_current_thread()
            .map_err(|e| Error::Session(format!("JNI attach: {}", e)))?;

        let protect_result = guard
            .call_method(
                &self.vpn_service,
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
            return Err(Error::Session("VpnService.protect() returned false".into()));
        }
        Ok(())
    }

    fn notify_ready(&self, host: &str) {
        let mut env = match self.vm.attach_current_thread() {
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
            &self.vpn_service,
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

    fn publish_recording_feedback(&self, fb: RecordingFeedback) {
        *ACTIVE_RECORDING_FEEDBACK
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(fb);
    }
}

// ──────────── Entry point ────────────

/// Blocking async function that runs the whole tunnel session.
/// Returns Err on any tunnel failure (causes the Kotlin reconnect loop to kick in).
#[allow(clippy::too_many_arguments)]
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
    mask_operator_pubkey: Option<[u8; 32]>,
    mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    polymorphic_base: Option<String>,
    share_mask_feedback: bool,
    receive_mask_hints: bool,
    country_code: Option<[u8; 2]>,
    prior_outcomes_json: Option<String>,
    cached_descriptors_json: Option<String>,
) -> Result<()> {
    // Reset per-session recording feedback so a stale message from a previous
    // session is never surfaced to a new one. Done here (not in the shared run
    // loop) because the static and its take-once semantics are Android's.
    *ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;

    run_tunnel_generic(
        AndroidPlatform { vm, vpn_service },
        tun_fd_int,
        server_host,
        server_port,
        server_key,
        psk,
        mtls_cert,
        mdh_len,
        adaptive_level,
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
    )
    .await
}
