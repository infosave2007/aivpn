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

/// Android's [`SocketGuard`]: exempts a socket from the VPN through
/// `VpnService.protect(int)`.
///
/// Separate from [`AndroidPlatform`] rather than folded into it, because the
/// two have different thread-safety contracts. `PlatformIo` is deliberately not
/// `Sync` — the iOS implementation of that trait carries a raw Swift context
/// pointer that nothing synchronises — while a `SocketGuard` is shared behind
/// an `Arc` by a transport that may open sockets from several tasks, so it must
/// be `Send + Sync`. Android can honour that: `JavaVM` is designed for
/// `AttachCurrentThread` from any thread, and `GlobalRef` is a JNI global
/// reference precisely so it can outlive one thread's frame.
///
/// The call itself is shared with `PlatformIo::protect_socket` below, so there
/// is one implementation of "protect this fd", not two that can drift.
#[derive(Clone)]
pub struct VpnProtectGuard {
    vm: std::sync::Arc<JavaVM>,
    vpn_service: GlobalRef,
}

impl VpnProtectGuard {
    /// Build a guard from the VM and the `VpnService` instance the tunnel was
    /// started with.
    pub fn new(vm: std::sync::Arc<JavaVM>, vpn_service: GlobalRef) -> Self {
        Self { vm, vpn_service }
    }
}

impl aivpn_common::transport::SocketGuard for VpnProtectGuard {
    fn protect(&self, fd: RawFd) -> Result<()> {
        vpn_protect(&self.vm, &self.vpn_service, fd)
    }
}

/// `VpnService.protect(int)` through JNI.
///
/// On failure the caller closes the fd — never this function.
fn vpn_protect(vm: &JavaVM, vpn_service: &GlobalRef, fd: RawFd) -> Result<()> {
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

    if !protect_result.unwrap_or(false) {
        return Err(Error::Session("VpnService.protect() returned false".into()));
    }
    Ok(())
}

impl PlatformIo for AndroidPlatform {
    fn protect_socket(&self, fd: RawFd) -> Result<()> {
        vpn_protect(&self.vm, &self.vpn_service, fd)
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
    transport_name: Option<String>,
    transport_params_json: Option<String>,
) -> Result<()> {
    // Reset per-session recording feedback so a stale message from a previous
    // session is never surfaced to a new one. Done here (not in the shared run
    // loop) because the static and its take-once semantics are Android's.
    *ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;

    // Open the alternative transport if one was configured. A build that
    // installed no factory has none to open and stays on direct UDP.
    let alt_transport: Option<std::sync::Arc<dyn aivpn_common::transport::DatagramTransport>> =
        build_alt_transport(&vm, &vpn_service, transport_name, transport_params_json).await?;

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
        alt_transport,
    )
    .await
}

/// Open the configured alternative transport, applying Android's socket guard
/// so its sockets stay out of the VPN.
///
/// `None` — the case in any build that installed no factory — means the direct
/// UDP socket, which is what this library has always used. There is no
/// `#[cfg]` here on purpose: the public build and an extended one are the same
/// code, and they differ only in whether something called
/// [`crate::install_transport_factory`] before the first JNI call.
async fn build_alt_transport(
    vm: &JavaVM,
    vpn_service: &GlobalRef,
    transport_name: Option<String>,
    transport_params_json: Option<String>,
) -> Result<Option<std::sync::Arc<dyn aivpn_common::transport::DatagramTransport>>> {
    use std::sync::Arc;

    let Some(name) = transport_name else {
        return Ok(None);
    };
    let Some(factory) = crate::installed_transport_factory() else {
        // A transport was configured but this build carries none. Returning
        // `None` here would silently send the traffic by direct UDP — wrong,
        // and conspicuous on a network where the transport was chosen for a
        // reason. Fail the session instead.
        return Err(Error::Session(format!(
            "transport {name:?} configured, but this build registers none"
        )));
    };

    // A second handle to the same JavaVM for the guard; the platform keeps the
    // original. `GlobalRef` is shareable across threads by design.
    let guard_vm = unsafe {
        JavaVM::from_raw(vm.get_java_vm_pointer())
            .map_err(|e| Error::Session(format!("JavaVM handle: {e}")))?
    };
    let guard: aivpn_common::transport::SharedGuard = Arc::new(VpnProtectGuard::new(
        Arc::new(guard_vm),
        vpn_service.clone(),
    ));

    let mut registry = aivpn_common::transport::TransportRegistry::new();
    registry.register(factory);
    let params = transport_params_json.unwrap_or_default().into_bytes();
    let cfg = aivpn_common::transport::TransportConfig::new(name, params);
    let transport = registry
        .open(&cfg, guard)
        .await
        .map_err(|e| Error::Session(format!("open alt transport: {e}")))?;
    Ok(Some(transport))
}
