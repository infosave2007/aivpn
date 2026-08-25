//! iOS VPN tunnel — runs on top of an AF_UNIX SOCK_DGRAM socketpair fd passed from
//! the NEPacketTunnelProvider extension. The protocol is byte-for-byte identical to the
//! Android and macOS clients; only the TUN I/O and stop-signal mechanisms differ.
//!
//! Key differences from android_tunnel.rs:
//!  - No JNI: protect() is unnecessary (NEPacketTunnelProvider is automatically outside VPN)
//!  - Stop signal uses pipe() instead of eventfd() (not available on iOS/macOS)
//!  - on_ready notification via C callback instead of JNI method call

#![allow(clippy::too_many_arguments)]

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aivpn_common::error::{Error, Result};

// Shared mobile tunnel core: constants, session state/lifecycle, the upload
// encryptor (MobileEncryptor) and low-level socket/TUN/stop-signal I/O all
// live in aivpn-common::mobile_tunnel now (hoisted from android_tunnel.rs,
// which was logic-identical to this file for all of them). Re-exported so
// lib.rs keeps importing them from this module unchanged.
pub use aivpn_common::mobile_tunnel::*;

use aivpn_common::client_wire::DEFAULT_MDH_LEN;
use aivpn_common::mobile_tunnel::{run_tunnel_generic, PlatformIo};
// `pub` because lib.rs's FFI getters import `RecordingFeedback` from this
// module (unchanged import list) — the type itself now lives in aivpn-common.
pub use aivpn_common::mobile_tunnel::RecordingFeedback;

pub static ACTIVE_RECORDING_FEEDBACK: Mutex<Option<RecordingFeedback>> = Mutex::new(None);
/// Bumped every time a new `RecordingFeedback` is stored, so Swift can detect
/// a fresh message by comparing against the last-seen sequence number rather
/// than re-reacting to a stale value every poll tick.
pub static RECORDING_FEEDBACK_SEQ: AtomicU64 = AtomicU64::new(0);

// ──────────── C callback type ────────────

pub type OnReadyFn = unsafe extern "C" fn(host: *const libc::c_char, ctx: *mut libc::c_void);

// Wrap the raw ctx pointer so the Future can be Send.
pub struct SendCtx(pub *mut libc::c_void);
unsafe impl Send for SendCtx {}

// ──────────── Platform adapter ────────────

/// iOS's [`PlatformIo`]. `protect_socket` keeps the trait default (a
/// NEPacketTunnelProvider is automatically outside the VPN); readiness goes
/// out over the C callback, and recording feedback lands in the static +
/// sequence counter Swift polls.
struct IosPlatform {
    on_ready: Option<OnReadyFn>,
    ctx: SendCtx,
}

impl PlatformIo for IosPlatform {
    fn notify_ready(&self, host: &str) {
        if let Some(cb) = self.on_ready {
            if let Ok(c_host) = CString::new(host) {
                unsafe { cb(c_host.as_ptr(), self.ctx.0) };
            }
        }
    }

    fn publish_recording_feedback(&self, fb: RecordingFeedback) {
        *ACTIVE_RECORDING_FEEDBACK
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(fb);
        RECORDING_FEEDBACK_SEQ.fetch_add(1, Ordering::Relaxed);
    }
}

// ──────────── Entry point ────────────

#[allow(clippy::too_many_arguments)]
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
    polymorphic_base: Option<String>,
    share_mask_feedback: bool,
    receive_mask_hints: bool,
    country_code: Option<[u8; 2]>,
    prior_outcomes_json: Option<String>,
    preferred_mask: Option<String>,
    cached_descriptors_json: Option<String>,
    mask_operator_pubkey: Option<[u8; 32]>,
    mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
) -> Result<()> {
    // Reset per-session recording state so a stale message from a previous
    // session is never surfaced to a new one: the NE process (and thus these
    // statics) is reused across connect/disconnect cycles, while Swift's
    // `lastSeenRecordingFeedbackSeq` resets to 0 in the fresh provider
    // instance — without this, a stale Ack/Complete/Failed would be re-applied
    // on the very first poll. Lives here (not in the shared run loop) because
    // both statics are iOS-owned.
    RECORDING_FEEDBACK_SEQ.store(0, Ordering::Relaxed);
    *ACTIVE_RECORDING_FEEDBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;

    let result = run_tunnel_generic(
        IosPlatform { on_ready, ctx },
        tun_fd,
        server_host,
        server_port,
        server_key,
        psk,
        mtls_cert,
        DEFAULT_MDH_LEN,
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
        // iOS does not wire an alternative transport yet — the seam is ready.
        None,
    )
    .await;

    // The shared loop returns Ok(()) on a user-requested stop (Android's
    // convention). iOS has ALWAYS returned an error there, and Swift's
    // `aivpn_run_tunnel` maps any error to -1 — so re-wrap it to keep the FFI
    // return value byte-identical to before this refactor.
    match result {
        Ok(()) => Err(Error::Session("Stop requested".into())),
        Err(e) => Err(e),
    }
}
