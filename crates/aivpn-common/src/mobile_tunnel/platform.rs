//! Platform seam for the shared mobile tunnel run loop.
//!
//! `run_tunnel_generic` is identical on iOS and Android except for three
//! things, all captured by [`PlatformIo`]: socket protection (Android must
//! call `VpnService.protect(int)` through JNI; the iOS NEPacketTunnelProvider
//! process is automatically outside the VPN), the tunnel-ready notification
//! (JNI `onTunnelReady` vs. a C callback), and how recording feedback is
//! published to the app (a take-once JSON static read by JNI vs. a static
//! plus sequence counter polled from Swift).

use std::os::unix::io::RawFd;

use crate::error::Result;

/// The per-platform hooks the shared run loop needs. One implementation per
/// mobile core (`AndroidPlatform` / `IosPlatform`); everything else about the
/// session is platform-independent.
// `Send + 'static` only — deliberately NOT `Sync`. The platform is owned by the
// single tunnel task and every hook is called from it; requiring `Sync` would
// force iOS to promise its raw Swift context pointer is safe to alias across
// threads, which nothing synchronises.
pub trait PlatformIo: Send + 'static {
    /// Exempt the freshly created UDP socket from the VPN so its own packets
    /// are not routed back into the tunnel. Android calls
    /// `VpnService.protect(int)`; iOS needs nothing (default impl).
    ///
    /// On `Err` the caller (`create_udp_socket`) closes the fd — an
    /// implementation must NOT close it itself.
    fn protect_socket(&self, _fd: RawFd) -> Result<()> {
        Ok(())
    }

    /// Announce that the tunnel finished its handshake and is carrying
    /// traffic. Called at most once per session, and never after a stop has
    /// been requested (the run loop re-checks immediately before calling).
    fn notify_ready(&self, host: &str);

    /// Hand the app the latest recording-related control message from the
    /// server. Each platform stores it in its own static, with its own
    /// take-once / sequence-counter semantics.
    fn publish_recording_feedback(&self, fb: RecordingFeedback);
}

/// Server feedback about an in-progress/completed mask-recording session —
/// the union of the fields the two mobile cores used to carry separately.
/// Mirrors the desktop client's handling of `ControlPayload::RecordingAck` /
/// `RecordingComplete` / `RecordingFailed` / `RecordingStatus` (see
/// aivpn-client's `client.rs`), field-for-field with the wire protocol in
/// `crate::protocol`.
///
/// `session_id` (Ack) and `service` (Complete) come from the iOS enum; the
/// Android enum omitted them. They are deliberately NOT part of [`to_json`]
/// (see that method's contract).
#[derive(Debug, Clone)]
pub enum RecordingFeedback {
    /// RecordingAck: `status` is "started" or "analyzing".
    Ack {
        session_id: [u8; 16],
        status: String,
    },
    /// RecordingComplete: mask generation succeeded.
    Complete {
        service: String,
        mask_id: String,
        confidence: f32,
    },
    /// RecordingFailed: recording or mask generation failed.
    Failed { reason: String },
    /// RecordingStatus: capability/status query response.
    Status {
        can_record: bool,
        active_service: Option<String>,
    },
}

impl RecordingFeedback {
    /// Encodes as a small JSON object for the Android JNI getter.
    /// `AivpnJni.kt`'s callers already depend on `org.json.JSONObject`
    /// everywhere else in this codebase, so a single JSON-string getter fits
    /// the existing Kotlin-side idiom better than four separate typed getters.
    ///
    /// CONTRACT: the emitted keys are EXACTLY those the Android enum emitted
    /// before this type was unified — Kotlin parses this shape. The superset
    /// fields inherited from the iOS enum (`session_id`, `service`) are
    /// deliberately excluded; adding them would change a shape the platform
    /// layer already parses.
    pub fn to_json(&self) -> String {
        match self {
            RecordingFeedback::Ack { status, .. } => {
                serde_json::json!({ "type": "ack", "status": status }).to_string()
            }
            RecordingFeedback::Complete {
                mask_id,
                confidence,
                ..
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
