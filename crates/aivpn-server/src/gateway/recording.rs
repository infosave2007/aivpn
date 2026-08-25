//! Traffic-recording helpers factored out of `Gateway`'s methods: whether a
//! given authenticated admin key is allowed to start a mask-recording
//! session, and how to react (control-message ack/complete/failed + async
//! mask generation) once the recorder reports a stop outcome. Pure moves out
//! of `gateway/mod.rs` — the hot-path `handle_control_message` dispatcher
//! that calls into these stays in `mod.rs`.

use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{info, warn};

use aivpn_common::protocol::ControlPayload;

use crate::mask_gen::generate_and_store_mask;
use crate::mask_store::MaskStore;
use crate::recording::{RecordingStopOutcome, RecordingStopReason};
use crate::session::{Session, SessionManager};

use super::Gateway;

impl Gateway {
    pub(crate) fn can_start_recording(&self, client_id: Option<&str>) -> bool {
        let Some(client_id) = client_id else {
            return false;
        };

        self.client_db
            .as_ref()
            .and_then(|db| db.find_by_id(client_id))
            .map(|client| client.name.starts_with("recording-admin"))
            .unwrap_or(false)
    }

    pub(crate) async fn handle_recording_outcome(
        socket: &Arc<UdpSocket>,
        sessions: &Arc<SessionManager>,
        store: &Arc<MaskStore>,
        mdh: &[u8],
        outcome: RecordingStopOutcome,
        notify_session: Option<Arc<parking_lot::Mutex<Session>>>,
    ) {
        match outcome {
            RecordingStopOutcome::Completed(completed) => {
                if let Some(ref session) = notify_session {
                    let ack = ControlPayload::RecordingAck {
                        session_id: completed.session_id,
                        status: "analyzing".into(),
                    };
                    if let Err(e) =
                        Self::send_control_message_via(socket.as_ref(), mdh, &ack, session).await
                    {
                        warn!("Failed to send RecordingAck: {}", e);
                    }
                }

                info!(
                    "Recording stopped for '{}' ({} packets, {}s), analyzing...",
                    completed.service, completed.total_packets, completed.duration_secs
                );

                let socket = socket.clone();
                let sessions = sessions.clone();
                let store = store.clone();
                let mdh = mdh.to_vec();
                tokio::spawn(async move {
                    match generate_and_store_mask(&completed.service, &completed.packets, &store)
                        .await
                    {
                        Ok(mask_id) => {
                            info!(
                                "✅ Mask generated: '{}' for service '{}' by {}",
                                mask_id, completed.service, completed.admin_key_id
                            );
                            if let Some(target_session) =
                                sessions.get_session(&completed.session_id)
                            {
                                let confidence = store
                                    .get_mask(&mask_id)
                                    .map(|entry| entry.stats.confidence)
                                    .unwrap_or(0.0);
                                let payload = ControlPayload::RecordingComplete {
                                    service: completed.service.clone(),
                                    mask_id,
                                    confidence,
                                };
                                if let Err(e) = Self::send_control_message_via(
                                    socket.as_ref(),
                                    &mdh,
                                    &payload,
                                    &target_session,
                                )
                                .await
                                {
                                    warn!("Failed to send RecordingComplete: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Mask generation failed for '{}': {}", completed.service, e);
                            if let Some(target_session) =
                                sessions.get_session(&completed.session_id)
                            {
                                let payload = ControlPayload::RecordingFailed {
                                    reason: e.to_string(),
                                };
                                if let Err(send_err) = Self::send_control_message_via(
                                    socket.as_ref(),
                                    &mdh,
                                    &payload,
                                    &target_session,
                                )
                                .await
                                {
                                    warn!("Failed to send RecordingFailed: {}", send_err);
                                }
                            }
                        }
                    }
                });
            }
            RecordingStopOutcome::Incomplete(incomplete) => {
                let reason = match incomplete.reason {
                    RecordingStopReason::IdleTimeout => {
                        "Recording stopped after idle timeout before enough traffic was captured"
                    }
                    RecordingStopReason::SessionEnded => {
                        "Recording ended with the session before enough traffic was captured"
                    }
                    _ => "Too few packets or too short duration",
                };
                if let Some(ref session) = notify_session {
                    let payload = ControlPayload::RecordingFailed {
                        reason: reason.into(),
                    };
                    if let Err(e) =
                        Self::send_control_message_via(socket.as_ref(), mdh, &payload, session)
                            .await
                    {
                        warn!("Failed to send RecordingFailed: {}", e);
                    }
                }
                warn!(
                    "Recording for '{}' ended without mask generation: {} packets, {}s ({:?})",
                    incomplete.service,
                    incomplete.total_packets,
                    incomplete.duration_secs,
                    incomplete.reason
                );
            }
            RecordingStopOutcome::NotFound => {}
        }
    }
}
