//! In-tunnel management-API client: `MgmtRequest`/`MgmtResponse` correlation
//! and the cached server-assigned role, shared by every client implementation
//! (desktop `aivpn-client`, `aivpn-ios-core`, `aivpn-android-core`).
//!
//! Originally landed only in `aivpn-client` (P2.1); hoisted here (P2.R) so the
//! mobile cores — which depend on `aivpn-common` but NOT on `aivpn-client` —
//! can reach the same correlation logic instead of re-implementing it.
//!
//! [`MgmtClient`] owns just the correlation state (pending requests, the
//! `req_id` allocator, the cached role). It does not own a control channel:
//! callers pass their own `tokio::sync::mpsc::Sender<ControlPayload>` into
//! [`MgmtClient::mgmt_call`] so each embedder can wire it to whatever
//! transport it already has (the desktop client's `control_tx`, a mobile
//! core's equivalent channel, ...).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::protocol::ControlPayload;

/// In-tunnel management-API client state: in-flight `MgmtRequest`s awaiting
/// their correlated `MgmtResponse`, the `req_id` allocator, and the cached
/// server-assigned role from the last `Capabilities` control message.
///
/// Cheaply cloneable (all fields are `Arc`-wrapped) so it can be shared
/// between the session loop (which feeds it inbound `Capabilities` /
/// `MgmtResponse` control messages) and embedders calling `mgmt_call`
/// concurrently (FFI, admin-socket bridge) while only holding a shared
/// reference.
#[derive(Clone)]
pub struct MgmtClient {
    /// In-flight `MgmtRequest`s awaiting their correlated `MgmtResponse`,
    /// keyed by `req_id`. `mgmt_call` registers a oneshot here before
    /// enqueuing the request; `on_mgmt_response` resolves it when the
    /// matching `MgmtResponse` arrives. An unmatched `req_id` (already timed
    /// out / unknown) is silently dropped. `std::sync::Mutex` is fine here —
    /// the critical section is a single HashMap insert/remove, never held
    /// across an `.await`.
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<(u16, Vec<u8>)>>>>,
    /// Monotonically increasing `req_id` allocator for `mgmt_call`.
    req_seq: Arc<AtomicU32>,
    /// Cached server-assigned role (0=User,1=Viewer,2=Admin) from the last
    /// `Capabilities` control message, defaulting to User (0) until one
    /// arrives.
    cached_role: Arc<AtomicU8>,
}

impl Default for MgmtClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MgmtClient {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            req_seq: Arc::new(AtomicU32::new(1)),
            cached_role: Arc::new(AtomicU8::new(0)),
        }
    }

    /// Clear all in-flight correlation state and reset the cached role to
    /// User (0). Intended for a session restart (reconnect): any pending
    /// `mgmt_call` from the previous session is no longer resolvable (its
    /// `req_id` space and the server-side session it referred to are both
    /// gone), and the role must be re-learned from a fresh `Capabilities`
    /// push rather than carrying a stale value across sessions.
    pub fn reset(&self) {
        self.pending
            .lock()
            .expect("mgmt pending mutex poisoned")
            .clear();
        self.cached_role.store(0, Ordering::Relaxed);
    }

    /// Current server-assigned role (0=User, 1=Viewer, 2=Admin), cached from
    /// the last `Capabilities` control message. Defaults to 0 (User) until
    /// one arrives (i.e. before the post-ratchet `Capabilities` push, or for
    /// a server build that predates it).
    pub fn cached_role(&self) -> u8 {
        self.cached_role.load(Ordering::Relaxed)
    }

    /// Store the server-assigned role from an inbound `Capabilities` control
    /// message. `features` is reserved and intentionally not stored today.
    pub fn on_capabilities(&self, role: u8) {
        self.cached_role.store(role, Ordering::Relaxed);
    }

    /// Resolve the oneshot registered for `req_id` (if still pending) with
    /// `(status, body)`. An unknown/already-resolved `req_id` (timed out,
    /// duplicate response, or a response for a request this client never
    /// sent) is silently dropped — never panics.
    pub fn on_mgmt_response(&self, req_id: u32, status: u16, body: Vec<u8>) {
        let sender = self
            .pending
            .lock()
            .expect("mgmt pending mutex poisoned")
            .remove(&req_id);
        if let Some(tx) = sender {
            // The receiver may already be gone (e.g. `mgmt_call` timed out
            // just before this response landed) — that's a normal race, not
            // an error.
            let _ = tx.send((status, body));
        }
    }

    /// Issue an in-tunnel management API call and await the correlated
    /// `MgmtResponse`. `method`: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT (see
    /// `ControlPayload::MgmtRequest`). `path` is a curated REST-shaped path
    /// (e.g. "/api/v1/clients"); `body` is an optional JSON payload.
    /// `control_tx` is the caller's outbound control channel — the same one
    /// used for every other outbound control payload (keepalives,
    /// MaskFeedback, ...), so `MgmtRequest` rides the identical encrypted
    /// path. `timeout` bounds how long to wait for the response.
    ///
    /// Resolves to `(status, body)` on a timely response. Returns an error
    /// if the channel is closed or no response arrives within `timeout` — on
    /// timeout the pending entry is removed so a very late/duplicate
    /// response is dropped by `on_mgmt_response` instead of being
    /// misdelivered.
    pub async fn mgmt_call(
        &self,
        control_tx: &mpsc::Sender<ControlPayload>,
        method: u8,
        path: &str,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        let req_id = self.req_seq.fetch_add(1, Ordering::Relaxed);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("mgmt pending mutex poisoned")
            .insert(req_id, resp_tx);
        // Cancellation-safe cleanup: this future can be dropped at any
        // `.await` below (embedder-side `select!`/FFI timeout). Without a
        // Drop-guard the `pending` entry registered above would leak until
        // `reset()` — every error/cancel path funnels through this guard
        // instead of hand-removing in each branch. On the success path
        // `on_mgmt_response` has already removed the entry, so the guard's
        // extra remove is a harmless no-op.
        struct PendingCleanup {
            pending: Arc<Mutex<HashMap<u32, oneshot::Sender<(u16, Vec<u8>)>>>>,
            req_id: u32,
        }
        impl Drop for PendingCleanup {
            fn drop(&mut self) {
                if let Ok(mut pending) = self.pending.lock() {
                    pending.remove(&self.req_id);
                }
            }
        }
        let _cleanup = PendingCleanup {
            pending: self.pending.clone(),
            req_id,
        };

        let payload = ControlPayload::MgmtRequest {
            req_id,
            method,
            path: path.to_string(),
            body,
        };
        if let Err(e) = control_tx.send(payload).await {
            return Err(Error::Channel(e.to_string()));
        }

        match tokio::time::timeout(timeout, resp_rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => {
                // Sender side dropped without sending, which
                // `on_mgmt_response` never does — defensive guard only.
                Err(Error::Session(
                    "mgmt_call: response channel closed unexpectedly".into(),
                ))
            }
            Err(_) => Err(Error::Session(format!(
                "mgmt_call: timed out awaiting MgmtResponse for req_id={}",
                req_id
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_role_defaults_to_user_before_any_capabilities_message() {
        let mgmt = MgmtClient::new();
        assert_eq!(mgmt.cached_role(), 0);
    }

    #[test]
    fn on_capabilities_updates_cached_role() {
        let mgmt = MgmtClient::new();
        assert_eq!(mgmt.cached_role(), 0);
        mgmt.on_capabilities(2);
        assert_eq!(mgmt.cached_role(), 2);
    }

    #[test]
    fn reset_clears_pending_and_cached_role() {
        let mgmt = MgmtClient::new();
        mgmt.on_capabilities(2);
        let (resp_tx, _resp_rx) = oneshot::channel::<(u16, Vec<u8>)>();
        mgmt.pending.lock().unwrap().insert(1, resp_tx);

        mgmt.reset();

        assert_eq!(mgmt.cached_role(), 0);
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn on_mgmt_response_resolves_the_matching_pending_oneshot() {
        let mgmt = MgmtClient::new();
        let (resp_tx, mut resp_rx) = oneshot::channel::<(u16, Vec<u8>)>();
        mgmt.pending.lock().unwrap().insert(1, resp_tx);

        mgmt.on_mgmt_response(1, 200, b"{\"ok\":true}".to_vec());

        let (status, body) = resp_rx
            .try_recv()
            .expect("oneshot must resolve immediately once completed");
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"ok\":true}".to_vec());
        assert!(
            mgmt.pending.lock().unwrap().is_empty(),
            "completed entry must be removed from pending"
        );
    }

    #[test]
    fn mgmt_response_for_unknown_req_id_is_dropped_without_panic() {
        let mgmt = MgmtClient::new();
        // No req_id=42 was ever registered — must not panic, must be a no-op.
        mgmt.on_mgmt_response(42, 404, vec![]);
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mgmt_call_sends_request_and_resolves_on_matching_response() {
        let mgmt = MgmtClient::new();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);

        let pending = mgmt.pending.clone();
        let responder = tokio::spawn(async move {
            let sent = control_rx.recv().await.expect("MgmtRequest must be sent");
            match sent {
                ControlPayload::MgmtRequest {
                    req_id,
                    method,
                    path,
                    body,
                } => {
                    assert_eq!(method, 0);
                    assert_eq!(path, "/api/v1/clients");
                    assert!(body.is_empty());
                    if let Some(tx) = pending.lock().unwrap().remove(&req_id) {
                        let _ = tx.send((200, b"[]".to_vec()));
                    }
                }
                other => panic!("expected MgmtRequest, got {:?}", other),
            }
        });

        let (status, body) = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await
            .expect("mgmt_call must resolve once the response is delivered");

        responder.await.expect("responder task must not panic");
        assert_eq!(status, 200);
        assert_eq!(body, b"[]".to_vec());
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mgmt_call_times_out_when_no_response_arrives() {
        // Paused virtual time: `mgmt_call`'s `tokio::time::timeout`
        // auto-advances past its deadline as soon as the runtime is idle,
        // instead of the test waiting real seconds.
        tokio::time::pause();
        let mgmt = MgmtClient::new();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        // Drain the outbound MgmtRequest so the bounded channel never fills,
        // but never send a MgmtResponse back.
        let _drainer = tokio::spawn(async move {
            let _ = control_rx.recv().await;
        });

        let result = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await;

        assert!(
            result.is_err(),
            "mgmt_call must return an error when no MgmtResponse arrives within the timeout"
        );
        assert!(
            mgmt.pending.lock().unwrap().is_empty(),
            "the timed-out entry must be removed from pending, not leaked"
        );
    }

    #[tokio::test]
    async fn mgmt_call_dropped_mid_flight_cleans_up_pending_entry() {
        // Regression: an embedder can cancel (drop) the `mgmt_call` future
        // itself — external `select!`/FFI timeout — after the pending entry
        // was registered but before any response/timeout. The Drop-guard
        // must remove the entry, otherwise repeated cancellations grow
        // `pending` without bound until `reset()`.
        let mgmt = MgmtClient::new();
        let (control_tx, _control_rx) = mpsc::channel::<ControlPayload>(4);

        {
            let fut = mgmt.mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            );
            tokio::pin!(fut);
            // Poll the future exactly once: it registers the pending entry
            // and parks awaiting the response (`ready(())` wins the race).
            tokio::select! {
                biased;
                _ = &mut fut => panic!("mgmt_call must not resolve with no responder"),
                _ = std::future::ready(()) => {}
            }
            assert_eq!(
                mgmt.pending.lock().unwrap().len(),
                1,
                "the in-flight call must have registered its pending entry"
            );
            // `fut` is dropped here — cancelled mid-flight.
        }

        assert!(
            mgmt.pending.lock().unwrap().is_empty(),
            "a cancelled (dropped) mgmt_call must not leak its pending entry"
        );
    }

    #[tokio::test]
    async fn mgmt_call_late_response_after_timeout_is_dropped_not_misdelivered() {
        // Regression test for the race the P2.R task description calls out:
        // a response that arrives AFTER the timeout already removed the
        // pending entry must be silently dropped by `on_mgmt_response`, not
        // panic and not resolve a future, unrelated `mgmt_call` with the same
        // (reused) req_id.
        tokio::time::pause();
        let mgmt = MgmtClient::new();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        let req_id_holder: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let req_id_holder2 = req_id_holder.clone();
        let _drainer = tokio::spawn(async move {
            if let Some(ControlPayload::MgmtRequest { req_id, .. }) = control_rx.recv().await {
                *req_id_holder2.lock().unwrap() = Some(req_id);
            }
        });

        let result = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await;
        assert!(result.is_err());

        let req_id = req_id_holder.lock().unwrap().expect("req_id was captured");
        // Simulate the late response landing after the timeout already fired.
        mgmt.on_mgmt_response(req_id, 200, b"late".to_vec());
        // Must not panic; pending must still be empty (nothing to misdeliver
        // to — no receiver was resolved).
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mgmt_call_errors_immediately_when_channel_closed() {
        let mgmt = MgmtClient::new();
        let (control_tx, control_rx) = mpsc::channel::<ControlPayload>(4);
        drop(control_rx);

        let result = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await;
        assert!(result.is_err());
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }
}
