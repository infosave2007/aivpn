//! Shared upload-task packet encryptor for the mobile tunnels (hoisted
//! verbatim from `android_tunnel.rs`'s `MobileEncryptor`, renamed
//! `MobileEncryptor`; the iOS nested `IosEncryptor` was logic-identical).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::crypto::SessionKeys;
use crate::error::Result;
use crate::mimicry::MimicryEncryptor;
use crate::protocol::ControlPayload;
use crate::upload_pipeline::PacketEncryptor;

use super::state::SessionRuntime;

// ──────────── Upload-task packet encryptor ────────────

/// FIFO of one-shot acknowledgements for in-flight `KeyRotate` responses.
///
/// The receive-loop rekey handler pushes a sender here *before* enqueueing its
/// `KeyRotate` response on the upload control channel, then blocks on the paired
/// receiver until the upload task's single encryptor has actually encrypted that
/// response (see [`MobileEncryptor::encrypt_control`]). Only after that ack does
/// the handler stage the new keys for the TX path (run_loop's
/// `pending_upload_keys`, promoted on the server's commit proof), guaranteeing
/// the response is never encrypted with a key the server has not yet installed.
pub type RekeyAckQueue = Arc<Mutex<VecDeque<oneshot::Sender<()>>>>;

/// One-shot old-key override for a RE-SENT `KeyRotate` response.
///
/// When the server retransmits a KeyRotate (our first response was lost), the
/// receive loop stages the OLD keys here before enqueueing the SAME response
/// again: `encrypt_control` swaps them in for that one packet — the server is
/// still on them — then restores whatever keys were live before the swap.
/// Restoring the LIVE keys (rather than a restore target staged alongside the
/// override) is what keeps this correct with staged TX promotion: while the
/// rekey commit is unconfirmed the live keys ARE the old keys (restore is a
/// no-op), and only after the promote do they become the new keys. The send
/// counter is shared and MONOTONIC across both keys, so the temporary swap
/// can never reuse a (key, nonce) pair. Consumed only by KeyRotate payloads;
/// the initial-response path never sets it (mirrors the desktop client.rs
/// upload-key swap/restore rendezvous).
pub type RekeyResendSlot = Arc<Mutex<Option<SessionKeys>>>;

/// Upload-side [`PacketEncryptor`] for Android: wraps a [`MimicryEncryptor`] and
/// owns the single send counter for the session. All steady-state outbound
/// packets (data, keepalive, control) go through this one encryptor so no two
/// senders ever reuse a ChaCha20-Poly1305 nonce under the same session key.
pub struct MobileEncryptor {
    pub inner: MimicryEncryptor,
    pub session: Arc<SessionRuntime>,
    pub keepalive_sent_ms: Arc<AtomicU64>,
    pub key_rotate_slot: Arc<Mutex<Option<SessionKeys>>>,
    pub rekey_ack: RekeyAckQueue,
    pub rekey_resend_keys: RekeyResendSlot,
}

impl MobileEncryptor {
    fn check_key_rotation(&mut self) {
        if let Some(new_keys) = self
            .key_rotate_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            self.inner.update_keys(new_keys);
        }
    }
}

impl PacketEncryptor for MobileEncryptor {
    fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.check_key_rotation();
        self.inner.encrypt_data(payload)
    }

    fn encrypt_control(&mut self, payload: &ControlPayload) -> Result<Vec<u8>> {
        // A KeyRotate response must go out under the pre-rotation keys, so a
        // pending rotation is deliberately NOT applied to it (the receive loop
        // only publishes the new keys into `key_rotate_slot` after we ack).
        // Every OTHER control packet applies the rotation like encrypt_data —
        // a data-idle session (only keepalives/quality reports flowing) must
        // still migrate the upload encryptor off the stale keys.
        let is_rotate = matches!(payload, ControlPayload::KeyRotate { .. });
        if !is_rotate {
            self.check_key_rotation();
        }
        // A RE-SENT response (server retransmitted KeyRotate because our first
        // response was lost) must go out under the PREVIOUS keys the server can
        // still read: swap them in for this one packet, then restore the keys
        // that were live before the swap. While the rekey commit is still
        // unconfirmed (staged TX switch — see run_loop's `pending_upload_keys`)
        // the live keys ARE the old keys, so the restore is a no-op and TX
        // stays on them; after the promote the live keys are the new ones.
        // The shared monotonic send counter makes the old-key send nonce-safe.
        let restore = if is_rotate {
            self.rekey_resend_keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .map(|old_keys| {
                    let live_keys = self.inner.current_keys();
                    self.inner.update_keys(old_keys);
                    live_keys
                })
        } else {
            None
        };
        let pkt = self.inner.encrypt_control(payload);
        if let Some(live_keys) = restore {
            self.inner.update_keys(live_keys);
        }
        let pkt = pkt?;
        if is_rotate {
            if let Some(ack) = self
                .rekey_ack
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
            {
                let _ = ack.send(());
            }
        }
        Ok(pkt)
    }

    fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
        // Apply a pending rotation here too: a session sending ONLY keepalives
        // otherwise strands the upload encryptor on pre-rekey keys until the
        // next data packet.
        self.check_key_rotation();
        let now_ms = crate::crypto::current_timestamp_ms();
        self.keepalive_sent_ms.store(now_ms, Ordering::Relaxed);
        self.inner.encrypt_keepalive_ts(now_ms)
    }

    fn on_data_sent(&mut self, payload_len: usize) {
        self.session
            .upload_bytes
            .fetch_add(payload_len as u64, Ordering::Relaxed);
    }

    fn take_fec_repair(&mut self) -> Option<Vec<u8>> {
        self.inner.take_fec_repair()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_session_keys, KeyPair};

    fn make_keys(tag: u8) -> SessionKeys {
        let ckp = KeyPair::generate();
        let skp = KeyPair::generate();
        let dh = ckp.compute_shared(&skp.public_key_bytes()).unwrap();
        derive_session_keys(&dh, Some(&[tag; 32]), &ckp.public_key_bytes())
    }

    fn make_encryptor(
        old_keys: SessionKeys,
        slot: Arc<Mutex<Option<SessionKeys>>>,
        ack: RekeyAckQueue,
    ) -> MobileEncryptor {
        MobileEncryptor {
            inner: MimicryEncryptor::new(
                old_keys,
                0,
                0,
                crate::mimicry::bootstrap_mask_for_psk(None),
                Arc::new(Mutex::new(None)),
            ),
            session: Arc::new(SessionRuntime::new()),
            keepalive_sent_ms: Arc::new(AtomicU64::new(0)),
            key_rotate_slot: slot,
            rekey_ack: ack,
            rekey_resend_keys: Arc::new(Mutex::new(None)),
        }
    }

    /// Regression: a `KeyRotate` response must be encrypted with the PRE-rotation
    /// keys and must fire the rekey ack, even when a rotation is already queued in
    /// `key_rotate_slot`. `encrypt_control` must NOT consume that pending rotation
    /// (proving the response used the old keys); only a later `encrypt_data` applies
    /// it. This is the invariant that lets the receive-loop handler safely switch
    /// keys only after the ack.
    #[tokio::test]
    async fn key_rotate_response_uses_pre_rotation_keys_and_acks() {
        let old_keys = make_keys(1);
        let new_keys = make_keys(2);
        let slot: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(Some(new_keys)));
        let ack_q: RekeyAckQueue = Arc::new(Mutex::new(VecDeque::new()));
        let (ack_tx, ack_rx) = oneshot::channel();
        ack_q.lock().unwrap().push_back(ack_tx);

        let mut enc = make_encryptor(old_keys, slot.clone(), ack_q.clone());

        let resp = ControlPayload::KeyRotate {
            new_eph_pub: [7u8; 32],
        };
        let _pkt = enc.encrypt_control(&resp).expect("encrypt_control");

        assert!(
            ack_rx.await.is_ok(),
            "encrypt_control must fire the rekey ack so the handler can proceed"
        );
        assert!(
            slot.lock().unwrap().is_some(),
            "encrypt_control must NOT apply the pending key rotation (response used old keys)"
        );

        let _ = enc.encrypt_data(b"hello world").expect("encrypt_data");
        assert!(
            slot.lock().unwrap().is_none(),
            "encrypt_data must apply the pending key rotation"
        );
    }

    /// A re-sent `KeyRotate` response must consume the one-shot old-key override
    /// (so it is encrypted under the PREVIOUS keys the server can still read)
    /// and still fire the rekey ack; a non-KeyRotate control payload must leave
    /// the override untouched.
    #[tokio::test]
    async fn keyrotate_resend_consumes_old_key_override_and_acks() {
        let old_keys = make_keys(1);
        let current_keys = make_keys(2);
        let slot: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(None));
        let ack_q: RekeyAckQueue = Arc::new(Mutex::new(VecDeque::new()));
        let (ack_tx, ack_rx) = oneshot::channel();
        ack_q.lock().unwrap().push_back(ack_tx);

        let mut enc = make_encryptor(current_keys.clone(), slot, ack_q.clone());
        *enc.rekey_resend_keys.lock().unwrap() = Some(old_keys);

        // A non-KeyRotate control payload must NOT consume the override.
        let qr = ControlPayload::QualityReport {
            quality: 90,
            rtt_ms: 10,
            loss_ppm: 0,
            jitter_ms: 1,
        };
        let _ = enc.encrypt_control(&qr).expect("encrypt_control");
        assert!(
            enc.rekey_resend_keys.lock().unwrap().is_some(),
            "non-KeyRotate control must leave the old-key override staged"
        );

        let resp = ControlPayload::KeyRotate {
            new_eph_pub: [7u8; 32],
        };
        let _ = enc.encrypt_control(&resp).expect("encrypt_control");
        assert!(
            enc.rekey_resend_keys.lock().unwrap().is_none(),
            "KeyRotate must consume the one-shot old-key override"
        );
        assert!(
            ack_rx.await.is_ok(),
            "the re-sent response must still fire the rekey ack"
        );
    }

    /// A non-`KeyRotate` control payload (e.g. `QualityReport`) must never consume
    /// a queued rekey ack — otherwise a QualityReport riding the same control
    /// channel would spuriously unblock a rekey handler.
    #[test]
    fn non_keyrotate_control_does_not_fire_ack() {
        let old_keys = make_keys(1);
        let slot: Arc<Mutex<Option<SessionKeys>>> = Arc::new(Mutex::new(None));
        let ack_q: RekeyAckQueue = Arc::new(Mutex::new(VecDeque::new()));
        let (ack_tx, mut ack_rx) = oneshot::channel();
        ack_q.lock().unwrap().push_back(ack_tx);

        let mut enc = make_encryptor(old_keys, slot, ack_q.clone());
        let qr = ControlPayload::QualityReport {
            quality: 90,
            rtt_ms: 10,
            loss_ppm: 0,
            jitter_ms: 1,
        };
        let _ = enc.encrypt_control(&qr).expect("encrypt_control");

        assert_eq!(
            ack_q.lock().unwrap().len(),
            1,
            "non-KeyRotate control must leave the rekey ack queued"
        );
        assert!(matches!(
            ack_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
}
