#![cfg(all(feature = "mobile-tunnel", unix))]

mod support;

use aivpn_common::mobile_tunnel::{
    run_tunnel_generic, PlatformIo, RecordingFeedback, HANDSHAKE_FAIL_STREAK,
};
use aivpn_common::{
    error::Result,
    transport::{DatagramTransport, TransportKind},
};
use std::{
    os::fd::AsRawFd,
    sync::{atomic::Ordering, Arc},
};

struct Platform;
impl PlatformIo for Platform {
    fn protect_socket(&self, _: std::os::fd::RawFd) -> Result<()> {
        unreachable!()
    }
    fn notify_ready(&self, _: &str) {}
    fn publish_recording_feedback(&self, _: RecordingFeedback) {}
}

struct FailingCarrier(bool);
#[async_trait::async_trait]
impl DatagramTransport for FailingCarrier {
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        if self.0 {
            Err(std::io::ErrorKind::TimedOut.into())
        } else {
            Ok(packet.len())
        }
    }
    async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::TimedOut.into())
    }
    fn kind(&self) -> TransportKind {
        TransportKind::Udp
    }
    fn max_datagram(&self) -> usize {
        65507
    }
}

#[tokio::test]
async fn carrier_errors_advance_handshake_fallback_streak() {
    let server = aivpn_common::crypto::KeyPair::generate();
    let (signing_key, descriptors) = support::signed_bootstrap();
    let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    for (index, send_fails) in [true, false, true].into_iter().enumerate() {
        let result = run_tunnel_generic(
            Platform,
            tun.as_raw_fd(),
            "unresolvable.invalid".into(),
            443,
            server.public_key_bytes(),
            Some([5; 32]),
            None,
            24,
            0,
            None,
            Some("webrtc_zoom_v3".into()),
            Some(signing_key),
            Some(signing_key),
            aivpn_common::mask::MaskVerifyMode::Enforce,
            None,
            false,
            false,
            None,
            None,
            Some(descriptors.clone()),
            Some(Arc::new(FailingCarrier(send_fails))),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            HANDSHAKE_FAIL_STREAK.load(Ordering::Relaxed),
            index as u32 + 1,
            "Ошибка внешней несущей должна учитываться до получения ServerHello"
        );
    }
}
