#![cfg(all(feature = "mobile-tunnel", unix))]

use aivpn_common::mobile_tunnel::{run_tunnel_generic, PlatformIo, RecordingFeedback};
use aivpn_common::{
    error::{Error, Result},
    transport::{DatagramTransport, TransportKind},
};
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct Platform(Arc<AtomicBool>);
impl PlatformIo for Platform {
    fn protect_socket(&self, _: std::os::fd::RawFd) -> Result<()> {
        self.0.store(true, Ordering::SeqCst);
        Err(Error::Session("Прямой сокет запрещен".into()))
    }
    fn notify_ready(&self, _: &str) {}
    fn publish_recording_feedback(&self, _: RecordingFeedback) {}
}

struct Carrier(Arc<AtomicBool>);
#[async_trait::async_trait]
impl DatagramTransport for Carrier {
    async fn send(&self, _: &[u8]) -> std::io::Result<usize> {
        self.0.store(true, Ordering::SeqCst);
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "carrier reached",
        ))
    }
    async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
        std::future::pending().await
    }
    fn kind(&self) -> TransportKind {
        TransportKind::Udp
    }
    fn max_datagram(&self) -> usize {
        65507
    }
}

#[tokio::test]
async fn alternative_mobile_transport_needs_neither_server_dns_nor_direct_udp() {
    let direct = Arc::new(AtomicBool::new(false));
    let reached = Arc::new(AtomicBool::new(false));
    let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let server = aivpn_common::crypto::KeyPair::generate();
    let outcome = run_tunnel_generic(
        Platform(direct.clone()),
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
        Some([7; 32]),
        Some([9; 32]),
        aivpn_common::mask::MaskVerifyMode::Enforce,
        None,
        false,
        false,
        None,
        None,
        None,
        Some(Arc::new(Carrier(reached.clone()))),
    )
    .await;
    assert!(outcome.is_err());
    assert!(reached.load(Ordering::SeqCst), "{outcome:?}");
    assert!(!direct.load(Ordering::SeqCst));
}
