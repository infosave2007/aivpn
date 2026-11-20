#![cfg(all(feature = "mobile-tunnel", unix))]

mod support;

use aivpn_common::mobile_tunnel::{
    run_tunnel_generic, stop_active_tunnel, PlatformIo, RecordingFeedback,
};
use aivpn_common::{
    error::Result,
    transport::{DatagramTransport, TransportKind},
};
use std::{
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct Platform;
impl PlatformIo for Platform {
    fn protect_socket(&self, _: std::os::fd::RawFd) -> Result<()> {
        unreachable!()
    }
    fn notify_ready(&self, _: &str) {}
    fn publish_recording_feedback(&self, _: RecordingFeedback) {}
}

struct BlockedCarrier {
    entered: Arc<tokio::sync::Notify>,
    successful_sends: AtomicUsize,
}
#[async_trait::async_trait]
impl DatagramTransport for BlockedCarrier {
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        if self
            .successful_sends
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Ok(packet.len());
        }
        self.entered.notify_one();
        std::future::pending().await
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

async fn stop_blocked_attempt(successful_sends: usize) {
    let entered = Arc::new(tokio::sync::Notify::new());
    let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let server = aivpn_common::crypto::KeyPair::generate();
    let (signing_key, descriptors) = support::signed_bootstrap();
    let attempt = run_tunnel_generic(
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
        Some(Arc::new(BlockedCarrier {
            entered: entered.clone(),
            successful_sends: AtomicUsize::new(successful_sends),
        })),
    );
    tokio::pin!(attempt);
    tokio::select! {
        result = &mut attempt => panic!("Попытка завершилась до остановки: {result:?}"),
        _ = entered.notified() => {},
        _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => panic!("Отправка не началась"),
    }
    stop_active_tunnel();
    let result = tokio::time::timeout(std::time::Duration::from_millis(200), &mut attempt).await;
    assert!(
        result.is_ok(),
        "Остановка ждет отправку в заблокированный транспорт"
    );
    assert!(result.unwrap().is_ok());
    assert_eq!(
        aivpn_common::mobile_tunnel::HANDSHAKE_FAIL_STREAK.load(Ordering::Relaxed),
        0,
        "Остановка пользователем не является отказом маски"
    );
}

#[tokio::test]
async fn stop_interrupts_blocked_initial_and_retry_sends() {
    for successful_sends in [0, 1] {
        stop_blocked_attempt(successful_sends).await;
    }
}
