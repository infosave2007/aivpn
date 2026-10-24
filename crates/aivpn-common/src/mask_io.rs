//! Состояние маски между шифрованием AIVPN и неизменным транспортом.
//!
//! Здесь нет нового транспортного режима: сокеты, socket guard и тип
//! транспорта принадлежат вызывающему коду. Протокольный движок маски
//! получает пакеты и таймеры, а затем возвращает готовые UDP payload.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::error::{Error, Result};
use crate::mask::{MaskProfile, SpoofProtocol};
use crate::mask_state::MaskState;
use crate::quic_mask::QuicMask;
use crate::rtc_carrier::{RtcCarrier as RtcMask, RtcKind};
use crate::transport::{DatagramTransport, TransportKind};

/// Вместе с заголовками QUIC/H3 помещается в начальные 1200 байт UDP.
pub const MAX_QUIC_INNER: usize = 1140;
pub const QUIC_WIRE_BUDGET: usize = 1380;
const QUEUE: usize = 64;

#[derive(Default)]
struct WireSamples {
    enabled: AtomicBool,
    packets: std::sync::Mutex<VecDeque<Vec<u8>>>,
}

impl WireSamples {
    fn record(&self, packet: &[u8]) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let mut packets = self
            .packets
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if packets.len() == QUEUE {
            packets.pop_front();
        }
        packets.push_back(packet.to_vec());
    }
}

pub fn needs_state(mask: &MaskProfile) -> bool {
    mask.spoof_protocol == SpoofProtocol::QUIC
}

pub fn uses_rtc(mask: &MaskProfile) -> bool {
    matches!(
        mask.spoof_protocol,
        SpoofProtocol::WebRTC_DTLS_SRTP
            | SpoofProtocol::WebRTC_TURN_DTLS_SRTP
            | SpoofProtocol::WebRTC_SDES_SRTP
    )
}

pub fn turn_realm(mask: &MaskProfile) -> Option<&'static str> {
    (mask.spoof_protocol == SpoofProtocol::WebRTC_TURN_DTLS_SRTP).then_some(
        match crate::mask::base_mask_family(&mask.mask_id).as_str() {
            "webrtc_sberjazz_v1" => "salutejazz.ru",
            "telegram_calls_v1" => "telegram.org",
            _ => "turn",
        },
    )
}

pub fn rtc_inner_budget(mask: &MaskProfile) -> usize {
    if mask.spoof_protocol == SpoofProtocol::WebRTC_SDES_SRTP {
        return crate::srtp_mask::MAX_INNER;
    }
    crate::rtc_mask::inner_budget(turn_realm(mask).is_some())
}

pub fn carrier_overhead(mask: &MaskProfile) -> usize {
    if !uses_rtc(mask) {
        0
    } else if mask.spoof_protocol == SpoofProtocol::WebRTC_SDES_SRTP {
        (crate::srtp_mask::OVERHEAD + 3) / 4 * 4
    } else {
        crate::rtc_mask::carrier_overhead(turn_realm(mask).is_some())
    }
}

pub fn requires_userspace(mask: &MaskProfile) -> bool {
    needs_state(mask) || uses_rtc(mask)
}

enum Command {
    Send(Vec<u8>, u8, bool, u64, oneshot::Sender<io::Result<usize>>),
    RtcOffer(
        String,
        u16,
        RtcKind,
        oneshot::Sender<Result<Option<MaskState>>>,
    ),
    RtcAnswer(MaskState, oneshot::Sender<Result<()>>),
    Close(oneshot::Sender<()>),
}

struct ClientMaskIo {
    raw: Arc<dyn DatagramTransport>,
    commands: mpsc::Sender<Command>,
    received: Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>,
    task: tokio::task::AbortHandle,
    stateful: AtomicBool,
    rtc: AtomicBool,
    rtc_inner_limit: AtomicUsize,
    rtc_ready: Arc<AtomicBool>,
    started: AtomicBool,
    samples: Arc<WireSamples>,
    mask_generation: Arc<AtomicU64>,
    mask_key: std::sync::Mutex<(String, u16, [u8; 64])>,
}

impl Drop for ClientMaskIo {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Один адаптер движка масок для всех реализаций транспорта и клиентов.
pub fn client(
    raw: Arc<dyn DatagramTransport>,
    mask: &MaskProfile,
    peer: SocketAddr,
    server_name: String,
) -> Result<Arc<dyn DatagramTransport>> {
    if requires_userspace(mask) && raw.max_datagram() < QUIC_WIRE_BUDGET {
        return Err(Error::Session(
            "Транспорт не вмещает пакет выбранной маски".into(),
        ));
    }
    let (tx, rx) = mpsc::channel(QUEUE);
    let (received_tx, received_rx) = mpsc::channel(QUEUE);
    let underlying = raw.clone();
    let samples = Arc::new(WireSamples::default());
    let driver_samples = samples.clone();
    let rtc_ready = Arc::new(AtomicBool::new(false));
    let driver_rtc_ready = rtc_ready.clone();
    let mask_generation = Arc::new(AtomicU64::new(0));
    let driver_generation = mask_generation.clone();
    let task = tokio::spawn(async move {
        let outcome = drive_client(
            underlying.clone(),
            rx,
            received_tx.clone(),
            peer,
            server_name,
            driver_samples,
            driver_rtc_ready,
            driver_generation,
        )
        .await;
        if let Err(error) = outcome {
            let _ = received_tx.try_send(Err(io::Error::other(error.to_string())));
        }
        let _ = underlying.close().await;
    });
    Ok(Arc::new(ClientMaskIo {
        raw,
        commands: tx,
        received: Mutex::new(received_rx),
        task: task.abort_handle(),
        stateful: AtomicBool::new(needs_state(mask)),
        rtc: AtomicBool::new(uses_rtc(mask)),
        rtc_inner_limit: AtomicUsize::new(rtc_inner_budget(mask)),
        rtc_ready,
        started: AtomicBool::new(false),
        samples,
        mask_generation,
        mask_key: std::sync::Mutex::new((mask.mask_id.clone(), mask.version, mask.signature)),
    }))
}

async fn drive_client(
    raw: Arc<dyn DatagramTransport>,
    mut commands: mpsc::Receiver<Command>,
    received: mpsc::Sender<io::Result<Vec<u8>>>,
    peer: SocketAddr,
    server_name: String,
    samples: Arc<WireSamples>,
    rtc_ready: Arc<AtomicBool>,
    mask_generation: Arc<AtomicU64>,
) -> Result<()> {
    let mut engine: Option<QuicMask> = None;
    let mut rtc: Option<RtcMask> = None;
    let mut offer: Option<MaskState> = None;
    let mut rtc_generation = 0;
    let mut buffer = vec![0; 65536];
    loop {
        let deadline = rtc
            .as_mut()
            .and_then(RtcMask::deadline)
            .or_else(|| engine.as_mut().and_then(QuicMask::deadline));
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Send(payload, mode, data, generation, response)) => {
                    if generation != mask_generation.load(Ordering::Acquire)
                        || (data && mode == 2 && (rtc_generation != generation || rtc.as_ref().is_none_or(|rtc| !rtc.connected())))
                    {
                        let _ = response.send(Err(io::ErrorKind::WouldBlock.into()));
                        continue;
                    }
                    let result = if mode == 2 {
                        match rtc.as_mut() {
                            Some(rtc) => match rtc.send(&payload, Instant::now()) {
                                Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock && !rtc.connected() => {
                                    raw.send(&payload).await.map(|_| samples.record(&payload)).map_err(Error::Io)
                                }
                                result => result,
                            },
                            None => raw.send(&payload).await.map(|_| samples.record(&payload)).map_err(Error::Io),
                        }
                    } else if mode == 0 {
                        rtc = None;
                        offer = None;
                        if let Some(mut previous) = engine.take() {
                            for packet in previous.close(Instant::now())? {
                                if raw.send(&packet).await.is_ok() { samples.record(&packet); }
                            }
                        }
                        engine = None;
                        raw.send(&payload).await.map(|_| samples.record(&payload)).map_err(Error::Io)
                    } else if let Some(engine) = engine.as_mut() {
                        engine.send(&payload)
                    } else {
                        rtc = None;
                        offer = None;
                        QuicMask::client(&payload, peer, &server_name, Instant::now())
                            .map(|created| engine = Some(created))
                    };
                    match result {
                        Ok(()) => { let _ = response.send(Ok(payload.len())); }
                        Err(error) => {
                            let error = match error { Error::Io(error) => error, other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()) };
                            let _ = response.send(Err(error));
                        }
                    }
                }
                Some(Command::RtcOffer(mask_id, mask_version, kind, response)) => {
                    let proposed_generation = mask_generation.load(Ordering::Acquire);
                    let result = if let Some(previous) = offer.as_ref()
                        .filter(|previous| rtc_generation == proposed_generation && previous.mask_id == mask_id && previous.mask_version == mask_version) {
                        Ok(if rtc.as_ref().is_some_and(RtcMask::connected) { None } else { Some(previous.clone()) })
                    } else {
                        let local = raw.local_addr().filter(|address| !address.ip().is_unspecified())
                            .unwrap_or_else(|| if peer.is_ipv4() { "192.0.2.1:10000" } else { "[2001:db8::1]:10000" }.parse().unwrap());
                        let created = RtcMask::create(kind, false, local, peer, peer, Instant::now());
                        created.map(|created| {
                            let state = MaskState { offer_id: rand::random(), answer: false,
                                mask_id, mask_version, parameters: created.parameters() };
                            rtc = Some(created);
                            rtc_ready.store(false, Ordering::Release);
                            engine = None;
                            offer = Some(state.clone());
                            Some(state)
                        })
                    };
                    if result.is_ok() { rtc_generation = proposed_generation; }
                    let _ = response.send(result);
                }
                Some(Command::RtcAnswer(answer, response)) => {
                    let result = if answer.answer && offer.as_ref().is_some_and(|current|
                        current.offer_id == answer.offer_id && current.mask_id == answer.mask_id &&
                        current.mask_version == answer.mask_version) {
                        rtc.as_mut().ok_or(Error::InvalidPacket("Нет предложения RTC"))
                            .and_then(|rtc| rtc.negotiate(&answer.parameters, Instant::now()))
                    } else { Err(Error::InvalidPacket("Ответ RTC не соответствует предложению")) };
                    let _ = response.send(result);
                }
                Some(Command::Close(response)) => {
                    if let Some(mut previous) = engine.take() {
                        for packet in previous.close(Instant::now())? {
                            if raw.send(&packet).await.is_ok() { samples.record(&packet); }
                        }
                    }
                    let _ = response.send(());
                    return Ok(());
                },
                None => return Ok(()),
            },
            packet = raw.recv(&mut buffer) => {
                let length = match packet {
                    Ok(0) => continue,
                    Ok(length) => length,
                    Err(error) if transient(&error) => {
                        // Не крутим CPU, если внешний адаптер повторяет ошибку
                        // немедленно, а не ожидает готовность своего сокета.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    },
                    Err(error) => return Err(error.into()),
                };
                if let Some(rtc) = rtc.as_mut().filter(|_| crate::rtc_mask::is_wire_packet(&buffer[..length])) {
                    rtc.receive(&buffer[..length], Instant::now())?;
                } else if let Some(engine) = engine.as_mut().filter(|_| buffer[0] & 0x40 != 0) {
                    engine.receive(&buffer[..length], peer, Instant::now())?;
                } else if received.try_send(Ok(buffer[..length].to_vec())).is_err() && received.is_closed() {
                    return Ok(());
                }
            }
            _ = async {
                if let Some(deadline) = deadline {
                    tokio::time::sleep_until(deadline.into()).await;
                } else { std::future::pending::<()>().await; }
            } => {}
        }
        if let Some(rtc) = rtc.as_mut() {
            let output = rtc.poll(Instant::now())?;
            rtc_ready.store(
                output.connected && rtc_generation == mask_generation.load(Ordering::Acquire),
                Ordering::Release,
            );
            for packet in output.wire {
                match raw.send(&packet).await {
                    Ok(_) => samples.record(&packet),
                    Err(error) if transient(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            for payload in output.payloads {
                if received.try_send(Ok(payload)).is_err() && received.is_closed() {
                    return Ok(());
                }
            }
        }
        if let Some(engine) = engine.as_mut() {
            let output = engine.poll(Instant::now())?;
            for packet in output.wire {
                if packet.len() > QUIC_WIRE_BUDGET {
                    return Err(Error::InvalidPacket("Движок маски превысил бюджет UDP"));
                }
                match raw.send(&packet).await {
                    Ok(_) => samples.record(&packet),
                    Err(error)
                        if transient(&error)
                            || crate::quic_mask::mtu_probe_error(&error, packet.len()) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            for payload in output.payloads {
                // Как в UDP, перегрузка приемника не раздувает память и не
                // блокирует ACK и таймеры протокольного движка.
                if received.try_send(Ok(payload)).is_err() && received.is_closed() {
                    return Ok(());
                }
            }
        }
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::TimedOut
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::PermissionDenied
    )
}

impl ClientMaskIo {
    async fn send_packet(&self, datagram: &[u8], data: bool) -> io::Result<usize> {
        let (stateful, rtc, limit, generation) = {
            let _selection = self
                .mask_key
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let stateful = self.stateful.load(Ordering::Acquire);
            let rtc = self.rtc.load(Ordering::Acquire);
            let limit = if rtc {
                self.rtc_inner_limit.load(Ordering::Acquire)
            } else {
                MAX_QUIC_INNER
            };
            (
                stateful,
                rtc,
                limit,
                self.mask_generation.load(Ordering::Acquire),
            )
        };
        if (stateful || rtc)
            && (datagram.len() > limit || self.raw.max_datagram() < QUIC_WIRE_BUDGET)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Пакет не вмещается в маску",
            ));
        }
        let (response, wait) = oneshot::channel();
        self.commands
            .send(Command::Send(
                datagram.to_vec(),
                if rtc { 2 } else { u8::from(stateful) },
                data,
                generation,
                response,
            ))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Движок маски остановлен"))?;
        let result = wait
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Движок маски остановлен"))?;
        if result.is_ok() && stateful && self.stateful.load(Ordering::Acquire) {
            self.started.store(true, Ordering::Release);
        }
        result
    }
}

#[async_trait]
impl DatagramTransport for ClientMaskIo {
    async fn send(&self, datagram: &[u8]) -> io::Result<usize> {
        self.send_packet(datagram, false).await
    }
    async fn send_data(&self, datagram: &[u8]) -> io::Result<usize> {
        self.send_packet(datagram, true).await
    }
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let payload = self.received.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "Движок маски остановлен")
        })??;
        if payload.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Недостаточный буфер приема",
            ));
        }
        buffer[..payload.len()].copy_from_slice(&payload);
        Ok(payload.len())
    }
    fn kind(&self) -> TransportKind {
        self.raw.kind()
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.raw.peer_addr()
    }
    fn local_addr(&self) -> Option<SocketAddr> {
        self.raw.local_addr()
    }
    fn max_datagram(&self) -> usize {
        if self.rtc.load(Ordering::Acquire) {
            self.rtc_inner_limit.load(Ordering::Acquire)
        } else if self.stateful.load(Ordering::Acquire) {
            MAX_QUIC_INNER
        } else {
            self.raw.max_datagram()
        }
    }
    fn set_mask_profile(&self, mask: &MaskProfile) {
        let mut selected = self
            .mask_key
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if selected.0 != mask.mask_id || selected.1 != mask.version || selected.2 != mask.signature
        {
            *selected = (mask.mask_id.clone(), mask.version, mask.signature);
            self.mask_generation.fetch_add(1, Ordering::AcqRel);
            self.rtc_ready.store(false, Ordering::Release);
        }
        let limit = rtc_inner_budget(mask);
        if self.rtc_inner_limit.swap(limit, Ordering::AcqRel) != limit {
            self.rtc_ready.store(false, Ordering::Release);
        }
        let rtc = uses_rtc(mask);
        if self.rtc.swap(rtc, Ordering::AcqRel) != rtc {
            self.rtc_ready.store(false, Ordering::Release);
        }
        let stateful = needs_state(mask);
        if self.stateful.swap(stateful, Ordering::AcqRel) != stateful {
            self.started.store(false, Ordering::Release);
        }
    }
    fn needs_mask_bootstrap(&self) -> bool {
        self.stateful.load(Ordering::Acquire) && !self.started.load(Ordering::Acquire)
    }
    fn mask_data_ready(&self) -> bool {
        !self.rtc.load(Ordering::Acquire) || self.rtc_ready.load(Ordering::Acquire)
    }
    async fn mask_state_offer(&self, mask: &MaskProfile) -> Result<Option<MaskState>> {
        if !uses_rtc(mask) {
            return Ok(None);
        }
        let (response, wait) = oneshot::channel();
        self.commands
            .send(Command::RtcOffer(
                mask.mask_id.clone(),
                mask.version,
                RtcKind::from_mask(mask)?,
                response,
            ))
            .await
            .map_err(|_| Error::Session("Движок маски остановлен".into()))?;
        wait.await
            .map_err(|_| Error::Session("Движок маски остановлен".into()))?
    }
    async fn accept_mask_state(&self, state: &MaskState) -> Result<()> {
        if !self.rtc.load(Ordering::Acquire) {
            return Err(Error::InvalidPacket("RTC-профиль не выбран"));
        }
        let (response, wait) = oneshot::channel();
        self.commands
            .send(Command::RtcAnswer(state.clone(), response))
            .await
            .map_err(|_| Error::Session("Движок маски остановлен".into()))?;
        wait.await
            .map_err(|_| Error::Session("Движок маски остановлен".into()))?
    }
    fn observe_wire(&self) {
        self.samples.enabled.store(true, Ordering::Release);
    }
    fn take_wire_samples(&self) -> Option<Vec<Vec<u8>>> {
        Some(
            self.samples
                .packets
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .drain(..)
                .collect(),
        )
    }
    #[cfg(unix)]
    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        if self.stateful.load(Ordering::Acquire) || self.rtc.load(Ordering::Acquire) {
            None
        } else {
            self.raw.raw_fd()
        }
    }
    async fn close(&self) -> Result<()> {
        let (response, wait) = oneshot::channel();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), async {
            self.commands.send(Command::Close(response)).await.ok()?;
            wait.await.ok()
        })
        .await;
        self.task.abort();
        self.raw.close().await
    }
    // Для QUIC raw_fd скрыт: ядро не реализует протокол маски.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_turn_profiles_preserve_the_base_realm() {
        for id in ["webrtc_sberjazz_v1", "telegram_calls_v1"] {
            let mut mask = crate::mask::preset_masks::by_id(id).unwrap();
            let expected = turn_realm(&mask);
            assert_ne!(expected, Some("turn"));
            for derived in [
                format!("polymorphic:{id}:abcd"),
                format!("bootstrap:epoch-1:{id}:0:abcd"),
            ] {
                mask.mask_id = derived;
                assert_eq!(turn_realm(&mask), expected);
            }
        }
    }

    #[tokio::test]
    async fn a_changed_signature_requires_a_new_rtc_offer_generation() {
        let mut mask = crate::mask::preset_masks::webrtc_zoom_v3();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp.connect(address).await.unwrap();
        let masked = client(
            crate::transport::udp_transport(udp),
            &mask,
            address,
            "localhost".into(),
        )
        .unwrap();
        let old = masked.mask_state_offer(&mask).await.unwrap().unwrap();
        assert_eq!(
            masked
                .mask_state_offer(&mask)
                .await
                .unwrap()
                .unwrap()
                .offer_id,
            old.offer_id
        );
        mask.signature[0] ^= 1;
        masked.set_mask_profile(&mask);
        let current = masked.mask_state_offer(&mask).await.unwrap().unwrap();
        assert_ne!(old.offer_id, current.offer_id);
        assert!(!masked.mask_data_ready());
        assert!(masked
            .accept_mask_state(&MaskState {
                answer: true,
                ..old
            })
            .await
            .is_err());
        masked.close().await.unwrap();
    }

    #[tokio::test]
    async fn rtc_data_never_uses_bootstrap_when_media_is_pending() {
        let mask = crate::mask::preset_masks::webrtc_zoom_v3();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp.connect(address).await.unwrap();
        let masked = client(
            crate::transport::udp_transport(udp),
            &mask,
            address,
            "localhost".into(),
        )
        .unwrap();
        masked.mask_state_offer(&mask).await.unwrap();
        // Готовность могла измениться после проверки uploader. Актор обязан
        // отличать DATA от control и не использовать bootstrap для данных.
        let result = masked.send_data(b"encrypted IP packet").await;
        assert!(result.is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
        assert!(peer.try_recv(&mut [0; 2048]).is_err());
        masked.send(b"bootstrap control").await.unwrap();
        let mut received = [0; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), peer.recv(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..n], b"bootstrap control");
        masked.close().await.unwrap();
    }

    #[tokio::test]
    async fn queued_send_from_previous_mask_generation_is_discarded() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp.connect(address).await.unwrap();
        let (tx, rx) = mpsc::channel(QUEUE);
        let (received, _received_rx) = mpsc::channel(QUEUE);
        let task = tokio::spawn(drive_client(
            crate::transport::udp_transport(udp),
            rx,
            received,
            address,
            "localhost".into(),
            Arc::new(WireSamples::default()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(1)),
        ));
        let (response, wait) = oneshot::channel();
        tx.send(Command::Send(
            b"old encrypted data".to_vec(),
            0,
            true,
            0,
            response,
        ))
        .await
        .unwrap();
        assert!(wait
            .await
            .unwrap()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
        assert!(peer.try_recv(&mut [0; 2048]).is_err());
        task.abort();
    }

    #[tokio::test]
    async fn whatsapp_uses_typed_srtp_signaling_without_dtls_fingerprint() {
        let mask = crate::mask::preset_masks::by_id("whatsapp_voip_v1").unwrap();
        assert!(
            uses_rtc(&mask),
            "WhatsApp не должен оставаться STUN-заголовком"
        );
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp.connect(address).await.unwrap();
        let masked = client(
            crate::transport::udp_transport(udp),
            &mask,
            address,
            "localhost".into(),
        )
        .unwrap();
        let offer = masked.mask_state_offer(&mask).await.unwrap().unwrap();
        let encoded = offer.encode_control().unwrap();
        assert_eq!(
            encoded[1], 2,
            "SRTP секрет не должен занимать поле DTLS fingerprint"
        );
        assert_eq!(MaskState::decode_control(&encoded).unwrap(), offer);
        masked.close().await.unwrap();
    }

    #[tokio::test]
    async fn recorded_turn_profiles_start_allocation_and_reserve_channel_header() {
        for id in ["webrtc_sberjazz_v1", "telegram_calls_v1"] {
            let mask = crate::mask::preset_masks::by_id(id).unwrap();
            assert!(uses_rtc(&mask), "{id}: нужен RTC за TURN");
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = peer.local_addr().unwrap();
            let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            udp.connect(address).await.unwrap();
            let masked = client(
                crate::transport::udp_transport(udp),
                &mask,
                address,
                "localhost".into(),
            )
            .unwrap();
            assert_eq!(masked.max_datagram(), 1324);
            let offer = masked.mask_state_offer(&mask).await.unwrap().unwrap();
            let server = RtcMask::new(
                true,
                address,
                masked.local_addr().unwrap(),
                address,
                Instant::now(),
            )
            .unwrap();
            masked
                .accept_mask_state(&MaskState {
                    answer: true,
                    parameters: server.parameters(),
                    ..offer
                })
                .await
                .unwrap();
            let mut wire = [0; 1500];
            let n = tokio::time::timeout(std::time::Duration::from_secs(1), peer.recv(&mut wire))
                .await
                .unwrap()
                .unwrap();
            assert!(n >= 20);
            assert_eq!(&wire[..2], &[0, 3], "{id}: первый внешний пакет - Allocate");
            masked.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn rtc_offer_is_idempotent_and_answer_bound_to_profile_and_generation() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp.connect(address).await.unwrap();
        let mut mask = crate::mask::preset_masks::webrtc_zoom_v3();
        mask.spoof_protocol = SpoofProtocol::WebRTC_DTLS_SRTP;
        let masked = client(
            crate::transport::udp_transport(udp),
            &mask,
            address,
            "localhost".into(),
        )
        .unwrap();
        let offer = masked
            .mask_state_offer(&mask)
            .await
            .unwrap()
            .expect("Нужно предложение RTC");
        assert!(!offer.answer);
        assert_eq!(offer.mask_id, mask.mask_id);
        assert_eq!(
            masked.mask_state_offer(&mask).await.unwrap(),
            Some(offer.clone())
        );
        assert!(masked.accept_mask_state(&offer).await.is_err());
        let mut wrong = offer.clone();
        wrong.answer = true;
        wrong.offer_id[0] ^= 1;
        assert!(masked.accept_mask_state(&wrong).await.is_err());
        wrong = offer.clone();
        wrong.answer = true;
        wrong.mask_version += 1;
        assert!(masked.accept_mask_state(&wrong).await.is_err());
        masked.close().await.unwrap();
    }

    #[tokio::test]
    async fn invalid_bootstrap_does_not_stop_the_mask_driver() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp.connect(address).await.unwrap();
        let raw = crate::transport::udp_transport(udp);
        let mask = crate::mask::preset_masks::quic_https_v2();
        let masked = client(raw, &mask, address, "localhost".into()).unwrap();
        assert!(masked.send(&[0x57; 600]).await.is_err());
        assert_eq!(masked.send(&[0x58; 80]).await.unwrap(), 80);
        let mut wire = vec![0; 2048];
        let length = tokio::time::timeout(std::time::Duration::from_secs(1), peer.recv(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            QuicMask::bootstrap(&wire[..length]),
            Some([0x58; 80].as_slice())
        );
        masked.close().await.unwrap();
    }
}
