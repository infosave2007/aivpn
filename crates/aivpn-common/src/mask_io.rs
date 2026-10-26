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
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

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
static QUIC_RECEIVE_DROPS: AtomicU64 = AtomicU64::new(0);

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
    #[cfg(test)]
    QuicTestState(Option<bool>, oneshot::Sender<QuicTestState>),
}

#[cfg(test)]
struct QuicTestState {
    frozen: bool,
    data: Option<Vec<u8>>,
    control: Option<Vec<u8>>,
}

struct PendingQuicSend {
    payload: Vec<u8>,
    generation: u64,
    response: oneshot::Sender<io::Result<usize>>,
}

fn reject_quic_send(pending: &mut Option<PendingQuicSend>, kind: io::ErrorKind) {
    if let Some(pending) = pending.take() {
        let _ = pending.response.send(Err(kind.into()));
    }
}

fn discard_stale_quic_send(pending: &mut Option<PendingQuicSend>, generation: u64) {
    if pending
        .as_ref()
        .is_some_and(|pending| pending.generation != generation || pending.response.is_closed())
    {
        reject_quic_send(pending, io::ErrorKind::WouldBlock);
    }
}

fn mask_send_error(error: Error) -> io::Error {
    match error {
        Error::Io(error) => error,
        other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()),
    }
}

fn retry_quic_send(
    pending: &mut Option<PendingQuicSend>,
    engine: &mut QuicMask,
    generation: u64,
) -> bool {
    discard_stale_quic_send(pending, generation);
    let Some(waiting) = pending.as_ref() else {
        return false;
    };
    match engine.send(&waiting.payload) {
        Ok(()) => {
            let waiting = pending.take().unwrap();
            let _ = waiting.response.send(Ok(waiting.payload.len()));
            true
        }
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => false,
        Err(error) => {
            let waiting = pending.take().unwrap();
            let _ = waiting.response.send(Err(mask_send_error(error)));
            false
        }
    }
}

async fn quic_send_cancelled(pending: &mut Option<PendingQuicSend>) {
    if let Some(pending) = pending {
        pending.response.closed().await;
    } else {
        std::future::pending::<()>().await;
    }
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
    mask_changed: Arc<Notify>,
    quic_data_gate: Mutex<()>,
    quic_control_gate: Mutex<()>,
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
    Ok(client_io(raw, mask, peer, server_name)?)
}

fn client_io(
    raw: Arc<dyn DatagramTransport>,
    mask: &MaskProfile,
    peer: SocketAddr,
    server_name: String,
) -> Result<Arc<ClientMaskIo>> {
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
    let mask_changed = Arc::new(Notify::new());
    let driver_changed = mask_changed.clone();
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
            driver_changed,
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
        mask_changed,
        quic_data_gate: Mutex::new(()),
        quic_control_gate: Mutex::new(()),
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
    mask_changed: Arc<Notify>,
) -> Result<()> {
    let mut engine: Option<QuicMask> = None;
    let mut rtc: Option<RtcMask> = None;
    let mut offer: Option<MaskState> = None;
    let mut rtc_generation = 0;
    let mut buffer = vec![0; 65536];
    // По одному ожидающему DATA и control. Сериализация на входе не дает
    // копировать новые payload, пока предыдущий не принят движком.
    let mut pending_data: Option<PendingQuicSend> = None;
    let mut pending_control: Option<PendingQuicSend> = None;
    #[cfg(test)]
    let mut frozen_quic_time: Option<Instant> = None;
    macro_rules! quic_now {
        () => {{
            #[cfg(test)]
            {
                frozen_quic_time.unwrap_or_else(Instant::now)
            }
            #[cfg(not(test))]
            {
                Instant::now()
            }
        }};
    }
    loop {
        let generation = mask_generation.load(Ordering::Acquire);
        discard_stale_quic_send(&mut pending_data, generation);
        discard_stale_quic_send(&mut pending_control, generation);
        let deadline = rtc
            .as_mut()
            .and_then(RtcMask::deadline)
            .or_else(|| engine.as_mut().and_then(QuicMask::deadline));
        // В тесте удержанные ACK не запрещают PTO освобождать DATAGRAM-буфер.
        // Фиксируем время QUIC, пока проверяем реальные ожидающие слоты.
        #[cfg(test)]
        let deadline = deadline.filter(|_| frozen_quic_time.is_none() || rtc.is_some());
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Send(payload, mode, data, generation, response)) => {
                    let current_generation = mask_generation.load(Ordering::Acquire);
                    discard_stale_quic_send(&mut pending_data, current_generation);
                    discard_stale_quic_send(&mut pending_control, current_generation);
                    if response.is_closed() { continue; }
                    if generation != mask_generation.load(Ordering::Acquire)
                        || (data && mode == 2 && (rtc_generation != generation || rtc.as_ref().is_none_or(|rtc| !rtc.connected())))
                    {
                        let _ = response.send(Err(io::ErrorKind::WouldBlock.into()));
                        continue;
                    }
                    if mode != 1 {
                        reject_quic_send(&mut pending_data, io::ErrorKind::WouldBlock);
                        reject_quic_send(&mut pending_control, io::ErrorKind::WouldBlock);
                    } else if if data { pending_data.is_some() } else { pending_control.is_some() } {
                        let _ = response.send(Err(io::ErrorKind::WouldBlock.into()));
                        continue;
                    }
                    let result = if mode == 1 && data && pending_control.is_some() {
                        Err(Error::Io(io::ErrorKind::WouldBlock.into()))
                    } else if mode == 2 {
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
                            for packet in previous.close(quic_now!())? {
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
                        QuicMask::client(&payload, peer, &server_name, quic_now!())
                            .map(|created| engine = Some(created))
                    };
                    match result {
                        Ok(()) => { let _ = response.send(Ok(payload.len())); }
                        Err(Error::Io(error)) if mode == 1 && error.kind() == io::ErrorKind::WouldBlock => {
                            let waiting = PendingQuicSend { payload, generation, response };
                            if data { pending_data = Some(waiting); } else { pending_control = Some(waiting); }
                        }
                        Err(error) => {
                            let _ = response.send(Err(mask_send_error(error)));
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
                            reject_quic_send(&mut pending_data, io::ErrorKind::WouldBlock);
                            reject_quic_send(&mut pending_control, io::ErrorKind::WouldBlock);
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
                    reject_quic_send(&mut pending_data, io::ErrorKind::BrokenPipe);
                    reject_quic_send(&mut pending_control, io::ErrorKind::BrokenPipe);
                    if let Some(mut previous) = engine.take() {
                        for packet in previous.close(quic_now!())? {
                            if raw.send(&packet).await.is_ok() { samples.record(&packet); }
                        }
                    }
                    let _ = response.send(());
                    return Ok(());
                },
                #[cfg(test)]
                Some(Command::QuicTestState(freeze, response)) => {
                    if let Some(freeze) = freeze {
                        frozen_quic_time = freeze.then(Instant::now);
                    }
                    let _ = response.send(QuicTestState {
                        frozen: frozen_quic_time.is_some(),
                        data: pending_data.as_ref().map(|pending| pending.payload.clone()),
                        control: pending_control.as_ref().map(|pending| pending.payload.clone()),
                    });
                    continue;
                },
                None => return Ok(()),
            },
            _ = mask_changed.notified() => {},
            _ = quic_send_cancelled(&mut pending_data) => {},
            _ = quic_send_cancelled(&mut pending_control) => {},
            packet = raw.recv(&mut buffer) => {
                let length = match packet {
                    Ok(0) => {
                        // После shutdown UDP может немедленно возвращать ноль.
                        // Оставляем время таймерам и отмене соседних задач.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    },
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
                    engine.receive(&buffer[..length], peer, quic_now!())?;
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
            let mut output = engine.poll(quic_now!())?;
            // ACK и штатный pacer освобождают буфер в poll. Сначала даем место
            // управлению; DATA не удерживает драйвер и не блокирует receive.
            let generation = mask_generation.load(Ordering::Acquire);
            let control_queued = retry_quic_send(&mut pending_control, engine, generation);
            // Меньший DATA не должен занимать место, которого пока не хватает
            // большему control. Отмена и смена поколения снимают этот запрет.
            let data_queued =
                pending_control.is_none() && retry_quic_send(&mut pending_data, engine, generation);
            if control_queued || data_queued {
                let next = engine.poll(quic_now!())?;
                output.wire.extend(next.wire);
                output.payloads.extend(next.payloads);
            }
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
                match received.try_send(Ok(payload)) {
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        let dropped = QUIC_RECEIVE_DROPS
                            .fetch_add(1, Ordering::Relaxed)
                            .wrapping_add(1);
                        if dropped.is_power_of_two() {
                            tracing::debug!(dropped, "Переполнена очередь приема QUIC");
                        }
                    }
                    Ok(()) => {}
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
        let _quic_gate = if stateful {
            Some(if data {
                self.quic_data_gate.lock().await
            } else {
                self.quic_control_gate.lock().await
            })
        } else {
            None
        };
        if generation != self.mask_generation.load(Ordering::Acquire) {
            return Err(io::ErrorKind::WouldBlock.into());
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
            self.mask_changed.notify_one();
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
    use std::future::Future;

    async fn quic_test_state(masked: &ClientMaskIo, freeze: Option<bool>) -> QuicTestState {
        let (response, state) = oneshot::channel();
        masked
            .commands
            .send(Command::QuicTestState(freeze, response))
            .await
            .unwrap();
        state.await.unwrap()
    }

    async fn start_quic_send(
        masked: &Arc<ClientMaskIo>,
        payload: Vec<u8>,
        data: bool,
    ) -> tokio::task::JoinHandle<io::Result<usize>> {
        let sender = masked.clone();
        let (polled, first_poll) = oneshot::channel();
        let send = tokio::spawn(async move {
            let mut sending = Box::pin(sender.send_packet(&payload, data));
            let mut polled = Some(polled);
            std::future::poll_fn(|context| {
                let result = sending.as_mut().poll(context);
                if let Some(polled) = polled.take() {
                    let _ = polled.send(());
                }
                result
            })
            .await
        });
        first_poll.await.unwrap();
        send
    }

    struct QuicPeerTransport {
        outbound: mpsc::Sender<Vec<u8>>,
        inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        hold: Arc<AtomicBool>,
        changed: Arc<tokio::sync::Notify>,
        payloads: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        observed: Arc<tokio::sync::Notify>,
        closed: Arc<AtomicBool>,
        task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    }

    impl QuicPeerTransport {
        fn new() -> Arc<Self> {
            let (outbound, mut packets) = mpsc::channel::<Vec<u8>>(64);
            let (wire, inbound) = mpsc::channel(256);
            let hold = Arc::new(AtomicBool::new(false));
            let changed = Arc::new(tokio::sync::Notify::new());
            let payloads = Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed = Arc::new(tokio::sync::Notify::new());
            let closed = Arc::new(AtomicBool::new(false));
            let (actor_hold, actor_changed) = (hold.clone(), changed.clone());
            let (actor_payloads, actor_observed) = (payloads.clone(), observed.clone());
            let actor_closed = closed.clone();
            let task = tokio::spawn(async move {
                let client_address = "127.0.0.1:44433".parse().unwrap();
                let mut engine: Option<QuicMask> = None;
                let mut withheld = VecDeque::new();
                let mut announced = false;
                loop {
                    let deadline = engine.as_mut().and_then(QuicMask::deadline);
                    tokio::select! {
                        packet = packets.recv() => {
                            let Some(packet) = packet else { break; };
                            if let Some(engine) = engine.as_mut() {
                                match engine.receive(&packet, client_address, Instant::now()) {
                                    Ok(()) => {},
                                    Err(Error::Session(reason)) if reason.starts_with("closed by peer:") => return,
                                    Err(error) => panic!("Ошибка тестового QUIC peer: {error}"),
                                }
                            } else {
                                engine = Some(QuicMask::server(&packet, client_address, Instant::now()).unwrap());
                            }
                        }
                        _ = actor_changed.notified() => {}
                        _ = async {
                            if let Some(deadline) = deadline {
                                crate::pacing::wait_until(deadline.into()).await;
                            } else { std::future::pending::<()>().await; }
                        } => {}
                    }
                    if actor_closed.load(Ordering::Acquire) {
                        return;
                    }
                    let Some(engine) = engine.as_mut() else {
                        continue;
                    };
                    let mut output = match engine.poll(Instant::now()) {
                        Ok(output) => output,
                        Err(Error::Session(reason)) if reason.starts_with("closed by peer:") => {
                            return
                        }
                        Err(error) => panic!("Ошибка тестового QUIC peer: {error}"),
                    };
                    if output.connected && !announced {
                        engine.send(b"peer-ready").unwrap();
                        announced = true;
                        let next = engine.poll(Instant::now()).unwrap();
                        output.wire.extend(next.wire);
                        output.payloads.extend(next.payloads);
                    }
                    if !output.payloads.is_empty() {
                        actor_payloads.lock().unwrap().extend(output.payloads);
                        actor_observed.notify_one();
                    }
                    withheld.extend(output.wire);
                    while !withheld.is_empty() {
                        if actor_hold.load(Ordering::Acquire) {
                            break;
                        }
                        if wire.send(withheld.pop_front().unwrap()).await.is_err() {
                            return;
                        }
                    }
                }
            });
            Arc::new(Self {
                outbound,
                inbound: Mutex::new(inbound),
                hold,
                changed,
                payloads,
                observed,
                closed,
                task: std::sync::Mutex::new(Some(task)),
            })
        }

        async fn connected(self: &Arc<Self>) -> Arc<ClientMaskIo> {
            let mask = crate::mask::preset_masks::quic_https_v2();
            let masked = client_io(
                self.clone(),
                &mask,
                "127.0.0.1:4433".parse().unwrap(),
                "localhost".into(),
            )
            .unwrap();
            masked.send(b"bootstrap").await.unwrap();
            let mut buffer = vec![0; 1500];
            let length =
                tokio::time::timeout(std::time::Duration::from_secs(3), masked.recv(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&buffer[..length], b"peer-ready");
            self.wait_for(b"bootstrap").await;
            masked
        }

        fn release(&self) {
            self.hold.store(false, Ordering::Release);
            self.changed.notify_one();
        }

        async fn fill_until_waiting(
            &self,
            masked: &Arc<ClientMaskIo>,
        ) -> (Vec<u8>, tokio::task::JoinHandle<io::Result<usize>>) {
            self.fill_until_waiting_size(masked, 1000).await
        }

        async fn fill_until_waiting_size(
            &self,
            masked: &Arc<ClientMaskIo>,
            size: usize,
        ) -> (Vec<u8>, tokio::task::JoinHandle<io::Result<usize>>) {
            self.hold.store(true, Ordering::Release);
            assert!(quic_test_state(masked, Some(true)).await.frozen);
            for sequence in 0u64..4096 {
                let mut payload = vec![0x5a; size];
                payload[..8].copy_from_slice(&sequence.to_le_bytes());
                let send = start_quic_send(masked, payload.clone(), true).await;
                // Первый poll поставил Send в очередь; следующий FIFO-запрос
                // видит слот после обработки Send и протокольного poll.
                let state = quic_test_state(masked, None).await;
                assert!(state.frozen);
                if state.data.as_ref() == Some(&payload) {
                    assert!(
                        sequence >= 256,
                        "Ожидание началось до заполнения широкополосного полета"
                    );
                    assert!(!send.is_finished());
                    return (payload, send);
                }
                assert!(state.data.is_none());
                assert_eq!(
                    send.await
                        .unwrap()
                        .expect("Полный буфер QUIC должен ждать, а не терять DATA"),
                    payload.len()
                );
            }
            panic!("Буфер QUIC не имеет конечного предела");
        }

        async fn wait_for(&self, expected: &[u8]) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let notified = self.observed.notified();
                    if self
                        .payloads
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|payload| payload == expected)
                    {
                        return;
                    }
                    notified.await;
                }
            })
            .await
            .expect("Ожидающий пакет не дошел после освобождения буфера");
        }

        fn count(&self, expected: &[u8]) -> usize {
            self.payloads
                .lock()
                .unwrap()
                .iter()
                .filter(|payload| payload.as_slice() == expected)
                .count()
        }

        async fn finish(&self, masked: &ClientMaskIo) {
            masked.close().await.unwrap();
            let task = self.task.lock().unwrap().take().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .expect("Тестовый QUIC peer не завершился")
                .expect("Тестовый QUIC peer упал");
        }
    }

    impl Drop for QuicPeerTransport {
        fn drop(&mut self) {
            if let Some(task) = self.task.lock().unwrap().as_ref() {
                task.abort();
            }
        }
    }

    #[async_trait]
    impl DatagramTransport for QuicPeerTransport {
        async fn send(&self, packet: &[u8]) -> io::Result<usize> {
            self.outbound
                .send(packet.to_vec())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            Ok(packet.len())
        }

        async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
            let packet = self
                .inbound
                .lock()
                .await
                .recv()
                .await
                .ok_or(io::ErrorKind::BrokenPipe)?;
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }

        fn kind(&self) -> TransportKind {
            TransportKind::Udp
        }
        fn max_datagram(&self) -> usize {
            QUIC_WIRE_BUDGET
        }
        async fn close(&self) -> Result<()> {
            self.closed.store(true, Ordering::Release);
            self.changed.notify_one();
            Ok(())
        }
    }

    #[tokio::test]
    async fn quic_fixture_observes_full_buffer_with_room_for_smaller_data() {
        let peer = QuicPeerTransport::new();
        let masked = peer.connected().await;
        let (_payload, waiting) = peer.fill_until_waiting_size(&masked, 1096).await;
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        // Отдельный контроль фикстуры: настоящий буфер отказал пакету 1096,
        // но меньший DATA 1000 помещается без ACK и продвижения времени QUIC.
        let smaller = start_quic_send(&masked, vec![0xd8; 1000], true).await;
        let state = quic_test_state(&masked, None).await;
        assert!(state.frozen);
        assert!(state.data.is_none());
        assert_eq!(smaller.await.unwrap().unwrap(), 1000);
        peer.finish(&masked).await;
    }

    #[tokio::test]
    async fn quic_full_send_buffer_waits_for_ack_and_delivers_data_once() {
        let peer = QuicPeerTransport::new();
        let masked = peer.connected().await;
        let (payload, send) = peer.fill_until_waiting(&masked).await;
        assert!(!send.is_finished());
        assert!(!quic_test_state(&masked, Some(false)).await.frozen);
        peer.release();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(3), send)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            payload.len()
        );
        peer.wait_for(&payload).await;
        masked.send(b"after-data").await.unwrap();
        peer.wait_for(b"after-data").await;
        assert_eq!(peer.count(&payload), 1);
        peer.finish(&masked).await;
    }

    #[tokio::test]
    async fn quic_cancelled_send_is_not_retried_after_ack() {
        let peer = QuicPeerTransport::new();
        let masked = peer.connected().await;
        let (cancelled, send) = peer.fill_until_waiting(&masked).await;
        send.abort();
        assert!(send.await.unwrap_err().is_cancelled());
        let next = vec![0x6b; 1000];
        let replacement = start_quic_send(&masked, next.clone(), true).await;
        assert_eq!(
            quic_test_state(&masked, None).await.data,
            Some(next.clone())
        );
        assert!(!replacement.is_finished());
        assert!(!quic_test_state(&masked, Some(false)).await.frozen);
        peer.release();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(3), replacement)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            next.len()
        );
        peer.wait_for(&next).await;
        assert_eq!(peer.count(&cancelled), 0);
        assert_eq!(peer.count(&next), 1);
        peer.finish(&masked).await;
    }

    #[tokio::test]
    async fn quic_profile_change_wakes_blocked_and_gate_waiting_sends() {
        let peer = QuicPeerTransport::new();
        let masked = peer.connected().await;
        let (stale, send) = peer.fill_until_waiting(&masked).await;
        let gated = start_quic_send(&masked, b"stale-behind-gate".to_vec(), true).await;
        assert_eq!(
            quic_test_state(&masked, None).await.data,
            Some(stale.clone())
        );
        assert!(!gated.is_finished());
        let mut mask = crate::mask::preset_masks::quic_https_v2();
        mask.signature[0] ^= 1;
        masked.set_mask_profile(&mask);
        for send in [send, gated] {
            let error = tokio::time::timeout(std::time::Duration::from_millis(100), send)
                .await
                .expect("Смена поколения не разбудила ожидающий send")
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }
        assert!(!quic_test_state(&masked, Some(false)).await.frozen);
        peer.release();
        masked.send(b"new-generation-barrier").await.unwrap();
        peer.wait_for(b"new-generation-barrier").await;
        assert_eq!(peer.count(&stale), 0);
        assert_eq!(peer.count(b"stale-behind-gate"), 0);
        peer.finish(&masked).await;
    }

    #[tokio::test]
    async fn quic_control_bypasses_blocked_data_and_uses_first_available_space() {
        let peer = QuicPeerTransport::new();
        let masked = peer.connected().await;
        let (data, send) = peer.fill_until_waiting(&masked).await;
        let control = start_quic_send(&masked, vec![0xc3; 1000], false).await;
        let state = quic_test_state(&masked, None).await;
        assert_eq!(state.control, Some(vec![0xc3; 1000]));
        assert_eq!(state.data, Some(data.clone()));
        assert!(!control.is_finished());
        assert!(!quic_test_state(&masked, Some(false)).await.frozen);
        peer.release();
        for send in [control, send] {
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(3), send)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
                1000
            );
        }
        peer.wait_for(&data).await;
        peer.wait_for(&vec![0xc3; 1000]).await;
        let positions = {
            let payloads = peer.payloads.lock().unwrap();
            (
                payloads
                    .iter()
                    .position(|payload| payload == &vec![0xc3; 1000])
                    .unwrap(),
                payloads
                    .iter()
                    .position(|payload| payload == &data)
                    .unwrap(),
            )
        };
        assert!(
            positions.0 < positions.1,
            "Управление попало за ожидающий DATA"
        );
        assert_eq!(peer.count(&data), 1);
        assert_eq!(peer.count(&vec![0xc3; 1000]), 1);
        peer.finish(&masked).await;
    }

    #[tokio::test]
    async fn quic_larger_pending_control_reserves_space_from_new_and_pending_data() {
        let peer = QuicPeerTransport::new();
        let masked = peer.connected().await;
        // Пакеты 1096 байт заполняют буфер так, что оставшегося места хватает
        // для DATA 1000, но не для control 1140. Пока время QUIC заморожено,
        // удержанные ACK не заменяются разрешенной отправкой после PTO.
        let (_cancelled, filled) = peer.fill_until_waiting_size(&masked, 1096).await;
        filled.abort();
        assert!(filled.await.unwrap_err().is_cancelled());
        let control_payload = vec![0xc7; 1140];
        let control = start_quic_send(&masked, control_payload.clone(), false).await;
        assert_eq!(
            quic_test_state(&masked, None).await.control,
            Some(control_payload.clone())
        );
        let data_payload = vec![0xd8; 1000];
        let data = start_quic_send(&masked, data_payload.clone(), true).await;
        let state = quic_test_state(&masked, None).await;
        assert_eq!(state.control, Some(control_payload.clone()));
        assert_eq!(
            state.data,
            Some(data_payload.clone()),
            "Меньший DATA занял место, зарезервированное ожидающим control"
        );
        assert!(!control.is_finished());
        assert!(!data.is_finished());
        assert!(!quic_test_state(&masked, Some(false)).await.frozen);
        peer.release();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), control)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            1140
        );
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), data)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            1000
        );
        peer.wait_for(&control_payload).await;
        peer.wait_for(&data_payload).await;
        let positions = {
            let payloads = peer.payloads.lock().unwrap();
            (
                payloads
                    .iter()
                    .position(|payload| payload == &control_payload)
                    .unwrap(),
                payloads
                    .iter()
                    .position(|payload| payload == &data_payload)
                    .unwrap(),
            )
        };
        assert!(positions.0 < positions.1);
        assert_eq!(peer.count(&control_payload), 1);
        assert_eq!(peer.count(&data_payload), 1);
        peer.finish(&masked).await;
    }

    #[tokio::test]
    async fn quic_close_finishes_both_blocked_slots_without_waiting_for_ack() {
        let peer = QuicPeerTransport::new();
        let masked = peer.connected().await;
        let (_data, send) = peer.fill_until_waiting(&masked).await;
        let control = start_quic_send(&masked, vec![0xc3; 1000], false).await;
        assert_eq!(
            quic_test_state(&masked, None).await.control,
            Some(vec![0xc3; 1000])
        );
        let (response, closed) = oneshot::channel();
        masked
            .commands
            .send(Command::Close(response))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(100), closed)
            .await
            .expect("Close заблокирован ожидающим DATA")
            .unwrap();
        for send in [send, control] {
            assert_eq!(
                send.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        peer.finish(&masked).await;
    }

    #[tokio::test]
    async fn repeated_empty_datagrams_do_not_starve_the_runtime() {
        use std::future::Future;
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Poll, Wake, Waker};
        struct EmptyTransport(AtomicUsize);
        #[async_trait::async_trait]
        impl DatagramTransport for EmptyTransport {
            async fn send(&self, data: &[u8]) -> io::Result<usize> {
                Ok(data.len())
            }
            async fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
                if self.0.fetch_add(1, Ordering::Relaxed) < 32 {
                    Ok(0)
                } else {
                    std::future::pending().await
                }
            }
            fn kind(&self) -> crate::transport::TransportKind {
                crate::transport::TransportKind::Udp
            }
            fn max_datagram(&self) -> usize {
                1380
            }
        }
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        let raw = Arc::new(EmptyTransport(AtomicUsize::new(0)));
        let (_sender, commands) = mpsc::channel(QUEUE);
        let (received, _receiver) = mpsc::channel(QUEUE);
        let mut driver = Box::pin(drive_client(
            raw.clone(),
            commands,
            received,
            "127.0.0.1:443".parse().unwrap(),
            "localhost".into(),
            Arc::new(WireSamples::default()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Notify::new()),
        ));
        let waker = Waker::from(Arc::new(Noop));
        assert!(matches!(
            driver.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Pending
        ));
        assert_eq!(
            raw.0.load(Ordering::Relaxed),
            1,
            "Пустые датаграммы не должны занимать весь опрос задачи"
        );
    }

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
            Arc::new(Notify::new()),
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
        assert!(masked.send(&[0x57; MAX_QUIC_INNER + 1]).await.is_err());
        assert_eq!(masked.send(&[0x58; 80]).await.unwrap(), 80);
        let mut wire = vec![0; 2048];
        let length = tokio::time::timeout(std::time::Duration::from_secs(1), peer.recv(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            QuicMask::initial_token(&wire[..length]),
            Some(b"".as_slice())
        );
        masked.close().await.unwrap();
    }
}
