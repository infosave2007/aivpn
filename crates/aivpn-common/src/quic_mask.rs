//! Состояние QUIC внутри существующей маски.
//!
//! Сокетов здесь нет: вызывающий код отдает UDP payload и забирает готовые
//! дейтаграммы. Начальные байты AIVPN едут один раз непрозрачным токеном
//! Initial. После рукопожатия внутренние пакеты идут стандартными DATAGRAM
//! TLS 1.3, без 0-RTT и без смены адреса.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, ConnectionIdGenerator, DatagramEvent, Endpoint,
    EndpointConfig, Event, IdleTimeout, MtuDiscoveryConfig, RandomConnectionIdGenerator,
    SendDatagramError, ServerConfig, TokenStore, TransportConfig, VarInt,
};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, PeerIncompatible, SignatureScheme};

use crate::error::{Error, Result};
use crate::h3_mask::H3Mask;

const MAX_LOGICAL: usize = crate::mask_io::MAX_QUIC_INNER;
const WIRE_MTU: u16 = 1380;
const MIN_DATAGRAM: usize = 1200;
const CID_LEN: usize = 8;
const CID_MIN: usize = 8;
const CID_MAX: usize = 20;
const TOKEN_MIN: u64 = 1;
const TOKEN_MAX: u64 = 512;
/// Минимум поля Length: однобайтовый номер пакета и тег AEAD.
const MIN_PACKET_REST: usize = 17;
const SEND_BUDGET: usize = 64 * 1024;
const RECV_BUDGET: usize = 128 * 1024;
const IDLE: Duration = Duration::from_secs(30);
const MAX_SEGMENTS: usize = 16;
const ALPN_H3: &[u8] = b"h3";

/// Отказ локального MTU для пробного пакета считаем потерей пробы.
/// Пакеты данных помещаются в начальные 1200 байт и сюда не попадают.
pub fn mtu_probe_error(error: &std::io::Error, packet_len: usize) -> bool {
    if packet_len <= MIN_DATAGRAM {
        return false;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EMSGSIZE)
    }
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(10040)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        false
    }
}

/// Результат одного шага движка маски.
#[derive(Debug)]
pub struct QuicMaskOutput {
    pub wire: Vec<Vec<u8>>,
    pub payloads: Vec<Vec<u8>>,
    pub connected: bool,
}

/// Протокольное состояние одной маскируемой сессии QUIC.
pub struct QuicMask {
    endpoint: Endpoint,
    conn: Option<(ConnectionHandle, Connection)>,
    connected: bool,
    pending: VecDeque<Bytes>,
    pending_bytes: usize,
    scratch: Vec<u8>,
    stateless: Vec<Vec<u8>>,
    closed: Option<String>,
    server: bool,
    received_bytes: usize,
    sent_bytes: usize,
    blocked_wire: VecDeque<Vec<u8>>,
    application: H3Mask,
    setup_deadline: Instant,
    next_application_poll: Option<Instant>,
    verified_wire: crate::verified_wire::VerifiedWire,
}

struct Identity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

struct BootstrapToken(Mutex<Option<Bytes>>);

#[derive(Debug)]
struct MaskServerCertVerifier;

impl QuicMask {
    /// Достает непрозрачный токен из строгого QUIC v1 Initial.
    ///
    /// Пакет не короче 1200 байт, обе стороны CID от 8 до 20, токен от 1 до 512.
    /// Нижние биты первого байта закрыты header protection и здесь не читаются.
    pub fn bootstrap(packet: &[u8]) -> Option<&[u8]> {
        if packet.len() < MIN_DATAGRAM {
            return None;
        }
        let first = packet[0];
        // Длинный заголовок, фиксированный бит, тип Initial. Младшая четверка защищена.
        if first & 0xf0 != 0xc0 {
            return None;
        }
        let version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
        if version != 0x0000_0001 {
            return None;
        }
        let mut offset = 5;
        let dcid_len = usize::from(*packet.get(offset)?);
        offset += 1;
        if !(CID_MIN..=CID_MAX).contains(&dcid_len) || packet.len() < offset + dcid_len {
            return None;
        }
        offset += dcid_len;
        let scid_len = usize::from(*packet.get(offset)?);
        offset += 1;
        if !(CID_MIN..=CID_MAX).contains(&scid_len) || packet.len() < offset + scid_len {
            return None;
        }
        offset += scid_len;
        let (token_len, eaten) = read_varint(packet.get(offset..)?)?;
        offset += eaten;
        if !(TOKEN_MIN..=TOKEN_MAX).contains(&token_len) {
            return None;
        }
        let token_len = token_len as usize;
        let token = packet.get(offset..offset + token_len)?;
        offset += token_len;
        let (length, eaten) = read_varint(packet.get(offset..)?)?;
        offset += eaten;
        let length = usize::try_from(length).ok()?;
        let rest = packet.len().checked_sub(offset)?;
        if length < MIN_PACKET_REST || length > rest {
            return None;
        }
        Some(token)
    }

    /// Клиент. `bootstrap` кладется в токен Initial и больше никуда.
    pub fn client(
        bootstrap: &[u8],
        peer: SocketAddr,
        server_name: &str,
        now: Instant,
    ) -> Result<Self> {
        if !(1..=512).contains(&bootstrap.len()) {
            return Err(Error::InvalidPacket("Начальный токен вне допустимой длины"));
        }
        if server_name.is_empty() || server_name.len() > 253 {
            return Err(Error::InvalidPacket("Имя сервера маски недопустимо"));
        }
        let mut endpoint = Endpoint::new(endpoint_config()?, None, false, None);
        let mut config = ClientConfig::new(Arc::new(client_crypto()?));
        config.transport_config(transport_config()?);
        config.token_store(Arc::new(BootstrapToken::new(Bytes::copy_from_slice(
            bootstrap,
        ))));
        config.initial_dst_cid_provider(Arc::new(|| {
            RandomConnectionIdGenerator::new(CID_LEN).generate_cid()
        }));
        let (handle, conn) = endpoint
            .connect(now, config, peer, server_name)
            .map_err(|err| Error::Session(err.to_string()))?;
        let mut mask = Self::from_parts(endpoint, Some((handle, conn)), false, now);
        mask.application.set_authority(server_name)?;
        Ok(mask)
    }

    /// Сервер. Вызывать только после проверки внутреннего AEAD по токену.
    ///
    /// Неизвестный токен для quinn не является доказательством адреса: соединение
    /// принимается как непроверенное, Retry не отправляется.
    pub fn server(first_packet: &[u8], peer: SocketAddr, now: Instant) -> Result<Self> {
        if Self::bootstrap(first_packet).is_none() {
            return Err(Error::InvalidPacket(
                "Первый пакет не является QUIC Initial v1",
            ));
        }
        let endpoint = Endpoint::new(endpoint_config()?, Some(server_config()?), false, None);
        let mut mask = Self::from_parts(endpoint, None, true, now);
        mask.receive(first_packet, peer, now)?;
        if mask.conn.is_none() {
            return Err(Error::InvalidPacket("Сервер не принял первый пакет"));
        }
        mask.drain_events(&mut Vec::new())?;
        Ok(mask)
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.ensure_open()?;
        if payload.is_empty() || payload.len() > MAX_LOGICAL {
            return Err(Error::InvalidPacket("Пакет не вмещается в маску"));
        }
        let data = Bytes::copy_from_slice(payload);
        if !self.connected || !self.application.ready() {
            return self.push_pending(data);
        }
        match self.send_now(data.clone()) {
            Ok(()) => Ok(()),
            Err(SendDatagramError::Blocked(_)) => {
                Err(Error::Io(std::io::ErrorKind::WouldBlock.into()))
            }
            Err(SendDatagramError::UnsupportedByPeer) => self.push_pending(data),
            Err(SendDatagramError::TooLarge) => {
                Err(Error::InvalidPacket("Дейтаграмма больше окна QUIC"))
            }
            Err(SendDatagramError::Disabled) => {
                Err(Error::Session("Дейтаграммы QUIC выключены".into()))
            }
        }
    }

    pub fn receive(&mut self, packet: &[u8], peer: SocketAddr, now: Instant) -> Result<()> {
        self.ensure_open()?;
        if packet.is_empty() {
            return Ok(());
        }
        self.scratch.clear();
        let incoming = BytesMut::from(packet);
        let event = self
            .endpoint
            .handle(now, peer, None, None, incoming, &mut self.scratch);
        match event {
            None => Ok(()),
            Some(DatagramEvent::ConnectionEvent(handle, connection_event)) => {
                if self
                    .conn
                    .as_ref()
                    .is_some_and(|(current, _)| *current == handle)
                {
                    self.received_bytes = self.received_bytes.saturating_add(packet.len());
                }
                let before = self.verified_wire.enabled().then(|| {
                    self.conn
                        .as_ref()
                        .map(|(_, conn)| conn.stats().frame_rx.datagram)
                        .unwrap_or(0)
                });
                self.dispatch_connection(handle, connection_event);
                if before.is_some_and(|before| {
                    self.conn
                        .as_ref()
                        .is_some_and(|(_, conn)| conn.stats().frame_rx.datagram > before)
                }) {
                    self.verified_wire.record(packet);
                }
                Ok(())
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                let first = self.conn.is_none();
                self.accept_new(incoming, now)?;
                if first {
                    self.received_bytes = self.received_bytes.saturating_add(packet.len());
                }
                Ok(())
            }
            Some(DatagramEvent::Response(transmit)) => {
                let size = transmit.size;
                let bytes = self.scratch[..size].to_vec();
                self.scratch.clear();
                self.stateless
                    .extend(split_segments(transmit.segment_size, &bytes));
                Ok(())
            }
        }
    }

    pub fn poll(&mut self, now: Instant) -> Result<QuicMaskOutput> {
        self.ensure_open()?;
        if !self.application.ready() && now >= self.setup_deadline {
            return Err(self.fail("Истекло время согласования HTTP/3".into()));
        }
        if let Some((_, conn)) = self.conn.as_mut() {
            if conn.poll_timeout().is_some_and(|deadline| deadline <= now) {
                conn.handle_timeout(now);
            }
        }
        let mut wire = Vec::new();
        wire.append(&mut self.stateless);
        self.pump(now, &mut wire)?;
        let mut payloads = Vec::new();
        self.drain_events(&mut payloads)?;
        if self.flush_pending()? {
            self.pump(now, &mut wire)?;
            self.drain_events(&mut payloads)?;
        }
        self.pump(now, &mut wire)?;
        self.next_application_poll = self
            .application
            .read_pending()
            .then_some(now + Duration::from_millis(1));
        for packet in &wire {
            if packet.len() > usize::from(WIRE_MTU) {
                return Err(Error::InvalidPacket("Движок маски превысил бюджет UDP"));
            }
        }
        // Quinn допускает превышение остатка anti-amplification на один MTU.
        // Здесь сохраняем строгий предел 3x до TLS-подтверждения адреса.
        if self.server && !self.connected {
            self.blocked_wire.extend(wire);
            if self.blocked_wire.len() > 64 {
                return Err(Error::Session(
                    "Очередь anti-amplification заполнена".into(),
                ));
            }
            wire = Vec::new();
            while self.blocked_wire.front().is_some_and(|packet| {
                self.sent_bytes.saturating_add(packet.len())
                    <= self.received_bytes.saturating_mul(3)
            }) {
                let packet = self.blocked_wire.pop_front().unwrap();
                self.sent_bytes = self.sent_bytes.saturating_add(packet.len());
                wire.push(packet);
            }
        } else if self.server {
            let mut ready: Vec<_> = self.blocked_wire.drain(..).collect();
            ready.append(&mut wire);
            wire = ready;
        }
        Ok(QuicMaskOutput {
            wire,
            payloads,
            connected: self.connected && self.application.ready(),
        })
    }

    pub fn deadline(&mut self) -> Option<Instant> {
        let protocol = self.conn.as_mut().and_then(|(_, conn)| conn.poll_timeout());
        [
            protocol,
            (!self.application.ready()).then_some(self.setup_deadline),
            self.next_application_poll,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Отправляет штатное закрытие при смене протокола или остановке клиента.
    pub fn close(&mut self, now: Instant) -> Result<Vec<Vec<u8>>> {
        if !self.connected {
            return Ok(Vec::new());
        }
        if let Some((_, conn)) = self.conn.as_mut() {
            conn.close(now, VarInt::from_u32(0x100), Bytes::new());
        }
        let mut wire = Vec::new();
        self.pump(now, &mut wire)?;
        Ok(wire)
    }

    fn from_parts(
        endpoint: Endpoint,
        conn: Option<(ConnectionHandle, Connection)>,
        server: bool,
        now: Instant,
    ) -> Self {
        Self {
            endpoint,
            conn,
            connected: false,
            pending: VecDeque::new(),
            pending_bytes: 0,
            scratch: Vec::new(),
            stateless: Vec::new(),
            closed: None,
            server,
            received_bytes: 0,
            sent_bytes: 0,
            blocked_wire: VecDeque::new(),
            application: H3Mask::new(server, String::new()),
            setup_deadline: now + Duration::from_secs(10),
            next_application_poll: None,
            verified_wire: Default::default(),
        }
    }

    pub fn observe_verified_wire(&mut self) {
        self.verified_wire.enable();
    }

    pub fn take_verified_wire(&mut self) -> Vec<Vec<u8>> {
        self.verified_wire.take()
    }

    fn ensure_open(&self) -> Result<()> {
        if let Some(reason) = &self.closed {
            return Err(Error::Session(reason.clone()));
        }
        Ok(())
    }

    fn fail(&mut self, reason: String) -> Error {
        self.closed = Some(reason.clone());
        Error::Session(reason)
    }

    fn push_pending(&mut self, payload: Bytes) -> Result<()> {
        let next = self.pending_bytes.saturating_add(payload.len());
        if next > SEND_BUDGET || self.pending.len() >= 64 {
            return Err(Error::Io(std::io::ErrorKind::WouldBlock.into()));
        }
        self.pending_bytes = next;
        self.pending.push_back(payload);
        Ok(())
    }

    fn send_now(&mut self, payload: Bytes) -> std::result::Result<(), SendDatagramError> {
        let Some((_, conn)) = self.conn.as_mut() else {
            return Err(SendDatagramError::UnsupportedByPeer);
        };
        if !self.application.ready() {
            return Err(SendDatagramError::UnsupportedByPeer);
        }
        conn.datagrams().send(H3Mask::datagram(&payload), false)
    }

    fn flush_pending(&mut self) -> Result<bool> {
        if !self.connected || !self.application.ready() {
            return Ok(false);
        }
        let mut flushed = false;
        loop {
            let Some(next) = self.pending.front().cloned() else {
                break;
            };
            match self.send_now(next) {
                Ok(()) => {
                    if let Some(item) = self.pending.pop_front() {
                        self.pending_bytes = self.pending_bytes.saturating_sub(item.len());
                    }
                    flushed = true;
                }
                Err(SendDatagramError::Blocked(_)) | Err(SendDatagramError::UnsupportedByPeer) => {
                    break;
                }
                Err(SendDatagramError::TooLarge) => {
                    if let Some(item) = self.pending.pop_front() {
                        self.pending_bytes = self.pending_bytes.saturating_sub(item.len());
                    }
                    return Err(Error::InvalidPacket("Дейтаграмма больше окна QUIC"));
                }
                Err(SendDatagramError::Disabled) => {
                    return Err(self.fail("Дейтаграммы QUIC выключены".into()));
                }
            }
        }
        Ok(flushed)
    }

    fn accept_new(&mut self, incoming: quinn_proto::Incoming, now: Instant) -> Result<()> {
        if self.conn.is_some() {
            // Вторая попытка не открывает еще одно соединение внутри маски.
            self.endpoint.ignore(incoming);
            return Ok(());
        }
        // remote_address_validated здесь ложь: чужой токен не доказывает адрес.
        let mut buf = Vec::new();
        match self.endpoint.accept(incoming, now, &mut buf, None) {
            Ok((handle, conn)) => {
                self.conn = Some((handle, conn));
                Ok(())
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    let size = transmit.size;
                    self.stateless
                        .extend(split_segments(transmit.segment_size, &buf[..size]));
                }
                Err(self.fail(error.cause.to_string()))
            }
        }
    }

    fn dispatch_connection(
        &mut self,
        handle: ConnectionHandle,
        event: quinn_proto::ConnectionEvent,
    ) {
        if let Some((current, conn)) = self.conn.as_mut() {
            if *current == handle {
                conn.handle_event(event);
            }
        }
    }

    fn pump(&mut self, now: Instant, wire: &mut Vec<Vec<u8>>) -> Result<()> {
        for _ in 0..32 {
            let mut endpoint_events = Vec::new();
            if let Some((handle, conn)) = self.conn.as_mut() {
                while let Some(event) = conn.poll_endpoint_events() {
                    endpoint_events.push((*handle, event));
                }
                loop {
                    self.scratch.clear();
                    let Some(transmit) = conn.poll_transmit(now, MAX_SEGMENTS, &mut self.scratch)
                    else {
                        break;
                    };
                    let size = transmit.size;
                    if size > self.scratch.len() {
                        return Err(Error::Session("Буфер передачи QUIC поврежден".into()));
                    }
                    wire.extend(split_segments(transmit.segment_size, &self.scratch[..size]));
                }
                self.scratch.clear();
            }
            if endpoint_events.is_empty() {
                break;
            }
            for (handle, event) in endpoint_events {
                if let Some(back) = self.endpoint.handle_event(handle, event) {
                    self.dispatch_connection(handle, back);
                }
            }
        }
        Ok(())
    }

    fn drain_events(&mut self, payloads: &mut Vec<Vec<u8>>) -> Result<()> {
        let mut lost = None;
        let mut alpn_error = None;
        if let Some((_, conn)) = self.conn.as_mut() {
            while let Some(event) = conn.poll() {
                match event {
                    Event::HandshakeDataReady => {
                        if let Err(error) = check_alpn(conn) {
                            alpn_error = Some(error.to_string());
                            break;
                        }
                    }
                    Event::Connected => self.connected = true,
                    Event::ConnectionLost { reason } => {
                        lost = Some(reason.to_string());
                        break;
                    }
                    Event::DatagramReceived => {}
                    Event::DatagramsUnblocked | Event::Stream(_) => {}
                }
            }
            if lost.is_none() && alpn_error.is_none() {
                if self.connected && self.server {
                    let handshake = conn
                        .crypto_session()
                        .handshake_data()
                        .and_then(|data| data.downcast::<HandshakeData>().ok());
                    if let Some(name) = handshake
                        .as_ref()
                        .and_then(|data| data.server_name.as_deref())
                    {
                        self.application.set_authority(name)?;
                    }
                }
                self.application.poll(conn, self.connected, payloads)?;
            }
        }
        if let Some(reason) = alpn_error.or(lost) {
            return Err(self.fail(reason));
        }
        Ok(())
    }
}

impl TokenStore for BootstrapToken {
    fn insert(&self, _server_name: &str, _token: Bytes) {}

    fn take(&self, _server_name: &str) -> Option<Bytes> {
        self.0.lock().unwrap_or_else(|err| err.into_inner()).take()
    }
}

impl BootstrapToken {
    fn new(token: Bytes) -> Self {
        Self(Mutex::new(Some(token)))
    }
}

impl ServerCertVerifier for MaskServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Публичный PKI не используется. Сертификат только должен разбираться,
        // чтобы следующая проверка CertificateVerify имела ключ.
        let _parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl Identity {
    fn generate() -> Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        Ok(Self { cert, key })
    }
}

fn cached_identity() -> Result<&'static Identity> {
    static CELL: OnceLock<Identity> = OnceLock::new();
    if let Some(identity) = CELL.get() {
        return Ok(identity);
    }
    let made = Identity::generate()?;
    Ok(CELL.get_or_init(|| made))
}

fn endpoint_config() -> Result<Arc<EndpointConfig>> {
    let mut config = EndpointConfig::default();
    config
        .max_udp_payload_size(WIRE_MTU)
        .map_err(|_| Error::Crypto("MTU маски вне диапазона QUIC".into()))?;
    config.grease_quic_bit(false);
    config.cid_generator(|| Box::new(RandomConnectionIdGenerator::new(CID_LEN)));
    Ok(Arc::new(config))
}

fn transport_config() -> Result<Arc<TransportConfig>> {
    let mut config = TransportConfig::default();
    let idle = IdleTimeout::try_from(IDLE)
        .map_err(|_| Error::Crypto("Таймаут простоя вне диапазона".into()))?;
    let mut discovery = MtuDiscoveryConfig::default();
    discovery.upper_bound(WIRE_MTU);
    config
        .max_idle_timeout(Some(idle))
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(3))
        .receive_window(VarInt::from_u32(RECV_BUDGET as u32))
        .stream_receive_window(VarInt::from_u32(SEND_BUDGET as u32))
        .send_window(SEND_BUDGET as u64)
        .crypto_buffer_size(SEND_BUDGET)
        .initial_rtt(Duration::from_millis(100))
        .initial_mtu(MIN_DATAGRAM as u16)
        .min_mtu(MIN_DATAGRAM as u16)
        .mtu_discovery_config(Some(discovery))
        .datagram_receive_buffer_size(Some(RECV_BUDGET))
        .datagram_send_buffer_size(SEND_BUDGET)
        .enable_segmentation_offload(true);
    Ok(Arc::new(config))
}

fn client_crypto() -> Result<QuicClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| Error::Crypto(err.to_string()))?;
    let mut inner = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(MaskServerCertVerifier))
        .with_no_client_auth();
    inner.alpn_protocols = vec![ALPN_H3.to_vec()];
    inner.enable_early_data = false;
    #[cfg(test)]
    {
        inner.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    QuicClientConfig::try_from(inner).map_err(|err| Error::Crypto(err.to_string()))
}

fn server_config() -> Result<Arc<ServerConfig>> {
    let identity = cached_identity()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| Error::Crypto(err.to_string()))?;
    let mut inner = builder
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .map_err(|err| Error::Crypto(err.to_string()))?;
    inner.alpn_protocols = vec![ALPN_H3.to_vec()];
    inner.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(inner).map_err(|err| Error::Crypto(err.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config
        .transport_config(transport_config()?)
        .migration(false);
    config.incoming_buffer_size(RECV_BUDGET as u64);
    config.incoming_buffer_size_total(RECV_BUDGET as u64);
    Ok(Arc::new(config))
}

fn check_alpn(conn: &Connection) -> Result<()> {
    let data = conn
        .crypto_session()
        .handshake_data()
        .ok_or(Error::Session("Нет данных рукопожатия TLS".into()))?;
    let handshake = data
        .downcast_ref::<HandshakeData>()
        .ok_or(Error::Session("Неизвестный тип данных рукопожатия".into()))?;
    if handshake.protocol.as_deref() != Some(ALPN_H3) {
        return Err(Error::Session("Согласован не ALPN h3".into()));
    }
    Ok(())
}

fn read_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    let bytes = input.get(..len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

/// GSO склеивает несколько UDP payload. Наружу уходит каждый сегмент отдельно.
fn split_segments(segment_size: Option<usize>, data: &[u8]) -> Vec<Vec<u8>> {
    let Some(segment) = segment_size.filter(|size| *size > 0 && *size < data.len()) else {
        return vec![data.to_vec()];
    };
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + segment).min(data.len());
        out.push(data[offset..end].to_vec());
        offset = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn sample_initial(token: &[u8], length: usize, total: usize) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0xc0);
        packet.extend_from_slice(&1u32.to_be_bytes());
        packet.push(CID_LEN as u8);
        packet.extend_from_slice(&[0x11; CID_LEN]);
        packet.push(CID_LEN as u8);
        packet.extend_from_slice(&[0x22; CID_LEN]);
        write_varint(&mut packet, token.len() as u64);
        packet.extend_from_slice(token);
        write_varint(&mut packet, length as u64);
        packet.resize(packet.len() + length, 0x5a);
        if packet.len() < total {
            // Дополнение внутри объявленной длины, чтобы граница Length совпала.
            let missing = total - packet.len();
            let declared = length + missing;
            let len_at = packet.len() - length - varint_size(length as u64);
            packet.truncate(len_at);
            write_varint(&mut packet, declared as u64);
            packet.resize(total, 0x5a);
        }
        packet
    }

    fn write_varint(out: &mut Vec<u8>, value: u64) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16384 {
            out.push(0x40 | ((value >> 8) as u8));
            out.push(value as u8);
        } else {
            out.push(0x80 | ((value >> 24) as u8));
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
    }

    fn varint_size(value: u64) -> usize {
        if value < 64 {
            1
        } else if value < 16384 {
            2
        } else {
            4
        }
    }

    fn long_dcid(packet: &[u8]) -> &[u8] {
        let len = packet[5] as usize;
        &packet[6..6 + len]
    }

    fn long_scid(packet: &[u8]) -> Vec<u8> {
        let dcid_len = packet[5] as usize;
        let scid_at = 6 + dcid_len;
        let scid_len = packet[scid_at] as usize;
        packet[scid_at + 1..scid_at + 1 + scid_len].to_vec()
    }

    struct Pipe {
        client: QuicMask,
        server: QuicMask,
        now: Instant,
        client_payloads: Vec<Vec<u8>>,
        server_payloads: Vec<Vec<u8>>,
        client_wire: Vec<Vec<u8>>,
        server_wire: Vec<Vec<u8>>,
        wire_events: Vec<(bool, Vec<u8>)>,
        path_mtu: usize,
    }

    impl Pipe {
        fn connect(bootstrap: &[u8]) -> Result<Self> {
            Self::connect_name(bootstrap, "localhost")
        }

        fn connect_name(bootstrap: &[u8], name: &str) -> Result<Self> {
            Self::connect_path(bootstrap, name, usize::from(WIRE_MTU))
        }

        fn connect_path(bootstrap: &[u8], name: &str, path_mtu: usize) -> Result<Self> {
            let now = Instant::now();
            let mut client = QuicMask::client(bootstrap, addr(4433), name, now)?;
            let started = client.poll(now)?;
            assert!(!started.wire.is_empty(), "клиент не отправил Initial");
            assert!(started.wire[0].len() <= path_mtu);
            let mut server = QuicMask::server(&started.wire[0], addr(44433), now)?;
            for extra in started.wire.iter().skip(1) {
                server.receive(extra, addr(44433), now)?;
            }
            let mut pipe = Self {
                client,
                server,
                now,
                client_payloads: Vec::new(),
                server_payloads: Vec::new(),
                wire_events: started
                    .wire
                    .iter()
                    .cloned()
                    .map(|wire| (true, wire))
                    .collect(),
                client_wire: started.wire,
                server_wire: Vec::new(),
                path_mtu,
            };
            pipe.drive(80)?;
            assert!(
                pipe.client.connected && pipe.server.connected,
                "рукопожатие не завершилось"
            );
            Ok(pipe)
        }

        fn drive(&mut self, rounds: usize) -> Result<()> {
            for _ in 0..rounds {
                let client_out = self.client.poll(self.now)?;
                let server_out = self.server.poll(self.now)?;
                self.client_payloads.extend(client_out.payloads);
                self.server_payloads.extend(server_out.payloads);
                let idle = client_out.wire.is_empty() && server_out.wire.is_empty();
                self.deliver(client_out.wire, true)?;
                self.deliver(server_out.wire, false)?;
                if idle && self.client.application.ready() && self.server.application.ready() {
                    return Ok(());
                }
                if idle {
                    self.advance()?;
                }
            }
            Err(Error::Session("Обмен не завершился".into()))
        }

        fn deliver(&mut self, packets: Vec<Vec<u8>>, from_client: bool) -> Result<()> {
            for packet in packets {
                assert!(packet.len() <= usize::from(WIRE_MTU));
                if packet.len() > self.path_mtu {
                    continue;
                }
                self.wire_events.push((from_client, packet.clone()));
                if from_client {
                    self.client_wire.push(packet.clone());
                    self.server.receive(&packet, addr(44433), self.now)?;
                } else {
                    self.server_wire.push(packet.clone());
                    self.client.receive(&packet, addr(4433), self.now)?;
                }
            }
            Ok(())
        }

        fn advance(&mut self) -> Result<()> {
            let next = match (self.client.deadline(), self.server.deadline()) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (Some(only), None) | (None, Some(only)) => Some(only),
                (None, None) => None,
            };
            match next {
                Some(deadline) if deadline > self.now => self.now = deadline,
                Some(_) => self.now += Duration::from_millis(1),
                None => return Err(Error::Session("Обмен остановился до соединения".into())),
            }
            Ok(())
        }

        fn exchange(&mut self, from_client: &[u8], from_server: &[u8]) -> Result<()> {
            self.client.send(from_client)?;
            self.server.send(from_server)?;
            self.drive(40)
        }
    }

    #[cfg(unix)]
    #[test]
    fn only_oversized_path_probes_can_ignore_local_mtu_errors() {
        let error = std::io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert!(mtu_probe_error(&error, 1380));
        assert!(!mtu_probe_error(&error, 1200));
        assert!(!mtu_probe_error(
            &std::io::ErrorKind::PermissionDenied.into(),
            1380
        ));
    }

    #[test]
    fn quic_operates_on_minimum_ipv6_path_without_large_datagrams() {
        let mut pipe = Pipe::connect_path(b"small-path", "localhost", 1240).unwrap();
        let payload = vec![0x31; MAX_LOGICAL];
        pipe.exchange(&payload, &payload).unwrap();
        assert_eq!(pipe.server_payloads, vec![payload.clone()]);
        assert_eq!(pipe.client_payloads, vec![payload]);
        assert!(pipe.wire_events.iter().all(|(_, wire)| wire.len() <= 1240));
    }

    #[test]
    fn h3_ip_authority_does_not_require_tls_sni() {
        let mut pipe = Pipe::connect_name(b"ip-authority", "192.0.2.1").unwrap();
        pipe.exchange(b"up", b"down").unwrap();
        assert_eq!(pipe.server_payloads, vec![b"up".to_vec()]);
    }

    #[test]
    fn h3_alpn_requires_control_qpack_and_connect_request_before_datagrams() {
        let mut pipe = Pipe::connect(b"h3-application-test").unwrap();
        for mask in [&mut pipe.client, &mut pipe.server] {
            let conn = &mut mask.conn.as_mut().unwrap().1;
            assert_eq!(
                conn.streams().remote_open_streams(quinn_proto::Dir::Uni),
                3,
                "ALPN h3 без управляющего потока и QPACK"
            );
        }
        assert_eq!(
            pipe.server
                .conn
                .as_mut()
                .unwrap()
                .1
                .streams()
                .remote_open_streams(quinn_proto::Dir::Bi),
            1,
            "HTTP DATAGRAM не привязан к CONNECT-запросу"
        );
        pipe.exchange(&[1; MAX_LOGICAL], &[2; MAX_LOGICAL]).unwrap();
        assert_eq!(pipe.client_payloads, vec![vec![2; MAX_LOGICAL]]);
        assert_eq!(pipe.server_payloads, vec![vec![1; MAX_LOGICAL]]);
        if let Some(path) = std::env::var_os("AIVPN_H3_TEST_WIRE") {
            std::fs::write(path, serde_json::to_vec(&pipe.wire_events).unwrap()).unwrap();
        }
    }

    #[test]
    fn bootstrap_parser_accepts_only_strict_initial() {
        let token = b"aivpn-initial-v2-token";
        let packet = sample_initial(token, 1100, 1200);
        assert_eq!(QuicMask::bootstrap(&packet), Some(token.as_slice()));

        let mut long_token = vec![0xab; 70];
        long_token[0] = 0x01;
        let wide = sample_initial(&long_token, 1000, 1200);
        assert_eq!(QuicMask::bootstrap(&wide), Some(long_token.as_slice()));

        let mut short = packet.clone();
        short.truncate(1199);
        assert!(QuicMask::bootstrap(&short).is_none());

        let mut version = packet.clone();
        version[1] = 0xff;
        assert!(QuicMask::bootstrap(&version).is_none());

        let mut handshake = packet.clone();
        handshake[0] = 0xe0;
        assert!(QuicMask::bootstrap(&handshake).is_none());

        let mut fixed = packet.clone();
        fixed[0] = 0x80;
        assert!(QuicMask::bootstrap(&fixed).is_none());

        for bad_len in [0u8, 7, 21] {
            let mut bad = Vec::new();
            bad.push(0xc0);
            bad.extend_from_slice(&1u32.to_be_bytes());
            bad.push(bad_len);
            bad.resize(1200, 0);
            assert!(QuicMask::bootstrap(&bad).is_none(), "cid {bad_len}");
        }

        let mut empty_token = sample_initial(b"x", 1100, 1200);
        // Подменяем длину токена на 0, оставляя прежние байты дальше.
        let token_at = 5 + 1 + CID_LEN + 1 + CID_LEN;
        empty_token[token_at] = 0;
        assert!(QuicMask::bootstrap(&empty_token).is_none());

        let huge = vec![0xcd; 513];
        let too_big = sample_initial(&huge, 700, 1300);
        assert!(QuicMask::bootstrap(&too_big).is_none());

        let mut overflow = sample_initial(token, 1100, 1200);
        let len_at = 5 + 1 + CID_LEN + 1 + CID_LEN + 1 + token.len();
        overflow[len_at] = 0x7f;
        assert!(QuicMask::bootstrap(&overflow).is_none());

        let mut tiny = sample_initial(token, 16, 0);
        tiny.resize(MIN_DATAGRAM, 0x5a);
        assert!(QuicMask::bootstrap(&tiny).is_none());
    }

    #[test]
    fn verified_wire_contains_authenticated_outer_datagram_and_excludes_corruption_and_replay() {
        let mut pipe = Pipe::connect(&[7; 100]).unwrap();
        pipe.server.observe_verified_wire();
        pipe.client.send(b"aivpn test payload").unwrap();
        pipe.drive(40).unwrap();
        let samples = pipe.server.take_verified_wire();
        assert!(!samples.is_empty());
        let wire = samples[0].clone();
        assert!(pipe.client_wire.contains(&wire));
        assert_ne!(wire, b"aivpn test payload");
        pipe.server.observe_verified_wire();
        let mut corrupt = wire.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        pipe.server
            .receive(&corrupt, addr(44433), pipe.now)
            .unwrap();
        assert!(pipe.server.take_verified_wire().is_empty());
        pipe.server.receive(&wire, addr(44433), pipe.now).unwrap();
        assert!(pipe.server.take_verified_wire().is_empty());
    }

    #[test]
    fn bidirectional_datagram_hides_bootstrap_token() {
        let bootstrap = vec![0x42; 80];
        let mut pipe = Pipe::connect(&bootstrap).unwrap();
        let first = &pipe.client_wire[0];
        assert_eq!(QuicMask::bootstrap(first), Some(bootstrap.as_slice()));
        assert!(first.len() >= MIN_DATAGRAM);

        let upstream = vec![0x11; MAX_LOGICAL];
        let downstream = b"downlink-payload".to_vec();
        pipe.exchange(&upstream, &downstream).unwrap();
        assert_eq!(pipe.server_payloads, vec![upstream]);
        assert_eq!(pipe.client_payloads, vec![downstream]);
        assert!(pipe
            .server_payloads
            .iter()
            .all(|payload| payload != &bootstrap));
        assert!(pipe
            .client_payloads
            .iter()
            .all(|payload| payload != &bootstrap));

        let mut too_big = vec![0; MAX_LOGICAL + 1];
        too_big[0] = 1;
        assert!(pipe.client.send(&too_big).is_err());
    }

    #[test]
    fn timer_loss_retransmits_with_stable_cid() {
        let bootstrap = b"loss-token-stable-cid".to_vec();
        let now = Instant::now();
        let mut client = QuicMask::client(&bootstrap, addr(4433), "localhost", now).unwrap();
        let first = client.poll(now).unwrap();
        assert_eq!(
            QuicMask::bootstrap(&first.wire[0]),
            Some(bootstrap.as_slice())
        );
        let deadline = client.deadline().expect("таймер потери");
        assert!(deadline > now);
        let second = client.poll(deadline).unwrap();
        assert!(!second.wire.is_empty());
        assert_ne!(first.wire[0], second.wire[0]);
        assert_eq!(long_dcid(&first.wire[0]), long_dcid(&second.wire[0]));
        assert_eq!(long_scid(&first.wire[0]), long_scid(&second.wire[0]));
        assert_eq!(
            QuicMask::bootstrap(&second.wire[0]),
            Some(bootstrap.as_slice())
        );

        let mut server = QuicMask::server(&second.wire[0], addr(44433), deadline).unwrap();
        for extra in second.wire.iter().skip(1) {
            server.receive(extra, addr(44433), deadline).unwrap();
        }
        let mut pipe = Pipe {
            client,
            server,
            now: deadline,
            client_payloads: Vec::new(),
            server_payloads: Vec::new(),
            wire_events: second
                .wire
                .iter()
                .cloned()
                .map(|wire| (true, wire))
                .collect(),
            client_wire: second.wire,
            server_wire: Vec::new(),
            path_mtu: usize::from(WIRE_MTU),
        };
        pipe.drive(80).unwrap();
        let client_scid = long_scid(&first.wire[0]);
        let shorts: Vec<_> = pipe
            .server_wire
            .iter()
            .filter(|packet| packet[0] & 0x80 == 0)
            .cloned()
            .collect();
        assert!(!shorts.is_empty());
        assert_eq!(&shorts[0][1..1 + CID_LEN], client_scid.as_slice());
        // После NEW_CONNECTION_ID законна согласованная смена CID. Проверяем
        // прием пакетов другой стороной, а не запрещаем работу QUIC.
        let client_before = pipe.client_wire.len();
        let server_before = pipe.server_wire.len();
        pipe.exchange(b"after-loss-up", b"after-loss-down").unwrap();
        assert_eq!(pipe.server_payloads, vec![b"after-loss-up".to_vec()]);
        assert_eq!(pipe.client_payloads, vec![b"after-loss-down".to_vec()]);
        assert!(pipe.client_wire[client_before..]
            .iter()
            .all(|packet| packet[0] & 0x80 == 0));
        assert!(pipe.server_wire[server_before..]
            .iter()
            .all(|packet| packet[0] & 0x80 == 0));
    }

    #[test]
    fn send_queue_is_bounded() {
        let mut pipe = Pipe::connect(&[0x7e; 40]).unwrap();
        let payload = vec![0x3c; MAX_LOGICAL];
        let mut sent = 0usize;
        loop {
            match pipe.client.send(&payload) {
                Ok(()) => sent += 1,
                Err(_) => break,
            }
            assert!(sent <= 64, "очередь отправки не ограничена");
        }
        assert!(sent >= 1);
        assert!(sent <= SEND_BUDGET / MAX_LOGICAL + 1);
    }

    #[test]
    fn unvalidated_address_keeps_three_times_amplification_limit() {
        let now = Instant::now();
        let mut client = QuicMask::client(&[0x35; 80], addr(4433), "localhost", now).unwrap();
        let initial = client.poll(now).unwrap();
        let first = &initial.wire[0];
        let mut server = QuicMask::server(first, addr(44433), now).unwrap();
        for _ in 0..64 {
            server.send(b"queued hello").unwrap();
        }
        assert!(server.send(b"overflow").is_err());
        assert!(server.send(b"").is_err());
        let mut sent = 0;
        let mut current = now;
        for _ in 0..6 {
            let output = server.poll(current).unwrap();
            sent += output.wire.iter().map(Vec::len).sum::<usize>();
            assert!(
                sent <= first.len() * 3,
                "PSK не доказывает обратный адрес: sent={sent}, received={}, packets={}",
                first.len(),
                output.wire.len()
            );
            let Some(deadline) = server.deadline() else {
                break;
            };
            if deadline.duration_since(now) >= Duration::from_secs(10) {
                break;
            }
            current = deadline;
        }
    }

    #[test]
    fn segmented_output_splits_on_segment_size() {
        let raw = vec![0xab; 300];
        let parts = split_segments(Some(100), &raw);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.len() == 100));
        assert_eq!(split_segments(None, &raw), vec![raw.clone()]);
        assert_eq!(split_segments(Some(300), &raw), vec![raw.clone()]);
        assert_eq!(split_segments(Some(0), &raw), vec![raw]);
    }
}
