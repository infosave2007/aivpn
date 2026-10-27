//! ICE/DTLS/SRTP внутри маски, без владения сокетом или средой исполнения.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rand::{rngs::OsRng, Rng, RngCore};
use str0m::crypto::{dtls::DtlsVersion, Fingerprint};
use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::net::{Protocol, Receive};
use str0m::rtp::RtpWrite;
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc};

use crate::error::{Error, Result};
use crate::mask_state::RtcParameters;
use crate::turn_mask::TurnMask;

pub const WIRE_BUDGET: usize = 1380;
const RTP_HEADER_BUDGET: usize = 32;
const SRTP_TAG_BYTES: usize = 16;
const SRTP_BLOCK_BYTES: usize = 16;
const RTX_PREFIX_BYTES: usize = 2;
pub const MAX_INNER: usize = inner_budget(false);

/// Резерв включает MID, TWCC, absolute send time, SRTP AEAD, выравнивание и RTX.
/// Внутренний STUN-пакет также выровнен до четырех байт.
pub const fn inner_budget(turn: bool) -> usize {
    let available = WIRE_BUDGET - if turn { 4 } else { 0 } - RTP_HEADER_BUDGET - SRTP_TAG_BYTES;
    (available / SRTP_BLOCK_BYTES * SRTP_BLOCK_BYTES - RTX_PREFIX_BYTES) / 4 * 4
}

/// Запас для обычного пакета округляется до четырех байт: это сохраняет
/// выравнивание STUN при подготовке padding до передачи в str0m.
pub const fn carrier_overhead(turn: bool) -> usize {
    let reserve =
        RTP_HEADER_BUDGET + SRTP_TAG_BYTES + (SRTP_BLOCK_BYTES - 1) + if turn { 4 } else { 0 };
    (reserve + 3) / 4 * 4
}
const QUEUE: usize = 64;
const HANDSHAKE_TIME: Duration = Duration::from_secs(10);
const HANDSHAKE_BYTES: usize = 128 * 1024;

pub fn is_wire_packet(packet: &[u8]) -> bool {
    match packet.first() {
        Some(20..=191) => true,
        Some(0..=3) => matches!(
            packet.get(..2),
            Some(
                [0, 1 | 3 | 4 | 8 | 9] | [1, 1 | 3 | 4 | 8 | 9 | 0x11 | 0x13 | 0x14 | 0x18 | 0x19]
            )
        ),
        _ => false,
    }
}

pub struct RtcMask {
    rtc: Rtc,
    local: SocketAddr,
    peer: SocketAddr,
    server: bool,
    parameters: RtcParameters,
    remote: Option<RtcParameters>,
    configured: bool,
    turn_realm: Option<String>,
    turn: Option<TurnMask>,
    turn_ready: bool,
    deadline: Instant,
    started: Instant,
    sequence: u64,
    timestamp_origin: u32,
    wire: VecDeque<Vec<u8>>,
    payloads: VecDeque<Vec<u8>>,
    handshake_bytes: usize,
    verified_wire: crate::verified_wire::VerifiedWire,
}

pub struct RtcMaskOutput {
    pub wire: Vec<Vec<u8>>,
    pub payloads: Vec<Vec<u8>>,
    pub connected: bool,
}

impl RtcMask {
    pub fn new_turn(
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        server_addr: SocketAddr,
        realm: &str,
        now: Instant,
    ) -> Result<Self> {
        Self::new_internal(server, local, peer, server_addr, Some(realm), now)
    }

    pub fn new(
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        server_addr: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        Self::new_internal(server, local, peer, server_addr, None, now)
    }

    fn new_internal(
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        server_addr: SocketAddr,
        turn_realm: Option<&str>,
        now: Instant,
    ) -> Result<Self> {
        static CRYPTO: OnceLock<Arc<str0m::crypto::CryptoProvider>> = OnceLock::new();
        let crypto = CRYPTO
            .get_or_init(|| Arc::new(str0m::crypto::from_feature_flags()))
            .clone();
        let mut rtc = Rtc::builder()
            .set_crypto_provider(crypto)
            .set_dtls_cert(webrtc_certificate()?)
            .set_local_ice_credentials(IceCreds {
                ufrag: secret_hex(16),
                pass: secret_hex(32),
            })
            .set_rtp_mode(true)
            .set_ice_lite(server)
            .set_dtls_version(DtlsVersion::Dtls12)
            .set_send_buffer_audio(QUEUE)
            .set_send_buffer_video(QUEUE)
            .set_mtu(
                1200..=if turn_realm.is_some() {
                    WIRE_BUDGET - 4
                } else {
                    WIRE_BUDGET
                },
            )
            .build(now);
        let fingerprint = rtc
            .direct_api()
            .local_dtls_fingerprint()
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidPacket("Неизвестный формат отпечатка RTC"))?;
        let credentials = rtc.direct_api().local_ice_credentials();
        let parameters = RtcParameters {
            fingerprint,
            ice_ufrag: credentials.ufrag,
            ice_password: credentials.pass,
            ssrc: rand::random::<u32>().max(1),
            server_addr,
        };
        parameters.validate()?;
        let mut result = Self {
            rtc,
            local,
            peer,
            server,
            parameters,
            remote: None,
            configured: false,
            turn_realm: turn_realm.map(str::to_owned),
            turn: None,
            turn_ready: turn_realm.is_none(),
            deadline: now,
            started: now,
            sequence: OsRng.gen_range(1..=u16::MAX) as u64,
            timestamp_origin: OsRng.gen_range(1..=u32::MAX),
            wire: VecDeque::new(),
            payloads: VecDeque::new(),
            handshake_bytes: 0,
            verified_wire: Default::default(),
        };
        result.drain(now)?;
        Ok(result)
    }

    pub fn parameters(&self) -> RtcParameters {
        self.parameters.clone()
    }

    pub fn connected(&self) -> bool {
        self.remote.is_some() && self.configured && self.turn_ready && self.rtc.is_connected()
    }

    /// Вызывать только после проверки защищенного согласования AIVPN.
    /// Адреса движка логические: сокет вызывающего кода не переназначается.
    pub fn negotiate(&mut self, remote: &RtcParameters, now: Instant) -> Result<()> {
        remote.validate()?;
        if let Some(previous) = &self.remote {
            return if previous == remote {
                Ok(())
            } else {
                Err(Error::InvalidPacket(
                    "Параметры RTC нельзя заменить в одном поколении",
                ))
            };
        }
        if remote.server_addr != self.parameters.server_addr || remote.ssrc == self.parameters.ssrc
        {
            return Err(Error::InvalidPacket("Несогласованные параметры RTC"));
        }
        self.remote = Some(remote.clone());
        self.started = now;
        if let Some(realm) = self.turn_realm.as_ref() {
            let client = if self.server {
                remote
            } else {
                &self.parameters
            };
            let password = zeroize::Zeroizing::new(hex::encode(blake3::derive_key(
                "aivpn-mask-turn-credentials-v1",
                client.ice_password.as_bytes(),
            )));
            self.turn = Some(if self.server {
                TurnMask::server(
                    &client.ice_ufrag,
                    &password,
                    realm,
                    self.parameters.server_addr,
                    self.peer,
                    now,
                )?
            } else {
                TurnMask::client(
                    &client.ice_ufrag,
                    &password,
                    realm,
                    self.parameters.server_addr,
                    now,
                )?
            });
            if self.server {
                self.peer = self.turn.as_ref().unwrap().relayed_addr();
                self.configure_rtc(remote, now)?;
            }
        } else {
            self.configure_rtc(remote, now)?;
        }
        Ok(())
    }

    fn configure_rtc(&mut self, remote: &RtcParameters, now: Instant) -> Result<()> {
        let local = if let Some(turn) = self.turn.as_ref().filter(|_| !self.server) {
            Candidate::relayed(turn.relayed_addr(), self.local, "udp")
        } else {
            Candidate::host(self.local, "udp")
        }
        .map_err(rtc_error)?;
        let peer = if self.turn.is_some() && self.server {
            Candidate::relayed(self.peer, self.peer, "udp")
        } else {
            Candidate::host(self.peer, "udp")
        }
        .map_err(rtc_error)?;
        self.rtc.add_local_candidate(local);
        self.drain(now)?;
        self.rtc.add_remote_candidate(peer);
        self.drain(now)?;
        self.rtc.direct_api().set_remote_fingerprint(Fingerprint {
            hash_func: "sha-256".into(),
            bytes: remote.fingerprint.to_vec(),
        });
        self.drain(now)?;
        self.rtc.direct_api().set_remote_ice_credentials(IceCreds {
            ufrag: remote.ice_ufrag.clone(),
            pass: remote.ice_password.clone(),
        });
        self.drain(now)?;
        self.rtc.direct_api().set_ice_controlling(!self.server);
        self.drain(now)?;
        let mid = "audio".into();
        self.rtc.direct_api().declare_media(mid, MediaKind::Audio);
        self.drain(now)?;
        self.rtc
            .direct_api()
            .declare_stream_tx(self.parameters.ssrc.into(), None, mid, None);
        self.drain(now)?;
        self.rtc
            .direct_api()
            .expect_stream_rx(remote.ssrc.into(), None, mid, None)
            .suppress_nack(true);
        self.drain(now)?;
        self.rtc
            .direct_api()
            .start_dtls(!self.server)
            .map_err(rtc_error)?;
        self.drain(now)?;
        self.configured = true;
        Ok(())
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.remote.as_ref()?;
        [
            self.configured.then_some(self.deadline),
            self.turn.as_ref().and_then(TurnMask::deadline),
            (!self.connected()).then_some(self.started + HANDSHAKE_TIME),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn poll(&mut self, now: Instant) -> Result<RtcMaskOutput> {
        self.ensure_open(now)?;
        self.poll_turn(now)?;
        if self.configured && self.deadline <= now {
            self.rtc
                .handle_input(Input::Timeout(now))
                .map_err(rtc_error)?;
            self.drain(now)?;
        }
        self.poll_turn(now)?;
        Ok(RtcMaskOutput {
            wire: self.wire.drain(..).collect(),
            payloads: self.payloads.drain(..).collect(),
            connected: self.connected(),
        })
    }

    pub fn receive(&mut self, packet: &[u8], now: Instant) -> Result<()> {
        let before = self.payloads.len();
        let result = if let Some(turn) = self.turn.as_mut() {
            turn.receive(packet, now)?;
            self.poll_turn(now)
        } else {
            self.receive_inner(packet, now)
        };
        if result.is_ok() && self.payloads.len() > before {
            self.verified_wire.record(packet);
        }
        result
    }

    pub fn observe_verified_wire(&mut self) {
        self.verified_wire.enable();
    }

    pub fn take_verified_wire(&mut self) -> Vec<Vec<u8>> {
        self.verified_wire.take()
    }

    fn receive_inner(&mut self, packet: &[u8], now: Instant) -> Result<()> {
        self.ensure_open(now)?;
        let Some(remote) = &self.remote else {
            return Ok(());
        };
        if packet.len() < 2 || packet.len() > WIRE_BUDGET {
            return Ok(());
        }
        match packet[0] {
            0..=3 => {}
            20..=63 => {}
            128..=191 => {
                if !self.rtc.is_connected() {
                    return Ok(());
                }
                // SRTP не должен создавать состояние для чужого SSRC до AEAD.
                // SRTCP проверяется библиотекой до разбора отчетов.
                if !(192..=223).contains(&packet[1])
                    && (packet.len() < 12 || packet[8..12] != remote.ssrc.to_be_bytes())
                {
                    return Ok(());
                }
            }
            _ => return Ok(()),
        }
        if !self.rtc.is_connected() {
            self.handshake_bytes = self.handshake_bytes.saturating_add(packet.len());
            if self.handshake_bytes > HANDSHAKE_BYTES {
                self.rtc.disconnect();
                return Err(Error::InvalidPacket("Превышен бюджет рукопожатия RTC"));
            }
        }
        let Ok(input) = Receive::new(Protocol::Udp, self.peer, self.local, packet) else {
            return Ok(());
        };
        // Ошибка внешнего пакета не превращается в новую сессию или обход AEAD.
        let _ = self.rtc.handle_input(Input::Receive(now, input));
        self.drain(now)
    }

    pub fn send(&mut self, packet: &[u8], now: Instant) -> Result<()> {
        self.ensure_open(now)?;
        if packet.is_empty() || packet.len() > inner_budget(self.turn_realm.is_some()) {
            return Err(Error::InvalidPacket("Пакет не вмещается в RTC-маску"));
        }
        if !self.connected() || self.wire.len() >= QUEUE {
            return Err(Error::Io(std::io::ErrorKind::WouldBlock.into()));
        }
        let pt = self
            .rtc
            .codec_config()
            .find(|parameters| parameters.spec().codec == Codec::Opus)
            .ok_or(Error::InvalidPacket("Нет согласованного RTP payload type"))?
            .pt();
        // 48 кГц, без накопления скрытой очереди полезных пакетов.
        let timestamp = now
            .saturating_duration_since(self.started)
            .as_micros()
            .saturating_mul(48)
            / 1000;
        let mut direct = self.rtc.direct_api();
        let stream = direct
            .stream_tx_by_mid("audio".into(), None)
            .ok_or(Error::InvalidPacket("Нет согласованного RTP потока"))?;
        stream.write_rtp(RtpWrite::new(
            pt,
            self.sequence.into(),
            self.timestamp_origin.wrapping_add(timestamp as u32),
            now,
            packet.to_vec(),
        ));
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::InvalidPacket("Исчерпан счетчик RTP"))?;
        self.drain(now)
    }

    fn ensure_open(&self, now: Instant) -> Result<()> {
        if !self.rtc.is_alive()
            || (self.remote.is_some()
                && !self.connected()
                && now.saturating_duration_since(self.started) >= HANDSHAKE_TIME)
        {
            return Err(Error::Session(
                "RTC-маска закрыта или истекло время рукопожатия".into(),
            ));
        }
        Ok(())
    }

    fn drain(&mut self, now: Instant) -> Result<()> {
        // Каждое изменение Rtc завершается Output::Timeout. Ограничение также
        // защищает актор от бесконечного цикла внутри протокольного движка.
        for _ in 0..256 {
            match self.rtc.poll_output().map_err(rtc_error)? {
                Output::Timeout(deadline) => {
                    self.deadline = deadline.max(now + Duration::from_millis(1));
                    return Ok(());
                }
                Output::Transmit(packet) => {
                    if let Some(turn) = self.turn.as_mut() {
                        match turn.send(&packet.contents, now) {
                            Err(Error::Io(error))
                                if error.kind() == std::io::ErrorKind::WouldBlock => {}
                            result => result?,
                        }
                        continue;
                    }
                    if packet.contents.len() > WIRE_BUDGET || self.wire.len() >= QUEUE {
                        return Err(Error::InvalidPacket("Превышен бюджет выхода RTC"));
                    }
                    self.wire.push_back(packet.contents.to_vec());
                }
                Output::Event(Event::RtpPacket(packet)) => {
                    if packet.payload.len() > MAX_INNER || self.payloads.len() >= QUEUE {
                        return Err(Error::InvalidPacket("Превышен бюджет приема RTC"));
                    }
                    self.payloads.push_back(packet.payload.to_vec());
                }
                Output::Event(_) => {}
            }
        }
        Err(Error::InvalidPacket("RTC не возвращает срок ожидания"))
    }

    fn poll_turn(&mut self, now: Instant) -> Result<()> {
        let Some(turn) = self.turn.as_mut() else {
            return Ok(());
        };
        let output = turn.poll(now)?;
        self.turn_ready = output.ready;
        for packet in output.wire {
            if self.wire.len() < QUEUE {
                self.wire.push_back(packet);
            }
        }
        if output.ready && !self.configured {
            let remote = self
                .remote
                .clone()
                .ok_or(Error::InvalidPacket("Нет параметров RTC для TURN"))?;
            self.configure_rtc(&remote, now)?;
        }
        for payload in output.payloads {
            self.receive_inner(&payload, now)?;
        }
        Ok(())
    }
}

fn rtc_error(error: impl std::fmt::Display) -> Error {
    Error::Session(error.to_string())
}

fn webrtc_certificate() -> Result<str0m::crypto::dtls::DtlsCert> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(rtc_error)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(rtc_error)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "WebRTC");
    // Как в libwebrtc: 30 дней жизни и сутки допуска для расхождения часов.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(30);
    params.serial_number = Some(OsRng.next_u64().max(1).into());
    let cert = params.self_signed(&key).map_err(rtc_error)?;
    Ok(str0m::crypto::dtls::DtlsCert {
        certificate: cert.der().to_vec(),
        private_key: key.serialize_der(),
    })
}

fn secret_hex(length: usize) -> String {
    let mut bytes = vec![0; length];
    OsRng.fill_bytes(&mut bytes);
    let text = hex::encode(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::time::Duration;

    #[test]
    fn boundary_payloads_fit_both_directions_before_and_after_rtcp_reports() {
        for turn in [false, true] {
            let start = Instant::now();
            let a = "192.0.2.1:50000".parse().unwrap();
            let b = "192.0.2.2:443".parse().unwrap();
            let (mut left, mut right) = if turn {
                (
                    RtcMask::new_turn(false, a, b, b, "turn.example", start).unwrap(),
                    RtcMask::new_turn(true, b, a, b, "turn.example", start).unwrap(),
                )
            } else {
                (
                    RtcMask::new(false, a, b, b, start).unwrap(),
                    RtcMask::new(true, b, a, b, start).unwrap(),
                )
            };
            left.negotiate(&right.parameters(), start).unwrap();
            right.negotiate(&left.parameters(), start).unwrap();
            let maximum = inner_budget(turn);
            let sizes = [1, 15, 16, 17, maximum - 16, maximum - 1, maximum];
            let mut wire = VecDeque::<(usize, Vec<u8>)>::new();
            let mut received = [vec![], vec![]];
            let mut expected = [vec![], vec![]];
            let mut reports = [false; 2];
            let mut batches = 0;
            for step in 0..20_000 {
                let now = start + Duration::from_millis(step);
                while let Some((destination, packet)) = wire.pop_front() {
                    let content = if turn && packet.first() == Some(&0x40) {
                        &packet[4..]
                    } else {
                        &packet
                    };
                    let report = content.first().is_some_and(|first| first & 0xc0 == 0x80)
                        && content
                            .get(1)
                            .is_some_and(|kind| matches!(*kind, 200 | 201));
                    let peer = if destination == 0 {
                        &mut left
                    } else {
                        &mut right
                    };
                    peer.receive(&packet, now).unwrap();
                    reports[destination] |= report;
                }
                let mut connected = true;
                for (index, peer) in [&mut left, &mut right].into_iter().enumerate() {
                    let output = peer.poll(now).unwrap();
                    connected &= output.connected;
                    received[index].extend(output.payloads);
                    for packet in output.wire {
                        assert!(packet.len() <= WIRE_BUDGET, "TURN={turn}: {}", packet.len());
                        wire.push_back((1 - index, packet));
                    }
                }
                if connected && (batches == 0 || (batches == 1 && reports.iter().all(|seen| *seen)))
                {
                    for (index, peer) in [&mut left, &mut right].into_iter().enumerate() {
                        assert!(peer.send(&vec![0; maximum + 1], now).is_err());
                        for (number, length) in sizes.iter().enumerate() {
                            let packet =
                                vec![(1 + index * 32 + batches * 8 + number) as u8; *length];
                            peer.send(&packet, now).unwrap();
                            expected[1 - index].push(packet);
                        }
                    }
                    batches += 1;
                }
                if batches == 2 && received == expected {
                    break;
                }
            }
            assert_eq!(batches, 2, "Не получены отчеты RTCP");
            assert_eq!(received, expected, "TURN={turn}");
        }
    }

    #[test]
    fn dtls_certificate_has_webrtc_identity_and_is_fresh_per_generation() {
        let first = webrtc_certificate().unwrap();
        let second = webrtc_certificate().unwrap();
        assert!(
            first.certificate.windows(6).any(|part| part == b"WebRTC"),
            "В сертификате осталась узнаваемая тестовая DTLS identity"
        );
        assert!(!first
            .certificate
            .windows(9)
            .any(|part| part == b"DTLS Peer"));
        assert_ne!(first.certificate, second.certificate);
        assert_ne!(first.private_key, second.private_key);
    }

    #[test]
    fn turn_contains_ice_dtls_and_srtp_without_opening_another_socket() {
        let start = Instant::now();
        let a = "192.0.2.1:50000".parse().unwrap();
        let b = "192.0.2.2:443".parse().unwrap();
        let mut left = RtcMask::new_turn(false, a, b, b, "turn.example", start).unwrap();
        let mut right = RtcMask::new_turn(true, b, a, b, "turn.example", start).unwrap();
        left.negotiate(&right.parameters(), start).unwrap();
        right.negotiate(&left.parameters(), start).unwrap();
        let mut wire = VecDeque::<(bool, Vec<u8>)>::new();
        let mut kinds = std::collections::HashSet::new();
        let mut received = [vec![], vec![]];
        let mut wrote = false;
        let mut dropped_turn = false;
        let mut dropped_dtls = false;
        let mut checked_mapped_relay = false;
        for step in 0..10_000 {
            let now = start + Duration::from_millis(step);
            while let Some((to_right, packet)) = wire.pop_front() {
                let peer = if to_right { &mut right } else { &mut left };
                if packet[0] & 0xc0 == 0x40
                    && packet.len() >= 16
                    && packet[4] & 0xc0 == 0x80
                    && !(192..=223).contains(&packet[5])
                {
                    peer.observe_verified_wire();
                    let mut corrupt = packet.clone();
                    *corrupt.last_mut().unwrap() ^= 1;
                    peer.receive(&corrupt, now).unwrap();
                    let mut foreign = packet.clone();
                    foreign[12..16].copy_from_slice(&0u32.to_be_bytes());
                    peer.receive(&foreign, now).unwrap();
                    assert!(peer.take_verified_wire().is_empty());
                    peer.receive(&packet, now).unwrap();
                    assert_eq!(peer.take_verified_wire(), vec![packet.clone()]);
                    peer.observe_verified_wire();
                }
                peer.receive(&packet, now).unwrap();
                assert!(peer.take_verified_wire().is_empty());
            }
            let mut connected = true;
            for (index, peer) in [&mut left, &mut right].into_iter().enumerate() {
                let output = peer.poll(now).unwrap();
                connected &= output.connected;
                received[index].extend(output.payloads);
                for packet in output.wire {
                    assert!(packet.len() <= 1380);
                    let typ = u16::from_be_bytes([packet[0], packet[1]]);
                    if packet[0] & 0xc0 == 0 {
                        assert!(
                            [3, 0x0113, 0x0103, 8, 0x0108, 9, 0x0109].contains(&typ),
                            "ICE вышел вне ChannelData: {typ:#x}"
                        );
                        kinds.insert("TURN");
                        if typ == 0x0113 && !dropped_turn {
                            dropped_turn = true;
                            continue;
                        }
                    } else {
                        assert_eq!(typ, 0x4000, "DTLS или SRTP вышел вне ChannelData");
                        let payload = &packet[4..];
                        if index == 1 && payload.starts_with(&[1, 1]) {
                            let message = crate::turn_wire::TurnMessage::parse(payload).unwrap();
                            let mapped = message
                                .address(stun::attributes::ATTR_XORMAPPED_ADDRESS)
                                .unwrap();
                            assert_eq!(mapped, peer.turn.as_ref().unwrap().relayed_addr());
                            assert_ne!(
                                mapped, a,
                                "Вложенный ICE раскрыл физический адрес вместо relay"
                            );
                            checked_mapped_relay = true;
                        }
                        if (20..=63).contains(&payload[0]) && !dropped_dtls {
                            dropped_dtls = true;
                            continue;
                        }
                        kinds.insert(match payload[0] {
                            0..=3 => "ICE",
                            20..=63 => "DTLS",
                            128..=191 => "SRTP",
                            _ => "other",
                        });
                    }
                    wire.push_back((index == 0, packet));
                }
            }
            if connected && !wrote {
                left.send(&vec![42; MAX_INNER], now).unwrap();
                right.send(&vec![43; MAX_INNER], now).unwrap();
                wrote = true;
            }
            if received.iter().all(|packets| !packets.is_empty()) {
                break;
            }
        }
        assert_eq!(received[0], vec![vec![43; MAX_INNER]]);
        assert_eq!(received[1], vec![vec![42; MAX_INNER]]);
        assert!(kinds.is_superset(&std::collections::HashSet::from([
            "TURN", "ICE", "DTLS", "SRTP"
        ])));
        assert!(dropped_turn && dropped_dtls);
        assert!(checked_mapped_relay);
    }

    fn pair(now: Instant, wrong_fingerprint: bool) -> (RtcMask, RtcMask) {
        let client = "192.0.2.1:10000".parse().unwrap();
        let server = "192.0.2.2:443".parse().unwrap();
        let mut left = RtcMask::new(false, client, server, server, now).unwrap();
        let mut right = RtcMask::new(true, server, client, server, now).unwrap();
        let mut remote = right.parameters();
        if wrong_fingerprint {
            remote.fingerprint[0] ^= 1;
        }
        left.negotiate(&remote, now).unwrap();
        right.negotiate(&left.parameters(), now).unwrap();
        (left, right)
    }

    #[test]
    fn real_ice_dtls_srtp_survives_loss_and_rejects_corruption_replay_and_foreign_ssrc() {
        let start = Instant::now();
        let (mut left, mut right) = pair(start, false);
        let mut wire = VecDeque::<(bool, Vec<u8>)>::new();
        let mut kinds = HashSet::new();
        let mut dropped = false;
        let mut wrote = false;
        let mut received = [vec![], vec![]];
        for step in 0..10_000 {
            let now = start + Duration::from_millis(step);
            while let Some((to_right, bytes)) = wire.pop_front() {
                let peer = if to_right { &mut right } else { &mut left };
                if bytes[0] & 0xc0 == 0x80 && !(192..=223).contains(&bytes[1]) {
                    peer.observe_verified_wire();
                    let mut damaged = bytes.clone();
                    *damaged.last_mut().unwrap() ^= 1;
                    peer.receive(&damaged, now).unwrap();
                    let mut foreign = bytes.clone();
                    foreign[8..12].copy_from_slice(&0u32.to_be_bytes());
                    peer.receive(&foreign, now).unwrap();
                    assert!(peer.take_verified_wire().is_empty());
                    peer.receive(&bytes, now).unwrap();
                    assert_eq!(peer.take_verified_wire(), vec![bytes.clone()]);
                    peer.observe_verified_wire();
                }
                peer.receive(&bytes, now).unwrap();
                assert!(peer.take_verified_wire().is_empty());
            }
            let mut connected = true;
            for (index, peer) in [&mut left, &mut right].into_iter().enumerate() {
                let output = peer.poll(now).unwrap();
                connected &= output.connected;
                received[index].extend(output.payloads);
                for bytes in output.wire {
                    assert!(bytes.len() <= 1380);
                    let kind = match bytes[0] {
                        0..=3 => "STUN",
                        20..=63 => "DTLS",
                        128..=191 => "SRTP",
                        _ => "other",
                    };
                    kinds.insert(kind);
                    if !dropped && kind == "DTLS" {
                        dropped = true;
                        continue;
                    }
                    assert!(wire.len() < 64);
                    wire.push_back((index == 0, bytes));
                }
            }
            if connected && !wrote {
                left.send(&vec![42; MAX_INNER], now).unwrap();
                right.send(&vec![43; MAX_INNER], now).unwrap();
                wrote = true;
            }
            if wrote && received.iter().all(|packets| !packets.is_empty()) {
                break;
            }
        }
        assert!(wrote, "Потерянный ClientHello не восстановлен");
        assert_eq!(received[0], vec![vec![43; MAX_INNER]]);
        assert_eq!(received[1], vec![vec![42; MAX_INNER]]);
        assert!(kinds.is_superset(&HashSet::from(["STUN", "DTLS", "SRTP"])));
        assert!(left
            .send(&vec![0; 1380], start + Duration::from_secs(11))
            .is_err());
    }

    #[test]
    fn fingerprint_mismatch_never_establishes_media() {
        let start = Instant::now();
        let (mut left, mut right) = pair(start, true);
        let mut wire = VecDeque::<(bool, Vec<u8>)>::new();
        for step in 0..10_000 {
            let now = start + Duration::from_millis(step);
            while let Some((to_right, bytes)) = wire.pop_front() {
                let _ = if to_right {
                    right.receive(&bytes, now)
                } else {
                    left.receive(&bytes, now)
                };
            }
            for (index, peer) in [&mut left, &mut right].into_iter().enumerate() {
                if let Ok(output) = peer.poll(now) {
                    assert!(!output.connected, "Отпечаток сертификата не проверен");
                    assert!(output.payloads.is_empty());
                    for bytes in output.wire {
                        wire.push_back((index == 0, bytes));
                    }
                }
            }
        }
    }

    #[test]
    fn restart_changes_fingerprint_credentials_and_ssrc() {
        let now = Instant::now();
        let a = "192.0.2.1:1".parse().unwrap();
        let b = "192.0.2.2:2".parse().unwrap();
        let left = RtcMask::new(false, a, b, b, now).unwrap().parameters();
        let right = RtcMask::new(false, a, b, b, now).unwrap().parameters();
        assert_ne!(left.fingerprint, right.fingerprint);
        assert_ne!(left.ice_password, right.ice_password);
        assert_ne!(left.ice_ufrag, right.ice_ufrag);
        assert_ne!(left.ssrc, right.ssrc);
        assert_eq!(
            left.ice_password.len(),
            64,
            "Пароль должен содержать 32 байта от OsRng"
        );
        assert_eq!(left.ice_ufrag.len(), 32);
        let engine = RtcMask::new(false, a, b, b, now).unwrap();
        assert!(
            (1..=u16::MAX as u64).contains(&engine.sequence),
            "Начальный RTP sequence не должен быть постоянным нулем"
        );
    }

    #[test]
    fn handshake_input_and_work_are_bounded() {
        let now = Instant::now();
        let (mut left, mut right) = pair(now, false);
        for peer in [&mut left, &mut right] {
            for _ in 0..1000 {
                let _ = peer.poll(now).unwrap();
                assert!(peer.deadline().unwrap() > now, "Таймер вызывает busy loop");
            }
        }
        let bad = [22; WIRE_BUDGET];
        let mut exhausted = false;
        for _ in 0..128 {
            if left.receive(&bad, now).is_err() {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted, "Входной бюджет DTLS не ограничен");
        assert!(left.handshake_bytes <= HANDSHAKE_BYTES + WIRE_BUDGET);
        assert!(
            right.poll(now + HANDSHAKE_TIME).is_err(),
            "Нет срока завершения handshake"
        );
    }

    #[test]
    fn idle_connection_does_not_wake_on_every_millisecond() {
        let start = Instant::now();
        let (mut left, mut right) = pair(start, false);
        let mut wire = VecDeque::<(bool, Vec<u8>)>::new();
        let mut wakes = 0;
        let mut reasons = std::collections::BTreeMap::new();
        for step in 0..20_000 {
            let now = start + Duration::from_millis(step);
            while let Some((to_right, bytes)) = wire.pop_front() {
                let peer = if to_right { &mut right } else { &mut left };
                peer.receive(&bytes, now).unwrap();
            }
            for (index, peer) in [&mut left, &mut right].into_iter().enumerate() {
                if peer.deadline().is_some_and(|deadline| deadline <= now) {
                    wakes += 1;
                    *reasons
                        .entry(format!("{:?}", peer.rtc.last_timeout_reason()))
                        .or_insert(0usize) += 1;
                }
                let output = peer.poll(now).unwrap();
                for bytes in output.wire {
                    wire.push_back((index == 0, bytes));
                }
            }
        }
        assert!(left.connected() && right.connected());
        assert!(
            wakes <= 400,
            "Простой создал {wakes} пробуждений за 20 секунд: {reasons:?}"
        );
    }
}
