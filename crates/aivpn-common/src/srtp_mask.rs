//! ICE и SRTP без DTLS. Секреты согласуются только защищенным обменом AIVPN.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};

use ice::stun::{StunMessage, StunPacket};
use ice::{Candidate, IceAgent, IceAgentEvent, IceConnectionState, IceCreds, Protocol};
use rand::{rngs::OsRng, Rng, RngCore};
use srtp::{
    context::Context,
    option::{srtcp_replay_protection, srtp_replay_protection},
    protection_profile::ProtectionProfile,
};
use zeroize::Zeroizing;

use crate::{
    mask_state::SrtpParameters, rtc_mask::RtcMaskOutput, turn_wire::TurnMessage, Error, Result,
};

pub const MAX_INNER: usize = 1358;
pub const OVERHEAD: usize = 22;
const QUEUE: usize = 64;

pub struct SrtpMask {
    ice: IceAgent,
    parameters: SrtpParameters,
    remote: Option<SrtpParameters>,
    tx: Context,
    rx: Option<Context>,
    local: SocketAddr,
    peer: SocketAddr,
    started: Instant,
    last_now: Instant,
    rtcp_at: Instant,
    sequence: u16,
    timestamp: u32,
    wire: VecDeque<Vec<u8>>,
    payloads: VecDeque<Vec<u8>>,
    verified_wire: crate::verified_wire::VerifiedWire,
}

impl SrtpMask {
    pub fn new(
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        server_addr: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        let parameters = SrtpParameters {
            master_secret: rand::random(),
            ice_ufrag: secret(16),
            ice_password: secret(32),
            ssrc: OsRng.gen_range(1..=u32::MAX),
            server_addr,
        };
        parameters.validate()?;
        let mut ice = IceAgent::new(IceCreds {
            ufrag: parameters.ice_ufrag.clone(),
            pass: parameters.ice_password.clone(),
        });
        ice.set_ice_lite(server);
        ice.set_controlling(!server);
        ice.set_control_tie_breaker(OsRng.next_u64());
        ice.set_mtu(1200..=1380);
        ice.set_max_candidate_pairs(1);
        let tx = context(&parameters.master_secret, false)?;
        Ok(Self {
            ice,
            parameters,
            remote: None,
            tx,
            rx: None,
            local,
            peer,
            started: now,
            last_now: now,
            rtcp_at: now + Duration::from_secs(5),
            sequence: OsRng.gen(),
            timestamp: OsRng.gen(),
            wire: VecDeque::new(),
            payloads: VecDeque::new(),
            verified_wire: Default::default(),
        })
    }

    pub fn parameters(&self) -> SrtpParameters {
        self.parameters.clone()
    }

    pub fn negotiate(&mut self, remote: &SrtpParameters, now: Instant) -> Result<()> {
        remote.validate()?;
        if let Some(previous) = &self.remote {
            return if previous == remote {
                Ok(())
            } else {
                Err(Error::InvalidPacket("Нельзя заменить поколение SRTP"))
            };
        }
        if remote.server_addr != self.parameters.server_addr
            || remote.ssrc == self.parameters.ssrc
            || remote.master_secret == self.parameters.master_secret
        {
            return Err(Error::InvalidPacket("Несогласованные параметры SRTP"));
        }
        let rx = context(&remote.master_secret, true)?;
        self.ice.set_remote_credentials(IceCreds {
            ufrag: remote.ice_ufrag.clone(),
            pass: remote.ice_password.clone(),
        });
        self.ice.add_local_candidate(
            Candidate::host(self.local, "udp")
                .map_err(|_| Error::InvalidPacket("Недопустимый ICE local"))?,
        );
        self.ice.add_remote_candidate(
            Candidate::host(self.peer, "udp")
                .map_err(|_| Error::InvalidPacket("Недопустимый ICE peer"))?,
        );
        self.rx = Some(rx);
        self.remote = Some(remote.clone());
        self.started = now;
        self.last_now = now;
        self.ice.handle_timeout(now);
        self.drain_ice()
    }

    pub fn connected(&self) -> bool {
        self.rx.is_some()
            && matches!(
                self.ice.state(),
                IceConnectionState::Connected | IceConnectionState::Completed
            )
    }

    pub fn deadline(&mut self) -> Option<Instant> {
        if self.remote.is_none() {
            return None;
        }
        [
            self.ice.poll_timeout(),
            Some(if self.connected() {
                self.rtcp_at
            } else {
                self.started + Duration::from_secs(10)
            }),
        ]
        .into_iter()
        .flatten()
        .min()
        .map(|at| at.max(self.last_now + Duration::from_millis(1)))
    }

    pub fn poll(&mut self, now: Instant) -> Result<RtcMaskOutput> {
        let now = now.max(self.last_now);
        self.last_now = now;
        if self.remote.is_some() {
            if !self.connected() && now >= self.started + Duration::from_secs(10) {
                return Err(Error::Session("Истекло время ICE/SRTP".into()));
            }
            if self.ice.poll_timeout().is_some_and(|at| at <= now) {
                self.ice.handle_timeout(now);
            }
            self.drain_ice()?;
            if self.connected() && self.rtcp_at <= now && self.wire.len() < QUEUE {
                let mut report = vec![0x80, 201, 0, 1];
                report.extend_from_slice(&self.parameters.ssrc.to_be_bytes());
                let mut chunk = self.parameters.ssrc.to_be_bytes().to_vec();
                chunk.extend_from_slice(&[1, self.parameters.ice_ufrag.len() as u8]);
                chunk.extend_from_slice(self.parameters.ice_ufrag.as_bytes());
                chunk.push(0);
                while chunk.len() % 4 != 0 {
                    chunk.push(0);
                }
                report.extend_from_slice(&[0x81, 202]);
                report.extend_from_slice(&((chunk.len() / 4) as u16).to_be_bytes());
                report.extend(chunk);
                self.wire.push_back(
                    self.tx
                        .encrypt_rtcp(&report)
                        .map_err(|_| Error::InvalidPacket("Не удалось защитить RTCP"))?
                        .to_vec(),
                );
                self.rtcp_at = now + Duration::from_millis(OsRng.gen_range(2500..=7500));
            }
        }
        Ok(RtcMaskOutput {
            wire: self.wire.drain(..).collect(),
            payloads: self.payloads.drain(..).collect(),
            connected: self.connected(),
        })
    }

    pub fn receive(&mut self, packet: &[u8], now: Instant) -> Result<()> {
        let now = now.max(self.last_now);
        self.last_now = now;
        let Some(remote) = &self.remote else {
            return Ok(());
        };
        if packet.len() < 2 || packet.len() > 1380 {
            return Ok(());
        }
        if packet[0] <= 3 {
            if TurnMessage::parse(packet).is_err() {
                return Ok(());
            }
            let Ok(message) = StunMessage::parse(packet) else {
                return Ok(());
            };
            let accepted = self.ice.handle_packet(
                now.max(self.last_now),
                StunPacket {
                    proto: Protocol::Udp,
                    source: self.peer,
                    destination: self.local,
                    message,
                },
            );
            if accepted {
                self.ice.handle_timeout(now);
            }
        } else if self.connected() {
            let Some(rx) = self.rx.as_mut() else {
                return Ok(());
            };
            if (192..=223).contains(&packet[1]) {
                if packet.len() >= 22 && packet[4..8] == remote.ssrc.to_be_bytes() {
                    let _ = rx.decrypt_rtcp(packet);
                }
            } else if packet.len() >= OVERHEAD
                && packet[0] == 0x80
                && packet[1] & 0x7f == 111
                && packet[8..12] == remote.ssrc.to_be_bytes()
            {
                if let Ok(plain) = rx.decrypt_rtp(packet) {
                    if plain.len() > 12
                        && plain.len() <= 12 + MAX_INNER
                        && self.payloads.len() < QUEUE
                    {
                        self.payloads.push_back(plain[12..].to_vec());
                        self.verified_wire.record(packet);
                    }
                }
            }
        }
        self.drain_ice()
    }

    pub fn send(&mut self, payload: &[u8], now: Instant) -> Result<()> {
        if !self.connected() || self.wire.len() >= QUEUE {
            return Err(Error::Io(std::io::ErrorKind::WouldBlock.into()));
        }
        if payload.is_empty() || payload.len() > MAX_INNER {
            return Err(Error::InvalidPacket("Пакет превышает бюджет SRTP"));
        }
        let now = now.max(self.last_now);
        let elapsed = now
            .duration_since(self.started)
            .as_micros()
            .saturating_mul(48)
            / 1000;
        let timestamp = self.timestamp.wrapping_add(elapsed as u32);
        self.last_now = now;
        let mut plain = vec![0x80, 111];
        plain.extend_from_slice(&self.sequence.to_be_bytes());
        plain.extend_from_slice(&timestamp.to_be_bytes());
        plain.extend_from_slice(&self.parameters.ssrc.to_be_bytes());
        plain.extend_from_slice(payload);
        let protected = self
            .tx
            .encrypt_rtp(&plain)
            .map_err(|_| Error::InvalidPacket("Не удалось защитить RTP"))?;
        self.sequence = self.sequence.wrapping_add(1);
        self.wire.push_back(protected.to_vec());
        Ok(())
    }

    pub fn observe_verified_wire(&mut self) {
        self.verified_wire.enable();
    }

    pub fn take_verified_wire(&mut self) -> Vec<Vec<u8>> {
        self.verified_wire.take()
    }

    fn drain_ice(&mut self) -> Result<()> {
        for _ in 0..QUEUE {
            let Some(packet) = self.ice.poll_transmit() else {
                break;
            };
            if packet.contents.len() <= 1380 && self.wire.len() < QUEUE {
                self.wire.push_back(packet.contents.to_vec());
            }
        }
        for _ in 0..QUEUE {
            let Some(event) = self.ice.poll_event() else {
                break;
            };
            if let IceAgentEvent::IceConnectionStateChange(IceConnectionState::Disconnected) = event
            {
                return Err(Error::Session("Потеряна ICE/SRTP сессия".into()));
            }
        }
        Ok(())
    }
}

fn context(secret: &[u8; 32], receive: bool) -> Result<Context> {
    let key = Zeroizing::new(blake3::derive_key("aivpn-srtp-mask-key-v1", secret));
    let salt = Zeroizing::new(blake3::derive_key("aivpn-srtp-mask-salt-v1", secret));
    Context::new(
        &key[..16],
        &salt[..14],
        ProtectionProfile::Aes128CmHmacSha1_80,
        receive.then(|| srtp_replay_protection(128)),
        receive.then(|| srtcp_replay_protection(128)),
    )
    .map_err(|_| Error::InvalidPacket("Не удалось создать SRTP context"))
}

fn secret(length: usize) -> String {
    let mut bytes = Zeroizing::new(vec![0; length]);
    OsRng.fill_bytes(&mut bytes);
    hex::encode(&*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected_pair(drop_first: bool) -> (SrtpMask, SrtpMask, Instant) {
        let start = Instant::now();
        let a = "192.0.2.1:50000".parse().unwrap();
        let b = "192.0.2.2:443".parse().unwrap();
        let mut left = SrtpMask::new(false, a, b, b, start).unwrap();
        let mut right = SrtpMask::new(true, b, a, b, start).unwrap();
        left.negotiate(&right.parameters(), start).unwrap();
        right.negotiate(&left.parameters(), start).unwrap();
        let mut dropped = !drop_first;
        for step in 0..5000 {
            let now = start + Duration::from_millis(step);
            let left_out = left.poll(now).unwrap();
            let right_out = right.poll(now).unwrap();
            for wire in left_out.wire {
                assert!(
                    wire[0] <= 3,
                    "До установления ICE не должно быть DTLS или SRTP"
                );
                if !dropped {
                    dropped = true;
                    continue;
                }
                right.receive(&wire, now).unwrap();
            }
            for wire in right_out.wire {
                assert!(
                    wire[0] <= 3,
                    "До установления ICE не должно быть DTLS или SRTP"
                );
                left.receive(&wire, now).unwrap();
            }
            if left.connected() && right.connected() {
                return (left, right, now);
            }
        }
        panic!("Не установлен ICE для SRTP");
    }

    #[test]
    fn ice_readiness_does_not_wait_for_idle_background_tick() {
        let (left, _, now) = connected_pair(false);
        assert!(
            now.duration_since(left.started) < Duration::from_millis(500),
            "ICE уже подтвержден, но готовность ждет фонового таймера"
        );
    }

    #[test]
    fn rtp_timestamp_uses_media_clock_even_when_poll_runs_between_packets() {
        let (mut left, _, now) = connected_pair(false);
        left.poll(now).unwrap();
        left.send(b"one", now).unwrap();
        let first = left.poll(now).unwrap().wire.pop().unwrap();
        left.poll(now + Duration::from_secs(1)).unwrap();
        left.send(b"two", now + Duration::from_secs(1)).unwrap();
        let second = left
            .poll(now + Duration::from_secs(1))
            .unwrap()
            .wire
            .pop()
            .unwrap();
        let at = |wire: &[u8]| u32::from_be_bytes(wire[4..8].try_into().unwrap());
        assert_eq!(at(&second).wrapping_sub(at(&first)), 48000);
    }

    #[test]
    fn srtp_after_ice_survives_loss_corruption_replay_foreign_ssrc_and_rollover() {
        let (mut left, mut right, now) = connected_pair(true);
        left.sequence = u16::MAX;
        let payload = vec![42; MAX_INNER];
        for round in 0..3 {
            let now = now + Duration::from_millis(round * 20);
            left.send(&payload, now).unwrap();
            let wire = left
                .poll(now)
                .unwrap()
                .wire
                .into_iter()
                .find(|wire| wire[0] == 0x80)
                .unwrap();
            assert_eq!(wire.len(), 1380);
            assert_ne!(&wire[12..24], &payload[..12]);
            right.observe_verified_wire();
            let mut corrupt = wire.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            right.receive(&corrupt, now).unwrap();
            for ssrc in 0..100u32 {
                let mut foreign = wire.clone();
                foreign[8..12].copy_from_slice(&ssrc.to_be_bytes());
                right.receive(&foreign, now).unwrap();
            }
            assert!(right.poll(now).unwrap().payloads.is_empty());
            assert!(right.take_verified_wire().is_empty());
            right.receive(&wire, now).unwrap();
            assert_eq!(right.take_verified_wire(), vec![wire.clone()]);
            right.observe_verified_wire();
            right.receive(&wire, now).unwrap();
            assert!(right.take_verified_wire().is_empty());
            assert_eq!(right.poll(now).unwrap().payloads, vec![payload.clone()]);
        }
        right.send(b"reverse", now).unwrap();
        for wire in right.poll(now).unwrap().wire {
            left.receive(&wire, now).unwrap();
        }
        assert_eq!(left.poll(now).unwrap().payloads, vec![b"reverse".to_vec()]);
        assert!(left.send(&vec![0; MAX_INNER + 1], now).is_err());
    }

    #[test]
    fn fresh_generations_and_idle_rtcp_have_bounded_timers() {
        let (mut left, mut right, start) = connected_pair(false);
        let fresh = SrtpMask::new(
            false,
            left.local,
            left.peer,
            left.parameters.server_addr,
            start,
        )
        .unwrap();
        assert_ne!(
            fresh.parameters.master_secret,
            left.parameters.master_secret
        );
        assert_ne!(fresh.parameters.ice_password, left.parameters.ice_password);
        assert_ne!(fresh.parameters.ssrc, left.parameters.ssrc);
        let mut rtcp = 0;
        let mut now = start;
        for wakes in 0..400 {
            let end = start + Duration::from_secs(20);
            if now >= end {
                assert!(rtcp > 0);
                return;
            }
            for wire in left.poll(now).unwrap().wire {
                if wire[1] == 201 {
                    rtcp += 1;
                }
                assert!(!(20..=63).contains(&wire[0]));
                right.receive(&wire, now).unwrap();
            }
            for wire in right.poll(now).unwrap().wire {
                left.receive(&wire, now).unwrap();
            }
            now = left.deadline().unwrap().min(right.deadline().unwrap());
            assert!(now > start);
            assert!(wakes < 399, "Busy loop таймеров ICE/SRTP");
        }
    }
}
