//! Общий интерфейс состояний RTC-масок, не отдельный транспорт.

use crate::{
    mask::{MaskProfile, SpoofProtocol},
    mask_state::MaskParameters,
    rtc_mask::{RtcMask, RtcMaskOutput},
    srtp_mask::SrtpMask,
    Error, Result,
};
use std::{net::SocketAddr, time::Instant};

pub enum RtcCarrier {
    Dtls(RtcMask),
    Srtp(SrtpMask),
}

#[derive(Clone, Copy)]
pub enum RtcKind {
    Dtls,
    Turn(&'static str),
    Sdes,
}

impl RtcKind {
    pub fn from_mask(mask: &MaskProfile) -> Result<Self> {
        match mask.spoof_protocol {
            SpoofProtocol::WebRTC_SDES_SRTP => Ok(Self::Sdes),
            SpoofProtocol::WebRTC_DTLS_SRTP => Ok(Self::Dtls),
            SpoofProtocol::WebRTC_TURN_DTLS_SRTP => {
                Ok(Self::Turn(crate::mask_io::turn_realm(mask).unwrap()))
            }
            _ => Err(Error::InvalidPacket("Не выбран RTC-профиль")),
        }
    }
}

impl RtcCarrier {
    pub fn for_mask(
        mask: &MaskProfile,
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        server_addr: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        Self::create(
            RtcKind::from_mask(mask)?,
            server,
            local,
            peer,
            server_addr,
            now,
        )
    }
    pub fn create(
        kind: RtcKind,
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        server_addr: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        match kind {
            RtcKind::Sdes => Ok(Self::Srtp(SrtpMask::new(
                server,
                local,
                peer,
                server_addr,
                now,
            )?)),
            RtcKind::Dtls => Self::new(server, local, peer, server_addr, now),
            RtcKind::Turn(realm) => Self::new_turn(server, local, peer, server_addr, realm, now),
        }
    }
    pub fn new(
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        addr: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        Ok(Self::Dtls(RtcMask::new(server, local, peer, addr, now)?))
    }
    pub fn new_turn(
        server: bool,
        local: SocketAddr,
        peer: SocketAddr,
        addr: SocketAddr,
        realm: &str,
        now: Instant,
    ) -> Result<Self> {
        Ok(Self::Dtls(RtcMask::new_turn(
            server, local, peer, addr, realm, now,
        )?))
    }
    pub fn parameters(&self) -> MaskParameters {
        match self {
            Self::Dtls(engine) => engine.parameters().into(),
            Self::Srtp(engine) => MaskParameters::Srtp(engine.parameters()),
        }
    }
    pub fn negotiate(&mut self, parameters: &MaskParameters, now: Instant) -> Result<()> {
        match self {
            Self::Dtls(engine) => engine.negotiate(parameters.rtc()?, now),
            Self::Srtp(engine) => engine.negotiate(parameters.srtp()?, now),
        }
    }
    pub fn connected(&self) -> bool {
        match self {
            Self::Dtls(engine) => engine.connected(),
            Self::Srtp(engine) => engine.connected(),
        }
    }
    pub fn deadline(&mut self) -> Option<Instant> {
        match self {
            Self::Dtls(engine) => engine.deadline(),
            Self::Srtp(engine) => engine.deadline(),
        }
    }
    pub fn poll(&mut self, now: Instant) -> Result<RtcMaskOutput> {
        match self {
            Self::Dtls(engine) => engine.poll(now),
            Self::Srtp(engine) => engine.poll(now),
        }
    }
    pub fn receive(&mut self, packet: &[u8], now: Instant) -> Result<()> {
        match self {
            Self::Dtls(engine) => engine.receive(packet, now),
            Self::Srtp(engine) => engine.receive(packet, now),
        }
    }
    pub fn send(&mut self, packet: &[u8], now: Instant) -> Result<()> {
        match self {
            Self::Dtls(engine) => engine.send(packet, now),
            Self::Srtp(engine) => engine.send(packet, now),
        }
    }

    pub fn observe_verified_wire(&mut self) {
        match self {
            Self::Dtls(engine) => engine.observe_verified_wire(),
            Self::Srtp(engine) => engine.observe_verified_wire(),
        }
    }

    pub fn take_verified_wire(&mut self) -> Vec<Vec<u8>> {
        match self {
            Self::Dtls(engine) => engine.take_verified_wire(),
            Self::Srtp(engine) => engine.take_verified_wire(),
        }
    }
}
