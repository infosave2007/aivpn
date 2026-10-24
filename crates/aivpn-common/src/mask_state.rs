//! Ограниченное согласование состояния маски внутри защищенного канала AIVPN.
//!
//! Наличие корректного сообщения не дает прав: обработчик обязан проверить
//! PFS, поколение сессии и выбранный профиль до применения параметров.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::protocol::ControlSubtype;

const MAX_CONTROL: usize = 512;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RtcParameters {
    pub fingerprint: [u8; 32],
    pub ice_ufrag: String,
    pub ice_password: String,
    pub ssrc: u32,
    /// Адрес сервера, уже выбранный клиентом. Это подсказка для логического
    /// ICE endpoint, не адрес для открытия нового сокета или отправки пакета.
    pub server_addr: SocketAddr,
}

impl fmt::Debug for RtcParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtcParameters")
            .finish_non_exhaustive()
    }
}

impl Drop for RtcParameters {
    fn drop(&mut self) {
        self.ice_password.zeroize();
    }
}

impl RtcParameters {
    pub fn validate(&self) -> Result<()> {
        validate_ice(
            &self.ice_ufrag,
            &self.ice_password,
            self.ssrc,
            self.server_addr,
        )?;
        if self.fingerprint == [0; 32] {
            return Err(Error::InvalidPacket("Пустой отпечаток RTC"));
        }
        Ok(())
    }
}

fn validate_ice(ufrag: &str, password: &str, ssrc: u32, server_addr: SocketAddr) -> Result<()> {
    let ice_char = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/');
    if !(4..=32).contains(&ufrag.len())
        || !(22..=64).contains(&password.len())
        || !ufrag.bytes().all(ice_char)
        || !password.bytes().all(ice_char)
        || ssrc == 0
        || server_addr.port() == 0
        || server_addr.ip().is_unspecified()
        || server_addr.ip().is_multicast()
        || matches!(server_addr, SocketAddr::V6(address) if address.scope_id() != 0 || address.flowinfo() != 0)
    {
        return Err(Error::InvalidPacket("Недопустимые параметры RTC-маски"));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SrtpParameters {
    pub master_secret: [u8; 32],
    pub ice_ufrag: String,
    pub ice_password: String,
    pub ssrc: u32,
    pub server_addr: SocketAddr,
}

impl fmt::Debug for SrtpParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SrtpParameters")
            .finish_non_exhaustive()
    }
}

impl Drop for SrtpParameters {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.ice_password.zeroize();
    }
}

impl SrtpParameters {
    pub fn validate(&self) -> Result<()> {
        validate_ice(
            &self.ice_ufrag,
            &self.ice_password,
            self.ssrc,
            self.server_addr,
        )?;
        if self.master_secret == [0; 32] {
            return Err(Error::InvalidPacket("Пустой SRTP secret"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MaskParameters {
    Rtc(RtcParameters),
    Srtp(SrtpParameters),
}

impl From<RtcParameters> for MaskParameters {
    fn from(value: RtcParameters) -> Self {
        Self::Rtc(value)
    }
}

impl MaskParameters {
    pub fn rtc(&self) -> Result<&RtcParameters> {
        match self {
            Self::Rtc(params) => Ok(params),
            _ => Err(Error::InvalidPacket("Ожидались параметры DTLS")),
        }
    }
    pub fn srtp(&self) -> Result<&SrtpParameters> {
        match self {
            Self::Srtp(params) => Ok(params),
            _ => Err(Error::InvalidPacket("Ожидались параметры SRTP без DTLS")),
        }
    }
    pub fn server_addr(&self) -> SocketAddr {
        match self {
            Self::Rtc(params) => params.server_addr,
            Self::Srtp(params) => params.server_addr,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Rtc(params) => params.validate(),
            Self::Srtp(params) => params.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaskState {
    pub offer_id: [u8; 16],
    pub answer: bool,
    pub mask_id: String,
    pub mask_version: u16,
    pub parameters: MaskParameters,
}

impl MaskState {
    pub fn validate(&self) -> Result<()> {
        if self.mask_version == 0
            || self.mask_id.is_empty()
            || self.mask_id.len() > 128
            || !self
                .mask_id
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(Error::InvalidPacket("Недопустимый профиль RTC-маски"));
        }
        self.parameters.validate()
    }

    pub fn encode_control(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let (format, material, ufrag, password, ssrc, server_addr) = match &self.parameters {
            MaskParameters::Rtc(params) => (
                1,
                &params.fingerprint,
                &params.ice_ufrag,
                &params.ice_password,
                params.ssrc,
                params.server_addr,
            ),
            MaskParameters::Srtp(params) => (
                2,
                &params.master_secret,
                &params.ice_ufrag,
                &params.ice_password,
                params.ssrc,
                params.server_addr,
            ),
        };
        let mut output = Vec::with_capacity(256);
        output.extend_from_slice(&[
            ControlSubtype::MaskState as u8,
            format,
            u8::from(self.answer),
        ]);
        output.extend_from_slice(&self.mask_version.to_le_bytes());
        output.extend_from_slice(&self.offer_id);
        output.extend_from_slice(&[
            self.mask_id.len() as u8,
            ufrag.len() as u8,
            password.len() as u8,
        ]);
        match server_addr.ip() {
            IpAddr::V4(address) => {
                output.push(4);
                output.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                output.push(6);
                output.extend_from_slice(&address.octets());
            }
        }
        output.extend_from_slice(&server_addr.port().to_be_bytes());
        output.extend_from_slice(material);
        output.extend_from_slice(&ssrc.to_be_bytes());
        output.extend_from_slice(self.mask_id.as_bytes());
        output.extend_from_slice(ufrag.as_bytes());
        output.extend_from_slice(password.as_bytes());
        Ok(output)
    }

    pub fn decode_control(data: &[u8]) -> Result<Self> {
        if !(25..=MAX_CONTROL).contains(&data.len())
            || data[0] != ControlSubtype::MaskState as u8
            || !matches!(data[1], 1 | 2)
            || data[2] > 1
        {
            return Err(Error::InvalidPacket("Некорректное сообщение RTC-маски"));
        }
        let mask_len = usize::from(data[21]);
        let ufrag_len = usize::from(data[22]);
        let password_len = usize::from(data[23]);
        let address_len = match data[24] {
            4 => 4,
            6 => 16,
            _ => return Err(Error::InvalidPacket("Неизвестное семейство адреса RTC")),
        };
        let fixed_end = 25 + address_len + 2 + 32 + 4;
        if !(1..=128).contains(&mask_len)
            || !(4..=32).contains(&ufrag_len)
            || !(22..=64).contains(&password_len)
            || data.len() != fixed_end + mask_len + ufrag_len + password_len
        {
            return Err(Error::InvalidPacket("Некорректная длина сообщения RTC"));
        }
        let ip = if address_len == 4 {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&data[25..29]).unwrap()))
        } else {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[25..41]).unwrap()))
        };
        let mut cursor = 25 + address_len;
        let port = u16::from_be_bytes(data[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let fingerprint = data[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let ssrc = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap());
        let text = |start, length| {
            std::str::from_utf8(&data[start..start + length])
                .map(str::to_owned)
                .map_err(|_| Error::InvalidPacket("Некорректный текст параметров RTC"))
        };
        let result = Self {
            offer_id: data[5..21].try_into().unwrap(),
            answer: data[2] == 1,
            mask_version: u16::from_le_bytes([data[3], data[4]]),
            mask_id: text(fixed_end, mask_len)?,
            parameters: if data[1] == 1 {
                MaskParameters::Rtc(RtcParameters {
                    fingerprint,
                    ice_ufrag: text(fixed_end + mask_len, ufrag_len)?,
                    ice_password: text(fixed_end + mask_len + ufrag_len, password_len)?,
                    ssrc,
                    server_addr: SocketAddr::new(ip, port),
                })
            } else {
                MaskParameters::Srtp(SrtpParameters {
                    master_secret: fingerprint,
                    ice_ufrag: text(fixed_end + mask_len, ufrag_len)?,
                    ice_password: text(fixed_end + mask_len + ufrag_len, password_len)?,
                    ssrc,
                    server_addr: SocketAddr::new(ip, port),
                })
            },
        };
        result.validate()?;
        Ok(result)
    }
}
