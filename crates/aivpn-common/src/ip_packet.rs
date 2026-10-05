//! Проверка длины и адресов IP-пакета перед маршрутизацией и проверкой источника.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub length: usize,
}

impl IpPacket {
    /// Допускает нулевой хвост FEC; вызывающий код передает дальше только `length` байт.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let packet = match bytes.first()? >> 4 {
            4 if bytes.len() >= 20 => {
                let header_len = usize::from(bytes[0] & 15) * 4;
                let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                if header_len < 20 || length < header_len {
                    return None;
                }
                Self {
                    source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).into(),
                    destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]).into(),
                    length,
                }
            }
            6 if bytes.len() >= 40 => {
                let payload = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
                // Jumbogram не помещается в согласованный MTU туннеля.
                if payload == 0 && bytes[6] != 59 {
                    return None;
                }
                Self {
                    source: Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?).into(),
                    destination: Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?).into(),
                    length: 40 + payload,
                }
            }
            _ => return None,
        };
        if packet.length > bytes.len() || bytes[packet.length..].iter().any(|b| *b != 0) {
            return None;
        }
        Some(packet)
    }

    pub fn destination_shard(self, count: usize) -> usize {
        let value = match self.destination {
            IpAddr::V4(address) => u128::from(u32::from(address)),
            IpAddr::V6(address) => u128::from(address),
        };
        (value % count.max(1) as u128) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_addresses_length_and_fec_padding() {
        let mut bytes = vec![0; 128];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&8u16.to_be_bytes());
        bytes[6] = 17;
        let source: Ipv6Addr = "fd10:cafe::a00:2".parse().unwrap();
        let destination: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        bytes[8..24].copy_from_slice(&source.octets());
        bytes[24..40].copy_from_slice(&destination.octets());
        let packet = IpPacket::parse(&bytes).unwrap();
        assert_eq!(packet.source, IpAddr::V6(source));
        assert_eq!(packet.destination, IpAddr::V6(destination));
        assert_eq!(packet.length, 48);
        assert!(IpPacket::parse(&bytes[..47]).is_none());
        bytes[100] = 1;
        assert!(IpPacket::parse(&bytes).is_none());
    }

    #[test]
    fn malformed_headers_are_rejected() {
        for len in 0..40 {
            let mut bytes = vec![0; len];
            if len > 0 {
                bytes[0] = 0x60;
            }
            assert!(IpPacket::parse(&bytes).is_none());
        }
        let mut bytes = vec![0; 40];
        bytes[0] = 0x44;
        bytes[3] = 20;
        assert!(IpPacket::parse(&bytes).is_none());
        bytes[0] = 0x45;
        assert_eq!(IpPacket::parse(&bytes).unwrap().length, 20);
        bytes[3] = 19;
        assert!(IpPacket::parse(&bytes).is_none());
    }
}
