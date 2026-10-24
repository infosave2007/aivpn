//! Ограниченный разбор управляющего STUN/TURN перед проверкой integrity.

use crate::{Error, Result};
use std::net::SocketAddr;
use stun::{
    agent::TransactionId,
    attributes::{AttrType, ATTR_FINGERPRINT, ATTR_MESSAGE_INTEGRITY},
    fingerprint::FINGERPRINT,
    integrity::MessageIntegrity,
    message::{Message, MessageType, Setter},
    xoraddr::XorMappedAddress,
};

pub(crate) struct TurnMessage {
    pub message: Message,
}

impl TurnMessage {
    pub fn build(
        typ: u16,
        transaction_id: [u8; 12],
        attributes: &[(AttrType, Vec<u8>)],
        integrity: Option<&MessageIntegrity>,
    ) -> Result<Vec<u8>> {
        let mut message = Message::new();
        let mut message_type = MessageType::default();
        message_type.read_value(typ);
        message.typ = message_type;
        message.transaction_id = TransactionId(transaction_id);
        message.write_header();
        if attributes.len() > 60
            || attributes
                .iter()
                .map(|(_, value)| 4 + value.len().next_multiple_of(4))
                .sum::<usize>()
                > 1200
        {
            return Err(Error::InvalidPacket("Слишком большой TURN control"));
        }
        for (kind, value) in attributes {
            message.add(*kind, value);
        }
        if let Some(integrity) = integrity {
            integrity
                .add_to(&mut message)
                .map_err(|_| Error::InvalidPacket("Не удалось подписать TURN control"))?;
        }
        FINGERPRINT
            .add_to(&mut message)
            .map_err(|_| Error::InvalidPacket("Не удалось добавить fingerprint TURN"))?;
        // Те же ограничения применяются к собственным сообщениям.
        Self::parse(&message.raw)?;
        Ok(message.raw)
    }

    pub fn address_attribute(
        typ: AttrType,
        address: SocketAddr,
        transaction_id: [u8; 12],
    ) -> Result<(AttrType, Vec<u8>)> {
        let mut message = Message::new();
        message.transaction_id = TransactionId(transaction_id);
        message.write_header();
        XorMappedAddress {
            ip: address.ip(),
            port: address.port(),
        }
        .add_to_as(&mut message, typ)
        .map_err(|_| Error::InvalidPacket("Не удалось закодировать адрес TURN"))?;
        Ok((
            typ,
            message
                .get(typ)
                .map_err(|_| Error::InvalidPacket("Нет адреса TURN"))?,
        ))
    }

    pub fn address(&self, typ: AttrType) -> Result<SocketAddr> {
        let mut address = XorMappedAddress::default();
        address
            .get_from_as(&self.message, typ)
            .map_err(|_| Error::InvalidPacket("Некорректный адрес TURN"))?;
        Ok(SocketAddr::new(address.ip, address.port))
    }

    pub fn parse(wire: &[u8]) -> Result<Self> {
        if !(20..=1380).contains(&wire.len())
            || wire[0] & 0xc0 != 0
            || wire[4..8] != [0x21, 0x12, 0xa4, 0x42]
            || usize::from(u16::from_be_bytes([wire[2], wire[3]])) + 20 != wire.len()
        {
            return Err(Error::InvalidPacket("Некорректный заголовок STUN/TURN"));
        }
        let mut seen = [0u16; 64];
        let mut count = 0;
        let mut offset = 20;
        let mut integrity = false;
        let mut fingerprint = false;
        while offset < wire.len() {
            if offset + 4 > wire.len() || count == seen.len() {
                return Err(Error::InvalidPacket("Превышен предел атрибутов TURN"));
            }
            let kind = u16::from_be_bytes([wire[offset], wire[offset + 1]]);
            let length = usize::from(u16::from_be_bytes([wire[offset + 2], wire[offset + 3]]));
            let end = offset + 4 + length.next_multiple_of(4);
            if end > wire.len()
                || seen[..count].contains(&kind)
                || (integrity && kind != ATTR_FINGERPRINT.0)
            {
                return Err(Error::InvalidPacket(
                    "Недопустимая структура атрибутов TURN",
                ));
            }
            seen[count] = kind;
            count += 1;
            if kind == ATTR_MESSAGE_INTEGRITY.0 {
                if length != 20 {
                    return Err(Error::InvalidPacket("Неверная длина integrity TURN"));
                }
                integrity = true;
            }
            if kind == ATTR_FINGERPRINT.0 {
                if length != 4 || end != wire.len() {
                    return Err(Error::InvalidPacket("Неверная позиция fingerprint TURN"));
                }
                fingerprint = true;
            }
            offset = end;
        }
        let mut message = Message {
            raw: wire.to_vec(),
            ..Default::default()
        };
        message
            .decode()
            .map_err(|_| Error::InvalidPacket("STUN/TURN не разобран"))?;
        if fingerprint {
            FINGERPRINT
                .check(&message)
                .map_err(|_| Error::InvalidPacket("Неверный fingerprint TURN"))?;
        }
        Ok(Self { message })
    }
    pub fn authenticate(&mut self, integrity: &MessageIntegrity) -> Result<()> {
        integrity
            .check(&mut self.message)
            .map_err(|_| Error::InvalidPacket("Неверный integrity TURN"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_term_request() -> Vec<u8> {
        // RFC 5769, раздел 2.4. Пароль - публичное значение тестового вектора.
        hex::decode(concat!(
            "000100602112a44278ad3433c6ad72c029da412e",
            "00060012e3839ee38388e383aae38383e382afe382b90000",
            "0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341",
            "0014000b6578616d706c652e6f726700",
            "00080014f67024656dd64a3e02b8e0712e85c9a28ca89666"
        ))
        .unwrap()
    }

    fn key() -> MessageIntegrity {
        MessageIntegrity::new_long_term_integrity(
            "マトリックス".into(),
            "example.org".into(),
            "TheMatrIX".into(),
        )
    }

    #[test]
    fn rfc5769_authentication_and_exact_bounded_parsing() {
        let wire = long_term_request();
        TurnMessage::parse(&wire)
            .unwrap()
            .authenticate(&key())
            .unwrap();
        for length in 0..wire.len() {
            assert!(
                TurnMessage::parse(&wire[..length]).is_err(),
                "Длина {length}"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(TurnMessage::parse(&trailing).is_err());
        assert!(TurnMessage::parse(&vec![0; 65_535]).is_err());
        let mut corrupt = wire;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(TurnMessage::parse(&corrupt)
            .unwrap()
            .authenticate(&key())
            .is_err());
    }

    #[test]
    fn integrity_length_duplicates_and_unsigned_trailer_are_rejected() {
        let wire = long_term_request();
        let mut short = wire.clone();
        let length_offset = short.len() - 22;
        short[length_offset..length_offset + 2].copy_from_slice(&19u16.to_be_bytes());
        assert!(TurnMessage::parse(&short).is_err());
        for trailer in [
            &wire[wire.len() - 24..],
            &[0x00, 0x0d, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff],
        ] {
            let mut duplicate = wire.clone();
            duplicate.extend_from_slice(trailer);
            let length = (duplicate.len() - 20) as u16;
            duplicate[2..4].copy_from_slice(&length.to_be_bytes());
            assert!(TurnMessage::parse(&duplicate).is_err());
        }
    }

    #[test]
    fn rfc5769_fingerprint_and_authenticated_address_roundtrip() {
        let reference = hex::decode(concat!(
            "0101003c2112a442b7e7a701bc34d686fa87dfae",
            "8022000b7465737420766563746f7220",
            "002000080001a147e112a643",
            "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7",
            "80280004c07d4c96"
        ))
        .unwrap();
        TurnMessage::parse(&reference)
            .unwrap()
            .authenticate(&MessageIntegrity::new_short_term_integrity(
                "VOkJxbRl1RmTxUk/WvJxBt".into(),
            ))
            .unwrap();
        let mut bad = reference;
        *bad.last_mut().unwrap() ^= 1;
        assert!(TurnMessage::parse(&bad).is_err());
        for address in ["192.0.2.1:32853", "[2001:db8::1]:32853"] {
            let address: SocketAddr = address.parse().unwrap();
            let typ = stun::attributes::ATTR_XOR_RELAYED_ADDRESS;
            let attributes = vec![TurnMessage::address_attribute(typ, address, [9; 12]).unwrap()];
            let wire = TurnMessage::build(0x0103, [9; 12], &attributes, Some(&key())).unwrap();
            let mut decoded = TurnMessage::parse(&wire).unwrap();
            decoded.authenticate(&key()).unwrap();
            assert_eq!(decoded.address(typ).unwrap(), address);
            assert_eq!(decoded.message.typ.value(), 0x0103);
            assert_eq!(decoded.message.transaction_id.0, [9; 12]);
        }
    }
}
