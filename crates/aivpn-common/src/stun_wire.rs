//! Проверяемая структура STUN: заголовок и выровненная цепочка TLV.
//!
//! Корректный разбор не доказывает сходство с конкретным WebRTC-приложением.

use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 20;
pub const ATTRIBUTE_HEADER_LEN: usize = 4;

/// Встроенные профили резервируют заголовок одного непрозрачного атрибута.
/// Это локальное описание раскладки, а не фиксированная метка в пакете.
pub const ATTRIBUTE_TEMPLATE: [u8; 4] = [0xc0, 0x72, 0, 0];

/// Выравниваем padding внутри AEAD, не добавляя незашифрованный хвост.
pub fn aligned_padding(base: usize, requested: u16, maximum: u16) -> Result<u16> {
    let desired = requested.min(maximum) as usize;
    let up = desired + (4 - (base + desired) % 4) % 4;
    if up <= maximum as usize {
        return Ok(up as u16);
    }
    let end = base + maximum as usize;
    let aligned = end - end % 4;
    aligned
        .checked_sub(base)
        .map(|value| value as u16)
        .ok_or(Error::InvalidPacket("Нет места для выравнивания STUN"))
}

pub fn finalize(packet: &mut [u8]) -> Result<()> {
    use rand::Rng;
    if packet.len() < HEADER_LEN + ATTRIBUTE_HEADER_LEN
        || packet.len() % 4 != 0
        || packet.len() - HEADER_LEN > u16::MAX as usize
    {
        return Err(Error::InvalidPacket("Некорректный размер носителя STUN"));
    }
    // Binding Indication не требует парного Response с тем же transaction ID.
    packet[..2].copy_from_slice(&0x0011u16.to_be_bytes());
    let body_len = (packet.len() - HEADER_LEN) as u16;
    packet[2..4].copy_from_slice(&body_len.to_be_bytes());
    // Не используем зарегистрированные атрибуты с другой семантикой.
    // По реестру IANA диапазон c072..ffff пока не назначен и optional.
    // Это расширение STUN, не реализация ICE/TURN или протокола Zoom.
    let attribute: u16 = rand::thread_rng().gen_range(0xc072..=0xffff);
    packet[20..22].copy_from_slice(&attribute.to_be_bytes());
    packet[22..24].copy_from_slice(&(body_len - 4).to_be_bytes());
    validate(packet)
}

pub fn validate(packet: &[u8]) -> Result<()> {
    if packet.len() < HEADER_LEN
        || packet[0] & 0xc0 != 0
        || packet[4..8] != [0x21, 0x12, 0xa4, 0x42]
    {
        return Err(Error::InvalidPacket("Некорректный заголовок STUN"));
    }
    let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if length % 4 != 0 || HEADER_LEN + length != packet.len() {
        return Err(Error::InvalidPacket("Некорректная длина STUN"));
    }
    let mut offset = HEADER_LEN;
    while offset < packet.len() {
        if packet.len() - offset < ATTRIBUTE_HEADER_LEN {
            return Err(Error::InvalidPacket("Обрезан заголовок атрибута STUN"));
        }
        let length = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        offset += ATTRIBUTE_HEADER_LEN + ((length + 3) & !3);
        if offset > packet.len() {
            return Err(Error::InvalidPacket(
                "Атрибут STUN выходит за границу пакета",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_tlv_padding_and_rejects_truncation() {
        let mut packet = vec![0; 28];
        packet[..8].copy_from_slice(&[0, 0x11, 0, 8, 0x21, 0x12, 0xa4, 0x42]);
        packet[20..24].copy_from_slice(&[0xc0, 0x01, 0, 1]);
        assert!(validate(&packet).is_ok());
        packet[23] = 5;
        assert!(validate(&packet).is_err());
        for length in 0..packet.len() {
            assert!(validate(&packet[..length]).is_err());
        }
    }
}
