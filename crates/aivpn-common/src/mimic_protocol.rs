//! Финализация полей статической маски после сборки внутреннего пакета.
//!
//! STUN получает длины сообщения и атрибута. Для QUIC этого недостаточно:
//! внешние кадры и таймеры обслуживает отдельный движок состояния маски.

use crate::crypto::TAG_SIZE;
use crate::mask::{MaskProfile, SpoofProtocol};

/// Выбор финализации статического заголовка, без состояния соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProtocol {
    /// No protocol-specific fixup (raw / opaque UDP).
    Raw,
    /// WebRTC STUN (RFC 5389). Patches the STUN message-length field so
    /// `msg_len + 20 == udp_payload_len`, which nDPI's `is_stun` requires.
    Stun,
    /// QUIC: внутренний пакет передается движку состояния маски.
    Quic,
    /// DNS over UDP.
    Dns,
    /// TLS / HTTPS.
    Tls,
}

impl MimicProtocol {
    /// Map a mask's [`SpoofProtocol`] to the mimic-protocol handler that owns its
    /// post-assembly DPI fixups.
    pub fn for_spoof(spoof: SpoofProtocol) -> Self {
        match spoof {
            SpoofProtocol::WebRTC_STUN
            | SpoofProtocol::WebRTC_DTLS_SRTP
            | SpoofProtocol::WebRTC_TURN_DTLS_SRTP
            | SpoofProtocol::WebRTC_SDES_SRTP => MimicProtocol::Stun,
            SpoofProtocol::QUIC => MimicProtocol::Quic,
            SpoofProtocol::DNS_over_UDP => MimicProtocol::Dns,
            SpoofProtocol::HTTPS_H2 => MimicProtocol::Tls,
            SpoofProtocol::None => MimicProtocol::Raw,
        }
    }

    /// Статический профиль больше не собирает внешний QUIC без состояния.
    pub fn is_constructed(&self) -> bool {
        false
    }

    /// Сохранено для вызывающего кода. Внешние кадры здесь не создаются.
    pub fn emit(&self, _tag: &[u8; TAG_SIZE], _ciphertext: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Согласует поля длины, не подменяя обмен состоянием соединения.
    pub fn finalize(&self, packet: &mut [u8], mask: &MaskProfile) -> crate::error::Result<()> {
        match self {
            // STUN: reconcile the message-length field with the final packet
            // size. The exact computation lives on `MaskProfile` as this
            // handler's implementation detail.
            MimicProtocol::Stun => return mask.finalize_packet(packet),
            MimicProtocol::Quic => {
                // TLS, номера пакетов и CID принадлежат движку состояния.
            }
            // Raw/DNS/TLS carry no post-assembly consistency field today.
            MimicProtocol::Raw | MimicProtocol::Dns | MimicProtocol::Tls => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::preset_masks;

    #[test]
    fn for_spoof_maps_every_variant() {
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::WebRTC_STUN),
            MimicProtocol::Stun
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::QUIC),
            MimicProtocol::Quic
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::DNS_over_UDP),
            MimicProtocol::Dns
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::HTTPS_H2),
            MimicProtocol::Tls
        );
        assert_eq!(
            MimicProtocol::for_spoof(SpoofProtocol::None),
            MimicProtocol::Raw
        );
    }

    #[test]
    fn stun_finalize_uses_the_shared_tlv_builder() {
        // The refactor must not change STUN's post-assembly behavior: routing
        // through MimicProtocol::finalize produces exactly what a direct
        // patch_stun_length call would.
        let mask = preset_masks::webrtc_zoom_v3();
        let proto = MimicProtocol::for_spoof(mask.spoof_protocol);
        assert_eq!(proto, MimicProtocol::Stun);
        for total in [24usize, 40, 172, 1380] {
            let mut via_finalize = vec![0u8; total];
            via_finalize[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
            let mut via_direct = vec![0u8; total];
            proto.finalize(&mut via_finalize, &mask).unwrap();
            mask.patch_stun_length(&mut via_direct);
            assert_eq!(&via_finalize[2..4], &via_direct[2..4]);
            crate::stun_wire::validate(&via_finalize).unwrap();
            // And the nDPI is_stun invariant holds.
            let msg_len = u16::from_be_bytes([via_finalize[2], via_finalize[3]]) as usize;
            assert_eq!(msg_len + 20, total);
        }
    }

    #[test]
    fn non_stun_finalize_is_noop() {
        // QUIC (and other non-STUN) masks must leave the packet untouched.
        let mask = preset_masks::quic_https_v2();
        let proto = MimicProtocol::for_spoof(mask.spoof_protocol);
        assert_eq!(proto, MimicProtocol::Quic);
        let mut packet = vec![0xABu8; 200];
        proto.finalize(&mut packet, &mask).unwrap();
        assert_eq!(packet, vec![0xABu8; 200]);
    }
}
