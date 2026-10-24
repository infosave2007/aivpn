//! Генератор прежней синтетической заготовки QUIC Initial для тестов.
//!
//! Не реализует соединение, ACK или TLS handshake и не используется
//! в сетевом пути клиента и сервера. Внешний QUIC формирует `quic_mask`
//! с состоянием обеих сторон. Разбор этой заготовки не заменяет живой DPI-gate.
//!
//! Старый генератор создает составную дейтаграмму:
//!
//! ```text
//! [ real RFC 9001 v1 QUIC Initial (header-protected, AEAD-encrypted) ]
//! [ aivpn's real ciphertext, appended after the Initial's Length ]
//! ```
//!
//! A DPI engine (e.g. nDPI's `ndpi_search_quic`) parses the first Initial:
//! it validates the long-header shape + version + CID lengths, then removes
//! header protection and AEAD-decrypts the CRYPTO frame using keys derived
//! from the packet's DCID via the public RFC 9001 v1 salt. Because the
//! Initial is a genuine, decryptable QUIC Initial carrying a minimal TLS
//! ClientHello, the flow classifies as QUIC by real DPI (not a port guess).
//!
//! The 8-byte aivpn resonance tag rides inside the DCID (offset 6), so the
//! per-packet key material is per-packet — the QUIC crypto is recomputed for
//! every packet. Прежний декодер извлекал тег из DCID и пропускал Initial.
//! В текущем gateway этот путь удален.
//!
//! Crypto (RFC 9001 §5.2, all SHA-256 / AES-128-GCM):
//! - `initial_secret        = HKDF-Extract(initial_salt, DCID)`
//! - `client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)`
//! - `key = Expand-Label(cis, "quic key", "", 16)`  (AEAD key)
//! - `iv  = Expand-Label(cis, "quic iv",  "", 12)`
//! - `hp  = Expand-Label(cis, "quic hp",  "", 16)`  (header-protection key)

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// RFC 9001 §5.2 QUIC v1 initial salt.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v1 version number (RFC 9000).
const QUIC_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// The resonance tag is 8 bytes and rides inside the DCID.
pub const QUIC_TAG_LEN: usize = 8;

/// DCID length used for aivpn's Initial: exactly the 8-byte resonance tag.
const DCID_LEN: u8 = QUIC_TAG_LEN as u8;

/// Byte offset of the DCID (== resonance tag) inside the datagram:
/// first_byte(1) + version(4) + dcid_len(1).
pub const QUIC_TAG_OFFSET: usize = 6;

/// Minimum UDP payload nDPI requires to even consider a datagram an Initial
/// (`may_be_initial_pkt`: "UDP payloads of at least 1200 bytes").
pub const QUIC_MIN_DATAGRAM: usize = 1200;

// ── Fixed header geometry of the aivpn Initial (single source of truth,
//    shared by `build_quic_initial` and `quic_initial_overhead`) ──
//
/// Header bytes up to (but excluding) the Length varint:
/// first_byte(1)+version(4)+dcid_len(1)+dcid(8)+scid_len(1)+token_len(1).
const HDR_BEFORE_LEN: usize = 1 + 4 + 1 + DCID_LEN as usize + 1 + 1;
/// We always encode the Initial's Length as a forced 2-byte varint.
const LEN_VARINT: usize = 2;
/// Packet number length used by the aivpn Initial (1 byte, packet number 0).
const PN_LEN: usize = 1;
/// Full unprotected header length (== AEAD AAD length).
const HDR_LEN: usize = HDR_BEFORE_LEN + LEN_VARINT + PN_LEN;
/// AES-128-GCM authentication tag length.
const AEAD_TAG: usize = 16;
/// Largest value encodable in a 2-byte QUIC varint (RFC 9000 §16). The forced
/// 2-byte Length encoding cannot represent anything above this.
const MAX_LEN_VARINT_VALUE: u64 = 0x3fff;

/// Fixed per-packet overhead that [`build_quic_initial`] adds ON TOP of
/// `aivpn_payload` when no interior QUIC PADDING is required (i.e. the payload
/// is already large enough that the datagram is >= [`QUIC_MIN_DATAGRAM`]). This
/// is the QUIC v1 Initial header + the CRYPTO(ClientHello) frame + the AEAD
/// tag — the number of bytes by which the emitted datagram exceeds
/// `aivpn_payload.len()` for a near-MTU packet.
///
/// The mimicry engine reserves this in its size budget so that wrapping a
/// near-MTU aivpn ciphertext in a real QUIC Initial does not push the FINAL
/// datagram past a path-MTU-safe size (which would fragment and, worse, be a
/// DPI anomaly since real QUIC does PMTUD).
pub fn quic_initial_overhead() -> usize {
    HDR_LEN + build_crypto_frame().len() + AEAD_TAG
}

/// TLS1.3 HKDF-Expand-Label (RFC 8446 §7.1) with QUIC's "tls13 " prefix.
fn hkdf_expand_label(prk: &[u8], label: &str, out_len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    debug_assert!(full.len() <= 255);
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0u8); // zero-length context
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("PRK length is SHA-256 output");
    let mut okm = vec![0u8; out_len];
    hk.expand(&info, &mut okm).expect("valid expand length");
    okm
}

/// Client-side Initial secrets derived from the DCID.
struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_initial_keys(dcid: &[u8]) -> InitialKeys {
    // initial_secret = HKDF-Extract(salt=initial_salt, IKM=DCID)
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT), dcid);
    let cis = hkdf_expand_label(&prk, "client in", 32);
    let key = hkdf_expand_label(&cis, "quic key", 16);
    let iv = hkdf_expand_label(&cis, "quic iv", 12);
    let hp = hkdf_expand_label(&cis, "quic hp", 16);
    let mut k = InitialKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    k.key.copy_from_slice(&key);
    k.iv.copy_from_slice(&iv);
    k.hp.copy_from_slice(&hp);
    k
}

/// A minimal but structurally valid TLS 1.3 ClientHello, carried in the
/// Initial's CRYPTO frame. nDPI decrypts and parses this to sub-classify;
/// the exact contents are not load-bearing for the QUIC verdict.
fn minimal_client_hello() -> Vec<u8> {
    // Extensions ---------------------------------------------------------
    // supported_versions (0x002b): TLS 1.3 (0x0304)
    let mut exts = Vec::new();
    exts.extend_from_slice(&[0x00, 0x2b]); // ext type
    exts.extend_from_slice(&[0x00, 0x03]); // ext len
    exts.push(0x02); // list len
    exts.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // ClientHello body ---------------------------------------------------
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0x00); // legacy_session_id (empty)
    body.extend_from_slice(&[0x00, 0x02]); // cipher_suites len
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(0x01); // compression methods len
    body.push(0x00); // null compression
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // Handshake header (type=ClientHello=1, 24-bit length) ----------------
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(0x01);
    let len = body.len() as u32;
    hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    hs.extend_from_slice(&body);
    hs
}

/// Encode a QUIC variable-length integer (RFC 9000 §16).
fn encode_varint(value: u64, out: &mut Vec<u8>) {
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    } else if value < 0x4000_0000 {
        out.push(0x80 | (value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(0xc0 | (value >> 56) as u8);
        out.push((value >> 48) as u8);
        out.push((value >> 40) as u8);
        out.push((value >> 32) as u8);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
}

/// Decode a QUIC varint at `buf[0..]`. Returns `(value, bytes_consumed)`.
fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    Some((value, len))
}

/// Build the Initial's CRYPTO frame: type(0x06) + offset(varint 0) +
/// length(varint) + minimal ClientHello. Deterministic (no RNG), so
/// [`quic_initial_overhead`] can size it without building a whole packet.
fn build_crypto_frame() -> Vec<u8> {
    let ch = minimal_client_hello();
    let mut crypto_frame = Vec::with_capacity(3 + ch.len());
    crypto_frame.push(0x06);
    encode_varint(0, &mut crypto_frame); // offset
    encode_varint(ch.len() as u64, &mut crypto_frame); // length
    crypto_frame.extend_from_slice(&ch);
    crypto_frame
}

/// AEAD-seal + header-protect a QUIC Initial (RFC 9001 §5.3–5.4).
///
/// `header` is the fully-assembled UNPROTECTED long header, INCLUDING the
/// packet-number bytes at its tail. `pn_offset` is the byte offset of the
/// packet number within `header`, `pn_len` its encoded length, and `pn` its
/// numeric value. Returns the protected header ++ ciphertext (no trailing
/// coalesced payload). Factored out of [`build_quic_initial`] so it can be
/// locked by a full-packet RFC 9001 Appendix A.2 known-answer test.
fn seal_and_protect(
    keys: &InitialKeys,
    mut header: Vec<u8>,
    plaintext: &[u8],
    pn_offset: usize,
    pn_len: usize,
    pn: u64,
) -> Vec<u8> {
    // nonce = iv XOR (pn, big-endian, left-padded to the 12-byte IV width).
    let mut nonce_bytes = keys.iv;
    let pn_be = pn.to_be_bytes(); // 8 bytes, big-endian
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_be[i];
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).expect("16-byte key");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .expect("AES-128-GCM encrypt");

    header.extend_from_slice(&ct);
    let mut packet = header;

    // Header protection (RFC 9001 §5.4): sample 16 bytes starting 4 bytes into
    // the packet-number field (the fixed sample offset accounts for the maximum
    // 4-byte packet number), regardless of the actual `pn_len`.
    let sample_off = pn_offset + 4;
    let mut block = [0u8; 16];
    block.copy_from_slice(&packet[sample_off..sample_off + 16]);
    let hp = Aes128::new_from_slice(&keys.hp).expect("16-byte hp key");
    let mut ga = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
    hp.encrypt_block(&mut ga);
    let mask = ga;
    packet[0] ^= mask[0] & 0x0f; // long header: mask low 4 bits of first byte
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

/// Build a coalesced datagram: a real RFC 9001 v1 QUIC Initial (whose DCID
/// carries `tag`) followed by `aivpn_payload`. The datagram is padded (with
/// QUIC PADDING frames inside the Initial) to at least `min_datagram` bytes,
/// which must be >= [`QUIC_MIN_DATAGRAM`] for DPI to treat it as an Initial.
pub fn build_quic_initial(
    tag: &[u8; QUIC_TAG_LEN],
    aivpn_payload: &[u8],
    min_datagram: usize,
) -> Vec<u8> {
    let min_datagram = min_datagram.max(QUIC_MIN_DATAGRAM);
    let keys = derive_initial_keys(tag);

    let crypto_frame = build_crypto_frame();

    // Pad so the whole datagram (Initial + trailing aivpn payload) >= min.
    let base = HDR_LEN + crypto_frame.len() + AEAD_TAG + aivpn_payload.len();
    let pad = min_datagram.saturating_sub(base);

    // Clamp the interior QUIC padding so the forced 2-byte Length varint can
    // never overflow. `length_value = PN_LEN + plaintext_len + AEAD_TAG` must
    // stay <= MAX_LEN_VARINT_VALUE; a `pub fn` must not silently truncate on a
    // caller-supplied `min_datagram`, so we hard-cap here instead of relying on
    // a release-compiled-out `debug_assert`. This only bites for an absurd
    // `min_datagram` (> ~16 KB, far past any real path MTU) — the aivpn callers
    // pass 1200, so `pad` is never actually clamped. The `crypto_frame`
    // (~57 bytes) is always far below the cap, so it is never truncated.
    let max_plaintext_len = (MAX_LEN_VARINT_VALUE as usize).saturating_sub(PN_LEN + AEAD_TAG);
    let plaintext_len = (crypto_frame.len() + pad).min(max_plaintext_len);
    let mut plaintext = Vec::with_capacity(plaintext_len);
    plaintext.extend_from_slice(&crypto_frame);
    plaintext.resize(plaintext_len, 0x00); // PADDING frames

    // Length field = packet_number_len + ciphertext_len + AEAD tag.
    let length_value = (PN_LEN + plaintext_len + AEAD_TAG) as u64;
    debug_assert!(
        length_value <= MAX_LEN_VARINT_VALUE,
        "Length exceeds 2-byte varint (clamp failed)"
    );

    // Assemble the unprotected header (INCLUDING the 1-byte packet number).
    let mut header = Vec::with_capacity(HDR_LEN);
    header.push(0xc0); // long header, fixed bit, type=Initial, pn_len=1
    header.extend_from_slice(&QUIC_V1);
    header.push(DCID_LEN);
    header.extend_from_slice(tag);
    header.push(0x00); // scid_len = 0
    header.push(0x00); // token_len = 0
                       // Length as a forced 2-byte varint (0x40xx).
    header.push(0x40 | (length_value >> 8) as u8);
    header.push(length_value as u8);
    header.push(0x00); // packet number = 0 (1 byte)
    debug_assert_eq!(header.len(), HDR_LEN);

    let pn_offset = HDR_BEFORE_LEN + LEN_VARINT; // start of packet number
    let mut packet = seal_and_protect(&keys, header, &plaintext, pn_offset, PN_LEN, 0);
    packet.extend_from_slice(aivpn_payload);
    packet
}

/// Parsed view of a coalesced QUIC-Initial datagram produced by
/// [`build_quic_initial`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicInitialLayout {
    /// The 8-byte resonance tag carried in the DCID.
    pub tag: [u8; QUIC_TAG_LEN],
    /// Offset in the datagram where aivpn's real ciphertext begins
    /// (== end of the QUIC Initial, per its Length field).
    pub payload_offset: usize,
}

/// Recognize the aivpn QUIC-Initial layout and locate the trailing aivpn
/// ciphertext. Returns `None` if the datagram is not our Initial shape.
///
/// This does not decrypt — the server only needs the DCID (tag) and the
/// Initial's Length field to skip past the decoy to the real payload.
pub fn parse_quic_initial(datagram: &[u8]) -> Option<QuicInitialLayout> {
    // first_byte(1)+version(4)+dcid_len(1) minimum.
    if datagram.len() < 6 {
        return None;
    }
    // Long header + fixed bit + Initial packet type (high nibble 0xC),
    // low nibble is header-protected so unknown here.
    if datagram[0] & 0xf0 != 0xc0 {
        return None;
    }
    if datagram[1..5] != QUIC_V1 {
        return None;
    }
    let dcid_len = datagram[5] as usize;
    if dcid_len != QUIC_TAG_LEN {
        return None;
    }
    let scid_len_pos = 6 + dcid_len;
    let scid_len = *datagram.get(scid_len_pos)? as usize;
    let mut pos = scid_len_pos + 1 + scid_len;
    // Token length varint (must be 0 for a client Initial we built).
    let (token_len, tl) = decode_varint(datagram.get(pos..)?)?;
    pos = pos
        .checked_add(tl)?
        .checked_add(usize::try_from(token_len).ok()?)?;
    // Length varint bounds the Initial (packet number + payload + AEAD tag).
    let (length_value, ll) = decode_varint(datagram.get(pos..)?)?;
    pos = pos.checked_add(ll)?;
    let payload_offset = pos.checked_add(usize::try_from(length_value).ok()?)?;
    if payload_offset > datagram.len() {
        return None;
    }
    let mut tag = [0u8; QUIC_TAG_LEN];
    tag.copy_from_slice(&datagram[6..6 + QUIC_TAG_LEN]);
    Some(QuicInitialLayout {
        tag,
        payload_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_audit_quic_rejects_oversized_varint_offsets() {
        for huge in [u32::MAX as u64 - 15, 1u64 << 32, (1u64 << 62) - 1] {
            let mut packet = vec![0xc0, 0, 0, 0, 1, 8];
            packet.extend_from_slice(&[0; 8]);
            packet.push(0);
            encode_varint(huge, &mut packet);
            packet.extend_from_slice(&[0; 32]);
            assert!(parse_quic_initial(&packet).is_none());

            let mut packet = vec![0xc0, 0, 0, 0, 1, 8];
            packet.extend_from_slice(&[0; 8]);
            packet.extend_from_slice(&[0, 0]);
            encode_varint(huge, &mut packet);
            packet.extend_from_slice(&[0; 32]);
            assert!(parse_quic_initial(&packet).is_none());
        }
    }

    #[test]
    fn roundtrip_layout() {
        let tag = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let aivpn = vec![0xAB; 200];
        let dg = build_quic_initial(&tag, &aivpn, QUIC_MIN_DATAGRAM);
        assert!(dg.len() >= QUIC_MIN_DATAGRAM);
        let layout = parse_quic_initial(&dg).expect("recognized");
        assert_eq!(layout.tag, tag);
        assert_eq!(&dg[layout.payload_offset..], &aivpn[..]);
        // Tag sits at the documented offset inside the DCID.
        assert_eq!(&dg[QUIC_TAG_OFFSET..QUIC_TAG_OFFSET + 8], &tag);
    }

    #[test]
    fn min_datagram_enforced() {
        let tag = [0u8; 8];
        // Even with empty aivpn payload, datagram is padded to the minimum.
        let dg = build_quic_initial(&tag, &[], 0);
        assert!(dg.len() >= QUIC_MIN_DATAGRAM);
        let layout = parse_quic_initial(&dg).unwrap();
        // Empty trailing payload -> offset at end.
        assert_eq!(layout.payload_offset, dg.len());
    }

    #[test]
    fn large_payload_minimal_padding() {
        let tag = [7u8; 8];
        let aivpn = vec![0xCD; 1300];
        let dg = build_quic_initial(&tag, &aivpn, QUIC_MIN_DATAGRAM);
        let layout = parse_quic_initial(&dg).unwrap();
        assert_eq!(&dg[layout.payload_offset..], &aivpn[..]);
    }

    #[test]
    fn known_answer_initial_secret() {
        // RFC 9001 Appendix A.1 test vector: DCID 0x8394c8f03e515708.
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_initial_keys(&dcid);
        // Expected client key/iv/hp from RFC 9001 A.1.
        assert_eq!(
            keys.key,
            [
                0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
                0xa2, 0x2d
            ]
        );
        assert_eq!(
            keys.iv,
            [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]
        );
        assert_eq!(
            keys.hp,
            [
                0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
                0xed, 0xd2
            ]
        );
    }

    /// Full-packet known-answer test for the HP + AEAD assembly, locked to the
    /// RFC 9001 Appendix A.2 client Initial sample. Unlike
    /// `known_answer_initial_secret` (which only checks key derivation), this
    /// drives the exact bytes through [`seal_and_protect`] — the same function
    /// [`build_quic_initial`] uses — so a subtle AEAD-nonce or header-protection
    /// bug (which would otherwise only surface as silent nDPI rejection) fails
    /// here loudly.
    ///
    /// A.2 uses DCID 0x8394c8f03e515708, a 4-byte packet number encoding for
    /// packet number 2, and a 1162-byte payload (a 245-byte CRYPTO frame
    /// carrying the ClientHello, PADDING-framed out to 1162 zero-tail bytes).
    #[test]
    fn known_answer_client_initial_rfc9001_a2() {
        // A.2 CRYPTO frame (type 0x06, offset 0, length 0x00f1, then the
        // 241-byte ClientHello). Padded with PADDING frames (0x00) to 1162.
        const CRYPTO_FRAME_HEX: &str = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff";
        // Expected 1200-byte protected packet (protected header ++ ciphertext).
        const EXPECTED_HEX: &str = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";

        // Reconstruct A.2's 1162-byte unprotected payload.
        let crypto_frame = hex::decode(CRYPTO_FRAME_HEX).unwrap();
        assert_eq!(crypto_frame.len(), 245);
        let mut plaintext = crypto_frame;
        plaintext.resize(1162, 0x00); // PADDING frames

        // A.2's unprotected header, INCLUDING the 4-byte packet number (0x00000002).
        let header = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();
        assert_eq!(header.len(), 22);
        // pn_offset = HDR_BEFORE_LEN(16) + LEN_VARINT(2) = 18; A.2 uses a 4-byte pn.
        let pn_offset = HDR_BEFORE_LEN + LEN_VARINT;
        assert_eq!(pn_offset, 18);

        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_initial_keys(&dcid);

        let produced = seal_and_protect(&keys, header, &plaintext, pn_offset, 4, 2);
        let expected = hex::decode(EXPECTED_HEX).unwrap();
        assert_eq!(expected.len(), 1200);
        assert_eq!(
            produced, expected,
            "seal_and_protect must reproduce the RFC 9001 A.2 client Initial byte-for-byte"
        );
    }

    /// A near-MTU aivpn payload must not overflow the forced 2-byte Length
    /// varint, and the datagram must still parse. Also checks
    /// [`quic_initial_overhead`] matches the real per-packet overhead.
    #[test]
    fn overhead_matches_and_no_varint_overflow() {
        let overhead = quic_initial_overhead();
        // For a large payload (no interior padding), datagram == overhead + payload.
        let tag = [0x5au8; 8];
        let payload = vec![0xEE; 1288];
        let dg = build_quic_initial(&tag, &payload, QUIC_MIN_DATAGRAM);
        assert_eq!(dg.len(), overhead + payload.len());
        let layout = parse_quic_initial(&dg).expect("valid Initial");
        assert_eq!(&dg[layout.payload_offset..], &payload[..]);
    }
}
