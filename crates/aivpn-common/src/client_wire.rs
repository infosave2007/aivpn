use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::crypto::{
    self, compute_time_window, current_timestamp_ms, decrypt_payload, derive_session_keys,
    encrypt_payload, generate_resonance_tag, KeyPair, SessionKeys, DEFAULT_WINDOW_MS, NONCE_SIZE,
    TAG_SIZE,
};
use crate::error::{Error, Result};
use crate::protocol::{ControlPayload, InnerHeader, InnerType};

/// Default MDH length matching the primary mask (STUN/WebRTC = 20 bytes).
pub const DEFAULT_MDH_LEN: usize = 20;

/// Legacy constant kept for backward compatibility references.
pub const DEFAULT_ZERO_MDH: [u8; 4] = [0u8; 4];

pub struct DecodedPacket {
    pub counter: u64,
    pub header: InnerHeader,
    pub payload: Vec<u8>,
}

const RECV_REORDER_WINDOW: usize = 256;
/// Forward tag search extent BEFORE the window is synced (first packet after a
/// handshake/ratchet reset). Bounds the one-shot zero-RTT catch-up scan.
const RECV_FUTURE_SEARCH_WINDOW: usize = 1024;
/// Forward tag search extent ONCE synced. Kept small so an attacker spraying
/// garbage UDP at the client's ip:port cannot force ~3×(FUTURE+REORDER) keyed
/// BLAKE3 hashes per packet (a CPU-amplification DoS). A legitimate gap larger
/// than this is rare and recovers via the RX-silence watchdog / reconnect
/// rather than an unbounded per-packet scan.
const RECV_FUTURE_SEARCH_SYNCED: usize = 512;

#[derive(Clone, Copy)]
struct Bitset256 {
    lo: u128,
    hi: u128,
}

impl Bitset256 {
    fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    fn clear(&mut self) {
        self.lo = 0;
        self.hi = 0;
    }

    fn shl(self, shift: u64) -> Self {
        if shift >= 256 {
            return Self::new();
        }
        if shift == 0 {
            return self;
        }
        if shift >= 128 {
            return Self {
                lo: 0,
                hi: self.lo << (shift - 128),
            };
        }

        Self {
            lo: self.lo << shift,
            hi: (self.hi << shift) | (self.lo >> (128 - shift)),
        }
    }

    fn set_bit(&mut self, bit: usize) {
        if bit < 128 {
            self.lo |= 1u128 << bit;
        } else if bit < 256 {
            self.hi |= 1u128 << (bit - 128);
        }
    }

    fn get_bit(&self, bit: usize) -> bool {
        if bit < 128 {
            (self.lo >> bit) & 1 == 1
        } else if bit < 256 {
            (self.hi >> (bit - 128)) & 1 == 1
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct RecvWindow {
    highest: i64,
    bitmap: Bitset256,
}

impl Default for RecvWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl RecvWindow {
    pub fn new() -> Self {
        Self {
            highest: -1,
            bitmap: Bitset256::new(),
        }
    }

    pub fn reset(&mut self) {
        self.highest = -1;
        self.bitmap.clear();
    }

    /// Highest downlink counter validated so far, or `None` before the first
    /// packet. Used by the Linux client's kernel-acceleration path (K6) to
    /// base the forward tag window it pushes to aivpn.ko on the most recent
    /// user-space-validated counter.
    pub fn highest(&self) -> Option<u64> {
        (self.highest >= 0).then_some(self.highest as u64)
    }

    pub fn find_counter(&self, tag: &[u8; TAG_SIZE], keys: &SessionKeys) -> Option<u64> {
        let base_tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let start = if self.highest < 0 {
            0
        } else {
            (self.highest as u64).saturating_sub((RECV_REORDER_WINDOW - 1) as u64)
        };
        let end = if self.highest < 0 {
            // One-shot zero-RTT catch-up before the window is synced.
            RECV_FUTURE_SEARCH_WINDOW as u64
        } else {
            // Steady state: bounded forward search (anti CPU-amplification DoS).
            self.highest as u64 + RECV_FUTURE_SEARCH_SYNCED as u64 + 1
        };

        for tw_offset in [0i64, -1, 1] {
            let tw = (base_tw as i64 + tw_offset) as u64;
            for counter in start..end {
                if !self.is_new(counter) {
                    continue;
                }
                let expected = generate_resonance_tag(&keys.tag_secret, counter, tw);
                // Use constant-time comparison to prevent timing-oracle tag forgery.
                if expected.ct_eq(tag).into() {
                    return Some(counter);
                }
            }
        }

        None
    }

    pub fn mark(&mut self, counter: u64) {
        if self.highest < 0 || counter > self.highest as u64 {
            let shift = if self.highest < 0 {
                RECV_REORDER_WINDOW as u64
            } else {
                counter - self.highest as u64
            };
            self.bitmap = if shift >= RECV_REORDER_WINDOW as u64 {
                let mut bitmap = Bitset256::new();
                bitmap.set_bit(0);
                bitmap
            } else {
                let mut bitmap = self.bitmap.shl(shift);
                bitmap.set_bit(0);
                bitmap
            };
            self.highest = counter as i64;
        } else {
            let diff = (self.highest as u64 - counter) as usize;
            if diff < RECV_REORDER_WINDOW {
                self.bitmap.set_bit(diff);
            }
        }
    }

    fn is_new(&self, counter: u64) -> bool {
        if self.highest < 0 {
            return true;
        }

        let highest = self.highest as u64;
        if counter > highest {
            return true;
        }

        let diff = highest - counter;
        if diff >= RECV_REORDER_WINDOW as u64 {
            return false;
        }

        !self.bitmap.get_bit(diff as usize)
    }
}

pub fn build_inner_packet(inner_type: InnerType, seq_num: u16, payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(4 + payload.len());
    inner.extend_from_slice(&(inner_type as u16).to_le_bytes());
    inner.extend_from_slice(&seq_num.to_le_bytes());
    inner.extend_from_slice(payload);
    inner
}

/// Build a packet with random MDH of given length (Issue #30 fix).
/// Each call generates fresh random MDH bytes, eliminating static fingerprints.
///
/// Uses the legacy `tag ++ mdh ++ ciphertext` wire layout (tag prefixed at
/// packet offset 0). This is a thin wrapper over
/// [`build_random_mdh_packet_with_tag_offset`] with the legacy sentinel.
pub fn build_random_mdh_packet(
    keys: &SessionKeys,
    counter: &mut u64,
    inner: &[u8],
    obfuscated_eph_pub: Option<&[u8; 32]>,
    mdh_len: usize,
) -> Result<Vec<u8>> {
    build_random_mdh_packet_with_tag_offset(
        keys,
        counter,
        inner,
        obfuscated_eph_pub,
        mdh_len,
        crate::mask::default_tag_offset(),
    )
}

/// Build a packet with random MDH, choosing the wire layout from `tag_offset`
/// (Variant A DPI fix — the second wire path used by the mobile cores).
///
/// * `tag_offset == u16::MAX` — legacy layout: `tag ++ mdh ++ ciphertext`, the
///   tag prefixed at packet offset 0. Byte-identical to the historical format.
/// * `tag_offset == N` — new layout: the 8-byte resonance tag is embedded INSIDE
///   the MDH at byte offset `N` (overwriting a reserved carrier slot) and the
///   packet is emitted as `mdh ++ ciphertext` with no separate tag prefix, so a
///   real protocol header can sit at packet offset 0. If `N + TAG_SIZE` would
///   not fit inside `mdh_len` the call falls back to the legacy layout.
pub fn build_random_mdh_packet_with_tag_offset(
    keys: &SessionKeys,
    counter: &mut u64,
    inner: &[u8],
    obfuscated_eph_pub: Option<&[u8; 32]>,
    mdh_len: usize,
    tag_offset: u16,
) -> Result<Vec<u8>> {
    build_mdh_packet_core(
        keys,
        counter,
        inner,
        obfuscated_eph_pub,
        mdh_len,
        tag_offset,
        None,
    )
}

/// Build a packet whose MDH is shaped from `mask`'s `header_spec` (FIX 3:
/// DPI-shaped mobile handshake/control plane).
///
/// The mobile cores use this for the handshake, retries, ClientCert,
/// keepalives, DeviceEnrollment and MaskFeedback/MaskPreference sends. Unlike
/// [`build_random_mdh_packet_with_tag_offset`] (pure-random MDH), the MDH here
/// is generated from the active mask's real protocol header — so the FIRST
/// packets of every iOS/Android connection already carry a valid header (STUN
/// magic cookie, QUIC long header, …) instead of structurally-invalid noise,
/// eliminating the "garbage-then-valid" opening flow signature.
///
/// The wire contract with the server is **unchanged**: the resonance tag is
/// still embedded at `mask.tag_offset`, and the ephemeral key (handshake
/// packets) is still appended immediately after the `mdh_len`-byte MDH region
/// — which equals `eph_pub_offset` for the shipped presets, exactly where the
/// server's handshake parser reads it. Only the previously-random MDH filler
/// bytes become protocol-shaped (the server treats the MDH as opaque apart
/// from the tag/eph slots). For STUN masks the message-length field is patched
/// post-assembly so the opening packets also satisfy nDPI's `is_stun`.
///
/// QUIC limitation: a handshake packet cannot be a full RFC 9001 Initial (the
/// Initial has no slot for the ephemeral key), so for QUIC masks the MDH stays
/// the (long-header-shaped) `header_spec` output rather than a real Initial.
/// The goal — no pure-random-noise opening — still holds for every mask; a
/// genuine QUIC Initial is only produced on the data path by
/// `MimicryEngine::build_packet`.
pub fn build_shaped_mdh_packet(
    keys: &SessionKeys,
    counter: &mut u64,
    inner: &[u8],
    obfuscated_eph_pub: Option<&[u8; 32]>,
    mdh_len: usize,
    mask: &crate::mask::MaskProfile,
) -> Result<Vec<u8>> {
    build_mdh_packet_core(
        keys,
        counter,
        inner,
        obfuscated_eph_pub,
        mdh_len,
        mask.tag_offset,
        Some(mask),
    )
}

/// Shared implementation for the random and header-spec-shaped MDH builders.
/// `header_mask == None` reproduces the historical pure-random MDH byte layout
/// exactly; `Some(mask)` shapes the MDH from `mask.header_spec` and patches the
/// STUN length field (embedded layout only). See [`build_shaped_mdh_packet`].
fn build_mdh_packet_core(
    keys: &SessionKeys,
    counter: &mut u64,
    inner: &[u8],
    obfuscated_eph_pub: Option<&[u8; 32]>,
    mdh_len: usize,
    tag_offset: u16,
    header_mask: Option<&crate::mask::MaskProfile>,
) -> Result<Vec<u8>> {
    let pad_len: u16 = 8 + rand::thread_rng().next_u32() as u16 % 16;
    let mut plaintext = Vec::with_capacity(2 + inner.len() + pad_len as usize);
    plaintext.extend_from_slice(&pad_len.to_le_bytes());
    plaintext.extend_from_slice(inner);
    plaintext.resize(2 + inner.len() + pad_len as usize, 0);
    rand::thread_rng().fill_bytes(&mut plaintext[2 + inner.len()..]);

    let current_counter = *counter;
    *counter += 1;

    let nonce = counter_to_nonce(current_counter);
    let ciphertext = encrypt_payload(&keys.session_key, &nonce, &plaintext)?;
    let time_window = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&keys.tag_secret, current_counter, time_window);

    // Generate the MDH bytes. With a header-spec'd mask, shape the MDH as that
    // protocol's real header (STUN magic cookie, QUIC long header, …); without
    // one, fall back to the historical pure-random MDH. In both cases the MDH is
    // fitted to exactly `mdh_len` so the appended ephemeral key still lands at
    // offset `mdh_len` (== `eph_pub_offset` for the presets), preserving the
    // server's handshake wire contract.
    let mut mdh = match header_mask.and_then(|m| m.header_spec.as_ref()) {
        Some(spec) => {
            let mut h = spec.generate(&mut rand::thread_rng());
            if h.len() < mdh_len {
                let start = h.len();
                h.resize(mdh_len, 0);
                rand::thread_rng().fill_bytes(&mut h[start..]);
            } else {
                h.truncate(mdh_len);
            }
            h
        }
        None => {
            let mut h = vec![0u8; mdh_len];
            rand::thread_rng().fill_bytes(&mut h);
            h
        }
    };

    // Embed the tag into the MDH only when a valid slot fits; otherwise fall
    // back to the legacy tag-prefix layout.
    let embed_tag_offset = if tag_offset != u16::MAX && (tag_offset as usize) + TAG_SIZE <= mdh_len
    {
        Some(tag_offset as usize)
    } else {
        None
    };

    let eph_len = if obfuscated_eph_pub.is_some() { 32 } else { 0 };
    let tag_prefix_len = if embed_tag_offset.is_some() {
        0
    } else {
        TAG_SIZE
    };
    let mut packet = Vec::with_capacity(tag_prefix_len + mdh_len + eph_len + ciphertext.len());

    if let Some(off) = embed_tag_offset {
        // New layout: tag hidden inside the MDH, no separate prefix.
        mdh[off..off + TAG_SIZE].copy_from_slice(&tag);
        packet.extend_from_slice(&mdh);
    } else {
        // Legacy layout: tag prefix then MDH.
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
    }
    if let Some(eph) = obfuscated_eph_pub {
        packet.extend_from_slice(eph);
    }
    packet.extend_from_slice(&ciphertext);

    // STUN masks (embedded layout only): reconcile the message-length field so
    // the opening handshake/control packets also satisfy nDPI's `is_stun`
    // (`msg_len + 20 == udp_payload_len`), matching the data path. A no-op for
    // non-STUN masks and for `header_mask == None`. Never applied in the legacy
    // tag-prefix layout, where the STUN header is shifted past the 8-byte tag
    // prefix and patching would corrupt the tag.
    if embed_tag_offset.is_some() {
        if let Some(mask) = header_mask {
            mask.patch_stun_length(&mut packet);
        }
    }

    Ok(packet)
}

/// Legacy: build packet with 4-byte zero MDH (kept for backward compatibility).
pub fn build_zero_mdh_packet(
    keys: &SessionKeys,
    counter: &mut u64,
    inner: &[u8],
    obfuscated_eph_pub: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    build_random_mdh_packet(
        keys,
        counter,
        inner,
        obfuscated_eph_pub,
        DEFAULT_ZERO_MDH.len(),
    )
}

/// Decode a packet using the legacy wire layout (tag prefixed at packet offset
/// 0, ciphertext at `TAG_SIZE + mdh_len`). Thin wrapper over
/// [`decode_packet_with_layout`] with the legacy sentinel.
pub fn decode_packet_with_mdh_len(
    packet: &[u8],
    keys: &SessionKeys,
    recv_window: &mut RecvWindow,
    mdh_len: usize,
) -> Result<DecodedPacket> {
    decode_packet_with_layout(
        packet,
        keys,
        recv_window,
        mdh_len,
        crate::mask::default_tag_offset(),
    )
}

/// Decode a packet, selecting the wire layout from `tag_offset` (Variant A).
///
/// * `tag_offset == u16::MAX` — legacy: the resonance tag is read from
///   `packet[0..TAG_SIZE]` and the ciphertext starts at `TAG_SIZE + mdh_len`.
/// * `tag_offset == N` — new: the tag is read from `packet[N..N+TAG_SIZE]`
///   (embedded inside the real protocol header) and the ciphertext starts at
///   `mdh_len` (there is no separate tag prefix).
///
/// The legacy branch is byte-for-byte identical to the historical decoder.
pub fn decode_packet_with_layout(
    packet: &[u8],
    keys: &SessionKeys,
    recv_window: &mut RecvWindow,
    mdh_len: usize,
    tag_offset: u16,
) -> Result<DecodedPacket> {
    // (tag_start, ciphertext_start, minimum header bytes before the ciphertext)
    let (tag_start, ct_start, header_len) = if tag_offset == u16::MAX {
        (0usize, TAG_SIZE + mdh_len, TAG_SIZE + mdh_len)
    } else {
        let off = tag_offset as usize;
        // A well-formed new-layout mask keeps mdh_len >= off + TAG_SIZE; guard
        // anyway so a short/malformed header can't slice out of bounds.
        (off, mdh_len, mdh_len.max(off + TAG_SIZE))
    };

    // +16 keeps the historical minimum ciphertext length (poly1305 tag).
    if packet.len() < header_len + 16 {
        return Err(Error::InvalidPacket("Packet too short"));
    }

    let tag: [u8; TAG_SIZE] = packet[tag_start..tag_start + TAG_SIZE]
        .try_into()
        .map_err(|_| Error::InvalidPacket("Packet tag malformed"))?;
    let counter = recv_window
        .find_counter(&tag, keys)
        .ok_or(Error::InvalidPacket("Invalid resonance tag"))?;

    let nonce = counter_to_nonce(counter);
    let ciphertext = &packet[ct_start..];
    // This decode path is the CLIENT's downlink receive (server→client packets),
    // so it decrypts with the S2C key. The server never uses decode_packet_*; it
    // decrypts client uplink with `session_key` (C2S) directly in the gateway.
    let padded = decrypt_payload(&keys.session_key_s2c, &nonce, ciphertext)?;
    recv_window.mark(counter);

    parse_downlink_inner(counter, &padded)
}

/// Strip the `pad_len(LE u16) || inner_header || payload || random_padding`
/// framing from a decrypted downlink payload. Shared by the fixed-length and
/// multi-length decoders so both apply identical bounds checks.
fn parse_downlink_inner(counter: u64, padded: &[u8]) -> Result<DecodedPacket> {
    if padded.len() < 2 {
        return Err(Error::InvalidPacket("Decrypted payload too short"));
    }

    let pad_len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    let end = padded
        .len()
        .checked_sub(pad_len)
        .ok_or(Error::InvalidPacket("Invalid padding length"))?;
    if end < 2 {
        return Err(Error::InvalidPacket("Invalid padding length"));
    }

    let inner = &padded[2..end];
    if inner.len() < 4 {
        return Err(Error::InvalidPacket("Inner payload too short"));
    }

    let header = InnerHeader::decode(inner)?;
    let payload = inner[4..].to_vec();

    Ok(DecodedPacket {
        counter,
        header,
        payload,
    })
}

/// Upper bound (inclusive) for the self-healing MDH-length scan in
/// [`decode_downlink_any_mdh_len`]. Every shipped mask header is <= 40 bytes
/// (STUN 20, QUIC 14, DNS 12, TLS 5, WebRTC <= 20); 64 covers any realistic
/// header with margin. The scan only runs after a valid resonance tag matched
/// and caches its result, so this bound is a one-off cost, not a hot path.
const MAX_DOWNLINK_MDH_SCAN: usize = 64;

/// Decode a legacy-framed downlink packet, trying each candidate MDH length.
///
/// Downlink (server→client) always uses legacy framing (`default_tag_offset()`
/// == `u16::MAX`): the 8-byte resonance tag sits at offset 0, so the counter
/// lookup is *independent* of the MDH length — only the ciphertext start
/// (`TAG_SIZE + mdh_len`) shifts. A server legitimately encodes different
/// downlink packets in a single session with different masks (the per-session
/// bootstrap mask for early DATA, the runtime/catalog mask for control and
/// rekey packets, a polymorphic variant after `MaskPreference`), and those
/// masks can have different header lengths. A client that assumes one fixed
/// MDH length silently drops every packet whose mask differs, which strands the
/// tunnel the moment the server rotates keys or masks.
///
/// This looks the counter up once (from the offset-0 tag) and then tries to
/// decrypt at each candidate MDH length, returning the first that
/// authenticates. AEAD authentication makes a wrong length a guaranteed miss,
/// so there is no risk of accepting a mis-framed packet. Put the most likely
/// (current) length first for the common-case fast path; duplicates and lengths
/// that overrun the packet are skipped cheaply.
pub fn decode_downlink_any_mdh_len(
    packet: &[u8],
    keys: &SessionKeys,
    recv_window: &mut RecvWindow,
    candidate_mdh_lens: &mut Vec<usize>,
) -> Result<DecodedPacket> {
    // Legacy framing only: tag at [0..TAG_SIZE], counter lookup once.
    if packet.len() < TAG_SIZE + 16 {
        return Err(Error::InvalidPacket("Packet too short"));
    }
    let tag: [u8; TAG_SIZE] = packet[0..TAG_SIZE]
        .try_into()
        .map_err(|_| Error::InvalidPacket("Packet tag malformed"))?;
    let counter = recv_window
        .find_counter(&tag, keys)
        .ok_or(Error::InvalidPacket("Invalid resonance tag"))?;
    let nonce = counter_to_nonce(counter);

    // Fast path: try every MDH length we have already learned.
    let mut tried_any = false;
    for &mdh_len in candidate_mdh_lens.iter() {
        let ct_start = TAG_SIZE + mdh_len;
        if packet.len() < ct_start + 16 {
            continue;
        }
        tried_any = true;
        if let Ok(padded) = decrypt_payload(&keys.session_key_s2c, &nonce, &packet[ct_start..]) {
            // Only advance the anti-replay window once we have a packet that
            // both authenticates and frames cleanly — a candidate that decrypts
            // but fails inner parsing must not consume the counter.
            let decoded = parse_downlink_inner(counter, &padded)?;
            recv_window.mark(counter);
            return Ok(decoded);
        }
    }

    // Robustness fallback (self-healing MDH discovery). The tag authenticated —
    // this genuinely IS a packet for our session at a counter we recovered — but
    // none of the lengths we have learned frame it. That happens when the server
    // commits a mask switch whose `MaskUpdate` we never processed (e.g. an early
    // MaskUpdate dropped before the downlink window synced): the server reframes
    // downlink with the new mask's MDH length while we still only know the
    // bootstrap length, and every DATA packet would otherwise be stranded → RX
    // silence → reconnect loop. Instead, scan a bounded range of plausible MDH
    // lengths. AEAD (Poly1305) authentication makes a wrong length a guaranteed
    // miss, so a hit is unambiguous and safe; and it is only reachable AFTER a
    // valid resonance tag matched, so a forged packet can never trigger the scan
    // (no CPU-amplification vector). Cache the discovered length so all further
    // packets take the fast path above — the scan runs at most once per new mask.
    for mdh_len in 0..=MAX_DOWNLINK_MDH_SCAN {
        if candidate_mdh_lens.contains(&mdh_len) {
            continue;
        }
        let ct_start = TAG_SIZE + mdh_len;
        if packet.len() < ct_start + 16 {
            continue;
        }
        if let Ok(padded) = decrypt_payload(&keys.session_key_s2c, &nonce, &packet[ct_start..]) {
            if let Ok(decoded) = parse_downlink_inner(counter, &padded) {
                recv_window.mark(counter);
                // Learn it: front = most-likely-next for the fast path.
                candidate_mdh_lens.insert(0, mdh_len);
                return Ok(decoded);
            }
        }
    }

    if tried_any {
        Err(Error::InvalidPacket(
            "resonance tag matched but no MDH length (learned or scanned) authenticated",
        ))
    } else {
        Err(Error::InvalidPacket("Packet too short"))
    }
}

/// Process a ServerHello control packet and complete the PFS ratchet.
///
/// `server_signing_key`, when `Some`, is the operator's ed25519 verifying key
/// (matching desktop's `ClientConfig::server_signing_key`). The ServerHello's
/// `signature` field is checked over `(server_eph_pub || client_eph_pub)` —
/// the same tuple and verification the server signs in `session.rs`
/// `create_session()` — before the ratchet is applied. A `None` key skips
/// verification entirely, mirroring desktop's own behaviour when no signing
/// key is configured (signature verification there is opt-in, not
/// mandatory), so this stays backward compatible with callers that have not
/// yet been wired up to supply a trusted key.
///
/// Returns `(network_config, server_eph_pub)` on success. Callers need
/// `server_eph_pub` after the handshake loop exits to build the
/// session-bound `DeviceEnrollment` proof (see
/// `crypto::device_enrollment_proof`), which must hash the exact
/// `server_eph_pub || client_eph_pub` pair this ratchet used.
pub fn process_server_hello_with_mdh_len(
    packet: &[u8],
    keys: &mut SessionKeys,
    keypair: &KeyPair,
    recv_window: &mut RecvWindow,
    send_counter: &mut u64,
    mdh_len: usize,
    server_signing_key: Option<&[u8; 32]>,
) -> Result<(Option<crate::network_config::ClientNetworkConfig>, [u8; 32])> {
    let decoded = decode_packet_with_mdh_len(packet, keys, recv_window, mdh_len)?;

    if decoded.header.inner_type != InnerType::Control {
        return Err(Error::InvalidPacket(
            "Expected control packet for ServerHello",
        ));
    }

    match ControlPayload::decode(&decoded.payload)? {
        ControlPayload::ServerHello {
            server_eph_pub,
            signature,
            network_config,
        } => {
            // Verify ed25519 signature over (server_eph_pub || client_eph_pub),
            // matching desktop's ServerHello handler in aivpn-client/src/client.rs.
            if let Some(signing_key) = server_signing_key {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let vk = VerifyingKey::from_bytes(signing_key)
                    .map_err(|e| Error::Crypto(format!("Invalid server signing key: {}", e)))?;
                let mut msg = Vec::with_capacity(64);
                msg.extend_from_slice(&server_eph_pub);
                msg.extend_from_slice(&keypair.public_key_bytes());
                let sig = Signature::from_bytes(&signature);
                if vk.verify(&msg, &sig).is_err() {
                    return Err(Error::Crypto(
                        "ServerHello signature invalid — possible MITM attack".into(),
                    ));
                }
            }

            let dh2 = keypair.compute_shared(&server_eph_pub)?;
            let old_session_key = keys.session_key;
            *keys = derive_session_keys(&dh2, Some(&old_session_key), &keypair.public_key_bytes());
            *send_counter = 0;
            recv_window.reset();
            Ok((network_config, server_eph_pub))
        }
        _ => Err(Error::InvalidPacket("Expected ServerHello control payload")),
    }
}

pub fn obfuscate_client_eph_pub(keypair: &KeyPair, server_public_key: &[u8; 32]) -> [u8; 32] {
    let mut obfuscated = keypair.public_key_bytes();
    crypto::obfuscate_eph_pub(&mut obfuscated, server_public_key);
    obfuscated
}

pub fn counter_to_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tag_layout_tests {
    use super::*;
    use crate::crypto::{
        compute_time_window, current_timestamp_ms, derive_session_keys, generate_resonance_tag,
        KeyPair, DEFAULT_WINDOW_MS,
    };
    use crate::protocol::InnerType;

    fn test_keys() -> SessionKeys {
        let client_kp = KeyPair::generate();
        let server_kp = KeyPair::generate();
        let dh = client_kp
            .compute_shared(&server_kp.public_key_bytes())
            .unwrap();
        let mut keys = derive_session_keys(&dh, None, &client_kp.public_key_bytes());
        // These round-trip tests exercise the wire FORMAT (encode → decode), not
        // directional key separation: they encode with the C2S key
        // (build_mdh_packet_core) and decode with the S2C key
        // (decode_packet_*). Equalise the two so the format round-trips; the
        // directional split itself is covered by `directional_keys_differ` and
        // the live tunnel.
        keys.session_key_s2c = keys.session_key;
        keys
    }

    #[test]
    fn directional_keys_differ() {
        // The whole point of the S2C key: it must NOT equal the C2S key, or the
        // two directions would reuse the ChaCha20 keystream (same counter space).
        let keys = {
            let c = KeyPair::generate();
            let s = KeyPair::generate();
            let dh = c.compute_shared(&s.public_key_bytes()).unwrap();
            derive_session_keys(&dh, Some(&[9u8; 32]), &c.public_key_bytes())
        };
        assert_ne!(keys.session_key, keys.session_key_s2c);
    }

    #[test]
    fn embedded_layout_roundtrip_recovers_tag_and_payload() {
        let keys = test_keys();
        let mdh_len = 20usize; // STUN-sized header
        let tag_offset: u16 = 8;
        let inner = build_inner_packet(InnerType::Data, 3, b"embedded-payload");

        let mut counter = 0u64;
        let pkt = build_random_mdh_packet_with_tag_offset(
            &keys,
            &mut counter,
            &inner,
            None,
            mdh_len,
            tag_offset,
        )
        .unwrap();

        // (c) tag sits at packet offset tag_offset, NOT at offset 0.
        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected = generate_resonance_tag(&keys.tag_secret, 0, tw);
        assert_eq!(
            &pkt[tag_offset as usize..tag_offset as usize + TAG_SIZE],
            &expected
        );

        // (a) decode with the same layout recovers the SAME inner payload.
        let mut win = RecvWindow::new();
        let decoded =
            decode_packet_with_layout(&pkt, &keys, &mut win, mdh_len, tag_offset).unwrap();
        assert_eq!(decoded.counter, 0);
        assert_eq!(decoded.payload, b"embedded-payload");
    }

    #[test]
    fn legacy_layout_is_tag_prefixed_and_roundtrips() {
        let keys = test_keys();
        let mdh_len = 20usize;
        let inner = build_inner_packet(InnerType::Data, 1, b"legacy-payload");

        // Explicit legacy sentinel.
        let mut counter = 0u64;
        let pkt = build_random_mdh_packet_with_tag_offset(
            &keys,
            &mut counter,
            &inner,
            None,
            mdh_len,
            u16::MAX,
        )
        .unwrap();

        // (d) legacy layout: tag is the prefix at packet offset 0.
        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected = generate_resonance_tag(&keys.tag_secret, 0, tw);
        assert_eq!(&pkt[0..TAG_SIZE], &expected);

        // The legacy public wrapper must delegate to exactly this layout — its
        // output decodes with the original legacy decoder.
        let mut win = RecvWindow::new();
        let decoded = decode_packet_with_mdh_len(&pkt, &keys, &mut win, mdh_len).unwrap();
        assert_eq!(decoded.payload, b"legacy-payload");
    }

    #[test]
    fn shaped_handshake_packet_carries_stun_header_for_stun_mask() {
        // FIX 3: a mobile-built handshake packet for a STUN mask must carry the
        // real STUN header (magic cookie at offset 4) instead of pure-random
        // noise, while keeping the tag at tag_offset and the eph key appended
        // after the MDH exactly as the server's handshake parser expects.
        use crate::mask::preset_masks::webrtc_zoom_v3;
        let keys = test_keys();
        let mask = webrtc_zoom_v3();
        assert_eq!(mask.tag_offset, 8);
        let mdh_len = mask.header_spec.as_ref().unwrap().min_length();
        assert_eq!(mdh_len, 20);

        let inner = build_inner_packet(InnerType::Control, 0, b"handshake");
        let eph = [0xABu8; 32];
        let mut counter = 0u64;
        let pkt = build_shaped_mdh_packet(&keys, &mut counter, &inner, Some(&eph), mdh_len, &mask)
            .unwrap();

        // STUN Binding Request type at offset 0, magic cookie at offset 4.
        assert_eq!(&pkt[0..2], &[0x00, 0x01], "STUN type at offset 0");
        assert_eq!(
            &pkt[4..8],
            &[0x21, 0x12, 0xA4, 0x42],
            "STUN magic cookie at offset 4"
        );

        // Resonance tag embedded at tag_offset (inside the transaction id).
        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected = generate_resonance_tag(&keys.tag_secret, 0, tw);
        assert_eq!(
            &pkt[mask.tag_offset as usize..mask.tag_offset as usize + TAG_SIZE],
            &expected
        );

        // Ephemeral key appended immediately after the mdh_len-byte MDH (==
        // eph_pub_offset), where the server reads it.
        assert_eq!(&pkt[mdh_len..mdh_len + 32], &eph);

        // STUN length field patched so nDPI's is_stun holds: msg_len + 20 == len.
        let msg_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        assert_eq!(msg_len + 20, pkt.len(), "is_stun length invariant");
    }

    #[test]
    fn public_wrapper_matches_legacy_layout() {
        // build_random_mdh_packet (no tag_offset) must stay legacy: tag at [0..8].
        let keys = test_keys();
        let inner = build_inner_packet(InnerType::Data, 0, b"x");
        let mut counter = 0u64;
        let pkt = build_random_mdh_packet(&keys, &mut counter, &inner, None, 20).unwrap();
        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected = generate_resonance_tag(&keys.tag_secret, 0, tw);
        assert_eq!(&pkt[0..TAG_SIZE], &expected);
    }

    #[test]
    fn any_mdh_len_decodes_mixed_downlink_lengths() {
        // Regression for the live-stand bug: the server frames DATA with the
        // per-session (bootstrap) mask while control/rekey packets used a
        // different (catalog) mask. A single-length decoder decodes one and
        // permanently drops the other, stranding the tunnel after the first
        // rekey. decode_downlink_any_mdh_len must decode BOTH interleaved,
        // regardless of arrival order.
        let keys = test_keys();
        let data_mdh = 24usize; // per-session bootstrap layout
        let ctrl_mdh = 20usize; // catalog/runtime layout
        let mut candidates = vec![ctrl_mdh, data_mdh]; // current-first, prior retained

        let mut win = RecvWindow::new();
        let mut counter = 0u64;

        // counter 0: DATA at the bootstrap length.
        let d0 = build_random_mdh_packet(
            &keys,
            &mut counter,
            &build_inner_packet(InnerType::Data, 0, b"data-zero"),
            None,
            data_mdh,
        )
        .unwrap();
        let dec0 = decode_downlink_any_mdh_len(&d0, &keys, &mut win, &mut candidates).unwrap();
        assert_eq!(dec0.payload, b"data-zero");

        // counter 1: a control/rekey packet at the catalog length (the packet
        // that used to clear the one-shot fallback and kill the connection).
        let c1 = build_random_mdh_packet(
            &keys,
            &mut counter,
            &build_inner_packet(InnerType::Control, 1, b"rekey"),
            None,
            ctrl_mdh,
        )
        .unwrap();
        let dec1 = decode_downlink_any_mdh_len(&c1, &keys, &mut win, &mut candidates).unwrap();
        assert_eq!(dec1.header.inner_type, InnerType::Control);

        // counter 2: DATA at the bootstrap length again — must STILL decode.
        let d2 = build_random_mdh_packet(
            &keys,
            &mut counter,
            &build_inner_packet(InnerType::Data, 2, b"data-two"),
            None,
            data_mdh,
        )
        .unwrap();
        let dec2 = decode_downlink_any_mdh_len(&d2, &keys, &mut win, &mut candidates).unwrap();
        assert_eq!(dec2.payload, b"data-two");
    }

    #[test]
    fn any_mdh_len_rejects_wrong_key() {
        // A genuine key mismatch (wrong session keys) must fail for every
        // candidate length — the fallback is a framing recovery, never a way to
        // accept a packet the client cannot authenticate.
        let keys = test_keys();
        let mut other = test_keys();
        other.tag_secret = [0x5Au8; 32]; // different tag secret → tag never found
        let mut counter = 0u64;
        let pkt = build_random_mdh_packet(
            &other,
            &mut counter,
            &build_inner_packet(InnerType::Data, 0, b"x"),
            None,
            20,
        )
        .unwrap();
        let mut win = RecvWindow::new();
        assert!(decode_downlink_any_mdh_len(&pkt, &keys, &mut win, &mut vec![20, 24]).is_err());
    }

    #[test]
    fn any_mdh_len_marks_replay_once() {
        // The anti-replay window must advance exactly once for an accepted
        // packet; a second decode of the same counter must be rejected as replay.
        let keys = test_keys();
        let mut counter = 0u64;
        let pkt = build_random_mdh_packet(
            &keys,
            &mut counter,
            &build_inner_packet(InnerType::Data, 0, b"once"),
            None,
            20,
        )
        .unwrap();
        let mut win = RecvWindow::new();
        assert!(decode_downlink_any_mdh_len(&pkt, &keys, &mut win, &mut vec![20, 24]).is_ok());
        // Same packet again: the counter is no longer new → tag lookup fails.
        assert!(decode_downlink_any_mdh_len(&pkt, &keys, &mut win, &mut vec![20, 24]).is_err());
    }

    #[test]
    fn server_downlink_padding_roundtrips_and_is_stripped() {
        // A7: the server pads server→client DATA to a size sampled from the
        // session mask's distribution, writing the filler into the pad_len
        // field. Build a downlink packet exactly as gateway.rs's downlink
        // worker does — legacy framing `tag || mdh || encrypt_s2c(pad_len ||
        // inner || payload || random_pad)` — and assert the client decoder
        // recovers the original payload and strips ALL padding. A large pad
        // (near the WAN budget) is used to exercise the resize path.
        let keys = test_keys();
        let mdh_len = 20usize;
        let payload = b"a7-downlink-payload";
        let inner = build_inner_packet(InnerType::Data, 7, payload);
        let pad_len: u16 = 900; // well past the 8-23 the helper would pick

        // Server plaintext layout: pad_len(LE) || inner || pad_len filler bytes.
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&pad_len.to_le_bytes());
        plaintext.extend_from_slice(&inner);
        let filler_start = plaintext.len();
        plaintext.resize(filler_start + pad_len as usize, 0);
        // Deterministic non-zero filler so a decoder that mis-strips would leak it.
        for (i, b) in plaintext[filler_start..].iter_mut().enumerate() {
            *b = (i % 251) as u8 + 1;
        }

        let counter = 0u64;
        let nonce = counter_to_nonce(counter);
        let ciphertext = encrypt_payload(&keys.session_key_s2c, &nonce, &plaintext).unwrap();

        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let tag = generate_resonance_tag(&keys.tag_secret, counter, tw);

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&tag);
        pkt.resize(TAG_SIZE + mdh_len, 0); // random-ish MDH (content irrelevant, legacy tag@0)
        pkt.extend_from_slice(&ciphertext);

        let mut win = RecvWindow::new();
        let decoded =
            decode_downlink_any_mdh_len(&pkt, &keys, &mut win, &mut vec![mdh_len, 24]).unwrap();
        assert_eq!(decoded.header.inner_type, InnerType::Data);
        assert_eq!(
            decoded.payload, payload,
            "padding must be fully stripped, leaving only the original payload"
        );
    }

    #[test]
    fn any_mdh_len_self_heals_unknown_length_and_caches_it() {
        // Live-stand root cause: the server commits a mask switch (new MDH
        // length) whose MaskUpdate the client never processed, so the client's
        // candidate set lacks that length and every DATA packet strands. The
        // self-healing scan must recover: a valid-tag packet framed at a length
        // NOT in the candidate set still decodes, and the discovered length is
        // cached so subsequent packets hit the fast path.
        let keys = test_keys();
        let unknown_mdh = 32usize; // not in candidates below, within the scan bound
        let mut counter = 0u64;
        let p0 = build_random_mdh_packet(
            &keys,
            &mut counter,
            &build_inner_packet(InnerType::Data, 0, b"heal-me"),
            None,
            unknown_mdh,
        )
        .unwrap();

        let mut win = RecvWindow::new();
        let mut candidates = vec![20usize]; // bootstrap length only — no 32
        let dec = decode_downlink_any_mdh_len(&p0, &keys, &mut win, &mut candidates).unwrap();
        assert_eq!(dec.payload, b"heal-me");
        assert!(
            candidates.contains(&unknown_mdh),
            "discovered MDH length must be cached for the fast path"
        );
        assert_eq!(
            candidates[0], unknown_mdh,
            "the freshly learned length should be tried first next time"
        );

        // A second packet at the same length now takes the fast path.
        let p1 = build_random_mdh_packet(
            &keys,
            &mut counter,
            &build_inner_packet(InnerType::Data, 1, b"again"),
            None,
            unknown_mdh,
        )
        .unwrap();
        let dec1 = decode_downlink_any_mdh_len(&p1, &keys, &mut win, &mut candidates).unwrap();
        assert_eq!(dec1.payload, b"again");
    }

    #[test]
    fn embedded_packet_is_tag_size_shorter_than_legacy() {
        // Same inner/mdh: embedded layout omits the 8-byte tag prefix, so for a
        // fixed padding it is exactly TAG_SIZE shorter. Padding is random here,
        // so instead assert the structural offset: embedded ciphertext starts at
        // mdh_len while legacy starts at TAG_SIZE + mdh_len.
        let keys = test_keys();
        let mdh_len = 20usize;
        let inner = build_inner_packet(InnerType::Data, 0, b"cmp");

        let mut c1 = 0u64;
        let emb = build_random_mdh_packet_with_tag_offset(&keys, &mut c1, &inner, None, mdh_len, 8)
            .unwrap();
        let mut win1 = RecvWindow::new();
        assert!(decode_packet_with_layout(&emb, &keys, &mut win1, mdh_len, 8).is_ok());
        // Decoding the embedded packet with the legacy decoder must NOT recover
        // the payload (tag would be read from the wrong offset).
        let mut win2 = RecvWindow::new();
        assert!(decode_packet_with_mdh_len(&emb, &keys, &mut win2, mdh_len).is_err());
    }
}

#[cfg(test)]
mod server_hello_signature_tests {
    use super::*;
    use crate::crypto::KeyPair;

    /// Builds an encrypted ServerHello packet (as the server would send it)
    /// signed with `signing_key` over `(server_eph_pub || client_eph_pub)`,
    /// matching aivpn-server's `session.rs` `create_session()`.
    fn build_signed_server_hello_packet(
        signing_key: &ed25519_dalek::SigningKey,
        client_keypair: &KeyPair,
        initial_keys: &SessionKeys,
    ) -> ([u8; 32], Vec<u8>) {
        use ed25519_dalek::Signer;

        let server_eph_kp = KeyPair::generate();
        let server_eph_pub = server_eph_kp.public_key_bytes();

        let mut sign_message = Vec::with_capacity(64);
        sign_message.extend_from_slice(&server_eph_pub);
        sign_message.extend_from_slice(&client_keypair.public_key_bytes());
        let signature = signing_key.sign(&sign_message).to_bytes();

        let hello = ControlPayload::ServerHello {
            server_eph_pub,
            signature,
            network_config: None,
        };
        let encoded = hello.encode().unwrap();
        let inner = build_inner_packet(InnerType::Control, 0, &encoded);

        let mut send_counter = 0u64;
        let packet = build_random_mdh_packet(
            initial_keys,
            &mut send_counter,
            &inner,
            None,
            DEFAULT_MDH_LEN,
        )
        .unwrap();
        (server_eph_pub, packet)
    }

    fn setup() -> (KeyPair, SessionKeys) {
        let client_kp = KeyPair::generate();
        let server_static_kp = KeyPair::generate();
        let dh1 = client_kp
            .compute_shared(&server_static_kp.public_key_bytes())
            .unwrap();
        let mut initial_keys = derive_session_keys(&dh1, None, &client_kp.public_key_bytes());
        // ServerHello is server→client (S2C), but this test builds it with the
        // C2S encode path; equalise so the format round-trips (directional
        // separation is covered by `directional_keys_differ` + live tunnel).
        initial_keys.session_key_s2c = initial_keys.session_key;
        (client_kp, initial_keys)
    }

    #[test]
    fn accepts_valid_signature_when_key_provided() {
        let (client_kp, initial_keys) = setup();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();

        let (_server_eph_pub, packet) =
            build_signed_server_hello_packet(&signing_key, &client_kp, &initial_keys);

        let mut keys = initial_keys;
        let mut recv_win = RecvWindow::new();
        let mut send_counter = 0u64;
        let result = process_server_hello_with_mdh_len(
            &packet,
            &mut keys,
            &client_kp,
            &mut recv_win,
            &mut send_counter,
            DEFAULT_MDH_LEN,
            Some(&verifying_key),
        );
        assert!(
            result.is_ok(),
            "valid signature must be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn rejects_signature_from_wrong_signing_key() {
        let (client_kp, initial_keys) = setup();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
        let trusted_verifying_key = wrong_key.verifying_key().to_bytes();

        // Packet is signed by `signing_key`, but the client trusts `wrong_key`'s
        // verifying key — this must be rejected as a possible MITM attack.
        let (_server_eph_pub, packet) =
            build_signed_server_hello_packet(&signing_key, &client_kp, &initial_keys);

        let mut keys = initial_keys;
        let mut recv_win = RecvWindow::new();
        let mut send_counter = 0u64;
        let result = process_server_hello_with_mdh_len(
            &packet,
            &mut keys,
            &client_kp,
            &mut recv_win,
            &mut send_counter,
            DEFAULT_MDH_LEN,
            Some(&trusted_verifying_key),
        );
        assert!(
            result.is_err(),
            "forged/mismatched signature must be rejected"
        );
    }

    #[test]
    fn skips_verification_when_no_signing_key_configured() {
        // No signing key configured (None) — must behave exactly like before
        // this fix: ratchet proceeds even with a bogus/zero signature. This
        // matches desktop's own opt-in verification behavior.
        let (client_kp, initial_keys) = setup();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);

        let (_server_eph_pub, packet) =
            build_signed_server_hello_packet(&signing_key, &client_kp, &initial_keys);

        let mut keys = initial_keys;
        let mut recv_win = RecvWindow::new();
        let mut send_counter = 0u64;
        let result = process_server_hello_with_mdh_len(
            &packet,
            &mut keys,
            &client_kp,
            &mut recv_win,
            &mut send_counter,
            DEFAULT_MDH_LEN,
            None,
        );
        assert!(
            result.is_ok(),
            "None signing key must skip verification (backward compatible)"
        );
    }
}
