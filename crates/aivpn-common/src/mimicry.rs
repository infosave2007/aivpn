//! Mimicry Engine
//!
//! Shapes traffic to match Mask profile characteristics.
//! Also provides [`MimicryEncryptor`], a [`crate::upload_pipeline::PacketEncryptor`]
//! implementation for mobile cores (iOS, Android) that wraps MimicryEngine with
//! session-key storage and an atomic pending-mask slot.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::debug;

use crate::client_wire::build_inner_packet;
use crate::crypto::{self, encrypt_payload, SessionKeys, NONCE_SIZE, POLY1305_TAG_SIZE, TAG_SIZE};
use crate::error::Result;
use crate::fec::FecEncoder;
use crate::mask::{IATDistribution, MaskProfile, PaddingStrategy, SizeDistribution, SpoofProtocol};
use crate::mimic_protocol::MimicProtocol;
use crate::protocol::{ControlPayload, InnerType, MAX_PACKET_SIZE};
use crate::upload_pipeline::PacketEncryptor;

const SAFE_OUTER_PACKET_BUDGET: usize = 1380;

// ──────────── MimicryState ────────────

pub struct MimicryState {
    pub current_state: u16,
    pub packets_in_state: u32,
    pub state_start: Instant,
    pub size_override: Option<SizeDistribution>,
    pub iat_override: Option<IATDistribution>,
    pub padding_override: Option<PaddingStrategy>,
    /// R3: when the mask carries a joint size↔IAT distribution, sampling the
    /// packet size draws the correlated (size, iat) pair together and stashes
    /// the IAT here for the matching `sample_iat` call, so the two stay coupled.
    pub pending_joint_iat: Option<f64>,
}

// ──────────── MimicryEngine ────────────

pub struct MimicryEngine {
    mask: MaskProfile,
    state: MimicryState,
    rng: StdRng,
}

impl MimicryEngine {
    pub fn new(mask: MaskProfile) -> Self {
        let initial_state = mask.initial_state();
        Self {
            mask,
            state: MimicryState {
                current_state: initial_state,
                packets_in_state: 0,
                state_start: Instant::now(),
                size_override: None,
                iat_override: None,
                padding_override: None,
                pending_joint_iat: None,
            },
            rng: StdRng::from_entropy(),
        }
    }

    pub fn mask(&self) -> &MaskProfile {
        &self.mask
    }

    pub fn update_mask(&mut self, new_mask: MaskProfile) {
        debug!("Updating mask to {}", new_mask.mask_id);
        self.mask = new_mask;
        self.state = MimicryState {
            current_state: self.mask.initial_state(),
            packets_in_state: 0,
            state_start: Instant::now(),
            size_override: None,
            iat_override: None,
            padding_override: None,
            pending_joint_iat: None,
        };
    }

    pub fn sample_packet_size(&mut self) -> u16 {
        // R3: a joint size↔IAT model (present only when the recording showed
        // material correlation) supersedes the independent marginals AND the FSM
        // per-state override — draw (size, iat) together and stash the IAT for
        // the paired sample_iat call so their correlation survives on the wire.
        if let Some(ref joint) = self.mask.size_iat_joint {
            let (size, iat) = joint.sample(&mut self.rng);
            self.state.pending_joint_iat = Some(iat);
            return size;
        }
        if let Some(ref d) = self.state.size_override {
            d.sample(&mut self.rng)
        } else {
            self.mask.size_distribution.sample(&mut self.rng)
        }
    }

    pub fn sample_iat(&mut self) -> f64 {
        // R3: consume the IAT paired with the most recent joint size sample.
        if let Some(iat) = self.state.pending_joint_iat.take() {
            return iat;
        }
        if let Some(ref d) = self.state.iat_override {
            d.sample(&mut self.rng)
        } else {
            self.mask.iat_distribution.sample(&mut self.rng)
        }
    }

    pub fn calc_padding(&mut self, payload_size: usize, target_size: u16) -> u16 {
        let strategy = self
            .state
            .padding_override
            .as_ref()
            .unwrap_or(&self.mask.padding_strategy);
        strategy.calc_padding(payload_size, target_size, &mut self.rng)
    }

    pub async fn apply_timing(&mut self) {
        let iat_ms = self.sample_iat();
        if iat_ms > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(iat_ms / 1000.0)).await;
        }
    }

    pub fn update_fsm(&mut self) {
        let duration_ms = self.state.state_start.elapsed().as_millis() as u64;
        let (new_state, size_override, iat_override, padding_override) =
            self.mask.process_transition(
                self.state.current_state,
                self.state.packets_in_state,
                duration_ms,
            );
        if new_state != self.state.current_state {
            debug!(
                "FSM transition: {} -> {}",
                self.state.current_state, new_state
            );
            self.state.current_state = new_state;
            self.state.packets_in_state = 0;
            self.state.state_start = Instant::now();
            self.state.size_override = size_override;
            self.state.iat_override = iat_override;
            self.state.padding_override = padding_override;
        }
        self.state.packets_in_state += 1;
    }

    pub fn build_mdh(&mut self, eph_pub: Option<&[u8; 32]>) -> Vec<u8> {
        let mut mdh = if let Some(ref spec) = self.mask.header_spec {
            spec.generate(&mut self.rng)
        } else {
            self.mask.header_template.clone()
        };
        if let Some(eph) = eph_pub {
            let offset = self.mask.eph_pub_offset as usize;
            let len = self.mask.eph_pub_length as usize;
            let required = offset + len;
            if mdh.len() < required {
                mdh.resize(required, 0);
            }
            // `eph` is always 32 bytes. A malformed/pushed mask may declare an
            // eph_pub_length other than 32; copy_from_slice would then panic on
            // the length mismatch. Copy only the overlapping bytes so a bad mask
            // can never crash the handshake path (len == 32 stays identical).
            let copy_len = len.min(eph.len());
            mdh[offset..offset + copy_len].copy_from_slice(&eph[..copy_len]);
        }
        mdh
    }

    pub fn build_packet(
        &mut self,
        plaintext: &[u8],
        keys: &SessionKeys,
        counter: &mut u64,
        eph_pub: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>> {
        let mut mdh = self.build_mdh(eph_pub);

        // Variant A wire-layout selection. A new-layout mask (`tag_offset != u16::MAX`)
        // presents a real protocol header at packet offset 0 and hides the 8-byte
        // resonance tag INSIDE that header, so there is no separate tag prefix.
        // We only take the embedded path when the header is long enough to hold
        // the tag AND the tag slot does not overlap the embedded ephemeral key;
        // a malformed mask falls back to the byte-identical legacy layout.
        // Embedded-vs-legacy decision goes through the shared MaskProfile method
        // so the server decoder computes the identical ciphertext offset (see
        // `MaskProfile::uses_embedded_layout`).
        let embed_tag_offset = if self.mask.uses_embedded_layout(mdh.len()) {
            self.mask.embedded_tag_offset()
        } else {
            if let Some(off) = self.mask.embedded_tag_offset() {
                debug!(
                    "mask {} has malformed tag_offset {} (header len {}, eph_pub {}..{}); \
                     falling back to legacy tag-prefix layout",
                    self.mask.mask_id,
                    off,
                    mdh.len(),
                    self.mask.eph_pub_offset,
                    self.mask.eph_pub_offset as usize + self.mask.eph_pub_length as usize,
                );
            }
            None
        };
        // Legacy layout carries an extra TAG_SIZE prefix; the embedded layout does not.
        let tag_prefix_len = if embed_tag_offset.is_some() {
            0
        } else {
            TAG_SIZE
        };

        let target_size = self.sample_packet_size();
        let base_overhead = tag_prefix_len + mdh.len() + 2 + plaintext.len() + POLY1305_TAG_SIZE;
        let requested_pad_len = self.calc_padding(base_overhead, target_size);
        let packet_budget = SAFE_OUTER_PACKET_BUDGET.min(MAX_PACKET_SIZE);

        // Budget correction for *constructed* (QUIC) masks. A QUIC DATA packet
        // (`eph_pub` is None → the `proto.emit()` path below is taken) is NOT
        // emitted as `[mdh][ciphertext]`: `emit()` discards the mdh and wraps the
        // ciphertext in a whole RFC 9001 Initial, adding `quic_initial_overhead()`
        // (~92 B: long header + CRYPTO(ClientHello) frame + AEAD tag) ON TOP.
        // `base_overhead` (sized for `[mdh][ciphertext]`) never reserved those
        // bytes, so a near-MTU QUIC packet could pad up to `packet_budget` and
        // then overflow it by the Initial overhead after `emit()` → fragmentation
        // (and a DPI anomaly, since real QUIC does PMTUD). Reserve the Initial
        // overhead here so the FINAL emitted datagram — not the pre-wrap packet —
        // stays within `packet_budget`. The final QUIC datagram size (before the
        // 1200-byte QUIC floor) is `quic_overhead + ciphertext_len`, where
        // `ciphertext_len = 2 + plaintext.len() + pad_len + POLY1305_TAG_SIZE`;
        // solving `<= packet_budget` for `pad_len` gives this reserved overhead.
        let emits_quic = eph_pub.is_none()
            && MimicProtocol::for_spoof(self.mask.spoof_protocol).is_constructed();
        let budget_overhead = if emits_quic {
            crate::quic_initial::quic_initial_overhead() + 2 + plaintext.len() + POLY1305_TAG_SIZE
        } else {
            base_overhead
        };
        let max_pad_len = packet_budget.saturating_sub(budget_overhead) as u16;
        let pad_len = requested_pad_len.min(max_pad_len);

        let mut padded = Vec::with_capacity(2 + plaintext.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(plaintext);
        padded.resize(2 + plaintext.len() + pad_len as usize, 0);
        self.rng.fill_bytes(&mut padded[2 + plaintext.len()..]);

        // Increment counter BEFORE encryption so a failed encrypt_payload call
        // never allows the same nonce to be reused with the same session key
        // (nonce-reuse would break ChaCha20-Poly1305 confidentiality).
        let packet_counter = *counter;
        *counter += 1;
        let nonce = self.generate_nonce(packet_counter);
        let ciphertext = encrypt_payload(&keys.session_key, &nonce, &padded)?;

        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            crate::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&keys.tag_secret, packet_counter, time_window);

        // Constructed protocols (QUIC) build the WHOLE datagram from the tag +
        // ciphertext (a crypto-built decoy header coalesced with aivpn's real
        // ciphertext), bypassing the `[mdh][ciphertext]` + finalize layout. The
        // resonance tag rides inside the decoy header (QUIC: the DCID), so the
        // server extracts it there and skips the decoy to reach the ciphertext.
        //
        // Only DATA packets take this path: a handshake packet (`eph_pub` set)
        // must carry the obfuscated ephemeral key inside the MDH for the server
        // to establish the session, so it keeps the standard layout. The flow
        // still classifies as QUIC because steady-state data packets are valid
        // RFC 9001 Initials (nDPI's `may_be_initial_pkt` runs per packet).
        let proto = MimicProtocol::for_spoof(self.mask.spoof_protocol);
        if eph_pub.is_none() {
            if let Some(datagram) = proto.emit(&tag, &ciphertext) {
                return Ok(datagram);
            }
        }

        let mut packet = Vec::with_capacity(tag_prefix_len + mdh.len() + ciphertext.len());
        if let Some(off) = embed_tag_offset {
            // New layout: real protocol header at offset 0 with the tag embedded
            // into its opaque carrier field; no separate tag prefix.
            mdh[off..off + TAG_SIZE].copy_from_slice(&tag);
            packet.extend_from_slice(&mdh);
            packet.extend_from_slice(&ciphertext);
            // Protocol-specific post-assembly DPI fixup: now that the full
            // `[mdh][ciphertext]` size is known, let the mimicked protocol
            // reconcile any size-dependent consistency field. For STUN this
            // patches the Length field to `packet_len - 20` (nDPI's `is_stun()`
            // demands the exact `msg_len + 20 == udp_payload_len`); other
            // protocols are a no-op for now. Mirrors the tag embed just above.
            proto.finalize(&mut packet, &self.mask);
        } else {
            // Legacy layout: tag ++ mdh ++ ciphertext (byte-identical to before).
            packet.extend_from_slice(&tag);
            packet.extend_from_slice(&mdh);
            packet.extend_from_slice(&ciphertext);
        }
        Ok(packet)
    }

    fn generate_nonce(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    pub fn spoof_protocol(&self) -> SpoofProtocol {
        self.mask.spoof_protocol
    }
}

// ──────────── MimicryEncryptor ────────────
//
// Self-contained PacketEncryptor that owns SessionKeys + counter/seq + MimicryEngine.
// Designed for mobile cores (iOS, Android) which cannot share UploadCryptoState via Arc<Mutex<>>.
// pending_mask receives server MaskUpdate payloads from the control-message handler and is
// applied before the next data packet is encrypted.

pub struct MimicryEncryptor {
    engine: MimicryEngine,
    keys: SessionKeys,
    counter: u64,
    seq: u16,
    /// Written by the control-message handler; consumed on next encrypt call.
    pub pending_mask: Arc<Mutex<Option<MaskProfile>>>,
    fec_encoder: Option<FecEncoder>,
    pending_fec: Option<Vec<u8>>,
}

impl MimicryEncryptor {
    pub fn new(
        keys: SessionKeys,
        counter: u64,
        seq: u16,
        mask: MaskProfile,
        pending_mask: Arc<Mutex<Option<MaskProfile>>>,
    ) -> Self {
        Self {
            engine: MimicryEngine::new(mask),
            keys,
            counter,
            seq,
            pending_mask,
            fec_encoder: None,
            pending_fec: None,
        }
    }

    /// Replaces the session keys used by this encryptor, keeping the packet
    /// counter MONOTONIC. Called by the mobile inline-rekey handler (via
    /// `check_key_rotation`, only ever fed from the KeyRotate path — a full
    /// reconnect builds a fresh encryptor instead). The uplink (c2s) counter must
    /// NOT reset to 0 here: the server matches inbound tags in a ±TAG_WINDOW_SIZE
    /// band around the highest received counter, so a from-zero restart under a
    /// heavy simultaneous upload (first c2s packets lost, client racing past the
    /// band) strands uplink — killing the tunnel. The key changes, so continuing
    /// the counter never reuses a (key, nonce) pair.
    pub fn update_keys(&mut self, keys: SessionKeys) {
        self.keys = keys;
    }

    pub fn set_fec_group(&mut self, group_size: u8) {
        self.fec_encoder = if group_size > 0 {
            Some(FecEncoder::new(group_size, 1500))
        } else {
            None
        };
    }

    fn check_mask(&mut self) {
        if let Some(mask) = self
            .pending_mask
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            self.engine.update_mask(mask);
        }
    }
}

impl PacketEncryptor for MimicryEncryptor {
    fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.check_mask();
        let inner = build_inner_packet(InnerType::Data, self.seq, payload);
        self.seq = self.seq.wrapping_add(1);
        let pkt = self
            .engine
            .build_packet(&inner, &self.keys, &mut self.counter, None)?;
        self.engine.update_fsm();
        if let Some(fec) = self.fec_encoder.as_mut() {
            if let Some(repair) = fec.feed(payload) {
                let repair_inner =
                    build_inner_packet(InnerType::FecRepair, self.seq, &repair.encode());
                self.seq = self.seq.wrapping_add(1);
                if let Ok(enc) =
                    self.engine
                        .build_packet(&repair_inner, &self.keys, &mut self.counter, None)
                {
                    self.pending_fec = Some(enc);
                }
            }
        }
        Ok(pkt)
    }

    fn encrypt_control(&mut self, payload: &ControlPayload) -> Result<Vec<u8>> {
        self.check_mask();
        let bytes = payload.encode()?;
        let inner = build_inner_packet(InnerType::Control, self.seq, &bytes);
        self.seq = self.seq.wrapping_add(1);
        self.engine
            .build_packet(&inner, &self.keys, &mut self.counter, None)
    }

    /// Sends `send_ts: 0` — server echoes 0, so RTT cannot be measured from the KeepaliveAck.
    /// Use `encrypt_keepalive_ts(current_timestamp_ms())` when RTT tracking is needed.
    fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
        self.encrypt_keepalive_ts(0)
    }

    fn encrypt_keepalive_ts(&mut self, send_ts: u64) -> Result<Vec<u8>> {
        let payload = ControlPayload::Keepalive { send_ts };
        let bytes = payload.encode()?;
        let inner = build_inner_packet(InnerType::Control, self.seq, &bytes);
        self.seq = self.seq.wrapping_add(1);
        self.engine
            .build_packet(&inner, &self.keys, &mut self.counter, None)
    }

    fn on_data_sent(&mut self, _payload_len: usize) {}

    fn take_fec_repair(&mut self) -> Option<Vec<u8>> {
        self.pending_fec.take()
    }
}

/// Decode a MaskProfile from the raw bytes of a `ControlPayload::MaskUpdate` payload.
/// Returns `None` if deserialization fails (malformed or unknown format).
pub fn decode_mask_update(mask_data: &[u8]) -> Option<MaskProfile> {
    rmp_serde::from_slice::<MaskProfile>(mask_data).ok()
}

/// Derive the bootstrap mask from PSK so iOS/Android start with mimicry active
/// before the server sends a MaskUpdate.
pub fn bootstrap_mask_for_psk(psk: Option<&[u8; 32]>) -> MaskProfile {
    let presets = crate::mask::preset_masks::all();
    debug_assert!(!presets.is_empty(), "preset_masks::all() must not be empty");
    if presets.is_empty() {
        return crate::mask::preset_masks::bootstrap_default();
    }
    if let Some(key) = psk {
        let hash = blake3::derive_key("aivpn-bootstrap-mask-v1", key);
        let idx = hash[0] as usize % presets.len();
        presets[idx].clone()
    } else {
        presets[0].clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::preset_masks::webrtc_zoom_v3;

    #[test]
    fn test_mimicry_engine_builds_packet() {
        let mask = webrtc_zoom_v3();
        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [0u8; 32],
            session_key_s2c: [0u8; 32],
            tag_secret: [0u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        let packet = engine.build_packet(b"Hello, World!", &keys, &mut counter, None);
        assert!(packet.is_ok());
        assert_eq!(counter, 1);
    }

    #[test]
    fn build_mdh_with_non32_eph_pub_length_does_not_panic() {
        // A mask that declares eph_pub_length != 32 must not panic build_mdh
        // when an ephemeral key is embedded during the handshake.
        let mut mask = webrtc_zoom_v3();
        mask.eph_pub_length = 16; // malformed / adversarial value
        mask.eph_pub_offset = 4;
        mask.header_spec = None;
        mask.header_template = vec![0u8; 4];
        let mut engine = MimicryEngine::new(mask);
        let mdh = engine.build_mdh(Some(&[0xABu8; 32]));
        assert!(mdh.len() >= 4 + 16);
    }

    #[test]
    fn build_mdh_with_oversized_eph_pub_length_does_not_panic() {
        let mut mask = webrtc_zoom_v3();
        mask.eph_pub_length = 64; // larger than the 32-byte key
        mask.eph_pub_offset = 4;
        mask.header_spec = None;
        mask.header_template = vec![0u8; 4];
        let mut engine = MimicryEngine::new(mask);
        let mdh = engine.build_mdh(Some(&[0xCDu8; 32]));
        assert!(mdh.len() >= 4 + 64);
        // First 32 embedded bytes are the key; the declared-but-unused tail is zero.
        assert_eq!(&mdh[4..4 + 32], &[0xCDu8; 32]);
        assert_eq!(&mdh[4 + 32..4 + 64], &[0u8; 32]);
    }

    #[test]
    fn embedded_stun_packet_roundtrips_and_shows_magic_cookie() {
        use crate::client_wire::{decode_packet_with_layout, RecvWindow};
        use crate::crypto::{
            compute_time_window, current_timestamp_ms, generate_resonance_tag, DEFAULT_WINDOW_MS,
        };
        use crate::protocol::InnerType;

        let mask = webrtc_zoom_v3();
        let tag_offset = mask.tag_offset;
        assert_eq!(tag_offset, 8);
        let mdh_len = mask.header_spec.as_ref().unwrap().min_length();
        assert_eq!(mdh_len, 20);

        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [7u8; 32],
            session_key_s2c: [7u8; 32],
            tag_secret: [9u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        let inner = build_inner_packet(InnerType::Data, 0, b"payload-abc");
        let pkt = engine
            .build_packet(&inner, &keys, &mut counter, None)
            .unwrap();

        // (b) Real STUN discriminator: magic cookie 0x2112A442 at packet offset 4.
        assert_eq!(&pkt[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        // Message type is STUN Binding Request at offset 0.
        assert_eq!(&pkt[0..2], &[0x00, 0x01]);

        // (c) Tag embedded at packet offset tag_offset (inside the transaction id).
        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected = generate_resonance_tag(&keys.tag_secret, 0, tw);
        assert_eq!(
            &pkt[tag_offset as usize..tag_offset as usize + TAG_SIZE],
            &expected
        );

        // (a) Round-trip: decode recovers the SAME tag (counter) and inner payload.
        let mut win = RecvWindow::new();
        let decoded =
            decode_packet_with_layout(&pkt, &keys, &mut win, mdh_len, tag_offset).unwrap();
        assert_eq!(decoded.counter, 0);
        assert_eq!(decoded.payload, b"payload-abc");
    }

    #[test]
    fn embedded_quic_packet_roundtrips_and_shows_long_header() {
        use crate::client_wire::{decode_packet_with_layout, RecvWindow};
        use crate::mask::preset_masks::quic_https_v2;
        use crate::protocol::InnerType;

        let mask = quic_https_v2();
        let tag_offset = mask.tag_offset;
        assert_eq!(tag_offset, 6);

        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [1u8; 32],
            session_key_s2c: [1u8; 32],
            tag_secret: [2u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        let inner = build_inner_packet(InnerType::Data, 0, b"quic-inner");
        let pkt = engine
            .build_packet(&inner, &keys, &mut counter, None)
            .unwrap();

        // (b) QUIC v1 long-header discriminator: long-header Initial form in the
        // high nibble (0xC = header-form + fixed-bit + Initial type), and
        // version 0x00000001. Only the high nibble is asserted: RFC 9001 §5.4.1
        // header protection masks the 4 LOW bits of the first byte (reserved +
        // packet-number length), so they vary per packet — asserting the full
        // 0xC0 byte was nondeterministic.
        assert_eq!(pkt[0] & 0xf0, 0xc0);
        assert_eq!(&pkt[1..5], &[0x00, 0x00, 0x00, 0x01]);
        // DCID length byte.
        assert_eq!(pkt[5], 8);

        // Round-trip: a QUIC data packet is a coalesced RFC 9001 Initial with
        // aivpn's ciphertext appended after it, so decode via the Initial parser
        // (as the server does) to locate the trailing payload, then decrypt it.
        // The resonance tag sits in the DCID at `tag_offset`.
        let layout = crate::quic_initial::parse_quic_initial(&pkt).expect("valid QUIC Initial");
        assert_eq!(
            &layout.tag[..],
            &pkt[tag_offset as usize..tag_offset as usize + 8]
        );
        let mut win = RecvWindow::new();
        let decoded =
            decode_packet_with_layout(&pkt, &keys, &mut win, layout.payload_offset, tag_offset)
                .unwrap();
        assert_eq!(decoded.payload, b"quic-inner");
    }

    #[test]
    fn legacy_mask_still_prefixes_tag() {
        use crate::client_wire::{decode_packet_with_mdh_len, RecvWindow};
        use crate::crypto::{
            compute_time_window, current_timestamp_ms, generate_resonance_tag, DEFAULT_WINDOW_MS,
        };
        use crate::protocol::InnerType;

        // Force the legacy sentinel on an otherwise-STUN mask: the packet must
        // revert to the byte-identical old layout (tag prefix at offset 0).
        let mut mask = webrtc_zoom_v3();
        mask.tag_offset = u16::MAX;
        let mdh_len = mask.header_spec.as_ref().unwrap().min_length();

        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [3u8; 32],
            session_key_s2c: [3u8; 32],
            tag_secret: [4u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        let inner = build_inner_packet(InnerType::Data, 0, b"legacy");
        let pkt = engine
            .build_packet(&inner, &keys, &mut counter, None)
            .unwrap();

        // Tag is the prefix at offset 0, header (STUN type) shifted to offset 8.
        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected = generate_resonance_tag(&keys.tag_secret, 0, tw);
        assert_eq!(&pkt[0..TAG_SIZE], &expected);
        assert_eq!(&pkt[TAG_SIZE..TAG_SIZE + 2], &[0x00, 0x01]);

        let mut win = RecvWindow::new();
        let decoded = decode_packet_with_mdh_len(&pkt, &keys, &mut win, mdh_len).unwrap();
        assert_eq!(decoded.payload, b"legacy");
    }

    #[test]
    fn overlapping_tag_and_eph_falls_back_to_legacy() {
        use crate::client_wire::{decode_packet_with_mdh_len, RecvWindow};
        use crate::protocol::InnerType;

        // Malformed mask: tag slot [8,16) overlaps eph_pub slot [10,42).
        // build_packet must fall back to the legacy tag-prefix layout so the
        // embedded key is never corrupted.
        let mut mask = webrtc_zoom_v3();
        mask.tag_offset = 8;
        mask.eph_pub_offset = 10;
        mask.eph_pub_length = 32;
        assert!(mask.tag_overlaps_eph_pub(TAG_SIZE));

        let mdh_len = mask.header_spec.as_ref().unwrap().min_length();
        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [5u8; 32],
            session_key_s2c: [5u8; 32],
            tag_secret: [6u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        let inner = build_inner_packet(InnerType::Data, 0, b"fallback");
        // eph_pub is None here, so the header is exactly mdh_len; the legacy
        // decoder must recover the payload (tag prefixed at offset 0).
        let pkt = engine
            .build_packet(&inner, &keys, &mut counter, None)
            .unwrap();
        let mut win = RecvWindow::new();
        let decoded = decode_packet_with_mdh_len(&pkt, &keys, &mut win, mdh_len).unwrap();
        assert_eq!(decoded.payload, b"fallback");
    }

    #[test]
    fn embedded_stun_packet_length_field_matches_ndpi_is_stun() {
        // nDPI's is_stun() requires EXACTLY `msg_len + 20 == udp_payload_len`
        // (STUN header is 20 bytes). Assert the built webrtc_zoom_v3 packet's
        // message-length field (bytes[2..4], big-endian) satisfies that for a
        // range of packet sizes, and that the magic cookie / type stay correct.
        let mask = webrtc_zoom_v3();
        assert_eq!(mask.stun_length_field_offset(), Some(2));
        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [7u8; 32],
            session_key_s2c: [7u8; 32],
            tag_secret: [9u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        // Several plaintext sizes → several distinct packet sizes.
        for chunk_len in [1usize, 16, 64, 128, 256, 512, 900, 1100, 1300] {
            let payload = vec![0x41u8; chunk_len];
            let inner = build_inner_packet(InnerType::Data, 0, &payload);
            let pkt = engine
                .build_packet(&inner, &keys, &mut counter, None)
                .unwrap();
            // STUN header must sit at offset 0: type + magic cookie intact.
            assert_eq!(&pkt[0..2], &[0x00, 0x01], "STUN type at offset 0");
            assert_eq!(
                &pkt[4..8],
                &[0x21, 0x12, 0xA4, 0x42],
                "STUN magic cookie at offset 4"
            );
            // The exact nDPI is_stun() condition.
            let msg_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            assert_eq!(
                msg_len + 20,
                pkt.len(),
                "msg_len({}) + 20 must equal packet len ({}) for chunk_len {}",
                msg_len,
                pkt.len(),
                chunk_len
            );
        }
    }

    #[test]
    fn legacy_stun_layout_does_not_patch_length_over_tag() {
        // In the legacy tag-prefix layout the STUN header is shifted past the
        // 8-byte tag; patch_stun_length must NOT run (it would corrupt the tag).
        // The packet still round-trips, proving the length patch stayed clear.
        use crate::client_wire::{decode_packet_with_mdh_len, RecvWindow};
        let mut mask = webrtc_zoom_v3();
        mask.tag_offset = u16::MAX;
        let mdh_len = mask.header_spec.as_ref().unwrap().min_length();
        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [3u8; 32],
            session_key_s2c: [3u8; 32],
            tag_secret: [4u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        let inner = build_inner_packet(InnerType::Data, 0, b"legacy-len");
        let pkt = engine
            .build_packet(&inner, &keys, &mut counter, None)
            .unwrap();
        let mut win = RecvWindow::new();
        let decoded = decode_packet_with_mdh_len(&pkt, &keys, &mut win, mdh_len).unwrap();
        assert_eq!(decoded.payload, b"legacy-len");
    }

    #[test]
    fn quic_data_packet_stays_within_wan_budget() {
        // FIX 1: a QUIC DATA packet is re-wrapped by emit() into a full RFC 9001
        // Initial (adding ~92 B on top of the ciphertext). The mimicry engine
        // must reserve that overhead so the FINAL emitted datagram never exceeds
        // the WAN-safe budget — even when padding tries to fill toward the
        // sampled target size. Loop many times per size because the padding is
        // randomized (without the reservation, some iterations pad the pre-emit
        // packet up to ~1380 and then overflow to ~1472 after emit()).
        use crate::mask::preset_masks::quic_https_v2;
        let mask = quic_https_v2();
        assert_eq!(
            MimicProtocol::for_spoof(mask.spoof_protocol),
            MimicProtocol::Quic
        );
        let mut engine = MimicryEngine::new(mask);
        let keys = SessionKeys {
            session_key: [1u8; 32],
            session_key_s2c: [1u8; 32],
            tag_secret: [2u8; 32],
            prng_seed: [0u8; 32],
        };
        let mut counter = 0u64;
        // Payloads that leave padding headroom (<= ~1266 so a zero-pad Initial
        // still fits the SAFE budget). The fix guarantees padding never pushes
        // the final datagram past the budget for these.
        for payload_len in [1usize, 64, 256, 700, 1000, 1200, 1264] {
            for _ in 0..40 {
                let inner = build_inner_packet(InnerType::Data, 0, &vec![0x42u8; payload_len]);
                let pkt = engine
                    .build_packet(&inner, &keys, &mut counter, None)
                    .unwrap();
                engine.update_fsm();
                // Confirm the QUIC emit() path actually ran (long-header Initial).
                assert_eq!(pkt[0] & 0xf0, 0xc0, "expected a QUIC Initial datagram");
                assert!(
                    pkt.len() <= MAX_PACKET_SIZE,
                    "QUIC datagram {} exceeds MAX_PACKET_SIZE for payload {}",
                    pkt.len(),
                    payload_len
                );
                assert!(
                    pkt.len() <= SAFE_OUTER_PACKET_BUDGET,
                    "QUIC datagram {} exceeds SAFE_OUTER_PACKET_BUDGET for payload {}",
                    pkt.len(),
                    payload_len
                );
            }
        }
    }

    #[test]
    fn test_mimicry_encryptor_data() {
        let mask = webrtc_zoom_v3();
        let keys = SessionKeys {
            session_key: [0u8; 32],
            session_key_s2c: [0u8; 32],
            tag_secret: [0u8; 32],
            prng_seed: [0u8; 32],
        };
        let pending = Arc::new(Mutex::new(None));
        let mut enc = MimicryEncryptor::new(keys, 0, 0, mask, pending);
        assert!(enc.encrypt_data(b"test payload").is_ok());
    }
}
