//! Mask catalog for automatic rotation (Patent 3 + Patent 9), plus the
//! free mask-wire-layout helper functions that operate on `MaskProfile`
//! without needing a `Gateway`/catalog instance.

use dashmap::DashMap;
use std::time::{Duration, Instant};

use aivpn_common::crypto::TAG_SIZE;
use aivpn_common::mask::MaskProfile;

/// Mask catalog for automatic rotation (Patent 3 + Patent 9)
///
/// Holds a pool of pre-generated masks. When neural resonance detects
/// that a mask is compromised by DPI, the catalog provides a replacement.
pub struct MaskCatalog {
    /// Available masks (mask_id → MaskProfile)
    ///
    /// `pub(crate)` (not private) so `Gateway::distinct_tag_offsets`'s hot
    /// path (in `gateway/mod.rs`) can iterate it directly without an extra
    /// wrapper method — mirrors the pre-move same-file field access.
    pub(crate) masks: DashMap<String, MaskProfile>,
    /// Compromised masks, keyed by mask_id, holding the time they were
    /// compromised AND the profile itself (H1: retained so
    /// `sweep_expired_compromised` can restore it to `masks` after
    /// `COMPROMISED_TTL` — a mask flagged compromised is not necessarily
    /// compromised forever, and an operator running a small/single-mask
    /// deployment must eventually regain a usable mask rather than being
    /// permanently locked out of new handshakes).
    compromised: DashMap<String, (Instant, MaskProfile)>,
    /// Primary mask used for initial handshake parsing.
    primary_mask_id: parking_lot::Mutex<String>,
}

/// H1: how long a mask stays excluded from rotation after being marked
/// compromised, before `sweep_expired_compromised` gives it another chance.
/// Generous — this is a last-resort backstop against total lockout, not a
/// substitute for the DPI/anomaly detectors' own judgement.
const COMPROMISED_TTL: Duration = Duration::from_secs(3600);

impl MaskCatalog {
    pub fn new() -> Self {
        Self {
            masks: DashMap::new(),
            compromised: DashMap::new(),
            primary_mask_id: parking_lot::Mutex::new(String::new()),
        }
    }

    /// Set the primary mask ID (first mask loaded from disk)
    pub fn set_primary_mask_id(&self, mask_id: String) {
        *self.primary_mask_id.lock() = mask_id;
    }

    /// Register a new mask (e.g., received via passive distribution or neural unpack)
    pub fn register_mask(&self, mask: MaskProfile) {
        if !self.compromised.contains_key(&mask.mask_id) {
            self.masks.insert(mask.mask_id.clone(), mask);
        }
    }

    /// H1: mark `mask_id` compromised and hand back the fallback to switch
    /// to — but ONLY if compromising it actually leaves a usable mask
    /// behind. `select_fallback` is checked BEFORE any removal happens: the
    /// old code removed first and checked after, so tripping the last (or
    /// only) mask emptied the catalog and permanently locked out every
    /// future handshake (`primary_mask()` → `None`), while existing
    /// sessions kept working and masked the failure until their next
    /// reconnect. Refusing the compromise when there is nowhere to fall
    /// back to trades "one bad mask stays in rotation a bit longer" for
    /// "the server never goes fully deaf" — `sweep_expired_compromised`
    /// still gives previously-compromised masks a second chance after
    /// `COMPROMISED_TTL`, including ones that were skipped here.
    pub fn mark_compromised_with_fallback(&self, mask_id: &str) -> Option<MaskProfile> {
        let fallback = self.select_fallback(mask_id)?;
        if let Some(mask) = self.masks.get(mask_id).map(|e| e.value().clone()) {
            self.compromised
                .insert(mask_id.to_string(), (Instant::now(), mask));
        }
        self.masks.remove(mask_id);
        Some(fallback)
    }

    /// H1 TTL backstop: give previously-compromised masks another chance
    /// after `COMPROMISED_TTL` by moving them back into the live rotation.
    /// Restoring the actual retained `MaskProfile` (not just clearing the
    /// compromised flag) means this works even for masks that were never
    /// reloadable from disk (e.g. neural-unpacked or passively-distributed).
    pub fn sweep_expired_compromised(&self) {
        let expired: Vec<(String, MaskProfile)> = self
            .compromised
            .iter()
            .filter(|e| e.value().0.elapsed() >= COMPROMISED_TTL)
            .map(|e| (e.key().clone(), e.value().1.clone()))
            .collect();
        for (mask_id, mask) in expired {
            self.compromised.remove(&mask_id);
            self.masks.insert(mask_id, mask);
        }
    }

    /// Remove a mask from live rotation without marking it as compromised.
    pub fn remove_mask(&self, mask_id: &str) {
        self.masks.remove(mask_id);
    }

    /// Select the best non-compromised mask, excluding `current_mask_id`
    pub fn select_fallback(&self, current_mask_id: &str) -> Option<MaskProfile> {
        self.masks
            .iter()
            .filter(|e| e.key() != current_mask_id)
            .map(|e| e.value().clone())
            .next()
    }

    /// Get mask count
    pub fn available_count(&self) -> usize {
        self.masks.len()
    }

    /// Get the primary packet layout for client->server traffic.
    /// Returns `(packet_mdh_len, handshake_mdh_len, eph_offset, eph_len)`.
    /// Normal packets use only the protocol header, while the initial
    /// handshake embeds `eph_pub` inside the MDH at `eph_offset`.
    pub fn packet_layout(&self) -> (usize, usize, usize, usize) {
        let fallback = (20usize, 52usize, 20usize, 32usize);
        let Some(mask) = self.primary_mask() else {
            return fallback;
        };

        packet_layout_for_mask(&mask)
    }

    /// Get the regular MDH bytes used for server->client packets.
    /// Uses HeaderSpec for dynamic per-packet generation when available (Issue #30 fix).
    pub fn packet_mdh_bytes(&self) -> Vec<u8> {
        self.primary_mask()
            .map(|mask| packet_mdh_bytes_for_mask(&mask))
            .unwrap_or_else(|| vec![0u8; 20])
    }

    pub fn primary_mask(&self) -> Option<MaskProfile> {
        let primary_id = self.primary_mask_id.lock().clone();
        self.masks
            .get(&primary_id)
            .map(|entry| entry.value().clone())
            .or_else(|| {
                // Deterministic fallback: smallest mask_id. `DashMap::iter()
                // .next()` depends on hash/shard order, so two nodes (or two
                // runs) with the same mask set could disagree on the primary
                // mask — and with it on every layout derived from it.
                self.masks
                    .iter()
                    .min_by(|a, b| a.key().cmp(b.key()))
                    .map(|entry| entry.value().clone())
            })
    }
}

pub(crate) fn packet_layout_for_mask(mask: &MaskProfile) -> (usize, usize, usize, usize) {
    let eph_offset = mask.eph_pub_offset as usize;
    let eph_len = mask.eph_pub_length as usize;
    let packet_mdh_len = mask
        .header_spec
        .as_ref()
        .map(|spec| spec.min_length())
        .unwrap_or_else(|| mask.header_template.len());
    let handshake_mdh_len = packet_mdh_len.max(eph_offset.saturating_add(eph_len));
    (packet_mdh_len, handshake_mdh_len, eph_offset, eph_len)
}

pub(crate) fn packet_mdh_bytes_for_mask(mask: &MaskProfile) -> Vec<u8> {
    if let Some(ref spec) = mask.header_spec {
        let mut rng = rand::thread_rng();
        spec.generate(&mut rng)
    } else {
        mask.header_template.clone()
    }
}

/// Byte length of the legacy tag prefix for a given mask wire layout
/// (Variant A DPI fix). See [`aivpn_common::mask::MaskProfile::tag_offset`].
///
/// * Legacy (`u16::MAX`): the 8-byte resonance tag is a separate prefix at
///   packet offset 0, so the real protocol header and the ciphertext start
///   `TAG_SIZE` bytes into the packet.
/// * Embedded (`N`): the tag hides INSIDE the header at byte offset `N` and
///   there is NO separate prefix, so the header sits at packet offset 0 and the
///   ciphertext starts right after the MDH.
pub(crate) fn tag_prefix_len(tag_offset: u16) -> usize {
    if tag_offset == u16::MAX {
        TAG_SIZE
    } else {
        0
    }
}

/// Extract up to 16 bytes of the L7 (transport-payload) prefix from a
/// *decrypted* inner IP packet, for auto-mask header learning.
///
/// The recording→mask_gen pipeline (`detect_mimic_protocol`,
/// `infer_header_spec`) keys off the cleartext application header — the STUN
/// magic cookie at offset 4, the QUIC long-header bits at offset 0, the DNS
/// header — which lives in the UDP/TCP payload of the tunnelled packet, NOT
/// in the encrypted AIVPN wire framing. Recording the raw ciphertext prefix
/// instead (as the code originally did) yields near-random bytes, so
/// `infer_header_spec` finds no constant positions and the self-test
/// `header_match` gate rejects every mask built from a real tunnel capture.
///
/// Returns an empty vec for non-IPv4 / non-UDP-TCP / truncated packets, which
/// then simply contribute no constant bytes to the inferred header spec.
pub(crate) fn inner_l7_prefix(ip: &[u8]) -> Vec<u8> {
    // IPv4 data plane only. (An IPv6 inner packet, if ever tunnelled, would
    // need the fixed-40-byte v6 header path added here.)
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return Vec::new();
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return Vec::new();
    }
    let l7_off = match ip[9] {
        17 => ihl + 8, // UDP: fixed 8-byte header
        6 => {
            // TCP: data offset = high nibble of byte 12, in 32-bit words.
            match ip.get(ihl..) {
                Some(tcp) if tcp.len() >= 13 => ihl + ((tcp[12] >> 4) as usize) * 4,
                _ => return Vec::new(),
            }
        }
        _ => return Vec::new(),
    };
    match ip.get(l7_off..) {
        Some(l7) => l7[..l7.len().min(16)].to_vec(),
        None => Vec::new(),
    }
}

/// Packet byte offset at which the resonance tag lives for a given layout:
/// 0 for the legacy tag-prefixed layout, `N` for an embedded-tag mask.
pub(crate) fn tag_byte_offset(tag_offset: u16) -> usize {
    if tag_offset == u16::MAX {
        0
    } else {
        tag_offset as usize
    }
}

/// Extract the 8-byte resonance tag from `packet` at the position dictated by
/// `tag_offset`'s layout, or `None` if the packet is too short to hold it.
pub(crate) fn extract_tag_for_layout(packet: &[u8], tag_offset: u16) -> Option<[u8; TAG_SIZE]> {
    let off = tag_byte_offset(tag_offset);
    let end = off.checked_add(TAG_SIZE)?;
    if packet.len() < end {
        return None;
    }
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&packet[off..end]);
    Some(tag)
}

/// Distinct packet byte offsets where an incoming resonance tag may live, given
/// the set of currently-relevant masks. Always includes 0 (legacy tag-prefix /
/// fast path) and adds each embedded mask's `tag_offset`. Bounded and tiny in
/// practice (the presets contribute at most 2 distinct embedded offsets).
pub(crate) fn distinct_tag_offsets_of<'a>(
    masks: impl Iterator<Item = &'a MaskProfile>,
) -> Vec<usize> {
    let mut offsets = vec![0usize];
    for mask in masks {
        if let Some(off) = mask.embedded_tag_offset() {
            if !offsets.contains(&off) {
                offsets.push(off);
            }
        }
    }
    offsets
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::mask::preset_masks::webrtc_zoom_v3;

    /// H1 regression: compromising the ONLY mask in the catalog must be
    /// refused — the old `mark_compromised` removed the mask unconditionally
    /// and only checked `select_fallback` afterward, so tripping a
    /// single-mask (or fully-tripped) deployment emptied the catalog and
    /// permanently locked out every future handshake.
    #[test]
    fn mark_compromised_refuses_to_empty_a_single_mask_catalog() {
        let catalog = MaskCatalog::new();
        let mask = webrtc_zoom_v3();
        catalog.register_mask(mask.clone());
        catalog.set_primary_mask_id(mask.mask_id.clone());

        let result = catalog.mark_compromised_with_fallback(&mask.mask_id);
        assert!(
            result.is_none(),
            "compromising the last mask must be refused, not return no fallback \
             after already emptying the catalog"
        );
        assert_eq!(
            catalog.available_count(),
            1,
            "the mask must remain available — nothing to fall back to"
        );
        assert!(
            catalog.primary_mask().is_some(),
            "the catalog must never go fully deaf (primary_mask() == None) just \
             because one mask tripped a detector"
        );
    }

    /// H1: with a real fallback available, the compromise DOES go through
    /// and the compromised mask is actually removed from live rotation.
    #[test]
    fn mark_compromised_succeeds_when_a_fallback_exists() {
        let catalog = MaskCatalog::new();
        let bad = webrtc_zoom_v3();
        let good = aivpn_common::mask::preset_masks::quic_https_v2();
        catalog.register_mask(bad.clone());
        catalog.register_mask(good.clone());
        catalog.set_primary_mask_id(bad.mask_id.clone());

        let result = catalog.mark_compromised_with_fallback(&bad.mask_id);
        assert_eq!(
            result.map(|m| m.mask_id),
            Some(good.mask_id),
            "the surviving mask must be handed back as the fallback"
        );
        assert_eq!(catalog.available_count(), 1, "the bad mask must be removed");
        // A freshly-registered mask with the same id must NOT resurrect the
        // compromised one within the TTL window.
        catalog.register_mask(bad.clone());
        assert_eq!(
            catalog.available_count(),
            1,
            "register_mask must still refuse a still-compromised id"
        );
    }

    #[test]
    fn packet_layout_extracts_embedded_eph_pub_from_mdh() {
        let catalog = MaskCatalog::new();
        let mask = webrtc_zoom_v3();
        catalog.register_mask(mask.clone());
        catalog.set_primary_mask_id(mask.mask_id.clone());
        let (packet_mdh_len, handshake_mdh_len, eph_offset, eph_len) = catalog.packet_layout();

        let mut mdh = mask.header_template.clone();
        if mdh.len() < handshake_mdh_len {
            mdh.resize(handshake_mdh_len, 0);
        }

        let expected_eph = [0x5au8; 32];
        mdh[eph_offset..eph_offset + eph_len].copy_from_slice(&expected_eph);

        let mut packet = vec![0u8; TAG_SIZE];
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&[0xabu8; 24]);

        let eph_start = TAG_SIZE + eph_offset;
        let payload_start = TAG_SIZE + handshake_mdh_len;

        assert_eq!(
            packet_mdh_len, 20,
            "regular STUN packet MDH length must stay at 20 bytes"
        );
        assert_eq!(
            handshake_mdh_len, 52,
            "handshake MDH length must include embedded eph_pub"
        );
        assert_eq!(&packet[eph_start..eph_start + eph_len], &expected_eph);
        assert_eq!(&packet[payload_start..], &[0xabu8; 24]);
    }

    #[test]
    fn inner_l7_prefix_extracts_udp_payload() {
        // IPv4 (IHL=5, proto=17 UDP) + 8-byte UDP header + STUN-shaped L7:
        // type@0, len@2, magic cookie 0x2112A442 @4 — what detect_mimic_protocol
        // keys off. inner_l7_prefix must return the L7 payload starting at
        // ip[20+8], i.e. the STUN bytes, NOT the IP/UDP header.
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, IHL 5
        ip[9] = 17; // UDP
        ip.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // UDP header (8B)
        let stun = [0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4];
        ip.extend_from_slice(&stun);
        let l7 = inner_l7_prefix(&ip);
        assert_eq!(&l7[..], &stun[..]);
        assert_eq!(&l7[4..8], &[0x21, 0x12, 0xA4, 0x42]); // magic cookie at offset 4
    }

    #[test]
    fn inner_l7_prefix_handles_tcp_and_caps_at_16() {
        // IPv4 + TCP (data offset 5 words = 20B header) + 20B payload → capped 16.
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6; // TCP
        let mut tcp = vec![0u8; 20];
        tcp[12] = 0x50; // data offset = 5 words (20 bytes)
        ip.extend_from_slice(&tcp);
        ip.extend_from_slice(&[0xAB; 20]);
        let l7 = inner_l7_prefix(&ip);
        assert_eq!(l7.len(), 16);
        assert!(l7.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn inner_l7_prefix_rejects_non_ipv4_and_ciphertext() {
        assert!(inner_l7_prefix(&[]).is_empty());
        assert!(inner_l7_prefix(&[0x60; 40]).is_empty()); // IPv6
        assert!(inner_l7_prefix(&[0x45, 0, 0, 0]).is_empty()); // truncated
                                                               // A raw encrypted wire prefix (random high bytes, first nibble != 4)
                                                               // must yield nothing — this is the exact regression the fix prevents.
        assert!(inner_l7_prefix(&[0x9f, 0x3c, 0xa1, 0x00, 0xde, 0xad, 0xbe, 0xef]).is_empty());
    }
}
