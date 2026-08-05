//! The server identifies a handshake's mask by trying candidates until one
//! parses out an ephemeral key that yields matching session keys. That probe
//! only constrains `(tag_offset, eph_pub_offset)` — the resonance tag and the
//! derived keys do not depend on anything else in the profile.
//!
//! So any two candidates that agree on those two numbers are INDISTINGUISHABLE
//! at handshake time. If they disagree on the header length, the server pins
//! the session to the wrong one and every uplink DATA packet lands at the wrong
//! ciphertext offset (`Crypto error: aead::Error`) while the fixed-length
//! control plane keeps working — the "connected, no traffic" shape of #71.

use aivpn_common::mask::{
    derive_bootstrap_candidates, preset_masks, BootstrapDescriptor, MaskProfile,
};
use std::collections::HashMap;

fn descriptor(id: &str, salt: u8) -> BootstrapDescriptor {
    BootstrapDescriptor {
        descriptor_id: id.to_string(),
        version: 1,
        created_at: 0,
        expires_at: u64::MAX,
        base_mask_ids: preset_masks::all()
            .iter()
            .map(|m| m.mask_id.clone())
            .collect(),
        embedded_masks: Vec::new(),
        candidate_count: 4,
        kdf_salt: [salt; 32],
        signature: [0u8; 64],
    }
}

fn header_len(mask: &MaskProfile) -> usize {
    mask.header_spec
        .as_ref()
        .map(|s| s.min_length())
        .unwrap_or_else(|| mask.header_template.len())
}

/// Every mask the server may pin a session to, for a realistic client: the
/// descriptor epochs it holds plus the builtin presets it always falls back to.
fn candidate_universe() -> Vec<MaskProfile> {
    let psk = [0x31u8; 32];
    let mut all = Vec::new();
    for (i, id) in ["epoch-20668", "epoch-20669", "epoch-20670", "epoch-20671"]
        .iter()
        .enumerate()
    {
        all.extend(derive_bootstrap_candidates(
            &descriptor(id, 0x5a + i as u8),
            Some(&psk),
        ));
    }
    all.extend(preset_masks::all());
    all
}

#[test]
fn handshake_layout_determines_the_data_plane_layout() {
    let mut by_probe: HashMap<(u16, u16), Vec<(String, usize)>> = HashMap::new();
    for mask in candidate_universe() {
        by_probe
            .entry((mask.tag_offset, mask.eph_pub_offset))
            .or_default()
            .push((mask.mask_id.clone(), header_len(&mask)));
    }

    let mut ambiguous = Vec::new();
    for ((tag_offset, eph_offset), masks) in &by_probe {
        let first_len = masks[0].1;
        if masks.iter().any(|(_, len)| *len != first_len) {
            ambiguous.push(format!(
                "tag_offset={tag_offset} eph_pub_offset={eph_offset} → {:?}",
                masks
            ));
        }
    }

    assert!(
        ambiguous.is_empty(),
        "masks that are indistinguishable at handshake time but frame DATA differently:\n{}",
        ambiguous.join("\n"),
    );
}
