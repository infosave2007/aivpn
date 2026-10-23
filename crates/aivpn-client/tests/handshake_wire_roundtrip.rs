//! Full client→server *handshake init packet* wire round-trip over every shipped
//! preset mask. The existing session/tag tests call `create_session` with a raw
//! public key, bypassing the init-packet path: the client obfuscates its
//! ephemeral key, `MimicryEngine::build_packet` embeds it at the mask-defined
//! offset (with the resonance tag placed per the mask's tag layout), and the
//! server must extract both from those exact offsets to complete the DH. A
//! mask whose embedded-vs-legacy layout the two sides disagree on, or an eph/tag
//! offset drift, breaks the handshake with a tag mismatch while every existing
//! test still passes. This locks that path down.

use aivpn_common::client_wire::build_inner_packet;
use aivpn_common::crypto::{self, KeyPair, DEFAULT_WINDOW_MS, TAG_SIZE};
use aivpn_common::mask::preset_masks;
use aivpn_common::mimicry::MimicryEngine;
use aivpn_common::protocol::{ControlPayload, InnerType};

// Mirror of the server's gateway layout helpers (tag_prefix_len / tag_byte_offset):
// a legacy mask (tag_offset == u16::MAX) carries an 8-byte tag prefix and the tag
// sits at offset 0; an embedded-tag mask has no prefix and the tag sits at tag_offset.
fn server_prefix(tag_offset: u16) -> usize {
    if tag_offset == u16::MAX {
        TAG_SIZE
    } else {
        0
    }
}
fn server_tag_off(tag_offset: u16) -> usize {
    if tag_offset == u16::MAX {
        0
    } else {
        tag_offset as usize
    }
}

#[test]
fn handshake_init_roundtrip_over_all_presets() {
    for mask in preset_masks::all() {
        let mask_id = mask.mask_id.clone();
        let server_kp = KeyPair::generate();
        let server_pub = server_kp.public_key_bytes();
        let client_kp = KeyPair::generate();
        let client_pub = client_kp.public_key_bytes();
        let psk = [7u8; 32];

        // ---- CLIENT: build the init packet exactly as send_init does ----
        let dh_c = client_kp.compute_shared(&server_pub).unwrap();
        let keys = crypto::derive_initial_session_keys(&dh_c, Some(&psk), &client_pub);
        let mut obf = client_pub;
        crypto::obfuscate_eph_pub(&mut obf, &server_pub);
        let mut engine = MimicryEngine::new(mask.clone());
        let inner = build_inner_packet(
            InnerType::Control,
            0,
            &ControlPayload::Keepalive { send_ts: 0 }.encode().unwrap(),
        );
        let mut counter: u64 = 0;
        let pkt = engine
            .build_packet(&inner, &keys, &mut counter, Some(&obf))
            .unwrap();

        // ---- SERVER: extract eph + tag at the mask's layout offsets ----
        let prefix = server_prefix(mask.tag_offset);
        let eph_len = mask.eph_pub_length as usize;
        let eph_start = prefix + mask.eph_pub_offset as usize;
        assert!(
            pkt.len() >= eph_start + eph_len,
            "{mask_id}: packet too short for eph slot"
        );
        let mut recovered_eph = [0u8; 32];
        let copy = eph_len.min(32);
        recovered_eph[..copy].copy_from_slice(&pkt[eph_start..eph_start + copy]);
        crypto::obfuscate_eph_pub(&mut recovered_eph, &server_pub);
        assert_eq!(
            recovered_eph, client_pub,
            "{mask_id}: server extracted the wrong ephemeral key (layout drift)"
        );

        let toff = server_tag_off(mask.tag_offset);
        assert!(
            pkt.len() >= toff + TAG_SIZE,
            "{mask_id}: packet too short for tag"
        );
        let mut recovered_tag = [0u8; TAG_SIZE];
        recovered_tag.copy_from_slice(&pkt[toff..toff + TAG_SIZE]);

        // ---- SERVER: derive keys from the recovered eph and validate the tag ----
        let dh_s = server_kp.compute_shared(&recovered_eph).unwrap();
        let skeys = crypto::derive_initial_session_keys(&dh_s, Some(&psk), &recovered_eph);
        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let tag_ok = (0..=8u64)
            .any(|c| crypto::generate_resonance_tag(&skeys.tag_secret, c, tw) == recovered_tag);
        assert!(tag_ok, "{mask_id}: handshake tag validation failed");

        let ct_start = prefix + mask.mdh_len().max(mask.eph_pub_offset as usize + eph_len);
        let plain = crypto::decrypt_session_payload(
            &skeys,
            crypto::PacketDirection::ClientToServer,
            0,
            &recovered_tag,
            &pkt[ct_start..],
        )
        .unwrap_or_else(|error| panic!("{mask_id}: init AEAD failed: {error}"));
        let pad = u16::from_le_bytes([plain[0], plain[1]]) as usize;
        assert_eq!(&plain[2..plain.len() - pad], &inner);
    }
}

#[test]
fn mobile_initial_v2_roundtrip_over_all_presets() {
    for mask in preset_masks::all() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let eph = client.public_key_bytes();
        let dh = client.compute_shared(&server.public_key_bytes()).unwrap();
        let keys = crypto::derive_initial_session_keys(&dh, Some(&[7; 32]), &eph);
        let obf = aivpn_common::client_wire::obfuscate_client_eph_pub(
            &client,
            &server.public_key_bytes(),
        );
        let inner = build_inner_packet(
            InnerType::Control,
            0,
            &ControlPayload::Keepalive { send_ts: 17 }.encode().unwrap(),
        );
        let mdh_len = mask.mdh_len();
        let packet = aivpn_common::client_wire::build_shaped_mdh_packet(
            &keys,
            &mut 0,
            &inner,
            Some(&obf),
            mdh_len,
            &mask,
        )
        .unwrap();
        let prefix = server_prefix(mask.tag_offset);
        let eph_start = prefix + mask.eph_pub_offset as usize;
        let mut recovered_eph: [u8; 32] = packet[eph_start..eph_start + 32].try_into().unwrap();
        crypto::obfuscate_eph_pub(&mut recovered_eph, &server.public_key_bytes());
        assert_eq!(recovered_eph, eph, "{}: mobile eph slot", mask.mask_id);
        let tag_start = server_tag_off(mask.tag_offset);
        let tag = packet[tag_start..tag_start + 8].try_into().unwrap();
        let server_dh = server.compute_shared(&recovered_eph).unwrap();
        let server_keys =
            crypto::derive_initial_session_keys(&server_dh, Some(&[7; 32]), &recovered_eph);
        let plain = crypto::decrypt_session_payload(
            &server_keys,
            crypto::PacketDirection::ClientToServer,
            0,
            &tag,
            &packet[prefix + mdh_len + 32..],
        )
        .unwrap_or_else(|error| panic!("{}: mobile init AEAD: {error}", mask.mask_id));
        let pad = u16::from_le_bytes([plain[0], plain[1]]) as usize;
        assert_eq!(&plain[2..plain.len() - pad], &inner);
    }
}
