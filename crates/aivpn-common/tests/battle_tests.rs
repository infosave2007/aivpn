//! Battle Tests for AIVPN
//!
//! Comprehensive tests covering:
//! - Crypto stress & edge cases
//! - Protocol wire format round-trips
//! - Session management & anti-replay
//! - Full client→server pipeline simulation
//! - Security edge cases (replay, wrong keys, corruption)

use std::collections::HashSet;

use aivpn_common::crypto::{
    self, compute_time_window, current_timestamp_ms, decrypt_payload, derive_session_keys,
    encrypt_payload, generate_resonance_tag, KeyPair, SessionKeys, CHACHA20_KEY_SIZE,
    DEFAULT_WINDOW_MS, NONCE_SIZE, TAG_SIZE,
};
use aivpn_common::mask::preset_masks::{all as all_preset_masks, webrtc_zoom_v3};
use aivpn_common::mask::MaskProfile;
use aivpn_common::protocol::{ControlPayload, ControlSubtype, InnerHeader, InnerType};
use subtle::ConstantTimeEq;

// ============================================================================
// Crypto Battle Tests
// ============================================================================

#[test]
fn battle_key_exchange_100_pairs() {
    // Generate 100 keypairs and verify all DH exchanges produce matching secrets
    for _ in 0..100 {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let sa = a.compute_shared(&b.public_key_bytes()).unwrap();
        let sb = b.compute_shared(&a.public_key_bytes()).unwrap();
        assert_eq!(sa, sb, "DH mismatch");
    }
}

#[test]
fn battle_key_exchange_deterministic_from_private() {
    // from_private_key must produce same public key and shared secret
    let _a = KeyPair::generate();
    let priv_bytes = {
        // Re-generate from same private — we'll use a known key
        let key = [0x42u8; 32];
        key
    };
    let k1 = KeyPair::from_private_key(priv_bytes);
    let k2 = KeyPair::from_private_key(priv_bytes);
    assert_eq!(k1.public_key_bytes(), k2.public_key_bytes());

    let peer = KeyPair::generate();
    let s1 = k1.compute_shared(&peer.public_key_bytes()).unwrap();
    let s2 = k2.compute_shared(&peer.public_key_bytes()).unwrap();
    assert_eq!(s1, s2);
}

#[test]
fn battle_all_zero_dh_rejected() {
    // Small subgroup attack: all-zero public key must be rejected
    let k = KeyPair::generate();
    let zero_pub = [0u8; 32];
    let result = k.compute_shared(&zero_pub);
    assert!(result.is_err(), "All-zero DH must be rejected");
}

#[test]
fn battle_low_order_points_rejected() {
    // Low-order points on Curve25519 that lead to zero shared secret
    let low_order_points: Vec<[u8; 32]> = vec![
        [0u8; 32], // Zero
        {
            // Order-1 point (identity)
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        },
    ];
    let k = KeyPair::generate();
    for point in &low_order_points {
        // Some low-order points will produce all-zero — must be rejected
        let result = k.compute_shared(point);
        // It's OK if compute_shared returns Ok for non-zero results
        if let Ok(shared) = &result {
            assert!(
                !bool::from(shared.ct_eq(&[0u8; 32])),
                "Zero shared secret must be rejected"
            );
        }
    }
}

#[test]
fn battle_encrypt_decrypt_various_sizes() {
    let key = crypto::blake3_hash(b"test-key");
    let sizes = [0, 1, 15, 16, 17, 31, 32, 64, 128, 255, 256, 1024, 4096];
    for size in sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let nonce = [0u8; NONCE_SIZE];
        let ct = encrypt_payload(&key, &nonce, &plaintext).unwrap();
        let pt = decrypt_payload(&key, &nonce, &ct).unwrap();
        assert_eq!(plaintext, pt, "Round-trip failed for size {}", size);
    }
}

#[test]
fn battle_encrypt_decrypt_unique_nonces() {
    // Same plaintext with different nonces must produce different ciphertexts
    let key = [0xAB; CHACHA20_KEY_SIZE];
    let plaintext = b"same plaintext";
    let mut ciphertexts = HashSet::new();

    for i in 0u64..100 {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&i.to_le_bytes());
        let ct = encrypt_payload(&key, &nonce, plaintext).unwrap();
        ciphertexts.insert(ct);
    }
    assert_eq!(ciphertexts.len(), 100, "All ciphertexts must be unique");
}

#[test]
fn battle_decrypt_wrong_key_fails() {
    let key1 = [1u8; CHACHA20_KEY_SIZE];
    let key2 = [2u8; CHACHA20_KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let ct = encrypt_payload(&key1, &nonce, b"secret").unwrap();
    let result = decrypt_payload(&key2, &nonce, &ct);
    assert!(result.is_err(), "Decryption with wrong key must fail");
}

#[test]
fn battle_decrypt_wrong_nonce_fails() {
    let key = [1u8; CHACHA20_KEY_SIZE];
    let nonce1 = [0u8; NONCE_SIZE];
    let nonce2 = [1u8; NONCE_SIZE];
    let ct = encrypt_payload(&key, &nonce1, b"secret").unwrap();
    let result = decrypt_payload(&key, &nonce2, &ct);
    assert!(result.is_err(), "Decryption with wrong nonce must fail");
}

#[test]
fn battle_ciphertext_tamper_detected() {
    let key = [1u8; CHACHA20_KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let mut ct = encrypt_payload(&key, &nonce, b"important data").unwrap();
    // Flip one bit in the middle
    let mid = ct.len() / 2;
    ct[mid] ^= 0x01;
    let result = decrypt_payload(&key, &nonce, &ct);
    assert!(result.is_err(), "Tampered ciphertext must be rejected");
}

#[test]
fn battle_ciphertext_truncation_detected() {
    let key = [1u8; CHACHA20_KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let ct = encrypt_payload(&key, &nonce, b"important data").unwrap();
    // Truncate
    let result = decrypt_payload(&key, &nonce, &ct[..ct.len() - 1]);
    assert!(result.is_err(), "Truncated ciphertext must be rejected");
}

#[test]
fn battle_resonance_tag_uniqueness() {
    let secret = [0x42u8; 32];
    let time_window = 12345u64;
    let mut tags = HashSet::new();
    for counter in 0u64..10000 {
        let tag = generate_resonance_tag(&secret, counter, time_window);
        tags.insert(tag);
    }
    // With 8-byte tags, collision probability for 10k tags is negligible
    assert!(tags.len() > 9990, "Too many tag collisions: {}", tags.len());
}

#[test]
fn battle_resonance_tag_time_window_isolation() {
    let secret = [0x42u8; 32];
    let counter = 42u64;
    let tag1 = generate_resonance_tag(&secret, counter, 100);
    let tag2 = generate_resonance_tag(&secret, counter, 101);
    assert_ne!(tag1, tag2, "Tags in different time windows must differ");
}

#[test]
fn battle_resonance_tag_secret_isolation() {
    let secret1 = [0x01u8; 32];
    let secret2 = [0x02u8; 32];
    let tag1 = generate_resonance_tag(&secret1, 0, 100);
    let tag2 = generate_resonance_tag(&secret2, 0, 100);
    assert_ne!(tag1, tag2, "Tags with different secrets must differ");
}

#[test]
fn battle_session_keys_derivation_deterministic() {
    let dh = [0xAB; 32];
    let eph = [0xCD; 32];
    let keys1 = derive_session_keys(&dh, None, &eph);
    let keys2 = derive_session_keys(&dh, None, &eph);
    assert_eq!(keys1.session_key, keys2.session_key);
    assert_eq!(keys1.tag_secret, keys2.tag_secret);
    assert_eq!(keys1.prng_seed, keys2.prng_seed);
}

#[test]
fn battle_session_keys_psk_affects_output() {
    let dh = [0xAB; 32];
    let eph = [0xCD; 32];
    let psk = [0xEF; 32];
    let keys_no_psk = derive_session_keys(&dh, None, &eph);
    let keys_with_psk = derive_session_keys(&dh, Some(&psk), &eph);
    assert_ne!(
        keys_no_psk.session_key, keys_with_psk.session_key,
        "PSK must affect derived keys"
    );
}

#[test]
fn battle_session_keys_all_fields_differ() {
    let dh = [0xAB; 32];
    let eph = [0xCD; 32];
    let keys = derive_session_keys(&dh, None, &eph);
    assert_ne!(
        keys.session_key, keys.tag_secret,
        "session_key and tag_secret must differ"
    );
    assert_ne!(
        keys.session_key, keys.prng_seed,
        "session_key and prng_seed must differ"
    );
    assert_ne!(
        keys.tag_secret, keys.prng_seed,
        "tag_secret and prng_seed must differ"
    );
}

// ============================================================================
// Protocol Wire Format Tests
// ============================================================================

#[test]
fn battle_inner_header_roundtrip_all_types() {
    let types = [
        InnerType::Data,
        InnerType::Control,
        InnerType::Fragment,
        InnerType::Ack,
    ];
    for inner_type in types {
        for seq in [0u16, 1, 255, 65535] {
            let hdr = InnerHeader {
                inner_type,
                seq_num: seq,
            };
            let encoded = hdr.encode();
            let decoded = InnerHeader::decode(&encoded).unwrap();
            assert_eq!(decoded.inner_type, inner_type);
            assert_eq!(decoded.seq_num, seq);
        }
    }
}

#[test]
fn battle_inner_header_too_short() {
    let result = InnerHeader::decode(&[0, 1, 2]); // 3 bytes, need 4
    assert!(result.is_err());
}

#[test]
fn battle_inner_header_unknown_type() {
    let data = [0xFF, 0xFF, 0x00, 0x00]; // Unknown type 0xFFFF
    let result = InnerHeader::decode(&data);
    assert!(result.is_err());
}

#[test]
fn battle_control_payload_keepalive_roundtrip() {
    let payload = ControlPayload::Keepalive { send_ts: 12345 };
    let encoded = payload.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    assert!(matches!(
        decoded,
        ControlPayload::Keepalive { send_ts: 12345 }
    ));
}

#[test]
fn battle_control_payload_shutdown_roundtrip() {
    let payload = ControlPayload::Shutdown { reason: 42 };
    let encoded = payload.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    if let ControlPayload::Shutdown { reason } = decoded {
        assert_eq!(reason, 42);
    } else {
        panic!("Expected Shutdown");
    }
}

#[test]
fn battle_control_payload_key_rotate_roundtrip() {
    let key = [0xABu8; 32];
    let payload = ControlPayload::KeyRotate { new_eph_pub: key };
    let encoded = payload.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    if let ControlPayload::KeyRotate { new_eph_pub } = decoded {
        assert_eq!(new_eph_pub, key);
    } else {
        panic!("Expected KeyRotate");
    }
}

#[test]
fn battle_control_payload_time_sync_roundtrip() {
    let payload = ControlPayload::TimeSync {
        server_ts_ms: 1700000000000,
    };
    let encoded = payload.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    if let ControlPayload::TimeSync { server_ts_ms } = decoded {
        assert_eq!(server_ts_ms, 1700000000000);
    } else {
        panic!("Expected TimeSync");
    }
}

#[test]
fn battle_control_payload_telemetry_roundtrip() {
    let payload = ControlPayload::TelemetryRequest { metric_flags: 0xFF };
    let encoded = payload.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    if let ControlPayload::TelemetryRequest { metric_flags } = decoded {
        assert_eq!(metric_flags, 0xFF);
    } else {
        panic!("Expected TelemetryRequest");
    }
}

#[test]
fn battle_control_payload_telemetry_response_roundtrip() {
    let payload = ControlPayload::TelemetryResponse {
        packet_loss: 100,
        rtt_ms: 50,
        jitter_ms: 5,
        buffer_pct: 80,
    };
    let encoded = payload.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    if let ControlPayload::TelemetryResponse {
        packet_loss,
        rtt_ms,
        jitter_ms,
        buffer_pct,
    } = decoded
    {
        assert_eq!(packet_loss, 100);
        assert_eq!(rtt_ms, 50);
        assert_eq!(jitter_ms, 5);
        assert_eq!(buffer_pct, 80);
    } else {
        panic!("Expected TelemetryResponse");
    }
}

#[test]
fn battle_control_payload_ack_roundtrip() {
    let payload = ControlPayload::ControlAck {
        ack_seq: 1234,
        ack_for_subtype: ControlSubtype::Keepalive as u8,
    };
    let encoded = payload.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    if let ControlPayload::ControlAck {
        ack_seq,
        ack_for_subtype,
    } = decoded
    {
        assert_eq!(ack_seq, 1234);
        assert_eq!(ack_for_subtype, ControlSubtype::Keepalive as u8);
    } else {
        panic!("Expected ControlAck");
    }
}

#[test]
fn battle_control_payload_empty_data() {
    let result = ControlPayload::decode(&[]);
    assert!(result.is_err());
}

#[test]
fn battle_control_payload_unknown_subtype() {
    let result = ControlPayload::decode(&[0xFF]);
    assert!(result.is_err());
}

// ============================================================================
// Full Wire Format Round-Trip (encrypt → wire → decrypt)
// ============================================================================

/// Simulates building a packet (client side) and parsing it (server side)
/// with the new CRIT-5 wire format: TAG | MDH | encrypt(pad_len || payload || padding)
#[test]
fn battle_wire_format_roundtrip() {
    // Setup: client and server derive same session keys
    let client_kp = KeyPair::generate();
    let server_kp = KeyPair::generate();
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());

    // Client builds packet
    let payload = b"Hello from client";
    let counter = 0u64;
    let pad_len = 16u16;

    // Build padded plaintext: pad_len(u16) || plaintext || random_padding
    let mut padded = Vec::new();
    padded.extend_from_slice(&pad_len.to_le_bytes());
    padded.extend_from_slice(payload);
    // Random padding
    let padding: Vec<u8> = (0..pad_len).map(|i| i as u8).collect();
    padded.extend_from_slice(&padding);

    // Encrypt
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    let ciphertext = encrypt_payload(&keys.session_key, &nonce, &padded).unwrap();

    // Generate tag
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&keys.tag_secret, counter, tw);

    // Assemble wire packet: TAG | MDH(4) | ciphertext
    let mdh = vec![0x00, 0x01, 0x02, 0x03];
    let mut wire_packet = Vec::new();
    wire_packet.extend_from_slice(&tag);
    wire_packet.extend_from_slice(&mdh);
    wire_packet.extend_from_slice(&ciphertext);

    // --- Server side ---
    // Validate tag
    let expected_tag = generate_resonance_tag(&keys.tag_secret, counter, tw);
    assert!(bool::from(expected_tag.ct_eq(&wire_packet[..TAG_SIZE])));

    // Extract ciphertext (skip TAG + MDH)
    let mdh_len = 4;
    let encrypted = &wire_packet[TAG_SIZE + mdh_len..];

    // Decrypt
    let decrypted_padded = decrypt_payload(&keys.session_key, &nonce, encrypted).unwrap();

    // Extract pad_len and strip padding
    let dec_pad_len = u16::from_le_bytes([decrypted_padded[0], decrypted_padded[1]]) as usize;
    let data = &decrypted_padded[2..decrypted_padded.len() - dec_pad_len];
    assert_eq!(data, payload);
}

#[test]
fn battle_wire_format_multiple_packets() {
    let client_kp = KeyPair::generate();
    let server_kp = KeyPair::generate();
    let shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let keys = derive_session_keys(&shared, None, &client_kp.public_key_bytes());
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);

    for counter in 0u64..100 {
        let payload = format!("Packet #{counter}");
        let pad_len = (counter % 32) as u16;

        let mut padded = Vec::new();
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(payload.as_bytes());
        for i in 0..pad_len {
            padded.push(i as u8);
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        let ct = encrypt_payload(&keys.session_key, &nonce, &padded).unwrap();

        let tag = generate_resonance_tag(&keys.tag_secret, counter, tw);
        let mdh = vec![0u8; 4];

        let mut wire = Vec::new();
        wire.extend_from_slice(&tag);
        wire.extend_from_slice(&mdh);
        wire.extend_from_slice(&ct);

        // Server-side parse
        let dec = decrypt_payload(&keys.session_key, &nonce, &wire[TAG_SIZE + 4..]).unwrap();
        let pl = u16::from_le_bytes([dec[0], dec[1]]) as usize;
        let data = &dec[2..dec.len() - pl];
        assert_eq!(data, payload.as_bytes(), "Packet {counter} mismatch");
    }
}

#[test]
fn battle_wire_format_zero_padding() {
    let keys = SessionKeys {
        session_key: crypto::blake3_hash(b"key"),
        session_key_s2c: crypto::blake3_hash(b"key"),
        tag_secret: crypto::blake3_hash(b"tag"),
        prng_seed: [0u8; 32],
    };
    let counter = 0u64;
    let pad_len = 0u16;
    let payload = b"no padding";

    let mut padded = Vec::new();
    padded.extend_from_slice(&pad_len.to_le_bytes());
    padded.extend_from_slice(payload);

    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    let ct = encrypt_payload(&keys.session_key, &nonce, &padded).unwrap();
    let dec = decrypt_payload(&keys.session_key, &nonce, &ct).unwrap();
    let pl = u16::from_le_bytes([dec[0], dec[1]]) as usize;
    assert_eq!(pl, 0);
    let data = &dec[2..dec.len() - pl];
    assert_eq!(data, payload);
}

#[test]
fn battle_wire_format_max_padding() {
    let keys = SessionKeys {
        session_key: crypto::blake3_hash(b"key"),
        session_key_s2c: crypto::blake3_hash(b"key"),
        tag_secret: crypto::blake3_hash(b"tag"),
        prng_seed: [0u8; 32],
    };
    let counter = 0u64;
    let pad_len = 500u16;
    let payload = b"max padding test";

    let mut padded = Vec::new();
    padded.extend_from_slice(&pad_len.to_le_bytes());
    padded.extend_from_slice(payload);
    padded.extend_from_slice(&vec![0xCC; pad_len as usize]);

    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    let ct = encrypt_payload(&keys.session_key, &nonce, &padded).unwrap();
    let dec = decrypt_payload(&keys.session_key, &nonce, &ct).unwrap();
    let pl = u16::from_le_bytes([dec[0], dec[1]]) as usize;
    assert_eq!(pl, 500);
    let data = &dec[2..dec.len() - pl];
    assert_eq!(data, payload);
}

// ============================================================================
// Session Key Exchange & Tag Validation (full pipeline)
// ============================================================================

#[test]
fn battle_full_key_exchange_pipeline() {
    // 1. Client generates keypair
    let client_kp = KeyPair::generate();
    // 2. Server has static keypair
    let server_kp = KeyPair::generate();

    // 3. Client computes shared secret using server's public key
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    // 4. Server computes shared secret using client's eph_pub
    let server_shared = server_kp
        .compute_shared(&client_kp.public_key_bytes())
        .unwrap();
    assert_eq!(client_shared, server_shared);

    // 5. Both derive identical session keys
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());
    let server_keys = derive_session_keys(&server_shared, None, &client_kp.public_key_bytes());
    assert_eq!(client_keys.session_key, server_keys.session_key);
    assert_eq!(client_keys.tag_secret, server_keys.tag_secret);

    // 6. Verify tag validation works
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&client_keys.tag_secret, 0, tw);
    let expected = generate_resonance_tag(&server_keys.tag_secret, 0, tw);
    assert!(bool::from(tag.ct_eq(&expected)));

    // 7. Verify encryption interop
    let nonce = [0u8; NONCE_SIZE];
    let ct = encrypt_payload(&client_keys.session_key, &nonce, b"test").unwrap();
    let pt = decrypt_payload(&server_keys.session_key, &nonce, &ct).unwrap();
    assert_eq!(pt, b"test");
}

#[test]
fn battle_full_key_exchange_with_psk() {
    let client_kp = KeyPair::generate();
    let server_kp = KeyPair::generate();
    let psk = crypto::blake3_hash(b"shared-secret-psk");

    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let server_shared = server_kp
        .compute_shared(&client_kp.public_key_bytes())
        .unwrap();

    let client_keys =
        derive_session_keys(&client_shared, Some(&psk), &client_kp.public_key_bytes());
    let server_keys =
        derive_session_keys(&server_shared, Some(&psk), &client_kp.public_key_bytes());

    assert_eq!(client_keys.session_key, server_keys.session_key);
    assert_eq!(client_keys.tag_secret, server_keys.tag_secret);
}

#[test]
fn battle_wrong_psk_different_keys() {
    let client_kp = KeyPair::generate();
    let server_kp = KeyPair::generate();
    let psk1 = [1u8; 32];
    let psk2 = [2u8; 32];

    let shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();

    let keys1 = derive_session_keys(&shared, Some(&psk1), &client_kp.public_key_bytes());
    let keys2 = derive_session_keys(&shared, Some(&psk2), &client_kp.public_key_bytes());

    assert_ne!(
        keys1.session_key, keys2.session_key,
        "Different PSKs must produce different keys"
    );
}

// ============================================================================
// Tag Constant-Time Comparison
// ============================================================================

#[test]
fn battle_tag_constant_time_comparison() {
    let secret = [0x42u8; 32];
    let tw = 100u64;

    for counter in 0u64..100 {
        let tag = generate_resonance_tag(&secret, counter, tw);
        let tag_copy = tag;

        // ct_eq should return true for identical tags
        assert!(bool::from(tag.ct_eq(&tag_copy)));

        // ct_eq should return false for different tags
        let other = generate_resonance_tag(&secret, counter + 1000, tw);
        assert!(!bool::from(tag.ct_eq(&other)));
    }
}

// ============================================================================
// Mask Profile Tests
// ============================================================================

#[test]
fn battle_all_preset_masks_valid() {
    let masks = all_preset_masks();
    assert!(!masks.is_empty(), "preset catalog must not be empty");

    let mut seen_ids = HashSet::new();
    for mask in masks {
        assert!(
            seen_ids.insert(mask.mask_id.clone()),
            "duplicate preset mask_id: {}",
            mask.mask_id
        );
        assert!(
            mask.version >= 2,
            "preset mask {} must use semantic header version",
            mask.mask_id
        );
        assert!(
            !mask.header_template.is_empty(),
            "preset mask {} must have a non-empty header template",
            mask.mask_id
        );
        assert!(
            mask.header_spec.is_some(),
            "preset mask {} must provide header_spec",
            mask.mask_id
        );
        assert_eq!(
            mask.eph_pub_length, 32,
            "preset mask {} must keep 32-byte eph pub length",
            mask.mask_id
        );
        assert!(
            !mask.fsm_states.is_empty(),
            "preset mask {} must have at least one FSM state",
            mask.mask_id
        );
    }
}

#[test]
fn battle_mask_signature_verification() {
    use ed25519_dalek::SigningKey;

    let mut mask = webrtc_zoom_v3();

    // Sign the whole mask (signature now covers every field via signing_message).
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    mask.sign(&signing_key);

    // Verify with correct key
    assert!(mask.verify_signature(&verifying_key.to_bytes()).unwrap());

    // Verify with wrong key rejects
    let wrong_key = SigningKey::from_bytes(&[0x99u8; 32]);
    assert!(!mask
        .verify_signature(&wrong_key.verifying_key().to_bytes())
        .unwrap());
}

#[test]
fn battle_mask_signature_tamper_detected() {
    use ed25519_dalek::SigningKey;

    let mut mask = webrtc_zoom_v3();
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    mask.sign(&signing_key);

    // Tamper with mask_id
    mask.mask_id = "tampered".to_string();
    assert!(!mask.verify_signature(&verifying_key.to_bytes()).unwrap());
}

#[test]
fn battle_mask_size_distribution_sampling() {
    let mask = webrtc_zoom_v3();
    let mut rng = rand::thread_rng();
    // Sample 1000 sizes — should all be positive
    for _ in 0..1000 {
        let size = mask.size_distribution.sample(&mut rng);
        assert!(size > 0, "Sampled size must be positive");
    }
}

#[test]
fn battle_mask_iat_distribution_sampling() {
    let mask = webrtc_zoom_v3();
    let mut rng = rand::thread_rng();
    for _ in 0..1000 {
        let iat = mask.iat_distribution.sample(&mut rng);
        assert!(iat >= 0.0, "IAT must be non-negative");
    }
}

#[test]
fn battle_mask_fsm_transitions() {
    // The bundled masks carry corpus-derived temporal-Markov FSMs (R4), whose
    // transitions use Random(prob) conditions rather than a hand-authored
    // AfterDuration graph, so this validates the transition MECHANISM
    // structure-agnostically: process_transition must always return a state_id
    // that exists in the mask (either the current state on no-op, or a declared
    // next_state) and must never panic for any (state, packets, duration).
    let mask = webrtc_zoom_v3();
    let valid: std::collections::HashSet<u16> =
        mask.fsm_states.iter().map(|s| s.state_id).collect();
    assert!(
        !mask.fsm_states.is_empty(),
        "R4: mask must carry fsm_states"
    );
    assert!(
        valid.contains(&mask.fsm_initial_state),
        "fsm_initial_state must be a declared state"
    );
    for &state in &[mask.fsm_initial_state, 0, 1, 2, 99] {
        for &(pkts, dur) in &[(0u32, 0u64), (1, 100), (100, 6000), (10_000, 600_000)] {
            let (next, _, _, _) = mask.process_transition(state, pkts, dur);
            // Either a declared state, or the input state echoed back (no match).
            assert!(
                valid.contains(&next) || next == state,
                "process_transition({state},{pkts},{dur}) -> {next} is not a valid state"
            );
        }
    }
}

#[test]
fn battle_mask_serialization_roundtrip() {
    let mask = webrtc_zoom_v3();
    let serialized = rmp_serde::to_vec(&mask).unwrap();
    let deserialized: MaskProfile = rmp_serde::from_slice(&serialized).unwrap();
    assert_eq!(mask.mask_id, deserialized.mask_id);
    assert_eq!(mask.version, deserialized.version);
    assert_eq!(mask.header_template, deserialized.header_template);
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn battle_stress_encrypt_decrypt_10k() {
    let key = crypto::blake3_hash(b"stress-key");
    let payload = vec![0xAB; 512];

    for i in 0u64..10_000 {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&i.to_le_bytes());
        let ct = encrypt_payload(&key, &nonce, &payload).unwrap();
        let pt = decrypt_payload(&key, &nonce, &ct).unwrap();
        assert_eq!(payload, pt);
    }
}

#[test]
fn battle_stress_tag_generation_10k() {
    let secret = crypto::blake3_hash(b"tag-stress");
    let tw = 999u64;
    let mut prev = [0u8; TAG_SIZE];
    for counter in 0u64..10_000 {
        let tag = generate_resonance_tag(&secret, counter, tw);
        if counter > 0 {
            assert_ne!(tag, prev, "Sequential tags must differ");
        }
        prev = tag;
    }
}

#[test]
fn battle_stress_key_derivation_100() {
    for i in 0u64..100 {
        let mut dh = [0u8; 32];
        dh[0..8].copy_from_slice(&i.to_le_bytes());
        let mut eph = [0u8; 32];
        eph[0..8].copy_from_slice(&(i + 1000).to_le_bytes());

        let keys = derive_session_keys(&dh, None, &eph);
        // All fields must be non-zero
        assert_ne!(keys.session_key, [0u8; 32]);
        assert_ne!(keys.tag_secret, [0u8; 32]);
        assert_ne!(keys.prng_seed, [0u8; 32]);
    }
}

// ============================================================================
// Security Edge Cases
// ============================================================================

#[test]
fn battle_nonce_reuse_different_ciphertext() {
    // Even with same nonce, different keys produce different ciphertexts
    let key1 = [1u8; CHACHA20_KEY_SIZE];
    let key2 = [2u8; CHACHA20_KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let ct1 = encrypt_payload(&key1, &nonce, b"same data").unwrap();
    let ct2 = encrypt_payload(&key2, &nonce, b"same data").unwrap();
    assert_ne!(ct1, ct2);
}

#[test]
fn battle_replay_tag_same_counter_same_window() {
    // Verifies that two tags with same counter+window are identical
    // (server uses this for O(1) lookup)
    let secret = [0x42u8; 32];
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag1 = generate_resonance_tag(&secret, 42, tw);
    let tag2 = generate_resonance_tag(&secret, 42, tw);
    assert_eq!(tag1, tag2);
}

#[test]
fn battle_time_window_rotation() {
    // Tags in adjacent windows must differ
    let secret = [0x42u8; 32];
    let tw = 1000u64;
    let tag_w1 = generate_resonance_tag(&secret, 0, tw);
    let tag_w2 = generate_resonance_tag(&secret, 0, tw + 1);
    assert_ne!(tag_w1, tag_w2);
}

#[test]
fn battle_tag_avoids_wireguard_first_byte() {
    // Issue #30: TAG first byte must NOT be 1–4 (WireGuard message types)
    // to prevent DPI/Wireshark from misidentifying packets as WireGuard.
    let secret = [0x42u8; 32];
    let tw = 1000u64;
    for counter in 0u64..50_000 {
        let tag = generate_resonance_tag(&secret, counter, tw);
        assert!(
            tag[0] < 1 || tag[0] > 4,
            "Tag first byte {} is in WireGuard range [1..4] at counter={}",
            tag[0],
            counter,
        );
    }
}

#[test]
fn battle_empty_payload_encrypt_decrypt() {
    let key = [1u8; CHACHA20_KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let ct = encrypt_payload(&key, &nonce, &[]).unwrap();
    let pt = decrypt_payload(&key, &nonce, &ct).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn battle_large_payload_1mb() {
    let key = [1u8; CHACHA20_KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let payload = vec![0xAA; 1_000_000];
    let ct = encrypt_payload(&key, &nonce, &payload).unwrap();
    let pt = decrypt_payload(&key, &nonce, &ct).unwrap();
    assert_eq!(payload, pt);
}

#[test]
fn battle_blake3_hash_deterministic() {
    let data = b"deterministic test";
    let h1 = crypto::blake3_hash(data);
    let h2 = crypto::blake3_hash(data);
    assert_eq!(h1, h2);
    // Different input, different hash
    let h3 = crypto::blake3_hash(b"different");
    assert_ne!(h1, h3);
}

#[test]
fn battle_hmac_sha256_deterministic() {
    let key = b"hmac-key";
    let data = b"hmac-data";
    let h1 = crypto::hmac_sha256(key, data);
    let h2 = crypto::hmac_sha256(key, data);
    assert_eq!(h1, h2);
    // Different key, different MAC
    let h3 = crypto::hmac_sha256(b"other-key", data);
    assert_ne!(h1, h3);
}
