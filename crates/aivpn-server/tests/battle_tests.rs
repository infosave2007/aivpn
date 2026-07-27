//! Server-Side Battle Tests
//!
//! Tests session management, gateway packet handling,
//! and full client→server crypto pipeline simulation

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use aivpn_common::crypto::{
    self, compute_time_window, current_timestamp_ms, decrypt_payload, derive_session_keys,
    encrypt_payload, generate_resonance_tag, KeyPair, SessionKeys, CHACHA20_KEY_SIZE,
    DEFAULT_WINDOW_MS, NONCE_SIZE, TAG_SIZE, X25519_PUBLIC_KEY_SIZE,
};
use aivpn_common::mask::preset_masks::webrtc_zoom_v3;
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType};
use subtle::ConstantTimeEq;

use aivpn_server::session::{
    ReplayWindow, Session, SessionManager, SessionState, IDLE_TIMEOUT, MAX_SESSIONS,
    TAG_WINDOW_SIZE,
};

fn make_session_manager() -> (SessionManager, KeyPair) {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);
    // We need to return server keypair separately for DH
    // But SessionManager takes ownership - create a duplicate
    let server_kp2 = KeyPair::from_private_key([0x42u8; 32]); // placeholder; we derive from mgr
    (mgr, server_kp)
}

fn make_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

/// Make an address with a unique IP (for tests needing >5 sessions)
fn make_unique_addr(index: u16) -> SocketAddr {
    let a = (index / 256) as u8;
    let b = (index % 256) as u8;
    format!("10.{}.{}.1:10000", a, b).parse().unwrap()
}

// ============================================================================
// QUIC-Initial mimic end-to-end (client builds -> server finds + decrypts)
// ============================================================================

/// Full QUIC-Initial mimic round trip through the server's decode contract:
/// the client emits a coalesced RFC 9001 v1 Initial (DCID = resonance tag)
/// with its real ciphertext appended, and the server (1) finds the session by
/// the tag it extracts at DCID offset 6, (2) recognizes the QUIC layout to
/// locate the trailing ciphertext, and (3) decrypts it back to the plaintext.
#[test]
fn battle_quic_initial_server_decode_roundtrip() {
    use aivpn_common::client_wire::build_inner_packet;
    use aivpn_common::quic_initial::{
        build_quic_initial, parse_quic_initial, QUIC_MIN_DATAGRAM, QUIC_TAG_OFFSET,
    };

    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = aivpn_common::mask::preset_masks::quic_https_v2();
    assert_eq!(
        mask.tag_offset, 6,
        "QUIC preset embeds tag at DCID offset 6"
    );
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let addr = make_addr(10000);
    let session = mgr
        .create_session(addr, client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Client derives the same session keys as the server.
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());

    // ── Client build path (exactly what MimicryEngine::emit does for QUIC) ──
    let counter: u64 = 0;
    let inner = build_inner_packet(InnerType::Data, 0, b"quic mimic payload");
    // Padded inner plaintext: [pad_len u16 LE][inner][pad]; pad_len = 0 here.
    let mut padded = Vec::new();
    padded.extend_from_slice(&0u16.to_le_bytes());
    padded.extend_from_slice(&inner);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    let ciphertext = encrypt_payload(&client_keys.session_key, &nonce, &padded).unwrap();
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&client_keys.tag_secret, counter, tw);
    let mut tag8 = [0u8; TAG_SIZE];
    tag8.copy_from_slice(&tag);
    let datagram = build_quic_initial(&tag8, &ciphertext, QUIC_MIN_DATAGRAM);

    // nDPI floor: the coalesced datagram is a valid-sized Initial.
    assert!(datagram.len() >= QUIC_MIN_DATAGRAM);

    // ── Server decode path ──
    // (1) Tag lives at DCID offset 6 (the layout-aware lookup extracts it there).
    let mut recv_tag = [0u8; TAG_SIZE];
    recv_tag.copy_from_slice(&datagram[QUIC_TAG_OFFSET..QUIC_TAG_OFFSET + TAG_SIZE]);
    assert_eq!(recv_tag, tag8, "tag must be readable at the DCID offset");

    // (2) Server finds the session by that tag.
    let found = mgr.get_session_by_tag(&recv_tag);
    assert!(found.is_some(), "server must find session by DCID tag");
    {
        let sess = session.lock();
        let v = sess.validate_tag(&recv_tag);
        assert!(v.is_some(), "server must validate the resonance tag");
        assert_eq!(v.unwrap().0, counter);
    }

    // (3) Server recognizes the QUIC layout and decrypts the trailing ciphertext.
    let layout = parse_quic_initial(&datagram).expect("server recognizes QUIC layout");
    assert_eq!(layout.tag, tag8);
    let decrypted = decrypt_payload(
        &client_keys.session_key,
        &nonce,
        &datagram[layout.payload_offset..],
    )
    .expect("server decrypts trailing ciphertext");
    // Strip the 2-byte pad-length prefix and confirm the inner survived.
    assert_eq!(&decrypted[2..], &inner[..], "inner payload must round-trip");
}

// ============================================================================
// ReplayWindow Bitmap Tests
// ============================================================================

#[test]
fn battle_u256_set_and_get() {
    let mut bm = ReplayWindow::default();
    assert!(!bm.get_bit(0));
    bm.set_bit(0);
    assert!(bm.get_bit(0));
    assert!(!bm.get_bit(1));
}

#[test]
fn battle_u256_all_bits() {
    let mut bm = ReplayWindow::default();
    for i in 0..256 {
        assert!(!bm.get_bit(i));
        bm.set_bit(i);
        assert!(bm.get_bit(i));
    }
}

#[test]
fn battle_u256_clear() {
    let mut bm = ReplayWindow::default();
    for i in 0..256 {
        bm.set_bit(i);
    }
    bm.clear();
    for i in 0..256 {
        assert!(!bm.get_bit(i));
    }
}

#[test]
fn battle_u256_boundary_bits() {
    let mut bm = ReplayWindow::default();
    // Test a word boundary (bit 127 = top of word 1, bit 128 = bit 0 of word 2)
    bm.set_bit(127);
    bm.set_bit(128);
    assert!(bm.get_bit(127));
    assert!(bm.get_bit(128));
    assert!(!bm.get_bit(126));
    assert!(!bm.get_bit(129));
}

// ============================================================================
// Session Creation Tests
// ============================================================================

#[test]
fn battle_session_creation() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let client_kp = KeyPair::generate();
    let addr = make_addr(10000);

    let session = mgr
        .create_session(addr, client_kp.public_key_bytes(), None, None)
        .unwrap();
    let sess = session.lock();
    assert_eq!(sess.state, SessionState::Active);
    assert_eq!(sess.client_addr, addr);
    assert_eq!(sess.eph_pub, client_kp.public_key_bytes());
    assert!(!sess.expected_tags.is_empty());
}

#[test]
fn battle_session_count() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    assert_eq!(mgr.session_count(), 0);

    for i in 0..10 {
        let kp = KeyPair::generate();
        mgr.create_session(make_unique_addr(i), kp.public_key_bytes(), None, None)
            .unwrap();
    }
    assert_eq!(mgr.session_count(), 10);
}

#[test]
fn battle_session_tag_lookup() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let client_kp = KeyPair::generate();
    let addr = make_addr(10000);
    let session = mgr
        .create_session(addr, client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Get one of the expected tags
    let tag = {
        let sess = session.lock();
        *sess.expected_tags.values().next().unwrap()
    };

    // O(1) lookup should find the session
    let found = mgr.get_session_by_tag(&tag);
    assert!(found.is_some());
}

#[test]
fn battle_session_tag_validation() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let addr = make_addr(10000);
    let session = mgr
        .create_session(addr, client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Client derives same keys
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());

    // Generate tag as client would
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&client_keys.tag_secret, 0, tw);

    // Server should be able to validate this tag
    let sess = session.lock();
    let counter = sess.validate_tag(&tag);
    assert!(counter.is_some(), "Server must validate client's tag");
    let (cnt, is_ratcheted) = counter.unwrap();
    assert_eq!(cnt, 0, "Counter for first tag should be 0");
    assert!(!is_ratcheted, "First tag should match initial keys");
}

#[test]
fn battle_session_anti_replay() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&client_keys.tag_secret, 0, tw);

    // First validation succeeds
    {
        let sess = session.lock();
        assert!(sess.validate_tag(&tag).is_some());
    }

    // Mark as received
    {
        let mut sess = session.lock();
        sess.mark_tag_received(0);
    }

    // Second validation (replay) must fail
    {
        let sess = session.lock();
        assert!(sess.validate_tag(&tag).is_none(), "Replay must be rejected");
    }
}

#[test]
fn battle_session_removal() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    let session_id = session.lock().session_id;
    assert!(mgr.get_session(&session_id).is_some());

    mgr.remove_session(&session_id);
    assert!(mgr.get_session(&session_id).is_none());
    assert_eq!(mgr.session_count(), 0);
}

#[test]
fn battle_session_remove_clears_tags() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Capture a tag before removal
    let tag = {
        let sess = session.lock();
        *sess.expected_tags.values().next().unwrap()
    };

    let session_id = session.lock().session_id;
    mgr.remove_session(&session_id);

    // Tag lookup must fail after removal
    assert!(mgr.get_session_by_tag(&tag).is_none());
}

#[test]
fn battle_session_multiple_clients() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let mut sessions = Vec::new();
    let mut client_keys_list = Vec::new();

    // Create 50 sessions
    for i in 0..50 {
        let client_kp = KeyPair::generate();
        let addr = make_unique_addr(i);
        let session = mgr
            .create_session(addr, client_kp.public_key_bytes(), None, None)
            .unwrap();

        let client_shared = client_kp
            .compute_shared(&server_kp.public_key_bytes())
            .unwrap();
        let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());

        sessions.push(session);
        client_keys_list.push(client_keys);
    }

    assert_eq!(mgr.session_count(), 50);

    // Verify each client can produce a valid tag for their session.
    // We compute tags for both the current and previous time windows to tolerate
    // clock crossings during the loop.
    let current_tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    for (i, client_keys) in client_keys_list.iter().enumerate() {
        let tag_current = generate_resonance_tag(&client_keys.tag_secret, 0, current_tw);
        let tag_prev =
            generate_resonance_tag(&client_keys.tag_secret, 0, current_tw.wrapping_sub(1));

        let found_current = mgr.get_session_by_tag(&tag_current);
        let found_prev = mgr.get_session_by_tag(&tag_prev);

        assert!(
            found_current.is_some() || found_prev.is_some(),
            "Client {i} tag must be found (current_tw={current_tw})"
        );
    }
}

#[test]
fn battle_session_send_counter() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // next_send_nonce should increment counter
    let mut sess = session.lock();
    let (nonce0, c0) = sess.next_send_nonce();
    assert_eq!(c0, 0);
    let (nonce1, c1) = sess.next_send_nonce();
    assert_eq!(c1, 1);
    assert_ne!(nonce0, nonce1);

    // Counter should be at 2 now
    assert_eq!(sess.send_counter, 2);
}

#[test]
fn battle_session_seq_wrapping() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    let mut sess = session.lock();
    // Set seq near u32 max
    sess.send_seq = u32::MAX - 1;
    let seq1 = sess.next_seq();
    assert_eq!(seq1, u32::MAX - 1);
    let seq2 = sess.next_seq();
    assert_eq!(seq2, u32::MAX);
    let seq3 = sess.next_seq();
    assert_eq!(seq3, 0); // Wrapped
}

#[test]
#[ignore]
fn battle_session_idle_detection() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Freshly created session is not idle
    assert!(!session.lock().is_idle());
}

// ============================================================================
// Full Client→Server Pipeline Simulation
// ============================================================================

/// Simulates the complete client→server packet flow without TUN/UDP
#[test]
fn battle_full_pipeline_data_packet() {
    // 1. Setup: Server has static keypair
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask.clone());

    // 2. Client generates ephemeral keypair and derives keys
    let client_kp = KeyPair::generate();
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());

    // 3. Server creates session (normally triggered by CRIT-4 session establishment)
    let _session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // 4. Client builds a data packet (simulating mimicry.build_packet)
    let ip_payload =
        b"\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\x0a\x00\x00\x02\x08\x08\x08\x08"; // Fake IPv4
    let inner_header = InnerHeader {
        inner_type: InnerType::Data,
        seq_num: 0,
    };
    let mut inner_payload = inner_header.encode().to_vec();
    inner_payload.extend_from_slice(ip_payload);

    let counter = 0u64;
    let pad_len = 16u16;
    let mut padded = Vec::new();
    padded.extend_from_slice(&pad_len.to_le_bytes());
    padded.extend_from_slice(&inner_payload);
    // Random padding
    for i in 0..pad_len {
        padded.push(i as u8);
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    let ciphertext = encrypt_payload(&client_keys.session_key, &nonce, &padded).unwrap();

    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&client_keys.tag_secret, counter, tw);

    let mdh = mask.header_template.clone();
    let mut wire = Vec::new();
    wire.extend_from_slice(&tag);
    wire.extend_from_slice(&mdh);
    wire.extend_from_slice(&ciphertext);

    // 5. Server receives packet
    // 5a. Tag lookup
    let session = mgr.get_session_by_tag(&tag.try_into().unwrap());
    assert!(session.is_some(), "Server must find session by tag");
    let session = session.unwrap();

    // 5b. Validate tag
    let validated_counter = session.lock().validate_tag(&tag);
    assert_eq!(validated_counter, Some((0, false)));

    // 5c. Decrypt
    let encrypted = &wire[TAG_SIZE + mdh.len()..];
    let server_keys = {
        let sess = session.lock();
        sess.keys.clone()
    };
    let decrypted = decrypt_payload(&server_keys.session_key, &nonce, encrypted).unwrap();

    // 5d. Strip padding
    let dec_pad_len = u16::from_le_bytes([decrypted[0], decrypted[1]]) as usize;
    assert_eq!(dec_pad_len, 16);
    let plaintext = &decrypted[2..decrypted.len() - dec_pad_len];

    // 5e. Parse inner header
    let inner = InnerHeader::decode(plaintext).unwrap();
    assert_eq!(inner.inner_type, InnerType::Data);
    assert_eq!(inner.seq_num, 0);
    let recovered_payload = &plaintext[4..];
    assert_eq!(recovered_payload, ip_payload);

    // 5f. Mark received (anti-replay)
    {
        let mut sess = session.lock();
        sess.mark_tag_received(0);
    }
}

/// Simulates 100 sequential data packets
#[test]
fn battle_full_pipeline_100_packets() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask.clone());

    let client_kp = KeyPair::generate();
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());

    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);

    for counter in 0u64..100 {
        let payload = format!("Packet #{counter}");
        let inner_header = InnerHeader {
            inner_type: InnerType::Data,
            seq_num: counter as u16,
        };
        let mut inner = inner_header.encode().to_vec();
        inner.extend_from_slice(payload.as_bytes());

        let pad_len = (counter % 32) as u16;
        let mut padded = Vec::new();
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner);
        for i in 0..pad_len {
            padded.push(i as u8);
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        let ct = encrypt_payload(&client_keys.session_key, &nonce, &padded).unwrap();
        let tag = generate_resonance_tag(&client_keys.tag_secret, counter, tw);

        // Server validates
        let found = mgr.get_session_by_tag(&tag);
        assert!(found.is_some(), "Counter {counter}: tag lookup failed");

        let valid = session.lock().validate_tag(&tag);
        assert!(valid.is_some(), "Counter {counter}: tag validation failed");

        // Decrypt
        let dec = decrypt_payload(&client_keys.session_key, &nonce, &ct).unwrap();
        let pl = u16::from_le_bytes([dec[0], dec[1]]) as usize;
        let data = &dec[2..dec.len() - pl];
        let hdr = InnerHeader::decode(data).unwrap();
        assert_eq!(hdr.inner_type, InnerType::Data);
        let recovered = &data[4..];
        assert_eq!(
            recovered,
            payload.as_bytes(),
            "Counter {counter}: payload mismatch"
        );

        // Mark received
        let mut sess = session.lock();
        sess.mark_tag_received(counter);
    }
}

/// Test control message pipeline
#[test]
fn battle_full_pipeline_control_messages() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask.clone());

    let client_kp = KeyPair::generate();
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());

    let _session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Test each control message type
    let controls = vec![
        ControlPayload::Keepalive { send_ts: 0 },
        ControlPayload::Shutdown { reason: 1 },
        ControlPayload::TelemetryRequest { metric_flags: 0xFF },
        ControlPayload::TimeSync {
            server_ts_ms: current_timestamp_ms(),
        },
        ControlPayload::KeyRotate {
            new_eph_pub: [0xAA; 32],
        },
    ];

    for (i, control) in controls.iter().enumerate() {
        let encoded = control.encode().unwrap();
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: i as u16,
        };
        let mut inner = inner_header.encode().to_vec();
        inner.extend_from_slice(&encoded);

        let pad_len = 8u16;
        let mut padded = Vec::new();
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner);
        padded.extend_from_slice(&[0u8; 8]);

        let counter = i as u64;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        let ct = encrypt_payload(&client_keys.session_key, &nonce, &padded).unwrap();

        // Server decrypts
        let dec = decrypt_payload(&client_keys.session_key, &nonce, &ct).unwrap();
        let pl = u16::from_le_bytes([dec[0], dec[1]]) as usize;
        let data = &dec[2..dec.len() - pl];

        let hdr = InnerHeader::decode(data).unwrap();
        assert_eq!(hdr.inner_type, InnerType::Control);

        let ctrl = ControlPayload::decode(&data[4..]).unwrap();
        // Verify type matches
        match (control, &ctrl) {
            (ControlPayload::Keepalive { .. }, ControlPayload::Keepalive { .. }) => {}
            (ControlPayload::Shutdown { reason: r1 }, ControlPayload::Shutdown { reason: r2 }) => {
                assert_eq!(r1, r2);
            }
            (
                ControlPayload::TelemetryRequest { metric_flags: f1 },
                ControlPayload::TelemetryRequest { metric_flags: f2 },
            ) => {
                assert_eq!(f1, f2);
            }
            (
                ControlPayload::TimeSync { server_ts_ms: t1 },
                ControlPayload::TimeSync { server_ts_ms: t2 },
            ) => {
                assert_eq!(t1, t2);
            }
            (
                ControlPayload::KeyRotate { new_eph_pub: k1 },
                ControlPayload::KeyRotate { new_eph_pub: k2 },
            ) => {
                assert_eq!(k1, k2);
            }
            _ => panic!("Control message type mismatch at index {i}"),
        }
    }
}

/// Test that wrong client's tag can't access another's session
#[test]
fn battle_cross_session_isolation() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    // Create two clients
    let client1_kp = KeyPair::generate();
    let client2_kp = KeyPair::generate();

    let session1 = mgr
        .create_session(make_addr(10000), client1_kp.public_key_bytes(), None, None)
        .unwrap();
    let session2 = mgr
        .create_session(make_addr(10001), client2_kp.public_key_bytes(), None, None)
        .unwrap();

    // Derive keys for both
    let shared1 = client1_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let keys1 = derive_session_keys(&shared1, None, &client1_kp.public_key_bytes());

    let shared2 = client2_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let keys2 = derive_session_keys(&shared2, None, &client2_kp.public_key_bytes());

    // Keys must be different
    assert_ne!(keys1.session_key, keys2.session_key);
    assert_ne!(keys1.tag_secret, keys2.tag_secret);

    // Client 1's tag should not validate on client 2's session
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag1 = generate_resonance_tag(&keys1.tag_secret, 0, tw);

    let found = mgr.get_session_by_tag(&tag1);
    assert!(found.is_some());
    // The found session should be session1, not session2
    let found_id = found.unwrap().lock().session_id;
    let session1_id = session1.lock().session_id;
    let session2_id = session2.lock().session_id;
    assert_eq!(found_id, session1_id);
    assert_ne!(found_id, session2_id);

    // Client 1's encrypted data can't be decrypted with client 2's key
    let mut nonce = [0u8; NONCE_SIZE];
    let ct = encrypt_payload(&keys1.session_key, &nonce, b"secret").unwrap();
    let result = decrypt_payload(&keys2.session_key, &nonce, &ct);
    assert!(result.is_err(), "Cross-session decryption must fail");
}

/// Server sign mask and verify
#[test]
fn battle_server_mask_signing() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key.clone(), mask);

    let mask_data = b"test mask binary data";
    let sig = mgr.sign_mask(mask_data);

    // Verify signature
    use ed25519_dalek::{Signature, Verifier};
    let vk = signing_key.verifying_key();
    let result = vk.verify(mask_data, &Signature::from_bytes(&sig));
    assert!(result.is_ok());
}

// ============================================================================
// Stress: Many Sessions
// ============================================================================

#[test]
fn battle_stress_100_sessions() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let mut all_tags = HashSet::new();

    for i in 0..100 {
        let client_kp = KeyPair::generate();
        // Capture tw immediately before create_session so the registered tag
        // and our lookup tag use the same (or adjacent) time window.
        // We also fall back to tw+1 in case the boundary is crossed during the call.
        let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let _session = mgr
            .create_session(
                make_unique_addr(i),
                client_kp.public_key_bytes(),
                None,
                None,
            )
            .unwrap();

        let shared = client_kp
            .compute_shared(&server_kp.public_key_bytes())
            .unwrap();
        let keys = derive_session_keys(&shared, None, &client_kp.public_key_bytes());

        let tag = generate_resonance_tag(&keys.tag_secret, 0, tw);
        let found = mgr.get_session_by_tag(&tag).or_else(|| {
            // Fallback: window may have advanced one step during create_session
            let tw_next = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
            let tag_next = generate_resonance_tag(&keys.tag_secret, 0, tw_next);
            mgr.get_session_by_tag(&tag_next)
        });
        assert!(found.is_some(), "Session {i} tag lookup failed");

        // Tags should be unique across sessions
        assert!(all_tags.insert(tag), "Tag collision at session {i}");
    }

    assert_eq!(mgr.session_count(), 100);
}

// ============================================================================
// PFS Ratchet Tests (CRIT-3 + HIGH-6)
// ============================================================================

#[test]
fn battle_ratchet_keys_created() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    let sess = session.lock();
    // Server should have generated ephemeral key and ratcheted keys
    assert!(
        sess.server_eph_pub.is_some(),
        "server_eph_pub must be populated"
    );
    assert!(
        sess.server_hello_signature.is_some(),
        "signature must be populated"
    );
    assert!(
        sess.ratcheted_keys.is_some(),
        "ratcheted_keys must be populated"
    );
    assert!(!sess.is_ratcheted, "Session should not be ratcheted yet");
    assert!(
        !sess.ratcheted_expected_tags.is_empty(),
        "Ratcheted tags must be pre-computed"
    );

    // Ratcheted keys must differ from initial keys
    let initial_key = sess.keys.session_key;
    let ratcheted_key = sess.ratcheted_keys.as_ref().unwrap().session_key;
    assert_ne!(
        initial_key, ratcheted_key,
        "Ratcheted keys must differ from initial"
    );
}

#[test]
fn battle_ratchet_tag_validation() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Generate tag using ratcheted keys (simulating client after receiving ServerHello)
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let ratcheted_tag_secret = {
        let sess = session.lock();
        sess.ratcheted_keys.as_ref().unwrap().tag_secret
    };
    let tag = generate_resonance_tag(&ratcheted_tag_secret, 0, tw);

    // Tag should be findable via tag_map
    let found = mgr.get_session_by_tag(&tag);
    assert!(found.is_some(), "Ratcheted tag must be in tag_map");

    // validate_tag should indicate ratcheted match
    let sess = session.lock();
    let result = sess.validate_tag(&tag);
    assert!(result.is_some(), "Ratcheted tag must validate");
    let (counter, is_ratcheted) = result.unwrap();
    assert_eq!(counter, 0);
    assert!(is_ratcheted, "Tag must be identified as ratcheted");
}

#[test]
#[ignore]
fn battle_complete_ratchet() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Save initial and ratcheted key material
    let (initial_key, ratcheted_key, session_id, initial_tag_secret, ratcheted_tag_secret) = {
        let sess = session.lock();
        (
            sess.keys.session_key,
            sess.ratcheted_keys.as_ref().unwrap().session_key,
            sess.session_id,
            sess.keys.tag_secret,
            sess.ratcheted_keys.as_ref().unwrap().tag_secret,
        )
    };

    // Complete the ratchet
    mgr.complete_session_ratchet(&session_id);

    // After ratchet: keys should be the ratcheted keys
    let sess = session.lock();
    assert!(sess.is_ratcheted, "Session must be marked as ratcheted");
    assert_eq!(
        sess.keys.session_key, ratcheted_key,
        "Keys must switch to ratcheted"
    );
    assert!(
        sess.ratcheted_keys.is_none(),
        "Ratcheted keys should be consumed"
    );
    assert!(
        sess.server_eph_pub.is_none(),
        "Ephemeral key should be cleared"
    );
    assert!(
        sess.ratcheted_expected_tags.is_empty(),
        "Ratcheted tags should be moved"
    );

    // Initial key tags should no longer validate
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let old_tag = generate_resonance_tag(&initial_tag_secret, 0, tw);
    assert!(
        sess.validate_tag(&old_tag).is_none(),
        "Old tags must be invalid after ratchet"
    );

    // Ratcheted tags should validate as normal (not ratcheted anymore, they're "initial" now)
    let new_tag = generate_resonance_tag(&ratcheted_tag_secret, 0, tw);
    let result = sess.validate_tag(&new_tag);
    assert!(
        result.is_some(),
        "Ratcheted tags must validate after ratchet"
    );
    let (counter, is_ratcheted) = result.unwrap();
    assert_eq!(counter, 0);
    assert!(
        !is_ratcheted,
        "After ratchet, tags are 'initial' (active) keys"
    );
}

#[test]
fn battle_server_hello_roundtrip() {
    use aivpn_common::protocol::ControlPayload;

    let server_eph_pub = [0xABu8; 32];
    let signature = [0xCDu8; 64];

    let hello = ControlPayload::ServerHello {
        server_eph_pub,
        signature,
        network_config: None,
    };

    let encoded = hello.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();

    match decoded {
        ControlPayload::ServerHello {
            server_eph_pub: pub_key,
            signature: sig,
            network_config,
        } => {
            assert_eq!(pub_key, server_eph_pub);
            assert_eq!(sig, signature);
            assert!(network_config.is_none());
        }
        _ => panic!("Expected ServerHello"),
    }
}

#[test]
fn battle_eph_pub_obfuscation() {
    let original = [0x42u8; 32];
    let server_pub = [0x99u8; 32];

    // Obfuscate
    let mut obfuscated = original;
    crypto::obfuscate_eph_pub(&mut obfuscated, &server_pub);
    assert_ne!(obfuscated, original, "Obfuscated must differ from original");

    // Deobfuscate (same operation — XOR is self-inverse)
    crypto::obfuscate_eph_pub(&mut obfuscated, &server_pub);
    assert_eq!(obfuscated, original, "Deobfuscation must recover original");
}

#[test]
fn battle_per_ip_session_limit() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp, signing_key, mask);

    let addr = make_addr(10000);

    // Create 5 sessions from same IP (should succeed)
    for i in 0..5 {
        let client_kp = KeyPair::generate();
        let result = mgr.create_session(addr, client_kp.public_key_bytes(), None, None);
        assert!(result.is_ok(), "Session {i} from same IP should succeed");
    }

    // 6th session from same IP should fail (MED-6 limit)
    let client_kp = KeyPair::generate();
    let result = mgr.create_session(addr, client_kp.public_key_bytes(), None, None);
    assert!(result.is_err(), "6th session from same IP must be rejected");
}

#[test]
fn battle_refresh_session_tags() {
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Advance counter and update tag window
    let session_id = {
        let mut sess = session.lock();
        for i in 0..10u64 {
            sess.counter = i;
            sess.mark_tag_received(i);
        }
        sess.counter = 10;
        sess.update_tag_window();
        sess.session_id
    };

    // Refresh tags in tag_map
    mgr.refresh_session_tags(&session_id);

    // New tags (counter 10+) should be findable
    let client_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_keys = derive_session_keys(&client_shared, None, &client_kp.public_key_bytes());
    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&client_keys.tag_secret, 10, tw);
    let found = mgr.get_session_by_tag(&tag);
    assert!(
        found.is_some(),
        "Tag for counter 10 must be findable after refresh"
    );
}

#[test]
fn battle_ratchet_full_crypto_pipeline() {
    // Full end-to-end: session creation → ratchet keys → encrypt with DH2 → decrypt with DH2
    let server_kp = KeyPair::generate();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mask = webrtc_zoom_v3();
    let mgr = SessionManager::new(server_kp.clone(), signing_key, mask);

    let client_kp = KeyPair::generate();
    let session = mgr
        .create_session(make_addr(10000), client_kp.public_key_bytes(), None, None)
        .unwrap();

    // Client-side: derive ratcheted keys (simulating ServerHello processing)
    let (server_eph_pub, server_hello_sig, initial_session_key) = {
        let sess = session.lock();
        (
            sess.server_eph_pub.unwrap(),
            sess.server_hello_signature.unwrap(),
            sess.keys.session_key,
        )
    };

    // Verify Ed25519 signature (HIGH-6: server auth)
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let vk = VerifyingKey::from(&signing_key);
        let mut message = Vec::new();
        message.extend_from_slice(&server_eph_pub);
        message.extend_from_slice(&client_kp.public_key_bytes());
        let sig = Signature::from_bytes(&server_hello_sig);
        vk.verify(&message, &sig)
            .expect("Server signature must verify");
    }

    // Client computes DH2 and ratcheted keys
    let client_dh2 = client_kp.compute_shared(&server_eph_pub).unwrap();
    let client_initial_shared = client_kp
        .compute_shared(&server_kp.public_key_bytes())
        .unwrap();
    let client_initial_keys =
        derive_session_keys(&client_initial_shared, None, &client_kp.public_key_bytes());
    let client_ratcheted = derive_session_keys(
        &client_dh2,
        Some(&client_initial_keys.session_key),
        &client_kp.public_key_bytes(),
    );

    // Encrypt a packet with ratcheted keys (as client would)
    let payload = b"PFS-protected data";
    let mut nonce = [0u8; NONCE_SIZE];
    // counter = 0 for ratcheted session
    let ciphertext = encrypt_payload(&client_ratcheted.session_key, &nonce, payload).unwrap();

    // Server decrypts with its ratcheted keys
    let server_ratcheted_key = {
        let sess = session.lock();
        sess.ratcheted_keys.as_ref().unwrap().session_key
    };
    let decrypted = decrypt_payload(&server_ratcheted_key, &nonce, &ciphertext).unwrap();
    assert_eq!(
        &decrypted, payload,
        "PFS ratcheted encryption must round-trip"
    );

    // Complete ratchet and verify keys match
    assert_eq!(
        client_ratcheted.session_key, server_ratcheted_key,
        "Client and server ratcheted keys must match"
    );
}

// ============================================================================
// Neural Resonance Module Tests (Patent 1 — Signal Reconstruction Resonance)
// ============================================================================

use aivpn_server::gateway::MaskCatalog;
use aivpn_server::neural::{NeuralConfig, NeuralResonanceModule, ResonanceResult, ResonanceStatus};

#[test]
fn test_neural_module_init() {
    let config = NeuralConfig::default();
    let module = NeuralResonanceModule::new(config);
    assert!(module.is_ok(), "Neural module must initialize successfully");
}

#[test]
fn test_neural_module_load_model() {
    let config = NeuralConfig::default();
    let mut module = NeuralResonanceModule::new(config).unwrap();
    let result = module.load_model();
    assert!(result.is_ok(), "Model loading (mock) must succeed");
}

#[test]
fn test_neural_register_mask_signature() {
    let config = NeuralConfig::default();
    let mut module = NeuralResonanceModule::new(config).unwrap();
    let mask = webrtc_zoom_v3();
    let result = module.register_mask(&mask);
    assert!(result.is_ok(), "Mask registration must succeed");
}

#[test]
fn test_neural_record_traffic() {
    let config = NeuralConfig::default();
    let module = NeuralResonanceModule::new(config).unwrap();
    let session_id = [0xABu8; 16];
    // Record several packets
    for i in 0..50 {
        module.record_traffic(session_id, 128 + i, 12.5, 7.2, true);
    }
    let stats = module.get_or_create_stats(session_id);
    assert_eq!(
        stats.packet_sizes.len(),
        50,
        "Must have recorded 50 packets"
    );
}

#[test]
fn test_neural_resonance_skip_no_model() {
    let config = NeuralConfig::default();
    let module = NeuralResonanceModule::new(config).unwrap();
    let session_id = [0xCDu8; 16];
    let result = module
        .check_resonance(session_id, "webrtc_zoom_v3")
        .unwrap();
    assert_eq!(
        result.status,
        ResonanceStatus::Skip,
        "Must skip when model not loaded"
    );
}

#[test]
fn test_neural_resonance_skip_no_stats() {
    let config = NeuralConfig::default();
    let mut module = NeuralResonanceModule::new(config).unwrap();
    module.load_model().unwrap();
    let mask = webrtc_zoom_v3();
    module.register_mask(&mask).unwrap();

    let session_id = [0xEFu8; 16];
    let result = module
        .check_resonance(session_id, "webrtc_zoom_v3")
        .unwrap();
    assert_eq!(
        result.status,
        ResonanceStatus::Skip,
        "Must skip with no traffic stats"
    );
}

#[test]
fn test_neural_resonance_check_with_data() {
    let config = NeuralConfig::default();
    let mut module = NeuralResonanceModule::new(config).unwrap();
    module.load_model().unwrap();
    let mask = webrtc_zoom_v3();
    module.register_mask(&mask).unwrap();

    let session_id = [0x11u8; 16];
    // Populate with traffic data
    for i in 0..100 {
        module.record_traffic(
            session_id,
            64 + (i % 200),
            10.0 + (i as f64 * 0.1),
            7.5,
            true,
        );
    }

    let result = module
        .check_resonance(session_id, "webrtc_zoom_v3")
        .unwrap();
    assert_ne!(
        result.status,
        ResonanceStatus::Skip,
        "Must not skip with sufficient data"
    );
    assert!(result.mse >= 0.0, "MSE must be non-negative");
}

#[test]
fn test_neural_anomaly_detector_normal() {
    let config = NeuralConfig::default();
    let mut module = NeuralResonanceModule::new(config).unwrap();
    // Record normal metrics from several reporters
    for r in 0u8..4 {
        for _ in 0..20 {
            module.record_telemetry("webrtc_zoom_v3", [r; 16], 0.005, 30.0);
        }
    }
    assert!(
        !module.is_mask_anomalous("webrtc_zoom_v3"),
        "Normal traffic should not be anomalous"
    );
}

#[test]
fn test_neural_anomaly_detector_high_loss() {
    let config = NeuralConfig::default();
    let mut module = NeuralResonanceModule::new(config).unwrap();
    // Anomalous packet loss (5x baseline) must be corroborated by multiple
    // distinct reporters before it counts (anti single-client DoS).
    for r in 0u8..3 {
        for _ in 0..20 {
            module.record_telemetry("webrtc_zoom_v3", [r; 16], 0.10, 30.0);
        }
    }
    assert!(
        module.is_mask_anomalous("webrtc_zoom_v3"),
        "10% packet loss from 3 reporters must trigger anomaly"
    );
    // A single reporter alone must NOT.
    let mut solo = NeuralResonanceModule::new(NeuralConfig::default()).unwrap();
    for _ in 0..50 {
        solo.record_telemetry("webrtc_zoom_v3", [42; 16], 0.10, 30.0);
    }
    assert!(
        !solo.is_mask_anomalous("webrtc_zoom_v3"),
        "single reporter must not be able to forge an anomaly"
    );
}

#[test]
fn test_neural_anomaly_detector_high_rtt() {
    let config = NeuralConfig::default();
    let mut module = NeuralResonanceModule::new(config).unwrap();
    // Anomalous RTT (3x baseline = 150ms) corroborated by multiple reporters.
    for r in 0u8..3 {
        for _ in 0..20 {
            module.record_telemetry("quic_https_v2", [r; 16], 0.001, 200.0);
        }
    }
    assert!(
        module.is_mask_anomalous("quic_https_v2"),
        "200ms RTT from 3 reporters must trigger anomaly"
    );
}

#[test]
fn test_neural_cleanup_stats() {
    let config = NeuralConfig::default();
    let module = NeuralResonanceModule::new(config).unwrap();
    let session_id = [0x22u8; 16];
    module.record_traffic(session_id, 100, 10.0, 7.0, true);
    module.cleanup_stats(session_id);
    // After cleanup, get_or_create_stats should return empty stats
    let stats = module.get_or_create_stats(session_id);
    assert!(
        stats.packet_sizes.is_empty(),
        "Stats must be empty after cleanup"
    );
}

// ============================================================================
// Mask Catalog Tests (Patent 3 — Self-Expanding Cognitive System)
// ============================================================================

#[test]
fn test_mask_catalog_init() {
    let catalog = MaskCatalog::new();
    assert_eq!(
        catalog.available_count(),
        0,
        "Catalog must start empty (masks loaded from disk)"
    );
}

#[test]
fn test_mask_catalog_register() {
    let catalog = MaskCatalog::new();
    let mask1 = webrtc_zoom_v3();
    catalog.register_mask(mask1);
    let mut custom_mask = webrtc_zoom_v3();
    custom_mask.mask_id = "custom_dns_tunnel_v1".to_string();
    catalog.register_mask(custom_mask);
    assert_eq!(
        catalog.available_count(),
        2,
        "Catalog must have 2 masks after registration"
    );
}

#[test]
fn test_mask_catalog_compromised() {
    let catalog = MaskCatalog::new();
    let mask1 = webrtc_zoom_v3();
    catalog.register_mask(mask1);
    let mask2 = aivpn_common::mask::preset_masks::quic_https_v2();
    catalog.register_mask(mask2);
    catalog.mark_compromised_with_fallback("webrtc_zoom_v3");
    assert_eq!(
        catalog.available_count(),
        1,
        "One mask left after compromise"
    );
    // Compromised mask should not be re-registered
    let mask = webrtc_zoom_v3();
    catalog.register_mask(mask);
    assert_eq!(
        catalog.available_count(),
        1,
        "Compromised mask must not be re-registered"
    );
}

#[test]
fn test_mask_catalog_select_fallback() {
    let catalog = MaskCatalog::new();
    let mask1 = webrtc_zoom_v3();
    catalog.register_mask(mask1);
    let mask2 = aivpn_common::mask::preset_masks::quic_https_v2();
    catalog.register_mask(mask2);
    let fallback = catalog.select_fallback("webrtc_zoom_v3");
    assert!(fallback.is_some(), "Must have a fallback mask");
    assert_eq!(
        fallback.unwrap().mask_id,
        "quic_https_v2",
        "Fallback must be the other mask"
    );
}

// H1 fix: compromising a mask is now refused when doing so would leave the
// catalog with nothing to fall back to. The old behavior (asserted by this
// test before the fix) let the catalog empty out entirely once every mask
// had tripped a detector, which permanently locked out every future
// handshake — see MaskCatalog::mark_compromised_with_fallback's doc comment.
#[test]
fn test_mask_catalog_second_compromise_refused_when_it_would_empty_catalog() {
    let catalog = MaskCatalog::new();
    let mask1 = webrtc_zoom_v3();
    catalog.register_mask(mask1);
    let mask2 = aivpn_common::mask::preset_masks::quic_https_v2();
    catalog.register_mask(mask2);

    let first = catalog.mark_compromised_with_fallback("webrtc_zoom_v3");
    assert_eq!(
        first.map(|m| m.mask_id),
        Some("quic_https_v2".to_string()),
        "first compromise succeeds — a fallback exists"
    );
    assert_eq!(catalog.available_count(), 1);

    // Compromising the LAST remaining mask must be refused, not empty the
    // catalog down to zero.
    let second = catalog.mark_compromised_with_fallback("quic_https_v2");
    assert!(
        second.is_none(),
        "compromising the last mask must be refused"
    );
    assert_eq!(
        catalog.available_count(),
        1,
        "the last mask must remain available — the server must never go fully deaf"
    );
}

// ============================================================================
// Session Mask Rotation Tests (Patent 3 — Integration)
// ============================================================================

#[test]
#[ignore]
fn test_session_mask_update() {
    let (mgr, _) = make_session_manager();
    let client_kp = KeyPair::generate();
    let addr = make_addr(30000);
    let session = mgr
        .create_session(addr, client_kp.public_key_bytes(), None, None)
        .unwrap();
    let session_id = session.lock().session_id;

    // Initially no mask set
    assert!(session.lock().mask.is_none());

    // Update mask
    use aivpn_common::mask::preset_masks::quic_https_v2;
    let new_mask = quic_https_v2();
    mgr.update_session_mask(&session_id, new_mask);

    let sess = session.lock();
    assert!(sess.mask.is_some());
    assert_eq!(sess.mask.as_ref().unwrap().mask_id, "quic_https_v2");
    assert_eq!(sess.state, SessionState::Active);
    assert_eq!(sess.fsm_state, 0, "FSM must reset after mask change");
}

// ============================================================================
// Metrics Tests
// ============================================================================

use aivpn_server::metrics::MetricsCollector;

#[test]
fn test_metrics_collector() {
    let collector = MetricsCollector::new();
    // Should not panic
    collector.record_packet_received(1024);
    collector.record_packet_sent(512);
    collector.record_processing_time(0.001);
    collector.record_mask_rotation();
    collector.record_key_rotation();
    collector.record_neural_check(false);
    collector.record_neural_check(true);
    collector.record_dpi_attack();
    collector.update_session_count(10, 8);
}

// ============================================================================
// Key Rotation Tests
// ============================================================================

use aivpn_server::key_rotation::{KeyRotationConfig, KeyRotator};

#[test]
fn test_key_rotator_init() {
    let config = KeyRotationConfig::default();
    let rotator = KeyRotator::new(config);
    assert!(rotator.is_ok());
}

#[test]
fn test_key_rotator_needs_rotation_data() {
    let config = KeyRotationConfig {
        time_interval_secs: 3600, // Large time window
        data_interval_bytes: 100, // Small data threshold
        enable_auto_rotation: true,
    };
    let mut rotator = KeyRotator::new(config).unwrap();
    assert!(
        !rotator.needs_rotation(),
        "Should not need rotation initially"
    );

    rotator.record_bytes(50);
    assert!(!rotator.needs_rotation(), "50 < 100 threshold");

    rotator.record_bytes(60);
    assert!(
        rotator.needs_rotation(),
        "110 >= 100 threshold — rotation needed"
    );
}

#[test]
fn test_key_rotator_rotate() {
    let config = KeyRotationConfig::default();
    let mut rotator = KeyRotator::new(config).unwrap();
    let old_pub = rotator.current_public_key();

    let event = rotator.rotate_keys().unwrap();
    // Since old_eph_pub was removed, we should probably check what the event contains or simply remove the assert if old_eph_pub is no longer part of KeyRotationEvent.
    // Wait, let me check the actual code first before applying blind replacements.
    assert_ne!(event.new_eph_pub, old_pub, "New key must differ from old");

    // Commit rotation
    rotator.commit_rotation();
    assert_eq!(
        rotator.current_public_key(),
        event.new_eph_pub,
        "Current key must be the new key after commit"
    );
}

// ============================================================================
// Passive Mask Distribution Tests
// ============================================================================

use aivpn_server::passive_distribution::{PassiveDistributionConfig, PassiveMaskReceiver};

#[test]
fn test_passive_distribution_disabled() {
    let config = PassiveDistributionConfig::default();
    assert!(
        !config.enable,
        "Passive distribution should be disabled by default"
    );
    let receiver = PassiveMaskReceiver::new(config);
    assert!(receiver.get_all_masks().is_empty());
}

// ============================================================================
// Gateway Config Tests
// ============================================================================

use aivpn_server::gateway::GatewayConfig;

#[test]
fn test_gateway_config_default_has_neural() {
    let config = GatewayConfig::default();
    assert!(config.enable_neural, "Neural must be enabled by default");
    assert_eq!(config.neural_config.check_interval_secs, 30);
    // Warm-up default calibrated against realcap2 healthy-traffic MSE
    // (overall p99 ≈ 0.26, live-stand max ≈ 0.31) — see neural.rs Default impl.
    assert_eq!(config.neural_config.compromised_threshold, 0.50);
}

#[test]
fn test_gateway_creation_with_neural() {
    use aivpn_server::Gateway;
    // Create temp mask dir with a mask file
    let mask_dir = std::path::PathBuf::from("/tmp/aivpn-test-gateway-masks");
    let _ = std::fs::create_dir_all(&mask_dir);
    let mask = webrtc_zoom_v3();
    let json = serde_json::to_string_pretty(&mask).unwrap();
    std::fs::write(mask_dir.join(format!("{}.json", mask.mask_id)), &json).unwrap();
    std::fs::write(mask_dir.join(format!("{}.stats", mask.mask_id)), "{}").unwrap();
    let mut config = GatewayConfig::default();
    config.mask_dir = mask_dir;
    let gateway = Gateway::new(config);
    assert!(
        gateway.is_ok(),
        "Gateway must create successfully with neural module"
    );
}
