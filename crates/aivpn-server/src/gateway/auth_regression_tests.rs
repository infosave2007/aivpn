//! Проверки границы допуска без запуска TUN, NAT и packet loop.

use super::*;
use aivpn_common::client_wire::{
    build_inner_packet, build_shaped_mdh_packet, obfuscate_client_eph_pub,
    process_server_hello_with_offsets, RecvWindow,
};
use aivpn_common::crypto::KeyPair;
use aivpn_common::mask::preset_masks;

#[tokio::test]
async fn neural_startup_loads_weights_before_catalog_registration_and_reports_bad_library() {
    let directory = tempfile::tempdir().unwrap();
    let mask_dir = directory.path().join("masks");
    std::fs::create_dir(&mask_dir).unwrap();
    let mut mask = preset_masks::webrtc_zoom_v3();
    mask.sign(&ed25519_dalek::SigningKey::from_bytes(&[71; 32]))
        .unwrap();
    std::fs::write(
        mask_dir.join(format!("{}.json", mask.mask_id)),
        serde_json::to_vec(&mask).unwrap(),
    )
    .unwrap();
    let mut config = GatewayConfig {
        mask_dir,
        mask_signing_key: Some([71; 32]),
        client_db: Some(Arc::new(
            crate::client_db::ClientDatabase::load(
                &directory.path().join("clients.json"),
                aivpn_common::network_config::VpnNetworkConfig::default(),
            )
            .unwrap(),
        )),
        enable_nat: false,
        enable_neural: true,
        ..Default::default()
    };
    let gateway = Gateway::new(config.clone()).unwrap();
    assert!(gateway
        .neural_module
        .lock()
        .has_trained_encoder(&mask.mask_id));
    let broken = directory.path().join("broken-models.json");
    std::fs::write(&broken, "{}").unwrap();
    config.neural_config.trained_models_file = Some(broken);
    assert!(Gateway::new(config).is_err());
}

#[tokio::test]
async fn rtc_control_requires_pfs_admission_and_selected_profile() {
    let directory = tempfile::tempdir().unwrap();
    let mask_dir = directory.path().join("masks");
    std::fs::create_dir(&mask_dir).unwrap();
    let mut mask = preset_masks::webrtc_zoom_v3();
    crate::test_masks::sign(&mut mask, &ed25519_dalek::SigningKey::from_bytes(&[71; 32]));
    std::fs::write(
        mask_dir.join(format!("{}.json", mask.mask_id)),
        serde_json::to_vec(&mask).unwrap(),
    )
    .unwrap();
    let mut gateway = Gateway::new(GatewayConfig {
        mask_dir,
        mask_signing_key: Some([71; 32]),
        client_db: Some(Arc::new(
            crate::client_db::ClientDatabase::load(
                &directory.path().join("clients.json"),
                aivpn_common::network_config::VpnNetworkConfig::default(),
            )
            .unwrap(),
        )),
        enable_nat: false,
        enable_neural: false,
        ..Default::default()
    })
    .unwrap();
    let raw = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server = raw.local_addr().unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = peer.local_addr().unwrap();
    let socket = super::MaskSocket::new(raw);
    gateway.udp_socket = Some(socket.clone());
    let session = gateway
        .session_manager
        .create_session(address, [7; 32], None, None)
        .unwrap();
    session.lock().mask = Some(mask.clone());
    let rtc = aivpn_common::rtc_mask::RtcMask::new(false, address, server, server, Instant::now())
        .unwrap();
    let offer = aivpn_common::mask_state::MaskState {
        offer_id: [3; 16],
        answer: false,
        mask_id: mask.mask_id,
        mask_version: mask.version,
        parameters: rtc.parameters().into(),
    };
    let control = ControlPayload::MaskState(offer.clone()).encode().unwrap();
    assert!(gateway
        .handle_control_message(&control, &session, address)
        .await
        .is_err());
    assert!(!socket.is_stateful(address));
    session.lock().is_ratcheted = true;
    assert!(gateway
        .handle_control_message(&control, &session, address)
        .await
        .is_err());
    assert!(!socket.is_stateful(address));
    session.lock().client_admitted = true;
    let mut wrong = offer.clone();
    wrong.mask_version += 1;
    assert!(gateway
        .handle_control_message(
            &ControlPayload::MaskState(wrong).encode().unwrap(),
            &session,
            address
        )
        .await
        .is_err());
    assert!(!socket.is_stateful(address));
    gateway
        .handle_control_message(&control, &session, address)
        .await
        .unwrap();
    assert!(socket.is_stateful(address));
    socket.use_plain_mask(address);
}

#[tokio::test]
async fn masked_peer_initial_replay_cannot_remove_live_or_pending_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let mask_dir = directory.path().join("masks");
    std::fs::create_dir(&mask_dir).unwrap();
    let mut mask = preset_masks::webrtc_zoom_v3();
    crate::test_masks::sign(&mut mask, &ed25519_dalek::SigningKey::from_bytes(&[71; 32]));
    std::fs::write(
        mask_dir.join(format!("{}.json", mask.mask_id)),
        serde_json::to_vec(&mask).unwrap(),
    )
    .unwrap();
    let database = Arc::new(
        crate::client_db::ClientDatabase::load(
            &directory.path().join("clients.json"),
            aivpn_common::network_config::VpnNetworkConfig::default(),
        )
        .unwrap(),
    );
    let pool_key = crypto::pool_server_keypair(&[7; 32]);
    let pool_psk = crypto::pool_client_psk(&[7; 32]);
    let mut gateway = Gateway::new(GatewayConfig {
        mask_dir,
        client_db: Some(database),
        mask_signing_key: Some([71; 32]),
        pool_server_keypair: Some(pool_key.clone()),
        pool_client_psk: Some(pool_psk),
        enable_nat: false,
        enable_neural: false,
        // Пул доказывает личность узла, а не сертификат конечного устройства.
        mtls: Some(crate::mtls::MtlsConfig {
            ca_public_key_hex: None,
            required: true,
        }),
        ..Default::default()
    })
    .unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = peer.local_addr().unwrap();
    gateway.udp_socket = Some(super::MaskSocket::new(Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    )));

    let live = gateway
        .session_manager
        .create_masked_pool_peer_session(
            address,
            KeyPair::generate().public_key_bytes(),
            &pool_key,
            &pool_psk,
        )
        .unwrap();
    let live_id = live.lock().session_id;
    gateway.session_manager.complete_session_ratchet(&live_id);
    {
        let mut state = live.lock();
        state.client_admitted = true;
        state.verified_node_id = Some("verified-peer".into());
        state.mask = Some(mask.clone());
    }
    let old_pending = gateway
        .session_manager
        .create_masked_pool_peer_session(
            address,
            KeyPair::generate().public_key_bytes(),
            &pool_key,
            &pool_psk,
        )
        .unwrap();
    let pending_id = old_pending.lock().session_id;
    old_pending.lock().mask = Some(mask.clone());

    let client = KeyPair::generate();
    let shared = client.compute_shared(&pool_key.public_key_bytes()).unwrap();
    let mut keys =
        crypto::derive_initial_session_keys(&shared, Some(&pool_psk), &client.public_key_bytes());
    let inner = build_inner_packet(
        InnerType::Control,
        0,
        &ControlPayload::Keepalive { send_ts: 17 }.encode().unwrap(),
    );
    let ephemeral = obfuscate_client_eph_pub(&client, &pool_key.public_key_bytes());
    let initial = build_shaped_mdh_packet(
        &keys,
        &mut 0,
        &inner,
        Some(&ephemeral),
        mask.mdh_len(),
        &mask,
    )
    .unwrap();
    let mut corrupt = initial.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(gateway.handle_packet(&corrupt, address).await.is_err());
    assert!(gateway.session_manager.get_session(&live_id).is_some());
    assert!(gateway.session_manager.get_session(&pending_id).is_some());
    assert!(
        peer.try_recv(&mut [0; 4096]).is_err(),
        "До AEAD не должно быть Hello"
    );

    gateway.handshake_cooldowns.remove(&address);
    gateway.handle_packet(&initial, address).await.unwrap();
    let replacement = gateway
        .session_manager
        .iter_sessions()
        .map(|entry| entry.value().clone())
        .find(|session| session.lock().eph_pub == client.public_key_bytes())
        .unwrap();
    let replacement_id = replacement.lock().session_id;
    assert!(!replacement.lock().client_admitted);
    assert!(gateway.session_manager.get_session(&live_id).is_some());
    assert!(gateway.session_manager.get_session(&pending_id).is_some());

    let mut reply = [0; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let mut outgoing = 0;
    process_server_hello_with_offsets(
        &reply[..n],
        &mut keys,
        &client,
        &mut RecvWindow::new(),
        &mut outgoing,
        mask.mdh_len(),
        None,
        &[mask.tag_offset],
    )
    .unwrap();
    assert_eq!(keys.packet_cipher, crypto::PacketCipher::Established);

    // Повтор уже использованного initial не выполняет cleanup повторно.
    let _ = gateway.handle_packet(&initial, address).await;
    assert!(gateway.session_manager.get_session(&live_id).is_some());
    assert!(gateway.session_manager.get_session(&pending_id).is_some());
    assert!(gateway
        .session_manager
        .get_session(&replacement_id)
        .is_some());

    let confirmation =
        build_shaped_mdh_packet(&keys, &mut outgoing, &inner, None, mask.mdh_len(), &mask).unwrap();
    gateway.handle_packet(&confirmation, address).await.unwrap();
    assert!(replacement.lock().client_admitted);
    assert!(
        gateway.session_manager.get_session(&pending_id).is_none(),
        "PFS допускает cleanup незавершенного peer"
    );
    assert!(
        gateway.session_manager.get_session(&live_id).is_some(),
        "NodeEnrollment еще не подтвердил замену проверенной личности"
    );
}
