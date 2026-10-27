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

struct InlineIngressFixture {
    _directory: tempfile::TempDir,
    gateway: Gateway,
    session: Arc<parking_lot::Mutex<Session>>,
    mask: MaskProfile,
    old_keys: crypto::SessionKeys,
    peer: SocketAddr,
    delivered: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

fn inline_ingress_fixture() -> InlineIngressFixture {
    inline_ingress_fixture_with_base(1000)
}

fn inline_ingress_fixture_with_base(precomputed_base: u64) -> InlineIngressFixture {
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
    gateway.mask_catalog.register_mask(mask.clone());
    let peer = "203.0.113.91:41001".parse().unwrap();
    let session = gateway
        .session_manager
        .create_session(peer, KeyPair::generate().public_key_bytes(), None, None)
        .unwrap();
    let old_keys = crypto::derive_session_keys(&[31; 32], None, &[32; 32]);
    let id = {
        let mut state = session.lock();
        state.keys = old_keys.clone();
        state.mask = Some(mask.clone());
        state.is_ratcheted = true;
        state.client_admitted = true;
        state.bootstrap_descriptors_sent = true;
        state.is_site_peer = true;
        state.vpn_ip = Some("10.0.0.2".parse().unwrap());
        state.ratcheted_keys = None;
        state.ratcheted_expected_tags.clear();
        state.mark_tag_received(precomputed_base);
        state.pending_rekey_keypair = Some(KeyPair::generate());
        state.update_tag_window();
        state.mark_tag_received(1000);
        assert!(state.expected_tags.contains_key(&1701));
        state.session_id
    };
    gateway
        .session_manager
        .commit_session_rekey(&id, &KeyPair::generate().public_key_bytes());
    let (sender, delivered) = tokio::sync::mpsc::channel(1);
    gateway.tun_write_tx = Some(sender);
    InlineIngressFixture {
        _directory: directory,
        gateway,
        session,
        mask,
        old_keys,
        peer,
        delivered,
    }
}

fn inline_data_packet(
    keys: &crypto::SessionKeys,
    mut counter: u64,
    mask: &MaskProfile,
) -> (Vec<u8>, Vec<u8>) {
    let mut ip = vec![0; 24];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&24u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
    ip[16..20].copy_from_slice(&[8, 8, 8, 8]);
    ip[20..24].copy_from_slice(&(counter as u32).to_be_bytes());
    let inner = build_inner_packet(InnerType::Data, 0, &ip);
    let packet =
        build_shaped_mdh_packet(keys, &mut counter, &inner, None, mask.mdh_len(), mask).unwrap();
    (packet, ip)
}

fn inline_primary_bitmap(session: &Session) -> Vec<bool> {
    (0..512)
        .map(|bit| session.received_bitmap.bit_set(bit))
        .collect()
}

async fn deliver_inline_data(fixture: &mut InlineIngressFixture, counter: u64, old: bool) {
    let keys = if old {
        fixture.old_keys.clone()
    } else {
        fixture.session.lock().keys.clone()
    };
    let (packet, ip) = inline_data_packet(&keys, counter, &fixture.mask);
    fixture
        .gateway
        .handle_packet(&packet, fixture.peer)
        .await
        .unwrap();
    assert_eq!(
        fixture.delivered.try_recv().unwrap(),
        ip,
        "AEAD DATA со счетчиком {counter} должен дойти до TUN-очереди"
    );
}

#[tokio::test]
async fn inline_old_data_refreshes_index_without_consuming_primary_replay() {
    let mut fixture = inline_ingress_fixture();
    let before = inline_primary_bitmap(&fixture.session.lock());
    let mut refreshes = 0;
    let mut base = fixture.session.lock().tag_window_base;
    for counter in 1001..=1700 {
        deliver_inline_data(&mut fixture, counter, true).await;
        let state = fixture.session.lock();
        assert_eq!(state.counter, 1000);
        assert_eq!(inline_primary_bitmap(&state), before);
        assert!(state.pre_ratchet_received.contains(&counter));
        if state.tag_window_base != base {
            refreshes += 1;
            base = state.tag_window_base;
        }
    }
    assert!(
        base >= 1640,
        "700 принятых old-key DATA должны сдвинуть индекс: base={base}"
    );
    assert!(
        refreshes <= 6,
        "Индекс обновлен {refreshes} раз на 700 DATA"
    );
}

#[tokio::test]
async fn inline_old_data_keeps_first_new_data_indexed_after_grace() {
    for expire_grace in [false, true] {
        let mut fixture = inline_ingress_fixture();
        let before = inline_primary_bitmap(&fixture.session.lock());
        for counter in 1001..=1700 {
            deliver_inline_data(&mut fixture, counter, true).await;
        }
        {
            let state = fixture.session.lock();
            assert_eq!(state.counter, 1000);
            assert_eq!(inline_primary_bitmap(&state), before);
        }
        if expire_grace {
            fixture.session.lock().pre_ratchet_expire =
                Some(Instant::now() - Duration::from_secs(1));
            fixture.gateway.session_manager.cleanup_expired();
            assert!(fixture.session.lock().pre_ratchet_keys.is_none());
        }
        let keys = fixture.session.lock().keys.clone();
        let (packet, _) = inline_data_packet(&keys, 1701, &fixture.mask);
        let tag = super::extract_tag_for_layout(&packet, fixture.mask.tag_offset).unwrap();
        assert!(
            fixture
                .gateway
                .session_manager
                .find_session_by_tag(&tag)
                .unwrap()
                .is_some(),
            "Первый новый DATA1701 должен быть в индексе, expired={expire_grace}"
        );
        deliver_inline_data(&mut fixture, 1701, false).await;
        assert_eq!(fixture.session.lock().counter, 1701);
        assert!(fixture.session.lock().received_bitmap.bit_set(0));
    }
}

#[tokio::test]
async fn inline_old_data_replay_and_tamper_leave_index_and_replay_unchanged() {
    let mut fixture = inline_ingress_fixture();
    for counter in 1001..=1127 {
        deliver_inline_data(&mut fixture, counter, true).await;
    }
    let (base, tags, received, bitmap) = {
        let state = fixture.session.lock();
        (
            state.tag_window_base,
            state.expected_tags.clone(),
            state.pre_ratchet_received.clone(),
            inline_primary_bitmap(&state),
        )
    };
    let (replay, _) = inline_data_packet(&fixture.old_keys, 1127, &fixture.mask);
    let _ = fixture.gateway.handle_packet(&replay, fixture.peer).await;
    let (mut tampered, _) = inline_data_packet(&fixture.old_keys, 1700, &fixture.mask);
    *tampered.last_mut().unwrap() ^= 1;
    assert!(fixture
        .gateway
        .handle_packet(&tampered, fixture.peer)
        .await
        .is_err());
    assert!(fixture.delivered.try_recv().is_err());
    let state = fixture.session.lock();
    assert_eq!(state.counter, 1000);
    assert_eq!(state.tag_window_base, base);
    assert_eq!(state.expected_tags, tags);
    assert_eq!(state.pre_ratchet_received, received);
    assert_eq!(inline_primary_bitmap(&state), bitmap);
}

#[tokio::test]
async fn inline_long_old_tail_keeps_new_data_on_fast_path() {
    let mut fixture = inline_ingress_fixture_with_base(921);
    assert_eq!(
        fixture.session.lock().pre_ratchet_tags.keys().max(),
        Some(&5528)
    );
    let bitmap = inline_primary_bitmap(&fixture.session.lock());
    let capacity = fixture.session.lock().pre_ratchet_tags.len();
    // Изолируем размер окна от скорости отладочной сборки.
    fixture.session.lock().pre_ratchet_expire = Some(Instant::now() + Duration::from_secs(30));
    for counter in 1001..=6096 {
        if counter == 6050 {
            continue;
        }
        deliver_inline_data(&mut fixture, counter, true).await;
        let state = fixture.session.lock();
        assert_eq!(state.counter, 1000);
        assert_eq!(inline_primary_bitmap(&state), bitmap);
        assert!(state.pre_ratchet_tags.len() <= capacity);
        assert!(state.pre_ratchet_received.len() <= capacity);
    }
    // Один отложенный пакет допускается, но повтор и подделка не двигают окна.
    deliver_inline_data(&mut fixture, 6050, true).await;
    let (base, tags, old_tags, received) = {
        let state = fixture.session.lock();
        (
            state.tag_window_base,
            state.expected_tags.clone(),
            state.pre_ratchet_tags.clone(),
            state.pre_ratchet_received.clone(),
        )
    };
    for counter in [1127, 6000] {
        let (replay, _) = inline_data_packet(&fixture.old_keys, counter, &fixture.mask);
        let _ = fixture.gateway.handle_packet(&replay, fixture.peer).await;
    }
    let (mut tampered, _) = inline_data_packet(&fixture.old_keys, 6097, &fixture.mask);
    *tampered.last_mut().unwrap() ^= 1;
    assert!(fixture
        .gateway
        .handle_packet(&tampered, fixture.peer)
        .await
        .is_err());
    assert!(fixture.delivered.try_recv().is_err());
    {
        let state = fixture.session.lock();
        assert_eq!(state.tag_window_base, base);
        assert_eq!(state.expected_tags, tags);
        assert_eq!(state.pre_ratchet_tags, old_tags);
        assert_eq!(state.pre_ratchet_received, received);
        assert_eq!(inline_primary_bitmap(&state), bitmap);
    }
    let keys = fixture.session.lock().keys.clone();
    let (packet, _) = inline_data_packet(&keys, 6097, &fixture.mask);
    let tag = super::extract_tag_for_layout(&packet, fixture.mask.tag_offset).unwrap();
    assert!(
        fixture
            .gateway
            .session_manager
            .find_session_by_tag(&tag)
            .unwrap()
            .is_some(),
        "Новая эпоха должна попасть в быстрый индекс после длинного старого хвоста"
    );
    fixture.session.lock().pre_ratchet_expire = Some(Instant::now() - Duration::from_secs(1));
    fixture.gateway.session_manager.cleanup_expired();
    assert!(fixture
        .gateway
        .session_manager
        .find_session_by_tag(&tag)
        .unwrap()
        .is_some());
    deliver_inline_data(&mut fixture, 6097, false).await;
    assert_eq!(fixture.session.lock().counter, 6097);
}

#[tokio::test]
async fn fec_receiver_observes_accepted_inline_epochs_and_reports_only_ordinary_clients() {
    let mut fixture = inline_ingress_fixture();
    for counter in 1001..=1032 {
        if counter != 1017 {
            deliver_inline_data(&mut fixture, counter, true).await;
        }
    }
    assert_eq!(fixture.session.lock().receiver_loss.counts(), (31, 32));
    assert_eq!(
        fixture.session.lock().receiver_loss.loss_ppm(),
        Some(31_250)
    );
    deliver_inline_data(&mut fixture, 1017, true).await;
    deliver_inline_data(&mut fixture, 1033, false).await;
    let before = fixture.session.lock().receiver_loss.counts();
    assert_eq!(before, (33, 33));
    let (replay, _) = inline_data_packet(&fixture.old_keys, 1017, &fixture.mask);
    let _ = fixture.gateway.handle_packet(&replay, fixture.peer).await;
    let (mut tampered, _) = inline_data_packet(&fixture.old_keys, 1034, &fixture.mask);
    *tampered.last_mut().unwrap() ^= 1;
    assert!(fixture
        .gateway
        .handle_packet(&tampered, fixture.peer)
        .await
        .is_err());
    assert!(fixture.delivered.try_recv().is_err());
    assert_eq!(fixture.session.lock().receiver_loss.counts(), before);
    fixture.session.lock().kernel_faulted = true;
    let (rejected, _) = inline_data_packet(&fixture.old_keys, 1034, &fixture.mask);
    let _ = fixture.gateway.handle_packet(&rejected, fixture.peer).await;
    assert!(fixture.delivered.try_recv().is_err());
    assert_eq!(fixture.session.lock().receiver_loss.counts(), before);
    let mut state = fixture.session.lock();
    state.kernel_faulted = false;
    let now = Instant::now();
    // Peer-сессия не отвечает отчетом на отчет другого gateway.
    assert!(state.receiver_quality_report(true, now).is_none());
    state.is_site_peer = false;
    assert!(state.receiver_quality_report(true, now).is_none());
    state.client_id = Some("registered-client".into());
    assert!(state.receiver_quality_report(false, now).is_none());
    let report = state
        .receiver_quality_report(true, now)
        .expect("Зрелое полное RX-наблюдение дает отчет клиенту");
    assert!(matches!(
        report,
        ControlPayload::QualityReport { loss_ppm: 0, .. }
    ));
    for blocked in 0..4 {
        match blocked {
            0 => state.is_site_peer = true,
            1 => state.is_masked_pool_peer = true,
            2 => state.client_admitted = false,
            _ => state.is_ratcheted = false,
        }
        assert!(
            state
                .receiver_quality_report(true, now + Duration::from_secs(2 * (blocked + 1)))
                .is_none(),
            "Ограничение допуска {blocked}"
        );
        state.is_site_peer = false;
        state.is_masked_pool_peer = false;
        state.client_admitted = true;
        state.is_ratcheted = true;
    }
}
