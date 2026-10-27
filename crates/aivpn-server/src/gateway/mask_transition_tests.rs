//! Переход маски через настоящий UDP-прием и обработчик gateway.

use super::*;
use aivpn_common::client_wire::{build_inner_packet, decode_downlink_with_offsets, RecvWindow};
use aivpn_common::mask::preset_masks;
use aivpn_common::mimicry::MimicryEngine;

async fn deliver(gateway: &Gateway, peer: &UdpSocket, packet: &[u8]) -> Result<()> {
    let socket = gateway.udp_socket.as_ref().unwrap();
    peer.send_to(packet, socket.local_addr().unwrap()).await?;
    let mut buffer = [0; 4096];
    let (length, address) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
            .await
            .unwrap()?;
    gateway.handle_packet(&buffer[..length], address).await
}

async fn receive_control(
    peer: &UdpSocket,
    keys: &crypto::SessionKeys,
    window: &mut RecvWindow,
    lengths: &mut Vec<usize>,
    offsets: &[u16],
) -> ControlPayload {
    let mut buffer = [0; 4096];
    let length = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let decoded =
        decode_downlink_with_offsets(&buffer[..length], keys, window, lengths, offsets).unwrap();
    ControlPayload::decode(&decoded.payload).unwrap()
}

#[tokio::test]
async fn idle_polymorphic_mask_transition_accepts_new_keepalive_after_grace() {
    for legacy in [false, true] {
        let mut base = preset_masks::webrtc_zoom_v3();
        if legacy {
            base.tag_offset = u16::MAX;
        }
        exercise_idle_transition(base, None).await;
    }
}

#[tokio::test]
async fn idle_mask_transition_accepts_changed_tag_layout() {
    let mut legacy = preset_masks::webrtc_zoom_v3();
    legacy.tag_offset = u16::MAX;
    exercise_idle_transition(legacy, Some(8)).await;
    exercise_idle_transition(preset_masks::webrtc_zoom_v3(), Some(u16::MAX)).await;
}

async fn exercise_idle_transition(mut base: MaskProfile, new_tag_offset: Option<u16>) {
    let directory = tempfile::tempdir().unwrap();
    let mask_dir = directory.path().join("masks");
    std::fs::create_dir(&mask_dir).unwrap();
    crate::test_masks::sign(&mut base, &ed25519_dalek::SigningKey::from_bytes(&[71; 32]));
    std::fs::write(
        mask_dir.join(format!("{}.json", base.mask_id)),
        serde_json::to_vec(&base).unwrap(),
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
    gateway.mask_catalog.register_mask(base.clone());
    gateway
        .mask_catalog
        .set_primary_mask_id(base.mask_id.clone());
    gateway.udp_socket = Some(super::MaskSocket::new(Arc::new(
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    )));
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session = gateway
        .session_manager
        .create_session(peer.local_addr().unwrap(), [7; 32], None, None)
        .unwrap();
    let session_id = session.lock().session_id;
    gateway
        .session_manager
        .complete_session_ratchet(&session_id);
    // Выбираем штатный вариант с зазором 4 байта, без случайного исхода теста.
    let (keys, mut variant) = (0u16..1000)
        .find_map(|seed| {
            let mut material = [0; 32];
            material[..2].copy_from_slice(&seed.to_le_bytes());
            let keys = crypto::derive_session_keys(&material, None, &[9; 32]);
            let variant = base.to_polymorphic(&keys.prng_seed);
            (variant.mdh_len() == base.mdh_len() + 4).then_some((keys, variant))
        })
        .unwrap();
    if let Some(offset) = new_tag_offset {
        variant.tag_offset = offset;
    }
    let tag_offsets = [base.tag_offset, variant.tag_offset];
    {
        let mut state = session.lock();
        state.keys = keys.clone();
        state.mask = Some(base.clone());
        state.client_admitted = true;
        state.bootstrap_descriptors_sent = true;
        state.mask_catalog_version_sent = 1;
        state.update_tag_window();
    }
    gateway.session_manager.refresh_session_tags(&session_id);
    let packet = gateway
        .session_manager
        .build_mask_update_packet(&session, &variant)
        .unwrap();
    gateway
        .udp_socket
        .as_ref()
        .unwrap()
        .send_with_mask(&packet, peer.local_addr().unwrap(), false)
        .await
        .unwrap();
    gateway
        .session_manager
        .update_session_mask(&session_id, variant.clone());
    let mut receive_window = RecvWindow::new();
    let mut receive_lengths = vec![base.mdh_len(), variant.mdh_len()];
    assert!(matches!(
        receive_control(
            &peer,
            &keys,
            &mut receive_window,
            &mut receive_lengths,
            &tag_offsets
        )
        .await,
        ControlPayload::MaskUpdate { .. }
    ));
    let mut counter = 0;
    let keepalive = |stamp| {
        build_inner_packet(
            InnerType::Control,
            0,
            &ControlPayload::Keepalive { send_ts: stamp }
                .encode()
                .unwrap(),
        )
    };
    // Старый пакет, уже находящийся в сети, принимается до конца grace.
    let old = MimicryEngine::new(base.clone())
        .build_packet(&keepalive(11), &keys, &mut counter, None)
        .unwrap();
    deliver(&gateway, &peer, &old).await.unwrap();
    assert!(session.lock().pending_mask.is_some());
    assert!(matches!(
        receive_control(
            &peer,
            &keys,
            &mut receive_window,
            &mut receive_lengths,
            &tag_offsets
        )
        .await,
        ControlPayload::KeepaliveAck { echo_ts: 11 }
    ));
    let _ = receive_control(
        &peer,
        &keys,
        &mut receive_window,
        &mut receive_lengths,
        &tag_offsets,
    )
    .await;
    // Новая раскладка тоже принимается до grace, сохраняя старую для downlink.
    let early = MimicryEngine::new(variant.clone())
        .build_packet(&keepalive(12), &keys, &mut counter, None)
        .unwrap();
    deliver(&gateway, &peer, &early).await.unwrap();
    assert_eq!(
        session.lock().mask.as_ref().unwrap().mdh_len(),
        base.mdh_len()
    );
    assert!(session.lock().pending_mask.is_some());
    assert!(matches!(
        receive_control(
            &peer,
            &keys,
            &mut receive_window,
            &mut receive_lengths,
            &tag_offsets
        )
        .await,
        ControlPayload::KeepaliveAck { echo_ts: 12 }
    ));
    let _ = receive_control(
        &peer,
        &keys,
        &mut receive_window,
        &mut receive_lengths,
        &tag_offsets,
    )
    .await;
    // После этого сервер ничего не отправляет. Переход должен завершить uplink.
    tokio::time::sleep(Duration::from_millis(520)).await;
    let before_replay = session.lock().counter;
    let _ = deliver(&gateway, &peer, &early).await;
    assert_eq!(session.lock().counter, before_replay);
    assert!(
        session.lock().pending_mask.is_some(),
        "Replay не фиксирует переход маски"
    );
    assert_eq!(
        session.lock().mask.as_ref().unwrap().mdh_len(),
        base.mdh_len()
    );
    let new = MimicryEngine::new(variant.clone())
        .build_packet(&keepalive(22), &keys, &mut counter, None)
        .unwrap();
    let mut corrupt = new.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let before_counter = session.lock().counter;
    assert!(deliver(&gateway, &peer, &corrupt).await.is_err());
    assert_eq!(session.lock().counter, before_counter);
    assert_eq!(
        session.lock().mask.as_ref().unwrap().mdh_len(),
        base.mdh_len()
    );
    assert!(session.lock().pending_mask.is_some());
    deliver(&gateway, &peer, &new).await.unwrap();
    assert_eq!(
        session.lock().mask.as_ref().unwrap().mdh_len(),
        variant.mdh_len()
    );
    assert!(session.lock().pending_mask.is_none());
    assert!(matches!(
        receive_control(
            &peer,
            &keys,
            &mut receive_window,
            &mut receive_lengths,
            &tag_offsets
        )
        .await,
        ControlPayload::KeepaliveAck { echo_ts: 22 }
    ));
    let state = session.lock();
    let (offset, length) = kernel_wire_layout(&state, base.tag_offset, base.mdh_len() as u16);
    assert_eq!(
        (offset, length),
        (variant.tag_offset, variant.mdh_len() as u16)
    );
    assert_ne!(
        kernel_offload::kernel_session_sig(&state, offset, length),
        kernel_offload::kernel_session_sig(&state, base.tag_offset, base.mdh_len() as u16),
        "Фиксация маски меняет отпечаток раскладки для ядра"
    );
}
