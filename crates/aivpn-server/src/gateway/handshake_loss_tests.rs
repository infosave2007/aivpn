//! Живой клиент и шлюз через UDP-relay с воспроизводимыми потерями.

use super::*;
use aivpn_client::client::{AivpnClient, ClientConfig};
use aivpn_common::mask::preset_masks;
use aivpn_common::quality::AdaptiveLevel;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
struct Tasks(Vec<tokio::task::AbortHandle>);

impl Tasks {
    fn track<T>(&mut self, task: &tokio::task::JoinHandle<T>) {
        self.0.push(task.abort_handle());
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

struct Capture {
    started: Instant,
    packets: Vec<(Duration, bool, Vec<u8>)>,
}

fn save_pcap(label: &str, capture: &Capture) {
    let Some(directory) = std::env::var_os("AIVPN_HANDSHAKE_PCAP_DIR") else {
        return;
    };
    write_pcap(std::path::Path::new(&directory), label, capture);
}

fn write_pcap(directory: &std::path::Path, label: &str, capture: &Capture) {
    std::fs::create_dir_all(directory).unwrap();
    // LINKTYPE_RAW, IPv4 + UDP. Тестовые ключи генерируются для каждого запуска.
    let mut output = Vec::new();
    output.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    output.extend_from_slice(&2u16.to_le_bytes());
    output.extend_from_slice(&4u16.to_le_bytes());
    for value in [0u32, 0, 65535, 101] {
        output.extend_from_slice(&value.to_le_bytes());
    }
    for (elapsed, uplink, payload) in &capture.packets {
        let length = 28 + payload.len();
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        let (source, destination, source_port, destination_port) = if *uplink {
            ([192, 0, 2, 1], [192, 0, 2, 2], 50000u16, 443u16)
        } else {
            ([192, 0, 2, 2], [192, 0, 2, 1], 443u16, 50000u16)
        };
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        let sum: u32 = packet[..20]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) as u32)
            .sum();
        let sum = (sum & 0xffff) + (sum >> 16);
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(payload);
        for value in [
            elapsed.as_secs() as u32 + 1,
            elapsed.subsec_micros(),
            length as u32,
            length as u32,
        ] {
            output.extend_from_slice(&value.to_le_bytes());
        }
        output.extend_from_slice(&packet);
    }
    std::fs::write(directory.join(format!("{label}.pcap")), output).unwrap();
}

async fn exercise(
    mask: MaskProfile,
    drop_init: usize,
    drop_hello: usize,
    rtt_ms: u64,
    duplicate: bool,
) {
    exercise_with_switch(
        mask, drop_init, drop_hello, rtt_ms, duplicate, None, false, false,
    )
    .await;
}

async fn exercise_with_switch(
    mask: MaskProfile,
    drop_init: usize,
    drop_hello: usize,
    rtt_ms: u64,
    duplicate: bool,
    switch: Option<MaskProfile>,
    tamper_first: bool,
    reconnect: bool,
) {
    let mut tasks = Tasks::default();
    let switching = switch.is_some();
    let directory = tempfile::tempdir().unwrap();
    let mask_dir = directory.path().join("masks");
    std::fs::create_dir(&mask_dir).unwrap();
    let mut signed_mask = mask.clone();
    crate::test_masks::sign(
        &mut signed_mask,
        &ed25519_dalek::SigningKey::from_bytes(&[71; 32]),
    );
    std::fs::write(
        mask_dir.join(format!("{}.json", mask.mask_id)),
        serde_json::to_vec(&signed_mask).unwrap(),
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
        server_private_key: [73; 32],
        pool_server_keypair: Some(pool_key.clone()),
        pool_client_psk: Some(pool_psk),
        enable_nat: false,
        enable_neural: false,
        ..Default::default()
    })
    .unwrap();
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_address = server.local_addr().unwrap();
    gateway.udp_socket = Some(super::MaskSocket::new(server.clone()));
    let gateway = Arc::new(gateway);
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_address = relay.local_addr().unwrap();
    let capture = Arc::new(parking_lot::Mutex::new(Capture {
        started: Instant::now(),
        packets: Vec::new(),
    }));
    let wire_capture = capture.clone();
    let relay_task = tokio::spawn(async move {
        let mut client = None;
        let mut buffer = [0; 65536];
        let (mut uplinks, mut downlinks) = (0, 0);
        let mut deliveries = tokio::task::JoinSet::new();
        loop {
            let (length, address) = tokio::select! {
                result = relay.recv_from(&mut buffer) => result.unwrap(),
                completed = deliveries.join_next(), if !deliveries.is_empty() => {
                    completed.unwrap().unwrap();
                    continue;
                }
            };
            let uplink = address != server_address;
            {
                let mut saved = wire_capture.lock();
                let elapsed = saved.started.elapsed();
                saved
                    .packets
                    .push((elapsed, uplink, buffer[..length].to_vec()));
            }
            let destination = if uplink {
                client = Some(address);
                uplinks += 1;
                if uplinks <= drop_init {
                    continue;
                }
                server_address
            } else {
                downlinks += 1;
                if downlinks <= drop_hello {
                    continue;
                }
                client.unwrap()
            };
            assert!(
                deliveries.len() < 128,
                "Очередь тестового relay переполнена"
            );
            let sender = relay.clone();
            let packet = buffer[..length].to_vec();
            let tamper = tamper_first && uplink && uplinks == 1;
            deliveries.spawn(async move {
                time_delay(Duration::from_millis(rtt_ms / 2)).await;
                if tamper {
                    let mut damaged = packet.clone();
                    let last = damaged.len() - 1;
                    damaged[last] ^= 1;
                    sender.send_to(&damaged, destination).await.unwrap();
                    time_delay(Duration::from_millis(10)).await;
                }
                sender.send_to(&packet, destination).await.unwrap();
                if duplicate {
                    sender.send_to(&packet, destination).await.unwrap();
                }
            });
        }
    });
    tasks.track(&relay_task);
    let receiver_gateway = gateway.clone();
    let debugging_rtc = aivpn_common::mask_io::uses_rtc(&mask);
    let server_task = tokio::spawn(async move {
        let mut buffer = [0; 65536];
        loop {
            let (length, address) = tokio::select! {
                decoded = receiver_gateway.udp_socket.as_ref().unwrap().decoded() => {
                    if let Some((packet, address, quic)) = decoded {
                        let _ = receiver_gateway.handle_unmasked_packet(&packet, address, quic).await;
                    }
                    continue;
                }
                result = server.recv_from(&mut buffer) => result.unwrap(),
            };
            // Дубликаты могут законно попасть в replay/cooldown, но не останавливают прием.
            let result = receiver_gateway
                .handle_packet(&buffer[..length], address)
                .await;
            if switching || debugging_rtc {
                if let Err(error) = result {
                    eprintln!("switch ingress: {error}");
                }
            }
        }
    });
    tasks.track(&server_task);
    let (tap_tx, mut tap_rx) = mpsc::channel(32);
    let config = ClientConfig {
        server_addr: relay_address.to_string(),
        server_public_key: pool_key.public_key_bytes(),
        server_signing_key: Some(
            derive_server_signing_key(&[73; 32])
                .verifying_key()
                .to_bytes(),
        ),
        preshared_key: Some(pool_psk),
        initial_mask: mask.clone(),
        tun_config: aivpn_client::tunnel::TunnelConfig::default(),
        proxy_listen: None,
        proxy_dns: vec![],
        mtls_cert: None,
        initial_adaptive_level: AdaptiveLevel::Off,
        polymorphic_base: None,
        share_mask_feedback: false,
        receive_mask_hints: false,
        country_code: None,
        mask_operator_pubkey: Some(
            ed25519_dalek::SigningKey::from_bytes(&[71; 32])
                .verifying_key()
                .to_bytes(),
        ),
        mask_verify_mode: aivpn_common::mask::MaskVerifyMode::Enforce,
        network_change_notify: None,
        is_bootstrap_fallback: false,
        control_only: true,
        inbound_control_tap: Some(tap_tx),
        node_identity: None,
        pool_node_id: None,
        remote_verified_node: None,
        remote_enroll_hook: None,
        transport: None,
    };
    let mut client = AivpnClient::new(config.clone()).unwrap();
    let client_control = client.control_handle();
    let stop = Arc::new(AtomicBool::new(false));
    let client_stop = stop.clone();
    let started = Instant::now();
    let mut client_task = tokio::spawn(async move { client.run(client_stop).await });
    tasks.track(&client_task);
    let mut label = format!(
        "{}-init{drop_init}-hello{drop_hello}-rtt{rtt_ms}-dup{duplicate}",
        mask.mask_id
    );
    if switching {
        label.push_str("-switch");
    }
    if tamper_first {
        label.push_str("-tamper");
    }
    if reconnect {
        label.push_str("-reconnect");
    }
    let outcome = tokio::time::timeout(
        Duration::from_secs(if rtt_ms <= 100 && !(drop_init == 2 && drop_hello == 2) {
            2
        } else {
            6
        }),
        async {
            loop {
                assert!(!client_task.is_finished(), "{label}: клиент остановился");
                if gateway
                    .session_manager
                    .iter_sessions()
                    .any(|entry| entry.value().lock().is_ratcheted)
                {
                    break;
                }
                time_delay(Duration::from_millis(5)).await;
            }
        },
    )
    .await;
    save_pcap(&label, &capture.lock());
    outcome.unwrap_or_else(|_| panic!("{label}: PFS не завершен за отведенное время"));
    assert_eq!(
        gateway.session_manager.session_count(),
        1,
        "{label}: повтор создал новую сессию"
    );
    let session = gateway
        .session_manager
        .iter_sessions()
        .next()
        .unwrap()
        .value()
        .clone();
    if aivpn_common::mask_io::uses_rtc(&mask) {
        let rtc_outcome = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let media_both_directions = {
                    let saved = capture.lock();
                    [false, true].into_iter().all(|direction| {
                        saved.packets.iter().any(|(_, uplink, packet)| {
                            *uplink == direction
                                && (if aivpn_common::mask_io::turn_realm(&mask).is_some()
                                    && packet.first() == Some(&0x40)
                                {
                                    packet.get(4)
                                } else {
                                    packet.first()
                                })
                                .is_some_and(|first| (128..=191).contains(first))
                        })
                    })
                };
                if media_both_directions {
                    break;
                }
                client_control
                    .send(ControlPayload::Keepalive {
                        send_ts: crypto::current_timestamp_ms(),
                    })
                    .await
                    .unwrap();
                assert!(
                    !client_task.is_finished(),
                    "{label}: клиент остановился на RTC"
                );
                time_delay(Duration::from_millis(100)).await;
            }
        })
        .await;
        save_pcap(&label, &capture.lock());
        rtc_outcome.unwrap_or_else(|_| panic!("{label}: нет SRTP в обе стороны после PFS"));
    }
    let expected = [83; 32];
    assert_eq!(
        session.lock().mask.as_ref().unwrap().mask_id,
        mask.mask_id,
        "{label}: сервер выбрал другой профиль с похожим заголовком"
    );
    gateway
        .send_control_message(
            &ControlPayload::PoolStateDigest { digest: expected },
            &session,
        )
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(3), tap_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received, ControlPayload::PoolStateDigest { digest } if digest == expected));
    if drop_init == 0 && drop_hello == 0 && !switching && !tamper_first && !reconnect {
        let previous_key = session.lock().keys.session_key;
        session.lock().bytes_since_rekey = u64::MAX;
        let due = gateway.session_manager.start_rekeying_sessions();
        assert_eq!(due.len(), 1);
        gateway
            .send_control_message(
                &ControlPayload::KeyRotate {
                    new_eph_pub: due[0].1,
                },
                &session,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let changed = {
                    let state = session.lock();
                    state.pending_rekey_keypair.is_none() && state.keys.session_key != previous_key
                };
                if changed {
                    break;
                }
                time_delay(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("Ротация PFS не завершилась внутри маски");
        gateway
            .send_control_message(
                &ControlPayload::PoolStateDigest { digest: [84; 32] },
                &session,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(tap_rx.recv().await, Some(ControlPayload::PoolStateDigest { digest }) if digest == [84; 32]) { break; }
            }
        }).await.expect("Downlink потерян после ротации ключей");
    }
    if reconnect {
        let old_id = session.lock().session_id;
        client_task.abort();
        assert!(client_task.await.unwrap_err().is_cancelled());
        while tap_rx.try_recv().is_ok() {}
        let mut next = AivpnClient::new(config).unwrap();
        let next_stop = stop.clone();
        client_task = tokio::spawn(async move { next.run(next_stop).await });
        tasks.track(&client_task);
        let replacement = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                assert!(!client_task.is_finished());
                if let Some(next) = gateway.session_manager.iter_sessions().find_map(|entry| {
                    let state = entry.value().lock();
                    (state.session_id != old_id && state.is_ratcheted)
                        .then(|| entry.value().clone())
                }) {
                    break next;
                }
                time_delay(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("Старое QUIC-состояние заблокировало reconnect за тем же NAT");
        gateway
            .send_control_message(
                &ControlPayload::PoolStateDigest { digest: expected },
                &replacement,
            )
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), tap_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(received, ControlPayload::PoolStateDigest { digest } if digest == expected)
        );
    }
    if let Some(mut next_mask) = switch {
        crate::test_masks::sign(
            &mut next_mask,
            &ed25519_dalek::SigningKey::from_bytes(&[71; 32]),
        );
        let packet = gateway
            .session_manager
            .build_mask_update_packets(&session, &next_mask)
            .unwrap();
        let address = session.lock().client_addr;
        gateway
            .udp_socket
            .as_ref()
            .unwrap()
            .send_packets_to(&packet, address)
            .await
            .unwrap();
        let id = session.lock().session_id;
        gateway
            .session_manager
            .update_session_mask(&id, next_mask.clone());
        let switched_digest = [94; 32];
        let result = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                time_delay(Duration::from_millis(100)).await;
                let _ = gateway
                    .send_control_message(
                        &ControlPayload::PoolStateDigest {
                            digest: switched_digest,
                        },
                        &session,
                    )
                    .await;
                if let Ok(Some(ControlPayload::PoolStateDigest { digest })) =
                    tokio::time::timeout(Duration::from_millis(200), tap_rx.recv()).await
                {
                    if digest == switched_digest
                        && session
                            .lock()
                            .mask
                            .as_ref()
                            .is_some_and(|mask| mask.mask_id == next_mask.mask_id)
                        && gateway.udp_socket.as_ref().unwrap().is_stateful(address)
                            == aivpn_common::mask_io::requires_userspace(&next_mask)
                    {
                        break;
                    }
                }
            }
        })
        .await;
        save_pcap(&label, &capture.lock());
        if result.is_err() {
            eprintln!(
                "switch failed: {} -> {}, actual={}, stateful={}, client_done={}",
                mask.mask_id,
                next_mask.mask_id,
                session.lock().mask.as_ref().unwrap().mask_id,
                gateway.udp_socket.as_ref().unwrap().is_stateful(address),
                client_task.is_finished()
            );
        }
        result.expect("Смена протокола потеряла downlink");
        assert_eq!(
            session.lock().mask.as_ref().unwrap().mask_id,
            next_mask.mask_id
        );
        assert_eq!(gateway.session_manager.session_count(), 1);
    }
    if mask.uses_stun_attributes() && !label.contains("switch") {
        let saved = capture.lock();
        assert!(saved.packets.iter().any(|(_, uplink, _)| !uplink));
        for (_, uplink, packet) in &saved.packets {
            if !aivpn_common::mask_io::uses_rtc(&mask)
                || !aivpn_common::rtc_mask::is_wire_packet(packet)
            {
                aivpn_common::stun_wire::validate(packet)
                    .unwrap_or_else(|error| panic!("{label} uplink={uplink}: {error}"));
            }
        }
    }
    save_pcap(&label, &capture.lock());
    eprintln!(
        "handshake-live: {label}: PFS и control OK, {} мс",
        started.elapsed().as_millis()
    );
    stop.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(2), client_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

async fn time_delay(delay: Duration) {
    tokio::time::sleep(delay).await;
}

#[tokio::test]
async fn live_initial_v2_all_masks_and_loss_recover_without_reconnect() {
    for mask in preset_masks::all() {
        for (drop_init, drop_hello) in [(0, 0), (1, 0), (2, 0), (0, 2), (2, 2)] {
            exercise(mask.clone(), drop_init, drop_hello, 20, false).await;
        }
    }
}

#[tokio::test]
async fn live_initial_v2_delayed_and_duplicated_packets_are_idempotent() {
    for mask in [
        preset_masks::webrtc_zoom_v3(),
        preset_masks::quic_https_v2(),
    ] {
        for rtt_ms in [100, 500] {
            exercise(mask.clone(), 1, 2, rtt_ms, true).await;
        }
    }
}

#[tokio::test]
async fn live_mask_switches_between_stun_and_quic_without_reconnect() {
    for (from, to) in [
        (
            preset_masks::webrtc_zoom_v3(),
            preset_masks::quic_https_v2(),
        ),
        (
            preset_masks::quic_https_v2(),
            preset_masks::webrtc_zoom_v3(),
        ),
        (
            preset_masks::webrtc_sberjazz_v1(),
            preset_masks::webrtc_zoom_v3(),
        ),
        (
            preset_masks::webrtc_zoom_v3(),
            preset_masks::webrtc_sberjazz_v1(),
        ),
        (
            preset_masks::by_id("telegram_calls_v1").unwrap(),
            preset_masks::quic_https_v2(),
        ),
        (
            preset_masks::quic_https_v2(),
            preset_masks::by_id("telegram_calls_v1").unwrap(),
        ),
        (
            preset_masks::quic_https_v2(),
            preset_masks::quic_https_v2().to_polymorphic(&[9; 32]),
        ),
    ] {
        exercise_with_switch(from, 0, 0, 20, false, Some(to), false, false).await;
    }
}

#[tokio::test]
async fn live_damaged_quic_initial_does_not_consume_bootstrap() {
    exercise_with_switch(
        preset_masks::quic_https_v2(),
        0,
        0,
        20,
        false,
        None,
        true,
        false,
    )
    .await;
}

#[tokio::test]
async fn live_quic_reconnect_replaces_stale_state_at_same_nat_address() {
    exercise_with_switch(
        preset_masks::quic_https_v2(),
        0,
        0,
        20,
        false,
        None,
        false,
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn diagnostics_use_the_authenticated_session_for_both_directions() {
    for carrier in [false, true] {
        exercise_diagnostics_session(carrier).await;
    }
}

async fn exercise_diagnostics_session(carrier: bool) {
    exercise_diagnostics_profile(carrier, preset_masks::webrtc_zoom_v3(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Генерация обучающих захватов по явно заданному пути"]
async fn export_authenticated_dpi_training_captures() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("AIVPN_DPI_CAPTURE_DIR").expect("Нужен AIVPN_DPI_CAPTURE_DIR"),
    );
    std::fs::create_dir_all(&directory).unwrap();
    for mask in preset_masks::all() {
        exercise_diagnostics_profile(false, mask, Some(&directory)).await;
    }
}

async fn exercise_diagnostics_profile(
    carrier: bool,
    mut mask: MaskProfile,
    training_dir: Option<&std::path::Path>,
) {
    use aivpn_common::diagnostics;
    let mut tasks = Tasks::default();
    let directory = tempfile::tempdir().unwrap();
    let mask_dir = directory.path().join("masks");
    std::fs::create_dir(&mask_dir).unwrap();
    let mask_id = mask.mask_id.clone();
    mask.sign(&ed25519_dalek::SigningKey::from_bytes(&[71; 32]))
        .unwrap();
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
    let user = database.add_client("diagnostics-user").unwrap();
    let mut gateway = Gateway::new(GatewayConfig {
        mask_dir,
        client_db: Some(database),
        mask_signing_key: Some([71; 32]),
        server_private_key: [73; 32],
        enable_nat: false,
        enable_neural: training_dir.is_some(),
        ..Default::default()
    })
    .unwrap();
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = server.local_addr().unwrap();
    let training = training_dir.is_some();
    let wire_samples = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
    let collected = wire_samples.clone();
    let observer = training.then(|| {
        Arc::new(move |_session_id, packet: &[u8]| {
            let mut saved = collected.lock();
            assert!(saved.len() < 8192, "Превышен размер обучающей выборки");
            saved.push(packet.iter().map(|byte| format!("{byte:02x}")).collect());
        }) as super::mask_socket::WireObserver
    });
    gateway.udp_socket = Some(super::MaskSocket::with_wire_observer(
        server.clone(),
        observer,
    ));
    let raw_capture = Arc::new(parking_lot::Mutex::new(Capture {
        started: Instant::now(),
        packets: vec![],
    }));
    let incoming_capture = raw_capture.clone();
    let gateway = Arc::new(gateway);
    let receive_gateway = gateway.clone();
    let server_task = tokio::spawn(async move {
        let mut buffer = [0; 65536];
        loop {
            let (length, peer) = tokio::select! {
                decoded = receive_gateway.udp_socket.as_ref().unwrap().decoded() => {
                    if let Some((packet, peer, stateful)) = decoded {
                        let _ = receive_gateway.handle_unmasked_packet(&packet, peer, stateful).await;
                    }
                    continue;
                }
                result = server.recv_from(&mut buffer) => result.unwrap(),
            };
            if training {
                let mut saved = incoming_capture.lock();
                let elapsed = saved.started.elapsed();
                assert!(saved.packets.len() < 65536);
                saved
                    .packets
                    .push((elapsed, true, buffer[..length].to_vec()));
            }
            let _ = receive_gateway.handle_packet(&buffer[..length], peer).await;
        }
    });
    tasks.track(&server_task);
    let mut config = ClientConfig {
        server_addr: address.to_string(),
        server_public_key: crypto::KeyPair::from_private_key([73; 32]).public_key_bytes(),
        server_signing_key: Some(
            derive_server_signing_key(&[73; 32])
                .verifying_key()
                .to_bytes(),
        ),
        preshared_key: Some(user.psk),
        initial_mask: mask,
        tun_config: aivpn_client::tunnel::TunnelConfig::default(),
        proxy_listen: None,
        proxy_dns: vec![],
        mtls_cert: None,
        initial_adaptive_level: AdaptiveLevel::Off,
        polymorphic_base: None,
        share_mask_feedback: false,
        receive_mask_hints: false,
        country_code: None,
        mask_operator_pubkey: Some(
            ed25519_dalek::SigningKey::from_bytes(&[71; 32])
                .verifying_key()
                .to_bytes(),
        ),
        mask_verify_mode: aivpn_common::mask::MaskVerifyMode::Enforce,
        network_change_notify: None,
        is_bootstrap_fallback: false,
        control_only: true,
        inbound_control_tap: None,
        node_identity: None,
        pool_node_id: None,
        remote_verified_node: None,
        remote_enroll_hook: None,
        transport: None,
    };
    if carrier {
        config.server_addr = "unresolvable.invalid:443".into();
        config.transport = Some(aivpn_common::transport::TransportConfig::new(
            "test-carrier",
            vec![],
        ));
    }
    let mut client = AivpnClient::new(config).unwrap();
    if carrier {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket.connect(address).await.unwrap();
        let mut registry = aivpn_common::transport::TransportRegistry::new();
        registry.register(Arc::new(DiagnosticCarrierFactory(socket)));
        client.set_transport_registry(
            Arc::new(registry),
            aivpn_common::transport::no_socket_guard(),
        );
    }
    let (mgmt, tx) = client.management_handle();
    let client_task =
        tokio::spawn(async move { client.run(Arc::new(AtomicBool::new(false))).await });
    tasks.track(&client_task);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if gateway
                .session_manager
                .iter_sessions()
                .any(|entry| entry.value().lock().client_admitted)
            {
                break;
            }
            assert!(!client_task.is_finished());
            time_delay(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    if let Some(directory) = training_dir {
        let seed = std::env::var("AIVPN_DPI_CAPTURE_SEED")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        for round in 0..1024u32 {
            let workload = blake3::Hasher::new()
                .update(&seed.to_le_bytes())
                .update(&round.to_le_bytes())
                .finalize();
            let size = [8, 64, 256, 768, 1000, 4096][usize::from(workload.as_bytes()[0]) % 6];
            let mut body = vec![0; size];
            blake3::Hasher::new()
                .update(mask_id.as_bytes())
                .update(&seed.to_le_bytes())
                .update(&round.to_le_bytes())
                .finalize_xof()
                .fill(&mut body);
            let (status, _) = mgmt
                .mgmt_call(&tx, 1, diagnostics::UP, body, Duration::from_secs(5))
                .await
                .unwrap();
            assert!(matches!(status, 200 | 400 | 429), "{mask_id}: {status}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let saved = wire_samples.lock();
        assert!(
            saved.len() >= 48,
            "{mask_id}: всего {} проверенных кадров",
            saved.len()
        );
        std::fs::write(
            directory.join(format!("{mask_id}.verified.json")),
            serde_json::to_vec(&*saved).unwrap(),
        )
        .unwrap();
        write_pcap(directory, &mask_id, &raw_capture.lock());
        eprintln!(
            "dpi-training: {mask_id}: {} проверенных внешних кадров",
            saved.len()
        );
        return;
    }
    let result = diagnostics::run(mgmt.clone(), tx.clone(), Duration::from_secs(3))
        .await
        .unwrap();
    assert!(result.samples > 0);
    assert!(
        result.throughput_up_kbps > 0.0 && result.throughput_down_kbps > 0.0,
        "{result:?}"
    );
    let (status, _) = mgmt
        .mgmt_call(
            &tx,
            1,
            diagnostics::DOWN,
            vec![0; 900],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(status, 400);
    let session = gateway
        .session_manager
        .iter_sessions()
        .next()
        .unwrap()
        .value()
        .clone();
    session.lock().client_admitted = false;
    // Проверяем сам обработчик: packet loop может повторно допустить корректного клиента.
    let id = session.lock().session_id;
    gateway.session_manager.remove_session(&id);
    assert!(mgmt
        .mgmt_call(
            &tx,
            1,
            diagnostics::PING,
            vec![0; 8],
            Duration::from_millis(200)
        )
        .await
        .is_err());
}

struct DiagnosticCarrierFactory(Arc<UdpSocket>);

struct DiagnosticCarrierLink(Arc<UdpSocket>);

#[async_trait::async_trait]
impl aivpn_common::transport::DatagramTransport for DiagnosticCarrierLink {
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        self.0.send(packet).await
    }

    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buffer).await
    }

    fn kind(&self) -> aivpn_common::transport::TransportKind {
        aivpn_common::transport::TransportKind::Udp
    }

    fn max_datagram(&self) -> usize {
        aivpn_common::transport::MAX_UDP_PAYLOAD
    }
}

#[async_trait::async_trait]
impl aivpn_common::transport::TransportFactory for DiagnosticCarrierFactory {
    fn name(&self) -> &str {
        "test-carrier"
    }
    async fn open(
        &self,
        _: &aivpn_common::transport::TransportConfig,
        _: aivpn_common::transport::SharedGuard,
    ) -> Result<aivpn_common::transport::SharedTransport> {
        // У внешней несущей нет адресов VPN peer и локального UDP endpoint.
        Ok(Arc::new(DiagnosticCarrierLink(self.0.clone())))
    }
}
