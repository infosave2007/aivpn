//! Два настоящих UDP-шлюза: handshake, node identity и двусторонняя БД.
use aivpn_common::{crypto, mask::preset_masks, network_config::VpnNetworkConfig};
use aivpn_server::{
    node_registry::NodeRegistry, pool_dialer::PoolDialer, pool_sync::PoolSyncConfig, AivpnServer,
    ClientDatabase, GatewayConfig,
};
use base64::Engine as _;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

fn endpoint() -> String {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

fn node(
    dir: &std::path::Path,
    own: &str,
    peer: &str,
    partition: u32,
    site_only: bool,
) -> (
    AivpnServer,
    Arc<ClientDatabase>,
    Arc<PoolDialer>,
    Arc<NodeRegistry>,
) {
    let seed = [91; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
    let mut mask = preset_masks::webrtc_zoom_v3();
    mask.sign(&signing);
    let masks = dir.join("masks");
    std::fs::create_dir_all(&masks).unwrap();
    std::fs::write(
        masks.join(format!("{}.json", mask.mask_id)),
        serde_json::to_vec(&mask).unwrap(),
    )
    .unwrap();
    let db = Arc::new(
        ClientDatabase::load(&dir.join("clients.json"), VpnNetworkConfig::default()).unwrap(),
    );
    db.set_node_partition_explicit(partition, Some(2));
    db.add_client(&format!("client-{partition}")).unwrap();
    let config = GatewayConfig {
        listen_addr: own.to_string(),
        mask_dir: masks,
        client_db: Some(db.clone()),
        enable_nat: false,
        enable_neural: false,
        pool_server_keypair: (!site_only).then(|| crypto::pool_server_keypair(&seed)),
        pool_client_psk: (!site_only).then(|| crypto::pool_client_psk(&seed)),
        mask_signing_key: Some([92; 32]),
        ..GatewayConfig::default()
    };
    let registry = Arc::new(NodeRegistry::load(dir.join("nodes.json"), true));
    let identity = crypto::node_identity_from_seed(&[partition as u8 + 1; 32]);
    let pool = PoolSyncConfig {
        peers: vec![peer.to_string()],
        node_id: Some(own.to_string()),
        sync_key: Some(base64::engine::general_purpose::STANDARD.encode(seed)),
        require_node_enrollment: Some(true),
        sync_beacon_secs: Some(1),
        ..Default::default()
    };
    let dialer = if site_only {
        let dialer =
            PoolDialer::site_only(db.clone(), own, vec![], true, Some(identity.clone())).unwrap();
        dialer.queue_site_peer(
            peer.to_string(),
            crypto::pool_server_keypair(&seed),
            crypto::pool_client_psk(&seed),
            peer.to_string(),
        );
        dialer
    } else {
        PoolDialer::new(db.clone(), &pool, vec![], None, Some(identity.clone())).unwrap()
    };
    dialer.set_node_registry(registry.clone());
    let mut server = AivpnServer::new(config).unwrap();
    if site_only {
        server
            .add_masked_peer_key(
                crypto::pool_server_keypair(&seed),
                crypto::pool_client_psk(&seed),
                "another-site".into(),
            )
            .unwrap();
        server
            .add_masked_peer_key(
                crypto::pool_server_keypair(&seed),
                crypto::pool_client_psk(&seed),
                peer.to_string(),
            )
            .unwrap();
    }
    server.set_node_registry(registry.clone());
    server.set_local_node_identity(identity, own.to_string());
    server.set_require_node_enrollment(true);
    server.set_pool_dialer(dialer.clone());
    (server, db, dialer, registry)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_reconcile_over_masked_udp_and_prove_identity() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("aivpn_server=warn,aivpn_client=warn")
        .try_init();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = endpoint();
    let b = endpoint();
    let (sa, da, pa, ra) = node(a_dir.path(), &a, &b, 0, false);
    let (sb, db, pb, rb) = node(b_dir.path(), &b, &a, 1, false);
    let ta = tokio::spawn(sa.run());
    let tb = tokio::spawn(sb.run());
    let stop = Arc::new(AtomicBool::new(false));
    pa.clone().start(stop.clone());
    pb.clone().start(stop.clone());
    let outcome = tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            if da.list_clients().len() == 2
                && db.list_clients().len() == 2
                && pa.has_live_session(&b)
                && pb.has_live_session(&a)
            {
                break;
            }
            assert!(
                !ta.is_finished() && !tb.is_finished(),
                "шлюз завершился до сходимости"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    ta.abort();
    tb.abort();
    outcome.expect("оба узла должны получить клиентов друг друга по UDP");
    assert_eq!(da.state_digest(), db.state_digest());
    assert!(serde_json::from_slice::<serde_json::Value>(
        &std::fs::read(a_dir.path().join("nodes.json")).unwrap()
    )
    .unwrap()["nodes"]
        .get(&b)
        .is_some());
    assert!(serde_json::from_slice::<serde_json::Value>(
        &std::fs::read(b_dir.path().join("nodes.json")).unwrap()
    )
    .unwrap()["nodes"]
        .get(&a)
        .is_some());
    drop((ra, rb));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standalone_sites_connect_without_pool_and_cannot_merge_database() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = endpoint();
    let b = endpoint();
    let (sa, da, pa, _) = node(a_dir.path(), &a, &b, 0, true);
    let (sb, db, pb, _) = node(b_dir.path(), &b, &a, 1, true);
    let ta = tokio::spawn(sa.run());
    let tb = tokio::spawn(sb.run());
    let stop = Arc::new(AtomicBool::new(false));
    pa.clone().start(stop.clone());
    pb.clone().start(stop.clone());
    // Первый UDP handshake может уйти до bind второго шлюза. Ждем и штатный повтор.
    let result = tokio::time::timeout(Duration::from_secs(35), async {
        while !pa.has_live_session(&b) || !pb.has_live_session(&a) {
            assert!(!ta.is_finished() && !tb.is_finished());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(pa.send_to_peer(
            &b,
            aivpn_common::protocol::ControlPayload::PoolSync {
                clients_json: serde_json::to_vec(&da.list_clients()).unwrap(),
            }
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(db.list_clients().len(), 1);
        assert_eq!(da.list_clients().len(), 1);
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    ta.abort();
    tb.abort();
    result.expect("площадки должны поднять канал без pool и без анонса локальных подсетей");
}

#[test]
fn site_credential_cannot_grant_pool_membership() {
    let dir = tempfile::tempdir().unwrap();
    let (mut server, _, _, _) = node(dir.path(), "127.0.0.1:25001", "127.0.0.1:25002", 0, false);
    let seed = [91; 32];
    assert!(server
        .add_masked_peer_key(
            crypto::pool_server_keypair(&seed),
            crypto::pool_client_psk(&seed),
            "site".into()
        )
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_from_another_process_disconnects_an_established_peer() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = endpoint();
    let b = endpoint();
    let (sa, _, pa, _) = node(a_dir.path(), &a, &b, 0, false);
    let (sb, _, pb, _) = node(b_dir.path(), &b, &a, 1, false);
    let ta = tokio::spawn(sa.run());
    let tb = tokio::spawn(sb.run());
    let stop = Arc::new(AtomicBool::new(false));
    pa.clone().start(stop.clone());
    pb.clone().start(stop.clone());
    let result = tokio::time::timeout(Duration::from_secs(35), async {
        while !pa.has_live_session(&b) || !pb.has_live_session(&a) {
            assert!(!ta.is_finished() && !tb.is_finished());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let cli_registry = NodeRegistry::load(b_dir.path().join("nodes.json"), false);
        assert!(cli_registry.try_revoke(&a).unwrap());
        tokio::time::timeout(Duration::from_secs(3), async {
            while pb.has_live_session(&a) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("отзыв должен закрыть установленный канал");
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    ta.abort();
    tb.abort();
    result.unwrap();
}
