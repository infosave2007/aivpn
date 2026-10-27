use super::*;

enum Boundary {
    Reconnect,
    FailedReconnect,
    Disconnect,
}

async fn assert_old_management_is_cancelled(boundary: Boundary) {
    let mut config = make_test_config();
    config.control_only = true;
    config.server_public_key = KeyPair::generate().public_key_bytes();
    let mut client = AivpnClient::new(config).unwrap();
    client.connect().await.unwrap();
    client.mgmt.on_capabilities(2);
    let (mgmt, sender) = client.management_handle();
    let mut receiver = client.preset_control_rx.take().unwrap();
    let mut sent =
        Box::pin(mgmt.mgmt_call(&sender, 0, "/old-read", vec![], Duration::from_secs(5)));
    tokio::select! {
        biased;
        _ = sent.as_mut() => panic!("Запрос должен ждать ответа"),
        _ = std::future::ready(()) => {}
    }
    assert!(matches!(
        receiver.try_recv(),
        Ok(ControlPayload::MgmtRequest { .. })
    ));
    let mut queued =
        Box::pin(mgmt.mgmt_call(&sender, 1, "/old-mutation", vec![], Duration::from_secs(5)));
    tokio::select! {
        biased;
        _ = queued.as_mut() => panic!("Мутация должна ждать интервала отправки"),
        _ = std::future::ready(()) => {}
    }

    match boundary {
        Boundary::Reconnect => client.connect().await.unwrap(),
        Boundary::FailedReconnect => {
            client.config.server_addr = "missing-port".into();
            assert!(client.connect().await.is_err());
        }
        Boundary::Disconnect => client.disconnect().await,
    }
    assert_eq!(client.cached_role(), 0, "Роль старой сессии сбрасывается");
    let cancelled_at = tokio::time::Instant::now();
    assert!(sent.await.is_err());
    assert!(queued.await.is_err());
    assert_eq!(cancelled_at.elapsed(), Duration::ZERO);
    tokio::time::advance(Duration::from_millis(300)).await;
    while let Ok(payload) = receiver.try_recv() {
        assert!(
            !matches!(payload, ControlPayload::MgmtRequest { .. }),
            "Старая команда не должна отправляться"
        );
    }
    client.disconnect().await;
}

#[tokio::test(start_paused = true)]
async fn reconnect_cancels_old_management_and_cached_role() {
    assert_old_management_is_cancelled(Boundary::Reconnect).await;
}

#[tokio::test(start_paused = true)]
async fn failed_reconnect_cancels_old_management_before_network_setup() {
    assert_old_management_is_cancelled(Boundary::FailedReconnect).await;
}

#[tokio::test(start_paused = true)]
async fn disconnect_cancels_old_management_without_waiting_for_timeouts() {
    assert_old_management_is_cancelled(Boundary::Disconnect).await;
}
