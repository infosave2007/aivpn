use super::*;
use tokio::task::JoinHandle;
use tokio::time::Instant;

fn call(
    client: &MgmtClient,
    sender: &mpsc::Sender<ControlPayload>,
    method: u8,
    path: &'static str,
    timeout: Duration,
) -> JoinHandle<Result<(u16, Vec<u8>)>> {
    let client = client.clone();
    let sender = sender.clone();
    tokio::spawn(async move {
        client
            .mgmt_call(&sender, method, path, vec![], timeout)
            .await
    })
}

async fn request(receiver: &mut mpsc::Receiver<ControlPayload>) -> (u32, String) {
    match tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("Запрос должен попасть в канал до контрольного срока")
        .expect("Канал должен оставаться открытым")
    {
        ControlPayload::MgmtRequest { req_id, path, .. } => (req_id, path),
        payload => panic!("Ожидался запрос управления: {payload:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn clones_pace_requests_and_correlate_out_of_order_responses() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let first = call(&client, &sender, 0, "/nodes", Duration::from_secs(5));
    let second = call(
        &client.clone(),
        &sender,
        0,
        "/health",
        Duration::from_secs(5),
    );
    let third = call(&client.clone(), &sender, 0, "/keys", Duration::from_secs(5));
    let mut requests = Vec::new();
    for _ in 0..3 {
        let (id, path) = request(&mut receiver).await;
        requests.push((id, path, Instant::now()));
    }
    for pair in requests.windows(2) {
        assert!(pair[1].2.duration_since(pair[0].2) >= Duration::from_millis(200));
        assert_ne!(pair[0].0, pair[1].0);
    }
    for (id, path, _) in requests.into_iter().rev() {
        client.on_mgmt_response(id, 200, path.into_bytes());
    }
    assert_eq!(first.await.unwrap().unwrap(), (200, b"/nodes".to_vec()));
    assert_eq!(second.await.unwrap().unwrap(), (200, b"/health".to_vec()));
    assert_eq!(third.await.unwrap().unwrap(), (200, b"/keys".to_vec()));
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn timeout_includes_waiting_for_the_shared_queue() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let first = call(&client, &sender, 0, "/first", Duration::from_secs(5));
    let (id, _) = request(&mut receiver).await;
    client.on_mgmt_response(id, 200, vec![]);
    first.await.unwrap().unwrap();

    let started = Instant::now();
    let second = client
        .mgmt_call(&sender, 0, "/expired", vec![], Duration::from_millis(100))
        .await;
    assert!(second.is_err());
    assert_eq!(started.elapsed(), Duration::from_millis(100));
    assert!(
        receiver.try_recv().is_err(),
        "Просроченный запрос не отправляется"
    );
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancelled_queue_waiter_never_sends_a_request() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let first = call(&client, &sender, 0, "/first", Duration::from_secs(5));
    let (id, _) = request(&mut receiver).await;
    client.on_mgmt_response(id, 200, vec![]);
    first.await.unwrap().unwrap();

    let cancelled = call(&client, &sender, 1, "/cancelled", Duration::from_secs(5));
    tokio::task::yield_now().await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    tokio::time::advance(Duration::from_millis(300)).await;
    assert!(
        receiver.try_recv().is_err(),
        "Отмененная команда не отправляется"
    );
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn reset_cancels_sent_pacing_and_backpressured_requests() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(1);
    let sent = call(&client, &sender, 0, "/sent", Duration::from_secs(5));
    let (old_id, _) = request(&mut receiver).await;
    sender
        .send(ControlPayload::Keepalive { send_ts: 1 })
        .await
        .unwrap();
    let waiting = call(&client, &sender, 1, "/old-mutation", Duration::from_secs(5));
    let pacing = call(&client, &sender, 0, "/old-read", Duration::from_secs(5));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(250)).await;
    tokio::task::yield_now().await;

    let reset_at = Instant::now();
    client.reset();
    assert!(sent.await.unwrap().is_err());
    assert!(waiting.await.unwrap().is_err());
    assert!(pacing.await.unwrap().is_err());
    assert_eq!(
        reset_at.elapsed(),
        Duration::ZERO,
        "Сброс не ждет таймаута старой сессии"
    );
    assert!(client.pending.lock().unwrap().is_empty());
    assert!(matches!(
        receiver.recv().await,
        Some(ControlPayload::Keepalive { .. })
    ));

    let fresh = call(&client, &sender, 0, "/fresh", Duration::from_secs(5));
    let (new_id, path) = request(&mut receiver).await;
    assert_eq!(path, "/fresh");
    assert_ne!(new_id, old_id);
    client.on_mgmt_response(old_id, 200, b"stale".to_vec());
    client.on_mgmt_response(new_id, 200, b"fresh".to_vec());
    assert_eq!(fresh.await.unwrap().unwrap(), (200, b"fresh".to_vec()));
    assert!(receiver.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn get_retries_explicit_429_after_the_server_delay() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let pending = call(&client, &sender, 0, "/nodes", Duration::from_secs(5));
    let (first_id, _) = request(&mut receiver).await;
    let rejected_at = Instant::now();
    client.on_mgmt_response(
        first_id,
        429,
        br#"{"code":"rate_limited","message":"wait","retry_after_ms":700}"#.to_vec(),
    );
    let (second_id, path) = request(&mut receiver).await;
    assert_eq!(path, "/nodes");
    assert_ne!(second_id, first_id);
    assert!(rejected_at.elapsed() >= Duration::from_millis(700));
    client.on_mgmt_response(first_id, 200, b"stale".to_vec());
    client.on_mgmt_response(second_id, 200, b"ok".to_vec());
    assert_eq!(pending.await.unwrap().unwrap(), (200, b"ok".to_vec()));
}

#[tokio::test(start_paused = true)]
async fn legacy_429_retries_are_delayed_and_bounded() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let pending = call(&client, &sender, 0, "/nodes", Duration::from_secs(5));
    let mut previous = None;
    for _ in 0..3 {
        let (id, _) = request(&mut receiver).await;
        let now = Instant::now();
        if let Some(previous) = previous {
            assert!(now.duration_since(previous) >= Duration::from_millis(200));
        }
        previous = Some(now);
        client.on_mgmt_response(id, 429, vec![]);
    }
    assert_eq!(pending.await.unwrap().unwrap(), (429, vec![]));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(
        receiver.try_recv().is_err(),
        "Количество повторов ограничено"
    );
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn retry_delay_uses_the_original_request_deadline() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let started = Instant::now();
    let pending = call(&client, &sender, 0, "/nodes", Duration::from_millis(500));
    let (id, _) = request(&mut receiver).await;
    tokio::time::advance(Duration::from_millis(100)).await;
    client.on_mgmt_response(
        id,
        429,
        br#"{"code":"rate_limited","message":"wait","retry_after_ms":600}"#.to_vec(),
    );
    assert!(pending.await.unwrap().is_err());
    assert_eq!(started.elapsed(), Duration::from_millis(500));
    assert!(receiver.try_recv().is_err());
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_ready_response_polled_after_the_deadline_still_times_out() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(1);
    let mut pending =
        Box::pin(client.mgmt_call(&sender, 0, "/nodes", vec![], Duration::from_millis(500)));
    tokio::select! {
        biased;
        _ = pending.as_mut() => panic!("Вызов должен ждать ответа"),
        _ = std::future::ready(()) => {}
    }
    let (id, _) = request(&mut receiver).await;
    tokio::time::advance(Duration::from_millis(501)).await;
    client.on_mgmt_response(id, 200, b"late".to_vec());
    assert!(
        pending.await.is_err(),
        "Готовый поздний ответ не продлевает срок"
    );
    assert!(receiver.try_recv().is_err());
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn reset_cancels_a_retry_delay_without_sending_to_the_new_session() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let pending = call(&client, &sender, 0, "/nodes", Duration::from_secs(5));
    let (id, _) = request(&mut receiver).await;
    client.on_mgmt_response(id, 429, br#"{"retry_after_ms":1000}"#.to_vec());
    tokio::task::yield_now().await;
    client.reset();
    assert!(pending.await.unwrap().is_err());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(receiver.try_recv().is_err());
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn mutations_and_non_429_responses_are_never_retried() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    for (method, status) in [(1, 429), (2, 429), (3, 429), (4, 429), (0, 503)] {
        let pending = call(&client, &sender, method, "/action", Duration::from_secs(5));
        let (id, _) = request(&mut receiver).await;
        let body = br#"{"code":"unavailable","message":"wait","retry_after_ms":1000}"#.to_vec();
        client.on_mgmt_response(id, status, body.clone());
        assert_eq!(pending.await.unwrap().unwrap(), (status, body));
        assert!(receiver.try_recv().is_err());
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(receiver.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn too_many_waiters_are_rejected_without_growing_the_queue() {
    let client = MgmtClient::new();
    let (sender, _receiver) = mpsc::channel(1);
    let mut calls = Vec::new();
    for _ in 0..64 {
        let mut waiting =
            Box::pin(client.mgmt_call(&sender, 0, "/nodes", vec![], Duration::from_secs(5)));
        tokio::select! {
            biased;
            _ = waiting.as_mut() => panic!("Запрос в пределах лимита должен ждать"),
            _ = std::future::ready(()) => {}
        }
        calls.push(waiting);
    }
    let started = Instant::now();
    assert!(client
        .mgmt_call(&sender, 0, "/overflow", vec![], Duration::from_secs(5))
        .await
        .is_err());
    assert_eq!(started.elapsed(), Duration::ZERO);
    drop(calls);
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn diagnostics_bypass_pacing_without_changing_the_admin_interval() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let first = call(&client, &sender, 0, "/nodes", Duration::from_secs(5));
    let (id, _) = request(&mut receiver).await;
    let started = Instant::now();
    client.on_mgmt_response(id, 200, vec![]);
    first.await.unwrap().unwrap();
    for path in [
        crate::diagnostics::PING,
        crate::diagnostics::UP,
        crate::diagnostics::DOWN,
    ] {
        let diagnostic = call(&client, &sender, 1, path, Duration::from_secs(1));
        let (id, received_path) = request(&mut receiver).await;
        assert_eq!(received_path, path);
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "Диагностика не ждет административный интервал"
        );
        client.on_mgmt_response(id, 200, vec![]);
        diagnostic.await.unwrap().unwrap();
    }
    let second = call(&client, &sender, 0, "/health", Duration::from_secs(5));
    let (id, path) = request(&mut receiver).await;
    assert_eq!(path, "/health");
    assert!(started.elapsed() >= Duration::from_millis(200));
    client.on_mgmt_response(id, 200, vec![]);
    second.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_full_diagnostic_window_leaves_capacity_for_admin_requests() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(128);
    let mut calls = Vec::new();
    for _ in 0..64 {
        let mut diagnostic = Box::pin(client.mgmt_call(
            &sender,
            1,
            crate::diagnostics::PING,
            vec![0; 8],
            Duration::from_secs(1),
        ));
        tokio::select! {
            biased;
            _ = diagnostic.as_mut() => panic!("Диагностическая проба должна ждать ответа"),
            _ = std::future::ready(()) => {}
        }
        calls.push(diagnostic);
        tokio::task::yield_now().await;
    }
    let started = Instant::now();
    let mut admin =
        Box::pin(client.mgmt_call(&sender, 0, "/nodes", vec![], Duration::from_secs(1)));
    tokio::select! {
        biased;
        _ = admin.as_mut() => panic!("Диагностика не занимает лимит административной очереди"),
        _ = std::future::ready(()) => {}
    }
    let mut diagnostics = 0;
    let mut admin_requests = 0;
    for _ in 0..65 {
        let (id, path) = request(&mut receiver).await;
        if path == crate::diagnostics::PING {
            diagnostics += 1;
        } else {
            assert_eq!(path, "/nodes");
            admin_requests += 1;
        }
        client.on_mgmt_response(id, 200, vec![]);
    }
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(diagnostics, 64);
    assert_eq!(admin_requests, 1);
    admin.await.unwrap();
    for call in calls {
        call.await.unwrap();
    }
    assert!(client.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn diagnostics_never_retry_rate_limit_responses() {
    let client = MgmtClient::new();
    let (sender, mut receiver) = mpsc::channel(4);
    let diagnostic = call(
        &client,
        &sender,
        0,
        crate::diagnostics::PING,
        Duration::from_secs(1),
    );
    let (id, _) = request(&mut receiver).await;
    client.on_mgmt_response(id, 429, vec![]);
    assert_eq!(diagnostic.await.unwrap().unwrap(), (429, vec![]));
    assert!(receiver.try_recv().is_err());
}
