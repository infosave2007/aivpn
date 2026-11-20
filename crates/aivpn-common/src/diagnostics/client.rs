//! Скорость измеряется пакетами DATA, служебные RPC только согласуют фазы.

use super::{data, BenchResult, MeasurementMethod, CAPABILITIES, PULL, RECEIPT, START, STOP};
use crate::{mgmt::MgmtClient, protocol::ControlPayload, Error, Result};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

struct StopGuard {
    tx: mpsc::Sender<ControlPayload>,
    id: [u8; 16],
    request_id: u32,
    epoch: watch::Receiver<u64>,
    generation: u64,
}
impl Drop for StopGuard {
    fn drop(&mut self) {
        if *self.epoch.borrow() == self.generation {
            let _ = self.tx.try_send(ControlPayload::MgmtRequest {
                req_id: self.request_id,
                method: 1,
                path: STOP.into(),
                body: self.id.to_vec(),
            });
        }
    }
}

async fn call(
    mgmt: &MgmtClient,
    tx: &mpsc::Sender<ControlPayload>,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>)> {
    let mut epoch = mgmt.diagnostic_epoch();
    let generation = *epoch.borrow_and_update();
    for attempt in 0..3 {
        let response = mgmt
            .mgmt_call(tx, 1, path, body.clone(), Duration::from_secs(2))
            .await;
        tracing::debug!(
            path,
            attempt,
            status = response.as_ref().ok().map(|(status, _)| *status),
            error = ?response.as_ref().err(),
            "Согласование диагностической фазы"
        );
        if *epoch.borrow() != generation || attempt == 2 {
            return response;
        }
        if let Ok((429, error)) = &response {
            // Явный отказ не создал DATA: повтор PULL допустим после паузы.
            let delay = serde_json::from_slice::<crate::mgmt_error::ManagementError>(error)
                .ok()
                .and_then(|error| error.retry_after_ms)
                .unwrap_or(200)
                .clamp(25, 1000);
            tokio::select! {
                _ = epoch.changed() => return Err(Error::Session("VPN session changed during benchmark".into())),
                _ = tokio::time::sleep(Duration::from_millis(delay)) => {},
            }
        } else if response.as_ref().is_err_and(crate::mgmt::request_timed_out)
            && matches!(path, CAPABILITIES | START | RECEIPT | STOP)
        {
            // Потерянный ответ PULL не подтверждает отказ: повтор создал бы новые блоки.
        } else {
            return response;
        }
    }
    unreachable!("Последняя попытка возвращает ответ")
}

pub(super) async fn run(
    mgmt: MgmtClient,
    control: mpsc::Sender<ControlPayload>,
    duration: Duration,
) -> Result<Option<BenchResult>> {
    let Some(sender) = mgmt.diagnostic_sender() else {
        return Ok(None);
    };
    let (status, body) = call(&mgmt, &control, CAPABILITIES, Vec::new()).await?;
    if matches!(status, 403 | 404 | 501) {
        return Ok(None);
    }
    if status != 200 {
        return Err(Error::Session(format!(
            "Data diagnostics unavailable (status {status})"
        )));
    }
    let capabilities: data::Capabilities = serde_json::from_slice(&body)
        .map_err(|_| Error::InvalidPacket("Invalid diagnostic capabilities"))?;
    if capabilities.version != 2 {
        return Err(Error::InvalidPacket("Unsupported diagnostic version"));
    }
    let phase = duration.clamp(Duration::from_secs(3), Duration::from_secs(30)) / 3;
    let (latency_mgmt, latency_control) = (mgmt.clone(), control.clone());
    let mut result = super::measure_latency(
        move |path, body| {
            let (mgmt, control) = (latency_mgmt.clone(), latency_control.clone());
            async move { call(&mgmt, &control, path, body).await }
        },
        phase,
    )
    .await?;
    let rtt = Duration::from_secs_f64((result.latency_p50_ms / 1000.0).clamp(0.001, 1.0));
    let mut limited = false;
    for direction in [data::Direction::Upload, data::Direction::Download] {
        let request = data::Start {
            id: rand::random(),
            seed: rand::random(),
            direction,
            response_id: mgmt.diagnostic_id().max(1),
            duration_ms: (phase.as_millis() as u64 + 4000).min(15_000),
        };
        let receiver = Arc::new(data::Receiver::new(request.clone(), capabilities.clone()));
        let _receiver_guard = mgmt.listen_diagnostic(receiver.clone());
        let mut epoch = mgmt.diagnostic_epoch();
        let generation = *epoch.borrow_and_update();
        let _stop = StopGuard {
            tx: control.clone(),
            id: request.id,
            request_id: mgmt.diagnostic_id(),
            epoch: epoch.clone(),
            generation,
        };
        let (status, _) = call(
            &mgmt,
            &control,
            START,
            serde_json::to_vec(&request).unwrap(),
        )
        .await?;
        if status != 200 {
            return Err(Error::Session(format!(
                "Cannot start data benchmark (status {status})"
            )));
        }
        let started = Instant::now();
        let deadline = started + phase;
        match direction {
            data::Direction::Upload => {
                let sent =
                    upload(&sender, &receiver, &mut epoch, generation, deadline, rtt).await?;
                receiver
                    .sending
                    .store(false, std::sync::atomic::Ordering::Release);
                drain(&receiver, &mut epoch, rtt).await?;
                let (status, receipt) = call(&mgmt, &control, RECEIPT, request.id.to_vec()).await?;
                if status != 200 || data::parse_receipt(&receipt, &request.id).is_none() {
                    return Err(Error::Session(format!(
                        "Missing upload receipt (status {status})"
                    )));
                }
                if data::parse_receipt(&receipt, &request.id).unwrap().1
                    > sent * data::DATA_BYTES as u64
                {
                    return Err(Error::InvalidPacket("Upload receipt exceeds sent bytes"));
                }
                receiver.acknowledge(&receipt);
            }
            data::Direction::Download => {
                download(
                    &mgmt, &control, &receiver, &mut epoch, generation, deadline, rtt,
                )
                .await?;
                drain(&receiver, &mut epoch, rtt).await?;
                let _ = call(&mgmt, &control, STOP, request.id.to_vec()).await?;
            }
        }
        let (credit, bytes) = receiver.snapshot();
        limited |= credit >= data::MAX_BYTES / data::DATA_BYTES as u64;
        if bytes == 0 {
            return Err(Error::Session(
                "No confirmed DATA bytes from the active VPN session".into(),
            ));
        }
        let speed = bytes as f64 * 8.0 / started.elapsed().as_secs_f64().max(0.001) / 1000.0;
        let window_ceiling =
            data::WINDOW as f64 * data::DATA_BYTES as f64 * 8.0 / rtt.as_secs_f64() / 1000.0;
        limited |= speed >= window_ceiling * 0.8;
        match direction {
            data::Direction::Upload => result.throughput_up_kbps = speed,
            data::Direction::Download => {
                limited |= capabilities.download_may_be_limited(speed);
                result.throughput_down_kbps = speed;
            }
        }
    }
    result.throughput_method = MeasurementMethod::Data;
    result.throughput_limited = limited;
    Ok(Some(result))
}

async fn upload(
    sender: &mpsc::Sender<Vec<u8>>,
    receiver: &data::Receiver,
    epoch: &mut watch::Receiver<u64>,
    generation: u64,
    deadline: Instant,
    rtt: Duration,
) -> Result<u64> {
    let mut sent = 0u64;
    let mut probe = false;
    while Instant::now() < deadline {
        if *epoch.borrow() != generation {
            return Err(Error::Session(
                "VPN session changed during benchmark".into(),
            ));
        }
        let notified = receiver.wake.notified();
        let (credit, _) = receiver.snapshot();
        let window = (64 + credit).min(data::WINDOW);
        if sent.saturating_sub(credit) < window || probe {
            let packet = data::packet(
                receiver.capabilities.client_ip,
                receiver.capabilities.server_ip,
                receiver.request.id,
                &receiver.request.seed,
                data::Direction::Upload,
                sent,
            );
            tokio::select! {
                biased;
                _ = epoch.changed() => return Err(Error::Session("VPN session changed during benchmark".into())),
                _ = tokio::time::sleep_until(deadline) => break,
                result = sender.send(packet) => result.map_err(|e| Error::Channel(e.to_string()))?,
            }
            sent += 1;
            probe = false;
            if sent >= data::MAX_BYTES / data::DATA_BYTES as u64 {
                break;
            }
            if sent.is_multiple_of(16) {
                tokio::task::yield_now().await;
            }
        } else {
            tokio::select! {
                _ = epoch.changed() => return Err(Error::Session("VPN session changed during benchmark".into())),
                _ = tokio::time::sleep_until(deadline) => break,
                _ = notified => {},
                _ = tokio::time::sleep((rtt * 2).max(Duration::from_millis(50))) => probe = true,
            }
        }
    }
    if receiver.snapshot().1 > sent * data::DATA_BYTES as u64 {
        return Err(Error::InvalidPacket("Upload receipt exceeds sent bytes"));
    }
    Ok(sent)
}

async fn download(
    mgmt: &MgmtClient,
    control: &mpsc::Sender<ControlPayload>,
    receiver: &data::Receiver,
    epoch: &mut watch::Receiver<u64>,
    generation: u64,
    deadline: Instant,
    rtt: Duration,
) -> Result<()> {
    let mut jobs = tokio::task::JoinSet::new();
    let mut estimated = 0u64;
    let mut probe = false;
    while Instant::now() < deadline {
        if *epoch.borrow() != generation {
            return Err(Error::Session(
                "VPN session changed during benchmark".into(),
            ));
        }
        let notified = receiver.wake.notified();
        let (credit, _) = receiver.snapshot();
        if credit >= data::MAX_BYTES / data::DATA_BYTES as u64 {
            break;
        }
        let window = (64 + credit).min(data::WINDOW);
        while jobs.len() < 32 && (estimated.saturating_sub(credit) < window || probe) {
            let count = if probe {
                1
            } else {
                data::BATCH.min((window - estimated.saturating_sub(credit)) as usize)
            };
            let (mgmt, control) = (mgmt.clone(), control.clone());
            let body = serde_json::to_vec(&data::Pull {
                id: receiver.request.id,
                count,
            })
            .unwrap();
            jobs.spawn(async move {
                let (status, body) = match call(&mgmt, &control, PULL, body).await {
                    Ok(reply) => reply,
                    Err(error) if crate::mgmt::request_timed_out(&error) => {
                        tracing::debug!(%error, "Нет ответа на порцию диагностических данных");
                        // DATA могли уйти до потери ответа. Освобождаем окно
                        // только подтвержденным счетчиком или редкой пробой.
                        return Ok(0);
                    }
                    Err(error) => return Err(error),
                };
                if status != 200 || body.len() != 2 {
                    return Err(Error::Session(format!(
                        "Diagnostic pull failed (status {status})"
                    )));
                }
                let sent = u16::from_be_bytes(body.try_into().unwrap()) as usize;
                if sent > count {
                    return Err(Error::InvalidPacket("Invalid diagnostic pull receipt"));
                }
                if sent == 0 {
                    // Исчерпан бюджет или заполнена очередь: не опрашивать сервер без паузы.
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok((count - sent) as u64)
            });
            estimated += count as u64;
            probe = false;
        }
        tokio::select! {
            _ = epoch.changed() => return Err(Error::Session("VPN session changed during benchmark".into())),
            _ = tokio::time::sleep_until(deadline) => break,
            _ = notified => {},
            result = jobs.join_next(), if !jobs.is_empty() => {
                if let Some(result) = result {
                    let unsent = result.map_err(|e| Error::Session(e.to_string()))??;
                    estimated = estimated.saturating_sub(unsent);
                }
            }
            _ = tokio::time::sleep((rtt * 2).max(Duration::from_millis(50))) => probe = true,
        }
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    Ok(())
}

async fn drain(
    receiver: &data::Receiver,
    epoch: &mut watch::Receiver<u64>,
    rtt: Duration,
) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(2);
    let quiet = (rtt * 2).clamp(Duration::from_millis(10), Duration::from_millis(500));
    loop {
        tokio::select! {
            _ = epoch.changed() => return Err(Error::Session("VPN session changed during benchmark".into())),
            _ = tokio::time::sleep_until(end) => return Ok(()),
            _ = tokio::time::sleep(quiet) => return Ok(()),
            _ = receiver.wake.notified() => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn lost_pull_reply_does_not_reopen_the_whole_window() {
        let mgmt = MgmtClient::new();
        let (tx, mut rx) = mpsc::channel(64);
        let request = data::Start {
            id: [1; 16],
            seed: [2; 32],
            direction: data::Direction::Download,
            response_id: 42,
            duration_ms: 5000,
        };
        let receiver = data::Receiver::new(
            request,
            data::Capabilities {
                version: 2,
                client_ip: "10.0.0.2".parse().unwrap(),
                server_ip: "10.0.0.1".parse().unwrap(),
                download_limit_kbps: None,
            },
        );
        let job = tokio::spawn(async move {
            let mut epoch = mgmt.diagnostic_epoch();
            let generation = *epoch.borrow();
            download(
                &mgmt,
                &tx,
                &receiver,
                &mut epoch,
                generation,
                Instant::now() + Duration::from_millis(2100),
                Duration::from_secs(2),
            )
            .await
        });
        let Some(ControlPayload::MgmtRequest { body, .. }) = rx.recv().await else {
            panic!("Ожидался PULL");
        };
        assert_eq!(
            serde_json::from_slice::<data::Pull>(&body).unwrap().count,
            64
        );
        job.await.unwrap().unwrap();
        assert!(
            rx.recv().await.is_none(),
            "Таймаут ответа не доказывает, что DATA не отправлены"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_pull_waits_before_retrying_the_same_request() {
        let mgmt = MgmtClient::new();
        let (tx, mut rx) = mpsc::channel(8);
        let caller = mgmt.clone();
        let job = tokio::spawn(async move { call(&caller, &tx, PULL, vec![1, 2, 3]).await });
        let Some(ControlPayload::MgmtRequest { req_id, body, .. }) = rx.recv().await else {
            panic!("Ожидался первый запрос");
        };
        assert_eq!(body, [1, 2, 3]);
        let rejected_at = Instant::now();
        mgmt.on_mgmt_response(
            req_id,
            429,
            br#"{"code":"rate_limited","message":"wait","retry_after_ms":200}"#.to_vec(),
        );
        let next = rx.recv().await;
        assert!(
            next.is_some(),
            "Отклоненная порция не завершает весь benchmark"
        );
        let Some(ControlPayload::MgmtRequest {
            req_id, body, path, ..
        }) = next
        else {
            panic!("Ожидался повтор запроса");
        };
        assert_eq!(path, PULL);
        assert_eq!(body, [1, 2, 3]);
        assert!(rejected_at.elapsed() >= Duration::from_millis(200));
        mgmt.on_mgmt_response(req_id, 200, vec![0, 0]);
        assert_eq!(job.await.unwrap().unwrap(), (200, vec![0, 0]));
    }

    #[tokio::test(start_paused = true)]
    async fn idempotent_phase_survives_two_lost_replies() {
        let mgmt = MgmtClient::new();
        let (tx, mut rx) = mpsc::channel(8);
        let caller = mgmt.clone();
        let job = tokio::spawn(async move { call(&caller, &tx, CAPABILITIES, Vec::new()).await });
        for _ in 0..2 {
            assert!(rx.recv().await.is_some());
            tokio::time::advance(Duration::from_secs(2)).await;
        }
        let Some(ControlPayload::MgmtRequest { req_id, .. }) = rx.recv().await else {
            panic!("Третья попытка должна использовать оставшийся бюджет");
        };
        mgmt.on_mgmt_response(req_id, 200, b"capabilities".to_vec());
        assert_eq!(job.await.unwrap().unwrap(), (200, b"capabilities".to_vec()));
    }

    #[tokio::test(start_paused = true)]
    async fn lost_pull_is_not_repeated() {
        let mgmt = MgmtClient::new();
        let (tx, mut rx) = mpsc::channel(8);
        let caller = mgmt.clone();
        let job = tokio::spawn(async move { call(&caller, &tx, PULL, vec![4]).await });
        assert!(rx.recv().await.is_some());
        assert!(job.await.unwrap().is_err());
        assert!(
            rx.recv().await.is_none(),
            "Потерянный ответ не разрешает повтор DATA"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn throttled_stop_has_bounded_retries() {
        let mgmt = MgmtClient::new();
        let (tx, mut rx) = mpsc::channel(8);
        let caller = mgmt.clone();
        let job = tokio::spawn(async move { call(&caller, &tx, STOP, vec![7; 16]).await });
        for _ in 0..3 {
            let Some(ControlPayload::MgmtRequest {
                req_id, body, path, ..
            }) = rx.recv().await
            else {
                panic!("Ожидался запрос завершения");
            };
            assert_eq!(path, STOP);
            assert_eq!(body, [7; 16]);
            mgmt.on_mgmt_response(req_id, 429, Vec::new());
        }
        assert_eq!(job.await.unwrap().unwrap().0, 429);
        assert!(
            rx.recv().await.is_none(),
            "Число повторов должно быть ограничено"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_cancels_throttled_diagnostic_retry() {
        let mgmt = MgmtClient::new();
        let (tx, mut rx) = mpsc::channel(8);
        let caller = mgmt.clone();
        let job = tokio::spawn(async move { call(&caller, &tx, START, vec![4]).await });
        let Some(ControlPayload::MgmtRequest { req_id, .. }) = rx.recv().await else {
            panic!("Ожидался запрос запуска");
        };
        mgmt.on_mgmt_response(req_id, 429, Vec::new());
        tokio::task::yield_now().await;
        mgmt.reset();
        assert!(job.await.unwrap().is_err());
        assert!(
            rx.recv().await.is_none(),
            "Старый запрос не переносится в новую сессию"
        );
    }

    #[tokio::test]
    async fn closed_control_channel_stops_download_instead_of_spinning() {
        let mgmt = MgmtClient::new();
        let (tx, rx) = mpsc::channel(8);
        drop(rx);
        let request = data::Start {
            id: [1; 16],
            seed: [2; 32],
            direction: data::Direction::Download,
            response_id: 42,
            duration_ms: 1000,
        };
        let caps = data::Capabilities {
            version: 2,
            client_ip: "10.0.0.2".parse().unwrap(),
            server_ip: "10.0.0.1".parse().unwrap(),
            download_limit_kbps: None,
        };
        let receiver = data::Receiver::new(request, caps);
        let mut epoch = mgmt.diagnostic_epoch();
        let generation = *epoch.borrow();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            download(
                &mgmt,
                &tx,
                &receiver,
                &mut epoch,
                generation,
                Instant::now() + Duration::from_secs(5),
                Duration::from_millis(10),
            ),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(Error::Channel(_)))),
            "Закрытый канал должен завершать тест: {result:?}"
        );
    }
}
