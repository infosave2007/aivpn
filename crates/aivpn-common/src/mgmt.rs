//! Общий клиент управления внутри туннеля для desktop, iOS и Android.
//! Сопоставляет `MgmtRequest` с `MgmtResponse` и запоминает роль от сервера.
//!
//! [`MgmtClient`] хранит общую очередь отправки, ожидающие ответы, счетчик
//! `req_id` и роль сервера. Канал управления принадлежит вызывающему коду:
//! [`MgmtClient::mgmt_call`] получает `tokio::sync::mpsc::Sender<ControlPayload>`
//! существующего транспорта, общего с остальными управляющими сообщениями.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::protocol::ControlPayload;

// Сервер допускает запрос раз в 200 мс; запас учитывает округление его часов.
const REQUEST_INTERVAL: Duration = Duration::from_millis(210);
const MAX_GET_RETRIES: usize = 2;
const MAX_ACTIVE_REQUESTS: usize = 64;
const RESPONSE_TIMEOUT: &str = "mgmt_call: timed out awaiting request queue or MgmtResponse";

pub(crate) fn request_timed_out(error: &Error) -> bool {
    matches!(error, Error::Session(message) if message == RESPONSE_TIMEOUT)
}

type PendingRequests = Arc<Mutex<HashMap<u32, oneshot::Sender<(u16, Vec<u8>)>>>>;

/// Очередь управления, ожидающие ответы и роль из последнего `Capabilities`.
/// Все клоны разделяют состояние: цикл сессии передает сюда входящие ответы,
/// а FFI и локальный API могут одновременно вызывать `mgmt_call`.
#[derive(Clone)]
pub struct MgmtClient {
    /// Ответы по `req_id`. Запись создается перед фактической отправкой.
    /// Mutex также не дает reset вклиниться между проверкой поколения
    /// и передачей запроса в канал; во время await он не удерживается.
    pending: PendingRequests,
    /// Monotonically increasing `req_id` allocator for `mgmt_call`.
    req_seq: Arc<AtomicU32>,
    /// Cached server-assigned role (0=User,1=Viewer,2=Admin) from the last
    /// `Capabilities` control message, defaulting to User (0) until one
    /// arrives.
    cached_role: Arc<AtomicU8>,
    /// FIFO-очередь сериализует только отправку, ответы могут приходить параллельно.
    send_queue: Arc<tokio::sync::Mutex<Option<Instant>>>,
    /// Лимит административных запросов, общий для отправленных и ожидающих.
    request_slots: Arc<Semaphore>,
    /// Окно диагностики не занимает места в административной очереди.
    diagnostic_slots: Arc<Semaphore>,
    /// Смена поколения прерывает ожидание очереди, канала, ответа и повтора.
    session_epoch: watch::Sender<u64>,
    diagnostic_sender: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
    diagnostic_receiver: Arc<Mutex<Option<Arc<crate::diagnostics::data::Receiver>>>>,
    diagnostic_network: Arc<Mutex<Option<crate::diagnostics::data::Capabilities>>>,
}

pub struct DiagnosticSenderGuard {
    owner: MgmtClient,
    sender: mpsc::Sender<Vec<u8>>,
}

impl Drop for DiagnosticSenderGuard {
    fn drop(&mut self) {
        let mut current = self
            .owner
            .diagnostic_sender
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if current
            .as_ref()
            .is_some_and(|s| s.same_channel(&self.sender))
        {
            *current = None;
            self.owner
                .diagnostic_receiver
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
    }
}

pub(crate) struct DiagnosticReceiverGuard {
    slot: Arc<Mutex<Option<Arc<crate::diagnostics::data::Receiver>>>>,
    receiver: Arc<crate::diagnostics::data::Receiver>,
}

impl Drop for DiagnosticReceiverGuard {
    fn drop(&mut self) {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot
            .as_ref()
            .is_some_and(|r| Arc::ptr_eq(r, &self.receiver))
        {
            *slot = None;
        }
        self.receiver.wake.notify_waiters();
    }
}

impl Default for MgmtClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MgmtClient {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            req_seq: Arc::new(AtomicU32::new(1)),
            cached_role: Arc::new(AtomicU8::new(0)),
            send_queue: Arc::new(tokio::sync::Mutex::new(None)),
            request_slots: Arc::new(Semaphore::new(MAX_ACTIVE_REQUESTS)),
            diagnostic_slots: Arc::new(Semaphore::new(MAX_ACTIVE_REQUESTS)),
            session_epoch: watch::channel(0).0,
            diagnostic_sender: Arc::new(Mutex::new(None)),
            diagnostic_receiver: Arc::new(Mutex::new(None)),
            diagnostic_network: Arc::new(Mutex::new(None)),
        }
    }

    /// Отменить отправленные и ожидающие запросы старой сессии, сбросить роль
    /// в User (0). После переподключения роль определяется новым `Capabilities`.
    /// Счетчик `req_id` сохраняется, чтобы поздние ответы не совпали с новыми.
    pub fn reset(&self) {
        let mut pending = self.pending.lock().expect("mgmt pending mutex poisoned");
        // Тот же mutex защищает проверку поколения перед передачей в канал.
        self.session_epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        pending.clear();
        self.cached_role.store(0, Ordering::Relaxed);
        self.diagnostic_sender
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(receiver) = self
            .diagnostic_receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            receiver.wake.notify_waiters();
        }
    }

    /// Диагностика пишет в ту же очередь RAW IP, что TUN и SOCKS.
    pub fn install_diagnostic_sender(
        &self,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> DiagnosticSenderGuard {
        *self
            .diagnostic_sender
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(sender.clone());
        DiagnosticSenderGuard {
            owner: self.clone(),
            sender,
        }
    }

    pub(crate) fn diagnostic_sender(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.diagnostic_sender
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(crate) fn diagnostic_id(&self) -> u32 {
        loop {
            let id = self.req_seq.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    pub(crate) fn diagnostic_epoch(&self) -> watch::Receiver<u64> {
        self.session_epoch.subscribe()
    }

    pub(crate) fn listen_diagnostic(
        &self,
        receiver: Arc<crate::diagnostics::data::Receiver>,
    ) -> DiagnosticReceiverGuard {
        *self
            .diagnostic_network
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(receiver.capabilities.clone());
        *self
            .diagnostic_receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(receiver.clone());
        DiagnosticReceiverGuard {
            slot: self.diagnostic_receiver.clone(),
            receiver,
        }
    }

    /// Служебные IP-пробы, в том числе запоздалые, не попадают в приложения.
    pub fn on_diagnostic_packet(&self, payload: &[u8]) -> bool {
        let Some(packet) = crate::diagnostics::data::parse(payload) else {
            return false;
        };
        if packet.direction != crate::diagnostics::data::Direction::Download
            || !self
                .diagnostic_network
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|caps| {
                    packet.source == caps.server_ip && packet.destination == caps.client_ip
                })
        {
            return false;
        }
        let receiver = self
            .diagnostic_receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(receiver) = receiver {
            receiver.receive(&packet);
        }
        true
    }

    /// Не отправлять оставшиеся в очереди блоки завершенного теста.
    pub fn diagnostic_packet_active(&self, payload: &[u8]) -> bool {
        let Some(packet) = crate::diagnostics::data::parse(payload) else {
            return true;
        };
        if packet.direction != crate::diagnostics::data::Direction::Upload
            || !self
                .diagnostic_network
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|caps| {
                    packet.source == caps.client_ip && packet.destination == caps.server_ip
                })
        {
            return true;
        }
        self.diagnostic_receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|r| r.request.id == packet.id && r.sending.load(Ordering::Acquire))
    }

    /// Current server-assigned role (0=User, 1=Viewer, 2=Admin), cached from
    /// the last `Capabilities` control message. Defaults to 0 (User) until
    /// one arrives (i.e. before the post-ratchet `Capabilities` push, or for
    /// a server build that predates it).
    pub fn cached_role(&self) -> u8 {
        self.cached_role.load(Ordering::Relaxed)
    }

    /// Store the server-assigned role from an inbound `Capabilities` control
    /// message. `features` is reserved and intentionally not stored today.
    pub fn on_capabilities(&self, role: u8) {
        self.cached_role.store(role, Ordering::Relaxed);
    }

    /// Resolve the oneshot registered for `req_id` (if still pending) with
    /// `(status, body)`. An unknown/already-resolved `req_id` (timed out,
    /// duplicate response, or a response for a request this client never
    /// sent) is silently dropped — never panics.
    pub fn on_mgmt_response(&self, req_id: u32, status: u16, body: Vec<u8>) {
        let receiver = self
            .diagnostic_receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(receiver) = receiver.filter(|r| r.request.response_id == req_id) {
            if status == 200 {
                receiver.acknowledge(&body);
            }
            return;
        }
        let sender = self
            .pending
            .lock()
            .expect("mgmt pending mutex poisoned")
            .remove(&req_id);
        if let Some(tx) = sender {
            // The receiver may already be gone (e.g. `mgmt_call` timed out
            // just before this response landed) — that's a normal race, not
            // an error.
            let _ = tx.send((status, body));
        }
    }

    /// Отправить запрос внутри туннеля и дождаться соответствующего ответа.
    /// `method`: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT. `path` содержит путь
    /// API (например, "/api/v1/clients"), `body` - необязательное тело JSON.
    /// Запрос идет через переданный канал существующего транспорта.
    /// Таймаут включает общую очередь, отправку, ответ и повторы.
    /// GET повторяется не более двух раз и только после явного статуса 429.
    /// Остальные методы, таймауты и ошибки канала не повторяются.
    /// Маршруты диагностики используют отдельный бюджет сервера и не ждут
    /// административный интервал. Повторы согласования v2 выполняет измеритель.
    ///
    /// Возвращает `(status, body)` либо ошибку канала, таймаута, сброса сессии
    /// или переполнения очереди. Отмена и таймаут удаляют запись из pending,
    /// поэтому поздние и повторные ответы отбрасываются.
    pub async fn mgmt_call(
        &self,
        control_tx: &mpsc::Sender<ControlPayload>,
        method: u8,
        path: &str,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        if path.len() > crate::protocol::MAX_MGMT_PATH_SIZE
            || body.len() > crate::protocol::MAX_MGMT_BODY_SIZE
        {
            return Err(Error::InvalidPacket(
                "Management request exceeds protocol limits",
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| Error::Session("mgmt_call: timeout exceeds clock limits".into()))?;
        let mut session = self.session_epoch.subscribe();
        let epoch = *session.borrow_and_update();
        let diagnostic = crate::diagnostics::is_diagnostic(path);
        let slots = if diagnostic {
            &self.diagnostic_slots
        } else {
            &self.request_slots
        };
        let _slot = slots
            .try_acquire()
            .map_err(|_| Error::Session("mgmt_call: management request queue is full".into()))?;

        // При отмене future запись удаляется, даже если внешний select прервал ожидание.
        struct PendingCleanup {
            pending: PendingRequests,
            req_id: u32,
        }
        impl Drop for PendingCleanup {
            fn drop(&mut self) {
                if let Ok(mut pending) = self.pending.lock() {
                    pending.remove(&self.req_id);
                }
            }
        }
        let timeout_error = || Error::Session(RESPONSE_TIMEOUT.into());
        let mut body = body;
        let request = async {
            for attempt in 0..=MAX_GET_RETRIES {
                let mut pacing = if diagnostic {
                    None
                } else {
                    Some(self.send_queue.lock().await)
                };
                if let Some(last_sent) = pacing.as_deref().copied().flatten() {
                    tokio::time::sleep_until(last_sent + REQUEST_INTERVAL).await;
                }
                // Резервирование не кладет команду в заполненный канал после ее отмены.
                let permit = control_tx
                    .reserve()
                    .await
                    .map_err(|e| Error::Channel(e.to_string()))?;
                let (resp_tx, resp_rx) = oneshot::channel();
                let req_id = {
                    let mut pending = self.pending.lock().expect("mgmt pending mutex poisoned");
                    if *self.session_epoch.borrow() != epoch {
                        return Err(Error::Session("mgmt_call: session reset".into()));
                    }
                    // timeout_at сначала опрашивает future: просроченную мутацию
                    // нельзя отправлять даже при готовом разрешении канала.
                    if Instant::now() >= deadline {
                        return Err(timeout_error());
                    }
                    let mut req_id = self.req_seq.fetch_add(1, Ordering::Relaxed);
                    while pending.contains_key(&req_id) {
                        req_id = self.req_seq.fetch_add(1, Ordering::Relaxed);
                    }
                    pending.insert(req_id, resp_tx);
                    permit.send(ControlPayload::MgmtRequest {
                        req_id,
                        method,
                        path: path.to_string(),
                        body: if method == 0 {
                            body.clone()
                        } else {
                            std::mem::take(&mut body)
                        },
                    });
                    if let Some(last_sent) = pacing.as_deref_mut() {
                        *last_sent = Some(Instant::now());
                    }
                    req_id
                };
                let cleanup = PendingCleanup {
                    pending: self.pending.clone(),
                    req_id,
                };
                drop(pacing);

                let response = resp_rx.await.map_err(|_| {
                    Error::Session("mgmt_call: response channel closed unexpectedly".into())
                })?;
                drop(cleanup);
                if Instant::now() >= deadline {
                    return Err(timeout_error());
                }
                if diagnostic || method != 0 || response.0 != 429 || attempt == MAX_GET_RETRIES {
                    return Ok(response);
                }

                #[derive(serde::Deserialize)]
                struct RetryAfter {
                    retry_after_ms: Option<u64>,
                }
                let delay = serde_json::from_slice::<RetryAfter>(&response.1)
                    .ok()
                    .and_then(|error| error.retry_after_ms)
                    .map(Duration::from_millis)
                    .unwrap_or(REQUEST_INTERVAL);
                let retry_at = Instant::now()
                    .checked_add(delay)
                    .unwrap_or(deadline)
                    .min(deadline);
                tokio::time::sleep_until(retry_at).await;
            }
            unreachable!("Ограниченный цикл всегда возвращает последний ответ")
        };
        tokio::select! {
            biased;
            _ = session.changed() => Err(Error::Session("mgmt_call: session reset".into())),
            result = tokio::time::timeout_at(deadline, request) => {
                result.unwrap_or_else(|_| Err(timeout_error()))
            }
        }
    }
}

#[cfg(test)]
mod scheduling_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_queue_is_cancelled_and_old_guards_cannot_clear_a_new_session() {
        use crate::diagnostics::data;
        let mgmt = MgmtClient::new();
        let (old_tx, _old_rx) = mpsc::channel(8);
        let old_guard = mgmt.install_diagnostic_sender(old_tx);
        mgmt.reset();
        let (tx, _rx) = mpsc::channel(8);
        let _sender = mgmt.install_diagnostic_sender(tx.clone());
        drop(old_guard);
        assert!(mgmt.diagnostic_sender().unwrap().same_channel(&tx));
        let request = data::Start {
            id: [1; 16],
            seed: [2; 32],
            direction: data::Direction::Upload,
            response_id: 42,
            duration_ms: 1000,
        };
        let caps = data::Capabilities {
            version: 2,
            client_ip: "10.0.0.2".parse().unwrap(),
            server_ip: "10.0.0.1".parse().unwrap(),
            download_limit_kbps: None,
        };
        let receiver = Arc::new(data::Receiver::new(request.clone(), caps.clone()));
        let _listen = mgmt.listen_diagnostic(receiver.clone());
        let packet = data::packet(
            caps.client_ip,
            caps.server_ip,
            request.id,
            &request.seed,
            data::Direction::Upload,
            0,
        );
        assert!(mgmt.diagnostic_packet_active(&packet));
        receiver.sending.store(false, Ordering::Release);
        assert!(!mgmt.diagnostic_packet_active(&packet));
        assert!(mgmt.diagnostic_packet_active(&[0x45; 100]));
        let other = data::packet(
            caps.client_ip,
            "192.0.2.10".parse().unwrap(),
            request.id,
            &request.seed,
            data::Direction::Upload,
            0,
        );
        assert!(
            mgmt.diagnostic_packet_active(&other),
            "Похожий UDP-пакет вне адресов диагностики остается обычным трафиком"
        );
        assert!(!mgmt.on_diagnostic_packet(&other));
        mgmt.reset();
        assert!(mgmt.diagnostic_sender().is_none());
        assert!(!mgmt.diagnostic_packet_active(&packet));
    }

    #[tokio::test(start_paused = true)]
    async fn mgmt_call_timeout_includes_waiting_for_channel_capacity() {
        let mgmt = MgmtClient::new();
        let (control_tx, mut control_rx) = mpsc::channel(1);
        control_tx
            .send(ControlPayload::Keepalive { send_ts: 1 })
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(11),
            mgmt.mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            ),
        )
        .await
        .expect("Переполненный канал должен учитывать таймаут запроса");
        assert!(result.is_err());
        assert!(mgmt.pending.lock().unwrap().is_empty());
        assert!(matches!(
            control_rx.try_recv(),
            Ok(ControlPayload::Keepalive { .. })
        ));
        assert!(control_rx.try_recv().is_err());
    }

    #[test]
    fn cached_role_defaults_to_user_before_any_capabilities_message() {
        let mgmt = MgmtClient::new();
        assert_eq!(mgmt.cached_role(), 0);
    }

    #[test]
    fn on_capabilities_updates_cached_role() {
        let mgmt = MgmtClient::new();
        assert_eq!(mgmt.cached_role(), 0);
        mgmt.on_capabilities(2);
        assert_eq!(mgmt.cached_role(), 2);
    }

    #[test]
    fn reset_clears_pending_and_cached_role() {
        let mgmt = MgmtClient::new();
        mgmt.on_capabilities(2);
        let (resp_tx, _resp_rx) = oneshot::channel::<(u16, Vec<u8>)>();
        mgmt.pending.lock().unwrap().insert(1, resp_tx);

        mgmt.reset();

        assert_eq!(mgmt.cached_role(), 0);
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn on_mgmt_response_resolves_the_matching_pending_oneshot() {
        let mgmt = MgmtClient::new();
        let (resp_tx, mut resp_rx) = oneshot::channel::<(u16, Vec<u8>)>();
        mgmt.pending.lock().unwrap().insert(1, resp_tx);

        mgmt.on_mgmt_response(1, 200, b"{\"ok\":true}".to_vec());

        let (status, body) = resp_rx
            .try_recv()
            .expect("oneshot must resolve immediately once completed");
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"ok\":true}".to_vec());
        assert!(
            mgmt.pending.lock().unwrap().is_empty(),
            "completed entry must be removed from pending"
        );
    }

    #[test]
    fn mgmt_response_for_unknown_req_id_is_dropped_without_panic() {
        let mgmt = MgmtClient::new();
        // No req_id=42 was ever registered — must not panic, must be a no-op.
        mgmt.on_mgmt_response(42, 404, vec![]);
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mgmt_call_sends_request_and_resolves_on_matching_response() {
        let mgmt = MgmtClient::new();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);

        let pending = mgmt.pending.clone();
        let responder = tokio::spawn(async move {
            let sent = control_rx.recv().await.expect("MgmtRequest must be sent");
            match sent {
                ControlPayload::MgmtRequest {
                    req_id,
                    method,
                    path,
                    body,
                } => {
                    assert_eq!(method, 0);
                    assert_eq!(path, "/api/v1/clients");
                    assert!(body.is_empty());
                    if let Some(tx) = pending.lock().unwrap().remove(&req_id) {
                        let _ = tx.send((200, b"[]".to_vec()));
                    }
                }
                other => panic!("expected MgmtRequest, got {:?}", other),
            }
        });

        let (status, body) = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await
            .expect("mgmt_call must resolve once the response is delivered");

        responder.await.expect("responder task must not panic");
        assert_eq!(status, 200);
        assert_eq!(body, b"[]".to_vec());
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mgmt_call_times_out_when_no_response_arrives() {
        // Paused virtual time: `mgmt_call`'s `tokio::time::timeout`
        // auto-advances past its deadline as soon as the runtime is idle,
        // instead of the test waiting real seconds.
        tokio::time::pause();
        let mgmt = MgmtClient::new();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        // Drain the outbound MgmtRequest so the bounded channel never fills,
        // but never send a MgmtResponse back.
        let _drainer = tokio::spawn(async move {
            let _ = control_rx.recv().await;
        });

        let result = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await;

        assert!(
            result.is_err(),
            "mgmt_call must return an error when no MgmtResponse arrives within the timeout"
        );
        assert!(
            mgmt.pending.lock().unwrap().is_empty(),
            "the timed-out entry must be removed from pending, not leaked"
        );
    }

    #[tokio::test]
    async fn mgmt_call_dropped_mid_flight_cleans_up_pending_entry() {
        // Regression: an embedder can cancel (drop) the `mgmt_call` future
        // itself — external `select!`/FFI timeout — after the pending entry
        // was registered but before any response/timeout. The Drop-guard
        // must remove the entry, otherwise repeated cancellations grow
        // `pending` without bound until `reset()`.
        let mgmt = MgmtClient::new();
        let (control_tx, _control_rx) = mpsc::channel::<ControlPayload>(4);

        {
            let fut = mgmt.mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            );
            tokio::pin!(fut);
            // Poll the future exactly once: it registers the pending entry
            // and parks awaiting the response (`ready(())` wins the race).
            tokio::select! {
                biased;
                _ = &mut fut => panic!("mgmt_call must not resolve with no responder"),
                _ = std::future::ready(()) => {}
            }
            assert_eq!(
                mgmt.pending.lock().unwrap().len(),
                1,
                "the in-flight call must have registered its pending entry"
            );
            // `fut` is dropped here — cancelled mid-flight.
        }

        assert!(
            mgmt.pending.lock().unwrap().is_empty(),
            "a cancelled (dropped) mgmt_call must not leak its pending entry"
        );
    }

    #[tokio::test]
    async fn mgmt_call_late_response_after_timeout_is_dropped_not_misdelivered() {
        // Regression test for the race the P2.R task description calls out:
        // a response that arrives AFTER the timeout already removed the
        // pending entry must be silently dropped by `on_mgmt_response`, not
        // panic and not resolve a future, unrelated `mgmt_call` with the same
        // (reused) req_id.
        tokio::time::pause();
        let mgmt = MgmtClient::new();
        let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(4);
        let req_id_holder: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let req_id_holder2 = req_id_holder.clone();
        let _drainer = tokio::spawn(async move {
            if let Some(ControlPayload::MgmtRequest { req_id, .. }) = control_rx.recv().await {
                *req_id_holder2.lock().unwrap() = Some(req_id);
            }
        });

        let result = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await;
        assert!(result.is_err());

        let req_id = req_id_holder.lock().unwrap().expect("req_id was captured");
        // Simulate the late response landing after the timeout already fired.
        mgmt.on_mgmt_response(req_id, 200, b"late".to_vec());
        // Must not panic; pending must still be empty (nothing to misdeliver
        // to — no receiver was resolved).
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mgmt_call_errors_immediately_when_channel_closed() {
        let mgmt = MgmtClient::new();
        let (control_tx, control_rx) = mpsc::channel::<ControlPayload>(4);
        drop(control_rx);

        let result = mgmt
            .mgmt_call(
                &control_tx,
                0,
                "/api/v1/clients",
                vec![],
                Duration::from_secs(10),
            )
            .await;
        assert!(result.is_err());
        assert!(mgmt.pending.lock().unwrap().is_empty());
    }
}
