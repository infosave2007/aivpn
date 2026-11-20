//! Согласование теста и обычные DATA-пробы без крупных управляющих сообщений.

use super::*;
use aivpn_common::diagnostics::{self as diag, data};

impl Gateway {
    pub(super) async fn diagnostic_request(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        method: u8,
        path: &str,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        if matches!(path, diag::PING | diag::UP | diag::DOWN) {
            return diag::response(method, path, body);
        }
        if method != 1 || body.len() > 512 {
            return (400, Vec::new());
        }
        // Получатель передается воркерам только после запуска пути downlink.
        if self.chain_reverse_rx.is_some() || self.chain_reverse_tx.is_closed() {
            return (501, Vec::new());
        }
        match path {
            diag::CAPABILITIES => self.diagnostic_capabilities(session, body),
            diag::START => self.diagnostic_start(session, body),
            diag::PULL => self.diagnostic_pull(session, body).await,
            _ => self.diagnostic_finish(session, path, body),
        }
    }

    fn diagnostic_capabilities(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        if !body.is_empty() {
            return (400, Vec::new());
        }
        let Some(client_ip) = session.lock().vpn_ip else {
            return (503, Vec::new());
        };
        let capabilities = data::Capabilities {
            version: 2,
            client_ip,
            server_ip: self.config.network_config.server_vpn_ip,
            download_limit_kbps: Some(
                diag::PACKETS_PER_SECOND * data::DATA_BYTES as u64 * 8 / 1000,
            ),
        };
        (200, serde_json::to_vec(&capabilities).unwrap())
    }

    fn diagnostic_start(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let now = Instant::now();
        let Ok(request) = serde_json::from_slice::<data::Start>(body) else {
            return (400, Vec::new());
        };
        let mut current = session.lock();
        if let Some(previous) = &current.diagnostic_state {
            if previous.active(&previous.request.id, now) {
                if previous.request == request {
                    return (200, Vec::new());
                }
                return (409, Vec::new());
            }
        }
        let Some(ip) = current.vpn_ip else {
            return (503, Vec::new());
        };
        let Some(state) =
            data::ServerState::new(request, ip, self.config.network_config.server_vpn_ip, now)
        else {
            return (400, Vec::new());
        };
        current.diagnostic_state = Some(state);
        self.refresh_kernel_session(&mut current);
        (200, Vec::new())
    }

    async fn diagnostic_pull(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let now = Instant::now();
        let Ok(pull) = serde_json::from_slice::<data::Pull>(body) else {
            return (400, Vec::new());
        };
        if pull.count == 0 || pull.count > data::BATCH {
            return (400, Vec::new());
        }
        if !session
            .lock()
            .diagnostic_state
            .as_ref()
            .is_some_and(|state| {
                state.active(&pull.id, now) && state.request.direction == data::Direction::Download
            })
        {
            return (409, Vec::new());
        }
        let sent = self.diagnostic_generate(session, &pull).await;
        (200, sent.to_be_bytes().to_vec())
    }

    async fn diagnostic_generate(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        pull: &data::Pull,
    ) -> u16 {
        let mut sent = 0u16;
        for _ in 0..pull.count {
            // Полная очередь не вызывает генерацию блока и не задерживает control.
            let Ok(permit) = self.chain_reverse_tx.try_reserve() else {
                break;
            };
            let packet = {
                let mut current = session.lock();
                if !current.diagnostic_data_budget.take(Instant::now()) {
                    break;
                }
                current
                    .diagnostic_state
                    .as_mut()
                    .filter(|state| state.request.id == pull.id)
                    .and_then(|state| state.download(Instant::now()))
            };
            let Some(packet) = packet else {
                break;
            };
            permit.send(packet);
            sent += 1;
            if sent.is_multiple_of(8) {
                tokio::task::yield_now().await;
            }
        }
        sent
    }

    fn diagnostic_finish(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        path: &str,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let now = Instant::now();
        if body.len() != 16 {
            return (400, Vec::new());
        }
        let mut current = session.lock();
        if path == diag::STOP && current.diagnostic_state.is_none() {
            return (200, Vec::new());
        }
        let Some(state) = current
            .diagnostic_state
            .as_ref()
            .filter(|state| state.request.id == body)
        else {
            return (404, Vec::new());
        };
        if path == diag::RECEIPT {
            let receipt = data::receipt(
                state.request.id,
                state.receipts.credit,
                state.receipts.bytes,
            );
            current.diagnostic_state.as_mut().unwrap().finish(now);
            self.refresh_kernel_session(&mut current);
            return (200, receipt);
        }
        if path == diag::STOP {
            current.diagnostic_state = None;
            self.refresh_kernel_session(&mut current);
            return (200, Vec::new());
        }
        (404, Vec::new())
    }

    pub(super) async fn diagnostic_upload(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        payload: &[u8],
    ) -> Result<bool> {
        let Some(packet) = data::parse(payload) else {
            return Ok(false);
        };
        if packet.destination != self.config.network_config.server_vpn_ip {
            return Ok(false);
        }
        let ack = {
            let mut current = session.lock();
            current.diagnostic_state.as_mut().and_then(|state| {
                state
                    .upload(&packet, Instant::now())
                    .map(|body| (state.request.response_id, body))
            })
        };
        if let Some((req_id, body)) = ack {
            self.send_control_message(
                &ControlPayload::MgmtResponse {
                    req_id,
                    status: 200,
                    body,
                },
                session,
            )
            .await?;
        }
        Ok(true)
    }
}
