//! Управление текущим работником без локального listener и файлов с токенами.
use crate::record_cmd::{RecordingLocalStatus, RecordingStatusStore};
use aivpn_common::{mgmt::MgmtClient, ControlPayload};
use std::{io, time::Duration};
use tokio::sync::{mpsc, oneshot};

pub use aivpn_common::local_admin::SessionStatistics;

/// Создается для одного экземпляра клиента. После завершения run каналы закрыты.
#[derive(Clone)]
pub struct SessionAdministration {
    pub(crate) mgmt: MgmtClient,
    pub(crate) control: mpsc::Sender<ControlPayload>,
    pub(crate) requests: mpsc::Sender<ClientRequest>,
    pub(crate) status: RecordingStatusStore,
}

impl SessionAdministration {
    /// Полномочия владельца и поколение сеанса проверяет служба до вызова.
    pub async fn execute(&self, command: &str) -> io::Result<String> {
        if self.control.is_closed() {
            return Err(closed());
        }
        if command.is_empty() || command.len() > aivpn_common::local_admin::MAX_FRAME {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        crate::admin_ipc::execute(command, &self.mgmt, &self.control, &self.requests)
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
    }

    pub fn recording_status(&self) -> Option<RecordingLocalStatus> {
        if self.control.is_closed() {
            return None;
        }
        self.status.read_local_status()
    }

    pub async fn statistics(&self) -> io::Result<SessionStatistics> {
        if self.control.is_closed() {
            return Err(closed());
        }
        let (reply, response) = oneshot::channel();
        tokio::time::timeout(Duration::from_secs(2), async {
            self.requests
                .send(ClientRequest::Statistics(reply))
                .await
                .map_err(|_| closed())?;
            response.await.map_err(|_| closed())
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Сеанс работника завершен")
}

pub(crate) enum ClientRequest {
    Recording(String),
    Statistics(oneshot::Sender<SessionStatistics>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_backpressure_returns_an_error_without_waiting_for_the_session_loop() {
        let (control, _controls) = mpsc::channel(1);
        let (recording, _commands) = mpsc::channel(1);
        recording
            .try_send(ClientRequest::Recording("record_stop".into()))
            .unwrap();
        let handle = SessionAdministration {
            mgmt: MgmtClient::new(),
            control,
            requests: recording,
            status: RecordingStatusStore::in_memory(),
        };
        let result =
            tokio::time::timeout(Duration::from_millis(100), handle.execute("record_stop")).await;
        assert!(
            result.is_ok(),
            "Полная очередь записи не должна задерживать запрос управления"
        );
        assert!(result.unwrap().is_err());
    }

    #[tokio::test]
    async fn administration_reuses_role_and_recording_dispatch_without_an_admin_listener() {
        let mgmt = MgmtClient::new();
        mgmt.on_capabilities(2);
        let (control, controls) = mpsc::channel(4);
        let (recording, mut commands) = mpsc::channel(4);
        let status = RecordingStatusStore::in_memory();
        let handle = SessionAdministration {
            mgmt,
            control,
            requests: recording,
            status: status.clone(),
        };
        assert_eq!(handle.execute("role").await.unwrap(), "2");
        assert_eq!(
            handle.execute("record_start:test-call").await.unwrap(),
            "ok"
        );
        assert!(
            matches!(commands.recv().await.unwrap(), ClientRequest::Recording(command) if command == "record_start:test-call")
        );
        status.handle_recording_status(true, Some("test-call"));
        assert_eq!(
            handle.recording_status().unwrap().service.as_deref(),
            Some("test-call")
        );
        assert!(handle.execute("unknown").await.is_err());
        let query_handle = handle.clone();
        let query = tokio::spawn(async move { query_handle.statistics().await });
        let ClientRequest::Statistics(reply) = commands.recv().await.unwrap() else {
            panic!("Неверный запрос статистики");
        };
        reply
            .send(SessionStatistics {
                sent: 123,
                received: 456,
                since: 77,
                ip: "10.77.0.2".into(),
                fallback: false,
                quality: 95,
                adaptive: 1,
                fec_group: 0,
                role: 2,
                recording: status.read_local_status(),
            })
            .unwrap();
        let statistics = query.await.unwrap().unwrap();
        assert_eq!(
            (statistics.sent, statistics.received, statistics.since),
            (123, 456, 77)
        );
        assert_eq!(statistics.ip, "10.77.0.2");
        assert_eq!(
            statistics.recording.unwrap().service.as_deref(),
            Some("test-call")
        );
        drop(commands);
        assert_eq!(
            handle.statistics().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(handle.execute("record_stop").await.is_err());
        drop(controls);
        assert_eq!(
            handle.execute("role").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(handle.recording_status().is_none());
    }
}
