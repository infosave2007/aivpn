//! Подключение из главного окна использует профиль действующих правил приложений.
use crate::{vpn_manager::ConnectionState, AivpnApp};
use aivpn_desktop_agent::{
    client::{
        editor::{Completion, Operation},
        session::ConnectionRoute,
    },
    connection::{ConnectionDocument, DesktopClientOptions},
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct Session {
    pending: Option<Receiver<Result<Event, String>>>,
    cancel_start: bool,
    policy_was_seen: bool,
    legacy_approved: bool,
    last_request: Option<Instant>,
    closed: Arc<AtomicBool>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
    }
}

enum Event {
    Route(ConnectionRoute),
    Started(Completion),
    Stopped(Completion),
    Inspected(Completion),
    Polled(
        Completion,
        Option<aivpn_common::local_admin::SessionStatistics>,
    ),
}

impl Session {
    fn submit(&mut self, operation: impl FnOnce() -> Result<Event, String> + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.last_request = Some(Instant::now());
        std::thread::spawn(move || {
            let _ = tx.send(operation());
        });
    }
}

impl AivpnApp {
    pub(crate) fn uses_application_routing(&self) -> bool {
        self.vpn.managed_profile().is_some() || self.app_routing.policy_was_seen()
    }

    pub(crate) fn begin_desktop_connect(&mut self) -> bool {
        if std::mem::take(&mut self.desktop_session.legacy_approved) {
            return false;
        }
        if self.desktop_session.pending.is_some() {
            self.desktop_session.cancel_start = true;
            return true;
        }
        if let Some(profile) = self.vpn.managed_profile() {
            if self.vpn.state() != ConnectionState::Disconnected {
                let operation = Operation::Stop(profile.into());
                self.desktop_session.cancel_start = true;
                self.desktop_session
                    .submit(move || operation.execute().map(Event::Stopped));
                return true;
            }
        } else if self.vpn.is_connected() || self.vpn.is_busy() {
            return false;
        }
        let Some(key) = self.keys.selected_key() else {
            return false;
        };
        let key = key.key.clone();
        self.desktop_session.policy_was_seen |= self.app_routing.policy_was_seen();
        let policy_was_seen = self.desktop_session.policy_was_seen;
        self.desktop_session.cancel_start = false;
        self.vpn.prepare_desktop_request();
        self.desktop_session.submit(move || {
            let connection =
                ConnectionDocument::from_key(&key).map_err(|error| error.to_string())?;
            ConnectionRoute::resolve(&connection, policy_was_seen)
                .map(Event::Route)
                .map_err(|error| error.to_string())
        });
        true
    }

    pub(crate) fn poll_desktop_session(&mut self) {
        let result = match self
            .desktop_session
            .pending
            .as_ref()
            .map(Receiver::try_recv)
        {
            Some(Ok(result)) => Some(result),
            Some(Err(TryRecvError::Disconnected)) => Some(Err("Запрос службы прерван".into())),
            _ => None,
        };
        if let Some(result) = result {
            self.desktop_session.pending = None;
            if let Err(error) = self.complete_desktop_session(result) {
                self.vpn.desktop_request_failed(error.clone());
                self.show_error(error);
            }
        }
        if self.desktop_session.pending.is_none()
            && self.vpn.managed_profile().is_some()
            && self
                .desktop_session
                .last_request
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(2))
        {
            let profile = self.vpn.managed_profile().unwrap().to_owned();
            self.desktop_session.submit(move || {
                let completion = Operation::Inspect.execute()?;
                let statistics = if completion
                    .snapshot
                    .session_status(&profile)
                    .map_err(|error| error.to_string())?
                    == aivpn_desktop_agent::client::session::SessionStatus::Connected
                {
                    Some(
                        completion
                            .snapshot
                            .administration_target(&profile)
                            .map_err(|error| error.to_string())?
                            .statistics()
                            .map_err(|error| error.to_string())?,
                    )
                } else {
                    None
                };
                Ok(Event::Polled(completion, statistics))
            });
        }
    }

    fn complete_desktop_session(&mut self, result: Result<Event, String>) -> Result<(), String> {
        match result? {
            Event::Polled(completion, statistics) => {
                self.complete_desktop_session(Ok(Event::Inspected(completion)))?;
                if let Some(statistics) = statistics.filter(|_| self.vpn.is_connected()) {
                    let role = statistics.role;
                    if self.vpn.apply_managed_statistics(statistics) {
                        self.reset_admin_state();
                        self.bench_running = false;
                        self.bench_result = None;
                        self.bench_rx = None;
                    }
                    self.admin_role = Some(role);
                }
            }
            Event::Route(ConnectionRoute::Legacy) => {
                self.vpn.release_managed_profile();
                if !self.desktop_session.cancel_start {
                    self.desktop_session.legacy_approved = true;
                    self.do_connect();
                }
            }
            Event::Route(ConnectionRoute::Managed { profile, active }) => {
                self.desktop_session.policy_was_seen = true;
                if self.desktop_session.cancel_start {
                    self.vpn.release_managed_profile();
                    return Ok(());
                }
                let operation = if active {
                    Operation::Inspect
                } else {
                    self.desktop_start_operation(&profile)?
                };
                self.vpn.adopt_managed_profile(
                    profile,
                    &self
                        .keys
                        .selected_key()
                        .ok_or("Выберите ключ подключения")?
                        .key,
                );
                if active {
                    self.desktop_session
                        .submit(move || operation.execute().map(Event::Inspected));
                    return Ok(());
                }
                let closed = self.desktop_session.closed.clone();
                self.desktop_session.submit(move || {
                    let Operation::StartConfigured { ref profile, .. } = operation else {
                        unreachable!()
                    };
                    let profile = profile.clone();
                    if closed.load(Ordering::Acquire) {
                        return Err("Запуск отменен при закрытии интерфейса".into());
                    }
                    let result = operation.execute();
                    if result.is_ok() && closed.load(Ordering::Acquire) {
                        Operation::Stop(profile).execute()?;
                        return Err("Профиль остановлен при закрытии интерфейса".into());
                    }
                    result.map(Event::Started)
                });
            }
            Event::Started(completion) | Event::Inspected(completion) => {
                self.vpn.apply_managed_snapshot(&completion.snapshot)?;
                self.app_routing.complete_home(completion);
                if self.desktop_session.cancel_start {
                    if let Some(profile) = self.vpn.managed_profile() {
                        let operation = Operation::Stop(profile.into());
                        self.desktop_session
                            .submit(move || operation.execute().map(Event::Stopped));
                    }
                }
            }
            Event::Stopped(completion) => {
                self.vpn.apply_managed_snapshot(&completion.snapshot)?;
                self.app_routing.complete_home(completion);
                self.desktop_session.cancel_start = false;
            }
        }
        Ok(())
    }

    fn desktop_start_operation(&self, profile: &str) -> Result<Operation, String> {
        let key = self
            .keys
            .selected_key()
            .ok_or("Выберите ключ подключения")?;
        Ok(Operation::StartConfigured {
            profile: profile.into(),
            connection: ConnectionDocument::from_key(&key.key)
                .map_err(|error| error.to_string())?,
            options: self.desktop_client_options(),
            certificate_file: key
                .mtls_cert_path
                .as_deref()
                .filter(|path| !path.is_empty())
                .map(std::path::PathBuf::from),
        })
    }

    pub(crate) fn desktop_client_options(&self) -> DesktopClientOptions {
        DesktopClientOptions {
            preferred_mask: Some(self.settings.preferred_mask.clone()),
            adaptive_level: self.settings.adaptive_level,
            polymorphic_mask: self.settings.polymorphic_mask,
            share_mask_feedback: self.settings.share_mask_feedback,
            receive_mask_hints: self.settings.receive_mask_hints,
            country_code: Some(self.settings.country_code.clone()),
            server_signing_key: (!self.settings.server_signing_key.trim().is_empty())
                .then(|| self.settings.server_signing_key.trim().to_owned()),
            ..Default::default()
        }
    }

    pub(crate) fn closing_desktop_session(&mut self) {
        self.desktop_session.closed.store(true, Ordering::Release);
    }
}
