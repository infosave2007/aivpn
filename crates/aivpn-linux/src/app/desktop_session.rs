//! Основная кнопка и трей управляют профилем той же службы, что и редактор правил.
use super::*;
use aivpn_desktop_agent::client::{
    editor::{Completion, Operation},
    session::{ConnectionRoute, SessionStatus},
};
use aivpn_desktop_agent::connection::ConnectionDocument;
use std::sync::atomic::AtomicBool;

#[derive(Default)]
pub(super) struct Session {
    profile: Option<String>,
    pending: bool,
    cancel_start: bool,
    policy_was_seen: bool,
    legacy_approved: bool,
    closed: Arc<AtomicBool>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Route(Result<ConnectionRoute, String>),
    Started(Result<Completion, String>),
    Stopped(Result<Completion, String>),
    Inspected(Result<Completion, String>),
    Polled(
        Result<
            (
                Completion,
                Option<aivpn_common::local_admin::SessionStatistics>,
            ),
            String,
        >,
    ),
}

impl App {
    pub(super) fn begin_desktop_connect(&mut self) -> Option<Task<Message>> {
        if std::mem::take(&mut self.desktop_session.legacy_approved)
            || self.connection_key.is_some()
            || self.adopted_client.is_some()
            || self.pending_connect
            || self.child_reap_in_flight
            || self.adopted_reap_in_flight
            || self.ks_clear_in_flight
            || self.kill_switch_retained
        {
            return None;
        }
        if self.desktop_session.pending {
            return Some(Task::none());
        }
        if self.has_desktop_session() && matches!(self.status, VpnStatus::Connected { .. }) {
            return Some(Task::none());
        }
        let key = self.storage.selected_key()?.key.clone();
        self.desktop_session.policy_was_seen |= self
            .app_routing
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.policy.is_some());
        let policy_was_seen = self.desktop_session.policy_was_seen;
        self.desktop_session.pending = true;
        self.desktop_session.cancel_start = false;
        self.status = VpnStatus::Connecting;
        Some(Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let connection = ConnectionDocument::from_key(&key)?;
                    ConnectionRoute::resolve(&connection, policy_was_seen)
                        .map_err(std::io::Error::other)
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())
            },
            |result| Message::DesktopSession(Event::Route(result)),
        ))
    }

    pub(super) fn disconnect_desktop_session(&mut self) -> Option<Task<Message>> {
        if self.desktop_session.pending {
            self.desktop_session.cancel_start = true;
            return Some(Task::none());
        }
        let profile = self.desktop_session.profile.clone()?;
        self.desktop_session.cancel_start = true;
        self.desktop_session.pending = true;
        self.invalidate_session_views();
        Some(home_operation(Operation::Stop(profile), Event::Stopped))
    }

    pub(super) fn poll_desktop_session(&mut self) -> Option<Task<Message>> {
        if self.desktop_session.profile.is_none() || self.desktop_session.pending {
            return None;
        }
        self.desktop_session.pending = true;
        let profile = self.desktop_session.profile.clone()?;
        Some(Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let completion = Operation::Inspect.execute()?;
                    let statistics = if completion
                        .snapshot
                        .session_status(&profile)
                        .map_err(|error| error.to_string())?
                        == SessionStatus::Connected
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
                    Ok((completion, statistics))
                })
                .await
                .map_err(|error| error.to_string())?
            },
            |result| Message::DesktopSession(Event::Polled(result)),
        ))
    }

    pub(super) fn has_desktop_session(&self) -> bool {
        self.desktop_session.profile.is_some()
    }

    pub(super) fn uses_application_routing(&self) -> bool {
        self.has_desktop_session()
            || self
                .app_routing
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.policy.is_some())
    }

    pub(super) fn desktop_administration_target(
        &self,
    ) -> Option<Result<aivpn_desktop_agent::client::SessionTarget, String>> {
        self.desktop_session.profile.as_deref().map(|profile| {
            self.app_routing
                .snapshot
                .as_ref()
                .ok_or("Нет подтвержденного состояния службы".to_owned())?
                .administration_target(profile)
                .map_err(|error| error.to_string())
        })
    }

    pub(super) fn update_desktop_session(&mut self, event: Event) -> Task<Message> {
        self.desktop_session.pending = false;
        match event {
            Event::Polled(result) => {
                match result {
                    Ok((completion, statistics)) => {
                        self.apply_desktop_snapshot(Ok(completion));
                        if let Some(statistics) = statistics {
                            self.apply_desktop_statistics(statistics);
                        }
                    }
                    Err(error) => self.status = VpnStatus::Error(error),
                }
                if self.desktop_session.cancel_start {
                    if let Some(task) = self.disconnect_desktop_session() {
                        return task;
                    }
                }
            }
            Event::Route(result) => match result {
                Ok(ConnectionRoute::Legacy) if !self.desktop_session.cancel_start => {
                    self.desktop_session.profile = None;
                    self.desktop_session.legacy_approved = true;
                    return self.update_inner(Message::Connect);
                }
                Ok(ConnectionRoute::Managed { profile, active }) => {
                    self.desktop_session.policy_was_seen = true;
                    if self.desktop_session.cancel_start {
                        self.status = VpnStatus::Disconnected;
                        return Task::none();
                    }
                    let operation = if active {
                        Ok(Operation::Inspect)
                    } else {
                        self.desktop_start_operation(&profile)
                    };
                    self.desktop_session.profile = Some(profile);
                    self.invalidate_session_views();
                    match operation {
                        Ok(operation) => {
                            self.desktop_session.pending = true;
                            if active {
                                return home_operation(operation, Event::Inspected);
                            }
                            return start_operation(operation, self.desktop_session.closed.clone());
                        }
                        Err(error) => self.status = VpnStatus::Error(error),
                    }
                }
                Ok(ConnectionRoute::Legacy) => self.status = VpnStatus::Disconnected,
                Err(error) => self.status = VpnStatus::Error(error),
            },
            Event::Started(result) | Event::Inspected(result) => {
                self.apply_desktop_snapshot(result);
                if self.desktop_session.cancel_start {
                    if let Some(task) = self.disconnect_desktop_session() {
                        return task;
                    }
                }
            }
            Event::Stopped(result) => {
                self.apply_desktop_snapshot(result);
                self.desktop_session.cancel_start = false;
            }
        }
        Task::none()
    }

    fn desktop_start_operation(&self, profile: &str) -> Result<Operation, String> {
        let key = self
            .storage
            .selected_key()
            .ok_or("Выберите ключ подключения")?;
        Ok(Operation::StartConfigured {
            profile: profile.into(),
            connection: ConnectionDocument::from_key(&key.key)
                .map_err(|error| error.to_string())?,
            options: self.desktop_client_options(),
            certificate_file: key
                .mtls_cert
                .as_deref()
                .filter(|path| !path.is_empty())
                .map(std::path::PathBuf::from),
        })
    }

    pub(super) fn desktop_client_options(
        &self,
    ) -> aivpn_desktop_agent::connection::DesktopClientOptions {
        aivpn_desktop_agent::connection::DesktopClientOptions {
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

    fn apply_desktop_snapshot(&mut self, result: Result<Completion, String>) {
        let result = result.and_then(|completion| {
            let profile = self
                .desktop_session
                .profile
                .as_deref()
                .ok_or("Нет выбранного профиля службы")?;
            let status = completion
                .snapshot
                .session_status(profile)
                .map_err(|error| error.to_string())?;
            self.desktop_session.policy_was_seen |= completion.snapshot.policy.is_some();
            self.status = match status {
                SessionStatus::Stopped => VpnStatus::Disconnected,
                SessionStatus::Connecting => VpnStatus::Connecting,
                SessionStatus::Connected if self.desktop_session.cancel_start => {
                    VpnStatus::Connecting
                }
                SessionStatus::Connected => VpnStatus::Connected {
                    vpn_ip: completion
                        .snapshot
                        .profiles
                        .iter()
                        .find(|candidate| candidate.id == profile)
                        .and_then(|profile| {
                            profile
                                .ipv4
                                .map(|ip| ip.to_string())
                                .or_else(|| profile.ipv6.map(|ip| ip.to_string()))
                        })
                        .unwrap_or_default(),
                },
            };
            self.app_routing.observe(completion.snapshot);
            Ok(())
        });
        if let Err(error) = result {
            self.status = VpnStatus::Error(error);
        }
    }

    fn apply_desktop_statistics(
        &mut self,
        statistics: aivpn_common::local_admin::SessionStatistics,
    ) {
        if self
            .stats
            .connected_since
            .is_some_and(|since| since != statistics.since)
        {
            self.invalidate_session_views();
        }
        self.stats = TrafficStats {
            bytes_sent: statistics.sent,
            bytes_received: statistics.received,
            quality_score: statistics.quality,
            server_adaptive_level: statistics.adaptive,
            fec_group: (statistics.fec_group != 0).then_some(statistics.fec_group),
            connected_since: Some(statistics.since),
        };
        self.admin_role = Some(statistics.role);
        if let Some(recording) = statistics.recording {
            self.recording_allowed = recording.can_record;
            let _ = self.update_inner(Message::RecordingPoll(Some(RecordingSnapshot {
                state: recording.state,
                service: recording.service.unwrap_or_default(),
                mask_id: recording.mask_id,
                message: recording.message,
            })));
        }
    }

    pub(super) fn closing_desktop_profile(&mut self) -> Option<String> {
        self.desktop_session
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.desktop_session.profile.clone()
    }
}

fn start_operation(operation: Operation, closed: Arc<AtomicBool>) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                let Operation::StartConfigured { ref profile, .. } = operation else {
                    unreachable!()
                };
                let profile = profile.clone();
                if closed.load(std::sync::atomic::Ordering::Acquire) {
                    return Err("Запуск отменен при закрытии интерфейса".into());
                }
                let result = operation.execute();
                if result.is_ok() && closed.load(std::sync::atomic::Ordering::Acquire) {
                    Operation::Stop(profile).execute()?;
                    return Err("Профиль остановлен при закрытии интерфейса".into());
                }
                result
            })
            .await
            .map_err(|error| error.to_string())?
        },
        |result| Message::DesktopSession(Event::Started(result)),
    )
}

fn home_operation(
    operation: Operation,
    event: fn(Result<Completion, String>) -> Event,
) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || operation.execute())
                .await
                .map_err(|error| error.to_string())?
        },
        move |result| Message::DesktopSession(event(result)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_desktop_agent::{
        client::editor::Snapshot,
        policy::{Owner, ProfileStatus},
        protocol::BackendState,
    };

    fn completion(ready: bool, active: bool) -> Completion {
        let owner = Owner::LinuxUser { uid: 1000 };
        Completion {
            snapshot: Snapshot {
                owner: owner.clone(),
                backend: BackendState::Guarded,
                global_dns_profile: Some("selected".into()),
                policy: None,
                profiles: vec![ProfileStatus {
                    id: "selected".into(),
                    owner,
                    control_allowed: true,
                    session_active: active,
                    ready_ipv4: ready,
                    ready_ipv6: false,
                    assignment_generation: u64::from(ready),
                    session_id: active.then_some([1; 16]),
                    registration_key: None,
                    ipv4: ready.then(|| "10.77.0.2".parse().unwrap()),
                    ipv6: None,
                }],
            },
            selected_profile: None,
            replace_draft: false,
            message: String::new(),
        }
    }

    #[test]
    fn main_status_follows_the_service_without_starting_a_legacy_child() {
        let (mut app, _) = App::from_state(AppSettings::default(), KeyStorage::default(), None);
        app.desktop_session.profile = Some("selected".into());
        let _ = app.update(Message::DesktopSession(Event::Started(Ok(completion(
            false, true,
        )))));
        assert_eq!(app.status, VpnStatus::Connecting);
        assert!(app.connection_key.is_none());
        let _ = app.update(Message::DesktopSession(Event::Inspected(Ok(completion(
            true, true,
        )))));
        assert!(matches!(app.status, VpnStatus::Connected { .. }));
        let _ = app.update(Message::StatusReceived(VpnStatus::Disconnected));
        assert!(matches!(app.status, VpnStatus::Connected { .. }));
        let _ = app.update(Message::DesktopSession(Event::Stopped(Ok(completion(
            false, false,
        )))));
        assert_eq!(app.status, VpnStatus::Disconnected);
        assert!(app.connection_key.is_none());
        let _ = app.update(Message::DesktopSession(Event::Inspected(Err(
            "Служба недоступна".into(),
        ))));
        assert_eq!(app.status, VpnStatus::Error("Служба недоступна".into()));
        assert!(app.connection_key.is_none());
    }

    #[test]
    fn disconnect_during_start_keeps_the_late_reply_from_showing_connected() {
        let (mut app, _) = App::from_state(AppSettings::default(), KeyStorage::default(), None);
        app.desktop_session.profile = Some("selected".into());
        app.desktop_session.pending = true;
        app.status = VpnStatus::Connecting;
        let _ = app.update(Message::Disconnect);
        assert!(app.desktop_session.cancel_start);
        let _ = app.update(Message::DesktopSession(Event::Started(Ok(completion(
            true, true,
        )))));
        assert!(app.desktop_session.pending);
        assert_eq!(app.status, VpnStatus::Connecting);
        assert!(app.connection_key.is_none());
        let _ = app.update(Message::DesktopSession(Event::Stopped(Ok(completion(
            false, false,
        )))));
        assert_eq!(app.status, VpnStatus::Disconnected);
        assert!(!app.desktop_session.cancel_start);
    }

    #[test]
    fn managed_statistics_update_counters_and_clear_previous_session_permissions() {
        let (mut app, _) = App::from_state(AppSettings::default(), KeyStorage::default(), None);
        app.desktop_session.profile = Some("selected".into());
        let statistics = |since, role, can_record| aivpn_common::local_admin::SessionStatistics {
            sent: 1234,
            received: 5678,
            since,
            ip: "10.77.0.2".into(),
            fallback: false,
            quality: 95,
            adaptive: 2,
            fec_group: 4,
            role,
            recording: Some(aivpn_common::local_admin::RecordingStatus {
                can_record: Some(can_record),
                ..Default::default()
            }),
        };
        let _ = app.update(Message::DesktopSession(Event::Polled(Ok((
            completion(true, true),
            Some(statistics(10, 2, true)),
        )))));
        assert_eq!(app.stats.bytes_sent, 1234);
        assert_eq!(app.stats.bytes_received, 5678);
        assert_eq!(app.route_summary(), "Application rules");
        assert_eq!(app.admin_role, Some(2));
        assert_eq!(app.recording_allowed, Some(true));
        app.admin_clients_loading = true;
        app.recording_state = RecordingState::Active("old".into());
        let _ = app.update(Message::DesktopSession(Event::Polled(Ok((
            completion(true, true),
            Some(statistics(20, 0, false)),
        )))));
        assert_eq!(app.admin_role, Some(0));
        assert_eq!(app.recording_allowed, Some(false));
        assert_eq!(app.recording_state, RecordingState::Idle);
        assert!(!app.admin_clients_loading);
        assert_eq!(app.stats.connected_since, Some(20));
    }

    #[test]
    fn canceling_preflight_does_not_take_control_of_an_existing_cli_session() {
        let (mut app, _) = App::from_state(AppSettings::default(), KeyStorage::default(), None);
        app.desktop_session.pending = true;
        let _ = app.update(Message::Disconnect);
        let _ = app.update(Message::DesktopSession(Event::Route(Ok(
            ConnectionRoute::Managed {
                profile: "selected".into(),
                active: true,
            },
        ))));
        assert!(app.desktop_session.profile.is_none());
        assert!(!app.desktop_session.pending);
        assert_eq!(app.status, VpnStatus::Disconnected);
    }
}
