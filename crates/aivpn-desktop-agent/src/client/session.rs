//! Главная кнопка интерфейса выбирает тот же профиль, который указан в правилах.
use super::{call, editor::Snapshot, ClientError};
use crate::{
    connection::ConnectionDocument,
    policy::{Action, ProfileStatus},
    protocol::{BackendState, Command, Reply},
};
use std::{io, num::NonZeroU64};

/// Полномочие интерфейса фиксирует профиль и назначение до запуска фоновой задачи.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTarget {
    profile: String,
    assignment_generation: NonZeroU64,
    session_id: [u8; 16],
}
impl SessionTarget {
    fn from_profile(profile: &ProfileStatus) -> io::Result<Self> {
        if !profile.control_allowed
            || !profile.session_active
            || !(profile.ready_ipv4 || profile.ready_ipv6)
        {
            return Err(io::ErrorKind::NotConnected.into());
        }
        Ok(Self {
            profile: profile.id.clone(),
            assignment_generation: NonZeroU64::new(profile.assignment_generation)
                .ok_or(io::ErrorKind::InvalidData)?,
            session_id: profile.session_id.ok_or(io::ErrorKind::InvalidData)?,
        })
    }
    pub fn current(profile: &str) -> Result<Self, ClientError> {
        let Reply::Profiles { profiles } = call(Command::ListProfiles {})? else {
            return Err(io::Error::from(io::ErrorKind::InvalidData).into());
        };
        let selected = profiles
            .iter()
            .find(|selected| selected.id == profile)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok(Self::from_profile(selected)?)
    }
    pub fn command(&self, query: crate::administration::SessionQuery) -> Command {
        Command::SessionAdmin {
            profile: self.profile.clone(),
            assignment_generation: self.assignment_generation,
            session_id: self.session_id,
            query,
        }
    }
    pub fn query(
        &self,
        query: crate::administration::SessionQuery,
    ) -> Result<crate::administration::ReplyText, ClientError> {
        match call(self.command(query))? {
            Reply::SessionReply { output } => Ok(output),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Неожиданный ответ управления сеансом",
            )
            .into()),
        }
    }
    pub fn execute(&self, command: String) -> Result<String, ClientError> {
        Ok(self
            .query(crate::administration::SessionQuery::Execute {
                command: crate::administration::CommandText::new(command)?,
            })?
            .into_string())
    }
    #[cfg(feature = "local-profile")]
    pub fn statistics(&self) -> Result<aivpn_common::local_admin::SessionStatistics, ClientError> {
        let response = self.query(crate::administration::SessionQuery::Statistics {})?;
        serde_json::from_str(response.as_str()).map_err(|error| io::Error::from(error).into())
    }
    pub fn management(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ClientError> {
        use base64::Engine;
        let method = match method {
            "GET" => 0,
            "POST" => 1,
            "PATCH" => 2,
            "DELETE" => 3,
            "PUT" => 4,
            _ => return Err(io::Error::from(io::ErrorKind::InvalidInput).into()),
        };
        if path.is_empty() || path.contains(':') {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let response = self.execute(format!(
            "mgmt:{method}:{path}:{}",
            base64::engine::general_purpose::STANDARD.encode(body)
        ))?;
        let (status, body) = response
            .split_once(':')
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let status = status
            .parse()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let body = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok((status, body))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionRoute {
    Legacy,
    Managed { profile: String, active: bool },
}

impl ConnectionRoute {
    /// При известной политике отказ службы не переключает интерфейс на обычный клиент.
    pub fn resolve(
        connection: &ConnectionDocument,
        policy_was_seen: bool,
    ) -> Result<Self, ClientError> {
        let mut service_responded = false;
        let snapshot = Snapshot::load_with(|command| {
            let result = call(command);
            service_responded |= result.is_ok();
            result
        });
        let route =
            Self::from_snapshot(connection, policy_was_seen || service_responded, snapshot)?;
        if !cfg!(feature = "routing-control") && matches!(route, Self::Managed { .. }) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Действующие правила приложений требуют сборки с app-routing",
            )
            .into());
        }
        Ok(route)
    }

    fn from_snapshot(
        connection: &ConnectionDocument,
        policy_was_seen: bool,
        snapshot: Result<Snapshot, ClientError>,
    ) -> Result<Self, ClientError> {
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(ClientError::Transport(error))
                if !policy_was_seen && error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(Self::Legacy);
            }
            Err(error) => return Err(error),
        };
        if !matches!(
            snapshot.backend,
            BackendState::Active | BackendState::Guarded
        ) {
            return Err(io::Error::other("Служба еще не готова к запуску профиля").into());
        }
        let Some(policy) = snapshot.policy else {
            return Ok(Self::Legacy);
        };
        let registration_key = connection.registration_key()?;
        let profile = snapshot
            .profiles
            .iter()
            .find(|profile| {
                profile.owner == snapshot.owner
                    && profile.control_allowed
                    && profile.registration_key.as_deref() == Some(registration_key.as_str())
            })
            .ok_or_else(|| {
                io::Error::other("Выбранный ключ не зарегистрирован в правилах приложений")
            })?;
        let uses_profile = |action: &Action| matches!(action, Action::Vpn { profile: selected } if selected == &profile.id);
        let used_by_split = policy.split_enabled
            && (uses_profile(&policy.default_action)
                || policy.rules.iter().any(|rule| uses_profile(&rule.action)));
        if policy.dns.profile() != profile.id && !used_by_split {
            return Err(io::Error::other(
                "Выбранный ключ не используется действующими правилами приложений",
            )
            .into());
        }
        Ok(Self::Managed {
            profile: profile.id.clone(),
            active: profile.session_active,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Stopped,
    Connecting,
    Connected,
}

impl Snapshot {
    pub fn administration_target(&self, profile: &str) -> io::Result<SessionTarget> {
        let selected = self
            .profiles
            .iter()
            .find(|selected| selected.id == profile)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        SessionTarget::from_profile(selected)
    }
    /// Ответ на StartProfile сам по себе не означает, что сервер уже ответил.
    pub fn session_status(&self, profile: &str) -> io::Result<SessionStatus> {
        let profile = self
            .profiles
            .iter()
            .find(|candidate| candidate.id == profile && candidate.control_allowed)
            .ok_or(io::ErrorKind::NotFound)?;
        Ok(if !profile.session_active {
            SessionStatus::Stopped
        } else if matches!(self.backend, BackendState::Active | BackendState::Guarded)
            && (profile.ready_ipv4 || profile.ready_ipv6)
        {
            SessionStatus::Connected
        } else {
            SessionStatus::Connecting
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::editor::Draft,
        policy::{Owner, ProfileStatus},
        protocol::ErrorCode,
    };

    fn connection() -> ConnectionDocument {
        ConnectionDocument::from_json(br#"{"s":"192.0.2.1:443"}"#).unwrap()
    }

    fn snapshot() -> Snapshot {
        let owner = Owner::LinuxUser { uid: 1000 };
        let mut snapshot = Snapshot {
            owner: owner.clone(),
            backend: BackendState::Guarded,
            global_dns_profile: Some("selected".into()),
            profiles: vec![ProfileStatus {
                id: "selected".into(),
                owner,
                control_allowed: true,
                session_active: false,
                ready_ipv4: false,
                ready_ipv6: false,
                assignment_generation: 0,
                session_id: None,
                registration_key: Some(connection().registration_key().unwrap()),
                ipv4: None,
                ipv6: None,
            }],
            policy: None,
        };
        snapshot.policy = Some(Draft::from_snapshot(&snapshot).document);
        snapshot
    }

    #[test]
    fn main_button_uses_the_selected_key_without_registering_or_replacing_grants() {
        assert_eq!(
            ConnectionRoute::from_snapshot(&connection(), false, Ok(snapshot())).unwrap(),
            ConnectionRoute::Managed {
                profile: "selected".into(),
                active: false,
            }
        );
    }

    #[test]
    fn an_existing_session_is_adopted_without_a_second_start_request() {
        let mut state = snapshot();
        state.profiles[0].session_active = true;
        assert_eq!(
            ConnectionRoute::from_snapshot(&connection(), false, Ok(state)).unwrap(),
            ConnectionRoute::Managed {
                profile: "selected".into(),
                active: true
            }
        );
    }

    #[test]
    fn disabled_split_cannot_start_a_profile_only_referenced_by_saved_rules() {
        let mut state = snapshot();
        let policy = state.policy.as_mut().unwrap();
        policy.default_action = Action::Vpn {
            profile: "selected".into(),
        };
        policy.dns = crate::policy::DnsPolicy::SharedVpn {
            profile: "other".into(),
            acknowledge_outage: true,
        };
        assert!(ConnectionRoute::from_snapshot(&connection(), false, Ok(state.clone())).is_ok());
        state.policy.as_mut().unwrap().split_enabled = false;
        assert!(ConnectionRoute::from_snapshot(&connection(), false, Ok(state)).is_err());
    }

    #[test]
    fn another_key_or_an_unused_profile_never_starts_a_legacy_connection() {
        let mut state = snapshot();
        state.profiles[0].registration_key = Some("other".into());
        assert!(ConnectionRoute::from_snapshot(&connection(), false, Ok(state)).is_err());
        let mut state = snapshot();
        state.policy.as_mut().unwrap().dns = crate::policy::DnsPolicy::SharedVpn {
            profile: "other".into(),
            acknowledge_outage: true,
        };
        assert!(ConnectionRoute::from_snapshot(&connection(), false, Ok(state)).is_err());
    }

    #[test]
    fn absent_service_only_uses_legacy_before_any_policy_was_seen() {
        for (known, kind) in [
            (false, io::ErrorKind::NotFound),
            (true, io::ErrorKind::NotFound),
            (false, io::ErrorKind::TimedOut),
            (false, io::ErrorKind::PermissionDenied),
        ] {
            let result = ConnectionRoute::from_snapshot(
                &connection(),
                known,
                Err(io::Error::from(kind).into()),
            );
            if !known && kind == io::ErrorKind::NotFound {
                assert_eq!(result.unwrap(), ConnectionRoute::Legacy);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn service_rejection_and_recovery_do_not_fall_back_to_a_legacy_connection() {
        assert!(ConnectionRoute::from_snapshot(
            &connection(),
            false,
            Err(ClientError::Rejected(ErrorCode::RecoveryRequired))
        )
        .is_err());
        let mut state = snapshot();
        state.backend = BackendState::Recovering;
        state.policy = None;
        assert!(ConnectionRoute::from_snapshot(&connection(), false, Ok(state)).is_err());
        let mut state = snapshot();
        state.profiles[0].control_allowed = false;
        assert!(ConnectionRoute::from_snapshot(&connection(), false, Ok(state)).is_err());
    }

    #[test]
    fn no_policy_keeps_existing_connection_behavior() {
        let mut state = snapshot();
        state.policy = None;
        assert_eq!(
            ConnectionRoute::from_snapshot(&connection(), false, Ok(state)).unwrap(),
            ConnectionRoute::Legacy
        );
    }

    #[test]
    fn status_requires_a_live_owned_session_and_current_readiness() {
        let mut state = snapshot();
        state.profiles[0].session_active = true;
        assert_eq!(
            state.session_status("selected").unwrap(),
            SessionStatus::Connecting
        );
        state.profiles[0].ready_ipv6 = true;
        assert_eq!(
            state.session_status("selected").unwrap(),
            SessionStatus::Connected
        );
        state.backend = BackendState::Recovering;
        assert_eq!(
            state.session_status("selected").unwrap(),
            SessionStatus::Connecting
        );
        state.profiles[0].session_active = false;
        assert_eq!(
            state.session_status("selected").unwrap(),
            SessionStatus::Stopped
        );
        state.profiles[0].control_allowed = false;
        assert!(state.session_status("selected").is_err());
    }
}
