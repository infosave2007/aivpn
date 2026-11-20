use super::{profile_error, Control, ControlStore, RoutingBackend};
use crate::protocol::ErrorCode;
use aivpn_desktop_policy::{Authority, PreparedAssignment, ProfileAssignment, ProfileLease};

#[cfg(all(
    not(feature = "local-profile"),
    any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    )
))]
impl<S: ControlStore, B: RoutingBackend<S>> Control<S, B> {
    pub(crate) fn resolve_worker_configuration(
        &mut self,
        source: &crate::connection::WorkerConfiguration,
    ) -> std::io::Result<crate::connection::WorkerConfiguration> {
        source.numeric_peer()?;
        Ok(source.clone())
    }
}

#[cfg(all(
    feature = "local-profile",
    any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    )
))]
impl<S: ControlStore, B: RoutingBackend<S>> Control<S, B> {
    /// Вызывается координатором только после проверки владельца исходного профиля.
    pub(crate) fn resolve_worker_configuration(
        &mut self,
        source: &mut crate::connection::WorkerConfiguration,
    ) -> std::io::Result<crate::connection::WorkerConfiguration> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut excluded = Vec::new();
        let mut last_error = None;
        loop {
            let selected = match source.next_attempt(&excluded) {
                Ok(selected) => selected,
                Err(error) => return Err(last_error.unwrap_or(error)),
            };
            if selected.peer.is_some() {
                return Ok(selected);
            }
            let (host, port) = selected
                .hostname
                .as_ref()
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            excluded.push(
                selected.connection["s"]
                    .as_str()
                    .ok_or(std::io::ErrorKind::InvalidInput)?
                    .to_owned(),
            );
            let timeout = deadline.saturating_duration_since(std::time::Instant::now());
            if timeout.is_zero() {
                source.finish_attempt();
                last_error = Some(std::io::ErrorKind::TimedOut.into());
                continue;
            }
            let servers = self.backend.transport_dns_servers(&self.store)?;
            self.transport_dns_epoch = self
                .transport_dns_epoch
                .checked_add(1)
                .ok_or(std::io::ErrorKind::Other)?;
            let epoch = self.transport_dns_epoch;
            self.backend.begin_transport_dns(epoch)?;
            let result = (|| {
                let registrar = self.backend.transport_dns_registrar(epoch)?;
                crate::dns::bootstrap::resolve(&servers, host, *port, timeout, registrar)
            })();
            if let Err(error) = self.backend.end_transport_dns() {
                self.fail_closed();
                return Err(error);
            }
            match result.and_then(|peers| {
                let peer = peers
                    .into_iter()
                    .find(|peer| !peer.ip().is_unspecified() && !peer.ip().is_multicast())
                    .ok_or(std::io::ErrorKind::NotFound)?;
                selected.resolved(peer)
            }) {
                Ok(resolved) => return Ok(resolved),
                Err(error) => {
                    source.finish_attempt();
                    last_error = Some(error);
                }
            }
        }
    }
}

impl<S: ControlStore, B: RoutingBackend<S>> Control<S, B> {
    pub(crate) fn authorize_session_administration(
        &self,
        authority: &Authority,
        profile: &str,
        lease: &ProfileLease,
        assignment_generation: std::num::NonZeroU64,
        session_id: [u8; 16],
    ) -> Result<(), ErrorCode> {
        self.state.authorize_profile_control(authority, profile)?;
        self.require_active_backend()?;
        let current = self
            .state
            .profiles
            .session_profile(lease)
            .map_err(profile_error)?;
        if lease.session_id() != session_id
            || current.id != profile
            || current.assignment_generation != assignment_generation.get()
            || !(current.ready_ipv4 || current.ready_ipv6)
        {
            return Err(ErrorCode::Conflict);
        }
        Ok(())
    }

    /// Вызывается доверенным обработчиком работника после проверки его роли и владельца профиля.
    pub fn begin_profile_session(
        &mut self,
        profile: &str,
        authority: &Authority,
    ) -> Result<ProfileLease, ErrorCode> {
        self.require_active_backend()?;
        self.state
            .profiles
            .validate_authority(authority)
            .map_err(profile_error)?;
        let lease = self
            .state
            .profiles
            .begin_session(profile, authority)
            .map_err(profile_error)?;
        self.install_runtime()?;
        Ok(lease)
    }

    /// Backend обязан проверить собственный интерфейс до публикации готовности.
    pub fn assign_profile(
        &mut self,
        lease: &ProfileLease,
        assignment: ProfileAssignment,
    ) -> Result<u64, ErrorCode> {
        self.require_active_backend()?;
        let current = self
            .state
            .profiles
            .session_profile(lease)
            .map_err(profile_error)?;
        if current.ready_ipv4 && current.assignment == Some(assignment) {
            self.install_runtime()?;
            return Ok(current.assignment_generation);
        }
        let prepared = self.state.profiles.prepare_assignment(lease, assignment);
        self.install_runtime()?;
        self.publish_assignment(prepared.map_err(profile_error)?)
    }

    fn publish_assignment(&mut self, prepared: PreparedAssignment) -> Result<u64, ErrorCode> {
        let generation = prepared.generation();
        let candidate = self.state.with_assignment(&prepared)?;
        let bytes = self.stage(&candidate)?;
        self.install_staged(&candidate, &bytes)?;
        self.state.serial = candidate.serial;
        self.state.profiles.commit_ready(prepared).map_err(|_| {
            self.fail_closed();
            ErrorCode::RecoveryRequired
        })?;
        self.install_runtime()?;
        Ok(generation)
    }

    pub fn disconnect_profile_session(&mut self, lease: &ProfileLease) -> Result<(), ErrorCode> {
        self.require_active_backend()?;
        self.state
            .profiles
            .disconnect(lease)
            .map_err(profile_error)?;
        self.install_runtime()
    }

    fn install_runtime(&mut self) -> Result<(), ErrorCode> {
        if self
            .backend
            .install(&mut self.store, &self.state, &self.state.profiles)
            .is_err()
        {
            self.fail_closed();
            return Err(ErrorCode::BackendUnavailable);
        }
        self.backend_state = self.backend.installed_state().into();
        Ok(())
    }
}
