mod runtime;
mod snapshot;
#[cfg(all(target_os = "linux", feature = "linux-kernel"))]
pub(crate) use snapshot::DurableLinuxTarget;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/support/control_state.rs"]
mod tests;

use crate::protocol::{BackendState, Command, ErrorCode, Reply, Request, Response};
use crate::state::StateFile;
use aivpn_desktop_policy::{
    Authority, Owner, Platform, PolicyDocument, PolicyRegistry, ProfileCatalog, ProfileError,
    RegistryError,
};
use std::io;

pub trait ControlStore {
    fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>>;
    fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()>;
    fn clear_pending(&mut self) -> io::Result<()>;
}

/// Только успешная установка сообщает проверенный уровень защиты.
#[derive(Clone, Copy)]
pub enum InstalledState {
    Guarded,
    Active,
}
impl From<InstalledState> for BackendState {
    fn from(value: InstalledState) -> Self {
        match value {
            InstalledState::Guarded => Self::Guarded,
            InstalledState::Active => Self::Active,
        }
    }
}

pub trait RoutingBackend<S: ControlStore> {
    fn supported(&self) -> bool;
    fn installed_state(&self) -> InstalledState;

    /// Только для фиксированных имен транспорта службы, без пользовательского DNS.
    fn transport_dns_servers(&mut self, _store: &S) -> io::Result<Vec<std::net::SocketAddr>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    #[cfg(any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    ))]
    fn begin_transport_dns(&mut self, _epoch: u64) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    #[cfg(any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    ))]
    fn transport_dns_registrar(
        &mut self,
        _epoch: u64,
    ) -> io::Result<crate::dns::BootstrapDnsRegistrar<'_>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    #[cfg(any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    ))]
    fn end_transport_dns(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Повторное применение должно сохранять решения старых потоков. После запуска
    /// профили не готовы, пока служба заново не проверит их интерфейсы и защиту.
    /// В desired находятся будущие права и политики, в live_profiles - текущие сеансы.
    fn install(
        &mut self,
        store: &mut S,
        desired: &ControlState,
        live_profiles: &ProfileCatalog,
    ) -> io::Result<()>;

    /// Закрывает готовность всех защищенных путей, сохраняя независимые SYSTEM-потоки.
    fn block(&mut self) -> io::Result<()>;
}

pub struct ControlState {
    platform: Platform,
    serial: u64,
    profiles: ProfileCatalog,
    policies: PolicyRegistry,
    decommissioned: bool,
}

impl ControlState {
    #[cfg(any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    ))]
    pub(crate) fn verify_decommissioned(
        platform: Platform,
        namespace: [u8; 16],
        store: &impl ControlStore,
    ) -> io::Result<(u64, Vec<u8>)> {
        if store.load(StateFile::Pending)?.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let bytes = store
            .load(StateFile::Committed)?
            .ok_or(io::ErrorKind::NotFound)?;
        let state = Self::decode(platform, &bytes)?;
        if !state.decommissioned || state.profiles.namespace() != namespace {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        crate::dns::journal::require_restored(store)?;
        Ok((state.serial, bytes))
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn profiles(&self) -> &ProfileCatalog {
        &self.profiles
    }
    pub fn policies(&self) -> &PolicyRegistry {
        &self.policies
    }

    pub(crate) fn authorize_decommission(&self, authority: &Authority) -> Result<(), ErrorCode> {
        self.profiles
            .validate_authority(authority)
            .map_err(profile_error)?;
        if !authority.machine_admin {
            return Err(ErrorCode::AccessDenied);
        }
        Ok(())
    }

    pub(crate) fn authorize_profile_control(
        &self,
        authority: &Authority,
        profile: &str,
    ) -> Result<(), ErrorCode> {
        let visible = self.profiles.list(authority).map_err(profile_error)?;
        match visible.iter().find(|entry| entry.id == profile) {
            Some(entry) if entry.control_allowed => Ok(()),
            Some(_) => Err(ErrorCode::AccessDenied),
            None => Err(ErrorCode::NotFound),
        }
    }

    fn new(platform: Platform, namespace: [u8; 16]) -> Self {
        Self {
            platform,
            serial: 0,
            profiles: ProfileCatalog::new(platform, namespace),
            policies: PolicyRegistry::new(platform),
            decommissioned: false,
        }
    }

    fn apply(&mut self, authority: &Authority, command: &Command) -> Result<Reply, ErrorCode> {
        if self.decommissioned && !matches!(command, Command::Decommission {}) {
            return Err(ErrorCode::Conflict);
        }
        match command {
            Command::Decommission {} => {
                self.authorize_decommission(authority)?;
                self.profiles
                    .clear_for_decommission(authority)
                    .map_err(profile_error)?;
                self.policies
                    .clear_for_decommission(authority)
                    .map_err(registry_error)?;
                self.decommissioned = true;
                Ok(Reply::Done {})
            }
            Command::RegisterProfile {
                owner,
                registration_key,
                consumers,
            } => self.register_profile(authority, owner, registration_key, consumers),
            Command::DeleteProfile { profile } => self.delete_profile(authority, profile),
            Command::SetGlobalDns {
                profile,
                acknowledge_outage,
            } => self.set_dns(authority, Some(profile), *acknowledge_outage),
            Command::ClearGlobalDns {} => self.set_dns(authority, None, true),
            Command::ApplyPolicy {
                document,
                expected_generation,
            } => self.apply_policy(authority, document, *expected_generation),
            Command::RemovePolicy {
                owner,
                expected_generation,
            } => self.remove_policy(authority, owner, *expected_generation),
            _ => Err(ErrorCode::InvalidRequest),
        }
    }

    fn register_profile(
        &mut self,
        authority: &Authority,
        owner: &Owner,
        registration_key: &str,
        consumers: &[Owner],
    ) -> Result<Reply, ErrorCode> {
        authorize_target(owner, authority)?;
        let profile = self
            .profiles
            .register_stable(
                authority,
                owner.clone(),
                registration_key,
                consumers.to_vec(),
            )
            .map_err(profile_error)?;
        Ok(Reply::Registered { profile })
    }

    fn apply_policy(
        &mut self,
        authority: &Authority,
        document: &PolicyDocument,
        expected_generation: Option<u64>,
    ) -> Result<Reply, ErrorCode> {
        let prepared = self.prepare_policy(authority, document, expected_generation)?;
        let revision = prepared.revision();
        self.policies.commit(prepared).map_err(registry_error)?;
        Ok(Reply::Applied { revision })
    }

    fn remove_policy(
        &mut self,
        authority: &Authority,
        owner: &Owner,
        expected_generation: u64,
    ) -> Result<Reply, ErrorCode> {
        authorize_target(owner, authority)?;
        let prepared = self
            .policies
            .prepare_removal(owner.clone(), authority, expected_generation)
            .map_err(registry_error)?;
        let revision = prepared.revision();
        self.policies
            .commit_removal(prepared)
            .map_err(registry_error)?;
        Ok(Reply::Applied { revision })
    }

    fn prepare_policy(
        &self,
        authority: &Authority,
        document: &PolicyDocument,
        expected_generation: Option<u64>,
    ) -> Result<aivpn_desktop_policy::PreparedPolicy, ErrorCode> {
        if self.decommissioned {
            return Err(ErrorCode::Conflict);
        }
        authorize_target(&document.owner, authority)?;
        let prepared = self
            .policies
            .prepare(document.clone(), authority, expected_generation)
            .map_err(registry_error)?;
        self.profiles
            .authorize_policy(prepared.policy(), authority)
            .map_err(profile_error)?;
        Ok(prepared)
    }

    fn delete_profile(&mut self, authority: &Authority, profile: &str) -> Result<Reply, ErrorCode> {
        self.check_profile_delete(authority, profile)?;
        self.profiles
            .remove(profile, authority)
            .map_err(profile_error)?;
        Ok(Reply::Done {})
    }

    fn check_profile_delete(&self, authority: &Authority, profile: &str) -> Result<(), ErrorCode> {
        let visible = self.profiles.list(authority).map_err(profile_error)?;
        let found = visible
            .iter()
            .find(|entry| entry.id == profile)
            .ok_or(ErrorCode::NotFound)?;
        if !found.control_allowed {
            return Err(ErrorCode::AccessDenied);
        }
        if found.session_active
            || self
                .policies
                .policies()
                .any(|policy| uses_profile(policy.document(), profile))
        {
            return Err(ErrorCode::Conflict);
        }
        Ok(())
    }

    fn set_dns(
        &mut self,
        authority: &Authority,
        profile: Option<&str>,
        acknowledged: bool,
    ) -> Result<Reply, ErrorCode> {
        if !authority.machine_admin {
            return Err(ErrorCode::AccessDenied);
        }
        if !acknowledged {
            return Err(ErrorCode::InvalidRequest);
        }
        if self
            .policies
            .policies()
            .any(|policy| Some(policy.document().dns.profile()) != profile)
        {
            return Err(ErrorCode::Conflict);
        }
        match profile {
            Some(profile) => self.profiles.set_global_dns(profile, authority),
            None => self.profiles.clear_global_dns(authority),
        }
        .map_err(profile_error)?;
        Ok(Reply::Done {})
    }
}

pub struct Control<S, B> {
    state: ControlState,
    store: S,
    backend: B,
    backend_state: BackendState,
    #[cfg(all(
        feature = "local-profile",
        any(
            all(target_os = "linux", feature = "linux-kernel"),
            target_os = "windows"
        )
    ))]
    transport_dns_epoch: u64,
}

impl<S: ControlStore, B: RoutingBackend<S>> Control<S, B> {
    pub fn open(
        platform: Platform,
        namespace: [u8; 16],
        store: S,
        mut backend: B,
    ) -> io::Result<Self> {
        let (state, pending) = snapshot::load(platform, namespace, &store).map_err(|error| {
            if backend.block().is_err() {
                return io::Error::other(
                    "Состояние службы повреждено, блокировка пути не подтверждена",
                );
            }
            error
        })?;
        let mut control = Self {
            state,
            store,
            backend,
            backend_state: BackendState::Unavailable,
            #[cfg(all(
                feature = "local-profile",
                any(
                    all(target_os = "linux", feature = "linux-kernel"),
                    target_os = "windows"
                )
            ))]
            transport_dns_epoch: 0,
        };
        if control.backend.supported() {
            control.recover(pending);
        } else if control.requires_protection(pending) {
            control.fail_closed();
        }
        Ok(control)
    }

    pub fn state(&self) -> &ControlState {
        &self.state
    }
    pub fn backend_state(&self) -> BackendState {
        self.backend_state
    }
    #[cfg(any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    ))]
    pub(crate) fn transport_dns_servers(&mut self) -> io::Result<Vec<std::net::SocketAddr>> {
        self.backend.transport_dns_servers(&self.store)
    }
    #[cfg(any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    ))]
    pub(crate) fn backend_and_state(&mut self) -> (&ControlState, &mut B) {
        (&self.state, &mut self.backend)
    }

    fn requires_protection(&self, pending: bool) -> bool {
        pending
            || self.state.policies.policies().next().is_some()
            || self.state.profiles.global_dns_profile().is_some()
            || self.state.profiles.has_recorded_assignments()
    }

    fn recover(&mut self, pending: bool) {
        let result = self
            .backend
            .install(&mut self.store, &self.state, &self.state.profiles)
            .and_then(|()| {
                if pending {
                    let bytes = self.state.encode()?;
                    self.store.replace(StateFile::Committed, &bytes)?;
                    self.store.clear_pending()?;
                }
                Ok(())
            });
        if result.is_ok() {
            self.backend_state = self.backend.installed_state().into();
        } else {
            self.fail_closed();
        }
    }

    /// authority создает обработчик соединения из учетных данных ОС. В JSON его нет.
    pub fn handle(&mut self, authority: &Authority, request: Request) -> Response {
        let result = self.dispatch(authority, request.command());
        match result {
            Ok(reply) => Response::success(request.id(), reply),
            Err(code) => Response::failure(request.id(), code),
        }
    }

    fn dispatch(&mut self, authority: &Authority, command: &Command) -> Result<Reply, ErrorCode> {
        self.state
            .profiles
            .validate_authority(authority)
            .map_err(profile_error)?;
        if let Some(result) = self.read(authority, command) {
            return result;
        }
        self.mutate(authority, command)
    }

    fn mutate(&mut self, authority: &Authority, command: &Command) -> Result<Reply, ErrorCode> {
        self.require_active_backend()?;
        if let Command::DeleteProfile { profile } = command {
            self.state.check_profile_delete(authority, profile)?;
        }
        if let Command::Decommission {} = command {
            self.state.authorize_decommission(authority)?;
            if self
                .state
                .profiles
                .list(authority)
                .map_err(profile_error)?
                .iter()
                .any(|profile| profile.session_active)
            {
                return Err(ErrorCode::Conflict);
            }
        }
        let (candidate, reply) = self.prepare_change(authority, command)?;
        let Some(candidate) = candidate else {
            return Ok(reply);
        };
        self.commit(&candidate)?;
        self.state.apply(authority, command).map_err(|_| {
            self.fail_closed();
            ErrorCode::RecoveryRequired
        })?;
        self.state.serial = candidate.serial;
        Ok(reply)
    }

    fn require_active_backend(&self) -> Result<(), ErrorCode> {
        match self.backend_state {
            BackendState::Unavailable => Err(ErrorCode::BackendUnavailable),
            BackendState::Recovering | BackendState::ProtectionUnverified => {
                Err(ErrorCode::RecoveryRequired)
            }
            BackendState::Guarded | BackendState::Active => Ok(()),
        }
    }

    fn prepare_change(
        &self,
        authority: &Authority,
        command: &Command,
    ) -> Result<(Option<ControlState>, Reply), ErrorCode> {
        let before = self.state.encode().map_err(|_| ErrorCode::Storage)?;
        let mut candidate =
            ControlState::decode(self.state.platform, &before).map_err(|_| ErrorCode::Storage)?;
        let reply = candidate.apply(authority, command)?;
        if candidate.encode().map_err(|_| ErrorCode::Storage)? == before {
            return Ok((None, reply));
        }
        candidate.serial = candidate.serial.checked_add(1).ok_or(ErrorCode::Capacity)?;
        Ok((Some(candidate), reply))
    }

    fn read(&self, authority: &Authority, command: &Command) -> Option<Result<Reply, ErrorCode>> {
        match command {
            Command::Status {} => Some(Ok(Reply::Status {
                platform: self.state.platform,
                backend: self.backend_state,
                revision: self.state.policies.revision(),
                global_dns_profile: self.state.profiles.global_dns_profile().map(str::to_owned),
            })),
            Command::ListProfiles {} => Some(
                self.state
                    .profiles
                    .list(authority)
                    .map(|profiles| Reply::Profiles { profiles })
                    .map_err(profile_error),
            ),
            Command::GetPolicy { owner } => Some(self.get_policy(authority, owner)),
            Command::ValidatePolicy {
                document,
                expected_generation,
            } => Some(
                self.state
                    .prepare_policy(authority, document, *expected_generation)
                    .map(|prepared| Reply::Validated {
                        revision: prepared.revision(),
                    }),
            ),
            _ => None,
        }
    }

    fn get_policy(&self, authority: &Authority, owner: &Owner) -> Result<Reply, ErrorCode> {
        if *owner != (Owner::Machine {}) {
            authorize_target(owner, authority)?;
        }
        Ok(Reply::Policy {
            document: self
                .state
                .policies
                .get(owner)
                .map(|policy| policy.document().clone()),
        })
    }

    fn commit(&mut self, candidate: &ControlState) -> Result<(), ErrorCode> {
        let bytes = self.stage(candidate)?;
        self.install_staged(candidate, &bytes)
    }

    fn stage(&mut self, candidate: &ControlState) -> Result<Vec<u8>, ErrorCode> {
        let bytes = candidate.encode().map_err(|_| ErrorCode::Storage)?;
        if self.store.replace(StateFile::Pending, &bytes).is_err() {
            self.fail_closed();
            return Err(ErrorCode::Storage);
        }
        Ok(bytes)
    }

    fn install_staged(&mut self, candidate: &ControlState, bytes: &[u8]) -> Result<(), ErrorCode> {
        if self
            .backend
            .install(&mut self.store, candidate, &self.state.profiles)
            .is_err()
        {
            self.fail_closed();
            return Err(ErrorCode::BackendUnavailable);
        }
        if self
            .store
            .replace(StateFile::Committed, bytes)
            .and_then(|()| self.store.clear_pending())
            .is_err()
        {
            self.fail_closed();
            return Err(ErrorCode::Storage);
        }
        self.backend_state = self.backend.installed_state().into();
        Ok(())
    }

    fn fail_closed(&mut self) {
        self.state.profiles.invalidate_sessions();
        self.backend_state = if self.backend.block().is_ok() {
            BackendState::Recovering
        } else {
            BackendState::ProtectionUnverified
        };
    }
}

fn authorize_target(owner: &Owner, authority: &Authority) -> Result<(), ErrorCode> {
    if owner != &authority.user && !authority.machine_admin {
        return Err(ErrorCode::AccessDenied);
    }
    Ok(())
}

fn uses_profile(document: &PolicyDocument, profile: &str) -> bool {
    let routes = std::iter::once(&document.default_action)
        .chain(document.rules.iter().map(|rule| &rule.action));
    document.dns.profile() == profile || routes.into_iter().any(|action| matches!(action, aivpn_desktop_policy::Action::Vpn { profile: used } if used == profile))
}

fn profile_error(error: ProfileError) -> ErrorCode {
    match error {
        ProfileError::NotFound => ErrorCode::NotFound,
        ProfileError::SessionIdentityUnavailable => ErrorCode::BackendUnavailable,
        ProfileError::AccessDenied => ErrorCode::AccessDenied,
        ProfileError::Capacity | ProfileError::GenerationExhausted => ErrorCode::Capacity,
        ProfileError::GlobalDnsMismatch
        | ProfileError::InUse
        | ProfileError::StaleLease
        | ProfileError::RegistrationConflict => ErrorCode::Conflict,
        _ => ErrorCode::InvalidRequest,
    }
}

fn registry_error(error: RegistryError) -> ErrorCode {
    match error {
        RegistryError::NotFound => ErrorCode::NotFound,
        RegistryError::Capacity => ErrorCode::Capacity,
        RegistryError::StaleGeneration
        | RegistryError::InvalidGeneration
        | RegistryError::OwnerConflict
        | RegistryError::DnsProfileConflict => ErrorCode::Conflict,
        _ => ErrorCode::InvalidRequest,
    }
}
