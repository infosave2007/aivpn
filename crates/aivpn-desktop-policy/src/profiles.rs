mod storage;

use crate::{network, validate, Action, Authority, Owner, Platform, Policy, PolicyError};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;
use std::sync::Arc;
use thiserror::Error;

const MAX_PROFILES: usize = 256;
const MAX_GRANTS: usize = 128;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("Профиль не найден")]
    NotFound,
    #[error("Общий DNS не выбран администратором или выбран другой профиль")]
    GlobalDnsMismatch,
    #[error("Профиль используется общим DNS")]
    InUse,
    #[error("Профиль недоступен владельцу политики")]
    AccessDenied,
    #[error("Достигнут предел профилей или полномочий")]
    Capacity,
    #[error("Список доступа содержит повторы или самого владельца")]
    DuplicateGrant,
    #[error("Ключ регистрации уже использован с другим списком доступа")]
    RegistrationConflict,
    #[error("Состояние относится к завершенному сеансу профиля")]
    StaleLease,
    #[error("Исчерпан счетчик поколений")]
    GenerationExhausted,
    #[error("Повреждены сохраненные данные каталога профилей")]
    InvalidMetadata,
    #[error("Некорректное назначение адресов или интерфейса VPN")]
    InvalidAssignment,
    #[error("Не удалось создать идентификатор сеанса")]
    SessionIdentityUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAssignment {
    pub interface_id: u64,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

/// Видимая пользователю часть состояния. Секреты и полномочия сеанса сюда не входят.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileStatus {
    pub id: String,
    pub owner: Owner,
    pub control_allowed: bool,
    pub session_active: bool,
    pub ready_ipv4: bool,
    pub ready_ipv6: bool,
    pub assignment_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Addr>,
}

/// Снимок для backend. Наличие прежнего назначения не означает готовность сеанса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProfile {
    pub id: String,
    pub assignment: Option<ProfileAssignment>,
    pub assignment_generation: u64,
    pub ready_ipv4: bool,
    pub ready_ipv6: bool,
}

impl ProfileAssignment {
    fn valid(&self) -> bool {
        let ipv4 = self.ipv4.octets();
        self.interface_id != 0
            && ipv4[0] != 0
            && ipv4[0] != 127
            && ipv4[0] < 224
            && self.ipv6.is_none_or(|address| {
                !address.is_unspecified()
                    && !address.is_multicast()
                    && !address.is_loopback()
                    && address.to_ipv4_mapped().is_none()
            })
    }
}

#[derive(Debug)]
struct SessionIdentity {
    id: [u8; 16],
}

#[derive(Debug)]
struct PreparationIdentity;

/// Право обновлять готовность выдает служба конкретному сеансу. Из IPC оно не читается.
#[derive(Debug, Clone)]
pub struct ProfileLease {
    profile: String,
    identity: Arc<SessionIdentity>,
}

impl ProfileLease {
    pub fn session_id(&self) -> [u8; 16] {
        self.identity.id
    }
}

/// Назначение подготавливается до изменения ОС и становится готовым только после проверки backend.
#[derive(Debug)]
pub struct PreparedAssignment {
    lease: ProfileLease,
    identity: Arc<PreparationIdentity>,
    previous_generation: u64,
    generation: u64,
    assignment: ProfileAssignment,
}

impl PreparedAssignment {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn assignment(&self) -> ProfileAssignment {
        self.assignment
    }
}

#[derive(Debug)]
struct Record {
    owner: Owner,
    registration_key: Option<String>,
    consumers: HashSet<Owner>,
    session: Option<Session>,
    assignment_generation: u64,
    assignment: Option<ProfileAssignment>,
}

#[derive(Debug)]
struct Session {
    identity: Arc<SessionIdentity>,
    preparation: Option<Arc<PreparationIdentity>>,
    ready: bool,
}

/// Идентификаторы относятся ко всей службе, а не к именам профилей отдельных пользователей.
/// Namespace создает доверенный backend из свежих случайных 128 бит для нового каталога.
#[derive(Debug)]
pub struct ProfileCatalog {
    platform: Platform,
    namespace: u128,
    next_id: NonZeroU64,
    records: HashMap<String, Record>,
    global_dns: Option<String>,
}

impl ProfileCatalog {
    pub fn namespace(&self) -> [u8; 16] {
        self.namespace.to_be_bytes()
    }

    /// Прежнее назначение может оставлять ресурсы защиты даже после завершения сеанса.
    pub fn has_recorded_assignments(&self) -> bool {
        self.records
            .values()
            .any(|record| record.assignment.is_some())
    }

    pub fn new(platform: Platform, namespace: [u8; 16]) -> Self {
        Self {
            platform,
            namespace: u128::from_be_bytes(namespace),
            next_id: NonZeroU64::MIN,
            records: HashMap::new(),
            global_dns: None,
        }
    }

    /// Меняет только доверенное состояние. Backend отдельно сохраняет его и устанавливает защиту DNS.
    pub fn set_global_dns(
        &mut self,
        profile: &str,
        authority: &Authority,
    ) -> Result<(), ProfileError> {
        self.require_machine_admin(authority)?;
        if !self.records.contains_key(profile) {
            return Err(ProfileError::NotFound);
        }
        self.global_dns = Some(profile.to_owned());
        Ok(())
    }

    /// Вызывается после согласованного восстановления DNS в ОС и проверки чужих настроек.
    pub fn clear_global_dns(&mut self, authority: &Authority) -> Result<(), ProfileError> {
        self.require_machine_admin(authority)?;
        self.global_dns = None;
        Ok(())
    }

    pub fn global_dns_profile(&self) -> Option<&str> {
        self.global_dns.as_deref()
    }

    /// Сеансы останавливает координатор до подготовки удаления службы.
    pub fn clear_for_decommission(&mut self, authority: &Authority) -> Result<(), ProfileError> {
        self.require_machine_admin(authority)?;
        if self.records.values().any(|record| record.session.is_some()) {
            return Err(ProfileError::InUse);
        }
        self.global_dns = None;
        self.records.clear();
        Ok(())
    }

    pub fn list(&self, authority: &Authority) -> Result<Vec<ProfileStatus>, ProfileError> {
        self.validate_authority(authority)?;
        let mut profiles = self
            .records
            .iter()
            .filter_map(|(id, record)| self.visible_profile(id, record, authority))
            .collect::<Vec<_>>();
        profiles.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        Ok(profiles)
    }

    /// Рабочие назначения доступны только доверенной службе, отдельно от пользовательского статуса.
    pub fn runtime_profiles(
        &self,
        authority: &Authority,
    ) -> Result<Vec<RuntimeProfile>, ProfileError> {
        self.require_machine_admin(authority)?;
        let mut profiles = self
            .records
            .iter()
            .map(|(id, record)| record.runtime_profile(id))
            .collect::<Vec<_>>();
        profiles.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        Ok(profiles)
    }

    /// Право сеанса открывает только соответствующий профиль, без доступа к остальному каталогу.
    pub fn session_profile(&self, lease: &ProfileLease) -> Result<RuntimeProfile, ProfileError> {
        let record = self
            .records
            .get(&lease.profile)
            .ok_or(ProfileError::NotFound)?;
        record.session_for(lease)?;
        Ok(record.runtime_profile(&lease.profile))
    }

    pub fn validate_authority(&self, authority: &Authority) -> Result<(), ProfileError> {
        validate::owner(&authority.user, self.platform)?;
        if authority.user == (Owner::Machine {}) {
            return Err(ProfileError::AccessDenied);
        }
        Ok(())
    }

    fn visible_profile(
        &self,
        id: &str,
        record: &Record,
        authority: &Authority,
    ) -> Option<ProfileStatus> {
        let control_allowed = authority.machine_admin || record.owner == authority.user;
        if !control_allowed && !record.consumers.contains(&authority.user) {
            return None;
        }
        let ready = record.ready_assignment();
        Some(ProfileStatus {
            id: id.into(),
            owner: record.owner.clone(),
            control_allowed,
            session_active: record.session.is_some(),
            ready_ipv4: ready.is_some(),
            ready_ipv6: ready.is_some_and(|assignment| assignment.ipv6.is_some()),
            assignment_generation: record.assignment_generation,
            session_id: control_allowed
                .then(|| record.session.as_ref().map(|session| session.identity.id))
                .flatten(),
            registration_key: control_allowed
                .then(|| record.registration_key.clone())
                .flatten(),
            ipv4: ready.map(|assignment| assignment.ipv4),
            ipv6: ready.and_then(|assignment| assignment.ipv6),
        })
    }

    fn require_machine_admin(&self, authority: &Authority) -> Result<(), ProfileError> {
        self.validate_authority(authority)?;
        if !authority.machine_admin {
            return Err(ProfileError::AccessDenied);
        }
        Ok(())
    }

    pub fn register(
        &mut self,
        authority: &Authority,
        owner: Owner,
        consumers: Vec<Owner>,
    ) -> Result<String, ProfileError> {
        self.register_with_key(authority, owner, None, consumers)
    }

    /// Повтор регистрации того же локального профиля возвращает прежний ID.
    /// После явного удаления новый профиль всегда получает новый ID службы.
    pub fn register_stable(
        &mut self,
        authority: &Authority,
        owner: Owner,
        registration_key: &str,
        consumers: Vec<Owner>,
    ) -> Result<String, ProfileError> {
        validate::identifier(registration_key)?;
        self.register_with_key(authority, owner, Some(registration_key.into()), consumers)
    }

    fn register_with_key(
        &mut self,
        authority: &Authority,
        owner: Owner,
        registration_key: Option<String>,
        consumers: Vec<Owner>,
    ) -> Result<String, ProfileError> {
        validate::owner(&owner, self.platform)?;
        validate::authorize(&owner, authority, self.platform)?;
        let consumers = self.validate_grants(&owner, consumers, authority)?;
        if let Some(key) = registration_key.as_deref() {
            if let Some(id) = self.existing_registration(&owner, key, &consumers)? {
                return Ok(id);
            }
        }
        self.insert_profile(owner, registration_key, consumers)
    }

    fn existing_registration(
        &self,
        owner: &Owner,
        key: &str,
        consumers: &HashSet<Owner>,
    ) -> Result<Option<String>, ProfileError> {
        let found = self.records.iter().find(|(_, record)| {
            &record.owner == owner && record.registration_key.as_deref() == Some(key)
        });
        let Some((id, record)) = found else {
            return Ok(None);
        };
        if &record.consumers != consumers {
            return Err(ProfileError::RegistrationConflict);
        }
        Ok(Some(id.clone()))
    }

    fn insert_profile(
        &mut self,
        owner: Owner,
        registration_key: Option<String>,
        consumers: HashSet<Owner>,
    ) -> Result<String, ProfileError> {
        if self.records.len() >= MAX_PROFILES {
            return Err(ProfileError::Capacity);
        }
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ProfileError::GenerationExhausted)?;
        let id = format!("p{:032x}-{:016x}", self.namespace, self.next_id.get());
        self.records.insert(
            id.clone(),
            Record {
                owner,
                registration_key,
                consumers,
                session: None,
                assignment_generation: 0,
                assignment: None,
            },
        );
        self.next_id = next_id;
        Ok(id)
    }

    fn validate_grants(
        &self,
        owner: &Owner,
        consumers: Vec<Owner>,
        authority: &Authority,
    ) -> Result<HashSet<Owner>, ProfileError> {
        if consumers.len() > MAX_GRANTS {
            return Err(ProfileError::Capacity);
        }
        if !consumers.is_empty() && !authority.machine_admin {
            return Err(ProfileError::AccessDenied);
        }
        let mut grants = HashSet::new();
        for consumer in consumers {
            validate::owner(&consumer, self.platform)?;
            if &consumer == owner || !grants.insert(consumer) {
                return Err(ProfileError::DuplicateGrant);
            }
        }
        Ok(grants)
    }

    pub fn authorize_policy(
        &self,
        policy: &Policy,
        authority: &Authority,
    ) -> Result<(), ProfileError> {
        let doc = policy.effective_document();
        if doc.platform != self.platform {
            return Err(ProfileError::AccessDenied);
        }
        validate::authorize(&doc.owner, authority, self.platform)?;
        if self.global_dns.as_deref() != Some(doc.dns.profile()) {
            return Err(ProfileError::GlobalDnsMismatch);
        }
        for action in
            std::iter::once(&doc.default_action).chain(doc.rules.iter().map(|rule| &rule.action))
        {
            if let Action::Vpn { profile } = action {
                self.authorize_consumer(profile, &doc.owner)?;
            }
        }
        Ok(())
    }

    fn authorize_consumer(&self, profile: &str, owner: &Owner) -> Result<(), ProfileError> {
        let record = self.records.get(profile).ok_or(ProfileError::NotFound)?;
        if &record.owner != owner && !record.consumers.contains(owner) {
            return Err(ProfileError::AccessDenied);
        }
        Ok(())
    }

    pub fn begin_session(
        &mut self,
        profile: &str,
        authority: &Authority,
    ) -> Result<ProfileLease, ProfileError> {
        let record = self
            .records
            .get_mut(profile)
            .ok_or(ProfileError::NotFound)?;
        validate::authorize(&record.owner, authority, self.platform)
            .map_err(|_| ProfileError::AccessDenied)?;
        use rand::RngCore;
        let mut id = [0; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| ProfileError::SessionIdentityUnavailable)?;
        let identity = Arc::new(SessionIdentity { id });
        record.session = Some(Session {
            identity: identity.clone(),
            preparation: None,
            ready: false,
        });
        Ok(ProfileLease {
            profile: profile.to_owned(),
            identity,
        })
    }

    fn leased_record(&mut self, lease: &ProfileLease) -> Result<&mut Record, ProfileError> {
        let record = self
            .records
            .get_mut(&lease.profile)
            .ok_or(ProfileError::NotFound)?;
        record.session_for(lease)?;
        Ok(record)
    }

    /// Подготовка закрывает готовность. Backend устанавливает guard и новое назначение,
    /// затем проверяет их и вызывает commit_ready с тем же объектом подготовки.
    pub fn prepare_assignment(
        &mut self,
        lease: &ProfileLease,
        assignment: ProfileAssignment,
    ) -> Result<PreparedAssignment, ProfileError> {
        let record = self.leased_record(lease)?;
        let session = record.session.as_mut().ok_or(ProfileError::StaleLease)?;
        session.ready = false;
        session.preparation = None;
        if !assignment.valid() {
            return Err(ProfileError::InvalidAssignment);
        }
        let generation = if record.assignment == Some(assignment) {
            record.assignment_generation
        } else {
            record
                .assignment_generation
                .checked_add(1)
                .ok_or(ProfileError::GenerationExhausted)?
        };
        let identity = Arc::new(PreparationIdentity);
        session.preparation = Some(identity.clone());
        Ok(PreparedAssignment {
            lease: lease.clone(),
            identity,
            previous_generation: record.assignment_generation,
            generation,
            assignment,
        })
    }

    fn check_preparation(&self, prepared: &PreparedAssignment) -> Result<(), ProfileError> {
        let record = self
            .records
            .get(&prepared.lease.profile)
            .ok_or(ProfileError::NotFound)?;
        let session = record.session_for(&prepared.lease)?;
        if !session
            .preparation
            .as_ref()
            .is_some_and(|identity| Arc::ptr_eq(identity, &prepared.identity))
            || record.assignment_generation != prepared.previous_generation
        {
            return Err(ProfileError::StaleLease);
        }
        Ok(())
    }

    pub fn commit_ready(&mut self, prepared: PreparedAssignment) -> Result<(), ProfileError> {
        self.check_preparation(&prepared)?;
        let record = self.leased_record(&prepared.lease)?;
        let session = record.session.as_mut().ok_or(ProfileError::StaleLease)?;
        record.assignment_generation = prepared.generation;
        record.assignment = Some(prepared.assignment);
        session.preparation = None;
        session.ready = true;
        Ok(())
    }

    pub fn disconnect(&mut self, lease: &ProfileLease) -> Result<(), ProfileError> {
        let record = self.leased_record(lease)?;
        record.session = None;
        Ok(())
    }

    /// После сбоя backend прежние сеансы не могут вернуть готовность старым полномочием.
    pub fn invalidate_sessions(&mut self) {
        for record in self.records.values_mut() {
            record.session = None;
        }
    }

    pub fn available(&self, profile: &str, destination: IpAddr) -> bool {
        let Some(record) = self.records.get(profile) else {
            return false;
        };
        record.ready_assignment().is_some_and(|assignment| {
            network::canonical_ip(destination).is_ipv4() || assignment.ipv6.is_some()
        })
    }

    /// Вызывается после запрета передачи и очистки ресурсов профиля в backend.
    pub fn remove(&mut self, profile: &str, authority: &Authority) -> Result<(), ProfileError> {
        let record = self.records.get(profile).ok_or(ProfileError::NotFound)?;
        validate::authorize(&record.owner, authority, self.platform)?;
        if self.global_dns.as_deref() == Some(profile) {
            return Err(ProfileError::InUse);
        }
        self.records.remove(profile);
        Ok(())
    }
}

impl Record {
    fn runtime_profile(&self, id: &str) -> RuntimeProfile {
        let ready = self.ready_assignment();
        RuntimeProfile {
            id: id.into(),
            assignment: self.assignment,
            assignment_generation: self.assignment_generation,
            ready_ipv4: ready.is_some(),
            ready_ipv6: ready.is_some_and(|assignment| assignment.ipv6.is_some()),
        }
    }

    fn ready_assignment(&self) -> Option<ProfileAssignment> {
        self.session
            .as_ref()
            .filter(|session| session.ready)
            .and(self.assignment)
    }

    fn session_for(&self, lease: &ProfileLease) -> Result<&Session, ProfileError> {
        self.session
            .as_ref()
            .filter(|session| Arc::ptr_eq(&session.identity, &lease.identity))
            .ok_or(ProfileError::StaleLease)
    }
}
