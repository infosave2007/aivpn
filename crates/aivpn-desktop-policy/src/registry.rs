mod storage;

use crate::{validate, Authority, Owner, Platform, Policy, PolicyDocument, PolicyError};
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use thiserror::Error;

const MAX_POLICIES: usize = 256;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("Политика предназначена для другой платформы")]
    PlatformMismatch,
    #[error("Поколение политики изменилось")]
    StaleGeneration,
    #[error("Нужно следующее последовательное поколение политики")]
    InvalidGeneration,
    #[error("Нельзя неявно совместить машинную и пользовательскую политику")]
    OwnerConflict,
    #[error("Достигнут предел числа политик")]
    Capacity,
    #[error("Подготовка принадлежит другому экземпляру реестра")]
    ForeignRegistry,
    #[error("Общий DNS уже использует другой профиль VPN")]
    DnsProfileConflict,
    #[error("Политика не найдена")]
    NotFound,
    #[error("Некорректный снимок реестра политик")]
    InvalidMetadata,
    #[error("Некорректный JSON снимка: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
struct RegistryIdentity;

/// Подготовка не меняет действующий снимок. Объекты ядра проверяет вызывающий backend.
#[derive(Debug)]
pub struct PreparedPolicy {
    policy: Arc<Policy>,
    expected_generation: Option<u64>,
    revision: NonZeroU64,
    registry: Arc<RegistryIdentity>,
}

impl PreparedPolicy {
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
}

#[derive(Debug)]
pub struct PreparedRemoval {
    owner: Owner,
    expected_generation: u64,
    revision: NonZeroU64,
    registry: Arc<RegistryIdentity>,
}

impl PreparedRemoval {
    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
}

/// Реестр имеет одного владельца записи в службе. Выданные снимки не меняются.
#[derive(Debug)]
pub struct PolicyRegistry {
    platform: Platform,
    policies: HashMap<Owner, Arc<Policy>>,
    revision: u64,
    identity: Arc<RegistryIdentity>,
}

impl PolicyRegistry {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            policies: HashMap::new(),
            revision: 0,
            identity: Arc::new(RegistryIdentity),
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn get(&self, owner: &Owner) -> Option<Arc<Policy>> {
        self.policies.get(owner).cloned()
    }

    pub fn policies(&self) -> impl Iterator<Item = &Policy> {
        self.policies.values().map(AsRef::as_ref)
    }

    /// Удаление службы снимает политики всех владельцев одной транзакцией.
    pub fn clear_for_decommission(&mut self, authority: &Authority) -> Result<(), RegistryError> {
        validate::authorize(&Owner::Machine {}, authority, self.platform)?;
        if !self.policies.is_empty() {
            let revision = self
                .revision
                .checked_add(1)
                .ok_or(RegistryError::Capacity)?;
            self.policies.clear();
            self.revision = revision;
        }
        Ok(())
    }

    pub fn prepare(
        &self,
        document: PolicyDocument,
        authority: &Authority,
        expected_generation: Option<u64>,
    ) -> Result<PreparedPolicy, RegistryError> {
        let policy = Arc::new(Policy::validate(document, authority)?);
        self.check_slot(policy.document(), expected_generation)?;
        Ok(PreparedPolicy {
            policy,
            expected_generation,
            revision: self.next_revision()?,
            registry: self.identity.clone(),
        })
    }

    /// Backend вызывает commit после установки и проверки нового поколения защиты.
    /// При ошибке commit он обязан откатить собственную транзакцию объектов ОС.
    pub fn commit(&mut self, update: PreparedPolicy) -> Result<(), RegistryError> {
        self.check_prepared(&update)?;
        self.revision = update.revision.get();
        self.policies
            .insert(update.policy.document().owner.clone(), update.policy);
        Ok(())
    }

    pub fn prepare_removal(
        &self,
        owner: Owner,
        authority: &Authority,
        expected_generation: u64,
    ) -> Result<PreparedRemoval, RegistryError> {
        validate::owner(&owner, self.platform)?;
        validate::authorize(&owner, authority, self.platform)?;
        self.check_removal(&owner, expected_generation)?;
        Ok(PreparedRemoval {
            owner,
            expected_generation,
            revision: self.next_revision()?,
            registry: self.identity.clone(),
        })
    }

    /// Backend сначала прекращает назначать новые потоки, сохраняя решения старых.
    pub fn commit_removal(&mut self, update: PreparedRemoval) -> Result<(), RegistryError> {
        self.check_prepared_removal(&update)?;
        self.policies.remove(&update.owner);
        self.revision = update.revision.get();
        Ok(())
    }

    fn next_revision(&self) -> Result<NonZeroU64, RegistryError> {
        self.revision
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(RegistryError::InvalidGeneration)
    }

    fn check_prepared(&self, update: &PreparedPolicy) -> Result<(), RegistryError> {
        self.check_revision(&update.registry, update.revision)?;
        self.check_slot(update.policy.document(), update.expected_generation)
    }

    fn check_revision(
        &self,
        identity: &Arc<RegistryIdentity>,
        revision: NonZeroU64,
    ) -> Result<(), RegistryError> {
        if !Arc::ptr_eq(&self.identity, identity) {
            return Err(RegistryError::ForeignRegistry);
        }
        if self.revision.checked_add(1) != Some(revision.get()) {
            return Err(RegistryError::StaleGeneration);
        }
        Ok(())
    }

    fn check_prepared_removal(&self, update: &PreparedRemoval) -> Result<(), RegistryError> {
        self.check_revision(&update.registry, update.revision)?;
        self.check_removal(&update.owner, update.expected_generation)
    }

    fn check_removal(&self, owner: &Owner, expected_generation: u64) -> Result<(), RegistryError> {
        let current = self.policies.get(owner).ok_or(RegistryError::NotFound)?;
        if current.document().generation != expected_generation {
            return Err(RegistryError::StaleGeneration);
        }
        Ok(())
    }

    fn check_slot(&self, doc: &PolicyDocument, expected: Option<u64>) -> Result<(), RegistryError> {
        self.check_compatibility(doc)?;
        let current = self
            .policies
            .get(&doc.owner)
            .map(|policy| policy.document().generation);
        if current != expected {
            return Err(RegistryError::StaleGeneration);
        }
        check_next_generation(doc.generation, expected)?;
        Ok(())
    }

    fn check_compatibility(&self, doc: &PolicyDocument) -> Result<(), RegistryError> {
        if doc.platform != self.platform {
            return Err(RegistryError::PlatformMismatch);
        }
        self.check_owner_capacity(&doc.owner)?;
        if self.policies.iter().any(|(owner, policy)| {
            owner != &doc.owner && policy.document().dns.profile() != doc.dns.profile()
        }) {
            return Err(RegistryError::DnsProfileConflict);
        }
        Ok(())
    }

    fn check_owner_capacity(&self, owner: &Owner) -> Result<(), RegistryError> {
        let machine_conflict = match owner {
            Owner::Machine {} => self
                .policies
                .keys()
                .any(|owner| owner != &Owner::Machine {}),
            _ => self.policies.contains_key(&Owner::Machine {}),
        };
        if machine_conflict {
            return Err(RegistryError::OwnerConflict);
        }
        if !self.policies.contains_key(owner) && self.policies.len() >= MAX_POLICIES {
            return Err(RegistryError::Capacity);
        }
        Ok(())
    }
}

fn check_next_generation(generation: u64, expected: Option<u64>) -> Result<(), RegistryError> {
    let next = match expected {
        Some(current) => current
            .checked_add(1)
            .ok_or(RegistryError::InvalidGeneration)?,
        None => 1,
    };
    if generation != next {
        return Err(RegistryError::InvalidGeneration);
    }
    Ok(())
}
