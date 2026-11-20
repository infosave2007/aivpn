use super::{PolicyRegistry, PreparedPolicy, PreparedRemoval, RegistryError, MAX_POLICIES};
use crate::{validate, Authority, Owner, Platform, Policy, PolicyDocument};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_METADATA_BYTES: usize = 36 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    platform: Platform,
    revision: u64,
    policies: Vec<PolicyDocument>,
}

impl PolicyRegistry {
    pub fn store_metadata(&self) -> Result<Vec<u8>, RegistryError> {
        self.snapshot().encode()
    }

    /// Подготовленный снимок сохраняется до публикации поколения в backend.
    pub fn store_metadata_for_policy(
        &self,
        prepared: &PreparedPolicy,
    ) -> Result<Vec<u8>, RegistryError> {
        self.check_prepared(prepared)?;
        let mut snapshot = self.snapshot();
        snapshot
            .policies
            .retain(|policy| policy.owner != prepared.policy.document().owner);
        snapshot.policies.push(prepared.policy.document().clone());
        snapshot.revision = prepared.revision.get();
        snapshot.encode()
    }

    pub fn store_metadata_for_removal(
        &self,
        prepared: &PreparedRemoval,
    ) -> Result<Vec<u8>, RegistryError> {
        self.check_prepared_removal(prepared)?;
        let mut snapshot = self.snapshot();
        snapshot
            .policies
            .retain(|policy| policy.owner != prepared.owner);
        snapshot.revision = prepared.revision.get();
        snapshot.encode()
    }

    /// Только для защищенного файла службы. Не используется как пользовательская команда IPC.
    pub fn restore_metadata(
        platform: Platform,
        bytes: &[u8],
        authority: &Authority,
    ) -> Result<Self, RegistryError> {
        validate::authorize(&Owner::Machine {}, authority, platform)?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(RegistryError::InvalidMetadata);
        }
        let snapshot: Snapshot = serde_json::from_slice(bytes)?;
        snapshot.validate(platform)?;
        let mut registry = Self::new(platform);
        registry.revision = snapshot.revision;
        for document in snapshot.policies {
            registry.restore_policy(document, authority)?;
        }
        Ok(registry)
    }

    fn restore_policy(
        &mut self,
        document: PolicyDocument,
        authority: &Authority,
    ) -> Result<(), RegistryError> {
        if document.generation > self.revision || self.policies.contains_key(&document.owner) {
            return Err(RegistryError::InvalidMetadata);
        }
        let policy = Policy::validate(document, authority)?;
        self.check_compatibility(policy.document())?;
        self.policies
            .insert(policy.document().owner.clone(), Arc::new(policy));
        Ok(())
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: 1,
            platform: self.platform,
            revision: self.revision,
            policies: self
                .policies
                .values()
                .map(|policy| policy.document().clone())
                .collect(),
        }
    }
}

impl Snapshot {
    fn validate(&self, platform: Platform) -> Result<(), RegistryError> {
        if self.version != 1 || self.platform != platform || self.policies.len() > MAX_POLICIES {
            return Err(RegistryError::InvalidMetadata);
        }
        Ok(())
    }

    fn encode(mut self) -> Result<Vec<u8>, RegistryError> {
        self.policies
            .sort_unstable_by_key(|policy| policy.owner.sort_key());
        Ok(serde_json::to_vec(&self)?)
    }
}
