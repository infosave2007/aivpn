use super::{
    PreparedAssignment, ProfileAssignment, ProfileCatalog, ProfileError, Record, MAX_PROFILES,
};
use crate::{validate, Authority, Owner, Platform};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroU64;

const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    platform: Platform,
    namespace: String,
    next_id: String,
    #[serde(default)]
    global_dns: Option<String>,
    profiles: Vec<StoredProfile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProfile {
    id: String,
    owner: Owner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration_key: Option<String>,
    consumers: Vec<Owner>,
    assignment_generation: u64,
    assignment: Option<ProfileAssignment>,
}

impl ProfileCatalog {
    /// Снимок содержит права и последнее назначение, без ключей и признака готовности.
    /// Служба сохраняет его атомарно до публикации изменений в ОС.
    pub fn store_metadata(&self) -> Result<Vec<u8>, ProfileError> {
        self.snapshot().encode()
    }

    /// Фиксирует новое поколение на диске до включения передачи в backend.
    /// Исходный каталог и готовность при этом не меняются.
    pub fn store_metadata_for_assignment(
        &self,
        prepared: &PreparedAssignment,
    ) -> Result<Vec<u8>, ProfileError> {
        self.check_preparation(prepared)?;
        let mut snapshot = self.snapshot();
        let record = snapshot
            .profiles
            .iter_mut()
            .find(|record| record.id == prepared.lease.profile)
            .ok_or(ProfileError::NotFound)?;
        record.assignment_generation = prepared.generation;
        record.assignment = Some(prepared.assignment);
        snapshot.encode()
    }

    fn snapshot(&self) -> Snapshot {
        let mut profiles = self
            .records
            .iter()
            .map(|(id, record)| {
                let mut consumers = record.consumers.iter().cloned().collect::<Vec<_>>();
                consumers.sort_unstable_by_key(Owner::sort_key);
                StoredProfile {
                    id: id.clone(),
                    owner: record.owner.clone(),
                    registration_key: record.registration_key.clone(),
                    consumers,
                    assignment_generation: record.assignment_generation,
                    assignment: record.assignment,
                }
            })
            .collect::<Vec<_>>();
        profiles.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        Snapshot {
            version: 1,
            platform: self.platform,
            namespace: format!("{:032x}", self.namespace),
            next_id: format!("{:016x}", self.next_id.get()),
            global_dns: self.global_dns.clone(),
            profiles,
        }
    }

    /// Принимает только содержимое защищенного файла службы после проверки его владельца.
    /// Этот формат нельзя принимать из пользовательского IPC: он восстанавливает права доступа.
    pub fn restore_metadata(platform: Platform, bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(ProfileError::InvalidMetadata);
        }
        let snapshot: Snapshot =
            serde_json::from_slice(bytes).map_err(|_| ProfileError::InvalidMetadata)?;
        let mut catalog = snapshot.empty_catalog(platform)?;
        for record in snapshot.profiles {
            catalog.restore_record(record)?;
        }
        if let Some(profile) = snapshot.global_dns {
            if !catalog.records.contains_key(&profile) {
                return Err(ProfileError::InvalidMetadata);
            }
            catalog.global_dns = Some(profile);
        }
        Ok(catalog)
    }

    fn restore_record(&mut self, stored: StoredProfile) -> Result<(), ProfileError> {
        self.check_stored_identity(&stored.id)?;
        validate::owner(&stored.owner, self.platform)?;
        let authority = Authority {
            user: stored.owner.clone(),
            machine_admin: true,
        };
        let consumers = self.validate_grants(&stored.owner, stored.consumers, &authority)?;
        self.check_stored_registration(&stored.owner, stored.registration_key.as_deref())?;
        if stored.assignment.is_some() != (stored.assignment_generation > 0)
            || stored.assignment.is_some_and(|value| !value.valid())
        {
            return Err(ProfileError::InvalidMetadata);
        }
        self.records.insert(
            stored.id,
            Record {
                owner: stored.owner,
                registration_key: stored.registration_key,
                consumers,
                session: None,
                assignment_generation: stored.assignment_generation,
                assignment: stored.assignment,
            },
        );
        Ok(())
    }

    fn check_stored_registration(
        &self,
        owner: &Owner,
        key: Option<&str>,
    ) -> Result<(), ProfileError> {
        if let Some(key) = key {
            validate::identifier(key)?;
            if self.records.values().any(|record| {
                &record.owner == owner && record.registration_key.as_deref() == Some(key)
            }) {
                return Err(ProfileError::InvalidMetadata);
            }
        }
        Ok(())
    }

    fn check_stored_identity(&self, id: &str) -> Result<(), ProfileError> {
        let prefix = format!("p{:032x}-", self.namespace);
        let suffix = id
            .strip_prefix(&prefix)
            .ok_or(ProfileError::InvalidMetadata)?;
        let counter = u64::from_str_radix(suffix, 16).map_err(|_| ProfileError::InvalidMetadata)?;
        if counter == 0
            || counter >= self.next_id.get()
            || suffix != format!("{counter:016x}")
            || self.records.contains_key(id)
        {
            return Err(ProfileError::InvalidMetadata);
        }
        Ok(())
    }
}

impl Snapshot {
    fn encode(&self) -> Result<Vec<u8>, ProfileError> {
        serde_json::to_vec(self).map_err(|_| ProfileError::InvalidMetadata)
    }

    fn empty_catalog(&self, platform: Platform) -> Result<ProfileCatalog, ProfileError> {
        if self.version != 1 || self.platform != platform || self.profiles.len() > MAX_PROFILES {
            return Err(ProfileError::InvalidMetadata);
        }
        let namespace =
            u128::from_str_radix(&self.namespace, 16).map_err(|_| ProfileError::InvalidMetadata)?;
        let next_id = u64::from_str_radix(&self.next_id, 16)
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(ProfileError::InvalidMetadata)?;
        if self.namespace != format!("{namespace:032x}")
            || self.next_id != format!("{:016x}", next_id.get())
        {
            return Err(ProfileError::InvalidMetadata);
        }
        Ok(ProfileCatalog {
            platform,
            namespace,
            next_id,
            records: HashMap::new(),
            global_dns: None,
        })
    }
}
