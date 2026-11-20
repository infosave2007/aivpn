use super::{ControlState, ControlStore};
use crate::protocol::ErrorCode;
use crate::state::{StateFile, MAX_STATE_BYTES};
use aivpn_desktop_policy::{
    Authority, Owner, Platform, PolicyRegistry, PreparedAssignment, ProfileCatalog,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::io;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    platform: Platform,
    serial: u64,
    profiles: Box<RawValue>,
    policies: Box<RawValue>,
    #[serde(default, skip_serializing_if = "is_false")]
    decommissioned: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ControlState {
    #[cfg(any(
        all(target_os = "linux", feature = "linux-kernel"),
        target_os = "windows"
    ))]
    pub(crate) fn dns_scope(&self) -> io::Result<Option<crate::dns::journal::DnsScope>> {
        use sha2::{Digest, Sha256};
        let Some(profile) = self.profiles.global_dns_profile() else {
            return Ok(None);
        };
        Ok(Some(crate::dns::journal::DnsScope {
            namespace: self.profiles.namespace(),
            control_serial: self.serial,
            control_digest: Sha256::digest(self.encode()?).into(),
            profile: profile.into(),
        }))
    }
    pub(super) fn encode(&self) -> io::Result<Vec<u8>> {
        self.encode_profiles(
            self.serial,
            &self.profiles.store_metadata().map_err(invalid)?,
        )
    }

    fn encode_profiles(&self, serial: u64, profiles: &[u8]) -> io::Result<Vec<u8>> {
        let snapshot = Snapshot {
            version: 1,
            platform: self.platform,
            serial,
            profiles: serde_json::from_slice(profiles)?,
            policies: serde_json::from_slice(&self.policies.store_metadata().map_err(invalid)?)?,
            decommissioned: self.decommissioned,
        };
        let bytes = serde_json::to_vec(&snapshot)?;
        check_length(&bytes)?;
        Ok(bytes)
    }

    pub(super) fn with_assignment(&self, prepared: &PreparedAssignment) -> Result<Self, ErrorCode> {
        let serial = self.serial.checked_add(1).ok_or(ErrorCode::Capacity)?;
        let profiles = self
            .profiles
            .store_metadata_for_assignment(prepared)
            .map_err(super::profile_error)?;
        let bytes = self
            .encode_profiles(serial, &profiles)
            .map_err(|_| ErrorCode::Storage)?;
        Self::decode(self.platform, &bytes).map_err(|_| ErrorCode::Storage)
    }

    pub(super) fn decode(platform: Platform, bytes: &[u8]) -> io::Result<Self> {
        check_length(bytes)?;
        let snapshot: Snapshot = serde_json::from_slice(bytes)?;
        if snapshot.version != 1 || snapshot.platform != platform {
            return Err(invalid("version"));
        }
        let profiles =
            ProfileCatalog::restore_metadata(platform, snapshot.profiles.get().as_bytes())
                .map_err(invalid)?;
        let authority = administrator(platform);
        let policies = PolicyRegistry::restore_metadata(
            platform,
            snapshot.policies.get().as_bytes(),
            &authority,
        )
        .map_err(invalid)?;
        let state = Self {
            platform,
            serial: snapshot.serial,
            profiles,
            policies,
            decommissioned: snapshot.decommissioned,
        };
        state.check_links(&authority)?;
        Ok(state)
    }

    fn check_links(&self, authority: &Authority) -> io::Result<()> {
        if self.decommissioned
            && (self.policies.policies().next().is_some()
                || !self.profiles.list(authority).map_err(invalid)?.is_empty()
                || self.profiles.global_dns_profile().is_some())
        {
            return Err(invalid("decommissioned"));
        }
        if self.policies.revision() > self.serial {
            return Err(invalid("revision"));
        }
        for policy in self.policies.policies() {
            self.profiles
                .authorize_policy(policy, authority)
                .map_err(invalid)?;
        }
        Ok(())
    }
}

pub(super) fn load(
    platform: Platform,
    namespace: [u8; 16],
    store: &impl ControlStore,
) -> io::Result<(ControlState, bool)> {
    let committed = store
        .load(StateFile::Committed)?
        .map(|bytes| ControlState::decode(platform, &bytes))
        .transpose()?;
    let pending_bytes = store.load(StateFile::Pending)?;
    let Some(bytes) = pending_bytes else {
        return Ok((
            committed.unwrap_or_else(|| ControlState::new(platform, namespace)),
            false,
        ));
    };
    let pending = ControlState::decode(platform, &bytes)?;
    check_pending(committed.as_ref(), &pending)?;
    Ok((pending, true))
}

fn check_pending(committed: Option<&ControlState>, pending: &ControlState) -> io::Result<()> {
    let Some(committed) = committed else {
        if pending.serial != 1 {
            return Err(invalid("initial serial"));
        }
        return Ok(());
    };
    if committed.profiles.namespace() != pending.profiles.namespace() {
        return Err(invalid("namespace"));
    }
    if committed.serial == pending.serial {
        if committed.encode()? != pending.encode()? {
            return Err(invalid("same serial"));
        }
    } else if committed.serial.checked_add(1) != Some(pending.serial) {
        return Err(invalid("serial"));
    }
    Ok(())
}

fn check_length(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_STATE_BYTES {
        return Err(invalid("length"));
    }
    Ok(())
}

fn administrator(platform: Platform) -> Authority {
    Authority {
        user: match platform {
            Platform::Linux => Owner::LinuxUser { uid: 0 },
            Platform::Windows => Owner::WindowsUser {
                sid: "S-1-5-18".into(),
            },
        },
        machine_admin: true,
    }
}

fn invalid(_error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Повреждено состояние службы маршрутизации",
    )
}

/// Доступна только внутри службы и заимствует конкретную блокировку Control.
#[cfg(all(target_os = "linux", feature = "linux-kernel"))]
pub(crate) struct DurableLinuxTarget<'a> {
    store: &'a crate::state::StateDirectory,
    state: &'a ControlState,
    file: StateFile,
    bytes: Vec<u8>,
}

#[cfg(all(target_os = "linux", feature = "linux-kernel"))]
impl ControlState {
    pub(crate) fn durable_linux_target<'a>(
        &'a self,
        store: &'a crate::state::StateDirectory,
    ) -> io::Result<DurableLinuxTarget<'a>> {
        if self.platform != Platform::Linux || self.serial == 0 {
            return Err(invalid("durable target"));
        }
        let (loaded, pending) = load(Platform::Linux, self.profiles.namespace(), store)?;
        if loaded.profiles.namespace() != self.profiles.namespace()
            || loaded.encode()? != self.encode()?
        {
            return Err(invalid("durable target mismatch"));
        }
        let file = if pending {
            StateFile::Pending
        } else {
            StateFile::Committed
        };
        let bytes = store.load(file)?.ok_or_else(|| invalid("missing target"))?;
        store.confirm_loaded(file, &bytes)?;
        Ok(DurableLinuxTarget {
            store,
            state: self,
            file,
            bytes,
        })
    }
}

#[cfg(all(target_os = "linux", feature = "linux-kernel"))]
impl DurableLinuxTarget<'_> {
    pub(crate) fn state(&self) -> &ControlState {
        self.state
    }

    pub(crate) fn confirm(&self) -> io::Result<()> {
        self.store.confirm_loaded(self.file, &self.bytes)?;
        let (loaded, _) = load(Platform::Linux, self.state.profiles.namespace(), self.store)?;
        if loaded.encode()? != self.state.encode()? {
            return Err(invalid("changed target"));
        }
        Ok(())
    }
}
