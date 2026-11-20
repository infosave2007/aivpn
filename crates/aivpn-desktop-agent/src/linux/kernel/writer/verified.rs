//! Проверенные ресурсы для будущего снимка. Подготовка не меняет routing maps.
use super::executable::{
    retention::{boot_digest, GroupEvidence, GroupRetention},
    VerifiedFile,
};
use super::KernelWriter;
use crate::bindings::BindingPlan;
use crate::linux::{ExecutableFile, LocatedExecutable, MountSnapshot};
use crate::slots::SlotKey;
use crate::state::{StateDirectory, StateFile, MAX_STATE_BYTES};
use aivpn_desktop_policy::{Authority, Owner, PolicyRegistry, ProfileCatalog, Selector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::num::NonZeroU32;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

mod cookie;
mod publication;
mod stage;
mod state;
pub(super) use state::Registry;
use state::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SelectorId(NonZeroU32);
impl SelectorId {
    pub fn get(self) -> u32 {
        self.0.get()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileGroupId(NonZeroU32);
impl FileGroupId {
    pub fn get(self) -> u32 {
        self.0.get()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingTxnId {
    instance: [u8; 32],
    number: u64,
}
impl BindingTxnId {
    pub fn get(self) -> u64 {
        self.number
    }
}

pub struct LinuxBindingRequest {
    instance: Instance,
    serial: u64,
    digest: [u8; 32],
    selected: Vec<Selected>,
    policies: Vec<Vec<u8>>,
}
impl LinuxBindingRequest {
    pub fn desired_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn desired_serial(&self) -> u64 {
        self.serial
    }
}

#[derive(Clone)]
pub struct VerifiedAlias {
    record: Alias,
}
impl VerifiedAlias {
    pub fn owner(&self) -> Owner {
        decode_owner(self.record.owner)
    }
    pub fn path(&self) -> &str {
        &self.record.path
    }
    pub fn selector(&self) -> SelectorId {
        SelectorId(NonZeroU32::new(self.record.selector).unwrap())
    }
    pub fn group(&self) -> FileGroupId {
        FileGroupId(NonZeroU32::new(self.record.group).unwrap())
    }
    pub fn negative_keys(&self) -> [[u64; 3]; 2] {
        self.record.keys
    }
    pub fn source_keys(&self) -> [[u64; 3]; 2] {
        self.record.source_keys
    }
    pub fn source_scope(&self) -> [u64; 4] {
        self.record.source_scope
    }
}
#[derive(Clone)]
pub struct VerifiedGroup {
    evidence: GroupEvidence,
}
impl VerifiedGroup {
    pub fn id(&self) -> FileGroupId {
        FileGroupId(NonZeroU32::new(self.evidence.slot).unwrap())
    }
    pub fn cookie(&self) -> u64 {
        self.evidence.cookie
    }
    pub fn link_id(&self) -> u32 {
        self.evidence.link
    }
    pub fn record_id(&self) -> u32 {
        self.evidence.record
    }
    pub fn record_digest(&self) -> [u8; 32] {
        self.evidence.digest
    }
    pub fn device_inode(&self) -> (u64, u64) {
        (self.evidence.device, self.evidence.inode)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMembership {
    owner: u64,
    selector: SelectorId,
    group: FileGroupId,
    accepted_serial: Option<u64>,
}
impl VerifiedMembership {
    pub fn owner(&self) -> Owner {
        decode_owner(self.owner)
    }
    pub fn selector(&self) -> SelectorId {
        self.selector
    }
    pub fn group(&self) -> FileGroupId {
        self.group
    }
    pub fn accepted_serial(&self) -> Option<u64> {
        self.accepted_serial
    }
}
pub struct VerifiedBindingSet {
    transaction: BindingTxnId,
    files: BTreeMap<String, VerifiedFile>,
}
impl VerifiedBindingSet {
    pub fn transaction(&self) -> BindingTxnId {
        self.transaction
    }
}

/// Закрытый artifact содержит точные текущие aliases, scoped memberships и pins.
/// Проверка desired/instance обязательна еще раз перед будущей активацией.
pub struct SealedBindingManifest {
    transaction: BindingTxnId,
    serial: u64,
    digest: [u8; 32],
    aliases: Vec<VerifiedAlias>,
    groups: Vec<VerifiedGroup>,
    memberships: Vec<VerifiedMembership>,
    policies: Vec<Vec<u8>>,
}
impl SealedBindingManifest {
    pub fn transaction(&self) -> BindingTxnId {
        self.transaction
    }
    pub fn desired_serial(&self) -> u64 {
        self.serial
    }
    pub fn desired_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn instance_digest(&self) -> [u8; 32] {
        self.transaction.instance
    }
    pub fn aliases(&self) -> &[VerifiedAlias] {
        &self.aliases
    }
    pub fn groups(&self) -> &[VerifiedGroup] {
        &self.groups
    }
    pub fn policies(&self) -> &[Vec<u8>] {
        &self.policies
    }
    pub fn memberships(&self) -> &[VerifiedMembership] {
        &self.memberships
    }
}
pub struct BindingRecovery {
    staged: Vec<BindingTxnId>,
}
impl BindingRecovery {
    pub fn staged(&self) -> &[BindingTxnId] {
        &self.staged
    }
}

impl KernelWriter {
    pub(in crate::linux::kernel) fn retirement_pins(
        &mut self,
    ) -> io::Result<Vec<super::super::retirement::Pin>> {
        self.check_owner()?;
        let mut pins = match &self.kernel {
            super::KernelResources::Snapshot(kernel) => {
                kernel.retirement_pins().map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("Проверка основных pins перед удалением: {error}"),
                    )
                })?
            }
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        pins.extend(
            self.with_registry(|writer, registry| registry.retirement_pins(writer))
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("Проверка pins привязок перед удалением: {error}"),
                    )
                })?,
        );
        Ok(pins)
    }

    /// Порядок блокировок службы: Control, slots, bindings. Последние два каталога
    /// разные; повторное открытие того же каталога отказывает на flock.
    pub fn open_verified_bindings(&mut self, store: StateDirectory) -> io::Result<()> {
        self.check_owner()?;
        if self.verified_store.is_some() {
            return Err(invalid());
        }
        if self.slots.grouped_mode() && store.load(StateFile::Committed)?.is_none() {
            return Err(invalid());
        }
        self.verified_store = Some(Registry::open(store, Instance::read(self)?)?);
        Ok(())
    }
    pub fn selected_executables(
        &mut self,
        registry: &PolicyRegistry,
        catalog: &ProfileCatalog,
        authority: &Authority,
        serial: u64,
    ) -> io::Result<LinuxBindingRequest> {
        self.with_registry(|writer, store| {
            store.ensure_recovered()?;
            validate_linux_inputs(registry, authority)?;
            let plan =
                BindingPlan::prepare_with(registry, catalog, authority, &mut writer.slots, true)?;
            let selected = select_aliases(writer, registry, &plan)?;
            let policies = plan
                .policies()
                .iter()
                .map(|p| p.to_native_bytes())
                .collect();
            let digest = desired_digest(registry, catalog)?;
            store.select(serial, digest)?;
            Ok(LinuxBindingRequest {
                instance: store.state.instance.clone(),
                serial,
                digest,
                selected,
                policies,
            })
        })
    }
    fn with_registry<T>(
        &mut self,
        operation: impl FnOnce(&mut Self, &mut Registry) -> io::Result<T>,
    ) -> io::Result<T> {
        self.check_owner()?;
        let mut registry = self.verified_store.take().ok_or_else(invalid)?;
        let result = operation(self, &mut registry);
        self.verified_store = Some(registry);
        result
    }
    pub fn recover_verified_bindings(&mut self) -> io::Result<BindingRecovery> {
        self.with_registry(|writer, registry| registry.recover(writer))
    }
    pub fn abort_unpublished(&mut self, transaction: BindingTxnId) -> io::Result<()> {
        self.with_registry(|writer, registry| registry.abort(writer, transaction))
    }
    pub fn resume_verified_bindings(
        &mut self,
        transaction: BindingTxnId,
    ) -> io::Result<VerifiedBindingSet> {
        self.with_registry(|writer, registry| {
            registry.ensure_recovered()?;
            let tx = registry.transaction(transaction)?;
            if !tx.staged {
                return Err(invalid());
            }
            let files = reopen_files(writer, tx)?;
            let set = VerifiedBindingSet { transaction, files };
            registry.verify_set(writer, &set)?;
            Ok(set)
        })
    }
    pub fn seal_for_publication(
        &mut self,
        set: &VerifiedBindingSet,
        desired_digest: [u8; 32],
    ) -> io::Result<SealedBindingManifest> {
        self.with_registry(|writer, registry| {
            registry.verify_set(writer, set)?;
            let tx = registry.transaction(set.transaction)?;
            if tx.digest != desired_digest {
                return Err(invalid());
            }
            Ok(SealedBindingManifest {
                transaction: set.transaction,
                serial: tx.serial,
                digest: tx.digest,
                aliases: tx
                    .aliases
                    .iter()
                    .cloned()
                    .map(|record| VerifiedAlias { record })
                    .collect(),
                groups: registry
                    .transaction_groups(tx)?
                    .into_iter()
                    .map(|evidence| VerifiedGroup { evidence })
                    .collect(),
                memberships: registry.memberships(tx),
                policies: tx.policies.clone(),
            })
        })
    }
    pub fn validate_sealed_bindings(
        &mut self,
        sealed: &SealedBindingManifest,
        request: &LinuxBindingRequest,
    ) -> io::Result<()> {
        self.with_registry(|writer, registry| {
            registry.check_request(request)?;
            let tx = registry.transaction(sealed.transaction)?;
            validate_sealed_contents(registry, sealed, request, tx)?;
            registry.verify_retained(writer, tx)
        })
    }
}

fn desired_digest(registry: &PolicyRegistry, catalog: &ProfileCatalog) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"linux-verified-bindings-v2");
    // Снимки содержат весь desired state, включая grants и назначения, без readiness.
    for bytes in [
        registry.store_metadata().map_err(io::Error::other)?,
        catalog.store_metadata().map_err(io::Error::other)?,
    ] {
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(digest.finalize().into())
}

fn encode_owner(owner: &Owner) -> io::Result<u64> {
    match owner {
        Owner::LinuxUser { uid } => Ok((1u64 << 32) | u64::from(*uid)),
        Owner::Machine {} => Ok(3u64 << 32),
        _ => Err(invalid()),
    }
}
fn decode_owner(owner: u64) -> Owner {
    if owner >> 32 == 1 {
        Owner::LinuxUser { uid: owner as u32 }
    } else {
        Owner::Machine {}
    }
}
fn invalid() -> io::Error {
    use io::ErrorKind::InvalidData;
    io::Error::new(InvalidData, "Недостоверный журнал привязок Linux")
}

fn select_aliases(
    writer: &KernelWriter,
    registry: &PolicyRegistry,
    plan: &BindingPlan,
) -> io::Result<Vec<Selected>> {
    let mut selected = BTreeSet::new();
    for policy in registry.policies() {
        let owner = encode_owner(&policy.document().owner)?;
        for rule in &policy.effective_document().rules {
            if let Selector::Executable { path } = &rule.application {
                selected.insert(Selected {
                    owner,
                    path: path.clone(),
                    selector: plan.executable_slot(&writer.slots, path)?.get(),
                });
            }
        }
    }
    Ok(selected.into_iter().collect())
}
fn reopen_files(
    writer: &KernelWriter,
    tx: &Transaction,
) -> io::Result<BTreeMap<String, VerifiedFile>> {
    let mounts = MountSnapshot::read_current()?;
    let mut files = BTreeMap::new();
    for alias in &tx.aliases {
        if !files.contains_key(&alias.path) {
            let file = mounts.locate(ExecutableFile::resolve_selected(Path::new(&alias.path))?)?;
            files.insert(alias.path.clone(), VerifiedFile::new(writer, file)?);
        }
    }
    Ok(files)
}
fn validate_sealed_contents(
    registry: &Registry,
    sealed: &SealedBindingManifest,
    request: &LinuxBindingRequest,
    tx: &Transaction,
) -> io::Result<()> {
    if !tx.staged || sealed.serial != request.serial || sealed.digest != request.digest {
        return Err(invalid());
    }
    validate_sealed_records(registry, sealed, tx)
}
fn validate_sealed_records(
    registry: &Registry,
    sealed: &SealedBindingManifest,
    tx: &Transaction,
) -> io::Result<()> {
    if sealed.policies != tx.policies
        || sealed
            .aliases
            .iter()
            .map(|a| &a.record)
            .ne(tx.aliases.iter())
    {
        return Err(invalid());
    }
    if sealed.memberships != registry.memberships(tx) {
        return Err(invalid());
    }
    let groups = registry.transaction_groups(tx)?;
    if sealed.groups.iter().map(|g| &g.evidence).ne(groups.iter()) {
        return Err(invalid());
    }
    Ok(())
}

pub(in crate::linux::kernel::writer) struct PreparedGroupExecutable<'a> {
    file: &'a VerifiedFile,
    instance: Instance,
    slot: NonZeroU32,
    cookie: std::num::NonZeroU64,
}
impl<'a> PreparedGroupExecutable<'a> {
    fn new(
        writer: &KernelWriter,
        instance: &Instance,
        group: &Group,
        file: &'a VerifiedFile,
    ) -> io::Result<Self> {
        let proof = Self {
            file,
            instance: instance.clone(),
            slot: NonZeroU32::new(group.slot).ok_or_else(invalid)?,
            cookie: std::num::NonZeroU64::new(group.cookie).ok_or_else(invalid)?,
        };
        proof.verify(writer)?;
        Ok(proof)
    }
    pub(in crate::linux::kernel::writer) fn verify(&self, writer: &KernelWriter) -> io::Result<()> {
        self.file.verify(writer)?;
        if Instance::read(writer)? != self.instance {
            return Err(invalid());
        }
        writer
            .slots
            .require_binding(&self.instance.key(self.cookie.get())?, self.slot)?;
        if cookie::acquire(writer, &self.file.executable)? != self.cookie.get() {
            return Err(invalid());
        }
        Ok(())
    }
    pub(in crate::linux::kernel::writer) fn file(&self) -> &VerifiedFile {
        self.file
    }
    pub(in crate::linux::kernel::writer) fn slot(&self) -> FileGroupId {
        FileGroupId(self.slot)
    }
    pub(in crate::linux::kernel::writer) fn cookie(&self) -> u64 {
        self.cookie.get()
    }
}

fn validate_linux_inputs(registry: &PolicyRegistry, authority: &Authority) -> io::Result<()> {
    encode_owner(&authority.user)?;
    for policy in registry.policies() {
        if policy.document().platform != aivpn_desktop_policy::Platform::Linux {
            return Err(invalid());
        }
        encode_owner(&policy.document().owner)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "snapshot/model_tests.rs"]
mod snapshot_model_tests;
