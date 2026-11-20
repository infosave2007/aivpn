//! Единственный журнал epoch, root swap и принятой истории привязок.
use super::super::snapshot::{
    compile::Bundle,
    schema::{Records, IDENTITY, META},
    storage,
};
use super::*;
use crate::control::DurableLinuxTarget;
use crate::linux::kernel::{
    objects::{open_pin, ObjectInfo},
    pins::{bpffs_root, open_directory_at},
};
use std::{
    ffi::{CStr, CString},
    fs::File,
    os::fd::{AsRawFd, OwnedFd},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    transaction: u64,
    serial: u64,
    digest: [u8; 32],
    aliases: Vec<Alias>,
    groups: Vec<GroupEvidence>,
    edges: Vec<History>,
    policies: Vec<Vec<u8>>,
}
impl Source {
    fn capture(registry: &Registry, tx: &Transaction) -> io::Result<Self> {
        Ok(Self {
            transaction: tx.id,
            serial: tx.serial,
            digest: tx.digest,
            aliases: tx.aliases.clone(),
            groups: registry.transaction_groups(tx)?,
            edges: registry
                .memberships(tx)
                .into_iter()
                .map(|edge| History {
                    owner: edge.owner,
                    selector: edge.selector.get(),
                    group: edge.group.get(),
                    accepted_serial: edge.accepted_serial.unwrap_or(0),
                })
                .collect(),
            policies: tx.policies.clone(),
        })
    }
    fn sealed(&self, registry: &Registry) -> io::Result<SealedBindingManifest> {
        let memberships = self
            .edges
            .iter()
            .map(|edge| {
                Ok(VerifiedMembership {
                    owner: edge.owner,
                    selector: SelectorId(NonZeroU32::new(edge.selector).ok_or_else(invalid)?),
                    group: FileGroupId(NonZeroU32::new(edge.group).ok_or_else(invalid)?),
                    accepted_serial: if edge.accepted_serial == 0 {
                        None
                    } else {
                        Some(edge.accepted_serial)
                    },
                })
            })
            .collect::<io::Result<_>>()?;
        Ok(SealedBindingManifest {
            transaction: registry.token(self.transaction),
            serial: self.serial,
            digest: self.digest,
            aliases: self
                .aliases
                .iter()
                .cloned()
                .map(|record| VerifiedAlias { record })
                .collect(),
            groups: self
                .groups
                .iter()
                .cloned()
                .map(|evidence| VerifiedGroup { evidence })
                .collect(),
            memberships,
            policies: self.policies.clone(),
        })
    }
    fn compile(&self, registry: &Registry, epoch: u64) -> io::Result<Bundle> {
        Bundle::compile_epoch(&self.sealed(registry)?, epoch)
    }
    fn verify_retained(&self, writer: &KernelWriter) -> io::Result<()> {
        for evidence in &self.groups {
            GroupRetention::verify(writer, evidence)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotRecord {
    epoch: u64,
    outer: u32,
    inner: u32,
    bundle: [u8; 32],
    records: usize,
    source: Source,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Preparing { candidate: SnapshotRecord },
    Intent { candidate: SnapshotRecord },
    CommittedCleanup { retiring: Option<SnapshotRecord> },
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Publication {
    high_water: u64,
    active: Option<SnapshotRecord>,
    previous: Option<SnapshotRecord>,
    operation: Option<Operation>,
}

/// Не сериализуется и создается только после actual root/readback и durable commit.
pub(crate) struct PublishedBindingSnapshot {
    epoch: u64,
    serial: u64,
    inner: u32,
    bundle: [u8; 32],
}
impl PublishedBindingSnapshot {
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn serial(&self) -> u64 {
        self.serial
    }
    pub(crate) fn map_id(&self) -> u32 {
        self.inner
    }
    pub(crate) fn bundle_digest(&self) -> [u8; 32] {
        self.bundle
    }
}

impl Publication {
    pub(super) fn unused(&self) -> bool {
        self.active.is_none() && self.previous.is_none() && self.operation.is_none()
    }
    pub(super) fn references(&self, transaction: u64) -> bool {
        self.records()
            .iter()
            .any(|record| record.source.transaction == transaction)
    }
    fn records(&self) -> Vec<&SnapshotRecord> {
        let mut result: Vec<_> = self.active.iter().chain(self.previous.iter()).collect();
        match &self.operation {
            Some(Operation::Preparing { candidate } | Operation::Intent { candidate }) => {
                result.push(candidate)
            }
            Some(Operation::CommittedCleanup {
                retiring: Some(retiring),
            }) => result.push(retiring),
            _ => {}
        }
        result
    }
    pub(super) fn validate(&self, state: &Manifest) -> io::Result<()> {
        let mut epochs = BTreeSet::new();
        let records = self.records();
        if records.len() > 3 || self.previous.is_some() && self.active.is_none() {
            return Err(invalid());
        }
        for record in records {
            if record.epoch == 0
                || record.epoch > self.high_water
                || record.outer == 0
                || !epochs.insert(record.epoch)
                || record.source.transaction == 0
                || record.source.transaction >= state.next
                || record.source.serial == 0
                || record.records > 397826
                || !state.transactions.iter().any(|tx| {
                    tx.id == record.source.transaction
                        && tx.serial == record.source.serial
                        && tx.digest == record.source.digest
                        && tx.aliases == record.source.aliases
                        && tx.policies == record.source.policies
                })
            {
                return Err(invalid());
            }
            for evidence in &record.source.groups {
                if !state
                    .groups
                    .iter()
                    .any(|group| group.evidence.as_ref() == Some(evidence) && !group.releasing)
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

impl KernelWriter {
    pub(crate) fn recover_durable_bindings(
        &mut self,
        target: &DurableLinuxTarget<'_>,
    ) -> io::Result<BindingRecovery> {
        target.confirm()?;
        self.with_registry(|writer, registry| {
            if let Err(error) = registry.recover_publication(writer) {
                registry.poisoned = true;
                return Err(error);
            }
            registry.recover(writer)
        })
    }
    pub(crate) fn publish_durable_bindings(
        &mut self,
        target: &DurableLinuxTarget<'_>,
        request: &LinuxBindingRequest,
        set: &VerifiedBindingSet,
    ) -> io::Result<PublishedBindingSnapshot> {
        target.confirm()?;
        if request.serial != target.state().serial()
            || request.instance.namespace != target.state().profiles().namespace()
            || request.digest
                != desired_digest(target.state().policies(), target.state().profiles())?
        {
            return Err(invalid());
        }
        self.with_registry(|writer, registry| {
            registry.check_request(request)?;
            registry.verify_set(writer, set)?;
            let source = Source::capture(registry, registry.transaction(set.transaction)?)?;
            registry.publish(writer, target, set, source)
        })
    }
}

impl Registry {
    pub(super) fn retirement_pins(
        &mut self,
        writer: &mut KernelWriter,
    ) -> io::Result<Vec<crate::linux::kernel::retirement::Pin>> {
        use crate::linux::kernel::retirement::{Base, Kind, Pin};
        self.recover_publication(writer)?;
        self.recover(writer)?;
        let namespace = self.state.instance.namespace;
        let mut pins = Vec::new();
        let mut expected_groups = std::collections::BTreeSet::new();
        let instance = map_id(writer.kernel.map(c"path_key")?)?;
        for group in &self.state.groups {
            let Some(evidence) = &group.evidence else {
                continue;
            };
            GroupRetention::verify(writer, evidence)?;
            let directory = format!("link_{:08x}", evidence.link);
            expected_groups.insert(CString::new(directory.as_str()).map_err(|_| invalid())?);
            for (name, kind, id) in [
                ("link", Kind::RetainerLink, evidence.link),
                ("record", Kind::Map, evidence.record),
                ("instance", Kind::Map, instance),
            ] {
                pins.push(Pin::capture(
                    Base::Groups,
                    namespace,
                    format!("{directory}/{name}"),
                    kind,
                    id,
                )?);
            }
        }
        let actual_groups: std::collections::BTreeSet<_> =
            GroupRetention::inventory(writer)?.into_iter().collect();
        if actual_groups != expected_groups {
            return Err(invalid());
        }
        let snapshots = SnapshotPins::open(namespace)?;
        let mut expected_snapshots = std::collections::BTreeSet::new();
        for record in self
            .state
            .publication
            .active
            .iter()
            .chain(self.state.publication.previous.iter())
        {
            self.verify_record(writer, &snapshots, record)?;
            let name = SnapshotPins::name(record);
            expected_snapshots.insert(name.clone());
            pins.push(Pin::capture(
                Base::Snapshots,
                namespace,
                name.to_str().map_err(|_| invalid())?.into(),
                Kind::Map,
                record.inner,
            )?);
        }
        let actual_snapshots = crate::linux::kernel::retirement::names(&snapshots.directory)?;
        if actual_snapshots != expected_snapshots {
            return Err(invalid());
        }
        Ok(pins)
    }

    fn publish(
        &mut self,
        writer: &mut KernelWriter,
        target: &DurableLinuxTarget<'_>,
        set: &VerifiedBindingSet,
        source: Source,
    ) -> io::Result<PublishedBindingSnapshot> {
        self.ensure_recovered()?;
        if self.state.publication.operation.is_some() {
            return Err(invalid());
        }
        let pins = SnapshotPins::open(writer.slots.namespace())?;
        self.verify_root(writer, &pins)?;
        if let Some(active) = &self.state.publication.active {
            let current = self.verify_record(writer, &pins, active)?;
            let proposed = source.compile(self, active.epoch)?;
            if active.source.serial == source.serial
                && active.source.digest == source.digest
                && active.source.aliases == source.aliases
                && active.source.groups == source.groups
                && equivalent(&current, &proposed.records)
            {
                target.confirm()?;
                let receipt = receipt(active);
                if active.source.transaction != set.transaction.number {
                    self.abort(writer, set.transaction)?;
                }
                return Ok(receipt);
            }
        }
        let epoch = self
            .state
            .publication
            .high_water
            .checked_add(1)
            .ok_or_else(invalid)?;
        let bundle = source.compile(self, epoch)?;
        let mut candidate = SnapshotRecord {
            epoch,
            outer: map_id(writer.kernel.map(c"binding_root")?)?,
            inner: 0,
            bundle: bundle.bundle_digest,
            records: bundle.records.len(),
            source,
        };
        self.state.publication.high_water = epoch;
        self.state.publication.operation = Some(Operation::Preparing {
            candidate: candidate.clone(),
        });
        self.persist()?;
        let result = self.prepare_and_swap(writer, target, set, &pins, &mut candidate, &bundle);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn prepare_and_swap(
        &mut self,
        writer: &mut KernelWriter,
        target: &DurableLinuxTarget<'_>,
        set: &VerifiedBindingSet,
        pins: &SnapshotPins,
        candidate: &mut SnapshotRecord,
        bundle: &Bundle,
    ) -> io::Result<PublishedBindingSnapshot> {
        let fd = storage::prepare(&bundle.records)?;
        candidate.inner = map_id(&fd)?;
        self.state.publication.operation = Some(Operation::Preparing {
            candidate: candidate.clone(),
        });
        self.persist()?;
        self.verify_set(writer, set)?;
        target.confirm()?;
        storage::freeze(&fd, &bundle.records)?;
        pins.pin(candidate, &fd)?;
        self.verify_record(writer, pins, candidate)?;
        // Проверяем размер и все ограничения будущего atomic commit до swap.
        let final_state = self.committed_state(candidate)?;
        let bytes = serde_json::to_vec(&final_state).map_err(io::Error::other)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid());
        }
        self.state.publication.operation = Some(Operation::Intent {
            candidate: candidate.clone(),
        });
        self.persist()?;
        target.confirm()?;
        self.verify_set(writer, set)?;
        let zero = 0u32;
        let descriptor = fd.as_raw_fd();
        result(unsafe {
            super::super::bpf_map_update_elem(
                writer.kernel.map(c"binding_root")?.as_raw_fd(),
                (&zero as *const u32).cast(),
                (&descriptor as *const i32).cast(),
                0,
            )
        })?;
        self.require_active(writer, pins, candidate)?;
        self.state = final_state;
        self.persist()?;
        self.finish_cleanup(writer, pins)?;
        Ok(receipt(candidate))
    }
    fn committed_state(&self, candidate: &SnapshotRecord) -> io::Result<Manifest> {
        let mut state = self.state.clone();
        for evidence in &candidate.source.groups {
            state
                .groups
                .iter_mut()
                .find(|group| {
                    group.slot == evidence.slot && group.evidence.as_ref() == Some(evidence)
                })
                .ok_or_else(invalid)?
                .published = true;
        }
        for edge in &candidate.source.edges {
            if !state.history.iter().any(|existing| {
                (existing.owner, existing.selector, existing.group)
                    == (edge.owner, edge.selector, edge.group)
            }) {
                state.history.push(History {
                    owner: edge.owner,
                    selector: edge.selector,
                    group: edge.group,
                    accepted_serial: if edge.accepted_serial == 0 {
                        candidate.source.serial
                    } else {
                        edge.accepted_serial
                    },
                });
            }
        }
        state
            .history
            .sort_by_key(|edge| (edge.owner, edge.selector, edge.group));
        let retiring = state.publication.previous.take();
        state.publication.previous = state.publication.active.replace(candidate.clone());
        state.publication.operation = Some(Operation::CommittedCleanup { retiring });
        validate_header(&state)?;
        validate_groups(&state.groups)?;
        validate_transactions(&state)?;
        validate_history(&state)?;
        state.publication.validate(&state)?;
        Ok(state)
    }
    fn recover_publication(&mut self, writer: &mut KernelWriter) -> io::Result<()> {
        self.available()?;
        let pins = SnapshotPins::open(writer.slots.namespace())?;
        match self.state.publication.operation.clone() {
            Some(Operation::Preparing { candidate }) => {
                self.verify_root(writer, &pins)?;
                if let Some(fd) = pins.existing(&candidate)? {
                    if map_id(&fd)? != candidate.inner {
                        return Err(invalid());
                    }
                    self.verify_record(writer, &pins, &candidate)?;
                    pins.remove(&candidate)?;
                }
                self.state.publication.operation = None;
                self.persist()?;
                self.abort(writer, self.token(candidate.source.transaction))?;
            }
            Some(Operation::Intent { candidate }) => {
                let actual = current_id(writer)?;
                if actual == Some(candidate.inner) {
                    self.require_active(writer, &pins, &candidate)?;
                    self.state = self.committed_state(&candidate)?;
                    self.persist()?;
                    self.finish_cleanup(writer, &pins)?;
                } else {
                    self.verify_root(writer, &pins)?;
                    self.verify_record(writer, &pins, &candidate)?;
                    pins.remove(&candidate)?;
                    self.state.publication.operation = None;
                    self.persist()?;
                    self.abort(writer, self.token(candidate.source.transaction))?;
                }
            }
            Some(Operation::CommittedCleanup { .. }) => self.finish_cleanup(writer, &pins)?,
            None => self.verify_root(writer, &pins)?,
        }
        self.verify_root(writer, &pins)?;
        pins.verify_names(&self.state.publication)?;
        self.publication_checked = true;
        Ok(())
    }
    fn finish_cleanup(&mut self, writer: &KernelWriter, pins: &SnapshotPins) -> io::Result<()> {
        self.verify_root(writer, pins)?;
        if let Some(Operation::CommittedCleanup { retiring }) =
            self.state.publication.operation.clone()
        {
            let retired_transaction = retiring.as_ref().map(|record| record.source.transaction);
            if let Some(retiring) = retiring {
                if current_id(writer)? == Some(retiring.inner) {
                    return Err(invalid());
                }
                pins.remove(&retiring)?;
            }
            self.state.publication.operation = None;
            if let Some(transaction) = retired_transaction {
                if !self.state.publication.references(transaction) {
                    self.state.transactions.retain(|tx| tx.id != transaction);
                }
            }
            self.persist()?;
        }
        Ok(())
    }
    fn verify_root(&self, writer: &KernelWriter, pins: &SnapshotPins) -> io::Result<()> {
        match &self.state.publication.active {
            Some(active) => self.require_active(writer, pins, active),
            None if current_id(writer)?.is_none() => Ok(()),
            None => Err(invalid()),
        }
    }
    fn require_active(
        &self,
        writer: &KernelWriter,
        pins: &SnapshotPins,
        record: &SnapshotRecord,
    ) -> io::Result<()> {
        if current_id(writer)? != Some(record.inner) {
            return Err(invalid());
        }
        self.verify_record(writer, pins, record)?;
        Ok(())
    }
    fn verify_record(
        &self,
        writer: &KernelWriter,
        pins: &SnapshotPins,
        record: &SnapshotRecord,
    ) -> io::Result<Records> {
        if record.outer != map_id(writer.kernel.map(c"binding_root")?)? || record.inner == 0 {
            return Err(invalid());
        }
        record.source.verify_retained(writer)?;
        let fd = pins.existing(record)?.ok_or_else(invalid)?;
        if map_id(&fd)? != record.inner {
            return Err(invalid());
        }
        storage::require_frozen(&fd)?;
        let actual = storage::read_records(&fd)?;
        let expected = record.source.compile(self, record.epoch)?;
        if record.records != expected.records.len()
            || record.bundle != expected.bundle_digest
            || actual != expected.records
        {
            return Err(invalid());
        }
        Ok(actual)
    }
}

fn receipt(record: &SnapshotRecord) -> PublishedBindingSnapshot {
    PublishedBindingSnapshot {
        epoch: record.epoch,
        serial: record.source.serial,
        inner: record.inner,
        bundle: record.bundle,
    }
}
fn equivalent(left: &Records, right: &Records) -> bool {
    left.iter()
        .filter(|(key, _)| ![META, IDENTITY].contains(&key[0]))
        .eq(right
            .iter()
            .filter(|(key, _)| ![META, IDENTITY].contains(&key[0])))
}
fn map_id(fd: &OwnedFd) -> io::Result<u32> {
    Ok(ObjectInfo::read(fd)?.words[1])
}
fn current_id(writer: &KernelWriter) -> io::Result<Option<u32>> {
    match storage::active(writer.kernel.map(c"binding_root")?) {
        Ok(fd) => map_id(&fd).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn result(status: i32) -> io::Result<()> {
    crate::linux::kernel::image::result(status)
}

struct SnapshotPins {
    directory: File,
}
impl SnapshotPins {
    fn open(namespace: [u8; 16]) -> io::Result<Self> {
        let root = bpffs_root()?;
        mkdir(&root, c"aivpn_app_binding_snapshots")?;
        let base = open_directory_at(&root, c"aivpn_app_binding_snapshots")?;
        let name = CString::new(
            namespace
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        mkdir(&base, &name)?;
        Ok(Self {
            directory: open_directory_at(&base, &name)?,
        })
    }
    fn name(record: &SnapshotRecord) -> CString {
        CString::new(format!("snapshot_{:016x}", record.epoch)).unwrap()
    }
    fn existing(&self, record: &SnapshotRecord) -> io::Result<Option<OwnedFd>> {
        match open_pin(&self.directory, &Self::name(record)) {
            Ok(fd) => Ok(Some(fd)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn pin(&self, record: &SnapshotRecord, fd: &OwnedFd) -> io::Result<()> {
        unsafe extern "C" {
            fn bpf_obj_pin(fd: i32, path: *const i8) -> i32;
        }
        let name = Self::name(record);
        let path = CString::new(format!(
            "/proc/thread-self/fd/{}/{}",
            self.directory.as_raw_fd(),
            name.to_str().unwrap()
        ))
        .unwrap();
        result(unsafe { bpf_obj_pin(fd.as_raw_fd(), path.as_ptr()) })?;
        if unsafe { libc::fchmodat(self.directory.as_raw_fd(), name.as_ptr(), 0o600, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if map_id(&self.existing(record)?.ok_or_else(invalid)?)? != record.inner {
            return Err(invalid());
        }
        Ok(())
    }
    fn remove(&self, record: &SnapshotRecord) -> io::Result<()> {
        if let Some(fd) = self.existing(record)? {
            if map_id(&fd)? != record.inner {
                return Err(invalid());
            }
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), Self::name(record).as_ptr(), 0) }
                < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    fn verify_names(&self, state: &Publication) -> io::Result<()> {
        let expected: BTreeSet<_> = state
            .records()
            .into_iter()
            .filter(|r| r.inner != 0)
            .map(|r| Self::name(r).to_str().unwrap().to_owned())
            .collect();
        let actual: BTreeSet<_> = std::fs::read_dir(format!(
            "/proc/thread-self/fd/{}",
            self.directory.as_raw_fd()
        ))?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
        if expected != actual {
            return Err(invalid());
        }
        Ok(())
    }
}
fn mkdir(parent: &File, name: &CStr) -> io::Result<()> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
