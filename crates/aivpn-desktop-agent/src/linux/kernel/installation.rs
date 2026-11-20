//! Захват процессов до сетевых consumers. Журнал удерживает спорные pins при отказе.
use super::{
    image::result,
    invalid_object,
    objects::{inventory_digest, open_pin, read_array, ObjectInfo},
    pins::PinTransaction,
    BindingMode, KernelImage,
};
use crate::state::{StateDirectory, StateFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};

const CAPTURE: &[&CStr] = &[
    c"release_lookup_task",
    c"lookup_file_free",
    c"lookup_fs_free",
    c"lookup_context_sys_exit",
    c"lookup_fdget",
    c"lookup_socket_clone",
    c"lookup_exec_open",
    c"lookup_walk_begin",
    c"lookup_directory_begin",
    c"lookup_directory_walk",
    c"lookup_directory_end",
    c"lookup_pwd_begin",
    c"lookup_pwd_end",
    c"lookup_root_begin",
    c"lookup_root_end",
    c"lookup_fs_copy_begin",
    c"lookup_fs_copy_end",
    c"lookup_walk_segment",
    c"lookup_fast_component",
    c"lookup_open_component",
    c"lookup_follow_link",
    c"lookup_magic_link",
    c"lookup_walk_end",
    c"lookup_exec_opened",
    c"lookup_exec_finished",
    c"prepare_socket",
    c"inherit_process",
    c"capture_exec_begin",
    c"classify_exec",
    c"prepare_connect",
    c"observe_owner",
];

#[derive(Clone, Copy)]
enum Role {
    Trace,
    SysExit,
    FdSession,
    Cgroup(u32),
    Netfilter(u32, u32, i32),
}
#[derive(Clone, Copy)]
struct Hook {
    name: &'static CStr,
    role: Role,
}

fn hooks() -> Vec<Hook> {
    let mut hooks: Vec<_> = CAPTURE
        .iter()
        .map(|&name| Hook {
            name,
            role: if name == c"lookup_fdget" {
                Role::FdSession
            } else if name == c"lookup_context_sys_exit" {
                Role::SysExit
            } else {
                Role::Trace
            },
        })
        .collect();
    for name in [
        c"record_udp_reuse",
        c"route_clone",
        c"route_request",
        c"route_mptcp_prepare_listener",
        c"route_mptcp_epoch",
        c"route_before_send",
        c"route_free",
        c"route_request_free",
        c"forget_connection",
        c"route_mptcp_listen",
        c"route_mptcp_listen_done",
        c"prepare_packet_dispatch",
    ] {
        hooks.push(Hook {
            name,
            role: Role::Trace,
        });
    }
    for (index, name) in [
        c"route_socket",
        c"route_connect4",
        c"route_connect6",
        c"route_send4",
        c"route_send6",
        c"guard_output",
        c"record_incoming_datagram",
    ]
    .into_iter()
    .enumerate()
    {
        hooks.push(Hook {
            name,
            role: Role::Cgroup(index as u32),
        });
    }
    for (name, hook, priority) in [
        (c"guard_profile_input", 0, -150),
        (c"guard_profile_forward", 2, -150),
        (c"guard_marked_output", 4, i32::MAX - 2),
        (c"guard_final_output", 4, i32::MAX - 1),
        (c"ensure_local_dispatch", 3, 0),
    ] {
        for family in [libc::AF_INET as u32, libc::AF_INET6 as u32] {
            hooks.push(Hook {
                name,
                role: Role::Netfilter(family, hook, priority),
            });
        }
    }
    hooks
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Reserved,
    Loading,
    CaptureReady,
    NetworkAttaching,
    Completed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    namespace: [u8; 16],
    boot: String,
    image: [u8; 32],
    phase: Phase,
    claims: BTreeMap<String, Vec<u32>>,
    core: Option<[u8; 32]>,
}

pub(super) struct Journal {
    store: StateDirectory,
    record: Record,
    poisoned: bool,
}
impl Journal {
    pub(super) fn claim_names(&self) -> impl Iterator<Item = &String> {
        self.record.claims.keys()
    }
    pub(super) fn reserve(store: StateDirectory, namespace: [u8; 16]) -> io::Result<Self> {
        if store.load(StateFile::Committed)?.is_some() || store.load(StateFile::Pending)?.is_some()
        {
            return Err(invalid_object());
        }
        let mut journal = Self {
            store,
            record: Record {
                version: 1,
                namespace,
                boot: boot()?,
                image: Sha256::digest(BindingMode::Snapshot.image()).into(),
                phase: Phase::Reserved,
                claims: BTreeMap::new(),
                core: None,
            },
            poisoned: false,
        };
        journal.persist()?;
        Ok(journal)
    }
    pub(super) fn open(store: StateDirectory, namespace: [u8; 16]) -> io::Result<Self> {
        let bytes = store
            .load(StateFile::Committed)?
            .ok_or_else(invalid_object)?;
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| invalid_object())?;
        if record.version != 1
            || record.namespace != namespace
            || record.boot != boot()?
            || record.image != <[u8; 32]>::from(Sha256::digest(BindingMode::Snapshot.image()))
            || store.load(StateFile::Pending)?.is_some()
        {
            return Err(invalid_object());
        }
        store.confirm_loaded(StateFile::Committed, &bytes)?;
        Ok(Self {
            store,
            record,
            poisoned: false,
        })
    }
    fn persist(&mut self) -> io::Result<()> {
        self.available()?;
        let bytes = serde_json::to_vec(&self.record).map_err(io::Error::other)?;
        if let Err(error) = self.store.replace(StateFile::Committed, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn available(&self) -> io::Result<()> {
        crate::slots::require_unpoisoned(self.poisoned)
    }
    pub(super) fn claim(&mut self, name: &CStr, descriptor: i32) -> io::Result<()> {
        self.available()?;
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(descriptor) };
        let info = ObjectInfo::read(&fd)?;
        let value = fingerprint(name, &info)?;
        if self
            .record
            .claims
            .insert(name.to_str().map_err(|_| invalid_object())?.into(), value)
            .is_some()
        {
            self.poisoned = true;
            return Err(invalid_object());
        }
        self.persist()
    }
    fn phase(&mut self, phase: Phase) -> io::Result<()> {
        self.record.phase = phase;
        self.persist()
    }
    pub(super) fn poison(&mut self) {
        self.poisoned = true;
    }
}

/// Полный core доказан, но сетевые consumers еще могут отсутствовать.
pub struct CorePhaseProof {
    digest: [u8; 32],
}
impl CorePhaseProof {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
/// Доказывает actual attachments; не заменяет durable publication, DNS или readiness.
pub struct FinalAttachmentReceipt {
    core: [u8; 32],
    inventory: [u8; 32],
}
impl FinalAttachmentReceipt {
    pub fn core_digest(&self) -> [u8; 32] {
        self.core
    }
    pub fn inventory_digest(&self) -> [u8; 32] {
        self.inventory
    }
}

pub struct InitializingKernel {
    pins: PinTransaction,
    resources: BTreeMap<CString, OwnedFd>,
    core: [u8; 32],
}
impl InitializingKernel {
    pub(super) fn retirement_pins(&self) -> io::Result<Vec<super::retirement::Pin>> {
        use super::retirement::{Base, Kind, Pin};
        let journal = self.pins.journal()?;
        journal.available()?;
        if journal.record.phase != Phase::Completed {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut pins = Vec::new();
        for (name, expected) in &journal.record.claims {
            let relative = CString::new(name.as_str()).map_err(|_| invalid_object())?;
            let info = ObjectInfo::read(&open_pin(self.pins.directory(), &relative)?)?;
            if fingerprint(&relative, &info)? != *expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Изменена идентичность pin {name}"),
                ));
            }
            let kind = if name.starts_with("links/") {
                Kind::RootLink
            } else if name.starts_with("programs/") {
                Kind::Program
            } else {
                Kind::Map
            };
            pins.push(Pin::capture(
                Base::Routes,
                journal.record.namespace,
                name.clone(),
                kind,
                info.words[1],
            )?);
        }
        Ok(pins)
    }

    pub(super) fn create(namespace: [u8; 16], store: StateDirectory) -> io::Result<Self> {
        let journal = Journal::reserve(store, namespace)?;
        let mut pins = PinTransaction::create_initializing(namespace, journal)?;
        pins.journal_mut()?.phase(Phase::Loading)?;
        let loaded = KernelImage::open_mode(BindingMode::Snapshot)?.load()?;
        loaded.pin_resources(&mut pins)?;
        let mut kernel = Self {
            pins,
            resources: BTreeMap::new(),
            core: [0; 32],
        };
        kernel.read_resources(0)?;
        kernel.attach_range(0, CAPTURE.len())?;
        kernel.read_resources(CAPTURE.len())?;
        kernel.core = kernel.resources_digest(true)?;
        kernel
            .pins
            .pin_frozen_array(c"core_inventory", &kernel.core)?;
        kernel.pins.journal_mut()?.record.core = Some(kernel.core);
        kernel.pins.journal_mut()?.phase(Phase::CaptureReady)?;
        kernel.verify_claims()?;
        kernel.verify_phase()?;
        Ok(kernel)
    }
    pub(super) fn open(namespace: [u8; 16], store: StateDirectory) -> io::Result<Self> {
        let journal = Journal::open(store, namespace)?;
        if !matches!(
            journal.record.phase,
            Phase::CaptureReady | Phase::NetworkAttaching | Phase::Completed
        ) {
            return Err(io::Error::other(
                "Незавершенная загрузка сохранена для восстановления",
            ));
        }
        let core = journal.record.core.ok_or_else(invalid_object)?;
        let pins = PinTransaction::open_initializing(namespace, journal)?;
        let mut kernel = Self {
            pins,
            resources: BTreeMap::new(),
            core,
        };
        kernel.verify_claims()?;
        let count = kernel
            .pins
            .journal_mut()?
            .record
            .claims
            .keys()
            .filter(|name| name.starts_with("links/"))
            .count();
        if count < CAPTURE.len() || count > hooks().len() {
            return Err(invalid_object());
        }
        kernel.read_resources(count)?;
        kernel.verify_phase()?;
        if kernel.resources_digest(true)? != core
            || read_array::<32>(&open_pin(kernel.pins.directory(), c"core_inventory")?)? != core
        {
            return Err(invalid_object());
        }
        Ok(kernel)
    }
    pub fn core_proof(&self) -> CorePhaseProof {
        CorePhaseProof { digest: self.core }
    }
    pub(super) fn available(&self) -> io::Result<()> {
        self.pins.journal()?.available()
    }
    pub(super) fn map(&self, name: &CStr) -> io::Result<&OwnedFd> {
        self.resource(c"maps", name)
    }
    pub(super) fn program(&self, name: &CStr) -> io::Result<&OwnedFd> {
        self.resource(c"programs", name)
    }
    fn resource(&self, group: &CStr, name: &CStr) -> io::Result<&OwnedFd> {
        self.resources
            .get(&qualified(group, name))
            .ok_or_else(invalid_object)
    }
    pub(super) fn complete(&mut self) -> io::Result<FinalAttachmentReceipt> {
        self.available()?;
        super::writer::snapshot::verify_active_root(self.map(c"binding_root")?)?;
        let current = self
            .resources
            .keys()
            .filter(|name| name.to_bytes().starts_with(b"links/"))
            .count();
        if self.pins.journal()?.record.phase != Phase::Completed {
            self.pins.journal_mut()?.phase(Phase::NetworkAttaching)?;
            if let Err(error) = self.attach_range(current, hooks().len()) {
                self.pins.journal_mut()?.poison();
                return Err(error);
            }
            self.read_resources(hooks().len())?;
            if self.resources_digest(true)? != self.core {
                self.pins.journal_mut()?.poison();
                return Err(invalid_object());
            }
            self.pins
                .pin_metadata(self.pins.journal()?.record.namespace, BindingMode::Snapshot)?;
            self.pins.journal_mut()?.phase(Phase::Completed)?;
        }
        self.verify_claims()?;
        self.verify_phase()?;
        let inventory = self.resources_digest(false)?;
        if read_array::<32>(&open_pin(self.pins.directory(), c"inventory")?)? != inventory {
            return Err(invalid_object());
        }
        Ok(FinalAttachmentReceipt {
            core: self.core,
            inventory,
        })
    }
    fn attach_range(&mut self, start: usize, end: usize) -> io::Result<()> {
        let cgroup = super::hooks::system_cgroup()?;
        for (index, hook) in hooks().iter().enumerate().take(end).skip(start) {
            let raw = hook.attach(self.program(hook.name)?.as_raw_fd(), cgroup.as_raw_fd());
            if raw < 0 {
                return Err(io::Error::from_raw_os_error(-raw));
            }
            let link = unsafe { OwnedFd::from_raw_fd(raw) };
            let name = CString::new(format!("root_{index:02}")).unwrap();
            self.pins.pin(c"links", &name, link.as_raw_fd())?;
        }
        Ok(())
    }
    fn read_resources(&mut self, count: usize) -> io::Result<()> {
        let expected = KernelImage::open_mode(BindingMode::Snapshot)?.expected_inventory()?;
        let mut resources = BTreeMap::new();
        for map in expected.maps {
            let name = qualified(c"maps", &map.name);
            let fd = open_pin(self.pins.directory(), &name)?;
            if ObjectInfo::read(&fd)?.map_shape() != map.shape {
                return Err(invalid_object());
            }
            resources.insert(name, fd);
        }
        for program in expected.programs {
            let name = qualified(c"programs", &program.name);
            let fd = open_pin(self.pins.directory(), &name)?;
            if ObjectInfo::read(&fd)?.words[0] != program.kind {
                return Err(invalid_object());
            }
            resources.insert(name, fd);
        }
        let cgroup = super::hooks::system_cgroup()?.metadata()?.ino();
        for (index, hook) in hooks().into_iter().take(count).enumerate() {
            let name = CString::new(format!("links/root_{index:02}")).unwrap();
            let fd = open_pin(self.pins.directory(), &name)?;
            let program = ObjectInfo::read(
                resources
                    .get(&qualified(c"programs", hook.name))
                    .ok_or_else(invalid_object)?,
            )?
            .words[1];
            hook.verify(fd.as_raw_fd(), program, cgroup)?;
            resources.insert(name, fd);
        }
        self.resources = resources;
        Ok(())
    }
    fn resources_digest(&self, core: bool) -> io::Result<[u8; 32]> {
        let mut info = BTreeMap::new();
        let first_consumer = format!("links/root_{:02}", CAPTURE.len());
        for (name, fd) in &self.resources {
            if core
                && name.to_bytes().starts_with(b"links/")
                && name.to_bytes() >= first_consumer.as_bytes()
            {
                continue;
            }
            info.insert(name.clone(), ObjectInfo::read(fd)?);
        }
        let inventory = inventory_digest(&info)?;
        if !core {
            return Ok(inventory);
        }
        let record = &self.pins.journal()?.record;
        let mut digest = Sha256::new();
        digest.update(b"linux-capture-core-v1");
        digest.update(record.namespace);
        digest.update(record.boot.as_bytes());
        digest.update(record.image);
        digest.update(inventory);
        Ok(digest.finalize().into())
    }
    fn verify_phase(&self) -> io::Result<()> {
        let record = &self.pins.journal()?.record;
        let count = self
            .resources
            .keys()
            .filter(|name| name.to_bytes().starts_with(b"links/"))
            .count();
        if (record.phase == Phase::CaptureReady && count != CAPTURE.len())
            || (record.phase == Phase::Completed && count != hooks().len())
        {
            return Err(invalid_object());
        }
        let names: std::collections::BTreeSet<_> = record
            .claims
            .keys()
            .filter(|name| name.contains('/'))
            .map(|name| name.as_bytes())
            .collect();
        let expected: std::collections::BTreeSet<_> =
            self.resources.keys().map(|name| name.to_bytes()).collect();
        if names != expected {
            return Err(invalid_object());
        }
        for name in record.claims.keys().filter(|name| !name.contains('/')) {
            if name != "core_inventory"
                && (record.phase == Phase::CaptureReady
                    || !["metadata", "inventory"].contains(&name.as_str()))
            {
                return Err(invalid_object());
            }
        }
        if record.phase == Phase::Completed || record.claims.contains_key("inventory") {
            if count != hooks().len()
                || read_array::<32>(&open_pin(self.pins.directory(), c"inventory")?)?
                    != self.resources_digest(false)?
            {
                return Err(invalid_object());
            }
        }
        if record.phase == Phase::Completed || record.claims.contains_key("metadata") {
            let bytes = read_array::<64>(&open_pin(self.pins.directory(), c"metadata")?)?;
            let mut expected = [0u8; 64];
            expected[..4].copy_from_slice(&5u32.to_ne_bytes());
            expected[4..8].copy_from_slice(&BindingMode::Snapshot.code().to_ne_bytes());
            expected[8..24].copy_from_slice(&record.namespace);
            expected[24..56].copy_from_slice(&record.image);
            if bytes != expected {
                return Err(invalid_object());
            }
        }
        Ok(())
    }
    fn verify_claims(&self) -> io::Result<()> {
        let journal = self.pins.journal()?;
        for (name, expected) in &journal.record.claims {
            let name = CString::new(name.as_str()).map_err(|_| invalid_object())?;
            let fd = open_pin(self.pins.directory(), &name)?;
            if &fingerprint(&name, &ObjectInfo::read(&fd)?)? != expected {
                return Err(invalid_object());
            }
        }
        super::recovery::require_claim_names(self.pins.directory(), journal.record.claims.keys())
    }
}

unsafe extern "C" {
    fn ar_attach_capture(program: i32) -> i32;
    fn ar_attach_fd_session(program: i32) -> i32;
    fn ar_attach_cgroup(program: i32, cgroup: i32, role: u32) -> i32;
    fn ar_attach_netfilter(program: i32, family: u32, hook: u32, priority: i32) -> i32;
    fn ar_verify_root_link(
        link: i32,
        program: u32,
        kind: i32,
        arg: u32,
        family: u32,
        hook: u32,
        priority: i32,
        cgroup: u64,
    ) -> i32;
}
impl Hook {
    fn attach(self, program: i32, cgroup: i32) -> i32 {
        unsafe {
            match self.role {
                Role::Trace | Role::SysExit => ar_attach_capture(program),
                Role::FdSession => ar_attach_fd_session(program),
                Role::Cgroup(role) => ar_attach_cgroup(program, cgroup, role),
                Role::Netfilter(family, hook, priority) => {
                    ar_attach_netfilter(program, family, hook, priority)
                }
            }
        }
    }
    fn verify(self, link: i32, program: u32, cgroup: u64) -> io::Result<()> {
        let (kind, arg, family, hook, priority) = match self.role {
            Role::Trace => (0, 0, 0, 0, 0),
            Role::SysExit => (4, 0, 0, 0, 0),
            Role::FdSession => (3, 0, 0, 0, 0),
            Role::Cgroup(role) => (1, role, 0, 0, 0),
            Role::Netfilter(f, h, p) => (2, 0, f, h, p),
        };
        result(unsafe {
            ar_verify_root_link(link, program, kind, arg, family, hook, priority, cgroup)
        })
    }
}
fn qualified(group: &CStr, name: &CStr) -> CString {
    CString::new([group.to_bytes(), b"/", name.to_bytes()].concat()).unwrap()
}
fn fingerprint(name: &CStr, info: &ObjectInfo) -> io::Result<Vec<u32>> {
    if name.to_bytes().contains(&b'/') {
        info.fingerprint(name)
    } else {
        Ok(info.words[..6].to_vec())
    }
}
fn boot() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
