//! Один владелец записи. Готовность сетевого пути и транзакции Control проверяются отдельно.

use super::image::result;
use super::{
    BindingMode, CorePhaseProof, FinalAttachmentReceipt, InitializingKernel, PinnedKernel,
    RecoveredKernel,
};
use crate::bindings::BindingPlan;
use crate::slots::{KernelSlotStore, KernelState};
use crate::state::StateDirectory;
use aivpn_desktop_policy::{Authority, KernelPolicy, Owner, PolicyRegistry, ProfileCatalog};
use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::AsRawFd;

mod dns;
mod executable;
pub use executable::{PinnedRetention, PreparedExecutable};
mod verified;
pub use verified::{
    BindingRecovery, BindingTxnId, FileGroupId, LinuxBindingRequest, SealedBindingManifest,
    SelectorId, VerifiedAlias, VerifiedBindingSet, VerifiedGroup, VerifiedMembership,
};

unsafe extern "C" {
    fn bpf_map_update_elem(
        descriptor: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_delete_elem(descriptor: c_int, key: *const c_void) -> c_int;
}

/// Каталог нумерации принадлежит только этому namespace и удерживает блокировку
/// единственного писателя. Backend использует один фиксированный каталог службы.
pub struct KernelWriter {
    kernel: KernelResources,
    slots: KernelSlotStore<StateDirectory>,
    owner_pid: u32,
    verified_store: Option<verified::Registry>,
}

enum KernelResources {
    Legacy(RecoveredKernel),
    Snapshot(InitializingKernel),
}
impl KernelResources {
    fn mode(&self) -> BindingMode {
        match self {
            Self::Legacy(kernel) => kernel.mode,
            Self::Snapshot(_) => BindingMode::Snapshot,
        }
    }
    fn map(&self, name: &std::ffi::CStr) -> io::Result<&std::os::fd::OwnedFd> {
        match self {
            Self::Legacy(kernel) => kernel.map(name),
            Self::Snapshot(kernel) => kernel.map(name),
        }
    }
    fn program(&self, name: &std::ffi::CStr) -> io::Result<&std::os::fd::OwnedFd> {
        match self {
            Self::Legacy(kernel) => kernel.program(name),
            Self::Snapshot(kernel) => kernel.program(name),
        }
    }
    fn identity_digest(&self) -> io::Result<[u8; 32]> {
        match self {
            Self::Legacy(kernel) => kernel.identity_digest(),
            Self::Snapshot(kernel) => Ok(kernel.core_proof().digest()),
        }
    }
}

impl KernelWriter {
    pub fn install_new(namespace: [u8; 16], store: StateDirectory) -> io::Result<Self> {
        Self::install_mode(namespace, store, BindingMode::Legacy)
    }

    /// Создает отдельный экземпляр Snapshot без активного корня и без readiness.
    pub fn install_new_snapshot(namespace: [u8; 16], store: StateDirectory) -> io::Result<Self> {
        super::hooks::require_system_namespaces()?;
        let journal = store.child(c"installation")?;
        let slots = KernelSlotStore::open(store, namespace, KernelState::Fresh)?;
        let kernel = InitializingKernel::create(namespace, journal)?;
        Ok(Self {
            kernel: KernelResources::Snapshot(kernel),
            slots,
            owner_pid: std::process::id(),
            verified_store: None,
        })
    }

    fn install_mode(
        namespace: [u8; 16],
        store: StateDirectory,
        mode: BindingMode,
    ) -> io::Result<Self> {
        super::hooks::require_system_namespaces()?;
        // Сначала доказываем отсутствие прежних pins, потом сохраняем счетчик,
        // затем загружаем hooks. Отказ новой установки не создает Fresh для старого ядра.
        let (kernel, slots) = PinnedKernel::install_reserved_mode(namespace, mode, || {
            KernelSlotStore::open(store, namespace, KernelState::Fresh)
        })?;
        drop(kernel);
        Self::adopt(namespace, slots, mode)
    }

    pub fn open_existing(namespace: [u8; 16], store: StateDirectory) -> io::Result<Self> {
        Self::open_mode(namespace, store, BindingMode::Legacy)
    }

    /// Проверяет прежний экземпляр Snapshot, не публикуя политики.
    pub fn open_existing_snapshot(namespace: [u8; 16], store: StateDirectory) -> io::Result<Self> {
        super::hooks::require_system_namespaces()?;
        let journal = store.child(c"installation")?;
        let slots = KernelSlotStore::open(store, namespace, KernelState::Existing)?;
        let kernel = InitializingKernel::open(namespace, journal)?;
        Ok(Self {
            kernel: KernelResources::Snapshot(kernel),
            slots,
            owner_pid: std::process::id(),
            verified_store: None,
        })
    }

    pub fn core_phase_proof(&self) -> io::Result<CorePhaseProof> {
        self.check_owner()?;
        match &self.kernel {
            KernelResources::Snapshot(kernel) => Ok(kernel.core_proof()),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }

    /// Требует настоящий frozen root. Receipt сообщает только проверенные attachments.
    pub fn complete_snapshot_installation(&mut self) -> io::Result<FinalAttachmentReceipt> {
        self.check_owner()?;
        match &mut self.kernel {
            KernelResources::Snapshot(kernel) => kernel.complete(),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }

    fn open_mode(
        namespace: [u8; 16],
        store: StateDirectory,
        mode: BindingMode,
    ) -> io::Result<Self> {
        super::hooks::require_system_namespaces()?;
        let slots = KernelSlotStore::open(store, namespace, KernelState::Existing)?;
        Self::adopt(namespace, slots, mode)
    }

    fn adopt(
        namespace: [u8; 16],
        slots: KernelSlotStore<StateDirectory>,
        mode: BindingMode,
    ) -> io::Result<Self> {
        Ok(Self {
            kernel: KernelResources::Legacy(RecoveredKernel::open_mode(namespace, mode)?),
            slots,
            owner_pid: std::process::id(),
            verified_store: None,
        })
    }

    pub fn prepare(
        &mut self,
        registry: &PolicyRegistry,
        catalog: &ProfileCatalog,
        authority: &Authority,
    ) -> io::Result<BindingPlan> {
        self.check_owner()?;
        BindingPlan::prepare(registry, catalog, authority, &mut self.slots)
    }

    /// Атомарно меняет одну политику. Служба сначала сохраняет журнал Control
    /// и проверяет привязки файлов, защиту, общий DNS и готовность маршрутов.
    /// Метод не подтверждает установку всей конфигурации backend.
    pub fn write_policy(&mut self, policy: &KernelPolicy) -> io::Result<()> {
        self.check_owner()?;
        let bytes = policy.to_native_bytes();
        let kind = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        let owner = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let key = linux_key(kind, owner)?;
        result(unsafe {
            bpf_map_update_elem(
                self.kernel.map(c"policies")?.as_raw_fd(),
                (&key as *const u64).cast(),
                bytes.as_ptr().cast(),
                0,
            )
        })
    }

    /// Решения уже принятых потоков остаются в socket storage и conntrack caches.
    pub fn withdraw_policy(&mut self, owner: &Owner) -> io::Result<()> {
        self.check_owner()?;
        let key = match owner {
            Owner::LinuxUser { uid } => linux_key(1, *uid)?,
            Owner::Machine {} => linux_key(3, 0)?,
            Owner::WindowsUser { .. } => return Err(unsupported_owner()),
        };
        let status = unsafe {
            bpf_map_delete_elem(
                self.kernel.map(c"policies")?.as_raw_fd(),
                (&key as *const u64).cast(),
            )
        };
        if status == -libc::ENOENT {
            return Ok(());
        }
        result(status)
    }

    fn check_owner(&self) -> io::Result<()> {
        if self.owner_pid != std::process::id() {
            // После fork отказ не выделяет память и предшествует другим операциям.
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.slots.ensure_available()?;
        if let KernelResources::Snapshot(kernel) = &self.kernel {
            kernel.available()?;
        }
        if let Some(registry) = &self.verified_store {
            registry.available()?;
        }
        super::hooks::require_system_namespaces()
    }
}

fn linux_key(kind: u32, owner: u32) -> io::Result<u64> {
    match kind {
        1 => Ok((1u64 << 32) | u64::from(owner)),
        3 if owner == 0 => Ok(3u64 << 32),
        _ => Err(unsupported_owner()),
    }
}

fn unsupported_owner() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Владелец не поддерживается Linux",
    )
}

pub(super) mod snapshot;
pub use snapshot::FrozenBindingSnapshot;
mod runtime;
pub(crate) use runtime::{ProfilePath, PROFILE_MARK_MASK};

mod maintenance;
pub(crate) use maintenance::CacheSweep;
