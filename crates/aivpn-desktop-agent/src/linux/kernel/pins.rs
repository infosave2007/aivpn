//! Закрепление ресурсов до публикации политик. При выходе службы защита остается в ядре.

use super::{BindingMode, KernelImage, UnpublishedKernel};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const GROUPS: &[&CStr] = &[c"maps", c"programs", c"links"];

unsafe extern "C" {
    fn bpf_obj_pin(descriptor: c_int, path: *const c_char) -> c_int;
    fn bpf_map_create(
        kind: c_uint,
        name: *const c_char,
        key: c_uint,
        value: c_uint,
        capacity: c_uint,
        options: *const c_void,
    ) -> c_int;
    fn bpf_map_update_elem(
        descriptor: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_freeze(descriptor: c_int) -> c_int;
}

/// Ресурсы закреплены, но маршруты, DNS и готовность VPN еще проверяются backend.
/// Закрытие этого владельца сохраняет pins. Повторный запуск должен проверить
/// существующие ресурсы, а не загружать поверх них новый пустой экземпляр.
pub struct PinnedKernel {
    _programs: UnpublishedKernel,
    _pins: PinTransaction,
}

pub(super) struct PinTransaction {
    base: File,
    directory: File,
    name: CString,
    files: Vec<CString>,
    committed: bool,
    journal: Option<super::installation::Journal>,
}

impl PinnedKernel {
    pub fn install_new(namespace: [u8; 16]) -> io::Result<Self> {
        Self::install_reserved(namespace, || Ok(())).map(|(kernel, ())| kernel)
    }

    pub(super) fn install_reserved<T>(
        namespace: [u8; 16],
        prepare: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<(Self, T)> {
        Self::install_reserved_mode(namespace, BindingMode::Legacy, prepare)
    }

    pub(super) fn install_reserved_mode<T>(
        namespace: [u8; 16],
        mode: BindingMode,
        prepare: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<(Self, T)> {
        // Резервируем namespace до load/attach: старые hooks могут занимать
        // ту же точку netfilter и должны восстанавливаться, а не заменяться.
        let mut pins = PinTransaction::create(namespace)?;
        let prepared = prepare()?;
        let programs = KernelImage::open_mode(mode)?
            .load()?
            .attach_pinned_root_hooks(&mut pins)?;
        pins.pin_metadata(namespace, mode)?;
        pins.committed = true;
        Ok((
            PinnedKernel {
                _programs: programs,
                _pins: pins,
            },
            prepared,
        ))
    }
}

impl PinTransaction {
    fn create(namespace: [u8; 16]) -> io::Result<Self> {
        super::hooks::require_system_namespaces()?;
        let base = open_base()?;
        let name = CString::new(
            namespace
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        // EEXIST сохраняет прежние ресурсы, включая незавершенную установку.
        create_directory(&base, &name)?;
        let directory = match open_directory_at(&base, &name) {
            Ok(directory) => directory,
            Err(error) => {
                unsafe { libc::unlinkat(base.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
                return Err(error);
            }
        };
        let pins = Self {
            base,
            directory,
            name,
            files: Vec::new(),
            committed: false,
            journal: None,
        };
        for group in GROUPS {
            create_directory(&pins.directory, group)?;
        }
        Ok(pins)
    }

    pub(super) fn pin(&mut self, group: &CStr, name: &CStr, descriptor: c_int) -> io::Result<()> {
        if !GROUPS.contains(&group)
            || name.to_bytes().is_empty()
            || !name
                .to_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let relative = CString::new([group.to_bytes(), b"/", name.to_bytes()].concat()).unwrap();
        self.pin_relative(relative, descriptor)
    }

    fn pin_relative(&mut self, relative: CString, descriptor: c_int) -> io::Result<()> {
        if let Some(journal) = &mut self.journal {
            journal.claim(&relative, descriptor)?;
        }
        let path = CString::new(format!(
            "/proc/thread-self/fd/{}/{}",
            self.directory.as_raw_fd(),
            relative.to_str().unwrap()
        ))
        .unwrap();
        if let Err(error) = super::image::result(unsafe { bpf_obj_pin(descriptor, path.as_ptr()) })
        {
            if let Some(journal) = &mut self.journal {
                journal.poison();
            }
            return Err(error);
        }
        // Успешно созданные имена принадлежат только этой транзакции.
        self.files.push(relative);
        if unsafe {
            libc::fchmodat(
                self.directory.as_raw_fd(),
                self.files.last().unwrap().as_ptr(),
                0o600,
                0,
            )
        } < 0
        {
            if let Some(journal) = &mut self.journal {
                journal.poison();
            }
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn pin_metadata(
        &mut self,
        namespace: [u8; 16],
        mode: BindingMode,
    ) -> io::Result<()> {
        let mut entries = BTreeMap::new();
        for name in &self.files {
            if !name.to_bytes().contains(&b'/') {
                continue;
            }
            let descriptor = super::objects::open_pin(&self.directory, name)?;
            entries.insert(name.clone(), super::objects::ObjectInfo::read(&descriptor)?);
        }
        let inventory = super::objects::inventory_digest(&entries)?;
        self.pin_frozen_array(c"inventory", &inventory)?;
        let mut metadata = [0u8; 64];
        metadata[..4].copy_from_slice(
            &(if mode == BindingMode::Snapshot {
                5u32
            } else {
                4u32
            })
            .to_ne_bytes(),
        );
        metadata[4..8].copy_from_slice(&mode.code().to_ne_bytes());
        metadata[8..24].copy_from_slice(&namespace);
        metadata[24..56].copy_from_slice(&Sha256::digest(mode.image()));
        // Наличие metadata подтверждает завершение pinning, но не готовность VPN.
        self.pin_frozen_array(c"metadata", &metadata)
    }

    pub(super) fn pin_frozen_array(&mut self, name: &CStr, value: &[u8]) -> io::Result<()> {
        if self.journal.is_some() && self.files.iter().any(|old| old == name) {
            let fd = super::objects::open_pin(&self.directory, name)?;
            let actual = match value.len() {
                32 => super::objects::read_array::<32>(&fd)?.to_vec(),
                64 => super::objects::read_array::<64>(&fd)?.to_vec(),
                _ => return Err(super::invalid_object()),
            };
            if actual != value {
                return Err(super::invalid_object());
            }
            return Ok(());
        }
        let descriptor =
            unsafe { bpf_map_create(2, name.as_ptr(), 4, value.len() as u32, 1, std::ptr::null()) };
        if descriptor < 0 {
            return Err(io::Error::from_raw_os_error(-descriptor));
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let zero = 0u32;
        super::image::result(unsafe {
            bpf_map_update_elem(
                descriptor.as_raw_fd(),
                (&zero as *const u32).cast(),
                value.as_ptr().cast(),
                0,
            )
        })?;
        super::image::result(unsafe { bpf_map_freeze(descriptor.as_raw_fd()) })?;
        self.pin_relative(name.to_owned(), descriptor.as_raw_fd())
    }
}

impl PinTransaction {
    pub(super) fn create_initializing(
        namespace: [u8; 16],
        journal: super::installation::Journal,
    ) -> io::Result<Self> {
        let mut pins = Self::create(namespace)?;
        pins.journal = Some(journal);
        // Durable reservation предшествует create; спорные ресурсы не удаляются Drop.
        pins.committed = true;
        Ok(pins)
    }
    pub(super) fn open_initializing(
        namespace: [u8; 16],
        journal: super::installation::Journal,
    ) -> io::Result<Self> {
        let base = open_base()?;
        let name = CString::new(
            namespace
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        let directory = open_directory_at(&base, &name)?;
        let files = journal
            .claim_names()
            .map(|name| CString::new(name.as_str()).map_err(|_| super::invalid_object()))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            base,
            directory,
            name,
            files,
            committed: true,
            journal: Some(journal),
        })
    }
    pub(super) fn directory(&self) -> &File {
        &self.directory
    }
    pub(super) fn journal(&self) -> io::Result<&super::installation::Journal> {
        self.journal.as_ref().ok_or_else(super::invalid_object)
    }
    pub(super) fn journal_mut(&mut self) -> io::Result<&mut super::installation::Journal> {
        self.journal.as_mut().ok_or_else(super::invalid_object)
    }
}

impl Drop for PinTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for name in self.files.iter().rev() {
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        }
        for group in GROUPS.iter().rev() {
            unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    group.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
        }
        unsafe {
            libc::unlinkat(
                self.base.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
    }
}

fn open_base() -> io::Result<File> {
    let parent = bpffs_root()?;
    let name = c"aivpn_app_routes";
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    open_directory_at(&parent, name)
}

pub(super) fn bpffs_root() -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/sys/fs/bpf")?;
    let host = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/proc/1/root/sys/fs/bpf")?;
    verify_permanent_root(&directory, &host)?;
    verify_bpffs(&host)?;
    // Все дальнейшие openat привязаны к mount основной системы. Частный mount
    // поверх дочернего каталога не должен перенаправлять pins службы.
    Ok(host)
}

fn verify_permanent_root(directory: &File, host: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    let host = host.metadata()?;
    if (metadata.dev(), metadata.ino()) != (host.dev(), host.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Pins должны сохраняться в bpffs основной системы",
        ));
    }
    if metadata.uid() != 0 || (metadata.mode() & 0o22 != 0 && metadata.mode() & 0o1000 == 0) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Корень bpffs доступен на запись другому владельцу",
        ));
    }
    Ok(())
}

fn verify_bpffs(directory: &File) -> io::Result<()> {
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if filesystem.f_type != libc::BPF_FS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Каталог pins должен находиться в bpffs",
        ));
    }
    Ok(())
}

fn create_directory(parent: &File, name: &CStr) -> io::Result<()> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn open_directory_at(parent: &File, name: &CStr) -> io::Result<File> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    verify_directory(&directory)?;
    Ok(directory)
}

fn verify_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Нужен закрытый каталог root с правами 0700",
        ));
    }
    Ok(())
}
