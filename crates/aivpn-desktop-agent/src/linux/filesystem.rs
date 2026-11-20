//! Снимок mount namespace для привязки файла к физическому пути в BPF.

use super::ExecutableFile;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod mountinfo;
use mountinfo::{invalid_location, Mount};

const MAX_MOUNT_BYTES: u64 = 8 * 1024 * 1024;

pub struct MountSnapshot {
    namespace: Arc<Namespace>,
    mounts: BTreeMap<u64, Mount>,
}

pub struct LocatedExecutable {
    executable: ExecutableFile,
    namespace: Arc<Namespace>,
    filesystem_path: Vec<u8>,
    filesystem_device: u64,
    mount_id: u64,
    #[cfg(feature = "linux-kernel")]
    source: SourceLocation,
}

#[cfg(feature = "linux-kernel")]
struct SourceLocation {
    directory: File,
    canonical: PathBuf,
    mount_id: u64,
    filesystem_path: Vec<u8>,
    device: u64,
    scope: [u64; 4],
}

struct Namespace {
    namespace: File,
    root: File,
    table: File,
    valid: Mutex<bool>,
}

impl MountSnapshot {
    pub fn read_current() -> io::Result<Self> {
        let namespace = Arc::new(Namespace {
            namespace: File::open("/proc/thread-self/ns/mnt")?,
            root: File::open("/")?,
            table: File::open("/proc/thread-self/mountinfo")?,
            valid: Mutex::new(true),
        });
        namespace.verify()?;
        let mut bytes = Vec::new();
        (&namespace.table)
            .take(MAX_MOUNT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MOUNT_BYTES {
            return Err(invalid_location());
        }
        let mounts = mountinfo::parse(&bytes)?;
        namespace.verify()?;
        Ok(Self { namespace, mounts })
    }

    pub fn locate(&self, executable: ExecutableFile) -> io::Result<LocatedExecutable> {
        self.namespace.verify()?;
        executable.verify()?;
        let mount_id = mount_id(executable.as_fd())?;
        let mount = self.mounts.get(&mount_id).ok_or_else(invalid_location)?;
        let filesystem_path = mount.filesystem_path(executable.canonical_path())?;
        #[cfg(feature = "linux-kernel")]
        let source = self.source_location(&executable)?;
        let located = LocatedExecutable {
            executable,
            namespace: self.namespace.clone(),
            filesystem_path,
            filesystem_device: mount.device,
            mount_id,
            #[cfg(feature = "linux-kernel")]
            source,
        };
        located.verify()?;
        Ok(located)
    }

    #[cfg(feature = "linux-kernel")]
    fn source_location(&self, executable: &ExecutableFile) -> io::Result<SourceLocation> {
        let (directory, suffix) = executable.source_anchor()?;
        let canonical = descriptor_path(&directory)?;
        let id = mount_id(directory.as_fd())?;
        let mount = self.mounts.get(&id).ok_or_else(invalid_location)?;
        let mut path = mount.filesystem_path(&canonical)?;
        if !path.ends_with(b"/") {
            path.push(b'/');
        }
        path.extend_from_slice(&suffix);
        let root = self.namespace.root.metadata()?;
        let device = root.dev();
        let major = libc::major(device);
        let minor = libc::minor(device);
        if major >= 1 << 12 || minor >= 1 << 20 {
            return Err(invalid_location());
        }
        Ok(SourceLocation {
            directory,
            canonical,
            mount_id: id,
            filesystem_path: path,
            device: mount.device,
            scope: [
                self.namespace.namespace.metadata()?.ino(),
                (u64::from(major) << 20) | u64::from(minor),
                root.ino(),
                mount_id(self.namespace.root.as_fd())?,
            ],
        })
    }
}

#[cfg(feature = "linux-kernel")]
fn descriptor_path(file: &File) -> io::Result<PathBuf> {
    let path = std::fs::read_link(format!("/proc/thread-self/fd/{}", file.as_raw_fd()))?;
    if !path.is_absolute() || file.metadata()?.nlink() == 0 {
        return Err(invalid_location());
    }
    Ok(path)
}

impl LocatedExecutable {
    #[cfg(feature = "linux-kernel")]
    pub(crate) fn source_path(&self) -> &Path {
        self.executable.source_path()
    }

    pub fn canonical_path(&self) -> &Path {
        self.executable.canonical_path()
    }

    pub fn filesystem_path(&self) -> &[u8] {
        &self.filesystem_path
    }

    pub fn filesystem_device(&self) -> u64 {
        self.filesystem_device
    }

    #[cfg(feature = "linux-kernel")]
    pub(crate) fn source_filesystem_path(&self) -> &[u8] {
        &self.source.filesystem_path
    }

    #[cfg(feature = "linux-kernel")]
    pub(crate) fn source_device(&self) -> u64 {
        self.source.device
    }

    #[cfg(feature = "linux-kernel")]
    pub(crate) fn source_scope(&self) -> [u64; 4] {
        self.source.scope
    }

    pub fn verify(&self) -> io::Result<()> {
        self.namespace.verify()?;
        self.executable.verify()?;
        if mount_id(self.executable.as_fd())? != self.mount_id {
            return Err(invalid_location());
        }
        #[cfg(feature = "linux-kernel")]
        if mount_id(self.source.directory.as_fd())? != self.source.mount_id
            || descriptor_path(&self.source.directory)? != self.source.canonical
        {
            return Err(invalid_location());
        }
        self.namespace.verify()
    }
}

impl AsFd for LocatedExecutable {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.executable.as_fd()
    }
}

impl Namespace {
    fn verify(&self) -> io::Result<()> {
        // poll сбрасывает событие mountinfo. Снимок после первого события
        // остается непригодным и не восстанавливается следующим вызовом.
        let mut valid = self.valid.lock().map_err(|_| invalid_location())?;
        if !*valid {
            return Err(invalid_location());
        }
        let result = self.verify_current();
        if result.is_err() {
            *valid = false;
        }
        result
    }

    fn verify_current(&self) -> io::Result<()> {
        same_file(&self.namespace, Path::new("/proc/thread-self/ns/mnt"))?;
        same_file(&self.root, Path::new("/"))?;
        let mut event = libc::pollfd {
            fd: self.table.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if event.revents != 0 {
            return Err(invalid_location());
        }
        Ok(())
    }
}

fn same_file(held: &File, path: &Path) -> io::Result<()> {
    let current = File::open(path)?;
    let held_metadata = held.metadata()?;
    let current_metadata = current.metadata()?;
    if held_metadata.dev() != current_metadata.dev()
        || held_metadata.ino() != current_metadata.ino()
        || mount_id(held.as_fd())? != mount_id(current.as_fd())?
    {
        return Err(invalid_location());
    }
    Ok(())
}

pub(super) fn mount_id(descriptor: BorrowedFd<'_>) -> io::Result<u64> {
    let mut metadata = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let result = unsafe {
        libc::statx(
            descriptor.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            libc::STATX_MNT_ID,
            metadata.as_mut_ptr(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.stx_mask & libc::STATX_MNT_ID == 0 || metadata.stx_mnt_id == 0 {
        return Err(invalid_location());
    }
    Ok(metadata.stx_mnt_id)
}
