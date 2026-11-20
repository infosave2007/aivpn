//! Собственный файл провайдера появляется только после сохранения DNS intent.
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

const MAX_BYTES: usize = 65536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Value {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    parent: (u64, u64),
    value: Option<Value>,
    stage: Option<String>,
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.parent == other.parent && self.value == other.value
    }
}
impl Eq for Snapshot {}
impl Snapshot {
    pub(super) fn is_absent(&self) -> bool {
        self.value.is_none()
    }
}

pub(super) struct Dropin {
    directory: File,
    directory_path: &'static str,
    parent: (u64, u64),
    name: CString,
    staging: super::staging::Staging,
}
impl Dropin {
    pub(super) fn open(
        namespace: [u8; 16],
        directory_path: &'static str,
        provider: &'static str,
    ) -> io::Result<Self> {
        let directory = directory(directory_path, true)?;
        let metadata = directory.metadata()?;
        let suffix: String = namespace.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            directory,
            directory_path,
            parent: (metadata.dev(), metadata.ino()),
            name: CString::new(format!("zz-aivpn-{suffix}.conf")).unwrap(),
            staging: super::staging::Staging::new(provider, namespace),
        })
    }
    fn check_parent(&self) -> io::Result<()> {
        let current = directory(self.directory_path, false)?.metadata()?;
        if (current.dev(), current.ino()) != self.parent {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(())
    }
    fn read(&self, name: &CString, stage: Option<String>) -> io::Result<Snapshot> {
        self.check_parent()?;
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(Snapshot {
                    parent: self.parent,
                    value: None,
                    stage,
                })
            } else {
                Err(error)
            };
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != 0
            || before.mode() & 0o022 != 0
            || before.nlink() != 1
            || before.len() > MAX_BYTES as u64
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() > MAX_BYTES
            || (
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            )
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(Snapshot {
            parent: self.parent,
            value: Some(Value {
                device: before.dev(),
                inode: before.ino(),
                uid: before.uid(),
                gid: before.gid(),
                mode: before.mode() & 0o7777,
                mtime: before.mtime(),
                mtime_nsec: before.mtime_nsec(),
                bytes,
            }),
            stage,
        })
    }
    pub(super) fn snapshot(&self) -> io::Result<Snapshot> {
        self.read(&self.name, None)
    }
    pub(super) fn cleanup_restored(&self) -> io::Result<()> {
        self.check_parent()?;
        self.staging.clear(&self.directory)
    }
    pub(super) fn plan(&self, bytes: &[u8]) -> io::Result<Snapshot> {
        if bytes.len() > MAX_BYTES {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.check_parent()?;
        let name = self.staging.prepare_name(&self.directory)?;
        let stage = name
            .to_str()
            .map_err(|_| io::ErrorKind::InvalidData)?
            .to_owned();
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o644,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let result = (|| {
            file.write_all(bytes)?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } < 0 {
                return Err(io::Error::last_os_error());
            }
            file.sync_all()?;
            let snapshot = self.read(&name, Some(stage))?;
            if snapshot
                .value
                .as_ref()
                .is_none_or(|value| value.bytes != bytes)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.directory.sync_all()?;
            Ok(snapshot)
        })();
        if result.is_err() {
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        }
        result
    }
    pub(super) fn apply(&self, before: &Snapshot, after: &Snapshot) -> io::Result<()> {
        if self.snapshot()? != *before || after.parent != self.parent {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if before == after {
            return Ok(());
        }
        if after.value.is_some() {
            let stage = after.stage.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            if !self.staging.accepts(stage) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let stage = CString::new(stage.as_str()).map_err(|_| io::ErrorKind::InvalidData)?;
            if self.read(&stage, after.stage.clone())? != *after || self.snapshot()? != *before {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let flags = if before.value.is_none() {
                libc::RENAME_NOREPLACE
            } else {
                0
            };
            if unsafe {
                libc::renameat2(
                    self.directory.as_raw_fd(),
                    stage.as_ptr(),
                    self.directory.as_raw_fd(),
                    self.name.as_ptr(),
                    flags,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        } else if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.directory.sync_all()?;
        if self.snapshot()? != *after {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}

fn directory(path: &str, create: bool) -> io::Result<File> {
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")?;
    for part in path.split('/').filter(|part| !part.is_empty()) {
        let name = CString::new(part).unwrap();
        let mut created = false;
        let mut raw = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o755) } < 0 {
                return Err(io::Error::last_os_error());
            }
            created = true;
            current.sync_all()?;
            raw = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
        }
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        current = unsafe { File::from_raw_fd(raw) };
        // Служба работает с umask 0077, а resolved читает конфигурацию со своим UID.
        if created && unsafe { libc::fchmod(current.as_raw_fd(), 0o755) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = current.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(current)
}
