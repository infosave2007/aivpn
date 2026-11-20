//! Удаляются только незавершенные планы из собственной области имен.
use std::{ffi::CString, fs::File, io, os::fd::AsRawFd};

pub(super) struct Staging {
    prefix: String,
    legacy_prefix: String,
}
impl Staging {
    pub(super) fn new(kind: &str, namespace: [u8; 16]) -> Self {
        let namespace: String = namespace.iter().map(|byte| format!("{byte:02x}")).collect();
        Self {
            prefix: format!(".aivpn-{kind}-{namespace}-"),
            legacy_prefix: format!(".aivpn-{kind}-"),
        }
    }

    fn matches(prefix: &str, name: &str) -> bool {
        name.strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(".new"))
            .is_some_and(|suffix| {
                suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
            })
    }

    pub(super) fn accepts(&self, name: &str) -> bool {
        Self::matches(&self.prefix, name) || Self::matches(&self.legacy_prefix, name)
    }

    pub(super) fn clear(&self, directory: &File) -> io::Result<()> {
        let fd = directory.as_raw_fd();
        let mut changed = false;
        for (index, entry) in std::fs::read_dir(format!("/proc/self/fd/{fd}"))?.enumerate() {
            if index >= 65536 {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            let entry = entry?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !Self::matches(&self.prefix, &name) {
                continue;
            }
            let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidData)?;
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    fd,
                    name.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let metadata = unsafe { metadata.assume_init() };
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                || metadata.st_uid != unsafe { libc::geteuid() }
                || metadata.st_nlink != 1
                || metadata.st_mode & 0o022 != 0
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if unsafe { libc::unlinkat(fd, name.as_ptr(), 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            changed = true;
        }
        if changed {
            directory.sync_all()?;
        }
        Ok(())
    }

    // Планирование вызывается, только когда журнал еще не содержит готового плана.
    // Повтор apply читает прежний файл и не проходит через эту очистку.
    pub(super) fn prepare_name(&self, directory: &File) -> io::Result<CString> {
        self.clear(directory)?;
        let mut random = [0u8; 16];
        let count = unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) };
        if count != random.len() as isize {
            return Err(if count < 0 {
                io::Error::last_os_error()
            } else {
                io::ErrorKind::UnexpectedEof.into()
            });
        }
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(CString::new(format!("{}{suffix}.new", self.prefix)).unwrap())
    }
}
