use super::{StateFile, MAX_STATE_BYTES};
use crate::control::ControlStore;
use std::ffi::CStr;
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

impl StateFile {
    fn names(self) -> (&'static CStr, &'static CStr) {
        match self {
            Self::Committed => (c"state.json", c".new-state.json"),
            Self::Pending => (c"pending.json", c".new-pending.json"),
            Self::DnsJournal => (c"dns-journal.json", c".new-dns-journal.json"),
        }
    }
}

/// Каталог заранее создается с правами 0700. Служба открывает его от root.
/// Все дальнейшие операции привязаны к дескриптору, а не к путям из IPC.
pub struct StateDirectory {
    directory: File,
    lock: File,
    owner_pid: u32,
}

impl StateDirectory {
    #[cfg(feature = "linux-kernel")]
    pub fn child(&self, name: &CStr) -> io::Result<Self> {
        self.check_process()?;
        if name.to_bytes().is_empty() || !name.to_bytes().iter().all(u8::is_ascii_alphanumeric) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name.as_ptr(), 0o700) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
        {
            return Err(io::Error::last_os_error());
        }
        self.directory.sync_all()?;
        Self::open(Path::new(&format!(
            "/proc/thread-self/fd/{}/{}",
            self.directory.as_raw_fd(),
            name.to_str().unwrap()
        )))
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || !private_permissions(&metadata, 0o700) {
            return Err(failure(Failure::UnsafeFile));
        }
        let lock = open_lock(&directory)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let store = Self {
            directory,
            lock,
            owner_pid: std::process::id(),
        };
        for file in [
            StateFile::Committed,
            StateFile::Pending,
            StateFile::DnsJournal,
        ] {
            store.remove_checked(file.names().1)?;
        }
        Ok(store)
    }

    pub fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
        self.check_process()?;
        self.open_record(file.names().0)?
            .map(read_snapshot)
            .transpose()
    }

    /// Подтверждает тот же файл под удерживаемой блокировкой и durable barrier.
    /// Capability не может появиться из MemoryStore или переданного номера serial.
    #[cfg(feature = "linux-kernel")]
    pub(crate) fn confirm_loaded(&self, file: StateFile, expected: &[u8]) -> io::Result<()> {
        self.check_process()?;
        let input = self
            .open_record(file.names().0)?
            .ok_or_else(|| failure(Failure::Snapshot))?;
        let bytes = read_snapshot(input.try_clone()?)?;
        if bytes != expected {
            return Err(failure(Failure::Snapshot));
        }
        input.sync_all()?;
        self.directory.sync_all()?;
        if self.load(file)?.as_deref() != Some(expected) {
            return Err(failure(Failure::Snapshot));
        }
        Ok(())
    }

    /// Успешный возврат подтверждает fsync файла и каталога.
    /// Ошибка после rename не отменяет замену: перед повторным применением нужно перечитать состояние.
    pub fn replace(&mut self, file: StateFile, data: &[u8]) -> io::Result<()> {
        self.check_process()?;
        if data.len() > MAX_STATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Превышен размер состояния",
            ));
        }
        let (name, temporary) = file.names();
        self.open_record(name)?;
        let mut output = create_private_file(&self.directory, temporary)?;
        let mut cleanup = TemporaryFile {
            directory: &self.directory,
            name: temporary,
            committed: false,
        };
        output.write_all(data)?;
        output.sync_all()?;
        let status = unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                self.directory.as_raw_fd(),
                name.as_ptr(),
            )
        };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        cleanup.committed = true;
        self.directory.sync_all()
    }

    pub fn clear_pending(&mut self) -> io::Result<()> {
        self.check_process()?;
        self.remove_checked(StateFile::Pending.names().0)
    }

    fn check_process(&self) -> io::Result<()> {
        if self.owner_pid != std::process::id() {
            return Err(failure(Failure::ForeignProcess));
        }
        Ok(())
    }

    fn open_record(&self, name: &CStr) -> io::Result<Option<File>> {
        match open_relative(&self.directory, name, libc::O_RDONLY) {
            Ok(file) => {
                validate_file(&file.metadata()?)?;
                Ok(Some(file))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn remove_checked(&self, name: &CStr) -> io::Result<()> {
        if self.open_record(name)?.is_some()
            && unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        self.directory.sync_all()
    }
}

impl Drop for StateDirectory {
    fn drop(&mut self) {
        if self.owner_pid == std::process::id() {
            // LOCK_UN снимает блокировку и с копий дескриптора между fork и exec.
            unsafe {
                libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn read_snapshot(mut input: File) -> io::Result<Vec<u8>> {
    let before = input.metadata()?;
    if before.len() > MAX_STATE_BYTES as u64 {
        return Err(failure(Failure::Snapshot));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(before.len() as usize)
        .map_err(io::Error::other)?;
    (&mut input)
        .take(MAX_STATE_BYTES as u64)
        .read_to_end(&mut bytes)?;
    let after = input.metadata()?;
    validate_file(&after)?;
    if !same_snapshot(&before, &after, bytes.len()) {
        return Err(failure(Failure::Snapshot));
    }
    Ok(bytes)
}

fn open_relative(directory: &File, name: &CStr, flags: i32) -> io::Result<File> {
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn create_private_file(directory: &File, name: &CStr) -> io::Result<File> {
    let file = open_relative(directory, name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?;
    let mut cleanup = TemporaryFile {
        directory,
        name,
        committed: false,
    };
    file.set_permissions(Permissions::from_mode(0o600))?;
    cleanup.committed = true;
    Ok(file)
}

fn open_lock(directory: &File) -> io::Result<File> {
    let file = match create_private_file(directory, c".lock") {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_relative(directory, c".lock", libc::O_RDWR)?
        }
        Err(error) => return Err(error),
    };
    validate_file(&file.metadata()?)?;
    Ok(file)
}

fn private_permissions(metadata: &Metadata, mode: u32) -> bool {
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o7777 == mode
}

fn validate_file(metadata: &Metadata) -> io::Result<()> {
    if metadata.is_file() && metadata.nlink() == 1 && private_permissions(metadata, 0o600) {
        return Ok(());
    }
    Err(failure(Failure::UnsafeFile))
}

fn same_snapshot(before: &Metadata, after: &Metadata, length: usize) -> bool {
    before.len() == after.len()
        && after.len() == length as u64
        && (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) == (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
}

enum Failure {
    UnsafeFile,
    Snapshot,
    ForeignProcess,
}

fn failure(failure: Failure) -> io::Error {
    let (kind, message) = match failure {
        Failure::UnsafeFile => (
            io::ErrorKind::PermissionDenied,
            "Небезопасный владелец, тип или права файла состояния",
        ),
        Failure::Snapshot => (
            io::ErrorKind::InvalidData,
            "Файл состояния превышает предел или изменился при чтении",
        ),
        Failure::ForeignProcess => (
            io::ErrorKind::PermissionDenied,
            "Хранилище принадлежит другому процессу",
        ),
    };
    io::Error::new(kind, message)
}

struct TemporaryFile<'a> {
    directory: &'a File,
    name: &'a CStr,
    committed: bool,
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

impl ControlStore for StateDirectory {
    fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
        self.load(file)
    }
    fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()> {
        self.replace(file, bytes)
    }
    fn clear_pending(&mut self) -> io::Result<()> {
        self.clear_pending()
    }
}
