use super::{StateFile, MAX_STATE_BYTES};
use crate::control::ControlStore;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::*,
};

mod api;
pub(crate) mod image;
mod logs;
pub(crate) mod retirement;
mod security;
use api::{checked, handle, information, open, unsafe_object, wide};
use security::Descriptor;

/// Закрытый каталог службы на локальном NTFS. Нужны права на сброс буферов тома.
/// Дескрипторы предков удерживают путь, а .lock допускает единственного писателя.
pub struct StateDirectory {
    path: PathBuf,
    volume_root: PathBuf,
    components: Vec<std::ffi::OsString>,
    ancestors: Vec<File>,
    _lock: File,
    volume: File,
    security: Descriptor,
}

impl StateDirectory {
    pub fn child(&self, name: &std::ffi::CStr) -> io::Result<Self> {
        self.validate_directory()?;
        let bytes = name.to_bytes();
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_alphanumeric) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut names = self.components.clone();
        names.push(
            name.to_str()
                .map_err(|_| io::ErrorKind::InvalidInput)?
                .into(),
        );
        Self::open_canonical(self.volume_root.clone(), names)
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        let (path, names) = api::volume_path(path)?;
        Self::open_canonical(path, names)
    }

    fn open_canonical(mut path: PathBuf, names: Vec<std::ffi::OsString>) -> io::Result<Self> {
        let security = Descriptor::current()?;
        let volume_root = path.clone();
        let root = open_directory(&path)?;
        api::require_ntfs(&root)?;
        let volume_name = path
            .as_os_str()
            .to_string_lossy()
            .trim_end_matches('\\')
            .to_owned();
        let volume = open(
            Path::new(&volume_name),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
            0,
        )?;
        // Проверяем возможность сброса тома до создания или удаления состояния.
        volume.sync_all()?;
        let mut ancestors = vec![root];
        for (index, name) in names.iter().enumerate() {
            path.push(name);
            let last = index + 1 == names.len();
            let directory = match open_directory(&path) {
                Ok(directory) => directory,
                Err(error) if last && error.kind() == io::ErrorKind::NotFound => {
                    checked(unsafe {
                        CreateDirectoryW(wide(&path).as_ptr(), &security.attributes())
                    })?;
                    open_directory(&path)?
                }
                Err(error) => return Err(error),
            };
            if last {
                security.validate(&directory, true)?;
            }
            ancestors.push(directory);
        }
        let lock_path = path.join(".lock");
        let lock = match open(
            &lock_path,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            0,
            CREATE_NEW,
            Some(&security.attributes()),
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => open(
                &lock_path,
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                0,
                OPEN_EXISTING,
                None,
                0,
            )?,
            Err(error) => return Err(error),
        };
        information(&lock, false)?;
        security.validate(&lock, false)?;
        let store = Self {
            path,
            volume_root,
            components: names,
            ancestors,
            _lock: lock,
            volume,
            security,
        };
        // Все объекты проверяем до первой уборки. Чужие записи не исправляем.
        for name in [
            "state.json",
            "pending.json",
            ".new-state.json",
            ".new-pending.json",
        ] {
            store.open_record(name)?;
        }
        for file in [
            StateFile::Committed,
            StateFile::Pending,
            StateFile::DnsJournal,
        ] {
            store.remove_checked(names_for(file).1)?;
        }
        Ok(store)
    }

    pub fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
        self.validate_directory()?;
        self.open_record(names_for(file).0)?
            .map(|mut input| {
                let before = information(&input, false)?;
                let length = file_length(&before);
                if length > MAX_STATE_BYTES as u64 {
                    return Err(oversized());
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length as usize)
                    .map_err(io::Error::other)?;
                (&mut input)
                    .take(MAX_STATE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                let after = information(&input, false)?;
                self.security.validate(&input, false)?;
                if bytes.len() as u64 != length
                    || file_length(&after) != length
                    || before.ftLastWriteTime.dwLowDateTime != after.ftLastWriteTime.dwLowDateTime
                    || before.ftLastWriteTime.dwHighDateTime != after.ftLastWriteTime.dwHighDateTime
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Состояние изменилось при чтении",
                    ));
                }
                Ok(bytes)
            })
            .transpose()
    }

    /// Успех подтверждает сброс файла, замену имени и сброс метаданных тома.
    /// Ошибка после замены не откатывает состояние: вызывающий код должен прекратить запись.
    pub fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()> {
        self.validate_directory()?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Превышен размер состояния",
            ));
        }
        let (name, temporary) = names_for(file);
        let target = self.open_record(name)?;
        fault(Point::Create)?;
        let mut output = open(
            &self.path.join(temporary),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            CREATE_NEW,
            Some(&self.security.attributes()),
            FILE_FLAG_WRITE_THROUGH,
        )?;
        information(&output, false)?;
        self.security.validate(&output, false)?;
        fault(Point::Write)?;
        output.write_all(bytes)?;
        fault(Point::FileFlush)?;
        output.sync_all()?;
        fault(Point::Rename)?;
        api::rename(&output, &self.path.join(name))?;
        drop(output);
        drop(target);
        self.flush_volume()
    }

    pub fn clear_pending(&mut self) -> io::Result<()> {
        self.validate_directory()?;
        self.remove_checked(names_for(StateFile::Pending).0)
    }

    fn validate_directory(&self) -> io::Result<()> {
        let directory = self.ancestors.last().ok_or_else(unsafe_object)?;
        information(directory, true)?;
        self.security.validate(directory, true)
    }

    fn open_record(&self, name: &str) -> io::Result<Option<File>> {
        match open(
            &self.path.join(name),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
            0,
        ) {
            Ok(file) => {
                information(&file, false)?;
                self.security.validate(&file, false)?;
                Ok(Some(file))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn remove_checked(&self, name: &str) -> io::Result<()> {
        let Some(input) = self.open_record(name)? else {
            // Имя могло исчезнуть до неудачного сброса в предыдущей попытке.
            return self.flush_volume();
        };
        // Удаление привязано к проверенному объекту, а не только к его имени.
        let file = open(
            &self.path.join(name),
            DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
            0,
        )?;
        let before = information(&input, false)?;
        let after = information(&file, false)?;
        self.security.validate(&file, false)?;
        if (
            before.dwVolumeSerialNumber,
            before.nFileIndexHigh,
            before.nFileIndexLow,
        ) != (
            after.dwVolumeSerialNumber,
            after.nFileIndexHigh,
            after.nFileIndexLow,
        ) {
            return Err(unsafe_object());
        }
        fault(Point::Delete)?;
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        checked(unsafe {
            SetFileInformationByHandle(
                handle(&file),
                FileDispositionInfoEx,
                ptr::addr_of!(disposition).cast(),
                std::mem::size_of_val(&disposition) as u32,
            )
        })?;
        drop(file);
        drop(input);
        self.flush_volume()
    }

    fn flush_volume(&self) -> io::Result<()> {
        fault(Point::VolumeFlush)?;
        self.volume.sync_all()
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    let file = open(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        None,
        FILE_FLAG_BACKUP_SEMANTICS,
    )?;
    information(&file, true)?;
    Ok(file)
}

fn names_for(file: StateFile) -> (&'static str, &'static str) {
    match file {
        StateFile::Committed => ("state.json", ".new-state.json"),
        StateFile::Pending => ("pending.json", ".new-pending.json"),
        StateFile::DnsJournal => ("dns-journal.json", ".new-dns-journal.json"),
    }
}

fn file_length(info: &BY_HANDLE_FILE_INFORMATION) -> u64 {
    ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64
}

fn oversized() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Файл состояния превышает предел",
    )
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Point {
    Create,
    Write,
    FileFlush,
    Rename,
    VolumeFlush,
    Delete,
}

#[cfg(not(test))]
fn fault(_: Point) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
thread_local! { static FAULT: std::cell::Cell<Option<Point>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
fn fault(point: Point) -> io::Result<()> {
    FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            Err(io::Error::other(format!("Тестовый отказ {point:?}")))
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests;
