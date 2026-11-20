//! Файл журнала открывается до записи заголовка и установки обработчика panic.
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            NtCreateFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_IF,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        },
    },
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING,
        },
        Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            FILE_SHARE_WRITE, SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

const SHARE_MODE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

pub(crate) struct LogFile {
    file: File,
    _parents: Vec<File>,
}
impl LogFile {
    pub(crate) fn try_clone(&self) -> io::Result<File> {
        self.file.try_clone()
    }
}
impl Write for LogFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Небезопасный путь журнала")
}

fn local_path(path: &Path) -> io::Result<()> {
    let mut parts = path.components();
    if !matches!(parts.next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || !matches!(parts.next(), Some(Component::RootDir))
        || path.file_name().is_none()
        || parts.any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid());
    }
    Ok(())
}

fn open_relative(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let mut name: Vec<u16> = name.encode_wide().collect();
    // Имя должно обозначать один компонент, без потока NTFS.
    if name.is_empty()
        || name
            .iter()
            .any(|unit| [0, u16::from(b'/'), u16::from(b':'), u16::from(b'\\')].contains(unit))
        || name == [u16::from(b'.')]
        || name == [u16::from(b'.'); 2]
    {
        return Err(invalid());
    }
    let length = u16::try_from(name.len() * size_of::<u16>()).map_err(|_| invalid())?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let (access, kind) = if directory {
        (FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_DIRECTORY_FILE)
    } else {
        (
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_NON_DIRECTORY_FILE,
        )
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    // Все указатели и родительский дескриптор действительны до конца вызова.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_MODE,
            FILE_OPEN_IF,
            kind | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    // При успешном вызове Windows передает нам открытый дескриптор.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn check_directory(directory: &File) -> io::Result<()> {
    let meta = directory.metadata()?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn open(path: &Path) -> io::Result<LogFile> {
    local_path(path)?;
    let mut parts = path.parent().ok_or_else(invalid)?.components();
    let mut root = PathBuf::from(parts.next().ok_or_else(invalid)?.as_os_str());
    root.push(parts.next().ok_or_else(invalid)?.as_os_str());
    let mut directory = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(SHARE_MODE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    check_directory(&directory)?;

    // Полный путь больше не разрешается. Каждый компонент открывается от
    // дескриптора предыдущего каталога, а переход через reparse point запрещен.
    let mut parents = Vec::new();
    for part in parts {
        let next = open_relative(&directory, part.as_os_str(), true)?;
        check_directory(&next)?;
        parents.push(directory);
        directory = next;
    }
    let file = open_relative(&directory, path.file_name().ok_or_else(invalid)?, false)?;
    parents.push(directory);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !file.metadata()?.is_file()
        || info.nNumberOfLinks != 1
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(invalid());
    }
    file.set_len(0)?;
    Ok(LogFile {
        file,
        _parents: parents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("aivpn-log-guard-{:032x}", rand::random::<u128>()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn remote_and_relative_names_are_rejected_before_io() {
        for name in [
            r"\\127.0.0.1\unavailable\client.log",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\client.log",
            r"client.log",
            r"C:\logs\..\client.log",
        ] {
            assert!(local_path(Path::new(name)).is_err());
        }
    }
    #[test]
    fn refuses_hard_link_before_truncating_the_victim() {
        let directory = Scratch::new();
        let victim = directory.0.join("victim");
        let link = directory.0.join("client.log");
        std::fs::write(&victim, b"keep original").unwrap();
        std::fs::hard_link(&victim, &link).unwrap();
        let result = open(&link);
        assert!(result.is_err(), "Журнал принял чужую жесткую ссылку");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep original");
    }
    #[test]
    fn refuses_a_reparse_parent_before_truncating_the_victim() {
        let directory = Scratch::new();
        let real = directory.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let victim = real.join("client.log");
        std::fs::write(&victim, b"keep original").unwrap();
        let link = directory.0.join("alias");
        std::os::windows::fs::symlink_dir(&real, &link).unwrap();
        let result = open(&link.join("client.log"));
        assert!(result.is_err(), "Журнал принял каталог-ссылку");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep original");
    }
    #[test]
    fn ordinary_log_and_panic_clone_keep_writing_to_one_file() {
        let directory = Scratch::new();
        let path = directory.0.join("new").join("client.log");
        let mut file = open(&path).unwrap();
        file.write_all(b"header\n").unwrap();
        file.try_clone().unwrap().write_all(b"panic\n").unwrap();
        file.flush().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"header\npanic\n");
    }
    #[test]
    fn rejects_alternate_data_stream_names() {
        let directory = Scratch::new();
        let path = directory.0.join("client.log");
        std::fs::write(&path, b"keep original").unwrap();
        assert!(open(&directory.0.join("client.log:diagnostics")).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep original");
    }
}
