use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle},
};
use std::{
    ffi::OsStr,
    fs::File,
    io, mem,
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
};

pub(super) fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(super) fn handle(file: &File) -> HANDLE {
    file.as_raw_handle()
}

pub(super) fn checked(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn unsafe_object() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Небезопасный владелец, тип или ACL состояния",
    )
}

pub(super) fn open(
    path: &Path,
    access: u32,
    sharing: u32,
    creation: u32,
    attributes: Option<&SECURITY_ATTRIBUTES>,
    flags: u32,
) -> io::Result<File> {
    let name = wide(path);
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            sharing,
            attributes.map_or(ptr::null(), |value| value),
            creation,
            FILE_FLAG_OPEN_REPARSE_POINT | flags,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}

pub(super) fn information(file: &File, directory: bool) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    checked(unsafe { GetFileInformationByHandle(handle(file), &mut info) })?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(unsafe_object());
    }
    Ok(info)
}

// Имена привязаны к GUID тома. Каждый компонент затем открывается с запретом удаления.
// Это исключает подмену предка, junction и повторное назначение буквы диска.
pub(super) fn volume_path(path: &Path) -> io::Result<(PathBuf, Vec<std::ffi::OsString>)> {
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) => drive,
            _ => return Err(unsafe_object()),
        },
        _ => return Err(unsafe_object()),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(unsafe_object());
    }
    let mut names = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(unsafe_object());
        };
        let units: Vec<_> = name.encode_wide().collect();
        if units.iter().any(|unit| [0, b':' as u16].contains(unit))
            || units
                .last()
                .is_some_and(|unit| [b'.' as u16, b' ' as u16].contains(unit))
        {
            return Err(unsafe_object());
        }
        names.push(name.to_os_string());
    }
    if names.is_empty() {
        return Err(unsafe_object());
    }
    let root = wide(format!("{}:\\", drive as char));
    if unsafe { GetDriveTypeW(root.as_ptr()) } != 3 {
        return Err(unsafe_object());
    }
    let mut guid = [0u16; 64];
    checked(unsafe {
        GetVolumeNameForVolumeMountPointW(root.as_ptr(), guid.as_mut_ptr(), guid.len() as u32)
    })?;
    let end = guid
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(unsafe_object)?;
    let root = PathBuf::from(String::from_utf16_lossy(&guid[..end]));
    Ok((root, names))
}

pub(super) fn require_ntfs(file: &File) -> io::Result<()> {
    let mut name = [0u16; 16];
    checked(unsafe {
        GetVolumeInformationByHandleW(
            handle(file),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    })?;
    if name[..5] != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0] {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Хранилище требует локальный том NTFS",
        ));
    }
    Ok(())
}

// Замена с POSIX_SEMANTICS оставляет старое состояние доступным открытым читателям.
// Флаги FILE_RENAME_REPLACE_IF_EXISTS и FILE_RENAME_POSIX_SEMANTICS заданы Win32.
pub(super) fn rename(file: &File, destination: &Path) -> io::Result<()> {
    let name = wide(destination);
    let bytes = mem::offset_of!(FILE_RENAME_INFO, FileName) + name.len() * 2;
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.Flags = 0x1 | 0x2;
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = ((name.len() - 1) * 2) as u32;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        checked(SetFileInformationByHandle(
            handle(file),
            FileRenameInfoEx,
            buffer.as_ptr().cast(),
            bytes as u32,
        ))
    }
}
