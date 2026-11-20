//! Read-only image и каталог DLL удерживаются до завершения дочернего процесса.
use super::api::{self, checked, handle, information, open, unsafe_object};
use std::{
    ffi::OsString,
    fs::File,
    io,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
};

pub(crate) struct TrustedImage {
    pub file: File,
    pub path: PathBuf,
    _ancestors: Vec<File>,
}
impl TrustedImage {
    pub fn shell_path(&self) -> io::Result<PathBuf> {
        let mut name = vec![0u16; 32_768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle(&self.file),
                name.as_mut_ptr(),
                name.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        let name = name
            .get(..length as usize)
            .filter(|name| {
                name.len() > 7
                    && name[..4] == [92, 92, 63, 92]
                    && ((65..=90).contains(&name[4]) || (97..=122).contains(&name[4]))
                    && name[5..7] == [58, 92]
                    && !name.contains(&0)
            })
            .ok_or_else(unsafe_object)?;
        // Shell не принимает GUID тома. DOS-имя проверяется по тем же удерживаемым объектам.
        let alias = Self::open(Path::new(&OsString::from_wide(&name[4..])))?;
        if self._ancestors.len() != alias._ancestors.len() {
            return Err(unsafe_object());
        }
        for (left, right, directory) in std::iter::once((&self.file, &alias.file, false)).chain(
            self._ancestors
                .iter()
                .zip(&alias._ancestors)
                .map(|(left, right)| (left, right, true)),
        ) {
            let left = information(left, directory)?;
            let right = information(right, directory)?;
            if (
                left.dwVolumeSerialNumber,
                left.nFileIndexHigh,
                left.nFileIndexLow,
            ) != (
                right.dwVolumeSerialNumber,
                right.nFileIndexHigh,
                right.nFileIndexLow,
            ) {
                return Err(unsafe_object());
            }
        }
        Ok(PathBuf::from(OsString::from_wide(name)))
    }

    pub fn open(requested: &Path) -> io::Result<Self> {
        let (mut path, names) = api::volume_path(requested)?;
        if names.is_empty() {
            return Err(unsafe_object());
        }
        let root = open(
            &path,
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
            FILE_FLAG_BACKUP_SEMANTICS,
        )?;
        api::require_ntfs(&root)?;
        information(&root, true)?;
        let mut ancestors = vec![root];
        for (index, name) in names.iter().enumerate() {
            path.push(name);
            let directory = index + 1 != names.len();
            let file = open(
                &path,
                FILE_READ_ATTRIBUTES | READ_CONTROL | if directory { 0 } else { FILE_READ_DATA },
                if directory {
                    FILE_SHARE_READ | FILE_SHARE_WRITE
                } else {
                    FILE_SHARE_READ
                },
                OPEN_EXISTING,
                None,
                if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
            )?;
            information(&file, directory)?;
            // Запрет rename каждого предка не позволяет перенести доверенный каталог из-под handle.
            // Image и ближайший DLL-каталог дополнительно запрещают запись непривилегированным SID.
            if index + 2 >= names.len() {
                protected_writer(&file)?;
            }
            if !directory {
                return Ok(Self {
                    file,
                    path,
                    _ancestors: ancestors,
                });
            }
            ancestors.push(file);
        }
        Err(unsafe_object())
    }
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn privileged(sid: PSID) -> bool {
    [WinLocalSystemSid, WinBuiltinAdministratorsSid]
        .into_iter()
        .any(|kind| unsafe { IsWellKnownSid(sid, kind) } != 0)
}
pub(super) fn protected_writer(file: &File) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = Descriptor(descriptor);
    if owner.is_null() || acl.is_null() || !privileged(owner) {
        return Err(unsafe_object());
    }
    for index in 0..unsafe { (*acl).AceCount } as u32 {
        let mut ace = ptr::null_mut();
        checked(unsafe { GetAce(acl, index, &mut ace) })?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        if header.AceType == 1 {
            continue;
        }
        if header.AceType != 0
            || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(unsafe_object());
        }
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let writable = FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | FILE_DELETE_CHILD
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER
            | windows_sys::Win32::Foundation::GENERIC_ALL
            | windows_sys::Win32::Foundation::GENERIC_WRITE;
        if ace.Mask & writable != 0 && !privileged(ptr::addr_of!(ace.SidStart).cast_mut().cast()) {
            return Err(unsafe_object());
        }
    }
    Ok(())
}
