use super::super::api::{check, denied};
use std::{
    io,
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{
        Rpc::UuidCreate,
        SystemServices::{SE_GROUP_INTEGRITY, SE_GROUP_USE_FOR_DENY_ONLY},
        Threading::*,
    },
};

fn sid(kind: WELL_KNOWN_SID_TYPE) -> io::Result<[u64; 9]> {
    let mut value = [0; 9];
    let mut length = std::mem::size_of_val(&value) as u32;
    check(unsafe {
        CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut length,
        )
    })?;
    Ok(value)
}
fn data(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, class, ptr::null_mut(), 0, &mut length);
    }
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || length > 65536 {
        return Err(denied());
    }
    let mut data = vec![0; (length as usize).div_ceil(8)];
    check(unsafe {
        GetTokenInformation(token, class, data.as_mut_ptr().cast(), length, &mut length)
    })?;
    Ok(data)
}
fn process_token(process: HANDLE, access: u32) -> io::Result<OwnedHandle> {
    let mut raw = ptr::null_mut();
    check(unsafe { OpenProcessToken(process, access, &mut raw) })?;
    super::process::owned(raw)
}

pub(super) struct RestrictedToken {
    pub handle: OwnedHandle,
    pub private_sid: String,
    pub objects: Descriptor,
}
pub(super) struct Descriptor(pub PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
impl Descriptor {
    pub fn new(sddl: &str) -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                super::process::wide(sddl).as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        })?;
        Ok(Self(raw))
    }
    fn dacl(&self) -> io::Result<*mut ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = ptr::null_mut();
        check(unsafe {
            GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted)
        })?;
        if present == 0 || acl.is_null() {
            return Err(denied());
        }
        Ok(acl)
    }
}
pub(super) fn restricted_token() -> io::Result<RestrictedToken> {
    let current = process_token(
        unsafe { GetCurrentProcess() },
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | WRITE_DAC,
    )?;
    let mut uuid = windows_sys::core::GUID::default();
    let status = unsafe { UuidCreate(&mut uuid) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let private_sid = format!(
        "S-1-5-21-{}-{}-{}-{}",
        uuid.data1,
        ((uuid.data2 as u32) << 16) | uuid.data3 as u32,
        u32::from_le_bytes(uuid.data4[..4].try_into().unwrap()),
        u32::from_le_bytes(uuid.data4[4..].try_into().unwrap())
    );
    let mut private = ptr::null_mut();
    check(unsafe {
        ConvertStringSidToSidW(super::process::wide(&private_sid).as_ptr(), &mut private)
    })?;
    let _private = Descriptor(private);
    let mut world = sid(WinWorldSid)?;
    let mut admin = sid(WinBuiltinAdministratorsSid)?;
    let mut users = sid(WinBuiltinUsersSid)?;
    let restrict = [
        SID_AND_ATTRIBUTES {
            Sid: world.as_mut_ptr().cast(),
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: users.as_mut_ptr().cast(),
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: private,
            Attributes: 0,
        },
    ];
    let disable = SID_AND_ATTRIBUTES {
        Sid: admin.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut raw = ptr::null_mut();
    check(unsafe {
        CreateRestrictedToken(
            current.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            &disable,
            0,
            ptr::null(),
            restrict.len() as u32,
            restrict.as_ptr(),
            &mut raw,
        )
    })?;
    let token = super::process::owned(raw)?;
    // Уникальный SID открывает только собственные объекты worker. Общие объекты
    // службы и других worker не получают дополнительных ACE.
    let objects = Descriptor::new(&format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{private_sid})S:(ML;;NW;;;LW)"
    ))?;
    let default = TOKEN_DEFAULT_DACL {
        DefaultDacl: objects.dacl()?,
    };
    check(unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            (&default as *const TOKEN_DEFAULT_DACL).cast(),
            std::mem::size_of_val(&default) as u32,
        )
    })?;
    let own_token = Descriptor::new(&format!("D:P(A;;GA;;;SY)(A;;0x8;;;{private_sid})"))?;
    let status = unsafe {
        SetSecurityInfo(
            token.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            own_token.dacl()?,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let mut low = sid(WinLowLabelSid)?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low.as_mut_ptr().cast(),
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    check(unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenIntegrityLevel,
            (&label as *const TOKEN_MANDATORY_LABEL).cast(),
            (std::mem::size_of_val(&label) + GetLengthSid(label.Label.Sid) as usize) as u32,
        )
    })?;
    verify_token(token.as_raw_handle(), Some(&private_sid))?;
    Ok(RestrictedToken {
        handle: token,
        private_sid,
        objects,
    })
}

/// Проверяются реальные свойства primary token, сообщение RESTRICTED не является доказательством.
pub fn verify_worker_token(process: &OwnedHandle) -> io::Result<()> {
    let token = process_token(process.as_raw_handle(), TOKEN_QUERY)?;
    verify_token(token.as_raw_handle(), None)
}
pub(super) fn verify_current() -> io::Result<()> {
    let token = process_token(unsafe { GetCurrentProcess() }, TOKEN_QUERY)?;
    verify_token(token.as_raw_handle(), None)
}
pub(super) fn verify_expected(process: &OwnedHandle, private_sid: &str) -> io::Result<()> {
    let token = process_token(process.as_raw_handle(), TOKEN_QUERY)?;
    verify_token(token.as_raw_handle(), Some(private_sid))
}
fn verify_token(token: HANDLE, expected: Option<&str>) -> io::Result<()> {
    if unsafe { IsTokenRestricted(token) } == 0 || data(token, TokenSessionId)?[0] as u32 != 0 {
        return Err(denied());
    }
    let user = data(token, TokenUser)?;
    let user = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() };
    let mut system = sid(WinLocalSystemSid)?;
    if unsafe { EqualSid(user.User.Sid, system.as_mut_ptr().cast()) } == 0 {
        return Err(denied());
    }
    let integrity = data(token, TokenIntegrityLevel)?;
    let label = unsafe { &*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    let mut low = sid(WinLowLabelSid)?;
    if unsafe { EqualSid(label.Label.Sid, low.as_mut_ptr().cast()) } == 0 {
        return Err(denied());
    }
    let restricting = data(token, TokenRestrictedSids)?;
    let groups = unsafe { &*restricting.as_ptr().cast::<TOKEN_GROUPS>() };
    let mut world = sid(WinWorldSid)?;
    if groups.GroupCount != 3 {
        return Err(denied());
    }
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), 3) };
    let mut users = sid(WinBuiltinUsersSid)?;
    if !entries
        .iter()
        .any(|entry| unsafe { EqualSid(entry.Sid, world.as_mut_ptr().cast()) } != 0)
        || !entries
            .iter()
            .any(|entry| unsafe { EqualSid(entry.Sid, users.as_mut_ptr().cast()) } != 0)
    {
        return Err(denied());
    }
    let private = entries
        .iter()
        .filter(|entry| unsafe {
            EqualSid(entry.Sid, world.as_mut_ptr().cast()) == 0
                && EqualSid(entry.Sid, users.as_mut_ptr().cast()) == 0
        })
        .collect::<Vec<_>>();
    if private.len() != 1 {
        return Err(denied());
    }
    let mut raw = ptr::null_mut();
    check(unsafe { ConvertSidToStringSidW(private[0].Sid, &mut raw) })?;
    let _raw = Descriptor(raw.cast());
    let mut length = 0;
    while unsafe { *raw.add(length) } != 0 && length < 184 {
        length += 1;
    }
    let private = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(io::Error::other)?;
    if !private.starts_with("S-1-5-21-") || expected.is_some_and(|value| value != private) {
        return Err(denied());
    }
    let groups_data = data(token, TokenGroups)?;
    let groups = unsafe { &*groups_data.as_ptr().cast::<TOKEN_GROUPS>() };
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    let mut admin = sid(WinBuiltinAdministratorsSid)?;
    if !entries.iter().any(|entry| unsafe { EqualSid(entry.Sid, admin.as_mut_ptr().cast()) } != 0 && entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0) {
        return Err(denied());
    }
    let privileges_data = data(token, TokenPrivileges)?;
    let privileges = unsafe { &*privileges_data.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let entries = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    let mut allowed = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    check(unsafe { LookupPrivilegeValueW(ptr::null(), SE_CHANGE_NOTIFY_NAME, &mut allowed) })?;
    if entries.iter().any(|entry| {
        entry.Luid.LowPart != allowed.LowPart || entry.Luid.HighPart != allowed.HighPart
    }) {
        return Err(denied());
    }
    Ok(())
}
