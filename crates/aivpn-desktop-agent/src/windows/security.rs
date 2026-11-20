use super::api::{check, denied, Handle};
use aivpn_desktop_policy::{Authority, Owner};
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{Pipes::*, Threading::*},
};

pub(super) const CLIENT_ACCESS: u32 = 0x0012_019b;

pub(super) struct Descriptor(pub PSECURITY_DESCRIPTOR);
impl Descriptor {
    pub fn new(admin: bool) -> io::Result<Self> {
        let group = if admin { "BA" } else { "AU" };
        let text = format!("O:SYG:SYD:P(A;;0x001f01ff;;;SY)(A;;0x0012019b;;;{group})\0")
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut value = ptr::null_mut();
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut value,
                ptr::null_mut(),
            )
        })?;
        Ok(Self(value))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) fn no_impersonation() -> io::Result<()> {
    let mut token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        drop(Handle::new(token)?);
        return Err(denied());
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn process_token() -> io::Result<Handle> {
    let mut token = ptr::null_mut();
    check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
    Handle::new(token)
}

pub(super) fn process_owner() -> io::Result<Owner> {
    no_impersonation()?;
    Ok(Owner::WindowsUser {
        sid: user_sid(process_token()?.raw())?,
    })
}

fn token_data(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, class, ptr::null_mut(), 0, &mut length);
    }
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    let mut data = vec![0u64; (length as usize).div_ceil(8)];
    check(unsafe {
        GetTokenInformation(token, class, data.as_mut_ptr().cast(), length, &mut length)
    })?;
    Ok(data)
}

pub(super) fn user_sid(token: HANDLE) -> io::Result<String> {
    let data = token_data(token, TokenUser)?;
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    let mut text = ptr::null_mut();
    check(unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) })?;
    let result = unsafe {
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(text, length)).map_err(|_| denied())
    };
    unsafe {
        LocalFree(text.cast());
    }
    result
}

fn member(token: HANDLE, kind: WELL_KNOWN_SID_TYPE) -> io::Result<bool> {
    let mut sid = [0u64; 9];
    let mut size = std::mem::size_of_val(&sid) as u32;
    check(unsafe {
        CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size)
    })?;
    let mut enabled = 0;
    check(unsafe { CheckTokenMembership(token, sid.as_ptr().cast_mut().cast(), &mut enabled) })?;
    Ok(enabled != 0)
}

pub(super) fn service_authority() -> io::Result<()> {
    no_impersonation()?;
    let token = process_token()?;
    let session = token_data(token.raw(), TokenSessionId)?;
    if user_sid(token.raw())? != "S-1-5-18"
        || session[0] as u32 != 0
        || member(ptr::null_mut(), WinInteractiveSid)?
    {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn is_admin() -> io::Result<bool> {
    member(ptr::null_mut(), WinBuiltinAdministratorsSid)
}

struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        // Продолжать работу после отказа RevertToSelf опасно для любого следующего вызова.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

pub(super) fn client_authority(pipe: HANDLE) -> io::Result<Authority> {
    no_impersonation()?;
    let mut pid = 0;
    check(unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) })?;
    if pid == 0 {
        return Err(denied());
    }
    check(unsafe { ImpersonateNamedPipeClient(pipe) })?;
    let guard = Revert;
    let result = impersonated_authority();
    drop(guard);
    no_impersonation()?;
    result
}

fn impersonated_authority() -> io::Result<Authority> {
    let mut token = ptr::null_mut();
    check(unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) })?;
    let token = Handle::new(token)?;
    let level = token_data(token.raw(), TokenImpersonationLevel)?;
    if (level[0] as i32) < SecurityIdentification {
        return Err(denied());
    }
    Ok(Authority {
        user: Owner::WindowsUser {
            sid: user_sid(token.raw())?,
        },
        machine_admin: member(token.raw(), WinBuiltinAdministratorsSid)?,
    })
}

pub(super) fn authenticate_server(pipe: HANDLE, admin: bool) -> io::Result<()> {
    let mut pid = 0;
    let mut session = u32::MAX;
    check(unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) })?;
    check(unsafe { GetNamedPipeServerSessionId(pipe, &mut session) })?;
    if pid == 0 || session != 0 {
        return Err(denied());
    }
    let mut descriptor = ptr::null_mut();
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let actual = Descriptor(descriptor);
    let expected = Descriptor::new(admin)?;
    verify_descriptor(&actual, &expected, owner, acl)
}

fn verify_descriptor(
    actual: &Descriptor,
    expected: &Descriptor,
    owner: PSID,
    acl: *mut ACL,
) -> io::Result<()> {
    let mut control = 0;
    let mut revision = 0;
    check(unsafe { GetSecurityDescriptorControl(actual.0, &mut control, &mut revision) })?;
    let mut expected_owner = ptr::null_mut();
    let mut defaulted = 0;
    check(unsafe { GetSecurityDescriptorOwner(expected.0, &mut expected_owner, &mut defaulted) })?;
    let mut expected_acl = ptr::null_mut();
    let mut present = 0;
    check(unsafe {
        GetSecurityDescriptorDacl(expected.0, &mut present, &mut expected_acl, &mut defaulted)
    })?;
    if control & SE_DACL_PROTECTED == 0
        || owner.is_null()
        || acl.is_null()
        || unsafe { EqualSid(owner, expected_owner) } == 0
    {
        return Err(denied());
    }
    let equal = unsafe {
        let a = std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize);
        let b =
            std::slice::from_raw_parts(expected_acl.cast::<u8>(), (*expected_acl).AclSize as usize);
        a == b
    };
    if !equal {
        return Err(denied());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(text: &str) -> Descriptor {
        let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let mut raw = ptr::null_mut();
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        })
        .unwrap();
        Descriptor(raw)
    }
    fn verify(text: &str, admin: bool) -> io::Result<()> {
        let actual = descriptor(text);
        let expected = Descriptor::new(admin)?;
        let mut owner = ptr::null_mut();
        let mut defaulted = 0;
        check(unsafe { GetSecurityDescriptorOwner(actual.0, &mut owner, &mut defaulted) })?;
        let mut acl = ptr::null_mut();
        let mut present = 0;
        check(unsafe {
            GetSecurityDescriptorDacl(actual.0, &mut present, &mut acl, &mut defaulted)
        })?;
        verify_descriptor(&actual, &expected, owner, acl)
    }
    #[test]
    fn exact_protected_system_descriptor_only() {
        assert!(verify("O:SYG:SYD:P(A;;0x001f01ff;;;SY)(A;;0x0012019b;;;AU)", false).is_ok());
        assert!(verify("O:SYG:SYD:P(A;;0x001f01ff;;;SY)(A;;0x0012019b;;;BA)", true).is_ok());
        for text in [
            "O:BAG:SYD:P(A;;0x001f01ff;;;SY)(A;;0x0012019b;;;AU)",
            "O:SYG:SYD:(A;;0x001f01ff;;;SY)(A;;0x0012019b;;;AU)",
            "O:SYG:SYD:P(A;;0x001f01ff;;;SY)(A;;GA;;;AU)",
            "O:SYG:SYD:P(A;;0x001f01ff;;;SY)(A;;0x0012019b;;;BA)",
            "O:SYG:SYD:NO_ACCESS_CONTROL",
        ] {
            assert!(
                verify(text, false).is_err(),
                "Принят чужой descriptor: {text}"
            );
        }
    }
}
