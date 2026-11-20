use super::api::{checked, handle, unsafe_object, wide};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::{ffi::c_void, fs::File, io, mem, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorOwner,
        GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
        SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::FILE_ALL_ACCESS,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub(super) struct Descriptor(*mut c_void);

impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

impl Descriptor {
    pub(super) fn current() -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) })?;
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut length = 0;
        unsafe {
            GetTokenInformation(raw, TokenUser, ptr::null_mut(), 0, &mut length);
        }
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
        checked(unsafe {
            GetTokenInformation(
                raw,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        })?;
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = ptr::null_mut();
        checked(unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) })?;
        let text_owner = Descriptor(text.cast());
        let mut count = 0;
        while unsafe { *text.add(count) } != 0 {
            count += 1;
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, count) });
        let sddl = wide(format!("O:{sid}D:P(A;OICI;FA;;;{sid})"));
        let mut descriptor = ptr::null_mut();
        checked(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        })?;
        drop(text_owner);
        drop(token);
        Ok(Self(descriptor))
    }

    pub(super) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    pub(super) fn validate(&self, file: &File, directory: bool) -> io::Result<()> {
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
        let allocated = Descriptor(descriptor);
        let mut expected = ptr::null_mut();
        let mut defaulted = 0;
        checked(unsafe { GetSecurityDescriptorOwner(self.0, &mut expected, &mut defaulted) })?;
        if owner.is_null() || acl.is_null() || unsafe { EqualSid(owner, expected) } == 0 {
            return Err(unsafe_object());
        }
        let mut control = 0;
        let mut revision = 0;
        checked(unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) })?;
        if directory && control & SE_DACL_PROTECTED == 0 {
            return Err(unsafe_object());
        }
        if unsafe { (*acl).AceCount } != 1 {
            return Err(unsafe_object());
        }
        let mut ace = ptr::null_mut();
        checked(unsafe { GetAce(acl, 0, &mut ace) })?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != 0 || usize::from(header.AceSize) < mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(unsafe_object());
        }
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceFlags & INHERIT_ONLY_ACE as u8 != 0
            || ace.Mask != FILE_ALL_ACCESS
            || unsafe { EqualSid(ptr::addr_of!(ace.SidStart).cast_mut().cast(), expected) } == 0
        {
            return Err(unsafe_object());
        }
        drop(allocated);
        Ok(())
    }
}
