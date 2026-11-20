//! Отдельная noninteractive station. Общая station службы не меняет ACL.
use super::super::api::{check, denied};
use super::{process::wide, token::RestrictedToken};
use std::{io, os::windows::io::AsRawHandle, ptr, sync::Mutex};
use windows_sys::Win32::{Foundation::*, Security::*, System::StationsAndDesktops::*};

static STATION_CHANGE: Mutex<()> = Mutex::new(());
const STATION_ACCESS: u32 = 0x000f037f;
const DESKTOP_ACCESS: u32 = 0x000f01ff;
pub(super) struct Desktop {
    desktop: HDESK,
    station: HWINSTA,
    pub name: Vec<u16>,
    pub inherited_access: bool,
}
impl Drop for Desktop {
    fn drop(&mut self) {
        unsafe {
            CloseDesktop(self.desktop);
            CloseWindowStation(self.station);
        }
    }
}
struct Restore(HWINSTA);
impl Drop for Restore {
    fn drop(&mut self) {
        unsafe {
            SetProcessWindowStation(self.0);
        }
    }
}
impl Desktop {
    pub fn new(token: &RestrictedToken) -> io::Result<Self> {
        let _lock = STATION_CHANGE.lock().map_err(|_| denied())?;
        let old = unsafe { GetProcessWindowStation() };
        if old.is_null() {
            return Err(io::Error::last_os_error());
        }
        let inherited_access = access(old, token, STATION_ACCESS)?;
        let name = format!("AivpnWorker-{}", token.private_sid);
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: token.objects.0,
            bInheritHandle: 0,
        };
        let station =
            unsafe { CreateWindowStationW(wide(&name).as_ptr(), 1, STATION_ACCESS, &security) };
        if station.is_null() {
            return Err(io::Error::last_os_error());
        }
        // UUID исключает повторное использование чужого имени, проверка ACL ниже
        // подтверждает доступ созданного restricted token к собственным объектам.
        let mut result = Self {
            desktop: ptr::null_mut(),
            station,
            name: wide(&format!("{name}\\worker")),
            inherited_access,
        };
        check(unsafe { SetProcessWindowStation(station) })?;
        let restore = Restore(old);
        result.desktop = unsafe {
            CreateDesktopExW(
                wide("worker").as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                DESKTOP_ACCESS,
                &security,
                512,
                ptr::null(),
            )
        };
        if result.desktop.is_null() {
            return Err(io::Error::last_os_error());
        }
        check(unsafe { SetProcessWindowStation(old) })?;
        std::mem::forget(restore);
        if !access(station, token, STATION_ACCESS)?
            || !access(result.desktop, token, DESKTOP_ACCESS)?
        {
            return Err(denied());
        }
        Ok(result)
    }
}
fn access(object: HANDLE, token: &RestrictedToken, desired: u32) -> io::Result<bool> {
    let mut information =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut length = 0;
    unsafe {
        GetUserObjectSecurity(object, &mut information, ptr::null_mut(), 0, &mut length);
    }
    if length == 0 || length > 65536 {
        return Err(denied());
    }
    let mut descriptor = vec![0u64; (length as usize).div_ceil(8)];
    check(unsafe {
        GetUserObjectSecurity(
            object,
            &mut information,
            descriptor.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    })?;
    let mut duplicate = ptr::null_mut();
    check(unsafe {
        DuplicateToken(
            token.handle.as_raw_handle(),
            SecurityImpersonation,
            &mut duplicate,
        )
    })?;
    let duplicate = super::process::owned(duplicate)?;
    let mapping = GENERIC_MAPPING {
        GenericRead: desired,
        GenericWrite: desired,
        GenericExecute: desired,
        GenericAll: desired,
    };
    let mut privileges = [0u64; 128];
    let mut size = std::mem::size_of_val(&privileges) as u32;
    let mut granted = 0;
    let mut allowed = 0;
    check(unsafe {
        AccessCheck(
            descriptor.as_mut_ptr().cast(),
            duplicate.as_raw_handle(),
            desired,
            &mapping,
            privileges.as_mut_ptr().cast(),
            &mut size,
            &mut granted,
            &mut allowed,
        )
    })?;
    Ok(allowed != 0 && granted & desired == desired)
}
