//! Разовый административный запрос общего DNS через установленную службу.

use std::io;

fn dns_parameters(profile: Option<&str>, acknowledge_outage: bool) -> io::Result<String> {
    match profile {
        Some(profile)
            if acknowledge_outage
                && !profile.is_empty()
                && profile.len() <= 64
                && profile.as_bytes()[0].is_ascii_alphanumeric()
                && profile
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)) =>
        {
            Ok(format!(
                "app-routing dns set {profile} --acknowledge-outage"
            ))
        }
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Нужны корректный профиль и подтверждение ограничения общего DNS",
        )),
        None => Ok("app-routing dns clear".into()),
    }
}

fn service_image_range(command: &[u16]) -> io::Result<std::ops::Range<usize>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Неоднозначный путь службы SCM");
    if command.is_empty() || command.contains(&0) {
        return Err(invalid());
    }
    let quoted = command[0] == u16::from(b'"');
    let start = usize::from(quoted);
    let end = if quoted {
        command[start..]
            .iter()
            .position(|unit| *unit == u16::from(b'"'))
            .map(|end| start + end)
            .ok_or_else(invalid)?
    } else {
        command
            .iter()
            .position(|unit| [u16::from(b' '), u16::from(b'\t')].contains(unit))
            .unwrap_or(command.len())
    };
    let image = &command[start..end];
    let tail = &command[end + usize::from(quoted)..];
    if image.len() < 7
        || !((u16::from(b'A')..=u16::from(b'Z')).contains(&image[0])
            || (u16::from(b'a')..=u16::from(b'z')).contains(&image[0]))
        || image[1..3] != [u16::from(b':'), u16::from(b'\\')]
        || !image[image.len() - 4..]
            .iter()
            .zip(b".exe")
            .all(|(unit, byte)| {
                *unit == u16::from(*byte) || *unit == u16::from(byte.to_ascii_uppercase())
            })
        || image.contains(&u16::from(b'"'))
        || tail
            .first()
            .is_some_and(|unit| ![u16::from(b' '), u16::from(b'\t')].contains(unit))
    {
        return Err(invalid());
    }
    Ok(start..end)
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;
    use crate::state::TrustedImage;
    use std::{
        ffi::OsString,
        mem,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::PathBuf,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{Com::*, Services::*, Threading::*},
        UI::Shell::*,
    };

    struct ServiceHandle(SC_HANDLE);
    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    fn service_handle(raw: SC_HANDLE) -> io::Result<ServiceHandle> {
        if raw.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(ServiceHandle(raw))
        }
    }
    fn stage_error(stage: &str, error: io::Error) -> io::Error {
        io::Error::new(error.kind(), format!("{stage}: {error}"))
    }
    fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }
    fn config_string(buffer: &[usize], value: *const u16) -> io::Result<&[u16]> {
        let base = buffer.as_ptr() as usize;
        let address = value as usize;
        let bytes = mem::size_of_val(buffer);
        let offset = address
            .checked_sub(base)
            .filter(|offset| *offset < bytes && *offset % 2 == 0)
            .ok_or(io::ErrorKind::InvalidData)?;
        let units = unsafe { std::slice::from_raw_parts(value, (bytes - offset) / 2) };
        let length = units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(&units[..length])
    }
    fn installed_control() -> io::Result<(TrustedImage, TrustedImage)> {
        let manager = service_handle(unsafe {
            OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT)
        })?;
        let name = wide("AivpnAppRouting");
        let service = service_handle(unsafe {
            OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_CONFIG)
        })?;
        let mut buffer = [0usize; 8192 / mem::size_of::<usize>()];
        let mut needed = 0;
        let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        if unsafe {
            QueryServiceConfigW(
                service.0,
                config,
                mem::size_of_val(&buffer) as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let config = unsafe { &*config };
        let account = String::from_utf16(config_string(&buffer, config.lpServiceStartName)?)
            .map_err(|_| io::ErrorKind::InvalidData)?;
        if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS
            || !(account.eq_ignore_ascii_case("LocalSystem")
                || account.eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM"))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Нужна установленная служба AIVPN от LocalSystem",
            ));
        }
        let command = config_string(&buffer, config.lpBinaryPathName)?;
        let range = service_image_range(command)?;
        let service_path = PathBuf::from(OsString::from_wide(&command[range]));
        let image = TrustedImage::open(&service_path)
            .map_err(|error| stage_error("Проверка файла службы", error))?;
        let control_path = service_path;
        let control = TrustedImage::open(&control_path)
            .map_err(|error| stage_error("Проверка административного клиента", error))?;
        Ok((image, control))
    }

    struct Com;
    impl Drop for Com {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }

    pub(super) fn execute(parameters: &str) -> io::Result<()> {
        // Файлы и предки удерживаются до завершения административного процесса.
        let (_service, control) = installed_control()
            .map_err(|error| stage_error("Подготовка изменения общего DNS", error))?;
        let initialized = unsafe {
            CoInitializeEx(
                ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if initialized < 0 {
            return Err(io::Error::other("Не удалось подготовить запрос UAC"));
        }
        let _com = Com;
        let verb = wide("runas");
        let shell_path = control
            .shell_path()
            .map_err(|error| stage_error("Подготовка пути для UAC", error))?;
        let file = wide(&shell_path);
        let directory = wide(shell_path.parent().ok_or(io::ErrorKind::InvalidData)?);
        let parameters = wide(parameters);
        let mut execute = SHELLEXECUTEINFOW {
            cbSize: mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: parameters.as_ptr(),
            lpDirectory: directory.as_ptr(),
            nShow: 0,
            ..Default::default()
        };
        if unsafe { ShellExecuteExW(&mut execute) } == 0 {
            return Err(stage_error(
                "Windows отклонила запрос UAC",
                io::Error::last_os_error(),
            ));
        }
        if execute.hProcess.is_null() {
            return Err(io::Error::other("Не получен процесс изменения DNS"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(execute.hProcess) };
        match unsafe { WaitForSingleObject(process.as_raw_handle(), 120_000) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Ожидание изменения DNS истекло. Перечитайте состояние службы",
                ))
            }
            _ => return Err(io::Error::last_os_error()),
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if code != 0 {
            return Err(io::Error::other(
                "Изменение общего DNS не подтверждено. Перечитайте состояние службы",
            ));
        }
        Ok(())
    }
}

/// Вызывается только после отказа службы обычному пользователю в изменении DNS.
#[cfg(target_os = "windows")]
pub fn set_shared_dns(profile: Option<&str>, acknowledge_outage: bool) -> io::Result<()> {
    native::execute(&dns_parameters(profile, acknowledge_outage)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_elevation_requires_acknowledgement_and_rejects_argument_injection() {
        assert_eq!(
            dns_parameters(Some("p123-456"), true).unwrap(),
            "app-routing dns set p123-456 --acknowledge-outage"
        );
        assert_eq!(
            dns_parameters(None, false).unwrap(),
            "app-routing dns clear"
        );
        assert!(dns_parameters(Some("p123-456"), false).is_err());
        for profile in ["", "--help", "p1 --help", "p1\"", "p1\0", "p1\np2", "p1&p2"] {
            assert!(dns_parameters(Some(profile), true).is_err(), "{profile:?}");
        }
        assert!(dns_parameters(Some(&"p".repeat(65)), true).is_err());
    }

    #[test]
    fn scm_image_must_be_an_unambiguous_absolute_executable() {
        for (command, expected) in [
            (
                r#""C:\Program Files\AIVPN\service.exe" --interface-guid test"#,
                r"C:\Program Files\AIVPN\service.exe",
            ),
            (
                r"C:\AIVPN\service.EXE --interface-guid test",
                r"C:\AIVPN\service.EXE",
            ),
        ] {
            let command: Vec<_> = command.encode_utf16().collect();
            let range = service_image_range(&command).unwrap();
            assert_eq!(String::from_utf16(&command[range]).unwrap(), expected);
        }
        for command in [
            r"C:\Program Files\AIVPN\service.exe",
            r#""C:\AIVPN\service.exe"x"#,
            r"service.exe",
            r"\\server\a\service.exe",
            "C:\\AIVPN\\service.exe\0",
            "",
            "\"C:\\service.exe",
        ] {
            assert!(
                service_image_range(&command.encode_utf16().collect::<Vec<_>>()).is_err(),
                "{command:?}"
            );
        }
    }
}
