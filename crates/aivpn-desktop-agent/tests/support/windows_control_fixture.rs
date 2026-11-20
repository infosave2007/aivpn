use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{Foundation::*, Security::*, System::Threading::*};
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn checked(v: i32) {
    assert_ne!(v, 0, "{}", io::Error::last_os_error());
}
pub fn own(h: HANDLE) -> OwnedHandle {
    assert!(!h.is_null() && h != INVALID_HANDLE_VALUE);
    unsafe { OwnedHandle::from_raw_handle(h) }
}
pub fn no_thread_token() {
    let mut token = ptr::null_mut();
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    assert_eq!(result, 0, "Writer не должен наследовать impersonation");
    assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
}
pub fn process_token() -> OwnedHandle {
    let mut token = ptr::null_mut();
    checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) });
    own(token)
}
pub fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> u32 {
    let mut value = 0u32;
    let mut size = 0;
    checked(unsafe {
        GetTokenInformation(token, class, (&mut value as *mut u32).cast(), 4, &mut size)
    });
    value
}
pub fn sid() -> String {
    let token = process_token();
    let mut buffer = [0u64; 64];
    let mut size = 0;
    checked(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            std::mem::size_of_val(&buffer) as u32,
            &mut size,
        )
    });
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut out = ptr::null_mut();
    checked(unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(user.User.Sid, &mut out)
    });
    let mut len = 0;
    unsafe {
        while *out.add(len) != 0 {
            len += 1;
        }
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(out, len) }).unwrap();
    unsafe {
        LocalFree(out.cast());
    }
    value
}
pub fn logon(user: &str, filtered: bool) -> OwnedHandle {
    let password = std::env::var("AIVPN_CONTROL_PASSWORD").unwrap();
    let mut token = ptr::null_mut();
    checked(unsafe {
        LogonUserW(
            wide(user).as_ptr(),
            wide(".").as_ptr(),
            wide(&password).as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    });
    let token = own(token);
    let elevation = token_u32(token.as_raw_handle(), TokenElevationType);
    let want_linked = (filtered && elevation == TokenElevationTypeFull as u32)
        || (!filtered && elevation == TokenElevationTypeLimited as u32);
    if !want_linked {
        return token;
    }
    let mut linked: TOKEN_LINKED_TOKEN = unsafe { std::mem::zeroed() };
    let mut size = 0;
    checked(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenLinkedToken,
            (&mut linked as *mut TOKEN_LINKED_TOKEN).cast(),
            std::mem::size_of_val(&linked) as u32,
            &mut size,
        )
    });
    own(linked.LinkedToken)
}
pub fn launch(token: HANDLE, role: &str, pipe: &str, state: &std::path::Path) {
    let executable = std::env::current_exe().unwrap();
    let mut command = wide(&format!(
        "\"{}\" --ignored --exact process_role_child --nocapture",
        executable.display()
    ));
    // Отдельное окружение дочернего процесса не меняет параллельные тесты.
    let mut env = std::env::vars()
        .filter(|(k, _)| !k.starts_with("AIVPN_CONTROL_"))
        .collect::<Vec<_>>();
    env.extend([
        ("AIVPN_CONTROL_ROLE".into(), role.into()),
        ("AIVPN_CONTROL_PIPE".into(), pipe.into()),
        ("AIVPN_CONTROL_STATE".into(), state.display().to_string()),
    ]);
    env.sort_by_key(|(k, _)| k.to_uppercase());
    let mut environment: Vec<u16> = env
        .into_iter()
        .flat_map(|(k, v)| wide(&format!("{k}={v}")))
        .collect();
    environment.push(0);
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    checked(unsafe {
        CreateProcessAsUserW(
            token,
            ptr::null(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment.as_ptr().cast(),
            wide("C:\\Users\\Public").as_ptr(),
            &startup,
            &mut process,
        )
    });
    let handle = own(process.hProcess);
    drop(own(process.hThread));
    assert_eq!(
        unsafe { WaitForSingleObject(handle.as_raw_handle(), 20000) },
        WAIT_OBJECT_0,
        "Дочерний процесс завис"
    );
    let mut exit = 1;
    checked(unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut exit) });
    let failure = std::fs::read_to_string(format!(
        "C:\\Users\\Public\\aivpn-control-task2-{role}.failure"
    ))
    .unwrap_or_default();
    assert_eq!(exit, 0, "Ошибка дочернего процесса {role}: {failure}");
}

pub fn resources() -> (u32, usize) {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let mut handles = 0;
    checked(unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handles) });
    let snapshot = own(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) });
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut count = 0;
    let mut result = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    while result != 0 {
        if entry.th32OwnerProcessID == std::process::id() {
            count += 1;
        }
        result = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    assert_eq!(unsafe { GetLastError() }, ERROR_NO_MORE_FILES);
    (handles, count)
}

pub fn forged_pipe(name: &str, admin: bool, sddl: Option<&str>) -> OwnedHandle {
    use windows_sys::Win32::{
        Security::Authorization::*, Storage::FileSystem::*, System::Pipes::*,
    };
    let mut descriptor = ptr::null_mut();
    if let Some(sddl) = sddl {
        checked(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        });
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateNamedPipeW(
            wide(&format!(
                "\\\\.\\pipe\\aivpn-{name}-{}",
                if admin { "admin" } else { "user" }
            ))
            .as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            if descriptor.is_null() {
                ptr::null()
            } else {
                &attributes
            },
        )
    };
    if !descriptor.is_null() {
        unsafe {
            LocalFree(descriptor);
        }
    }
    own(handle)
}

pub fn rejected_without_document(pipe: &impl AsRawHandle) {
    use windows_sys::Win32::System::Pipes::*;
    let mut available = 0;
    let result = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    };
    if result == 0 {
        assert!(matches!(
            unsafe { GetLastError() },
            ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED
        ));
    }
    assert_eq!(
        available, 0,
        "Клиент отправил данные неподтвержденному серверу"
    );
}
