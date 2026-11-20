use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};

pub const QUERY: u32 = (0x12 << 16) | (3 << 14) | (0x900 << 2);
pub const STAGE: u32 = QUERY + 4;
pub const POLICY_BYTES: usize = 40 + 56 * 256;

pub fn request(session: u64, size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    bytes[8..16].copy_from_slice(&session.to_le_bytes());
    bytes
}

pub fn ioctl(
    handle: &OwnedHandle,
    code: u32,
    bytes: &[u8],
    capacity: usize,
) -> io::Result<Vec<u8>> {
    let mut output = vec![0u8; capacity];
    let mut returned = 0;
    let result = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            handle.as_raw_handle(),
            code,
            bytes.as_ptr().cast(),
            bytes.len() as u32,
            output.as_mut_ptr().cast(),
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    output.truncate(returned as usize);
    Ok(output)
}

pub fn query(handle: &OwnedHandle, session: u64) -> Vec<u8> {
    ioctl(handle, QUERY, &request(session, 24), 48).unwrap()
}

pub fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

pub fn wide_word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

pub fn open() -> io::Result<OwnedHandle> {
    open_with("", GENERIC_READ | GENERIC_WRITE, 0)
}

pub fn open_with(suffix: &str, access: u32, flags: u32) -> io::Result<OwnedHandle> {
    let path: Vec<u16> = format!("\\\\.\\AivpnAppRouting{suffix}\0")
        .encode_utf16()
        .collect();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

pub fn policy(generation: u64) -> aivpn_desktop_policy::KernelPolicy {
    use aivpn_desktop_policy::*;
    use std::num::NonZeroU32;
    let authority = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-18".into(),
        },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Windows, [51; 16]);
    let id = catalog
        .register(&authority, authority.user.clone(), vec![])
        .unwrap();
    catalog.set_global_dns(&id, &authority).unwrap();
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "driver-check".into(),
            generation,
            platform: Platform::Windows,
            owner: authority.user.clone(),
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: id.clone(),
                acknowledge_outage: true,
            },
            rules: vec![RuleDocument {
                id: "selected".into(),
                application: Selector::Executable {
                    path: "\\device\\harddiskvolume3\\example\\app.exe".into(),
                },
                destination: Some("192.0.2.0/24".into()),
                inherit_children: true,
                action: Action::Vpn {
                    profile: id.clone(),
                },
            }],
        },
        &authority,
    )
    .unwrap();
    let mut bindings = KernelBindings::default();
    bindings
        .windows_owners
        .insert("S-1-5-18".into(), NonZeroU32::new(13).unwrap());
    bindings.profiles.insert(id, NonZeroU32::new(17).unwrap());
    bindings.executables.insert(
        "\\device\\harddiskvolume3\\example\\app.exe".into(),
        NonZeroU32::new(19).unwrap(),
    );
    KernelPolicy::compile(&policy, &catalog, &authority, &bindings).unwrap()
}

pub fn stage_request(session: u64, generation: u64) -> Vec<u8> {
    let mut bytes = request(session, 24 + POLICY_BYTES);
    bytes[24..].copy_from_slice(&policy(generation).to_native_bytes());
    bytes
}

pub fn system_child(role: &str, inherited: Option<&OwnedHandle>) {
    use windows_sys::Win32::System::Threading::*;
    let executable = std::env::current_exe().unwrap();
    let mut command = format!(
        "\"{}\" --ignored --exact system_process_child --nocapture\0",
        executable.display()
    )
    .encode_utf16()
    .collect::<Vec<_>>();
    let mut environment = std::env::vars()
        .filter(|(key, _)| !key.starts_with("AIVPN_DRIVER_") && !key.starts_with("AIVPN_CONTROL_"))
        .collect::<Vec<_>>();
    environment.push(("AIVPN_DRIVER_ROLE".into(), role.into()));
    if let Some(handle) = inherited {
        assert_ne!(
            unsafe {
                SetHandleInformation(
                    handle.as_raw_handle(),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            },
            0
        );
        environment.push((
            "AIVPN_DRIVER_HANDLE".into(),
            (handle.as_raw_handle() as usize).to_string(),
        ));
    }
    environment.sort_by_key(|(key, _)| key.to_uppercase());
    let mut env = environment
        .into_iter()
        .flat_map(|(key, value)| {
            format!("{key}={value}\0")
                .encode_utf16()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    env.push(0);
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            ptr::null(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            i32::from(inherited.is_some()),
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            env.as_ptr().cast(),
            ptr::null(),
            &startup,
            &mut process,
        )
    };
    if let Some(handle) = inherited {
        assert_ne!(
            unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) },
            0
        );
    }
    assert_ne!(created, 0, "{}", io::Error::last_os_error());
    let handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    drop(unsafe { OwnedHandle::from_raw_handle(process.hThread) });
    assert_eq!(
        unsafe { WaitForSingleObject(handle.as_raw_handle(), 15000) },
        WAIT_OBJECT_0
    );
    let mut exit = 1;
    assert_ne!(
        unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut exit) },
        0
    );
    assert_eq!(
        exit, 0,
        "Дочерний процесс SYSTEM завершился с ошибкой: {role}"
    );
}
