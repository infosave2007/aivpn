use aivpn_desktop_policy::*;
use std::{
    num::NonZeroU32,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*, Security::*, Storage::FileSystem::*, System::Threading::*,
};

pub fn own(handle: HANDLE) -> OwnedHandle {
    assert!(
        !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        "{}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedHandle::from_raw_handle(handle) }
}
pub fn current() -> OwnedHandle {
    own(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, GetCurrentProcessId()) })
}
pub fn token(process: &OwnedHandle) -> OwnedHandle {
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) },
        0
    );
    own(token)
}
pub fn native_path(path: &Path) -> String {
    let file = std::fs::File::open(path).unwrap();
    let mut text = vec![0u16; 4096];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            text.as_mut_ptr(),
            text.len() as u32,
            VOLUME_NAME_NT,
        )
    };
    assert!(count > 0 && (count as usize) < text.len());
    String::from_utf16(&text[..count as usize])
        .unwrap()
        .to_lowercase()
}
pub fn policy(
    path: Option<&str>,
    action: u32,
    generation: u64,
    inherit: bool,
) -> (KernelPolicy, KernelBindings) {
    let selector = path
        .map(|path| Selector::Executable { path: path.into() })
        .unwrap_or(Selector::Any {});
    policy_selector(selector, action, generation, inherit)
}
pub fn policy_selector(
    selector: Selector,
    action: u32,
    generation: u64,
    inherit: bool,
) -> (KernelPolicy, KernelBindings) {
    policy_default(selector, action, generation, inherit, Action::Block {})
}
pub fn policy_default(
    selector: Selector,
    action: u32,
    generation: u64,
    inherit: bool,
    default_action: Action,
) -> (KernelPolicy, KernelBindings) {
    policy_selected(
        &[selector],
        &[0],
        action,
        generation,
        inherit,
        default_action,
    )
}

pub fn policy_paths(
    paths: &[String],
    order: &[usize],
    generation: u64,
) -> (KernelPolicy, KernelBindings) {
    let selectors = paths
        .iter()
        .map(|path| Selector::Executable { path: path.clone() })
        .collect::<Vec<_>>();
    policy_selected(&selectors, order, 2, generation, false, Action::System {})
}

fn policy_selected(
    selectors: &[Selector],
    order: &[usize],
    action: u32,
    generation: u64,
    inherit: bool,
    default_action: Action,
) -> (KernelPolicy, KernelBindings) {
    let authority = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-18".into(),
        },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Windows, [88; 16]);
    let profile = catalog
        .register(&authority, Owner::Machine {}, vec![])
        .unwrap();
    catalog.set_global_dns(&profile, &authority).unwrap();
    let selected = match action {
        0 => Action::System {},
        1 => Action::Block {},
        _ => Action::Vpn {
            profile: profile.clone(),
        },
    };
    let document = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "identity-unit".into(),
        generation,
        platform: Platform::Windows,
        owner: Owner::Machine {},
        default_action,
        dns: DnsPolicy::SharedVpn {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
        rules: order
            .iter()
            .map(|index| RuleDocument {
                id: format!("selected-{index}"),
                application: selectors[*index].clone(),
                destination: None,
                inherit_children: inherit,
                action: selected.clone(),
            })
            .collect(),
    };
    let policy = Policy::validate(document, &authority).unwrap();
    let mut bindings = KernelBindings::default();
    bindings
        .windows_owners
        .insert("S-1-5-18".into(), NonZeroU32::new(1).unwrap());
    bindings
        .profiles
        .insert(profile, NonZeroU32::new(2).unwrap());
    for (index, selector) in selectors.iter().enumerate() {
        match selector {
            Selector::Executable { path } => {
                bindings
                    .executables
                    .insert(path.clone(), NonZeroU32::new(3 + 2 * index as u32).unwrap());
            }
            Selector::WindowsPackage { sid } => {
                bindings
                    .packages
                    .insert(sid.clone(), NonZeroU32::new(4 + 2 * index as u32).unwrap());
            }
            Selector::Any {} => {}
        }
    }
    (
        KernelPolicy::compile(&policy, &catalog, &authority, &bindings).unwrap(),
        bindings,
    )
}
pub fn bind(
    session: &mut aivpn_desktop_agent::windows::driver::DriverSession,
    path: &str,
    bindings: &KernelBindings,
) {
    session.bind_token(&token(&current()), bindings).unwrap();
    session.bind_executable(path, bindings).unwrap();
}
pub struct ChildGuard(pub Child);
impl ChildGuard {
    pub fn handle(&self) -> OwnedHandle {
        let mut copy = ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.0.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut copy,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    0,
                )
            },
            0
        );
        own(copy)
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub fn child(path: &Path) -> ChildGuard {
    let mut command = Command::new(path);
    command
        .args(["--ignored", "--exact", "identity_child", "--test-threads=1"])
        .env("AIVPN_IDENTITY_HELPER", "hold")
        .env_remove("AIVPN_CONTROL_PASSWORD")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ChildGuard(command.spawn().unwrap())
}
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aivpn-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn copy(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct Suspended(pub OwnedHandle);
impl Drop for Suspended {
    fn drop(&mut self) {
        unsafe {
            TerminateProcess(self.0.as_raw_handle(), 0);
            WaitForSingleObject(self.0.as_raw_handle(), 5000);
        }
    }
}

pub fn suspended(path: &Path, user: Option<&OwnedHandle>, container: Option<PSID>) -> Suspended {
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut attribute_bytes = 0;
    unsafe {
        InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attribute_bytes);
    }
    let mut attributes = vec![0usize; attribute_bytes.div_ceil(std::mem::size_of::<usize>())];
    let mut capabilities = SECURITY_CAPABILITIES::default();
    let mut flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    if let Some(sid) = container {
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.as_mut_ptr().cast();
        assert_ne!(
            unsafe {
                InitializeProcThreadAttributeList(
                    startup.lpAttributeList,
                    1,
                    0,
                    &mut attribute_bytes,
                )
            },
            0
        );
        capabilities.AppContainerSid = sid;
        assert_ne!(
            unsafe {
                UpdateProcThreadAttribute(
                    startup.lpAttributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (&mut capabilities as *mut SECURITY_CAPABILITIES).cast(),
                    std::mem::size_of::<SECURITY_CAPABILITIES>(),
                    ptr::null_mut(),
                    ptr::null(),
                )
            },
            0
        );
        flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    let mut command: Vec<u16> = format!("\"{}\"\0", path.display()).encode_utf16().collect();
    let mut environment = [
        "SystemRoot",
        "SystemDrive",
        "WINDIR",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok().map(|value| (name, value)))
    .collect::<Vec<_>>();
    environment.sort_by_key(|(name, _)| name.to_uppercase());
    let mut environment = environment
        .into_iter()
        .flat_map(|(name, value)| {
            format!("{name}={value}\0")
                .encode_utf16()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    environment.push(0);
    let mut process = PROCESS_INFORMATION::default();
    let ok = unsafe {
        match user {
            Some(token) => CreateProcessAsUserW(
                token.as_raw_handle(),
                ptr::null(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                flags,
                environment.as_ptr().cast(),
                ptr::null(),
                &startup.StartupInfo,
                &mut process,
            ),
            None => CreateProcessW(
                ptr::null(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                flags,
                environment.as_ptr().cast(),
                ptr::null(),
                &startup.StartupInfo,
                &mut process,
            ),
        }
    };
    let error = std::io::Error::last_os_error();
    if container.is_some() {
        unsafe {
            DeleteProcThreadAttributeList(startup.lpAttributeList);
        }
    }
    assert_ne!(ok, 0, "{error}");
    drop(own(process.hThread));
    Suspended(own(process.hProcess))
}

pub struct ContainerSid(pub PSID, Vec<u16>);
impl ContainerSid {
    pub fn new() -> Self {
        #[link(name = "userenv")]
        unsafe extern "system" {
            fn CreateAppContainerProfile(
                name: *const u16,
                display: *const u16,
                description: *const u16,
                capabilities: *const SID_AND_ATTRIBUTES,
                count: u32,
                sid: *mut PSID,
            ) -> i32;
        }
        let name: Vec<u16> = format!(
            "AivpnIdentityTest{}{}\0",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
        .encode_utf16()
        .collect();
        let mut sid = ptr::null_mut();
        assert_eq!(
            unsafe {
                CreateAppContainerProfile(
                    name.as_ptr(),
                    name.as_ptr(),
                    name.as_ptr(),
                    ptr::null(),
                    0,
                    &mut sid,
                )
            },
            0
        );
        Self(sid, name)
    }
    pub fn text(&self) -> String {
        let mut text = ptr::null_mut();
        assert_ne!(
            unsafe {
                windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(
                    self.0, &mut text,
                )
            },
            0
        );
        let mut length = 0;
        unsafe {
            while *text.add(length) != 0 {
                length += 1;
            }
        }
        let result =
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap();
        unsafe {
            LocalFree(text.cast());
        }
        result
    }
}
impl Drop for ContainerSid {
    fn drop(&mut self) {
        #[link(name = "userenv")]
        unsafe extern "system" {
            fn DeleteAppContainerProfile(name: *const u16) -> i32;
        }
        unsafe {
            FreeSid(self.0);
            let result = DeleteAppContainerProfile(self.1.as_ptr());
            assert_eq!(result, 0, "Удаление собственного AppContainer profile");
        }
    }
}

pub fn request_path(request: &mut [u8], path: &str) {
    let wide: Vec<u16> = path.encode_utf16().collect();
    request[120..124].copy_from_slice(&(wide.len() as u32).to_le_bytes());
    for (index, unit) in wide.iter().enumerate() {
        request[128 + 2 * index..130 + 2 * index].copy_from_slice(&unit.to_le_bytes());
    }
}

pub fn replace(source: &Path, destination: &Path) {
    let wide = |path: &Path| {
        path.as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>()
    };
    let source = wide(source);
    let destination = wide(destination);
    let handle = own(unsafe {
        CreateFileW(
            source.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    });
    let size = std::mem::size_of::<FILE_RENAME_INFO>() + destination.len() * 2;
    let mut data = vec![0u64; size.div_ceil(8)];
    let rename = data.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        // FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS, WDK ntifs.h.
        (*rename).Anonymous.Flags = 3;
        (*rename).FileNameLength = ((destination.len() - 1) * 2) as u32;
        ptr::copy_nonoverlapping(
            destination.as_ptr(),
            (*rename).FileName.as_mut_ptr(),
            destination.len(),
        );
    }
    assert_ne!(
        unsafe {
            SetFileInformationByHandle(
                handle.as_raw_handle(),
                FileRenameInfoEx,
                data.as_ptr().cast(),
                size as u32,
            )
        },
        0,
        "Штатный updater должен заменить выбранный path: {}",
        std::io::Error::last_os_error()
    );
}
pub fn junction(link: &Path, destination: &Path) {
    let status = Command::new("C:\\Windows\\System32\\cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(destination)
        .env_remove("AIVPN_CONTROL_PASSWORD")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}
