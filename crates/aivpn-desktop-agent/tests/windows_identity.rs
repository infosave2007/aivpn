#![cfg(target_os = "windows")]

#[path = "support/windows_driver_fixture.rs"]
#[allow(dead_code)]
mod fixture;

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn diagnostic_uses_os_identity_without_activating_enforcement() {
    use aivpn_desktop_agent::windows::driver::{DiagnosticAction, DriverSession};
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::*;
    let process = unsafe {
        OwnedHandle::from_raw_handle(OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            GetCurrentProcessId(),
        ))
    };
    let mut session = DriverSession::open().unwrap();
    session.stage(&fixture::policy(1)).unwrap();
    let result = session.diagnose(&process, "192.0.2.1".parse().unwrap());
    assert!(
        result.is_err(),
        "Непривязанные номера policy не дают решение"
    );
    let _ = DiagnosticAction::System;
}

#[path = "support/windows_identity_fixture.rs"]
mod os;
use aivpn_desktop_agent::windows::driver::{DiagnosticAction, DriverSession};
use std::os::windows::io::AsRawHandle;

#[test]
#[ignore = "Дочерний helper запускается родителем с обязательным окружением"]
fn identity_child() {
    assert_eq!(std::env::var("AIVPN_IDENTITY_HELPER").unwrap(), "hold");
    std::thread::sleep(std::time::Duration::from_secs(30));
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn actual_image_token_and_policy_changes_have_real_consumer() {
    let path = os::native_path(&std::env::current_exe().unwrap());
    let mut session = DriverSession::open().unwrap();
    let process = os::current();
    let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let mut file_identity = windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO::default();
    accounts::checked(unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx(
            file.as_raw_handle(),
            windows_sys::Win32::Storage::FileSystem::FileIdInfo,
            (&mut file_identity as *mut windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO)
                .cast(),
            std::mem::size_of_val(&file_identity) as u32,
        )
    });
    let mut created = windows_sys::Win32::Foundation::FILETIME::default();
    let mut unused = [windows_sys::Win32::Foundation::FILETIME::default(); 3];
    accounts::checked(unsafe {
        windows_sys::Win32::System::Threading::GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut unused[0],
            &mut unused[1],
            &mut unused[2],
        )
    });
    for (generation, selected, expected) in [
        (1, 0, DiagnosticAction::System),
        (2, 1, DiagnosticAction::Block),
        (3, 2, DiagnosticAction::VpnNotReady),
    ] {
        let (policy, bindings) = os::policy(Some(&path), selected, generation, false);
        os::bind(&mut session, &path, &bindings);
        session.stage(&policy).unwrap();
        for destination in ["192.0.2.1", "2001:db8::1"] {
            let diagnostic = session
                .diagnose(&process, destination.parse().unwrap())
                .unwrap();
            assert_eq!(diagnostic.action, expected);
            assert_eq!(diagnostic.generation.get(), generation);
            assert_eq!(diagnostic.rule, Some(0));
            assert_eq!(diagnostic.depth, 0);
            assert_eq!(diagnostic.user_sid, "S-1-5-18");
            assert_eq!(diagnostic.package_sid, None);
            assert_eq!(diagnostic.owner_slot, 1);
            assert_eq!(diagnostic.executable_slot, 3);
            assert!(
                diagnostic.os_image_available
                    && diagnostic.policy_image_resolved
                    && !diagnostic.unresolved
            );
            assert_ne!(diagnostic.file_id, [0; 16]);
            assert_eq!(diagnostic.file_id, file_identity.FileId.Identifier);
            assert_eq!(diagnostic.volume, file_identity.VolumeSerialNumber);
            assert_eq!(
                diagnostic.created,
                (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
            );
        }
    }
    for destination in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        assert_eq!(
            session
                .diagnose(&process, destination.parse().unwrap())
                .unwrap()
                .action,
            DiagnosticAction::System
        );
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn inherited_identity_is_available_before_child_code_and_handles_do_not_retarget() {
    let scratch = os::Scratch::new();
    let copy = scratch.copy("child.exe");
    let path = os::native_path(&std::env::current_exe().unwrap());
    let (policy, bindings) = os::policy(Some(&path), 0, 1, true);
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    let mut child = os::child(&copy);
    let handle = child.handle();
    let first = session
        .diagnose(&handle, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(first.action, DiagnosticAction::System);
    assert_eq!(first.executable_slot, 0);
    assert_eq!(first.depth, 1);
    assert!(first.policy_image_resolved);
    accounts::checked(unsafe {
        windows_sys::Win32::System::Threading::TerminateProcess(child.0.as_raw_handle(), 259)
    });
    child.0.wait().unwrap();
    assert!(session
        .diagnose(&handle, "192.0.2.1".parse().unwrap())
        .is_err());
    let next = os::child(&copy);
    let second = session
        .diagnose(&next.handle(), "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_ne!(first.created, second.created);
    assert_eq!(first.file_id, second.file_id);
    assert!(session
        .diagnose(&handle, "192.0.2.1".parse().unwrap())
        .is_err());
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn atomic_replacement_preserves_rule_and_hardlink_without_blocking_other_apps() {
    use aivpn_desktop_policy::{Action, Selector};
    let scratch = os::Scratch::new();
    let executable = scratch.copy("selected.exe");
    let replacement = scratch.copy("replacement.exe");
    let other = scratch.copy("other.exe");
    let alias = scratch.0.join("alias.exe");
    std::fs::hard_link(&executable, &alias).unwrap();
    let path = os::native_path(&executable);
    let (policy, mut bindings) = os::policy_default(
        Selector::Executable { path: path.clone() },
        2,
        1,
        false,
        Action::System {},
    );
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    for image in [&executable, &alias] {
        let child = os::suspended(image, None, None);
        assert_eq!(
            session
                .diagnose(&child.0, "192.0.2.1".parse().unwrap())
                .unwrap()
                .action,
            DiagnosticAction::VpnNotReady
        );
    }
    assert!(std::fs::OpenOptions::new()
        .write(true)
        .open(&executable)
        .is_err());
    os::replace(&replacement, &executable);
    let replaced = os::suspended(&executable, None, None);
    let diagnostic = session
        .diagnose(&replaced.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert!(diagnostic.os_image_available && diagnostic.os_path_available);
    assert!(!diagnostic.policy_image_resolved && diagnostic.unresolved);
    assert_eq!(diagnostic.action, DiagnosticAction::Block);
    assert_eq!(diagnostic.executable_slot, 0);
    let unrelated = os::suspended(&other, None, None);
    assert_eq!(
        session
            .diagnose(&unrelated.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::System
    );
    let old_alias = os::suspended(&alias, None, None);
    assert_eq!(
        session
            .diagnose(&old_alias.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::VpnNotReady
    );
    let alias_path = os::native_path(&alias);
    bindings
        .executables
        .insert(alias_path.clone(), std::num::NonZeroU32::new(4).unwrap());
    assert!(session.bind_executable(&alias_path, &bindings).is_err());
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn malformed_identity_requests_handles_and_stale_sessions_are_denied() {
    use windows_sys::Win32::System::Threading::*;
    let device = fixture::open().unwrap();
    let session = fixture::wide_word(&fixture::query(&device, 0), 8);
    let mut binding = fixture::request(session, 8320);
    os::request_path(
        &mut binding,
        &os::native_path(&std::env::current_exe().unwrap()),
    );
    binding[24] = 1;
    binding[28] = 1;
    let event = os::own(unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) });
    for handle in [
        event.as_raw_handle() as u64,
        0,
        u64::MAX,
        0xffff_8000_0000_0004,
    ] {
        binding[32..40].copy_from_slice(&handle.to_le_bytes());
        assert!(fixture::ioctl(&device, fixture::QUERY + 8, &binding, 48).is_err());
    }
    let process = os::current();
    let mut request = fixture::request(session, 56);
    request[24..32].copy_from_slice(&(process.as_raw_handle() as u64).to_le_bytes());
    request[32] = 4;
    request[40] = 192;
    let (policy, _) = os::policy(None, 0, 1, false);
    let mut stage = fixture::request(session, 14400);
    stage[24..].copy_from_slice(&policy.to_native_bytes());
    fixture::ioctl(&device, fixture::STAGE, &stage, 48).unwrap();
    assert_eq!(
        fixture::ioctl(&device, fixture::QUERY + 12, &request, 264)
            .unwrap()
            .len(),
        264
    );
    for offset in [0, 4, 8, 16, 20, 32, 36, 44] {
        let mut bad = request.clone();
        bad[offset] ^= 0xff;
        assert!(
            fixture::ioctl(&device, fixture::QUERY + 12, &bad, 264).is_err(),
            "offset={offset}"
        );
    }
    for length in [0, 55, 57, 65536] {
        let mut bad = request.clone();
        bad.resize(length, 0);
        assert!(fixture::ioctl(&device, fixture::QUERY + 12, &bad, 264).is_err());
    }
    for capacity in [0, 263, 265, 65536] {
        assert!(fixture::ioctl(&device, fixture::QUERY + 12, &request, capacity).is_err());
    }
    let limited = os::own(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, GetCurrentProcessId()) });
    for handle in [event.as_raw_handle(), limited.as_raw_handle()] {
        request[24..32].copy_from_slice(&(handle as u64).to_le_bytes());
        assert!(fixture::ioctl(&device, fixture::QUERY + 12, &request, 264).is_err());
    }
    let (vpn, _) = os::policy(None, 2, 2, false);
    stage[24..].copy_from_slice(&vpn.to_native_bytes());
    fixture::ioctl(&device, fixture::STAGE, &stage, 48).unwrap();
    request[24..32].copy_from_slice(&(process.as_raw_handle() as u64).to_le_bytes());
    request[32] = 6;
    request[40..56].copy_from_slice(
        &"::ffff:127.0.0.1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    let mapped = fixture::ioctl(&device, fixture::QUERY + 12, &request, 264).unwrap();
    assert_eq!(fixture::word(&mapped, 24), 0);
    assert_eq!(fixture::word(&mapped, 28), 0);
    assert_eq!(fixture::word(&fixture::query(&device, session), 40), 0);
}

#[path = "support/windows_control_fixture.rs"]
#[allow(dead_code)]
mod accounts;

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn suspended_launch_and_owner_transition_use_actual_tokens() {
    let scratch = os::Scratch::new();
    let copy = scratch.copy("other-user.exe");
    let path = os::native_path(&std::env::current_exe().unwrap());
    let (policy, bindings) = os::policy(Some(&path), 0, 1, true);
    let mut session = DriverSession::open().unwrap();
    session.bind_executable(&path, &bindings).unwrap();
    session.stage(&policy).unwrap();
    let same = os::suspended(&copy, None, None);
    let diagnostic = session
        .diagnose(&same.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(diagnostic.action, DiagnosticAction::System);
    assert_eq!(diagnostic.depth, 1);
    let user = accounts::logon("AivpnDriverUser", false);
    let other = os::suspended(&copy, Some(&user), None);
    let diagnostic = session
        .diagnose(&other.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(diagnostic.action, DiagnosticAction::Block);
    assert_ne!(diagnostic.user_sid, "S-1-5-18");
    assert_eq!(diagnostic.owner_slot, 0);
    assert_eq!(diagnostic.parent_count, 0);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn appcontainer_package_is_read_from_the_real_process_token() {
    let sid = os::ContainerSid::new();
    let process = os::suspended(
        std::path::Path::new("C:\\Windows\\System32\\cmd.exe"),
        None,
        Some(sid.0),
    );
    let (policy, mut bindings) = os::policy_selector(
        aivpn_desktop_policy::Selector::WindowsPackage { sid: sid.text() },
        0,
        1,
        false,
    );
    bindings.windows_owners.clear();
    let mut session = DriverSession::open().unwrap();
    session
        .bind_token(&os::token(&process.0), &bindings)
        .unwrap();
    session.stage(&policy).unwrap();
    let diagnostic = session
        .diagnose(&process.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(diagnostic.package_sid, Some(sid.text()));
    assert_eq!(diagnostic.package_slot, 4);
    assert_eq!(diagnostic.action, DiagnosticAction::System);
    assert_eq!(diagnostic.rule, Some(0));
    let ordinary = os::suspended(
        std::path::Path::new("C:\\Windows\\System32\\cmd.exe"),
        None,
        None,
    );
    assert_eq!(
        session
            .diagnose(&ordinary.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::Block
    );
    assert!(diagnostic.policy_image_resolved);
    assert_eq!(diagnostic.user_sid, "S-1-5-18");
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn preexisting_process_is_explicitly_unresolved() {
    use windows_sys::Win32::System::Threading::*;
    let pid = std::env::var("AIVPN_IDENTITY_EXISTING_PID")
        .expect("PID процесса, запущенного до загрузки драйвера")
        .parse()
        .unwrap();
    let existing = os::own(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    let path = os::native_path(&std::env::current_exe().unwrap());
    let (policy, bindings) = os::policy(Some(&path), 0, 1, true);
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    let result = session
        .diagnose(&existing, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert!(!result.policy_image_resolved);
    assert!(result.unresolved);
    assert_eq!(result.action, DiagnosticAction::Block);
    assert_eq!(result.executable_slot, 0);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn repeated_bind_evaluate_exit_and_cleanup_release_resources() {
    let scratch = os::Scratch::new();
    let copy = scratch.copy("repeated.exe");
    let path = os::native_path(&copy);
    let (policy, bindings) = os::policy(Some(&path), 0, 1, false);
    let cycle = || {
        let mut session = DriverSession::open().unwrap();
        os::bind(&mut session, &path, &bindings);
        session.stage(&policy).unwrap();
        let child = os::suspended(&copy, None, None);
        assert_eq!(
            session
                .diagnose(&child.0, "192.0.2.1".parse().unwrap())
                .unwrap()
                .action,
            DiagnosticAction::System
        );
        drop(child);
        drop(session);
        let moved = scratch.0.join("moved.exe");
        std::fs::rename(&copy, &moved).unwrap();
        std::fs::rename(&moved, &copy).unwrap();
    };
    for _ in 0..16 {
        cycle();
    }
    let before = accounts::resources();
    for batch in 1..=3 {
        for _ in 0..64 {
            cycle();
        }
        let after = accounts::resources();
        println!("resource batch={batch} baseline={before:?} after={after:?}");
        assert!(after.0 <= before.0 + 2, "handles {before:?} -> {after:?}");
        assert_eq!(before.1, after.1);
    }
}

#[test]
#[ignore = "Дочерний helper запускается родителем с обязательным окружением"]
fn identity_chain_child() {
    let remaining: u32 = std::env::var("AIVPN_IDENTITY_CHAIN")
        .expect("Окружение задает родитель")
        .parse()
        .unwrap();
    assert!(remaining <= 33);
    let marker = std::path::PathBuf::from(std::env::var("AIVPN_IDENTITY_MARKER").unwrap());
    if remaining == 0 {
        std::fs::write(&marker, std::process::id().to_string()).unwrap();
    } else {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "identity_chain_child",
                "--test-threads=1",
            ])
            .env("AIVPN_IDENTITY_CHAIN", (remaining - 1).to_string())
            .env_remove("AIVPN_CONTROL_PASSWORD")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        assert!(child.wait().unwrap().success());
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !marker.with_extension("release").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn inherited_identity_has_a_flat_32_generation_limit() {
    use windows_sys::Win32::System::Threading::*;
    let scratch = os::Scratch::new();
    let copy = scratch.copy("chain.exe");
    let path = os::native_path(&std::env::current_exe().unwrap());
    let (policy, bindings) = os::policy(Some(&path), 0, 1, true);
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    for depth in [32, 33] {
        let marker = scratch.0.join(format!("chain-{depth}"));
        let mut child = std::process::Command::new(&copy)
            .args([
                "--ignored",
                "--exact",
                "identity_chain_child",
                "--test-threads=1",
            ])
            .env("AIVPN_IDENTITY_CHAIN", (depth - 1).to_string())
            .env("AIVPN_IDENTITY_MARKER", &marker)
            .env_remove("AIVPN_CONTROL_PASSWORD")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while !marker.exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let pid = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
            let handle = os::own(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
            let diagnostic = session
                .diagnose(&handle, "192.0.2.1".parse().unwrap())
                .unwrap();
            assert_eq!(diagnostic.parent_count, 32);
            assert_eq!(
                diagnostic.action,
                if depth == 32 {
                    DiagnosticAction::System
                } else {
                    DiagnosticAction::Block
                }
            );
            if depth == 32 {
                assert_eq!(diagnostic.depth, 32);
            }
        }));
        std::fs::write(marker.with_extension("release"), "release").unwrap();
        assert!(child.wait().unwrap().success());
        result.unwrap();
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn binding_capacity_idempotency_and_cleanup_are_bounded() {
    use windows_sys::Win32::Storage::FileSystem::*;
    let scratch = os::Scratch::new();
    let device = fixture::open().unwrap();
    let session = fixture::wide_word(&fixture::query(&device, 0), 8);
    for index in 0..258u32 {
        let path = scratch.0.join(format!("file-{index}"));
        std::fs::write(&path, []).unwrap();
        let wide: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        let file = os::own(unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        });
        let mut request = fixture::request(session, 8320);
        os::request_path(&mut request, &os::native_path(&path));
        request[24] = 1;
        request[28..32].copy_from_slice(&(1000 + index).to_le_bytes());
        request[32..40].copy_from_slice(&(file.as_raw_handle() as u64).to_le_bytes());
        let result = fixture::ioctl(&device, fixture::QUERY + 8, &request, 48);
        assert_eq!(
            result.is_ok(),
            index < 257,
            "index={index}, result={result:?}"
        );
        if index == 256 {
            assert!(fixture::ioctl(&device, fixture::QUERY + 8, &request, 48).is_ok());
        }
    }
    drop(device);
    std::fs::remove_dir_all(&scratch.0).unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn identity_ioctl_does_not_bypass_impersonation_or_token_verification() {
    use windows_sys::Win32::Security::*;
    let device = fixture::open().unwrap();
    let session = fixture::wide_word(&fixture::query(&device, 0), 8);
    let token = os::token(&os::current());
    let mut bind = fixture::request(session, 8320);
    bind[24] = 2;
    bind[28] = 1;
    bind[40] = 12;
    bind[32..40].copy_from_slice(&(token.as_raw_handle() as u64).to_le_bytes());
    bind[48..60].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0]);
    assert!(fixture::ioctl(&device, fixture::QUERY + 8, &bind, 48).is_err());
    bind[56] = 18;
    assert!(fixture::ioctl(&device, fixture::QUERY + 8, &bind, 48).is_ok());
    for offset in [24, 28, 40, 44, 49, 115, 116] {
        let mut bad = bind.clone();
        bad[offset] = if offset == 28 { 0 } else { 255 };
        assert!(
            fixture::ioctl(&device, fixture::QUERY + 8, &bad, 48).is_err(),
            "offset={offset}"
        );
    }
    accounts::checked(unsafe { ImpersonateSelf(SecurityImpersonation) });
    let result = std::panic::catch_unwind(|| {
        assert_eq!(
            fixture::ioctl(&device, fixture::QUERY + 8, &bind, 48)
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
        let mut diagnostic = fixture::request(session, 56);
        diagnostic[32] = 4;
        assert_eq!(
            fixture::ioctl(&device, fixture::QUERY + 12, &diagnostic, 264)
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
    });
    accounts::checked(unsafe { RevertToSelf() });
    result.unwrap();
}

#[test]
#[ignore = "Дочерний helper запускается родителем с обязательным окружением"]
fn identity_crash_child() {
    let path = std::env::var("AIVPN_IDENTITY_CRASH_PATH").expect("Окружение задает родитель");
    let path = os::native_path(std::path::Path::new(&path));
    let (policy, bindings) = os::policy(Some(&path), 0, 1, false);
    let mut session = DriverSession::open().unwrap();
    session.bind_executable(&path, &bindings).unwrap();
    session.stage(&policy).unwrap();
    std::process::exit(0);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn service_process_exit_releases_binding_without_rust_destructors() {
    let scratch = os::Scratch::new();
    let copy = scratch.copy("crash-bound.exe");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "identity_crash_child",
            "--test-threads=1",
        ])
        .env("AIVPN_IDENTITY_CRASH_PATH", &copy)
        .env_remove("AIVPN_CONTROL_PASSWORD")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::rename(&copy, scratch.0.join("released.exe")).unwrap();
    let mut session = DriverSession::open().unwrap();
    assert_eq!(
        session.status().unwrap().state,
        aivpn_desktop_agent::windows::driver::StagedState::Empty
    );
}

#[test]
#[ignore = "Дочерний helper запускается родителем с обязательным окружением"]
#[expect(
    clippy::zombie_processes,
    reason = "Создатель должен завершиться раньше потомка, который проверяется и завершается родительским тестом"
)]
fn identity_orphan_creator() {
    let child_path =
        std::env::var("AIVPN_IDENTITY_ORPHAN_PATH").expect("Окружение задает родитель");
    let marker = std::env::var("AIVPN_IDENTITY_ORPHAN_MARKER").unwrap();
    let child = std::process::Command::new(child_path)
        .args(["--ignored", "--exact", "identity_child", "--test-threads=1"])
        .env("AIVPN_IDENTITY_HELPER", "hold")
        .env_remove("AIVPN_CONTROL_PASSWORD")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::fs::write(marker, child.id().to_string()).unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn exited_creator_keeps_its_identity_for_living_descendant() {
    let scratch = os::Scratch::new();
    let child_path = scratch.copy("orphan.exe");
    let marker = scratch.0.join("orphan-pid");
    let path = os::native_path(&std::env::current_exe().unwrap());
    let (policy, bindings) = os::policy(Some(&path), 0, 1, true);
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    let descendant = launch_orphan(&std::env::current_exe().unwrap(), &child_path, &marker);
    let diagnostic = session
        .diagnose(&descendant.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(diagnostic.action, DiagnosticAction::System);
    assert_eq!(diagnostic.depth, 1);
    assert_eq!(diagnostic.executable_slot, 0);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn parent_directory_replacement_cannot_fall_back_to_system() {
    use aivpn_desktop_policy::{Action, Selector};
    let scratch = os::Scratch::new();
    let directory = scratch.0.join("selected");
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("app.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let path = os::native_path(&executable);
    let (policy, bindings) = os::policy_default(
        Selector::Executable { path: path.clone() },
        2,
        1,
        false,
        Action::System {},
    );
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    // NTFS не переименовывает каталог с открытым потомком. Updater сначала переносит файл.
    os::replace(&executable, &scratch.0.join("retained.exe"));
    os::replace(&directory, &scratch.0.join("old-directory"));
    std::fs::create_dir(&directory).unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let child = os::suspended(&executable, None, None);
    let result = session
        .diagnose(&child.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert!(result.os_image_available && !result.policy_image_resolved && result.unresolved);
    assert_eq!(result.action, DiagnosticAction::Block);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn junction_revalidation_and_sticky_negative_marker_do_not_grant_new_image() {
    use aivpn_desktop_policy::{Action, Selector};
    let scratch = os::Scratch::new();
    let old = scratch.0.join("old");
    let new = scratch.0.join("new");
    let link = scratch.0.join("link");
    for directory in [&old, &new] {
        std::fs::create_dir(directory).unwrap();
        std::fs::copy(std::env::current_exe().unwrap(), directory.join("app.exe")).unwrap();
    }
    os::junction(&link, &old);
    let path = os::native_path(&old.join("app.exe")).replace("\\old\\app.exe", "\\link\\app.exe");
    let (policy, bindings) = os::policy_default(
        Selector::Executable { path: path.clone() },
        2,
        1,
        false,
        Action::System {},
    );
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    let initial = os::suspended(&link.join("app.exe"), None, None);
    assert_eq!(
        session
            .diagnose(&initial.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::VpnNotReady
    );
    drop(initial);
    std::fs::remove_dir(&link).unwrap();
    os::junction(&link, &new);
    let replacement = os::suspended(&link.join("app.exe"), None, None);
    let result = session
        .diagnose(&replacement.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert!(result.os_image_available && !result.policy_image_resolved && result.unresolved);
    assert_eq!(result.action, DiagnosticAction::Block);
    std::fs::remove_dir(&link).unwrap();
    os::junction(&link, &old);
    assert_eq!(
        session
            .diagnose(&replacement.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::Block
    );
    std::fs::remove_dir(&link).unwrap();
    os::junction(&link, &new);
    let before_first_observation = os::suspended(&link.join("app.exe"), None, None);
    std::fs::remove_dir(&link).unwrap();
    os::junction(&link, &old);
    assert_eq!(
        session
            .diagnose(&before_first_observation.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::Block,
        "Смена junction обратно до первого DIAGNOSE не возвращает SYSTEM"
    );
    std::fs::remove_dir(&link).unwrap();
}

fn two_alias_policy_case(initial_selected: &[usize], observe_before_restore: bool) {
    let scratch = os::Scratch::new();
    let directories = [
        scratch.0.join("a"),
        scratch.0.join("b"),
        scratch.0.join("new"),
    ];
    for directory in &directories {
        std::fs::create_dir(directory).unwrap();
        std::fs::copy(std::env::current_exe().unwrap(), directory.join("app.exe")).unwrap();
    }
    let other = scratch.copy("unrelated.exe");
    let aliases = [scratch.0.join("link-a"), scratch.0.join("link-b")];
    for index in 0..2 {
        os::junction(&aliases[index], &directories[index]);
    }
    let paths = [
        os::native_path(&directories[0].join("app.exe"))
            .replace("\\a\\app.exe", "\\link-a\\app.exe"),
        os::native_path(&directories[1].join("app.exe"))
            .replace("\\b\\app.exe", "\\link-b\\app.exe"),
    ];
    let (policy, bindings) = os::policy_paths(&paths, initial_selected, 1);
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &paths[0], &bindings);
    session.bind_executable(&paths[1], &bindings).unwrap();
    session.stage(&policy).unwrap();
    for alias in &aliases {
        std::fs::remove_dir(alias).unwrap();
        os::junction(alias, &directories[2]);
    }
    let launch = if observe_before_restore {
        directories[2].join("app.exe")
    } else {
        aliases[1].join("app.exe")
    };
    let child = os::suspended(&launch, None, None);
    if observe_before_restore {
        assert_eq!(
            session
                .diagnose(&child.0, "192.0.2.1".parse().unwrap())
                .unwrap()
                .action,
            DiagnosticAction::Block
        );
    }
    for index in 0..2 {
        std::fs::remove_dir(&aliases[index]).unwrap();
        os::junction(&aliases[index], &directories[index]);
    }
    for (generation, selected) in [(2, vec![1]), (3, vec![]), (4, vec![1])] {
        let (policy, _) = os::policy_paths(&paths, &selected, generation);
        session.stage(&policy).unwrap();
        let diagnostic = session
            .diagnose(&child.0, "192.0.2.1".parse().unwrap())
            .unwrap();
        if selected.is_empty() {
            assert_eq!(diagnostic.action, DiagnosticAction::System);
        } else {
            assert_eq!(diagnostic.action, DiagnosticAction::Block,
                "Вторая заранее привязанная роль не теряется: initial={initial_selected:?}, observed={observe_before_restore}, generation={generation}");
            assert!(diagnostic.unresolved && !diagnostic.policy_image_resolved);
        }
    }
    let known = os::suspended(&other, None, None);
    assert_eq!(
        session
            .diagnose(&known.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::System
    );
    let original = os::suspended(&aliases[1].join("app.exe"), None, None);
    assert_eq!(
        session
            .diagnose(&original.0, "192.0.2.1".parse().unwrap())
            .unwrap()
            .action,
        DiagnosticAction::VpnNotReady
    );
    for alias in &aliases {
        std::fs::remove_dir(alias).unwrap();
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn two_prebound_aliases_keep_negative_identity_across_policy_generations() {
    for initial_selected in [[0, 1], [1, 0]] {
        for observed in [false, true] {
            two_alias_policy_case(&initial_selected, observed);
        }
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn prebound_unselected_alias_keeps_fact_when_later_selected() {
    two_alias_policy_case(&[0], true);
}

fn named_stream_case(
    action: u32,
    default: aivpn_desktop_policy::Action,
    expected: DiagnosticAction,
) {
    use aivpn_desktop_policy::Selector;
    use windows_sys::Win32::Storage::FileSystem::*;
    let scratch = os::Scratch::new();
    let base = scratch.copy("base.exe");
    let stream = scratch.0.join("base.exe:other.exe");
    std::fs::write(&stream, std::fs::read(&base).unwrap()).unwrap();
    let mut identities = [FILE_ID_INFO::default(); 2];
    for (index, path) in [&base, &stream].into_iter().enumerate() {
        let file = std::fs::File::open(path).unwrap();
        accounts::checked(unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut identities[index] as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        });
    }
    assert_eq!(
        identities[0].VolumeSerialNumber,
        identities[1].VolumeSerialNumber
    );
    assert_eq!(
        identities[0].FileId.Identifier,
        identities[1].FileId.Identifier
    );
    let path = os::native_path(&base);
    let (policy, bindings) = os::policy_default(
        Selector::Executable { path: path.clone() },
        action,
        1,
        false,
        default,
    );
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    let original = os::suspended(&base, None, None);
    let original_identity = session
        .diagnose(&original.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(original_identity.executable_slot, 3);
    let child = os::suspended(&stream, None, None);
    let diagnostic = session
        .diagnose(&child.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(
        diagnostic.executable_slot, 0,
        "Другой stream не получает роль основного executable"
    );
    assert!(
        diagnostic.os_image_available && diagnostic.policy_image_resolved && !diagnostic.unresolved
    );
    assert_eq!(diagnostic.action, expected);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn named_stream_does_not_inherit_base_roles() {
    for (action, default, expected) in [
        (
            2,
            aivpn_desktop_policy::Action::System {},
            DiagnosticAction::System,
        ),
        (
            0,
            aivpn_desktop_policy::Action::Block {},
            DiagnosticAction::Block,
        ),
    ] {
        named_stream_case(action, default, expected);
    }
}

fn launch_orphan(
    creator: &std::path::Path,
    child_path: &std::path::Path,
    marker: &std::path::Path,
) -> os::Suspended {
    use windows_sys::Win32::System::Threading::*;
    let status = std::process::Command::new(creator)
        .args([
            "--ignored",
            "--exact",
            "identity_orphan_creator",
            "--test-threads=1",
        ])
        .env("AIVPN_IDENTITY_ORPHAN_PATH", child_path)
        .env("AIVPN_IDENTITY_ORPHAN_MARKER", marker)
        .env_remove("AIVPN_CONTROL_PASSWORD")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let pid = std::fs::read_to_string(marker).unwrap().parse().unwrap();
    os::Suspended(os::own(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    }))
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn fast_exit_stream_survives_update_until_late_binding() {
    for _ in 0..4 {
        let scratch = os::Scratch::new();
        let creator = scratch.copy("creator.exe");
        let replacement = scratch.copy("replacement.exe");
        let child_path = scratch.copy("descendant.exe");
        let old = scratch.0.join("old.exe");
        std::fs::hard_link(&creator, &old).unwrap();
        let descendant = launch_orphan(&creator, &child_path, &scratch.0.join("pid"));
        // Creator уже завершен. Ни один binding или открытый user handle его образ не удерживал.
        os::replace(&replacement, &creator);
        let path = os::native_path(&old);
        let (policy, bindings) = os::policy(Some(&path), 0, 1, true);
        let mut session = DriverSession::open().unwrap();
        os::bind(&mut session, &path, &bindings);
        session.stage(&policy).unwrap();
        let diagnostic = session
            .diagnose(&descendant.0, "192.0.2.1".parse().unwrap())
            .unwrap();
        assert_eq!(diagnostic.action, DiagnosticAction::System);
        assert_eq!(diagnostic.depth, 1);
        assert!(!diagnostic.unresolved);
        let old_child = os::suspended(&old, None, None);
        assert_eq!(
            session
                .diagnose(&old_child.0, "192.0.2.1".parse().unwrap())
                .unwrap()
                .executable_slot,
            3
        );
        let new_child = os::suspended(&creator, None, None);
        assert_eq!(
            session
                .diagnose(&new_child.0, "192.0.2.1".parse().unwrap())
                .unwrap()
                .action,
            DiagnosticAction::Block
        );
    }
}

#[test]
#[ignore = "Требуется собственный второй NTFS-том AIVPN_IDENTITY_SECOND_ROOT на Windows-стенде"]
fn equal_relative_paths_on_distinct_volumes_keep_distinct_roles() {
    use aivpn_desktop_policy::{Action, Selector};
    let scratch = os::Scratch::new();
    let selected = scratch.copy("selected.exe");
    let second_root = std::env::var("AIVPN_IDENTITY_SECOND_ROOT")
        .expect("Runner создает собственный временный том");
    let native = selected.to_str().unwrap();
    assert_eq!(&native[1..3], ":\\");
    let second = std::path::PathBuf::from(format!(
        "{}{}",
        second_root.trim_end_matches('\\'),
        &native[2..]
    ));
    std::fs::create_dir_all(second.parent().unwrap()).unwrap();
    std::fs::copy(&selected, &second).unwrap();
    let path = os::native_path(&selected);
    let other_path = os::native_path(&second);
    assert_ne!(path, other_path);
    let (policy, bindings) = os::policy_default(
        Selector::Executable { path: path.clone() },
        2,
        1,
        false,
        Action::System {},
    );
    let mut session = DriverSession::open().unwrap();
    os::bind(&mut session, &path, &bindings);
    session.stage(&policy).unwrap();
    let child = os::suspended(&second, None, None);
    let result = session
        .diagnose(&child.0, "192.0.2.1".parse().unwrap())
        .unwrap();
    assert_eq!(result.action, DiagnosticAction::System);
    assert_eq!(result.executable_slot, 0);
    assert!(result.os_image_available && result.policy_image_resolved);
    drop(child);
    std::fs::remove_file(second).unwrap();
}
