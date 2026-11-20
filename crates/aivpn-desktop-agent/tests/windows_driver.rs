#![cfg(target_os = "windows")]

#[path = "support/windows_driver_fixture.rs"]
mod fixture;

#[path = "support/windows_control_fixture.rs"]
#[allow(dead_code)]
mod identity;

#[test]
#[ignore = "Дочерний сценарий native Windows suite, окружение задает родитель"]
fn process_role_child() {
    use aivpn_desktop_agent::windows::driver::DriverSession;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::*;
    let role = std::env::var("AIVPN_CONTROL_ROLE")
        .expect("Дочерний сценарий запускает родитель с проверяемой ролью");
    let result = std::panic::catch_unwind(|| {
        let token = identity::process_token();
        let expected = match role.as_str() {
            "ordinary" => TokenElevationTypeDefault,
            "filtered" => TokenElevationTypeLimited,
            "elevated" => TokenElevationTypeFull,
            _ => panic!("Неизвестная роль"),
        };
        assert_eq!(
            identity::token_u32(token.as_raw_handle(), TokenElevationType),
            expected as u32
        );
        assert_eq!(fixture::open().unwrap_err().raw_os_error(), Some(5));
        assert!(DriverSession::open().is_err());
    });
    if result.is_err() {
        std::process::exit(1);
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn ordinary_filtered_and_elevated_cannot_control_device() {
    use std::os::windows::io::AsRawHandle;
    for (role, user, filtered) in [
        ("ordinary", "AivpnDriverUser", false),
        ("filtered", "AivpnDriverAdmin", true),
        ("elevated", "AivpnDriverAdmin", false),
    ] {
        let token = identity::logon(user, filtered);
        identity::launch(
            token.as_raw_handle(),
            role,
            "unused",
            std::path::Path::new("C:\\Users\\Public"),
        );
    }
}

#[test]
#[ignore = "Дочерний сценарий native Windows suite, окружение задает родитель"]
fn system_process_child() {
    use fixture::*;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    let role = std::env::var("AIVPN_DRIVER_ROLE")
        .expect("Дочерний сценарий запускает родитель с проверяемой ролью");
    match role.as_str() {
        "foreign" => {
            let raw = std::env::var("AIVPN_DRIVER_HANDLE")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let inherited = unsafe { OwnedHandle::from_raw_handle(raw as _) };
            assert_eq!(
                ioctl(&inherited, QUERY, &request(0, 24), 48)
                    .unwrap_err()
                    .raw_os_error(),
                Some(5)
            );
            assert!(open().is_err());
        }
        "crash" => {
            let device = open().unwrap();
            let session = wide_word(&query(&device, 0), 8);
            ioctl(&device, STAGE, &stage_request(session, 71), 48).unwrap();
            // Завершение без Rust Drop проверяет освобождение ядром handles процесса.
            std::process::exit(0);
        }
        _ => panic!("Неизвестная роль SYSTEM"),
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn handle_ownership_duplication_and_process_exit() {
    use fixture::*;
    let device = open().unwrap();
    let original = query(&device, 0);
    assert!(open().is_err());
    system_child("foreign", Some(&device));
    assert_eq!(query(&device, 0), original);
    let duplicate = device.try_clone().unwrap();
    drop(device);
    assert_eq!(query(&duplicate, 0), original);
    assert!(open().is_err());
    drop(duplicate);
    system_child("crash", None);
    let device = open().unwrap();
    let after = query(&device, 0);
    assert!(wide_word(&after, 8) > wide_word(&original, 8));
    assert_eq!(wide_word(&after, 24), 0);
    assert_eq!(word(&after, 32), 0);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn impersonated_system_thread_is_denied_before_open_and_on_existing_handle() {
    use fixture::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::{Security::*, System::Threading::*};
    let packet_stats = (0x12 << 16) | (1 << 14) | (0x8a1 << 2);
    let device = open().unwrap();
    let stats = ioctl(&device, packet_stats, &[], 44).unwrap();
    assert_eq!(stats.len(), 44);
    assert_eq!(word(&stats, 0), 1);
    let mut raw_token = ptr::null_mut();
    identity::checked(unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut raw_token,
        )
    });
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut duplicate = ptr::null_mut();
    identity::checked(unsafe {
        DuplicateToken(token.as_raw_handle(), SecurityImpersonation, &mut duplicate)
    });
    let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate) };
    identity::checked(unsafe { SetThreadToken(ptr::null(), duplicate.as_raw_handle()) });
    let result = std::panic::catch_unwind(|| {
        assert_eq!(open().unwrap_err().raw_os_error(), Some(5));
        assert_eq!(
            ioctl(&device, QUERY, &request(0, 24), 48)
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
        // Пакетный IOCTL проходит проверку ядра даже без обертки DriverSession.
        for (function, access, method) in [
            (0x8a0, 3, 0),
            (0x8a1, 1, 0),
            (0x8a2, 1, 2),
            (0x8a3, 2, 1),
            (0x8a4, 3, 0),
            (0x8a5, 1, 2),
            (0x8a6, 2, 1),
            (0x8a7, 3, 0),
        ] {
            let code = (0x12 << 16) | (access << 14) | (function << 2) | method;
            assert_eq!(
                ioctl(&device, code, &[], 44).unwrap_err().raw_os_error(),
                Some(5),
                "IOCTL {code:#x}"
            );
        }
        assert!(aivpn_desktop_agent::windows::driver::DriverSession::open().is_err());
    });
    identity::checked(unsafe { RevertToSelf() });
    assert!(result.is_ok());
    assert_ne!(wide_word(&query(&device, 0), 8), 0);
    assert_eq!(ioctl(&device, packet_stats, &[], 44).unwrap().len(), 44);
    drop(device);

    let session = aivpn_desktop_agent::windows::driver::DriverSession::open().unwrap();
    session.packet_statistics().unwrap();
    identity::checked(unsafe { SetThreadToken(ptr::null(), duplicate.as_raw_handle()) });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            session.packet_statistics().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }));
    identity::checked(unsafe { RevertToSelf() });
    assert!(result.is_ok());
    session.packet_statistics().unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn policy_staging_is_atomic_monotonic_and_idempotent() {
    use fixture::*;
    let device = open().unwrap();
    let session = wide_word(&query(&device, 0), 8);
    let good = stage_request(session, 7);
    let staged = ioctl(&device, STAGE, &good, 48).unwrap();
    assert_eq!(wide_word(&staged, 24), 7);
    assert_eq!(word(&staged, 32), 1);
    assert_eq!(word(&staged, 40), 0);
    assert_eq!(ioctl(&device, STAGE, &good, 48).unwrap(), staged);
    assert!(ioctl(&device, STAGE, &stage_request(session, 6), 48).is_err());
    for offset in [24, 28, 36, 56, 60, 64, 72, 80, 112, 24 + POLICY_BYTES - 1] {
        let mut bad = good.clone();
        bad[offset] ^= 0xff;
        assert!(ioctl(&device, STAGE, &bad, 48).is_err(), "offset={offset}");
        assert_eq!(query(&device, session), staged);
    }
    for length in [24, good.len() - 1, good.len() + 1, 65536] {
        let mut bad = good.clone();
        bad.resize(length, 0);
        assert!(ioctl(&device, STAGE, &bad, 48).is_err());
    }
    let newer = ioctl(&device, STAGE, &stage_request(session, 8), 48).unwrap();
    assert_eq!(wide_word(&newer, 24), 8);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn invalid_new_policy_cannot_replace_the_staged_revision() {
    use fixture::*;
    let device = open().unwrap();
    let session = wide_word(&query(&device, 0), 8);
    let original = ioctl(&device, STAGE, &stage_request(session, 7), 48).unwrap();
    let next = stage_request(session, 8);
    for (offset, value) in [
        (24, 2),
        (28, 1),
        (32, 0),
        (36, 257),
        (40, 0),
        (48, 3),
        (52, 1),
        (56, 0),
        (60, 1),
        (64, 3),
        (68, 0),
        (72, 9),
        (76, 2),
        (80, 3),
        (84, 0),
    ] {
        let mut bad = next.clone();
        bad[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        assert!(ioctl(&device, STAGE, &bad, 48).is_err(), "offset={offset}");
        assert_eq!(query(&device, session), original);
    }
    for offset in [91, 92, 105, 112, next.len() - 1] {
        let mut bad = next.clone();
        bad[offset] = 1;
        assert!(ioctl(&device, STAGE, &bad, 48).is_err(), "offset={offset}");
        assert_eq!(query(&device, session), original);
    }
    let accepted = ioctl(&device, STAGE, &next, 48).unwrap();
    assert_eq!(wide_word(&accepted, 24), 8);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn typed_policy_stage_and_resource_plateau() {
    use aivpn_desktop_agent::windows::driver::{DriverSession, StagedState};
    let before = identity::resources();
    let policy = fixture::policy(2);
    for _ in 0..128 {
        let mut session = DriverSession::open().unwrap();
        let status = session.stage(&policy).unwrap();
        assert_eq!(status.state, StagedState::PolicyStaged);
        assert_eq!(status.generation.unwrap().get(), 2);
        assert_eq!(status, session.status().unwrap());
    }
    let after = identity::resources();
    assert!(after.0 <= before.0 + 2, "handles {before:?} -> {after:?}");
    assert_eq!(after.1, before.1);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn simultaneous_opens_have_one_owner() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };
    let begin = Barrier::new(16);
    let finish = Barrier::new(16);
    let admitted = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| {
                begin.wait();
                let device = fixture::open();
                if device.is_ok() {
                    admitted.fetch_add(1, Ordering::Relaxed);
                }
                finish.wait();
                drop(device);
            });
        }
    });
    assert_eq!(admitted.load(Ordering::Relaxed), 1);
    assert!(fixture::open().is_ok());
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn namespace_and_read_only_handle_cannot_control_session() {
    use fixture::*;
    use windows_sys::Win32::Foundation::*;
    assert_eq!(
        open_with("\\child", GENERIC_READ | GENERIC_WRITE, 0)
            .unwrap_err()
            .raw_os_error(),
        Some(5)
    );
    for access in [0, GENERIC_READ, GENERIC_WRITE] {
        let device = open_with("", access, 0).unwrap();
        assert_eq!(
            ioctl(&device, QUERY, &request(0, 24), 48)
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn completed_ioctl_has_no_cancellable_request_or_retained_session() {
    use fixture::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Storage::FileSystem::*,
        System::{Threading::*, IO::*},
    };
    let device = open_with("", GENERIC_READ | GENERIC_WRITE, FILE_FLAG_OVERLAPPED).unwrap();
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(!event.is_null());
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
    operation.hEvent = event.as_raw_handle();
    let input = request(0, 24);
    let mut output = [0u8; 48];
    let mut returned = 0;
    let submitted = unsafe {
        DeviceIoControl(
            device.as_raw_handle(),
            QUERY,
            input.as_ptr().cast(),
            input.len() as u32,
            output.as_mut_ptr().cast(),
            48,
            &mut returned,
            &mut operation,
        )
    };
    assert_ne!(
        submitted, 0,
        "Ограниченный IOCTL должен завершиться синхронно"
    );
    assert_eq!(unsafe { CancelIoEx(device.as_raw_handle(), &operation) }, 0);
    assert_eq!(unsafe { GetLastError() }, ERROR_NOT_FOUND);
    identity::checked(unsafe {
        GetOverlappedResult(device.as_raw_handle(), &operation, &mut returned, 1)
    });
    assert_eq!(returned, 48);
    let old_session = wide_word(&output, 8);
    drop(device);
    let next = open().unwrap();
    assert!(wide_word(&query(&next, 0), 8) > old_session);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn typed_session_starts_without_enforcement() {
    use aivpn_desktop_agent::windows::driver::{DriverSession, StagedState};
    let mut session = DriverSession::open().unwrap();
    let status = session.status().unwrap();
    assert_eq!(status.state, StagedState::Empty);
    assert_eq!(status.generation, None);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn native_driver_is_available_to_service() {
    let device = fixture::open().expect("Служба должна открыть установленный драйвер");
    let status = fixture::query(&device, 0);
    assert_eq!(status.len(), 48);
    assert_eq!(fixture::word(&status, 0), 1);
    assert_ne!(fixture::wide_word(&status, 8), 0);
    assert_eq!(fixture::wide_word(&status, 24), 0);
    assert_eq!(fixture::word(&status, 32), 0);
    assert_eq!(fixture::word(&status, 36), 1);
    assert_eq!(fixture::word(&status, 40), 0);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и установленным драйвером"]
fn malformed_requests_do_not_change_session() {
    use fixture::*;
    let device = open().unwrap();
    let status = query(&device, 0);
    let session = wide_word(&status, 8);
    for length in [0, 1, 23, 25, 65536] {
        let bad = vec![0; length];
        assert!(ioctl(&device, QUERY, &bad, 48).is_err());
    }
    for offset in [0, 4, 16, 20] {
        let mut bad = request(session, 24);
        bad[offset] ^= 2;
        assert!(ioctl(&device, QUERY, &bad, 48).is_err());
    }
    for capacity in [0, 47, 49, 65536] {
        assert!(ioctl(&device, QUERY, &request(session, 24), capacity).is_err());
    }
    assert!(ioctl(&device, QUERY, &request(session + 1, 24), 48).is_err());
    assert!(ioctl(&device, QUERY + 8, &request(session, 24), 48).is_err());
    let mut policy = request(session, 24 + POLICY_BYTES);
    policy[24..28].copy_from_slice(&1u32.to_le_bytes());
    assert!(ioctl(&device, STAGE, &policy, 48).is_err());
    assert_eq!(query(&device, session), status);
}
