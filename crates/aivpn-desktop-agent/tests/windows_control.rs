#![cfg(target_os = "windows")]
#[path = "support/windows_control_fixture.rs"]
mod fixture;
use aivpn_desktop_agent::{
    control::{Control, ControlState, ControlStore, RoutingBackend},
    protocol::{BackendState, Command, ErrorCode, Outcome, Reply, Request},
    state::{StateDirectory, StateFile},
    windows::{ControlClient, ControlServer},
};
use aivpn_desktop_policy::{Owner, Platform, ProfileCatalog};
use std::{
    io,
    num::NonZeroU64,
    os::windows::io::AsRawHandle,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::*, Security::*, Storage::FileSystem::*};
struct Backend(bool);
impl<S: aivpn_desktop_agent::control::ControlStore> RoutingBackend<S> for Backend {
    fn installed_state(&self) -> aivpn_desktop_agent::control::InstalledState {
        aivpn_desktop_agent::control::InstalledState::Active
    }
    fn supported(&self) -> bool {
        self.0
    }
    fn install(&mut self, _store: &mut S, _: &ControlState, _: &ProfileCatalog) -> io::Result<()> {
        fixture::no_thread_token();
        Ok(())
    }
    fn block(&mut self) -> io::Result<()> {
        fixture::no_thread_token();
        Ok(())
    }
}
struct Store(StateDirectory);
impl ControlStore for Store {
    fn load(&self, f: StateFile) -> io::Result<Option<Vec<u8>>> {
        fixture::no_thread_token();
        self.0.load(f)
    }
    fn replace(&mut self, f: StateFile, b: &[u8]) -> io::Result<()> {
        fixture::no_thread_token();
        self.0.replace(f, b)
    }
    fn clear_pending(&mut self) -> io::Result<()> {
        fixture::no_thread_token();
        self.0.clear_pending()
    }
}
fn request(command: Command) -> Request {
    Request::new(NonZeroU64::new(1).unwrap(), command)
}
fn unique(case: &str) -> String {
    format!("task2-{case}-{}", std::process::id())
}
fn path(case: &str) -> PathBuf {
    std::env::temp_dir().join(unique(case))
}
fn ok(pipe: &str, command: Command) -> Reply {
    match ControlClient::call(pipe, &request(command))
        .unwrap()
        .result()
    {
        Outcome::Ok { reply } => {
            serde_json::from_value(serde_json::to_value(reply).unwrap()).unwrap()
        }
        other => panic!("Операция отклонена: {other:?}"),
    }
}
fn error(pipe: &str, command: Command, code: ErrorCode) {
    assert!(
        matches!(ControlClient::call(pipe,&request(command)).unwrap().result(),Outcome::Error{code:actual} if *actual==code)
    );
}
fn running(case: &str, active: bool) -> (String, PathBuf, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let name = unique(case);
    let path = path(case);
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let (n, p, s) = (name.clone(), path.clone(), stop.clone());
    let thread = thread::spawn(move || {
        let mut server = ControlServer::bind(&n, || {
            Control::open(
                Platform::Windows,
                [31; 16],
                Store(StateDirectory::open(&p)?),
                Backend(active),
            )
        })
        .unwrap();
        tx.send(()).unwrap();
        server.run(&s).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    (name, path, stop, thread)
}
fn finish(path: PathBuf, stop: Arc<AtomicBool>, worker: thread::JoinHandle<()>) {
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn system_startup() {
    let p = path("startup");
    let server = ControlServer::open(&unique("startup"), &p, [31; 16], Backend(false))
        .expect("SYSTEM должен открыть сервер");
    drop(server);
    std::fs::remove_dir_all(p).unwrap();
}
#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn unavailable_backend_and_squatting() {
    let (name, p, stop, worker) = running("unavailable", false);
    assert!(matches!(
        ok(&name, Command::Status {}),
        Reply::Status {
            backend: BackendState::Unavailable,
            ..
        }
    ));
    error(
        &name,
        Command::ClearGlobalDns {},
        ErrorCode::BackendUnavailable,
    );
    let second = ControlServer::<StateDirectory, Backend>::bind(&name, || {
        panic!("Фабрика не должна вызываться при занятом имени")
    });
    assert!(second.is_err());
    finish(p, stop, worker);
}
#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn real_user_filtered_and_elevated_authority() {
    let (name, p, stop, worker) = running("authority", true);
    for (user, filtered, role) in [
        ("AivpnControlUser", false, "ordinary"),
        ("AivpnControlAdmin", true, "filtered"),
        ("AivpnControlAdmin", false, "elevated"),
    ] {
        let token = fixture::logon(user, filtered);
        fixture::launch(token.as_raw_handle(), role, &name, &p);
    }
    finish(p, stop, worker);
}
#[test]
#[ignore = "Дочерний сценарий native Windows suite, окружение задает родитель"]
fn process_role_child() {
    let role = std::env::var("AIVPN_CONTROL_ROLE")
        .expect("Дочерний сценарий запускает родитель с проверяемой ролью");
    std::panic::set_hook(Box::new(|info| {
        let role = std::env::var("AIVPN_CONTROL_ROLE").unwrap();
        let _ = std::fs::write(
            format!("C:\\Users\\Public\\aivpn-control-task2-{role}.failure"),
            info.to_string(),
        );
    }));
    let name = std::env::var("AIVPN_CONTROL_PIPE").unwrap();
    let p = PathBuf::from(std::env::var("AIVPN_CONTROL_STATE").unwrap());
    if role == "early-close" {
        drop(raw(&name, false));
        return;
    }
    let token = fixture::process_token();
    let elevation = fixture::token_u32(token.as_raw_handle(), TokenElevationType);
    if role == "filtered" {
        assert_eq!(elevation, TokenElevationTypeLimited as u32);
    }
    if role == "elevated" {
        assert_eq!(elevation, TokenElevationTypeFull as u32);
    }
    // Пользователь не может создать дополнительный экземпляр реального endpoint.
    let endpoint = fixture::wide(&format!("\\\\.\\pipe\\aivpn-{name}-user"));
    let squatted = unsafe {
        windows_sys::Win32::System::Pipes::CreateNamedPipeW(
            endpoint.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            0,
            2,
            4096,
            4096,
            0,
            std::ptr::null(),
        )
    };
    if squatted != INVALID_HANDLE_VALUE {
        drop(fixture::own(squatted));
        panic!("Удалось расширить endpoint");
    }
    if role != "elevated" {
        let endpoint = fixture::wide(&format!("\\\\.\\pipe\\aivpn-{name}-admin"));
        let handle = unsafe {
            CreateFileW(
                endpoint.as_ptr(),
                0x0012019b,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
    }
    let fake_name = unique("forged-user");
    let fake = fixture::forged_pipe(&fake_name, role == "elevated", None);
    assert!(ControlClient::call(&fake_name, &request(Command::Status {})).is_err());
    fixture::rejected_without_document(&fake);
    drop(fake);
    let own = Owner::WindowsUser {
        sid: fixture::sid(),
    };
    let mut called = false;
    let result = ControlServer::<StateDirectory, Backend>::bind(&unique("forbidden"), || {
        called = true;
        panic!("Нельзя открывать state до SYSTEM gate")
    });
    assert!(result.is_err());
    assert!(!called);
    if role != "elevated" {
        assert!(std::fs::read(p.join("committed.json")).is_err());
        assert!(std::fs::write(p.join("attack"), b"x").is_err());
        assert!(StateDirectory::open(&p).is_err());
    }
    assert!(matches!(
        ok(
            &name,
            Command::RegisterProfile {
                owner: own.clone(),
                registration_key: format!("own-{role}"),
                consumers: vec![]
            }
        ),
        Reply::Registered { .. }
    ));
    if role != "elevated" {
        error(
            &name,
            Command::GetPolicy {
                owner: Owner::WindowsUser {
                    sid: "S-1-5-18".into(),
                },
            },
            ErrorCode::AccessDenied,
        );
        error(
            &name,
            Command::RegisterProfile {
                owner: Owner::Machine {},
                registration_key: "spoof".into(),
                consumers: vec![],
            },
            ErrorCode::AccessDenied,
        );
        error(&name, Command::ClearGlobalDns {}, ErrorCode::AccessDenied);
    } else {
        ok(&name, Command::ClearGlobalDns {});
    }
    assert!(matches!(
        ok(&name, Command::GetPolicy { owner: own }),
        Reply::Policy { document: None }
    ));
}
fn raw(name: &str, admin: bool) -> std::os::windows::io::OwnedHandle {
    let path = fixture::wide(&format!(
        "\\\\.\\pipe\\aivpn-{name}-{}",
        if admin { "admin" } else { "user" }
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0x0012019b,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return fixture::own(handle);
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}
fn raw_write(handle: &impl AsRawHandle, bytes: &[u8]) {
    let mut count = 0;
    fixture::checked(unsafe {
        WriteFile(
            handle.as_raw_handle(),
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut count,
            std::ptr::null_mut(),
        )
    });
    assert_eq!(count as usize, bytes.len());
}
#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn malformed_partial_idle_admin_rescue_and_stop() {
    let (name, p, stop, worker) = running("faults", false);
    for bytes in [
        &[0xff, 0xff, 0xff, 0xff][..],
        &[0, 0, 0, 1, b'{'][..],
        &[0, 0][..],
        &[][..],
    ] {
        let pipe = raw(&name, false);
        if !bytes.is_empty() {
            raw_write(&pipe, bytes);
        }
        thread::sleep(Duration::from_millis(80));
        let start = Instant::now();
        // SYSTEM использует резервный endpoint; обычный idle клиент не забирает его имя.
        ControlClient::call(&name, &request(Command::Status {})).unwrap();
        assert!(start.elapsed() < Duration::from_secs(4));
        drop(pipe);
    }
    let idle = raw(&name, false);
    thread::sleep(Duration::from_millis(30));
    let start = Instant::now();
    finish(p, stop, worker);
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(idle);
}

fn disconnected(pipe: &impl AsRawHandle) {
    let mut byte = [0];
    let mut count = 0;
    let result = unsafe {
        ReadFile(
            pipe.as_raw_handle(),
            byte.as_mut_ptr(),
            1,
            &mut count,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(result, 0, "Сервер ответил на некорректный кадр");
    assert!(matches!(
        unsafe { GetLastError() },
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED
    ));
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn bad_frames_disconnect_and_absolute_deadline() {
    let (name, p, stop, worker) = running("deadline", false);
    for bytes in [
        vec![0, 0, 0, 0],
        vec![0xff; 4],
        vec![0, 0, 0, 1, b'{'],
        vec![0, 0],
        vec![],
    ] {
        let pipe = raw(&name, false);
        let start = Instant::now();
        if !bytes.is_empty() {
            raw_write(&pipe, &bytes);
        }
        disconnected(&pipe);
        assert!(start.elapsed() < Duration::from_millis(2800));
        if bytes.len() < 4 {
            assert!(start.elapsed() >= Duration::from_millis(1700));
        }
        ok(&name, Command::Status {});
    }
    // Малые порции не продлевают общий deadline кадра.
    let pipe = raw(&name, false);
    let start = Instant::now();
    raw_write(&pipe, &[0, 0, 0, 20]);
    for _ in 0..5 {
        thread::sleep(Duration::from_millis(300));
        raw_write(&pipe, b" ");
    }
    disconnected(&pipe);
    assert!(start.elapsed() < Duration::from_millis(2800));
    finish(p, stop, worker);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn forged_system_acl_and_first_instance_rejected() {
    for (case, sddl) in [
        ("broad", "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;AU)"),
        (
            "inherit",
            "O:SYG:SYD:(A;;0x001f01ff;;;SY)(A;;0x0012019b;;;BA)",
        ),
    ] {
        let name = unique(case);
        let fake = fixture::forged_pipe(&name, true, Some(sddl));
        assert!(ControlClient::call(&name, &request(Command::Status {})).is_err());
        fixture::rejected_without_document(&fake);
        let server = ControlServer::<StateDirectory, Backend>::bind(&name, || {
            panic!("Поддельный endpoint должен блокировать factory")
        });
        assert!(server.is_err());
        drop(fake);
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn concurrent_clients_stop_restart_and_resource_bounds() {
    let before = fixture::resources();
    for round in 0..8 {
        let (name, p, stop, worker) = running(&format!("resources-{round}"), false);
        let clients: Vec<_> = (0..16)
            .map(|_| {
                let name = name.clone();
                thread::spawn(move || {
                    ok(&name, Command::Status {});
                })
            })
            .collect();
        for client in clients {
            client.join().unwrap();
        }
        let idle_public = raw(&name, false);
        let idle_admin = raw(&name, true);
        let start = Instant::now();
        finish(p, stop, worker);
        assert!(start.elapsed() < Duration::from_secs(1));
        drop((idle_public, idle_admin));
    }
    let after = fixture::resources();
    assert!(
        after.0 <= before.0 + 2,
        "Handles выросли: {before:?} -> {after:?}"
    );
    assert_eq!(after.1, before.1, "Потоки не завершились");
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn stopped_server_can_run_again() {
    let name = unique("rerun");
    let p = path("rerun");
    let mut server = ControlServer::open(&name, &p, [31; 16], Backend(false)).unwrap();
    server.run(&AtomicBool::new(true)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let client_stop = stop.clone();
    let client = thread::spawn(move || {
        ok(&name, Command::Status {});
        client_stop.store(true, Ordering::Release);
    });
    server.run(&stop).unwrap();
    client.join().unwrap();
    drop(server);
    std::fs::remove_dir_all(p).unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд с LocalSystem-службой и тестовыми учетными записями"]
fn early_ordinary_disconnect_before_run_recovers() {
    let name = unique("early-close");
    let p = path("early-close");
    let mut server = ControlServer::open(&name, &p, [31; 16], Backend(false)).unwrap();
    let user = fixture::logon("AivpnControlUser", false);
    fixture::launch(user.as_raw_handle(), "early-close", &name, &p);
    let stop = Arc::new(AtomicBool::new(false));
    let client_stop = stop.clone();
    let client = thread::spawn(move || {
        let result = ControlClient::call(&name, &request(Command::Status {}));
        client_stop.store(true, Ordering::Release);
        result
    });
    let result = server.run(&stop);
    let response = client.join().unwrap();
    drop(server);
    std::fs::remove_dir_all(p).unwrap();
    result.expect("Ранний disconnect обычного клиента не должен останавливать сервер");
    assert!(matches!(
        response.unwrap().result(),
        Outcome::Ok {
            reply: Reply::Status { .. }
        }
    ));
}
