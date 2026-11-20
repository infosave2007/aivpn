#![cfg(target_os = "linux")]

use aivpn_desktop_agent::control::{Control, ControlState, RoutingBackend};
use aivpn_desktop_agent::protocol::*;
use aivpn_desktop_agent::unix::{
    service::{ControlServer, ControlStop},
    LocalStream,
};
use aivpn_desktop_policy::*;
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[path = "support/control_fixture.rs"]
mod fixture;
use fixture::{Backend, Memory};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aivpn-control-service-{}-{nonce}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Running {
    _directory: Directory,
    path: PathBuf,
    stop: ControlStop,
    worker: Option<std::thread::JoinHandle<Control<Memory, Backend>>>,
}
impl Running {
    fn new(mut control: Control<Memory, Backend>) -> Self {
        let directory = Directory::new();
        let path = directory.0.join("control.sock");
        let (server, stop) = ControlServer::new(UnixListener::bind(&path).unwrap()).unwrap();
        let worker = std::thread::spawn(move || {
            server.run(&mut control).unwrap();
            control
        });
        Self {
            _directory: directory,
            path,
            stop,
            worker: Some(worker),
        }
    }
    fn call(&self, command: Command) -> Response {
        let mut client = LocalStream::new(UnixStream::connect(&self.path).unwrap());
        let request = Request::new(NonZeroU64::new(75).unwrap(), command);
        client.send(&request.to_json().unwrap(), &[]).unwrap();
        let frame = client.receive(Some(Duration::from_secs(2))).unwrap();
        assert!(frame.descriptors.is_empty());
        let response = Response::from_json(&frame.payload).unwrap();
        assert_eq!(response.id(), request.id());
        response
    }
    fn finish(mut self) -> Control<Memory, Backend> {
        self.stop.stop();
        self.stop.stop();
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn empty() -> Control<Memory, Backend> {
    Control::open(Platform::Linux, [8; 16], Memory::default(), Backend).unwrap()
}

#[test]
fn stopping_service_keeps_socket_activators_listener_usable() {
    let directory = Directory::new();
    let path = directory.0.join("activated.sock");
    let activator = UnixListener::bind(&path).unwrap();
    let (server, stop) = ControlServer::new(activator.try_clone().unwrap()).unwrap();
    stop.stop();
    stop.stop();
    drop(server);
    let _client =
        UnixStream::connect(&path).expect("Сокет активатора должен принимать новый запуск");
    activator.set_nonblocking(true).unwrap();
    let _connection = activator.accept().unwrap();
}
fn is_status(response: &Response) {
    assert!(matches!(
        response.result(),
        Outcome::Ok {
            reply: Reply::Status { .. }
        }
    ));
}

#[test]
fn a_slow_sender_does_not_hold_the_state_writer() {
    let service = Running::new(empty());
    let mut slow = UnixStream::connect(&service.path).unwrap();
    slow.write_all(&[0xa1]).unwrap();
    is_status(&service.call(Command::Status {}));
    drop(slow);
    assert_eq!(service.finish().state().serial(), 0);
}

#[test]
fn deferred_management_does_not_hold_the_state_writer() {
    use aivpn_desktop_agent::unix::service::ControlHandler;
    use std::sync::mpsc;
    struct Handler {
        started: mpsc::Sender<std::thread::ThreadId>,
        release: Option<mpsc::Receiver<()>>,
    }
    impl ControlHandler for Handler {
        fn handle(&mut self, _: &Authority, request: Request) -> Response {
            Response::success(request.id(), Reply::Done {})
        }
        fn prepare(&mut self, authority: &Authority, request: Request) -> PreparedResponse {
            if !matches!(request.command(), Command::ListProfiles {}) {
                return PreparedResponse::Ready(self.handle(authority, request));
            }
            let release = self.release.take().unwrap();
            let started = self.started.clone();
            let writer = std::thread::current().id();
            PreparedResponse::Deferred(Box::new(move || {
                assert_ne!(std::thread::current().id(), writer);
                started.send(std::thread::current().id()).unwrap();
                release.recv_timeout(Duration::from_secs(3)).unwrap();
                Response::success(request.id(), Reply::Done {})
            }))
        }
    }
    fn call(path: &std::path::Path, command: Command) -> io::Result<Response> {
        let mut stream = LocalStream::new(UnixStream::connect(path)?);
        stream.send(
            &Request::new(NonZeroU64::MIN, command).to_json().unwrap(),
            &[],
        )?;
        Response::from_json(&stream.receive(Some(Duration::from_secs(1)))?.payload)
            .map_err(io::Error::other)
    }
    let directory = Directory::new();
    let path = directory.0.join("deferred.sock");
    let (server, stop) = ControlServer::new(UnixListener::bind(&path).unwrap()).unwrap();
    let (started, begin) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let server_thread = std::thread::spawn(move || {
        server.run_handler(&mut Handler {
            started,
            release: Some(wait),
        })
    });
    let slow_path = path.clone();
    let slow = std::thread::spawn(move || call(&slow_path, Command::ListProfiles {}));
    let began = begin.recv_timeout(Duration::from_secs(1));
    let fast = began.is_ok().then(|| call(&path, Command::Status {}));
    let _ = release.send(());
    let slow_result = slow.join().unwrap();
    stop.stop();
    let server_result = server_thread.join().unwrap();
    assert!(
        began.is_ok(),
        "Отложенная работа не дошла до I/O обработчика"
    );
    assert!(
        fast.unwrap().is_ok(),
        "Долгий запрос задержал чтение состояния"
    );
    assert!(slow_result.is_ok());
    assert!(server_result.is_ok());
}

fn large_policy() -> Control<Memory, Backend> {
    let mut control = empty();
    let uid = unsafe { libc::geteuid() };
    let authority = Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: true,
    };
    let request = |command| Request::new(NonZeroU64::MIN, command);
    let response = control.handle(
        &authority,
        request(Command::RegisterProfile {
            owner: authority.user.clone(),
            registration_key: "large-policy".into(),
            consumers: vec![],
        }),
    );
    let profile = match response.result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    };
    let response = control.handle(
        &authority,
        request(Command::SetGlobalDns {
            profile: profile.clone(),
            acknowledge_outage: true,
        }),
    );
    assert!(matches!(response.result(), Outcome::Ok { .. }));
    let document = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "large".into(),
        generation: 1,
        platform: Platform::Linux,
        owner: authority.user.clone(),
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile,
            acknowledge_outage: true,
        },
        rules: (0..200)
            .map(|index| RuleDocument {
                id: format!("rule-{index}"),
                application: Selector::Executable {
                    path: format!("/{}/{index}", "a".repeat(400)),
                },
                destination: None,
                inherit_children: false,
                action: Action::Block {},
            })
            .collect(),
    };
    let response = control.handle(
        &authority,
        request(Command::ApplyPolicy {
            document,
            expected_generation: None,
        }),
    );
    assert!(matches!(response.result(), Outcome::Ok { .. }));
    control
}

#[test]
fn a_slow_reader_does_not_hold_the_state_writer() {
    let service = Running::new(large_policy());
    let socket = UnixStream::connect(&service.path).unwrap();
    let observer = socket.try_clone().unwrap();
    let mut slow = LocalStream::new(socket);
    let request = Request::new(
        NonZeroU64::MIN,
        Command::GetPolicy {
            owner: Owner::LinuxUser {
                uid: unsafe { libc::geteuid() },
            },
        },
    );
    slow.send(&request.to_json().unwrap(), &[]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut available: libc::c_int = 0;
    while available < 32768 && Instant::now() < deadline {
        assert_eq!(
            unsafe { libc::ioctl(observer.as_raw_fd(), libc::FIONREAD, &mut available) },
            0
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!((32768..90000).contains(&available), "{available}");
    is_status(&service.call(Command::Status {}));
    let frame = slow.receive(Some(Duration::from_secs(2))).unwrap();
    assert!(frame.payload.len() > 90000);
    assert!(matches!(
        Response::from_json(&frame.payload).unwrap().result(),
        Outcome::Ok {
            reply: Reply::Policy { document: Some(_) }
        }
    ));
    assert_eq!(service.finish().state().serial(), 3);
}

#[test]
fn repeated_requests_release_admission_slots_and_malformed_input_does_not_mutate_state() {
    let service = Running::new(empty());
    for _ in 0..1000 {
        is_status(&service.call(Command::Status {}));
    }
    let mut bad = LocalStream::new(UnixStream::connect(&service.path).unwrap());
    bad.send(
        br#"{"version":1,"id":1,"command":{"method":"status","authority":true}}"#,
        &[],
    )
    .unwrap();
    assert!(bad.receive(Some(Duration::from_secs(2))).is_err());
    is_status(&service.call(Command::Status {}));
    assert_eq!(service.finish().state().serial(), 0);
}

struct Panicking(u32);
impl<S: aivpn_desktop_agent::control::ControlStore> RoutingBackend<S> for Panicking {
    fn installed_state(&self) -> aivpn_desktop_agent::control::InstalledState {
        aivpn_desktop_agent::control::InstalledState::Active
    }
    fn supported(&self) -> bool {
        true
    }
    fn install(
        &mut self,
        _store: &mut S,
        _state: &ControlState,
        _profiles: &ProfileCatalog,
    ) -> io::Result<()> {
        self.0 += 1;
        if self.0 == 2 {
            panic!("test backend failure");
        }
        Ok(())
    }
    fn block(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn unwinding_the_writer_closes_the_listener_without_acknowledging_the_change() {
    let directory = Directory::new();
    let path = directory.0.join("control.sock");
    let (server, stop) = ControlServer::new(UnixListener::bind(&path).unwrap()).unwrap();
    let worker = std::thread::spawn(move || {
        let mut control =
            Control::open(Platform::Linux, [12; 16], Memory::default(), Panicking(0)).unwrap();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| server.run(&mut control))).is_err()
    });
    let mut client = LocalStream::new(UnixStream::connect(&path).unwrap());
    let request = Request::new(
        NonZeroU64::MIN,
        Command::RegisterProfile {
            owner: Owner::LinuxUser {
                uid: unsafe { libc::geteuid() },
            },
            registration_key: "panic".into(),
            consumers: vec![],
        },
    );
    client.send(&request.to_json().unwrap(), &[]).unwrap();
    assert!(client.receive(Some(Duration::from_secs(2))).is_err());
    assert!(worker.join().unwrap());
    let refused = UnixStream::connect(&path).is_err();
    stop.stop();
    assert!(refused);
}

#[test]
fn one_owner_cannot_occupy_more_than_four_connections() {
    use std::io::Read;
    let service = Running::new(empty());
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut stream = UnixStream::connect(&service.path).unwrap();
        stream.write_all(&[0xa1]).unwrap();
        held.push(stream);
    }
    let mut excess = UnixStream::connect(&service.path).unwrap();
    excess
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(excess.read(&mut [0; 1]).unwrap(), 0);
    drop(held);
    drop(excess);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut stream = LocalStream::new(UnixStream::connect(&service.path).unwrap());
        let request = Request::new(NonZeroU64::MIN, Command::Status {});
        if stream.send(&request.to_json().unwrap(), &[]).is_ok()
            && stream.receive(Some(Duration::from_millis(200))).is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Не освободились места управления"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(service.finish().state().serial(), 0);
}

#[test]
#[ignore = "Проверяется в отдельной root VM"]
fn root_connections_remain_available_under_other_owners_slow_frames() {
    for roots_first in [false, true] {
        check_admin_reserve(roots_first);
    }
}

fn check_admin_reserve(roots_first: bool) {
    use std::fs::Permissions;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command as ProcessCommand, Stdio};
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let service = Running::new(empty());
    std::fs::set_permissions(&service._directory.0, Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&service.path, Permissions::from_mode(0o666)).unwrap();
    let hold_root = || {
        (0..2)
            .map(|_| {
                let mut stream = UnixStream::connect(&service.path).unwrap();
                stream.write_all(&[0xa1]).unwrap();
                stream
            })
            .collect::<Vec<_>>()
    };
    let mut reserved = if roots_first { hold_root() } else { Vec::new() };
    let mut children = Vec::new();
    for index in 0..9 {
        let namespace = index == 8;
        let uid = if namespace { 1000 } else { 1000 + index };
        let executable = std::env::current_exe().unwrap();
        let mut command = if namespace {
            let mut command = ProcessCommand::new("unshare");
            command.args(["--user", "--map-root-user"]).arg(executable);
            command
        } else {
            ProcessCommand::new(executable)
        };
        command
            .args([
                "--ignored",
                "--exact",
                "quota_probe_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("AIVPN_SERVICE_QUOTA_SOCKET", &service.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .uid(uid)
            .gid(uid);
        let mut child = ChildGuard(command.spawn().unwrap());
        let mut output = BufReader::new(child.0.stdout.take().unwrap());
        let mut line = String::new();
        let active = loop {
            line.clear();
            assert!(output.read_line(&mut line).unwrap() > 0);
            if let Some((_, count)) = line.split_once("QUOTA_READY ") {
                break count.trim().parse::<usize>().unwrap();
            }
        };
        child.0.stdout = Some(output.into_inner());
        assert_eq!(
            active,
            if namespace {
                0
            } else if index == 7 {
                2
            } else {
                4
            },
            "uid={uid} namespace={namespace}"
        );
        children.push(child);
    }
    if !roots_first {
        reserved = hold_root();
    }
    let mut excess = UnixStream::connect(&service.path).unwrap();
    excess
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(std::io::Read::read(&mut excess, &mut [0; 1]).unwrap(), 0);
    drop(excess);
    drop(reserved);
    let path = service.path.clone();
    let roots = (0..2)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                let request = Request::new(NonZeroU64::MIN, Command::Status {});
                let response =
                    aivpn_desktop_agent::unix::connect_root_control(&path, &request).unwrap();
                is_status(&response);
            })
        })
        .collect::<Vec<_>>();
    for root in roots {
        root.join().unwrap();
    }
    for mut child in children {
        child.0.stdin.take().unwrap().write_all(b"close\n").unwrap();
        assert!(child.0.wait().unwrap().success());
    }
    assert_eq!(service.finish().state().serial(), 0);
}

#[test]
#[ignore]
fn quota_probe_child() {
    use std::io::Read;
    let path = PathBuf::from(std::env::var_os("AIVPN_SERVICE_QUOTA_SOCKET").unwrap());
    let mut sockets = Vec::new();
    for _ in 0..4 {
        let mut stream = UnixStream::connect(&path).unwrap();
        let _ = stream.write_all(&[0xa1]);
        sockets.push(stream);
    }
    std::thread::sleep(Duration::from_millis(100));
    let active = sockets
        .iter()
        .filter(|stream| {
            let mut byte = 0u8;
            let received = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            received < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
        })
        .count();
    println!("QUOTA_READY {active}");
    let _ = std::io::stdin().read(&mut [0; 1]);
    drop(sockets);
}

#[test]
fn startup_and_native_io_faults_release_threads_and_descriptors() {
    let directory = Directory::new();
    std::fs::write(
        directory.0.join("faults.c"),
        include_str!("support/service_faults.c"),
    )
    .unwrap();
    let result = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(directory.0.join("faults.c"))
        .args(["-ldl", "-pthread", "-o"])
        .arg(directory.0.join("faults.so"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for mode in [
        "worker_spawn",
        "acceptor_spawn",
        "accept_denied",
        "accept_interrupted",
        "reply_buffer",
        "peer_denied",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "service_fault_probe_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LD_PRELOAD", directory.0.join("faults.so"))
            .env("AIVPN_SERVICE_FAULT", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore]
fn service_fault_probe_child() {
    let mode = std::env::var("AIVPN_SERVICE_FAULT").unwrap();
    let directory = Directory::new();
    let path = directory.0.join("control.sock");
    let count = || {
        (
            std::fs::read_dir("/proc/self/fd").unwrap().count(),
            std::fs::read_dir("/proc/self/task").unwrap().count(),
        )
    };
    let before = count();
    let (server, stop) = ControlServer::new(UnixListener::bind(&path).unwrap()).unwrap();
    let mut control = empty();
    let assert_released = || {
        // pthread_join завершается после clear_child_tid; /proc может еще видеть
        // завершающуюся задачу. Дескрипторы при этом уже должны быть закрыты.
        assert_eq!(count().0, before.0);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while count().1 != before.1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(count(), before);
    };
    let arm = || {
        let pointer =
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"aivpn_service_arm_fault".as_ptr()) };
        assert!(!pointer.is_null());
        let callback: unsafe extern "C" fn() = unsafe { std::mem::transmute(pointer) };
        unsafe { callback() };
    };
    if matches!(
        mode.as_str(),
        "worker_spawn" | "acceptor_spawn" | "accept_denied"
    ) {
        let pending = (mode == "accept_denied").then(|| UnixStream::connect(&path).unwrap());
        arm();
        let error = server.run(&mut control).unwrap_err();
        assert_eq!(
            error.kind(),
            if mode == "accept_denied" {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::WouldBlock
            }
        );
        assert!(UnixStream::connect(&path).is_err());
        drop(pending);
        drop(stop);
        assert_released();
        assert_eq!(control.state().serial(), 0);
        return;
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let ready = barrier.clone();
    let shutdown = stop.clone();
    let expected = mode == "accept_interrupted";
    let client = std::thread::spawn(move || {
        ready.wait();
        let mut client = LocalStream::new(UnixStream::connect(path).unwrap());
        let request = Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                owner: Owner::LinuxUser {
                    uid: unsafe { libc::geteuid() },
                },
                registration_key: "fault-probe".into(),
                consumers: vec![],
            },
        );
        let _ = client.send(&request.to_json().unwrap(), &[]);
        let response = client.receive(Some(Duration::from_secs(3)));
        shutdown.stop();
        if expected {
            assert!(matches!(
                Response::from_json(&response.unwrap().payload)
                    .unwrap()
                    .result(),
                Outcome::Ok {
                    reply: Reply::Registered { .. }
                }
            ));
        } else {
            assert!(response.is_err());
        }
    });
    arm();
    barrier.wait();
    server.run(&mut control).unwrap();
    client.join().unwrap();
    assert_eq!(control.state().serial(), u64::from(expected));
    drop(stop);
    assert_released();
}
