use super::*;
use aivpn_desktop_agent::unix::{call_root_control, connect_root_control};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::time::Duration;

#[test]
fn a_full_service_socket_queue_does_not_block_the_control_client() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = Directory(std::env::temp_dir().join(format!(
        "aivpn-control-queue-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let path = directory.0.join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
    let _queued = UnixStream::connect(&path).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "root_client::full_queue_probe_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("AIVPN_CONTROL_QUEUE_TEST_SOCKET", &path)
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore]
fn full_queue_probe_child() {
    let path =
        std::path::PathBuf::from(std::env::var_os("AIVPN_CONTROL_QUEUE_TEST_SOCKET").unwrap());
    // Таймер действует только в отдельном процессе теста.
    unsafe { libc::alarm(2) };
    let request = Request::new(NonZeroU64::MIN, Command::Status {});
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    for _ in 0..1000 {
        assert_eq!(
            connect_root_control(&path, &request).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    unsafe { libc::alarm(0) };
    assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
}

#[test]
fn a_non_root_endpoint_receives_no_request() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (client, mut server) = UnixStream::pair().unwrap();
    let request = Request::new(NonZeroU64::MIN, Command::Status {});
    let error = call_root_control(client, &request).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    server
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
#[ignore = "Проверяется в отдельной root VM"]
fn root_control_replies_are_checked_before_returning_to_ui() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    for case in 0..7 {
        let (client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut server = LocalStream::new(server);
            let frame = server.receive(Some(Duration::from_secs(2))).unwrap();
            assert!(frame.descriptors.is_empty());
            let request = Request::from_json(&frame.payload).unwrap();
            assert_eq!(request.id().get(), 75);
            if case == 6 {
                return;
            }
            let id = NonZeroU64::new(if case == 2 { 76 } else { 75 }).unwrap();
            let payload=match case {
                1=>Response::failure(id,ErrorCode::Conflict).to_json().unwrap(),
                4=>br#"{"version":1,"id":75,"result":{"outcome":"ok","reply":{"kind":"done","authority":true}}}"#.to_vec(),
                5=>br#"{"version":2,"id":75,"result":{"outcome":"ok","reply":{"kind":"done"}}}"#.to_vec(),
                _=>Response::success(id,Reply::Done {}).to_json().unwrap(),
            };
            let file = std::fs::File::open("/dev/null").unwrap();
            let descriptors = if case == 3 {
                vec![file.as_fd()]
            } else {
                vec![]
            };
            server.send(&payload, &descriptors).unwrap();
        });
        let request = Request::new(NonZeroU64::new(75).unwrap(), Command::Status {});
        let response = call_root_control(client, &request);
        if case < 2 {
            let response = response.unwrap();
            assert_eq!(response.id(), request.id());
            if case == 0 {
                assert!(matches!(
                    response.result(),
                    Outcome::Ok {
                        reply: Reply::Done {}
                    }
                ));
            } else {
                assert!(matches!(
                    response.result(),
                    Outcome::Error {
                        code: ErrorCode::Conflict
                    }
                ));
            }
        } else if case == 6 {
            assert_eq!(response.err().unwrap().kind(), io::ErrorKind::UnexpectedEof);
        } else {
            assert_eq!(response.err().unwrap().kind(), io::ErrorKind::InvalidData);
        }
        worker.join().unwrap();
    }
    let (client, mut server) = UnixStream::pair().unwrap();
    let oversized = Request::new(
        NonZeroU64::MIN,
        Command::RegisterProfile {
            owner: Owner::LinuxUser { uid: 0 },
            registration_key: "x".repeat(aivpn_desktop_agent::MAX_FRAME_BYTES),
            consumers: vec![],
        },
    );
    assert_eq!(
        call_root_control(client, &oversized).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    server
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
    let executable = std::env::current_exe().unwrap();
    let status = std::process::Command::new("unshare")
        .args(["--user", "--map-root-user"])
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            "root_client::a_nested_namespace_cannot_supply_a_fake_root_endpoint",
            "--nocapture",
        ])
        .uid(1000)
        .gid(1000)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore]
fn a_nested_namespace_cannot_supply_a_fake_root_endpoint() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let (client, mut server) = UnixStream::pair().unwrap();
    let peer = LocalStream::new(client.try_clone().unwrap())
        .peer_credentials()
        .unwrap();
    assert_eq!(peer.uid, 0);
    let request = Request::new(NonZeroU64::MIN, Command::Status {});
    assert_eq!(
        call_root_control(client, &request).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
    server
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
}
