#![cfg(target_os = "linux")]
use aivpn_desktop_agent::unix::LocalStream;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static SERIAL: Mutex<()> = Mutex::new(());

fn supported_peer(channel: &LocalStream) -> Option<aivpn_desktop_agent::unix::PeerProcess> {
    match channel.peer_process() {
        Ok(peer) => Some(peer),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            eprintln!("Ядро не поддерживает SO_PEERPIDFD, проверен отказ функции");
            None
        }
        Err(error) => panic!("{error}"),
    }
}

struct ChildPeer {
    process: Child,
    directory: std::path::PathBuf,
    channel: LocalStream,
}

impl ChildPeer {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "aivpn-pidfd-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        fs::write(
            directory.join(".aivpn-pidfd-test"),
            b"aivpn-pidfd-fixture-v1\n",
        )
        .unwrap();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "peer_child", "--test-threads=1"])
            .env("AIVPN_PIDFD_SOCKET", &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
            assert!(process.try_wait().unwrap().is_none());
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut channel = LocalStream::new(stream);
        assert_eq!(
            channel
                .receive(Some(Duration::from_secs(2)))
                .unwrap()
                .payload,
            b"ready"
        );
        Self {
            process,
            directory,
            channel,
        }
    }
}

impl Drop for ChildPeer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn captured_peer_identity_matches_the_kernel_process_and_is_close_on_exec() {
    let _serial = SERIAL.lock().unwrap();
    let (raw, _other) = UnixStream::pair().unwrap();
    let channel = LocalStream::new(raw);
    let Some(peer) = supported_peer(&channel) else {
        return;
    };
    assert_eq!(peer.credentials(), channel.peer_credentials().unwrap());
    assert_eq!(peer.credentials().pid.get(), std::process::id());
    assert!(format!("{peer:?}").contains(&std::process::id().to_string()));
    assert!(peer.is_alive().unwrap());
    assert_ne!(
        unsafe { libc::fcntl(peer.as_fd().as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
}

#[test]
fn repeated_process_queries_do_not_add_millisecond_waits() {
    let _serial = SERIAL.lock().unwrap();
    let (raw, _other) = UnixStream::pair().unwrap();
    let channel = LocalStream::new(raw);
    let Some(peer) = supported_peer(&channel) else {
        return;
    };
    let started = std::time::Instant::now();
    for _ in 0..1000 {
        assert!(peer.is_alive().unwrap());
    }
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "Проверка процесса добавляет ожидание к запросам"
    );
}

#[test]
fn a_completed_peer_stays_dead_when_another_connection_is_opened() {
    let _serial = SERIAL.lock().unwrap();
    let mut first = ChildPeer::new();
    let Some(peer) = supported_peer(&first.channel) else {
        return;
    };
    assert_eq!(peer.credentials().pid.get(), first.process.id());
    first.channel.send(b"exit", &[]).unwrap();
    assert!(first.process.wait().unwrap().success());
    assert!(!peer.is_alive().unwrap());
    let second = ChildPeer::new();
    assert!(second.channel.peer_process().unwrap().is_alive().unwrap());
    peer.terminate().unwrap();
    assert!(second.channel.peer_process().unwrap().is_alive().unwrap());
}

#[test]
fn terminating_a_peer_uses_its_kernel_reference() {
    use std::os::unix::process::ExitStatusExt;
    let _serial = SERIAL.lock().unwrap();
    let mut child = ChildPeer::new();
    let Some(peer) = supported_peer(&child.channel) else {
        return;
    };
    peer.terminate().unwrap();
    assert_eq!(child.process.wait().unwrap().signal(), Some(libc::SIGTERM));
    assert!(!peer.is_alive().unwrap());
    peer.terminate().unwrap();
}

#[test]
#[ignore]
fn peer_child() {
    let path = std::env::var_os("AIVPN_PIDFD_SOCKET").unwrap();
    let mut channel = LocalStream::new(UnixStream::connect(path).unwrap());
    channel.send(b"ready", &[]).unwrap();
    assert_eq!(channel.receive(None).unwrap().payload, b"exit");
}

#[test]
#[ignore = "Проверяется в отдельной root VM"]
fn peer_signal_respects_kernel_permissions() {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let (client, _server) = UnixStream::pair().unwrap();
    let number = unsafe { libc::fcntl(client.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 128) };
    assert!(number >= 128);
    let exported = unsafe { OwnedFd::from_raw_fd(number) };
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "peer_low_uid_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("AIVPN_PIDFD_NUMBER", number.to_string())
        .env("AIVPN_PIDFD_ROOT_PID", std::process::id().to_string())
        .uid(1000)
        .gid(1000);
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(number, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    drop(exported);
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore]
fn peer_low_uid_child() {
    use std::os::fd::FromRawFd;
    assert_eq!(unsafe { libc::geteuid() }, 1000);
    let number: i32 = std::env::var("AIVPN_PIDFD_NUMBER")
        .unwrap()
        .parse()
        .unwrap();
    let channel = LocalStream::new(unsafe { UnixStream::from_raw_fd(number) });
    let peer = channel.peer_process().unwrap();
    assert_eq!(peer.credentials().uid, 0);
    assert_eq!(
        peer.credentials().pid.get().to_string(),
        std::env::var("AIVPN_PIDFD_ROOT_PID").unwrap()
    );
    assert!(peer.is_alive().unwrap());
    assert_eq!(
        peer.terminate().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}
