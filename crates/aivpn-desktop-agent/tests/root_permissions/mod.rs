use super::*;
use std::fs::{self, Permissions};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command as ProcessCommand};
use std::time::{Duration, Instant};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn accepted(listener: &UnixListener) -> UnixStream {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("{error}"),
        }
    }
}

#[test]
#[ignore = "Проверяется в отдельной root VM"]
fn root_service_observes_global_uid_for_plain_and_user_namespace_clients() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let directory =
        Directory(std::env::temp_dir().join(format!("aivpn-rpc-root-test-{}", std::process::id())));
    fs::DirBuilder::new()
        .mode(0o755)
        .create(&directory.0)
        .unwrap();
    fs::write(
        directory.0.join(".aivpn-rpc-test"),
        b"aivpn-rpc-fixture-v1\n",
    )
    .unwrap();
    let socket = directory.0.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::set_permissions(&socket, Permissions::from_mode(0o666)).unwrap();
    let mut service = Control::open(Platform::Linux, [7; 16], Memory::default(), Backend).unwrap();
    for (uid, namespace) in [(1000, false), (1000, true), (1, false)] {
        let executable = std::env::current_exe().unwrap();
        let mut command = if namespace {
            let mut command = ProcessCommand::new("unshare");
            command.args(["--user", "--map-root-user"]).arg(&executable);
            command
        } else {
            ProcessCommand::new(&executable)
        };
        command
            .args([
                "--ignored",
                "--exact",
                "root_permissions::unprivileged_rpc_child",
                "--nocapture",
            ])
            .env("AIVPN_RPC_TEST_SOCKET", &socket)
            .env(
                "AIVPN_RPC_TEST_NAMESPACE",
                if namespace { "1" } else { "0" },
            )
            .env("AIVPN_RPC_TEST_UID", uid.to_string())
            .uid(uid)
            .gid(uid);
        let mut child = ChildGuard(command.spawn().unwrap());
        for _ in 0..3 {
            IncomingControl::receive(accepted(&listener))
                .unwrap()
                .execute(&mut service)
                .send()
                .unwrap();
        }
        assert!(child.0.wait().unwrap().success());
    }
    assert_eq!(service.state().serial(), 3);
    let profiles = service
        .state()
        .profiles()
        .list(&Authority {
            user: Owner::LinuxUser { uid: 0 },
            machine_admin: true,
        })
        .unwrap();
    assert_eq!(profiles.len(), 3);
    assert_eq!(
        profiles
            .iter()
            .filter(|profile| profile.owner == (Owner::LinuxUser { uid: 1000 }))
            .count(),
        2
    );
    assert_eq!(
        profiles
            .iter()
            .filter(|profile| profile.owner == (Owner::LinuxUser { uid: 1 }))
            .count(),
        1
    );
    assert!(service.state().profiles().global_dns_profile().is_none());
    let profile = profiles[0].id.clone();
    let (client, server) = UnixStream::pair().unwrap();
    let mut client = LocalStream::new(client);
    let request = Request::new(
        NonZeroU64::MIN,
        Command::SetGlobalDns {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
    );
    client.send(&request.to_json().unwrap(), &[]).unwrap();
    IncomingControl::receive(server)
        .unwrap()
        .execute(&mut service)
        .send()
        .unwrap();
    let response = Response::from_json(
        &client
            .receive(Some(Duration::from_secs(2)))
            .unwrap()
            .payload,
    )
    .unwrap();
    assert!(matches!(
        response.result(),
        Outcome::Ok {
            reply: Reply::Done {}
        }
    ));
    assert_eq!(
        service.state().profiles().global_dns_profile(),
        Some(profile.as_str())
    );
    assert_eq!(service.state().serial(), 4);
}

#[test]
#[ignore]
fn unprivileged_rpc_child() {
    let socket = std::env::var_os("AIVPN_RPC_TEST_SOCKET").unwrap();
    let namespace = std::env::var("AIVPN_RPC_TEST_NAMESPACE").unwrap() == "1";
    let uid = std::env::var("AIVPN_RPC_TEST_UID")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    assert_eq!(unsafe { libc::geteuid() }, if namespace { 0 } else { uid });
    let input = (!namespace).then(|| {
        let saved = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(saved >= 0);
        assert_eq!(unsafe { libc::close(0) }, 0);
        unsafe { OwnedFd::from_raw_fd(saved) }
    });
    let send = |command| {
        let request = Request::new(NonZeroU64::MIN, command);
        if !namespace {
            return aivpn_desktop_agent::unix::connect_root_control(
                std::path::Path::new(&socket),
                &request,
            )
            .unwrap();
        }
        let connection = UnixStream::connect(&socket).unwrap();
        let mut stream = LocalStream::new(connection);
        // В дочернем user namespace UID root-службы не отображается в локальную таблицу.
        assert_ne!(stream.peer_credentials().unwrap().uid, 0);
        stream.send(&request.to_json().unwrap(), &[]).unwrap();
        Response::from_json(
            &stream
                .receive(Some(Duration::from_secs(3)))
                .unwrap()
                .payload,
        )
        .unwrap()
    };
    let response = send(Command::RegisterProfile {
        owner: Owner::LinuxUser { uid },
        registration_key: if namespace { "namespace" } else { "plain" }.into(),
        consumers: vec![],
    });
    let id = match response.result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    };
    let response = send(Command::RegisterProfile {
        owner: Owner::LinuxUser { uid: 0 },
        registration_key: "foreign-root".into(),
        consumers: vec![],
    });
    assert!(matches!(
        response.result(),
        Outcome::Error {
            code: ErrorCode::AccessDenied
        }
    ));
    let response = send(Command::SetGlobalDns {
        profile: id,
        acknowledge_outage: true,
    });
    assert!(matches!(
        response.result(),
        Outcome::Error {
            code: ErrorCode::AccessDenied
        }
    ));
    if let Some(input) = input {
        assert_eq!(unsafe { libc::dup2(input.as_raw_fd(), 0) }, 0);
    }
}
