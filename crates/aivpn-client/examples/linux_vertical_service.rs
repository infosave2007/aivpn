//! Ранний no-NIC harness соединяет настоящие компоненты без Control receipt.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use aivpn_desktop_agent::{linux::OwnedTunnel, unix::LocalStream};
    use std::{
        fs,
        io::{self, BufRead, Write},
        os::{
            fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
            unix::{
                fs::{MetadataExt, PermissionsExt},
                net::UnixStream,
                process::CommandExt,
            },
        },
        process::{Command, Stdio},
        time::Duration,
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(fs::read_to_string("/proc/cmdline")?
        .split_whitespace()
        .any(|s| s == "aivpn.vertical-path=1"));
    assert_eq!(
        fs::read_to_string("/lab/.app-routing-guest")?,
        "aivpn-offline-routing-lab\n"
    );
    let executable = "/usr/libexec/aivpn/aivpn";
    let metadata = fs::metadata(executable)?;
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.mode() & 0o022, 0);
    let home = "/run/vertical-worker";
    fs::create_dir(home)?;
    fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
    let name = std::ffi::CString::new(home).unwrap();
    assert_eq!(unsafe { libc::chown(name.as_ptr(), 65532, 65532) }, 0);
    let connection: serde_json::Value =
        serde_json::from_slice(&fs::read("/run/vertical-connection.json")?)?;
    let peer: std::net::SocketAddr = connection["s"].as_str().unwrap().parse().unwrap();
    let tunnel = OwnedTunnel::create()?;
    let identity = tunnel.verify()?;
    println!(
        "TUN {}",
        serde_json::json!({"name":tunnel.name(),"ifindex":identity.index.get(),"netns":identity.network_namespace.get(),"device":identity.device_identity.get()})
    );
    io::stdout().flush()?;
    let (parent, child_channel) = UnixStream::pair()?;
    let control_fd = child_channel.as_raw_fd();
    let mut command = Command::new(executable);
    command.arg("__packet-worker");
    command
        .env_clear()
        .env("HOME", home)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(control_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 4u32) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    drop(child_channel);
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
    if raw < 0 {
        child.kill()?;
        child.wait()?;
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut channel = LocalStream::new(parent);
    let restricted = channel.receive(Some(Duration::from_secs(10)))?;
    assert_eq!(restricted.payload, b"RESTRICTED");
    assert!(restricted.descriptors.is_empty());
    assert!(child.try_wait()?.is_none());
    println!(
        "RESTRICTED {}",
        serde_json::json!({"pid":child.id(),"parent":std::process::id(),"pidfd":pidfd.as_raw_fd(),"creds_are_child_proof":false})
    );
    io::stdout().flush()?;
    let descriptor = tunnel.duplicate_descriptor()?;
    channel.send(
        &serde_json::to_vec(
            &serde_json::json!({"name":tunnel.name(),"generation":1,"connection":connection}),
        )?,
        &[descriptor.as_fd()],
    )?;
    drop(descriptor);
    let mut stdin = io::stdin().lock().lines();
    let mut transports = Vec::new();
    loop {
        let frame = match channel.receive(Some(Duration::from_secs(30))) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("WORKER_CHANNEL {error}");
                break;
            }
        };
        let event: serde_json::Value = serde_json::from_slice(&frame.payload)?;
        match event["event"].as_str() {
            Some("transport") => {
                assert_eq!(
                    event["peer"]
                        .as_str()
                        .unwrap()
                        .parse::<std::net::SocketAddr>()
                        .unwrap(),
                    peer
                );
                assert_eq!(frame.descriptors.len(), 1);
                let fd = frame.descriptors.into_iter().next().unwrap();
                let socket = socket2::SockRef::from(&fd);
                assert!(socket.peer_addr().is_err());
                assert_eq!(socket.local_addr()?.as_socket().unwrap().port(), 0);
                assert_eq!(socket.r#type()?, socket2::Type::DGRAM);
                let property = |option| -> io::Result<u64> {
                    let mut value = 0u64;
                    let mut size = 8;
                    if unsafe {
                        libc::getsockopt(
                            fd.as_raw_fd(),
                            libc::SOL_SOCKET,
                            option,
                            (&mut value as *mut u64).cast(),
                            &mut size,
                        )
                    } < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    assert_eq!(size, 8);
                    Ok(value)
                };
                let cookie = property(libc::SO_COOKIE)?;
                let netns = property(libc::SO_NETNS_COOKIE)?;
                assert_ne!(cookie, 0);
                assert_eq!(netns, identity.network_namespace.get());
                assert!(child.try_wait()?.is_none());
                transports.push(fd);
                println!(
                    "TRANSPORT {}",
                    serde_json::json!({"cookie":cookie,"netns":netns,"peer":peer,"unbound":true,"before_send":true})
                );
                io::stdout().flush()?;
                channel.send(b"ACK", &[])?;
            }
            Some("assignment") => {
                assert!(frame.descriptors.is_empty());
                println!("ASSIGNMENT {}", event["network"]);
                io::stdout().flush()?;
                assert_eq!(stdin.next().transpose()?.as_deref(), Some("ready"));
                tunnel.verify()?;
                channel.send(b"ACK", &[])?;
            }
            Some("disconnected") => {
                channel.send(b"ACK", &[])?;
                std::thread::sleep(Duration::from_millis(100));
                break;
            }
            _ => panic!("Чужое событие работника"),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    drop(transports);
    drop(channel);
    drop(tunnel);
    fs::remove_dir_all(home)?;
    println!("VERTICAL_SERVICE_CLEANED");
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() {
    panic!("Только собственный Linux guest");
}
