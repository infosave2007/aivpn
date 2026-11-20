#![cfg(target_os = "linux")]

use aivpn_desktop_agent::linux::{
    administration_stream, initialize_packet_worker, restrict_packet_worker, OwnedTunnel,
};
use aivpn_desktop_agent::unix::LocalStream;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "support/tunnel_packets.rs"]
mod tunnel_packets;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        if std::thread::panicking() {
            for mut stream in self
                .0
                .stdout
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn Read>)
                .into_iter()
                .chain(
                    self.0
                        .stderr
                        .take()
                        .map(|pipe| Box::new(pipe) as Box<dyn Read>),
                )
            {
                let mut output = String::new();
                let _ = stream.read_to_string(&mut output);
                eprintln!("{output}");
            }
        }
    }
}

fn isolated_root() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_whitespace()
        .any(|part| part == "aivpn.app-routing-lab=1"));
    assert_eq!(
        fs::read("/lab/.app-routing-guest").unwrap(),
        b"aivpn-offline-routing-lab\n"
    );
}

fn ip(args: &[&str]) {
    let result = Command::new("ip").args(args).output().unwrap();
    assert!(result.status.success(), "{result:?}");
}

fn worker(mode: &str) -> (LocalStream, ChildGuard) {
    let (parent, child) = UnixStream::pair().unwrap();
    let process = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "packet_worker_child", "--nocapture"])
        .env("AIVPN_PACKET_WORKER_TEST", mode)
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (LocalStream::new(parent), ChildGuard(process))
}

#[test]
#[ignore = "Проверяет реальный seccomp в отдельной root VM"]
fn restricted_worker_accepts_administration_without_enabling_ioctl() {
    isolated_root();
    let (mut channel, mut child) = worker("administration");
    assert_eq!(
        channel
            .receive(Some(Duration::from_secs(5)))
            .unwrap()
            .payload,
        b"sealed"
    );
    let (mut root, worker) = UnixStream::pair().unwrap();
    root.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    root.write_all(b"request").unwrap();
    channel.send(b"administration", &[worker.as_fd()]).unwrap();
    let mut reply = [0; 5];
    root.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"reply");
    assert!(child.0.wait().unwrap().success());
}

#[test]
#[ignore = "Проверяет TSYNC на уже созданном потоке в отдельной root VM"]
fn restricted_worker_seals_threads_created_by_runtime_initialization() {
    isolated_root();
    let (mut channel, mut child) = worker("existing_thread");
    assert_eq!(
        channel
            .receive(Some(Duration::from_secs(5)))
            .unwrap()
            .payload,
        b"sealed"
    );
    assert!(child.0.wait().unwrap().success());
}

#[test]
#[ignore = "Выдает TUN только дочернему процессу в отдельной root VM"]
fn restricted_worker_keeps_ipv4_ipv6_and_transport_while_control_operations_are_denied() {
    isolated_root();
    let tunnel = OwnedTunnel::create().unwrap();
    ip(&["link", "set", "dev", tunnel.name(), "up"]);
    ip(&["addr", "add", "10.66.0.1/30", "dev", tunnel.name()]);
    ip(&[
        "-6",
        "addr",
        "add",
        "fd66::1/64",
        "dev",
        tunnel.name(),
        "nodad",
    ]);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let endpoints = format!(
        "{} {}",
        udp.local_addr().unwrap(),
        tcp.local_addr().unwrap()
    );
    let (mut channel, mut child) = worker("packets");
    assert_eq!(
        channel
            .receive(Some(Duration::from_secs(5)))
            .unwrap()
            .payload,
        b"sealed"
    );
    let descriptor = tunnel.duplicate_descriptor().unwrap();
    channel
        .send(endpoints.as_bytes(), &[descriptor.as_fd()])
        .unwrap();
    let mut packet = [0; 32];
    for _ in 0..2 {
        let (length, peer) = udp.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..length], b"transport");
        udp.send_to(b"ok", peer).unwrap();
    }
    let end = Instant::now() + Duration::from_secs(4);
    let mut stream = loop {
        match tcp.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("{error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut request = [0; 3];
    stream.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"tcp");
    stream.write_all(b"ok").unwrap();
    for destination in ["10.66.0.2", "fd66::2"] {
        let result = Command::new("ping")
            .args(["-n", "-c", "1", "-W", "3", "-I", tunnel.name(), destination])
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
    }
    assert_eq!(
        channel
            .receive(Some(Duration::from_secs(5)))
            .unwrap()
            .payload,
        b"finished"
    );
    assert!(child.0.wait().unwrap().success());
    assert!(tunnel.verify().is_ok());
}

#[test]
#[ignore = "Проверяет запуск работника только в отдельной root VM"]
fn privileged_or_extra_unix_capabilities_never_receive_a_tunnel() {
    isolated_root();
    for mode in [
        "root",
        "saved_uid",
        "root_gid",
        "saved_gid",
        "groups",
        "capabilities",
        "extra_unix",
        "raw_socket",
        "netlink",
    ] {
        let (mut channel, mut child) = worker(mode);
        assert_eq!(
            channel
                .receive(Some(Duration::from_secs(5)))
                .unwrap()
                .payload,
            b"rejected",
            "{mode}"
        );
        assert!(child.0.wait().unwrap().success(), "{mode}");
    }
}

fn denied(result: libc::c_long) {
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
}

#[test]
#[ignore = "Вспомогательный процесс нативного стенда"]
fn packet_worker_child() {
    let Ok(mode) = std::env::var("AIVPN_PACKET_WORKER_TEST") else {
        return;
    };
    isolated_root();
    let control = unsafe { OwnedFd::from_raw_fd(0) };
    let extra = (mode == "extra_unix").then(|| UnixStream::pair().unwrap());
    let retained = if mode == "raw_socket" || mode == "netlink" {
        let (family, kind, protocol) = if mode == "raw_socket" {
            (libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
        } else {
            (libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)
        };
        let descriptor = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, protocol) };
        assert!(descriptor >= 0, "{}", std::io::Error::last_os_error());
        Some(unsafe { OwnedFd::from_raw_fd(descriptor) })
    } else if mode == "packets" {
        Some(OwnedFd::from(UdpSocket::bind("127.0.0.1:0").unwrap()))
    } else {
        None
    };

    if mode == "capabilities" {
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) }, 0);
    }
    if mode != "root" {
        let groups: &[libc::gid_t] = if mode == "groups" { &[1] } else { &[] };
        assert_eq!(unsafe { libc::setgroups(groups.len(), groups.as_ptr()) }, 0);
        let gid = if mode == "root_gid" { 0 } else { 1000 };
        let saved_gid = if mode == "saved_gid" { 0 } else { gid };
        assert_eq!(unsafe { libc::setresgid(gid, gid, saved_gid) }, 0);
        let saved = if mode == "saved_uid" { 0 } else { 1000 };
        assert_eq!(unsafe { libc::setresuid(1000, 1000, saved) }, 0);
    }
    if mode == "existing_thread" {
        let (release, ready) = std::sync::mpsc::sync_channel(1);
        let thread = initialize_packet_worker(control.as_fd(), || {
            std::thread::Builder::new().spawn(move || {
                ready.recv().unwrap();
                // Без TSYNC этот вызов обычного пользователя успешно меняет dumpable.
                denied(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } as _);
                assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }, 2);
            })
        })
        .unwrap();
        release.send(()).unwrap();
        thread.join().unwrap();
        LocalStream::new(UnixStream::from(control))
            .send(b"sealed", &[])
            .unwrap();
        return;
    }
    let result = restrict_packet_worker(control.as_fd());
    std::hint::black_box(&retained);
    if mode == "root_datagram" {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            unsafe { libc::write(control.as_raw_fd(), b"rejected".as_ptr().cast(), 8) },
            8
        );
        return;
    }
    let mut channel = LocalStream::new(UnixStream::from(control));
    if mode == "administration" {
        result.unwrap();
        let pid = channel.peer_credentials().unwrap().pid;
        channel.send(b"sealed", &[]).unwrap();
        let frame = channel.receive(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(frame.payload, b"administration");
        assert_eq!(frame.descriptors.len(), 1);
        let mut stream = administration_stream(frame.descriptors.into_iter().next().unwrap(), pid)
            .expect("Канал администрирования должен работать после seccomp");
        let mut request = [0; 7];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"request");
        assert_eq!(
            stream.read(&mut request).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut enabled: libc::c_int = 1;
        denied(unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONBIO, &mut enabled) } as _);
        stream.write_all(b"reply").unwrap();
        return;
    }
    if mode != "packets" {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        channel.send(b"rejected", &[]).unwrap();
        drop(extra);
        return;
    }
    result.unwrap();
    channel.send(b"sealed", &[]).unwrap();
    let frame = channel.receive(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(frame.descriptors.len(), 1);
    let endpoints = std::str::from_utf8(&frame.payload)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>();
    let mut file = fs::File::from(frame.descriptors.into_iter().next().unwrap());
    denied(unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETPERSIST, 1) } as _);
    denied(unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETOWNER, 1000) } as _);
    denied(unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETGROUP, 1000) } as _);
    denied(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } as _);
    denied(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) } as _);
    denied(unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) } as _);
    denied(unsafe { libc::unshare(libc::CLONE_NEWUSER) } as _);
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
        1
    );
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }, 2);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    udp.send_to(b"transport", endpoints[0]).unwrap();
    let mut answer = [0; 2];
    udp.recv(&mut answer).unwrap();
    assert_eq!(&answer, b"ok");
    let endpoint = endpoints[0].to_owned();
    std::thread::spawn(move || {
        denied(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } as _);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        udp.connect(endpoint).unwrap();
        let mut vector = libc::iovec {
            iov_base: b"transport".as_ptr().cast_mut().cast(),
            iov_len: b"transport".len(),
        };
        let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
        message.msg_hdr.msg_iov = &mut vector;
        message.msg_hdr.msg_iovlen = 1;
        assert_eq!(
            unsafe { libc::sendmmsg(udp.as_raw_fd(), &mut message, 1, 0) },
            1
        );
        assert_eq!(message.msg_len, 9);
        let mut answer = [0; 2];
        udp.recv(&mut answer).unwrap();
        assert_eq!(&answer, b"ok");
    })
    .join()
    .unwrap();
    let mut tcp = TcpStream::connect(endpoints[1]).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp.write_all(b"tcp").unwrap();
    tcp.read_exact(&mut answer).unwrap();
    assert_eq!(&answer, b"ok");
    for ipv6 in [false, true] {
        let end = Instant::now() + Duration::from_secs(4);
        let mut packet = [0u8; 2048];
        let length = loop {
            match file.read(&mut packet) {
                Ok(length) if length > 40 && packet[0] >> 4 == if ipv6 { 6 } else { 4 } => {
                    if ipv6 && packet[40] != 128 {
                        continue;
                    }
                    break length;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
            assert!(Instant::now() < end, "No packet for the worker");
            std::thread::sleep(Duration::from_millis(1));
        };
        tunnel_packets::reply(&mut packet[..length], ipv6);
        file.write_all(&packet[..length]).unwrap();
    }
    channel.send(b"finished", &[]).unwrap();
}

#[test]
#[ignore = "Проверяет канал работника в отдельной root VM"]
fn a_root_owned_datagram_channel_cannot_export_tunnel_capabilities() {
    isolated_root();
    let (parent, child) = std::os::unix::net::UnixDatagram::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut process = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "packet_worker_child", "--nocapture"])
            .env("AIVPN_PACKET_WORKER_TEST", "root_datagram")
            .stdin(Stdio::from(OwnedFd::from(child)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut reply = [0; 16];
    let length = parent.recv(&mut reply).unwrap();
    assert_eq!(&reply[..length], b"rejected");
    assert!(process.0.wait().unwrap().success());
}
