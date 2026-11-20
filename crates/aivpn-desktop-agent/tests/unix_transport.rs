#![cfg(target_os = "linux")]
use aivpn_desktop_agent::{
    unix::{Frame, LocalStream},
    MAX_FRAME_BYTES,
};
use std::{
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    sync::Mutex,
    thread,
    time::Duration,
};
static SERIAL: Mutex<()> = Mutex::new(());

fn pair() -> (LocalStream, LocalStream) {
    let (a, b) = UnixStream::pair().unwrap();
    (LocalStream::new(a), LocalStream::new(b))
}
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    }
}
#[test]
fn framing_preserves_messages_and_kernel_credentials() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, mut b) = pair();
    let peer = a.peer_credentials().unwrap();
    assert_eq!(peer.uid, unsafe { libc::geteuid() });
    assert_eq!(peer.pid.get(), std::process::id());
    let server = thread::spawn(move || {
        for text in [b"first".as_slice(), b"second"] {
            let request = b.receive(None).unwrap();
            assert_eq!(request.payload, text);
            assert!(request.descriptors.is_empty());
            b.send(&request.payload, &[]).unwrap();
        }
    });
    for text in [b"first".as_slice(), b"second"] {
        a.send(text, &[]).unwrap();
        assert_eq!(
            a.receive(Some(Duration::from_secs(1))).unwrap().payload,
            text
        );
    }
    server.join().unwrap();
}
#[test]
fn file_descriptors_arrive_once_and_close_on_exec() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, mut b) = pair();
    let (read, write) = pipe();
    a.send(b"tun", &[read.as_fd()]).unwrap();
    let frame = b.receive(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(frame.descriptors.len(), 1);
    assert_ne!(frame.descriptors[0].as_raw_fd(), read.as_raw_fd());
    let flags = unsafe { libc::fcntl(frame.descriptors[0].as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    assert_eq!(
        unsafe { libc::write(write.as_raw_fd(), b"payload".as_ptr().cast(), 7) },
        7
    );
    let mut file = std::fs::File::from(frame.descriptors.into_iter().next().unwrap());
    let mut bytes = [0; 7];
    file.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"payload");
}
#[test]
fn local_rejection_does_not_corrupt_the_next_frame() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, mut b) = pair();
    assert!(a.send(&[], &[]).is_err());
    assert!(a.send(&vec![0; MAX_FRAME_BYTES + 1], &[]).is_err());
    let (read, _write) = pipe();
    assert!(a
        .send(b"x", &[read.as_fd(), read.as_fd(), read.as_fd()])
        .is_err());
    a.send(b"valid", &[]).unwrap();
    assert_eq!(
        b.receive(Some(Duration::from_secs(1))).unwrap().payload,
        b"valid"
    );
}
#[test]
fn the_exact_payload_limit_is_accepted_without_truncation() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, mut b) = pair();
    let expected = vec![0x5a; MAX_FRAME_BYTES];
    let sent = expected.clone();
    let writer = thread::spawn(move || a.send(&sent, &[]).unwrap());
    let frame = b.receive(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(frame.payload, expected);
    writer.join().unwrap();
}
#[test]
fn invalid_magic_and_length_poison_the_connection() {
    let _guard = SERIAL.lock().unwrap();
    for header in [
        vec![0, 0, 0, 0, 0, 1],
        vec![0xa1, 0, 0, 0, 0, 0],
        vec![0xa1, 0, 0xff, 0xff, 0xff, 0xff],
    ] {
        let (raw, stream) = UnixStream::pair().unwrap();
        let mut sender = raw;
        let mut receiver = LocalStream::new(stream);
        sender.write_all(&header).unwrap();
        assert!(receiver.receive(Some(Duration::from_secs(1))).is_err());
        assert_eq!(
            receiver.receive(None).unwrap_err().kind(),
            std::io::ErrorKind::NotConnected
        );
    }
}
#[test]
fn a_partial_frame_has_a_total_deadline() {
    let _guard = SERIAL.lock().unwrap();
    let (mut raw, stream) = UnixStream::pair().unwrap();
    let mut receiver = LocalStream::new(stream);
    receiver
        .limit_frame_timeout(Duration::from_millis(30))
        .unwrap();
    raw.write_all(&[0xa1, 0, 0, 0, 0, 4, b'a']).unwrap();
    assert!(receiver.receive(Some(Duration::from_secs(1))).is_err());
    assert_eq!(
        receiver.receive(None).unwrap_err().kind(),
        std::io::ErrorKind::NotConnected
    );
}
#[test]
fn frame_debug_never_prints_payload_contents() {
    let _guard = SERIAL.lock().unwrap();
    let frame = Frame {
        payload: b"secret-connection-key".to_vec(),
        descriptors: vec![],
    };
    let debug = format!("{frame:?}");
    assert!(!debug.contains("secret"));
    assert!(debug.contains("21"));
}

fn raw_marker(stream: &UnixStream, byte: u8, descriptors: &[std::os::fd::BorrowedFd<'_>]) {
    let mut control = vec![0usize; 32];
    let marker = [byte];
    let mut vector = libc::iovec {
        iov_base: marker.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE((descriptors.len() * 4) as u32) } as usize;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((descriptors.len() * 4) as u32) as usize;
            for (index, fd) in descriptors.iter().enumerate() {
                libc::CMSG_DATA(header)
                    .cast::<i32>()
                    .add(index)
                    .write_unaligned(fd.as_raw_fd());
            }
        }
    }
    assert_eq!(
        unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
        1
    );
}

// Проверка всего списка FD идет в отдельном процессе, без соседних тестов.
fn isolated_descriptor_check(name: &str) -> bool {
    if std::env::var("AIVPN_AGENT_FD_TEST").ok().as_deref() == Some(name) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env("AIVPN_AGENT_FD_TEST", name)
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

fn original_pipe_remains_usable(read: &OwnedFd, write: &OwnedFd) {
    assert_eq!(
        unsafe { libc::write(write.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let mut byte = 0u8;
    assert_eq!(
        unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
        1
    );
    assert_eq!(byte, b'x');
}

fn descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn malformed_ancillary_frames_do_not_leak_descriptors() {
    if !isolated_descriptor_check("malformed_ancillary_frames_do_not_leak_descriptors") {
        return;
    }
    let _guard = SERIAL.lock().unwrap();
    let (read, write) = pipe();
    let before = descriptor_count();
    for index in 0..300 {
        let (mut raw, stream) = UnixStream::pair().unwrap();
        let mut receiver = LocalStream::new(stream);
        let count = if index % 3 == 0 { 20 } else { 1 };
        let descriptors = (0..count).map(|_| read.as_fd()).collect::<Vec<_>>();
        raw_marker(&raw, if index % 3 == 1 { 0 } else { 0xa1 }, &descriptors);
        raw.write_all(&[0, 0, 0, 0, 1, b'x']).unwrap();
        assert!(receiver.receive(Some(Duration::from_secs(1))).is_err());
    }
    original_pipe_remains_usable(&read, &write);
    assert_eq!(descriptor_count(), before);
}
#[test]
fn an_ancillary_descriptor_in_the_payload_is_rejected_and_closed() {
    if !isolated_descriptor_check("an_ancillary_descriptor_in_the_payload_is_rejected_and_closed") {
        return;
    }
    let _guard = SERIAL.lock().unwrap();
    let (read, write) = pipe();
    let before = descriptor_count();
    {
        let (mut raw, stream) = UnixStream::pair().unwrap();
        let mut receiver = LocalStream::new(stream);
        raw.write_all(&[0xa1, 0, 0, 0, 0, 1]).unwrap();
        raw_marker(&raw, b'x', &[read.as_fd()]);
        assert!(receiver.receive(Some(Duration::from_secs(1))).is_err());
    }
    original_pipe_remains_usable(&read, &write);
    assert_eq!(descriptor_count(), before);
}
#[test]
fn eof_during_a_frame_releases_its_received_descriptor() {
    if !isolated_descriptor_check("eof_during_a_frame_releases_its_received_descriptor") {
        return;
    }
    let _guard = SERIAL.lock().unwrap();
    let (read, write) = pipe();
    let before = descriptor_count();
    {
        let (mut raw, stream) = UnixStream::pair().unwrap();
        let mut receiver = LocalStream::new(stream);
        raw_marker(&raw, 0xa1, &[read.as_fd()]);
        raw.write_all(&[1, 0, 0, 0, 10, b'a']).unwrap();
        drop(raw);
        assert!(receiver.receive(Some(Duration::from_secs(1))).is_err());
    }
    original_pipe_remains_usable(&read, &write);
    assert_eq!(descriptor_count(), before);
}
#[test]
fn two_descriptors_share_one_frame_without_stealing_the_next_frame() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, mut b) = pair();
    let (read, write) = pipe();
    a.send(b"two", &[read.as_fd(), write.as_fd()]).unwrap();
    a.send(b"next", &[]).unwrap();
    assert_eq!(
        b.receive(Some(Duration::from_secs(1)))
            .unwrap()
            .descriptors
            .len(),
        2
    );
    assert_eq!(
        b.receive(Some(Duration::from_secs(1))).unwrap().payload,
        b"next"
    );
}
#[test]
fn a_failed_write_closes_the_channel_without_sigpipe() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, b) = pair();
    drop(b);
    assert!(a.send(b"closed", &[]).is_err());
    assert_eq!(
        a.send(b"again", &[]).unwrap_err().kind(),
        std::io::ErrorKind::NotConnected
    );
}
#[test]
fn invalid_timeout_settings_do_not_disable_deadlines() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, mut b) = pair();
    assert!(a.limit_frame_timeout(Duration::ZERO).is_err());
    assert!(a.limit_frame_timeout(Duration::from_secs(6)).is_err());
    assert!(a.limit_frame_timeout(Duration::from_secs(5)).is_ok());
    a.send(b"still-open", &[]).unwrap();
    assert_eq!(
        b.receive(Some(Duration::from_secs(1))).unwrap().payload,
        b"still-open"
    );
}
#[test]
fn a_blocked_write_obeys_the_frame_deadline() {
    let _guard = SERIAL.lock().unwrap();
    let (a, _b) = UnixStream::pair().unwrap();
    let limit: libc::c_int = 1024;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                a.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&limit as *const libc::c_int).cast(),
                std::mem::size_of_val(&limit) as libc::socklen_t,
            )
        },
        0
    );
    let mut sender = LocalStream::new(a);
    sender
        .limit_frame_timeout(Duration::from_millis(30))
        .unwrap();
    assert!(sender.send(&vec![42; MAX_FRAME_BYTES], &[]).is_err());
    assert_eq!(
        sender.send(b"again", &[]).unwrap_err().kind(),
        std::io::ErrorKind::NotConnected
    );
}

#[test]
fn unexpected_ancillary_credentials_do_not_leave_received_rights_open() {
    if !isolated_descriptor_check(
        "unexpected_ancillary_credentials_do_not_leave_received_rights_open",
    ) {
        return;
    }
    let _guard = SERIAL.lock().unwrap();
    let (read, write) = pipe();
    let before = descriptor_count();
    {
        let (mut raw, stream) = UnixStream::pair().unwrap();
        let enabled: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            },
            0
        );
        let mut receiver = LocalStream::new(stream);
        raw_marker(&raw, 0xa1, &[read.as_fd()]);
        raw.write_all(&[1, 0, 0, 0, 1, b'x']).unwrap();
        assert!(receiver.receive(Some(Duration::from_secs(1))).is_err());
    }
    original_pipe_remains_usable(&read, &write);
    assert_eq!(descriptor_count(), before);
}
#[test]
fn an_expired_write_deadline_never_starts_a_frame() {
    let _guard = SERIAL.lock().unwrap();
    let (mut a, _b) = pair();
    a.limit_frame_timeout(Duration::from_nanos(1)).unwrap();
    assert_eq!(
        a.send(b"too-late", &[]).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
}
#[test]
fn a_peer_cannot_extend_the_frame_deadline_by_dribbling_bytes() {
    let _guard = SERIAL.lock().unwrap();
    let (mut raw, stream) = UnixStream::pair().unwrap();
    let observer = stream.try_clone().unwrap();
    let mut receiver = LocalStream::new(stream);
    receiver
        .limit_frame_timeout(Duration::from_millis(100))
        .unwrap();
    raw.write_all(&[0xa1, 0, 0, 0, 0, 4]).unwrap();
    let sender = thread::spawn(move || {
        loop {
            let mut available: libc::c_int = -1;
            assert_eq!(
                unsafe { libc::ioctl(observer.as_raw_fd(), libc::FIONREAD, &mut available) },
                0
            );
            if available == 0 {
                break;
            }
            thread::yield_now();
        }
        for byte in b"slow" {
            thread::sleep(Duration::from_millis(40));
            if raw.write_all(&[*byte]).is_err() {
                break;
            }
        }
    });
    assert!(receiver.receive(Some(Duration::from_secs(1))).is_err());
    sender.join().unwrap();
}

#[test]
fn an_unrepresentable_idle_deadline_is_rejected() {
    let _guard = SERIAL.lock().unwrap();
    let (_a, mut b) = pair();
    assert!(b.receive(Some(Duration::MAX)).is_err());
}

#[cfg(target_env = "gnu")]
struct FaultLibrary(std::path::PathBuf);
#[cfg(target_env = "gnu")]
impl Drop for FaultLibrary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[cfg(target_env = "gnu")]
fn fault_library() -> FaultLibrary {
    use std::os::unix::fs::DirBuilderExt;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("aivpn-agent-io-{}-{nonce}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    let library = FaultLibrary(path);
    std::fs::write(
        library.0.join(".aivpn-agent-io-test"),
        b"aivpn-agent-io-fixture-v1\n",
    )
    .unwrap();
    std::fs::write(
        library.0.join("faults.c"),
        include_str!("support/io_faults.c"),
    )
    .unwrap();
    let output = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(format!("-DAIVPN_SO_PEERPIDFD={}", libc::SO_PEERPIDFD))
        .arg(library.0.join("faults.c"))
        .args(["-ldl", "-o"])
        .arg(library.0.join("faults.so"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    library
}
#[cfg(target_env = "gnu")]
#[test]
fn native_syscall_faults_preserve_framing_and_identity_checks() {
    let _guard = SERIAL.lock().unwrap();
    let library = fault_library();
    let (probe, _other) = pair();
    let pidfd_supported = match probe.peer_process() {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => false,
        Err(error) => panic!("{error}"),
    };
    for mode in [
        "send_interrupted_forever",
        "start_interrupted_forever",
        "receive_interrupted_forever",
        "body_interrupted_forever",
        "send_late",
        "receive_late",
        "send_zero",
        "send_denied",
        "send_interrupted",
        "start_zero",
        "start_denied",
        "start_interrupted",
        "receive_oversized",
        "receive_eof",
        "receive_denied",
        "receive_interrupted",
        "short_io",
        "peer_denied",
        "peer_zero",
        "peer_one",
        "peer_negative",
        "peer_short",
        "pidfd_denied",
        "pidfd_unsupported",
        "pidfd_short",
        "pidfd_negative",
        "pidfd_no_cloexec",
        "pidfd_zero",
        "pidfd_poll_error",
        "pidfd_poll_invalid",
        "pidfd_poll_unknown",
        "pidfd_poll_hup",
    ] {
        if !pidfd_supported
            && mode.starts_with("pidfd_")
            && !matches!(mode, "pidfd_denied" | "pidfd_unsupported")
        {
            continue;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "fault_probe_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LD_PRELOAD", library.0.join("faults.so"))
            .env("AIVPN_AGENT_IO_FAULT", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "mode {mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// Отдельный процесс нужен для подмены libc, чтобы не затронуть остальные проверки.
#[cfg(target_env = "gnu")]
#[test]
#[ignore]
fn fault_probe_child() {
    let mode = std::env::var("AIVPN_AGENT_IO_FAULT").unwrap();
    let (mut a, mut b) = pair();
    if mode.starts_with("pidfd_") {
        let before = descriptor_count();
        let saved_stdin = (mode == "pidfd_zero").then(|| {
            let fd = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(fd >= 0);
            unsafe { OwnedFd::from_raw_fd(fd) }
        });
        match mode.as_str() {
            "pidfd_zero" => {
                let peer = a.peer_process().unwrap();
                assert_eq!(peer.as_fd().as_raw_fd(), 0);
                assert!(peer.is_alive().unwrap());
            }
            "pidfd_poll_hup" => assert!(!a.peer_process().unwrap().is_alive().unwrap()),
            mode if mode.starts_with("pidfd_poll_") => {
                assert!(a.peer_process().unwrap().is_alive().is_err())
            }
            "pidfd_unsupported" => assert_eq!(
                a.peer_process().unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            ),
            _ => assert_eq!(
                a.peer_process().unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            ),
        }
        if let Some(input) = saved_stdin {
            assert_eq!(unsafe { libc::dup2(input.as_raw_fd(), 0) }, 0);
        }
        assert_eq!(descriptor_count(), before);
        return;
    }
    if mode.ends_with("forever") || mode.ends_with("late") {
        a.limit_frame_timeout(Duration::from_millis(50)).unwrap();
        b.limit_frame_timeout(Duration::from_millis(50)).unwrap();
        let result = if mode.starts_with("send_") || mode.starts_with("start_") {
            a.send(b"frame", &[])
        } else {
            a.send(b"frame", &[]).unwrap();
            b.receive(Some(Duration::from_millis(50))).map(|_| ())
        };
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        return;
    }
    if mode == "receive_oversized" {
        a.send(b"frame", &[]).unwrap();
        assert_eq!(
            b.receive(Some(Duration::from_secs(1))).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        return;
    }
    if mode.starts_with("peer_") {
        match mode.as_str() {
            "peer_one" => assert_eq!(a.peer_credentials().unwrap().pid.get(), 1),
            "peer_denied" => assert_eq!(
                a.peer_credentials().unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            ),
            _ => assert_eq!(
                a.peer_credentials().unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            ),
        }
        return;
    }
    if mode.starts_with("receive_") && !mode.ends_with("interrupted") {
        let expected = if mode == "receive_eof" {
            std::io::ErrorKind::UnexpectedEof
        } else {
            std::io::ErrorKind::PermissionDenied
        };
        assert_eq!(
            b.receive(Some(Duration::from_secs(1))).unwrap_err().kind(),
            expected
        );
        return;
    }
    if mode.ends_with("zero") || mode.ends_with("denied") {
        let expected = if mode.ends_with("zero") {
            std::io::ErrorKind::WriteZero
        } else {
            std::io::ErrorKind::PermissionDenied
        };
        assert_eq!(a.send(b"frame", &[]).unwrap_err().kind(), expected);
        return;
    }
    a.send(b"frame", &[]).unwrap();
    let reply = b.receive(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(reply.payload, b"frame");
}
