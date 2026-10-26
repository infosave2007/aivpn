//! Shared low-level I/O for the mobile tunnels: UDP socket factory (with a
//! platform `protect` hook for Android's `VpnService.protect`), the stop
//! signal (eventfd on linux/android, pipe elsewhere) and async TUN I/O.
//! Hoisted verbatim from `android_tunnel.rs`; the pipe-based
//! `create_stop_signal` fallback is iOS's version (it has the race-arm
//! re-check the Android pipe fallback lacked).

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::unix::AsyncFd;

use crate::error::{Error, Result};

use super::state::{SessionRuntime, LAST_LOCAL_PORT};

// ──────────── Protected UDP socket creation ────────────

pub fn create_udp_socket(
    dest: SocketAddr,
    session: &Arc<SessionRuntime>,
    // No `Sync` bound: this is invoked synchronously on the calling task and is
    // never stored or sent elsewhere. Requiring `Sync` here would force it up
    // through `PlatformIo`, obliging iOS to make its raw Swift context pointer
    // `Sync` — a promise nothing in the call graph needs or can honour.
    protect: &dyn Fn(RawFd) -> Result<()>,
) -> Result<RawFd> {
    let port_hint = LAST_LOCAL_PORT.load(Ordering::Relaxed);
    let bind_address = |port| match dest {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], port)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], port)),
    };
    let socket = std::net::UdpSocket::bind(bind_address(port_hint)).or_else(|error| {
        if port_hint != 0 {
            std::net::UdpSocket::bind(bind_address(0))
        } else {
            Err(error)
        }
    })?;
    // Защита применяется до отправки первого пакета; RAII закрывает fd при ошибке.
    let fd = socket.as_raw_fd();
    protect(fd)?;
    let sock_buf: libc::c_int = 4 * 1024 * 1024;
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                &sock_buf as *const _ as *const libc::c_void,
                std::mem::size_of_val(&sock_buf) as libc::socklen_t,
            );
        }
    }
    socket.connect(dest)?;
    LAST_LOCAL_PORT.store(socket.local_addr()?.port(), Ordering::Relaxed);
    let control = socket.try_clone()?;
    session
        .udp_control_fd
        .store(control.into_raw_fd(), Ordering::SeqCst);
    Ok(socket.into_raw_fd())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn create_stop_signal(session: &Arc<SessionRuntime>) -> Result<AsyncFd<OwnedFd>> {
    let stop_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if stop_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    let control_fd = unsafe { libc::dup(stop_fd) };
    if control_fd < 0 {
        unsafe { libc::close(stop_fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    session.stop_signal_fd.store(control_fd, Ordering::SeqCst);

    // If stop_active_tunnel() fired in the race window between the last
    // stop_requested check and this function, the eventfd was never written
    // to (stop_signal_fd was -1 at that point). Arm it now so the main loop
    // exits on its first poll instead of hanging forever.
    if session.stop_requested.load(Ordering::SeqCst) {
        let v: u64 = 1;
        unsafe {
            let _ = libc::write(
                stop_fd,
                &v as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }

    let owned_stop_fd = unsafe { OwnedFd::from_raw_fd(stop_fd) };
    // AsyncFd владеет этим fd до deregister; control_fd является отдельным dup.
    Ok(unsafe { AsyncFd::register(owned_stop_fd) }.map_err(std::io::Error::from)?)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn create_stop_signal(session: &Arc<SessionRuntime>) -> Result<AsyncFd<OwnedFd>> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    unsafe { libc::fcntl(read_fd, libc::F_SETFL, libc::O_NONBLOCK) };
    let dup_write = unsafe { libc::dup(write_fd) };
    if dup_write < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd)
        };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    session.stop_signal_fd.store(dup_write, Ordering::SeqCst);

    // If stop_active_tunnel() fired in the race window between the last
    // stop_requested check and this function, the pipe was never written to
    // (stop_signal_fd was -1 at that point). Arm it now so the tunnel exits
    // on its first poll instead of hanging forever (mirrors android_tunnel.rs).
    if session.stop_requested.load(Ordering::SeqCst) {
        let v: u8 = 1;
        unsafe { libc::write(write_fd, &v as *const u8 as *const libc::c_void, 1) };
    }

    unsafe { libc::close(write_fd) };
    let owned_read_fd = unsafe { OwnedFd::from_raw_fd(read_fd) };
    // Read fd не меняется до drop AsyncFd; сигнал записывается через другой fd.
    Ok(unsafe { AsyncFd::register(owned_read_fd) }.map_err(std::io::Error::from)?)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub async fn wait_for_stop(stop_signal: &AsyncFd<OwnedFd>) -> std::io::Result<()> {
    loop {
        let mut guard = stop_signal.readable().await?;
        match guard.try_io(|inner| {
            let mut value: u64 = 0;
            let n = unsafe {
                libc::read(
                    inner.as_raw_fd(),
                    &mut value as *mut u64 as *mut libc::c_void,
                    std::mem::size_of::<u64>(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub async fn wait_for_stop(stop_signal: &AsyncFd<OwnedFd>) -> std::io::Result<()> {
    loop {
        let mut guard = stop_signal.readable().await?;
        match guard.try_io(|inner| {
            let mut b = [0u8; 1];
            let n =
                unsafe { libc::read(inner.as_raw_fd(), b.as_mut_ptr() as *mut libc::c_void, 1) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

// ──────────── Async TUN I/O ────────────

#[derive(Default)]
struct TunState {
    io: Option<AsyncFd<OwnedFd>>,
    closed: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// Один владелец регистрации и fd; задачи получают только общий handle.
#[derive(Default)]
pub(crate) struct SessionTun {
    state: Mutex<TunState>,
    #[cfg(test)]
    before_release: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl SessionTun {
    pub(crate) fn install(&self, fd: OwnedFd, stop: &AtomicBool) -> std::io::Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed || stop.load(Ordering::SeqCst) {
            return Ok(false);
        }
        if state.io.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "TUN уже установлен",
            ));
        }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN должен быть неблокирующим",
            ));
        }
        // OwnedFd остается внутри регистрации без close/dup2 до ее drop.
        let io = unsafe { AsyncFd::register(fd) }.map_err(std::io::Error::from)?;
        if stop.load(Ordering::SeqCst) {
            return Ok(false);
        }
        state.io = Some(io);
        Ok(true)
    }

    pub(crate) fn close(&self) {
        self.close_inner(None);
    }

    pub(crate) fn request_stop(&self, stop: &AtomicBool) {
        self.close_inner(Some(stop));
    }

    fn close_inner(&self, stop: Option<&AtomicBool>) {
        let (reader, writer) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(stop) = stop {
                stop.store(true, Ordering::SeqCst);
            }
            state.closed = true;
            #[cfg(test)]
            {
                let hook = self.before_release.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            // Другой close не вернется, пока deregister и close не завершены.
            drop(state.io.take());
            (state.reader.take(), state.writer.take())
        };
        for waker in [reader, writer].into_iter().flatten() {
            waker.wake();
        }
    }

    fn poll_io<T>(
        &self,
        cx: &mut Context<'_>,
        read: bool,
        mut operation: impl FnMut(RawFd) -> std::io::Result<T>,
    ) -> Poll<std::io::Result<T>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.io.is_none() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "TUN закрыт",
            )));
        }
        *if read {
            &mut state.reader
        } else {
            &mut state.writer
        } = Some(cx.waker().clone());
        let io = state.io.as_ref().unwrap();
        loop {
            let mut ready = std::task::ready!(if read {
                io.poll_read_ready(cx)
            } else {
                io.poll_write_ready(cx)
            })?;
            match ready.try_io(|io| operation(io.as_raw_fd())) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
}

pub(crate) async fn tun_async_read(tun: &SessionTun, buf: &mut [u8]) -> std::io::Result<usize> {
    std::future::poll_fn(|cx| {
        tun.poll_io(cx, true, |fd| {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        })
    })
    .await
}

pub(crate) async fn tun_async_write(tun: &SessionTun, data: &[u8]) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let n = std::future::poll_fn(|cx| {
            tun.poll_io(cx, false, |fd| {
                let n = unsafe {
                    libc::write(
                        fd,
                        data[written..].as_ptr() as *const libc::c_void,
                        data.len() - written,
                    )
                };

                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                    } else {
                        Err(err)
                    }
                } else {
                    Ok(n as usize)
                }
            })
        })
        .await?;
        match n {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "TUN write returned 0",
                ));
            }
            n => {
                written += n;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    #[test]
    fn connected_udp_supports_both_address_families() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let server = std::net::UdpSocket::bind(bind).unwrap();
            server
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let session = Arc::new(SessionRuntime::new());
            let fd =
                create_udp_socket(server.local_addr().unwrap(), &session, &|_| Ok(())).unwrap();
            let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            socket.send(b"probe").unwrap();
            let mut buffer = [0; 16];
            let (length, peer) = server.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], b"probe");
            assert_eq!(peer.is_ipv6(), server.local_addr().unwrap().is_ipv6());
            let control = session.udp_control_fd.swap(-1, Ordering::SeqCst);
            if control >= 0 {
                unsafe {
                    libc::close(control);
                }
            }
        }
    }
}

#[cfg(test)]
mod fd_lifecycle_tests {
    use super::*;
    use std::future::Future;
    use std::os::unix::net::UnixDatagram;
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    fn isolated(name: &str) -> bool {
        let module = module_path!().split_once("::").unwrap().1;
        let name = format!("{module}::{name}");
        if std::env::var("AIVPN_FD_LIFECYCLE_CHILD").ok().as_deref() == Some(&name) {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--test-threads=1", "--nocapture"])
            .env("AIVPN_FD_LIFECYCLE_CHILD", &name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn closed(fd: RawFd) -> bool {
        (unsafe { libc::fcntl(fd, libc::F_GETFD) }) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    }

    #[test]
    fn actual_fd_is_nonblocking_and_released_without_polling_runtime() {
        if isolated("actual_fd_is_nonblocking_and_released_without_polling_runtime") {
            return;
        }
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let platform_copy = socket.try_clone().unwrap();
        let fd = socket.as_raw_fd();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        let runtime = runtime();
        let _entered = runtime.enter();
        let tun = SessionTun::default();
        assert!(tun.install(socket.into(), &AtomicBool::new(false)).unwrap());
        assert_ne!(
            unsafe { libc::fcntl(platform_copy.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        tun.close();
        assert!(closed(fd));
        assert!(!closed(platform_copy.as_raw_fd()));
    }

    struct WakeProbe {
        tun: std::sync::Weak<SessionTun>,
        wakes: AtomicUsize,
    }

    impl Wake for WakeProbe {
        fn wake(self: Arc<Self>) {
            assert!(
                self.tun.upgrade().unwrap().state.try_lock().is_ok(),
                "Wake вызван под TUN mutex"
            );
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn pending_reader_and_writer_wake_after_close_without_runtime_progress() {
        if isolated("pending_reader_and_writer_wake_after_close_without_runtime_progress") {
            return;
        }
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let platform_copy = socket.try_clone().unwrap();
        let runtime = runtime();
        let _entered = runtime.enter();
        let tun = Arc::new(SessionTun::default());
        assert!(tun.install(socket.into(), &AtomicBool::new(false)).unwrap());
        loop {
            match platform_copy.send(&[0; 1024]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
        let probe = Arc::new(WakeProbe {
            tun: Arc::downgrade(&tun),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(probe.clone());
        let mut cx = Context::from_waker(&waker);
        let mut buffer = [0; 32];
        let mut read = Box::pin(tun_async_read(&tun, &mut buffer));
        let mut write = Box::pin(tun_async_write(&tun, b"blocked"));
        assert!(read.as_mut().poll(&mut cx).is_pending());
        assert!(write.as_mut().poll(&mut cx).is_pending());
        tun.close();
        assert!(probe.wakes.load(Ordering::SeqCst) >= 2);
        assert!(
            matches!(read.as_mut().poll(&mut cx), Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted)
        );
        assert!(
            matches!(write.as_mut().poll(&mut cx), Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted)
        );
    }

    #[test]
    fn stop_during_install_cannot_publish_a_late_descriptor() {
        if isolated("stop_during_install_cannot_publish_a_late_descriptor") {
            return;
        }
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let platform_copy = socket.try_clone().unwrap();
        let fd = socket.as_raw_fd();
        let tun = Arc::new(SessionTun::default());
        let stop = Arc::new(AtomicBool::new(false));
        let locked = tun.state.lock().unwrap();
        let (installing, entered) = std::sync::mpsc::channel();
        let installer_tun = tun.clone();
        let installer_stop = stop.clone();
        let installer = std::thread::spawn(move || {
            let runtime = runtime();
            let _entered = runtime.enter();
            installing.send(()).unwrap();
            installer_tun
                .install(socket.into(), &installer_stop)
                .unwrap()
        });
        entered.recv().unwrap();
        let (stopping, stopped) = std::sync::mpsc::channel();
        let stopper_tun = tun.clone();
        let stopper_stop = stop.clone();
        let stopper = std::thread::spawn(move || {
            stopper_stop.store(true, Ordering::SeqCst);
            stopping.send(()).unwrap();
            stopper_tun.request_stop(&stopper_stop);
        });
        stopped.recv().unwrap();
        drop(locked);
        assert!(!installer.join().unwrap());
        stopper.join().unwrap();
        assert!(tun.state.lock().unwrap().io.is_none());
        assert!(closed(fd));
        assert!(!closed(platform_copy.as_raw_fd()));
    }

    #[cfg(target_os = "linux")]
    fn epoll_watchers(fd: RawFd) -> Vec<std::path::PathBuf> {
        std::fs::read_dir("/proc/self/fdinfo")
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let text = std::fs::read_to_string(&path).ok()?;
                text.lines()
                    .any(|line| {
                        let mut fields = line.split_whitespace();
                        fields.next() == Some("tfd:")
                            && fields.next().and_then(|value| value.parse::<RawFd>().ok())
                                == Some(fd)
                    })
                    .then_some(path)
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn epoll_deregistration_precedes_fd_reuse_and_old_guard_cannot_close_new_session() {
        if isolated("epoll_deregistration_precedes_fd_reuse_and_old_guard_cannot_close_new_session")
        {
            return;
        }
        use super::super::state::{activate_session, stop_active_tunnel, ACTIVE_SESSION};
        for _ in 0..32 {
            let (socket, old_peer) = UnixDatagram::pair().unwrap();
            let platform_copy = socket.try_clone().unwrap();
            let fd = socket.as_raw_fd();
            let runtime = runtime();
            let _entered = runtime.enter();
            let old = Arc::new(SessionRuntime::new());
            let old_guard = activate_session(old.clone()).unwrap();
            assert!(old.tun.install(socket.into(), &old.stop_requested).unwrap());
            assert!(!epoll_watchers(fd).is_empty());
            stop_active_tunnel();
            assert!(
                epoll_watchers(fd).is_empty(),
                "Старая регистрация пережила close при живом platform dup"
            );
            assert!(closed(fd));
            let (replacement, new_peer) = UnixDatagram::pair().unwrap();
            assert_eq!(
                replacement.as_raw_fd(),
                fd,
                "Проверка требует настоящего reuse номера"
            );
            let new = Arc::new(SessionRuntime::new());
            let new_guard = activate_session(new.clone()).unwrap();
            assert!(new
                .tun
                .install(replacement.into(), &new.stop_requested)
                .unwrap());
            drop(old_guard);
            assert!(Arc::ptr_eq(
                ACTIVE_SESSION.lock().unwrap().as_ref().unwrap(),
                &new
            ));
            assert!(!epoll_watchers(fd).is_empty());
            old_peer.send(b"old").unwrap();
            new_peer.send(b"new").unwrap();
            let mut buffer = [0; 8];
            assert_eq!(
                runtime
                    .block_on(tun_async_read(&new.tun, &mut buffer))
                    .unwrap(),
                3
            );
            assert_eq!(&buffer[..3], b"new");
            assert_eq!(
                runtime
                    .block_on(tun_async_read(&old.tun, &mut buffer))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::Interrupted
            );
            assert_eq!(platform_copy.recv(&mut buffer).unwrap(), 3);
            assert_eq!(&buffer[..3], b"old");
            drop(new_guard);
            assert!(closed(fd));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn registration_failure_and_revoked_install_close_owned_descriptors() {
        if isolated("registration_failure_and_revoked_install_close_owned_descriptors") {
            return;
        }
        let runtime = runtime();
        let _entered = runtime.enter();
        let tun = SessionTun::default();
        let nonpollable = std::fs::File::open("/dev/null").unwrap();
        let fd = nonpollable.as_raw_fd();
        assert!(tun
            .install(nonpollable.into(), &AtomicBool::new(false))
            .is_err());
        assert!(closed(fd));
        tun.close();
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let fd = socket.as_raw_fd();
        assert!(!tun.install(socket.into(), &AtomicBool::new(false)).unwrap());
        assert!(closed(fd));
    }

    #[test]
    fn cancelled_owner_closes_tun_while_child_handle_is_still_alive() {
        if isolated("cancelled_owner_closes_tun_while_child_handle_is_still_alive") {
            return;
        }
        use super::super::state::activate_session;
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let platform_copy = socket.try_clone().unwrap();
        let fd = socket.as_raw_fd();
        let runtime = runtime();
        runtime.block_on(async {
            let session = Arc::new(SessionRuntime::new());
            let retained = session.tun.clone();
            let (started, ready) = tokio::sync::oneshot::channel();
            let owner = tokio::spawn(async move {
                let _active = activate_session(session.clone()).unwrap();
                assert!(session
                    .tun
                    .install(socket.into(), &session.stop_requested)
                    .unwrap());
                started.send(()).unwrap();
                std::future::pending::<()>().await;
            });
            ready.await.unwrap();
            let child = tokio::spawn(async move {
                std::future::pending::<()>().await;
                drop(retained);
            });
            owner.abort();
            assert!(owner.await.unwrap_err().is_cancelled());
            assert!(!child.is_finished());
            assert!(closed(fd));
            assert!(!closed(platform_copy.as_raw_fd()));
            child.abort();
            assert!(child.await.unwrap_err().is_cancelled());
        });
    }

    #[test]
    fn owned_registration_transfers_packets_in_both_directions() {
        if isolated("owned_registration_transfers_packets_in_both_directions") {
            return;
        }
        let (socket, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let runtime = runtime();
        runtime.block_on(async {
            let tun = SessionTun::default();
            assert!(tun.install(socket.into(), &AtomicBool::new(false)).unwrap());
            peer.send(b"uplink").unwrap();
            let mut buffer = [0; 16];
            assert_eq!(tun_async_read(&tun, &mut buffer).await.unwrap(), 6);
            assert_eq!(&buffer[..6], b"uplink");
            tun_async_write(&tun, b"downlink").await.unwrap();
            assert_eq!(peer.recv(&mut buffer).unwrap(), 8);
            assert_eq!(&buffer[..8], b"downlink");
            tun.close();
        });
    }

    #[test]
    fn cancelled_reader_and_writer_do_not_delay_owner_close() {
        if isolated("cancelled_reader_and_writer_do_not_delay_owner_close") {
            return;
        }
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let platform_copy = socket.try_clone().unwrap();
        let fd = socket.as_raw_fd();
        let runtime = runtime();
        runtime.block_on(async {
            let tun = Arc::new(SessionTun::default());
            assert!(tun.install(socket.into(), &AtomicBool::new(false)).unwrap());
            while platform_copy.send(&[0; 1024]).is_ok() {}
            let (read_started, read_ready) = tokio::sync::oneshot::channel();
            let (write_started, write_ready) = tokio::sync::oneshot::channel();
            let read_tun = tun.clone();
            let write_tun = tun.clone();
            let reader = tokio::spawn(async move {
                let mut buffer = [0; 32];
                read_started.send(()).unwrap();
                tun_async_read(&read_tun, &mut buffer).await
            });
            let writer = tokio::spawn(async move {
                write_started.send(()).unwrap();
                tun_async_write(&write_tun, b"blocked").await
            });
            read_ready.await.unwrap();
            write_ready.await.unwrap();
            reader.abort();
            writer.abort();
            assert!(reader.await.unwrap_err().is_cancelled());
            assert!(writer.await.unwrap_err().is_cancelled());
            tun.close();
            assert!(closed(fd));
            assert!(!closed(platform_copy.as_raw_fd()));
        });
    }

    #[test]
    fn concurrent_close_cannot_return_before_the_fd_owner_is_dropped() {
        if isolated("concurrent_close_cannot_return_before_the_fd_owner_is_dropped") {
            return;
        }
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let platform_copy = socket.try_clone().unwrap();
        let fd = socket.as_raw_fd();
        let runtime = runtime();
        let _entered = runtime.enter();
        let tun = Arc::new(SessionTun::default());
        assert!(tun.install(socket.into(), &AtomicBool::new(false)).unwrap());
        let observed_closed = Arc::new(AtomicBool::new(false));
        let second_handle = Arc::new(Mutex::new(None));
        let observer = observed_closed.clone();
        let pending = second_handle.clone();
        let weak = Arc::downgrade(&tun);
        *tun.before_release.lock().unwrap() = Some(Box::new(move || {
            let tun = weak.upgrade().unwrap();
            let can_enter = tun.state.try_lock().is_ok();
            let started = Arc::new(std::sync::Barrier::new(2));
            let second_started = started.clone();
            let second = std::thread::spawn(move || {
                second_started.wait();
                tun.close();
                observer.store(closed(fd), Ordering::SeqCst);
            });
            started.wait();
            if can_enter {
                second.join().unwrap();
            } else {
                *pending.lock().unwrap() = Some(second);
            }
        }));
        tun.close();
        if let Some(second) = second_handle.lock().unwrap().take() {
            second.join().unwrap();
        }
        assert!(
            observed_closed.load(Ordering::SeqCst),
            "Второй close вернулся раньше реального закрытия fd"
        );
        assert!(!closed(platform_copy.as_raw_fd()));
    }
}
