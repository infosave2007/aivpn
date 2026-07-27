//! Shared low-level I/O for the mobile tunnels: UDP socket factory (with a
//! platform `protect` hook for Android's `VpnService.protect`), the stop
//! signal (eventfd on linux/android, pipe elsewhere) and async TUN I/O.
//! Hoisted verbatim from `android_tunnel.rs`; the pipe-based
//! `create_stop_signal` fallback is iOS's version (it has the race-arm
//! re-check the Android pipe fallback lacked).

use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::unix::AsyncFd;

use crate::error::{Error, Result};

use super::state::{SessionRuntime, LAST_LOCAL_PORT};

// ──────────── Protected UDP socket creation ────────────

pub fn create_udp_socket(
    dest: SocketAddr,
    session: &Arc<SessionRuntime>,
    protect: &(dyn Fn(RawFd) -> Result<()> + Sync),
) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Exempt this socket from the VPN (Android: VpnService.protect(int) via
    // the JNI closure passed by the platform adapter; iOS: no-op — the
    // NEPacketTunnelProvider process is automatically outside the VPN).
    if let Err(e) = protect(fd) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    // Increase OS socket buffers to reduce drops/backpressure on high-throughput links.
    // Ignore errors: kernels may cap/override values.
    let sock_buf: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sock_buf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sock_buf) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &sock_buf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sock_buf) as libc::socklen_t,
        );
    }

    // Try to reuse the same local port as the previous session.  When a
    // port-preserving CGNAT (MTS, Beeline, etc.) is in use, the carrier's
    // inbound routing table still maps the old external port back to this
    // phone.  Binding to the same internal port means no CGNAT update is
    // needed and downlink arrives immediately without a stale-mapping delay.
    // Falls back to OS-assigned ephemeral port if the saved port is
    // unavailable (first connect, or port taken by another socket).
    let port_hint = LAST_LOCAL_PORT.load(Ordering::Relaxed);
    unsafe {
        let mut any: libc::sockaddr_in = std::mem::zeroed();
        any.sin_family = libc::AF_INET as libc::sa_family_t;
        if port_hint != 0 {
            any.sin_port = port_hint.to_be();
            if libc::bind(
                fd,
                &any as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) < 0
            {
                // Port unavailable — fall back to OS-assigned ephemeral.
                any.sin_port = 0;
                let _ = libc::bind(
                    fd,
                    &any as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
            }
        } else {
            let _ = libc::bind(
                fd,
                &any as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
        }
    }

    // Connect to server (sets default destination for send/recv, non-blocking for UDP).
    let SocketAddr::V4(v4) = dest else {
        unsafe { libc::close(fd) };
        return Err(Error::Session(
            "Only IPv4 server addresses are supported".into(),
        ));
    };
    let sa = to_sockaddr_in(&v4);
    let rc = unsafe {
        libc::connect(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Persist the local port for the next reconnect attempt.
    unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockname(
            fd,
            &mut sa as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut len,
        ) == 0
        {
            LAST_LOCAL_PORT.store(u16::from_be(sa.sin_port), Ordering::Relaxed);
        }
    }

    let control_fd = unsafe { libc::dup(fd) };
    if control_fd < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    session.udp_control_fd.store(control_fd, Ordering::SeqCst);

    Ok(fd)
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
    Ok(AsyncFd::new(owned_stop_fd)?)
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
    Ok(AsyncFd::new(unsafe { OwnedFd::from_raw_fd(read_fd) })?)
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

pub fn to_sockaddr_in(addr: &SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

// ──────────── Async TUN I/O ────────────

pub async fn tun_async_read(tun: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = tun.readable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

pub async fn tun_async_write(tun: &AsyncFd<OwnedFd>, data: &[u8]) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let mut guard = tun.writable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::write(
                    inner.as_raw_fd(),
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
        }) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "TUN write returned 0",
                ));
            }
            Ok(Ok(n)) => {
                written += n;
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_would_block) => continue,
        }
    }
    Ok(())
}
