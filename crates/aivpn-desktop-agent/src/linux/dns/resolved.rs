//! Проверяет процесс системного DNS и временно удерживает его точные слушающие сокеты.
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
use zbus::blocking::{Connection, Proxy};

const SERVICE: &str = "org.freedesktop.resolve1";
const MAX_FDS: usize = 4096;

#[derive(Clone, Copy)]
pub(super) enum StubService {
    Resolved,
    NetworkManagerDnsmasq,
    Networkd,
}
impl StubService {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Resolved => SERVICE,
            Self::NetworkManagerDnsmasq => "org.freedesktop.NetworkManager.dnsmasq",
            Self::Networkd => "org.freedesktop.network1",
        }
    }
    fn images(self) -> &'static [&'static str] {
        match self {
            Self::Resolved => &["/usr/lib/systemd/systemd-resolved"],
            Self::NetworkManagerDnsmasq => &["/usr/sbin/dnsmasq", "/usr/bin/dnsmasq"],
            Self::Networkd => &["/usr/lib/systemd/systemd-networkd"],
        }
    }
    fn accepts(self, address: [u8; 4]) -> bool {
        match self {
            Self::Resolved => matches!(address, [127, 0, 0, 53] | [127, 0, 0, 54]),
            Self::NetworkManagerDnsmasq => address == [127, 0, 0, 1],
            Self::Networkd => false,
        }
    }
}

pub(crate) struct StubSocket {
    socket: OwnedFd,
    uid: u32,
}
impl StubSocket {
    pub(crate) fn socket(&self) -> &OwnedFd {
        &self.socket
    }
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
}

pub(super) fn capture(bus: &Connection) -> io::Result<Vec<StubSocket>> {
    capture_service(bus, StubService::Resolved)
}

/// Перечитывает собственный DNS drop-in у проверенного процесса, без гонки повторного PID.
pub(super) fn reload_configuration(bus: &Connection) -> io::Result<()> {
    let (pidfd, _) = service_process(bus, StubService::Resolved)?;
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGHUP,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn networkd_running(bus: &Connection) -> io::Result<bool> {
    let dbus = Proxy::new(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(super::nm::bus_error)?;
    let present: bool = dbus
        .call("NameHasOwner", &(StubService::Networkd.name(),))
        .map_err(super::nm::bus_error)?;
    if present {
        service_process(bus, StubService::Networkd)?;
    }
    Ok(present)
}

pub(super) fn require_configuration_reload(bus: &Connection) -> io::Result<()> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let (pidfd, _) = service_process(bus, StubService::Resolved)?;
    let mut child = Command::new("/usr/lib/systemd/systemd-resolved")
        .arg("--version")
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::ErrorKind::TimedOut.into());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    };
    let mut output = String::new();
    child
        .stdout
        .take()
        .ok_or(io::ErrorKind::BrokenPipe)?
        .take(4097)
        .read_to_string(&mut output)?;
    let major = output
        .split_whitespace()
        .nth(1)
        .and_then(|version| version.split(['.', '-']).next())
        .and_then(|version| version.parse::<u32>().ok());
    if !status.success() || output.len() > 4096 || major.is_none_or(|major| major < 256) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Для безопасного перечитывания DNS-конфигурации нужен resolved 256 или новее",
        ));
    }
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
        return Err(io::ErrorKind::ConnectionAborted.into());
    }
    Ok(())
}

pub(super) fn resolved_owner(bus: &Connection) -> io::Result<String> {
    service_process(bus, StubService::Resolved).map(|(_, owner)| owner)
}

fn service_process(bus: &Connection, service: StubService) -> io::Result<(OwnedFd, String)> {
    let dbus = Proxy::new(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(super::nm::bus_error)?;
    let owner: String = dbus
        .call("GetNameOwner", &(service.name(),))
        .map_err(super::nm::bus_error)?;
    let pid: u32 = dbus
        .call("GetConnectionUnixProcessID", &(owner.as_str(),))
        .map_err(super::nm::bus_error)?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    verify_process(pid, &pidfd, service)?;
    let current: String = dbus
        .call("GetNameOwner", &(service.name(),))
        .map_err(super::nm::bus_error)?;
    if current != owner {
        return Err(io::ErrorKind::ConnectionAborted.into());
    }
    Ok((pidfd, owner))
}

pub(super) fn capture_service(
    bus: &Connection,
    service: StubService,
) -> io::Result<Vec<StubSocket>> {
    let dbus = Proxy::new(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(super::nm::bus_error)?;
    let owner: String = dbus
        .call("GetNameOwner", &(service.name(),))
        .map_err(super::nm::bus_error)?;
    let pid: u32 = dbus
        .call("GetConnectionUnixProcessID", &(owner.as_str(),))
        .map_err(super::nm::bus_error)?;
    let uid: u32 = dbus
        .call("GetConnectionUnixUser", &(owner.as_str(),))
        .map_err(super::nm::bus_error)?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    verify_process(pid, &pidfd, service)?;
    let descriptors = fs::read_dir(format!("/proc/{pid}/fd"))?
        .take(MAX_FDS + 1)
        .collect::<io::Result<Vec<_>>>()?;
    if descriptors.len() > MAX_FDS {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    let mut sockets = Vec::new();
    for descriptor in descriptors {
        let target = match fs::read_link(descriptor.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !target
            .as_os_str()
            .as_encoded_bytes()
            .starts_with(b"socket:[")
        {
            continue;
        }
        let fd: i32 = descriptor
            .file_name()
            .to_str()
            .ok_or(io::ErrorKind::InvalidData)?
            .parse()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
        if raw < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        if !is_stub(&socket, service)? {
            continue;
        }
        sockets.push(StubSocket { socket, uid });
        if sockets.len() > 4 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    verify_process(pid, &pidfd, service)?;
    let current: String = dbus
        .call("GetNameOwner", &(service.name(),))
        .map_err(super::nm::bus_error)?;
    if current != owner || sockets.is_empty() {
        return Err(io::ErrorKind::ConnectionAborted.into());
    }
    Ok(sockets)
}

fn verify_process(pid: u32, pidfd: &OwnedFd, service: StubService) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
        return Err(io::ErrorKind::NotConnected.into());
    }
    for (ours, remote) in [
        ("/", format!("/proc/{pid}/root")),
        ("/proc/thread-self/ns/net", format!("/proc/{pid}/ns/net")),
    ] {
        let a = fs::metadata(ours)?;
        let b = fs::metadata(remote)?;
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let running = File::open(format!("/proc/{pid}/exe"))?;
    let b = running.metadata()?;
    for image in service.images() {
        let path = match Path::new(image).canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if trusted_image_matches(&path, &b)? {
            return Ok(());
        }
    }
    Err(io::ErrorKind::PermissionDenied.into())
}

fn trusted_image_matches(path: &Path, running: &fs::Metadata) -> io::Result<bool> {
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let expected = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let a = expected.metadata()?;
    if !a.is_file() || a.mode() & 0o111 == 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok((a.dev(), a.ino(), a.ctime(), a.ctime_nsec())
        == (
            running.dev(),
            running.ino(),
            running.ctime(),
            running.ctime_nsec(),
        ))
}

fn is_stub(socket: &OwnedFd, service: StubService) -> io::Result<bool> {
    use crate::linux::transport::property;
    let domain = property::<i32>(socket, libc::SO_DOMAIN)?;
    if domain != libc::AF_INET
        && !(domain == libc::AF_INET6 && matches!(service, StubService::NetworkManagerDnsmasq))
    {
        return Ok(false);
    }
    match property::<i32>(socket, libc::SO_TYPE)? {
        libc::SOCK_STREAM if property::<i32>(socket, libc::SO_ACCEPTCONN)? == 1 => {}
        libc::SOCK_DGRAM => {
            let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
            if unsafe {
                libc::getpeername(
                    socket.as_raw_fd(),
                    (&mut peer as *mut libc::sockaddr_storage).cast(),
                    &mut length,
                )
            } == 0
            {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOTCONN) {
                return Err(error);
            }
        }
        _ => return Ok(false),
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if domain == libc::AF_INET && length as usize == std::mem::size_of::<libc::sockaddr_in>() {
        let address = unsafe {
            (&address as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_in>()
                .read()
        };
        Ok(u16::from_be(address.sin_port) == 53
            && service.accepts(address.sin_addr.s_addr.to_ne_bytes()))
    } else if domain == libc::AF_INET6
        && length as usize == std::mem::size_of::<libc::sockaddr_in6>()
    {
        let address = unsafe {
            (&address as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_in6>()
                .read()
        };
        Ok(u16::from_be(address.sin6_port) == 53
            && address.sin6_scope_id == 0
            && std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).is_loopback())
    } else {
        Ok(false)
    }
}
