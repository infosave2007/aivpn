use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

mod filter;

/// Доверенный код вызывает это до чтения профиля и пакетов, после снятия UID и capabilities.
/// Единственный внешний Unix-канал остается соединенным с root-службой. Ограничения необратимы.
pub fn restrict_packet_worker(control: BorrowedFd<'_>) -> io::Result<()> {
    initialize_packet_worker(control, || Ok(()))
}

/// Доверенная инициализация runtime завершается до seccomp и до чтения профиля.
/// Новые внутренние stream-пары не имеют имени и принадлежат этому же процессу.
pub fn initialize_packet_worker<T>(
    control: BorrowedFd<'_>,
    initialize: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    require_unprivileged_identity()?;
    require_root_control(control)?;
    set_process_flag(libc::PR_SET_DUMPABLE, 0)?;
    set_process_flag(libc::PR_SET_NO_NEW_PRIVS, 1)?;
    require_safe_descriptors(control.as_raw_fd(), false)?;
    let runtime = initialize()?;
    require_safe_descriptors(control.as_raw_fd(), true)?;
    filter::install()?;
    Ok(runtime)
}

fn require_unprivileged_identity() -> io::Result<()> {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } < 0 {
        return Err(io::Error::last_os_error());
    }
    require_uniform_identity(real, effective, saved)?;
    if unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) } < 0 {
        return Err(io::Error::last_os_error());
    }
    require_uniform_identity(real, effective, saved)?;
    match unsafe { libc::getgroups(0, std::ptr::null_mut()) } {
        0 => require_no_capabilities(),
        -1 => Err(io::Error::last_os_error()),
        _ => Err(denied("У работника остались дополнительные группы")),
    }
}

fn require_uniform_identity(real: u32, effective: u32, saved: u32) -> io::Result<()> {
    if real == 0 || real != effective || real != saved {
        return Err(denied("Учетная запись работника не снята полностью"));
    }
    Ok(())
}

fn require_no_capabilities() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [[0u32; 3]; 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if data.iter().flatten().any(|bits| *bits != 0) {
        return Err(denied("У работника остались capabilities"));
    }
    Ok(())
}

fn require_root_control(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    if socket_property(descriptor.as_raw_fd(), libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_property(descriptor.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
    {
        return Err(denied("Неверный канал управления работником"));
    }
    let stream = UnixStream::from(descriptor.try_clone_to_owned()?);
    let credentials = crate::unix::LocalStream::new(stream).peer_credentials()?;
    if credentials.uid != 0 {
        return Err(denied("Канал управления не принадлежит root-службе"));
    }
    Ok(())
}

/// Дополнительный канал должен принадлежать той же службе, что и начальный control.
pub fn administration_stream(
    descriptor: OwnedFd,
    service_pid: std::num::NonZeroU32,
) -> io::Result<UnixStream> {
    require_root_control(descriptor.as_fd())?;
    let stream = UnixStream::from(descriptor);
    let credentials = crate::unix::LocalStream::new(stream.try_clone()?).peer_credentials()?;
    if credentials.pid != service_pid {
        return Err(denied("Канал управления принадлежит другой службе"));
    }
    // std включает O_NONBLOCK через ioctl, который запрещен фильтром работника.
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(stream)
}

fn set_process_flag(option: libc::c_int, value: libc::c_ulong) -> io::Result<()> {
    if unsafe { libc::prctl(option, value, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn require_safe_descriptors(control: RawFd, runtime_initialized: bool) -> io::Result<()> {
    for entry in fs::read_dir("/proc/thread-self/fd")? {
        let descriptor = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
            .ok_or_else(|| denied("Не удалось проверить дескриптор работника"))?;
        if descriptor != control {
            if runtime_initialized && socket_domain(descriptor)? == Some(libc::AF_UNIX) {
                require_private_wakeup(descriptor)?;
            } else {
                require_safe_descriptor(descriptor)?;
            }
        }
    }
    Ok(())
}

fn require_private_wakeup(descriptor: RawFd) -> io::Result<()> {
    if socket_property(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM {
        return Err(denied("Недопустимый внутренний сокет runtime"));
    }
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&peer)
        || peer.pid != unsafe { libc::getpid() }
        || peer.uid != unsafe { libc::geteuid() }
        || peer.gid != unsafe { libc::getegid() }
    {
        return Err(denied("Внутренний сокет runtime связан с другим процессом"));
    }
    for remote in [false, true] {
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        let pointer = (&mut address as *mut libc::sockaddr_un).cast();
        let status = unsafe {
            if remote {
                libc::getpeername(descriptor, pointer, &mut length)
            } else {
                libc::getsockname(descriptor, pointer, &mut length)
            }
        };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        if address.sun_family as libc::c_int != libc::AF_UNIX
            || length as usize != std::mem::offset_of!(libc::sockaddr_un, sun_path)
        {
            return Err(denied("Внутренний сокет runtime имеет внешний адрес"));
        }
    }
    Ok(())
}

fn require_safe_descriptor(descriptor: RawFd) -> io::Result<()> {
    match socket_domain(descriptor)? {
        None => Ok(()),
        Some(libc::AF_INET | libc::AF_INET6) => require_ip_socket(descriptor),
        _ => Err(denied("У работника остался посторонний сетевой дескриптор")),
    }
}

fn socket_domain(descriptor: RawFd) -> io::Result<Option<libc::c_int>> {
    match socket_property(descriptor, libc::SO_DOMAIN) {
        Ok(domain) => Ok(Some(domain)),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTSOCK | libc::EBADF)) => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn require_ip_socket(descriptor: RawFd) -> io::Result<()> {
    match socket_property(descriptor, libc::SO_TYPE)? {
        libc::SOCK_STREAM | libc::SOCK_DGRAM => Ok(()),
        _ => Err(denied(
            "У работника остался необработанный сетевой дескриптор",
        )),
    }
}

fn socket_property(descriptor: RawFd, property: libc::c_int) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            property,
            (&mut value as *mut libc::c_int).cast(),
            &mut size,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of_val(&value) {
        return Err(denied("Неверный размер свойства сетевого дескриптора"));
    }
    Ok(value)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn anonymous_runtime_wakeup_does_not_authorize_inherited_or_named_unix_sockets() {
        let (first, _second) = UnixStream::pair().unwrap();
        assert!(require_private_wakeup(first.as_raw_fd()).is_ok());
        assert!(require_safe_descriptor(first.as_raw_fd()).is_err());
        let listener = std::os::unix::net::UnixListener::bind("").unwrap();
        assert!(require_private_wakeup(listener.as_raw_fd()).is_err());
        let client = UnixStream::connect_addr(&listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(require_private_wakeup(client.as_raw_fd()).is_err());
        assert!(require_private_wakeup(server.as_raw_fd()).is_err());
    }
    #[test]
    fn identity_must_be_nonroot_and_fully_dropped() {
        assert!(require_uniform_identity(1000, 1000, 1000).is_ok());
        for ids in [
            (0, 0, 0),
            (1000, 0, 1000),
            (1000, 1000, 0),
            (1000, 1001, 1000),
            (1000, 1000, 1001),
        ] {
            assert!(require_uniform_identity(ids.0, ids.1, ids.2).is_err());
        }
    }
    #[test]
    fn an_unprivileged_peer_cannot_authorize_a_worker() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (first, _) = UnixStream::pair().unwrap();
        assert_eq!(
            require_root_control(first.as_fd()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn only_ip_sockets_and_nonsocket_descriptors_can_be_inherited() {
        let file = fs::File::open("/dev/null").unwrap();
        assert!(require_safe_descriptor(file.as_raw_fd()).is_ok());
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(require_safe_descriptor(udp.as_raw_fd()).is_ok());
        let (first, second) = UnixStream::pair().unwrap();
        assert!(require_safe_descriptor(first.as_raw_fd()).is_err());
        assert!(require_safe_descriptor(second.as_raw_fd()).is_err());
        assert!(require_safe_descriptor(-1).is_ok());
    }
}
