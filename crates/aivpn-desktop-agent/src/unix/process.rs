use super::{error, LocalStream, PeerCredentials};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Ссылка ядра на процесс отправителя сохраняется при повторном использовании PID.
pub struct PeerProcess {
    descriptor: OwnedFd,
    credentials: PeerCredentials,
}

impl fmt::Debug for PeerProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerProcess")
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl AsFd for PeerProcess {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl PeerProcess {
    pub fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    /// Проверяет состояние без ожидания события завершения.
    pub fn is_alive(&self) -> io::Result<bool> {
        let mut watch = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut watch, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if watch.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(error(
                io::ErrorKind::BrokenPipe,
                "Недоступна ссылка на процесс отправителя",
            ));
        }
        if result == 0 {
            return Ok(true);
        }
        if watch.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            return Ok(false);
        }
        Err(error(
            io::ErrorKind::BrokenPipe,
            "Неизвестное состояние процесса отправителя",
        ))
    }

    /// Повторная остановка уже завершенного процесса безопасна.
    pub fn terminate(&self) -> io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.descriptor.as_raw_fd(),
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let failure = io::Error::last_os_error();
        if failure.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(failure)
    }
}

impl LocalStream {
    pub fn peer_process(&self) -> io::Result<PeerProcess> {
        self.check_open()?;
        let credentials = self.peer_credentials()?;
        let descriptor = socket_pidfd(self.stream.as_raw_fd())?;
        Ok(PeerProcess {
            descriptor,
            credentials,
        })
    }
}

fn socket_pidfd(socket: libc::c_int) -> io::Result<OwnedFd> {
    let mut descriptor = -1;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut descriptor as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result < 0 {
        let failure = io::Error::last_os_error();
        if failure.raw_os_error() == Some(libc::ENOPROTOOPT) {
            return Err(error(
                io::ErrorKind::Unsupported,
                "Ядро не поддерживает SO_PEERPIDFD",
            ));
        }
        return Err(failure);
    }
    if descriptor < 0 {
        return Err(error(
            io::ErrorKind::PermissionDenied,
            "Некорректная ссылка на процесс отправителя",
        ));
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    validate_pidfd(descriptor, length)
}

fn validate_pidfd(descriptor: OwnedFd, length: libc::socklen_t) -> io::Result<OwnedFd> {
    if length as usize != std::mem::size_of::<libc::c_int>() {
        return Err(error(
            io::ErrorKind::PermissionDenied,
            "Неверный размер ссылки на процесс отправителя",
        ));
    }
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC == 0 {
        return Err(error(
            io::ErrorKind::PermissionDenied,
            "Ссылка на процесс не закрывается при exec",
        ));
    }
    Ok(descriptor)
}
