use crate::{MAX_FRAME_BYTES, MAX_FRAME_DESCRIPTORS};
use std::fmt;
use std::io;
use std::net::Shutdown;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

mod process;
pub use process::PeerProcess;

mod control_client;
pub mod rpc;
pub mod service;
pub use control_client::{call_root_control, connect_root_control};

const MARKER: u8 = 0xa1;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Frame {
    pub payload: Vec<u8>,
    pub descriptors: Vec<OwnedFd>,
}

impl fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("payload_len", &self.payload.len())
            .field("descriptor_count", &self.descriptors.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: NonZeroU32,
}

/// Один владелец читает и пишет кадры. После ошибки частичный поток закрывается.
pub struct LocalStream {
    stream: UnixStream,
    poisoned: bool,
    frame_timeout: Duration,
}

impl LocalStream {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            poisoned: false,
            frame_timeout: FRAME_TIMEOUT,
        }
    }

    pub fn limit_frame_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() || timeout > FRAME_TIMEOUT {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "Некорректный предел ожидания кадра",
            ));
        }
        self.frame_timeout = timeout;
        Ok(())
    }

    /// UID и PID получены от ядра, а не из тела запроса.
    pub fn peer_credentials(&self) -> io::Result<PeerCredentials> {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                self.stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of::<libc::ucred>() {
            return Err(error(
                io::ErrorKind::PermissionDenied,
                "Не удалось проверить владельца локального соединения",
            ));
        }
        Ok(PeerCredentials {
            uid: credentials.uid,
            gid: credentials.gid,
            pid: u32::try_from(credentials.pid)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or_else(|| {
                    error(
                        io::ErrorKind::PermissionDenied,
                        "Недоступен PID отправителя",
                    )
                })?,
        })
    }

    pub fn send(&mut self, payload: &[u8], descriptors: &[BorrowedFd<'_>]) -> io::Result<()> {
        self.check_open()?;
        if payload.is_empty()
            || payload.len() > MAX_FRAME_BYTES
            || descriptors.len() > MAX_FRAME_DESCRIPTORS
        {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "Превышен размер локального кадра или число дескрипторов",
            ));
        }
        let result = self.send_frame(payload, descriptors);
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Пустой канал может ждать отдельно; после первого байта действует общий срок на весь кадр.
    pub fn receive(&mut self, idle_timeout: Option<Duration>) -> io::Result<Frame> {
        self.check_open()?;
        let result = self.receive_frame(idle_timeout);
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn check_open(&self) -> io::Result<()> {
        if self.poisoned {
            Err(error(
                io::ErrorKind::NotConnected,
                "Локальный канал закрыт после ошибки",
            ))
        } else {
            Ok(())
        }
    }

    fn poison(&mut self) {
        self.poisoned = true;
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn send_frame(&self, payload: &[u8], descriptors: &[BorrowedFd<'_>]) -> io::Result<()> {
        let deadline = deadline(self.frame_timeout)?;
        send_marker(&self.stream, descriptors, deadline)?;
        let length = (payload.len() as u32).to_be_bytes();
        let header = [
            descriptors.len() as u8,
            length[0],
            length[1],
            length[2],
            length[3],
        ];
        self.write_all(&header, deadline)?;
        self.write_all(payload, deadline)
    }

    fn write_all(&self, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
        while !bytes.is_empty() {
            self.stream.set_write_timeout(Some(remaining(deadline)?))?;
            let count = unsafe {
                libc::send(
                    self.stream.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if count < 0 {
                let failure = io::Error::last_os_error();
                if failure.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(failure);
            }
            if count == 0 {
                return Err(error(
                    io::ErrorKind::WriteZero,
                    "Локальный канал перестал принимать кадр",
                ));
            }
            bytes = &bytes[count as usize..];
        }
        remaining(deadline).map(|_| ())
    }

    fn receive_frame(&self, idle_timeout: Option<Duration>) -> io::Result<Frame> {
        let (marker, descriptors) = self.receive_start(idle_timeout)?;
        if marker != MARKER {
            return Err(error(
                io::ErrorKind::InvalidData,
                "Неизвестный формат локального кадра",
            ));
        }
        let deadline = deadline(self.frame_timeout)?;
        let mut header = [0; 5];
        self.read_exact(&mut header, deadline)?;
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if header[0] as usize != descriptors.len() || length == 0 || length > MAX_FRAME_BYTES {
            return Err(error(
                io::ErrorKind::InvalidData,
                "Некорректный размер локального кадра",
            ));
        }
        let mut payload = vec![0; length];
        self.read_exact(&mut payload, deadline)?;
        Ok(Frame {
            payload,
            descriptors,
        })
    }

    fn receive_start(&self, idle_timeout: Option<Duration>) -> io::Result<(u8, Vec<OwnedFd>)> {
        let idle_deadline = idle_timeout.map(deadline).transpose()?;
        loop {
            self.stream
                .set_read_timeout(idle_deadline.map(remaining).transpose()?)?;
            let mut marker = [0];
            match receive_chunk(&self.stream, &mut marker) {
                Ok((0, _)) => {
                    return Err(error(
                        io::ErrorKind::UnexpectedEof,
                        "Локальный канал закрыт",
                    ))
                }
                Ok((_, descriptors)) => return Ok((marker[0], descriptors)),
                Err(failure) if failure.kind() == io::ErrorKind::Interrupted => continue,
                Err(failure) => return Err(failure),
            }
        }
    }

    fn read_exact(&self, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
        while !bytes.is_empty() {
            self.stream.set_read_timeout(Some(remaining(deadline)?))?;
            let (count, descriptors) = match receive_chunk(&self.stream, bytes) {
                Err(failure) if failure.kind() == io::ErrorKind::Interrupted => continue,
                other => other?,
            };
            if !descriptors.is_empty() {
                return Err(error(
                    io::ErrorKind::InvalidData,
                    "Дескриптор передан вне начала кадра",
                ));
            }
            if count == 0 {
                return Err(error(
                    io::ErrorKind::UnexpectedEof,
                    "Локальный кадр не завершен",
                ));
            }
            bytes = &mut bytes[count..];
        }
        remaining(deadline).map(|_| ())
    }
}

fn deadline(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| error(io::ErrorKind::InvalidInput, "Некорректный срок ожидания"))
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| {
            error(
                io::ErrorKind::TimedOut,
                "Истек срок передачи локального кадра",
            )
        })
}
fn error(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

fn send_marker(
    stream: &UnixStream,
    descriptors: &[BorrowedFd<'_>],
    deadline: Instant,
) -> io::Result<()> {
    let marker = [MARKER];
    let mut vector = libc::iovec {
        iov_base: marker.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe {
            libc::CMSG_SPACE((descriptors.len() * std::mem::size_of::<libc::c_int>()) as u32)
        } as usize;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN((descriptors.len() * std::mem::size_of::<libc::c_int>()) as u32)
                    as usize;
            let target = libc::CMSG_DATA(header).cast::<libc::c_int>();
            for (index, descriptor) in descriptors.iter().enumerate() {
                target.add(index).write_unaligned(descriptor.as_raw_fd());
            }
        }
    }
    loop {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let result = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if result == 1 {
            return Ok(());
        }
        if result == 0 {
            return Err(error(
                io::ErrorKind::WriteZero,
                "Не удалось передать начало кадра",
            ));
        }
        let failure = io::Error::last_os_error();
        if failure.kind() != io::ErrorKind::Interrupted {
            return Err(failure);
        }
    }
}

fn receive_chunk(stream: &UnixStream, bytes: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let count = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    // recvmsg заполнил заголовки ядра, а выровненный буфер control еще жив.
    let descriptors = unsafe { take_descriptors(&message) }?;
    if count as usize > bytes.len() {
        return Err(error(io::ErrorKind::InvalidData, "Локальный кадр усечен"));
    }
    Ok((count as usize, descriptors))
}

// Вызывается только для msghdr, только что заполненного recvmsg с живым control.
unsafe fn take_descriptors(message: &libc::msghdr) -> io::Result<Vec<OwnedFd>> {
    let mut descriptors = Vec::new();
    let mut invalid = message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        if unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS
        } {
            unsafe { take_rights(header, &mut descriptors) };
        } else {
            invalid = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    if invalid || descriptors.len() > MAX_FRAME_DESCRIPTORS {
        return Err(error(
            io::ErrorKind::InvalidData,
            "Некорректный блок дескрипторов",
        ));
    }
    Ok(descriptors)
}

unsafe fn take_rights(header: *mut libc::cmsghdr, descriptors: &mut Vec<OwnedFd>) {
    // Формат и номера SCM_RIGHTS проверены ядром; здесь не разбираются байты пользовательского JSON.
    let size = unsafe { (*header).cmsg_len - libc::CMSG_LEN(0) as usize };
    let source = unsafe { libc::CMSG_DATA(header).cast::<libc::c_int>() };
    for index in 0..size / std::mem::size_of::<libc::c_int>() {
        let descriptor = unsafe { source.add(index).read_unaligned() };
        descriptors.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
    }
}
