use super::{rpc::invalid_message, Frame, LocalStream};
use crate::protocol::{Request, Response};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Переполненная очередь службы возвращает WouldBlock, не задерживая интерфейс.
pub fn connect_root_control(path: &Path, request: &Request) -> io::Result<Response> {
    require_initial_namespace()?;
    call_root_control(connect_socket(path)?, request)
}

fn socket_address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !path.is_absolute() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Некорректный путь управляющего сокета",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    Ok((address, length as libc::socklen_t))
}

fn connect_socket(path: &Path) -> io::Result<UnixStream> {
    let (address, length) = socket_address(path)?;
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    // Адрес проверен; его буфер и дескриптор живы до завершения connect.
    if unsafe {
        libc::connect(
            descriptor.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let stream = UnixStream::from(descriptor);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// Один запрос к root-службе. Соединение закрывается после ответа или ошибки.
pub fn call_root_control(stream: UnixStream, request: &Request) -> io::Result<Response> {
    require_initial_namespace()?;
    let mut stream = LocalStream::new(stream);
    if stream.peer_credentials()?.uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Управляющее соединение не принадлежит root-службе",
        ));
    }
    let payload = request.to_json().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Некорректный управляющий запрос",
        )
    })?;
    stream.send(&payload, &[])?;
    check_response(stream.receive(Some(request.response_timeout()))?, request)
}

fn require_initial_namespace() -> io::Result<()> {
    // В дочернем user namespace UID 0 может принадлежать обычному пользователю.
    let mapping = std::fs::File::open("/proc/thread-self/uid_map")?;
    check_mapping(mapping)
}

fn check_mapping(mapping: impl Read) -> io::Result<()> {
    let mut bytes = Vec::new();
    mapping.take(129).read_to_end(&mut bytes)?;
    if bytes.len() > 128 || !initial_mapping(&bytes) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Управляющий клиент требует исходное пространство UID",
        ));
    }
    Ok(())
}

fn initial_mapping(bytes: &[u8]) -> bool {
    bytes
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .eq([b"0".as_slice(), b"0", b"4294967295"])
}

fn check_response(frame: Frame, request: &Request) -> io::Result<Response> {
    if !frame.descriptors.is_empty() {
        return Err(invalid_message());
    }
    let response = Response::from_json(&frame.payload).map_err(|_| invalid_message())?;
    if response.id() != request.id() {
        return Err(invalid_message());
    }
    Ok(response)
}

#[cfg(test)]
#[path = "../../tests/support/control_client_unit.rs"]
mod tests;
