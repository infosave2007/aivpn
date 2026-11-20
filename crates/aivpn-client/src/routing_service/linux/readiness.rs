//! Готовность отправляет основной процесс после установки захвата и открытия состояния.
use std::{
    ffi::OsStr,
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::{ffi::OsStrExt, net::SocketAddr, net::UnixDatagram},
    },
    time::Duration,
};

pub(super) fn notify(target: Option<&OsStr>) -> io::Result<()> {
    let Some(target) = target else {
        return Ok(());
    };
    let bytes = target.as_bytes();
    let address = match bytes.first() {
        Some(b'/') => SocketAddr::from_pathname(target)?,
        Some(b'@') if bytes.len() > 1 => SocketAddr::from_abstract_name(&bytes[1..])?,
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    let message = b"READY=1";
    if socket.send_to_addr(message, &address)? != message.len() {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("aivpn-readiness-{}-{stamp}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn receive(socket: UnixDatagram) {
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0; 32];
        let count = socket.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..count], b"READY=1");
    }

    #[test]
    fn filesystem_socket_receives_the_ready_datagram() {
        let directory = Directory::new();
        let path = directory.0.join("notify.sock");
        let socket = UnixDatagram::bind(&path).unwrap();
        notify(Some(path.as_os_str())).unwrap();
        receive(socket);
    }

    #[test]
    fn abstract_socket_receives_the_ready_datagram() {
        let name = format!("aivpn-ready-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let socket = UnixDatagram::bind_addr(&address).unwrap();
        notify(Some(OsStr::new(&format!("@{name}")))).unwrap();
        receive(socket);
    }

    #[test]
    fn invalid_or_unavailable_target_does_not_report_success() {
        for target in ["", "@", "relative/notify.sock"] {
            assert_eq!(
                notify(Some(OsStr::new(target))).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let directory = Directory::new();
        assert!(notify(Some(directory.0.join("missing.sock").as_os_str())).is_err());
        notify(None).unwrap();
    }
}
