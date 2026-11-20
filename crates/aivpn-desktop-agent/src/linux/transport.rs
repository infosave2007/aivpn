use super::InterfaceIdentity;
use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
};

/// Возникает только из FD собственного приватного канала после проверки Child.
pub(crate) struct ValidatedTransport {
    pub(super) fd: OwnedFd,
    pub(super) cookie: u64,
    pub(super) netns: u64,
    pub(super) device: u64,
    pub(super) peer: SocketAddr,
    pub(super) pid: u32,
}
pub(super) enum TransportInspection {
    Ready(ValidatedTransport),
    RouteUnavailable(io::Error),
}

impl ValidatedTransport {
    pub(crate) fn cookie(&self) -> u64 {
        self.cookie
    }
    pub(crate) fn verify_lifetime(&self) -> io::Result<()> {
        if property::<u64>(&self.fd, libc::SO_COOKIE)? != self.cookie
            || property::<u64>(&self.fd, libc::SO_NETNS_COOKIE)? != self.netns
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn inspect(
        fd: OwnedFd,
        peer: SocketAddr,
        pid: u32,
        interface: InterfaceIdentity,
    ) -> io::Result<TransportInspection> {
        let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&local) as u32;
        if unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                (&mut local as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(invalid());
        }
        let unbound = match peer {
            SocketAddr::V4(_)
                if local.ss_family == libc::AF_INET as u16
                    && length as usize == std::mem::size_of::<libc::sockaddr_in>() =>
            {
                let address = unsafe {
                    &*(&local as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                address.sin_port == 0 && address.sin_addr.s_addr == 0
            }
            SocketAddr::V6(_)
                if local.ss_family == libc::AF_INET6 as u16
                    && length as usize == std::mem::size_of::<libc::sockaddr_in6>() =>
            {
                let address = unsafe {
                    &*(&local as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                address.sin6_port == 0
                    && address.sin6_addr.s6_addr == [0; 16]
                    && address.sin6_scope_id == 0
                    && address.sin6_flowinfo == 0
            }
            _ => false,
        };
        if !unbound {
            return Err(invalid());
        }
        length = std::mem::size_of_val(&local) as u32;
        if unsafe {
            libc::getpeername(
                fd.as_raw_fd(),
                (&mut local as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } == 0
            || io::Error::last_os_error().raw_os_error() != Some(libc::ENOTCONN)
        {
            return Err(invalid());
        }
        if property::<i32>(&fd, libc::SO_TYPE)? != libc::SOCK_DGRAM
            || property::<i32>(&fd, libc::SO_PROTOCOL)? != libc::IPPROTO_UDP
        {
            return Err(invalid());
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } < 0
            || stat.st_uid != 65532
            || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
        {
            return Err(invalid());
        }
        let cookie = property::<u64>(&fd, libc::SO_COOKIE)?;
        let netns = property::<u64>(&fd, libc::SO_NETNS_COOKIE)?;
        if cookie == 0 || netns != interface.network_namespace.get() {
            return Err(invalid());
        }
        // Сокет уже проверен, но системный маршрут может временно отсутствовать.
        // До его появления lease не выдается, работник повторяет обычное подключение.
        let device = match system_device(peer, 65532, None) {
            Ok(device) => device,
            Err(error) => return Ok(TransportInspection::RouteUnavailable(error)),
        };
        if device == interface.device_identity.get() {
            return Err(invalid());
        }
        Ok(TransportInspection::Ready(Self {
            fd,
            cookie,
            netns,
            device,
            peer,
            pid,
        }))
    }
}
pub(super) fn system_device(peer: SocketAddr, uid: u32, excluded: Option<u64>) -> io::Result<u64> {
    let family = if peer.is_ipv4() { "-4" } else { "-6" };
    let address = peer.ip().to_string();
    let uid = uid.to_string();
    let mut args = vec![family, "-j", "route", "get", &address, "uid", &uid];
    let mut interface = [0i8; libc::IF_NAMESIZE];
    let name;
    if let SocketAddr::V6(peer) = peer {
        if peer.scope_id() != 0 {
            if unsafe { libc::if_indextoname(peer.scope_id(), interface.as_mut_ptr()) }.is_null() {
                return Err(io::Error::last_os_error());
            }
            name = unsafe { std::ffi::CStr::from_ptr(interface.as_ptr()) }
                .to_str()
                .map_err(|_| invalid())?
                .to_owned();
            args.extend(["oif", &name]);
        }
    }
    let route: serde_json::Value =
        serde_json::from_slice(&super::backend::path::run("ip", &args, None)?)?;
    let name = route[0]["dev"].as_str().ok_or_else(invalid)?;
    if name.contains('/') || name.is_empty() {
        return Err(invalid());
    }
    use std::os::unix::fs::MetadataExt;
    let device = std::fs::metadata(format!("/sys/class/net/{name}"))?.ino();
    if excluded == Some(device) {
        return Err(invalid());
    }
    Ok(device)
}

pub(super) fn property<T: Default>(fd: &OwnedFd, option: i32) -> io::Result<T> {
    let mut value = T::default();
    let mut size = std::mem::size_of::<T>() as u32;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut T).cast(),
            &mut size,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<T>() {
        return Err(invalid());
    }
    Ok(value)
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "FD не является новым транспортом собственного работника",
    )
}
