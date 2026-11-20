//! Защита общего DNS остается в ядре при остановке сеанса или службы.
use super::KernelWriter;
use crate::linux::transport::property;
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
};

impl KernelWriter {
    pub(crate) fn set_system_dns_guard(&mut self, netns: u64, active: bool) -> io::Result<()> {
        self.check_owner()?;
        if netns == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut value = [0u8; 16];
        value[..8].copy_from_slice(&netns.to_ne_bytes());
        value[8..12].copy_from_slice(&u32::from(active).to_ne_bytes());
        self.write_runtime(c"dns_guard", &0u32.to_ne_bytes(), &value)
    }

    pub(crate) fn register_dns_listener(&mut self, socket: &OwnedFd, netns: u64) -> io::Result<()> {
        self.register_listener(socket, netns, 0, false)
    }
    pub(crate) fn register_resolved_dns_listener(
        &mut self,
        listener: &crate::linux::dns::resolved::StubSocket,
        netns: u64,
    ) -> io::Result<()> {
        // SO_REUSEADDR у resolved допустим только при привилегированном DNS-порте.
        // Простому пользователю нельзя занять тот же UDP endpoint.
        let first: u32 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")?
            .trim()
            .parse()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        if first <= 53 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.register_listener(listener.socket(), netns, listener.uid(), true)
    }
    fn register_listener(
        &mut self,
        socket: &OwnedFd,
        netns: u64,
        uid: u32,
        provider: bool,
    ) -> io::Result<()> {
        self.check_owner()?;
        let domain = property::<i32>(socket, libc::SO_DOMAIN)?;
        let kind = property::<i32>(socket, libc::SO_TYPE)?;
        let protocol = property::<i32>(socket, libc::SO_PROTOCOL)?;
        if !matches!(domain, libc::AF_INET | libc::AF_INET6)
            || !matches!(
                (kind, protocol),
                (libc::SOCK_DGRAM, libc::IPPROTO_UDP) | (libc::SOCK_STREAM, libc::IPPROTO_TCP)
            )
            || property::<u64>(socket, libc::SO_NETNS_COOKIE)? != netns
            || property::<u32>(socket, libc::SO_MARK)? != 0
            || property::<i32>(socket, libc::SO_REUSEPORT)? != 0
            || (!provider
                && kind == libc::SOCK_DGRAM
                && property::<i32>(socket, libc::SO_REUSEADDR)? != 0)
            || (kind == libc::SOCK_STREAM && property::<i32>(socket, libc::SO_ACCEPTCONN)? != 1)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(socket.as_raw_fd(), &mut status) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if status.st_uid != uid || status.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let (family, address) = listener_address(socket, domain)?;
        let cookie = property::<u64>(socket, libc::SO_COOKIE)?;
        if cookie == 0 || netns == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut endpoint = [0u8; 40];
        endpoint[..8].copy_from_slice(&netns.to_ne_bytes());
        endpoint[8..12].copy_from_slice(&family.to_ne_bytes());
        endpoint[12..16].copy_from_slice(&(protocol as u32).to_ne_bytes());
        endpoint[16..20].copy_from_slice(&53u32.to_ne_bytes());
        endpoint[24..40].copy_from_slice(&address);
        let mut value = [0u8; 16];
        value[..8].copy_from_slice(&cookie.to_ne_bytes());
        value[8..].copy_from_slice(&std::fs::metadata("/sys/class/net/lo")?.ino().to_ne_bytes());
        self.write_runtime(c"dns_listener_fds", &cookie.to_ne_bytes(), &endpoint)?;
        self.write_runtime(c"dns_listeners", &endpoint, &value)
    }
}

fn listener_address(socket: &OwnedFd, domain: i32) -> io::Result<(u32, [u8; 16])> {
    let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&local) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_storage).cast(),
            &mut size,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut address = [0; 16];
    let (family, port, loopback) = if domain == libc::AF_INET
        && size as usize == std::mem::size_of::<libc::sockaddr_in>()
    {
        let raw = unsafe {
            (&local as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_in>()
                .read()
        };
        let ip = std::net::Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes());
        address[..4].copy_from_slice(&ip.octets());
        (4, u16::from_be(raw.sin_port), ip.is_loopback())
    } else if domain == libc::AF_INET6 && size as usize == std::mem::size_of::<libc::sockaddr_in6>()
    {
        let raw = unsafe {
            (&local as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_in6>()
                .read()
        };
        address = raw.sin6_addr.s6_addr;
        (
            6,
            u16::from_be(raw.sin6_port),
            std::net::Ipv6Addr::from(address).is_loopback(),
        )
    } else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    if port != 53 || !loopback {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok((family, address))
}
