use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// Индекс без namespace и идентичности устройства недостаточен после его удаления.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceIdentity {
    pub index: NonZeroU32,
    pub network_namespace: NonZeroU64,
    pub device_identity: NonZeroU64,
}

/// Непостоянный TUN. Защита пути должна сохраняться до закрытия всех переданных FD.
#[derive(Debug)]
pub struct OwnedTunnel {
    descriptor: File,
    name: String,
    identity: InterfaceIdentity,
}

impl OwnedTunnel {
    pub fn create() -> io::Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(invalid("Интерфейс создает только привилегированная служба"));
        }
        require_system_namespace()?;
        let descriptor = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open("/dev/net/tun")?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (target, value) in request.ifr_name.iter_mut().zip(b"aivpn-app%d") {
            *target = *value as libc::c_char;
        }
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
        if unsafe { libc::ioctl(descriptor.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = interface_name(&request)?;
        let identity = identity(&name)?;
        let tunnel = Self {
            descriptor,
            name,
            identity,
        };
        tunnel.verify()?;
        Ok(tunnel)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn verify(&self) -> io::Result<InterfaceIdentity> {
        let request = self.read_interface()?;
        let expected = (libc::IFF_TUN | libc::IFF_NO_PI) as u16;
        if unsafe { request.ifr_ifru.ifru_flags } as u16 != expected
            || interface_name(&request)? != self.name
        {
            return Err(invalid("Параметры принадлежащего службе TUN изменены"));
        }
        let current = identity(&self.name)?;
        if current != self.identity {
            return Err(invalid("Идентичность принадлежащего службе TUN изменилась"));
        }
        verify_owner(&self.name)?;
        Ok(current)
    }

    /// Доверенный обработчик передает FD только после установки ограничений работника.
    pub fn duplicate_descriptor(&self) -> io::Result<OwnedFd> {
        self.verify()?;
        self.descriptor.as_fd().try_clone_to_owned()
    }

    fn read_interface(&self) -> io::Result<libc::ifreq> {
        let mut request = unsafe { std::mem::zeroed::<libc::ifreq>() };
        if unsafe { libc::ioctl(self.descriptor.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(request)
    }
}

fn interface_name(request: &libc::ifreq) -> io::Result<String> {
    let bytes = request.ifr_name.map(|value| value as u8);
    let name = CStr::from_bytes_until_nul(&bytes)
        .map_err(|_| invalid("Ядро вернуло некорректное имя TUN"))?;
    let name = name
        .to_str()
        .map_err(|_| invalid("Ядро вернуло некорректное имя TUN"))?;
    if name.is_empty() || name.contains('/') {
        return Err(invalid("Ядро вернуло некорректное имя TUN"));
    }
    Ok(name.to_owned())
}

fn identity(name: &str) -> io::Result<InterfaceIdentity> {
    let index = interface_index(name)?;
    let metadata = fs::metadata(format!("/sys/class/net/{name}"))?;
    Ok(InterfaceIdentity {
        index,
        network_namespace: namespace_cookie()?,
        device_identity: NonZeroU64::new(metadata.ino())
            .ok_or_else(|| invalid("Не удалось проверить идентичность TUN"))?,
    })
}

fn interface_index(name: &str) -> io::Result<NonZeroU32> {
    let index = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
        .trim()
        .parse::<NonZeroU32>()
        .map_err(|_| invalid("Некорректный индекс TUN"))?;
    let kernel_name = CString::new(name).map_err(|_| invalid("Некорректное имя TUN"))?;
    let kernel_index = unsafe { libc::if_nametoindex(kernel_name.as_ptr()) };
    if kernel_index != index.get() {
        return Err(invalid("Sysfs не соответствует namespace интерфейса"));
    }
    Ok(index)
}

fn require_system_namespace() -> io::Result<()> {
    let current = fs::metadata("/proc/thread-self/ns/net")?;
    let system = fs::metadata("/proc/1/ns/net")?;
    if (current.dev(), current.ino()) != (system.dev(), system.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Служба создает интерфейсы только в системном сетевом namespace",
        ));
    }
    Ok(())
}

fn namespace_cookie() -> io::Result<NonZeroU64> {
    use std::os::fd::FromRawFd;
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let mut cookie = 0u64;
    let mut size = std::mem::size_of_val(&cookie) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut size,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    parse_namespace_cookie(size, cookie)
}

fn parse_namespace_cookie(size: libc::socklen_t, cookie: u64) -> io::Result<NonZeroU64> {
    if size as usize != std::mem::size_of_val(&cookie) {
        return Err(invalid("Не удалось проверить namespace TUN"));
    }
    NonZeroU64::new(cookie).ok_or_else(|| invalid("Не удалось проверить namespace TUN"))
}

fn verify_owner(name: &str) -> io::Result<()> {
    for field in ["owner", "group"] {
        if fs::read_to_string(format!("/sys/class/net/{name}/{field}"))?.trim() != "-1" {
            return Err(invalid("Права открытия TUN изменены"));
        }
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_kernel_interface_names_are_rejected() {
        for bytes in [
            b"".as_slice(),
            b"invalid/name",
            b"\xff",
            b"1234567890123456",
        ] {
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            for (target, value) in request.ifr_name.iter_mut().zip(bytes) {
                *target = *value as libc::c_char;
            }
            assert!(interface_name(&request).is_err(), "{bytes:?}");
        }
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (target, value) in request.ifr_name.iter_mut().zip(b"aivpn-app1") {
            *target = *value as libc::c_char;
        }
        assert_eq!(interface_name(&request).unwrap(), "aivpn-app1");
    }

    #[test]
    fn namespace_response_keeps_the_complete_nonzero_cookie() {
        for cookie in [1, 2, u64::MAX] {
            assert_eq!(parse_namespace_cookie(8, cookie).unwrap().get(), cookie);
        }
        assert!(parse_namespace_cookie(8, 0).is_err());
        for size in [0, 1, 7, 9, u32::MAX] {
            assert!(parse_namespace_cookie(size, 1).is_err());
        }
    }

    #[test]
    fn interface_identity_agrees_with_the_current_kernel_namespace() {
        let current = identity("lo").unwrap();
        assert_eq!(current.index.get(), 1);
        assert_ne!(current.device_identity.get(), 0);
        assert_ne!(current.network_namespace.get(), 0);
        assert_eq!(identity("lo").unwrap(), current);
        assert!(identity("aivpn-missing").is_err());
    }
}
