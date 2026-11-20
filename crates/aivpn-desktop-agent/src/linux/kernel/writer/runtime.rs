//! Типизированная публикация сетевого пути после проверки принадлежащего службе TUN.
use super::KernelWriter;
use crate::linux::{InterfaceIdentity, OwnedTunnel};
use aivpn_desktop_policy::{Authority, RuntimeProfile};
use std::{
    ffi::{c_void, CStr},
    io,
    os::fd::{AsRawFd, OwnedFd},
};

pub(crate) const PROFILE_MARK_MASK: u32 = 0xffff0000;
pub(crate) struct ProfilePath {
    pub slot: u32,
    pub mark: u32,
    pub zone: u32,
    pub identity: InterfaceIdentity,
}

impl KernelWriter {
    pub(crate) fn begin_bootstrap_dns(&mut self, epoch: u64) -> io::Result<()> {
        self.check_owner()?;
        if epoch == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut owner = [0u8; 16];
        owner[..8].copy_from_slice(&epoch.to_ne_bytes());
        owner[8..12].copy_from_slice(&std::process::id().to_ne_bytes());
        // Нулевой slot зарезервирован для служебного DNS и никогда не является VPN-профилем.
        self.write_runtime(c"transport_leases", &0u32.to_ne_bytes(), &owner)
    }
    pub(crate) fn end_bootstrap_dns(&mut self) -> io::Result<()> {
        self.check_owner()?;
        self.write_runtime(c"transport_leases", &0u32.to_ne_bytes(), &[0u8; 16])
    }
    pub(crate) fn register_bootstrap_dns_socket(
        &mut self,
        socket: &OwnedFd,
        peer: std::net::SocketAddr,
        netns: u64,
        device: u64,
        epoch: u64,
    ) -> io::Result<()> {
        self.check_owner()?;
        crate::dns::journal::validate_bootstrap_servers(&[peer])?;
        if device == 0 || epoch == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let ServiceDnsSocket {
            cookie,
            protocol,
            expires,
        } = inspect_service_dns_socket(socket, peer, netns)?;
        let mut owner = [0u8; 16];
        super::super::image::result(unsafe {
            bpf_map_lookup_elem(
                self.kernel.map(c"transport_leases")?.as_raw_fd(),
                (&0u32 as *const u32).cast(),
                owner.as_mut_ptr().cast(),
            )
        })?;
        if u64::from_ne_bytes(owner[..8].try_into().unwrap()) != epoch
            || u32::from_ne_bytes(owner[8..12].try_into().unwrap()) != std::process::id()
            || owner[12..] != [0; 4]
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut record = [0u8; 72];
        for (offset, value) in [(0, epoch), (8, netns), (16, device), (24, expires)] {
            record[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        for (offset, value) in [
            (36, std::process::id()),
            (44, if peer.is_ipv4() { 4u32 } else { 6 }),
            (48, protocol as u32),
            (52, peer.port() as u32),
        ] {
            record[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        match peer.ip() {
            std::net::IpAddr::V4(ip) => record[56..60].copy_from_slice(&ip.octets()),
            std::net::IpAddr::V6(ip) => record[56..72].copy_from_slice(&ip.octets()),
        }
        self.write_runtime(c"transport_sockets", &cookie.to_ne_bytes(), &record)
    }
    pub(crate) fn publish_dns_epoch(&mut self, epoch: u64, slot: u32) -> io::Result<()> {
        self.check_owner()?;
        if epoch == 0 || slot == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut value = [0u8; 16];
        value[..8].copy_from_slice(&epoch.to_ne_bytes());
        value[8..12].copy_from_slice(&slot.to_ne_bytes());
        self.write_runtime(c"dns_epochs", &0u32.to_ne_bytes(), &value)
    }
    pub(crate) fn revoke_dns_epoch(&mut self) -> io::Result<()> {
        self.emergency_owner()?;
        let fd = self.kernel.map(c"dns_epochs")?;
        let code =
            unsafe { super::bpf_map_delete_elem(fd.as_raw_fd(), (&0u32 as *const u32).cast()) };
        if code == -libc::ENOENT {
            return Ok(());
        }
        super::super::image::result(code)
    }
    pub(crate) fn register_dns_socket(
        &mut self,
        socket: &OwnedFd,
        peer: std::net::SocketAddr,
        slot: u32,
        generation: u64,
        epoch: u64,
        netns: u64,
    ) -> io::Result<()> {
        self.check_owner()?;
        if epoch == 0
            || generation == 0
            || slot == 0
            || peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let ServiceDnsSocket {
            cookie,
            protocol,
            expires,
        } = inspect_service_dns_socket(socket, peer, netns)?;
        let mut record = [0u8; 72];
        for (offset, value) in [(0, epoch), (8, generation), (16, netns), (24, expires)] {
            record[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        for (offset, value) in [
            (32, slot),
            (36, if peer.is_ipv4() { 4 } else { 6 }),
            (40, protocol as u32),
            (44, peer.port() as u32),
            (64, std::process::id()),
        ] {
            record[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        match peer.ip() {
            std::net::IpAddr::V4(ip) => record[48..52].copy_from_slice(&ip.octets()),
            std::net::IpAddr::V6(ip) => record[48..64].copy_from_slice(&ip.octets()),
        }
        let mut active = [0u8; 16];
        super::super::image::result(unsafe {
            bpf_map_lookup_elem(
                self.kernel.map(c"dns_epochs")?.as_raw_fd(),
                (&0u32 as *const u32).cast(),
                active.as_mut_ptr().cast(),
            )
        })?;
        if u64::from_ne_bytes(active[..8].try_into().unwrap()) != epoch
            || u32::from_ne_bytes(active[8..12].try_into().unwrap()) != slot
            || active[12..] != [0; 4]
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.write_runtime(c"dns_sockets", &cookie.to_ne_bytes(), &record)
    }
    pub(crate) fn register_transport(
        &mut self,
        transport: &crate::linux::transport::ValidatedTransport,
        slot: u32,
        lease: u64,
    ) -> io::Result<()> {
        self.check_owner()?;
        transport.verify_lifetime()?;
        if slot == 0 || lease == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let peer = transport.peer;
        let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let expires = (clock.tv_sec as u64)
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(clock.tv_nsec as u64))
            .and_then(|n| n.checked_add(10_000_000_000))
            .ok_or_else(|| io::Error::other("Исчерпано время регистрации"))?;
        let mut record = [0u8; 72];
        for (offset, value) in [
            (0, lease),
            (8, transport.netns),
            (16, transport.device),
            (24, expires),
        ] {
            record[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        for (offset, value) in [
            (32, slot),
            (36, transport.pid),
            (40, 65532),
            (44, if peer.is_ipv4() { 4 } else { 6 }),
            (48, 17),
            (52, peer.port() as u32),
        ] {
            record[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        match peer.ip() {
            std::net::IpAddr::V4(address) => record[56..60].copy_from_slice(&address.octets()),
            std::net::IpAddr::V6(address) => record[56..72].copy_from_slice(&address.octets()),
        }
        let mut owner = [0u8; 16];
        owner[..8].copy_from_slice(&lease.to_ne_bytes());
        owner[8..12].copy_from_slice(&transport.pid.to_ne_bytes());
        owner[12..16].copy_from_slice(&65532u32.to_ne_bytes());
        self.write_runtime(
            c"transport_sockets",
            &transport.cookie.to_ne_bytes(),
            &record,
        )?;
        self.write_runtime(c"transport_leases", &slot.to_ne_bytes(), &owner)
    }
    pub(crate) fn revoke_all_transport_leases(&mut self) -> io::Result<()> {
        self.emergency_owner()?;
        let fd = self.kernel.map(c"transport_leases")?;
        for _ in 0..257 {
            let mut key = 0u32;
            let status = unsafe {
                bpf_map_get_next_key(
                    fd.as_raw_fd(),
                    std::ptr::null(),
                    (&mut key as *mut u32).cast(),
                )
            };
            if status == -libc::ENOENT {
                return Ok(());
            }
            super::super::image::result(status)?;
            super::super::image::result(unsafe {
                super::bpf_map_delete_elem(fd.as_raw_fd(), (&key as *const u32).cast())
            })?;
        }
        Err(io::ErrorKind::InvalidData.into())
    }
    pub(crate) fn revoke_transport_lease(&mut self, slot: u32) -> io::Result<()> {
        self.emergency_owner()?;
        if slot == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fd = self.kernel.map(c"transport_leases")?;
        let status =
            unsafe { super::bpf_map_delete_elem(fd.as_raw_fd(), (&slot as *const u32).cast()) };
        if status == -libc::ENOENT {
            return Ok(());
        }
        super::super::image::result(status)
    }
    pub(crate) fn object_id(&self, fd: &OwnedFd) -> io::Result<u32> {
        self.check_owner()?;
        Ok(super::super::objects::ObjectInfo::read(fd)?.words[1])
    }
    pub(crate) fn verify_profile_matcher(&self, slot: u32, expected: u32) -> io::Result<()> {
        self.check_owner()?;
        if slot == 0 || expected == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let root = super::super::pins::bpffs_root()?;
        let base = super::super::pins::open_directory_at(&root, c"aivpn_app_profile_programs")?;
        let namespace = self
            .slots
            .namespace()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let name = std::ffi::CString::new(format!("{namespace}_{slot:08x}")).unwrap();
        let fd = super::super::objects::open_pin(&base, &name)?;
        let info = super::super::objects::ObjectInfo::read(&fd)?;
        if info.words[0] != 1 || info.words[1] != expected {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    pub(crate) fn pin_profile_matcher(&self, slot: u32, matcher: &OwnedFd) -> io::Result<String> {
        self.check_owner()?;
        let root = super::super::pins::bpffs_root()?;
        let directory = c"aivpn_app_profile_programs";
        if unsafe { libc::mkdirat(root.as_raw_fd(), directory.as_ptr(), 0o700) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
        {
            return Err(io::Error::last_os_error());
        }
        let base = super::super::pins::open_directory_at(&root, directory)?;
        let namespace = self
            .slots
            .namespace()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let name = std::ffi::CString::new(format!("{namespace}_{slot:08x}")).unwrap();
        let pin = std::ffi::CString::new(format!(
            "/proc/thread-self/fd/{}/{}",
            base.as_raw_fd(),
            name.to_str().unwrap()
        ))
        .unwrap();
        unsafe extern "C" {
            fn bpf_obj_pin(fd: i32, path: *const i8) -> i32;
        }
        super::super::image::result(unsafe { bpf_obj_pin(matcher.as_raw_fd(), pin.as_ptr()) })?;
        if unsafe { libc::fchmodat(base.as_raw_fd(), name.as_ptr(), 0o600, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = super::super::objects::open_pin(&base, &name)?;
        if super::super::objects::ObjectInfo::read(&actual)?.words[1]
            != super::super::objects::ObjectInfo::read(matcher)?.words[1]
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(format!(
            "/sys/fs/bpf/aivpn_app_profile_programs/{}",
            name.to_str().unwrap()
        ))
    }
    pub(crate) fn profile_slot(
        &mut self,
        desired: &crate::control::ControlState,
        profile: &str,
    ) -> io::Result<u32> {
        self.check_owner()?;
        let authority = Authority {
            user: aivpn_desktop_policy::Owner::LinuxUser { uid: 0 },
            machine_admin: true,
        };
        let plan = crate::bindings::BindingPlan::prepare_with(
            desired.policies(),
            desired.profiles(),
            &authority,
            &mut self.slots,
            true,
        )?;
        plan.bindings()
            .profiles
            .get(profile)
            .map(|slot| slot.get())
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
    pub(crate) fn profile_matcher(&self, slot: u32) -> io::Result<OwnedFd> {
        self.check_owner()?;
        let image = super::super::KernelImage::open_mode(self.kernel.mode())?;
        image
            .load_profile_match(slot, |name| Ok(self.kernel.map(name)?.as_raw_fd()))?
            .duplicate_program(c"match_profile")
    }
    pub(crate) fn publish_profile(
        &mut self,
        profile: &RuntimeProfile,
        path: &ProfilePath,
        tunnel: &OwnedTunnel,
    ) -> io::Result<()> {
        self.check_owner()?;
        if tunnel.verify()? != path.identity
            || path.slot == 0
            || path.mark == 0
            || path.mark & !PROFILE_MARK_MASK != 0
            || path.zone == 0
            || path.zone > 65535
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut value = [0u8; 64];
        value[..4].copy_from_slice(&path.mark.to_ne_bytes());
        value[4..8].copy_from_slice(&u32::from(profile.ready_ipv4).to_ne_bytes());
        value[8..12].copy_from_slice(&u32::from(profile.ready_ipv6).to_ne_bytes());
        value[12..16].copy_from_slice(&path.identity.index.get().to_ne_bytes());
        value[16..24].copy_from_slice(&profile.assignment_generation.to_ne_bytes());
        if let Some(assignment) = profile.assignment {
            if assignment.interface_id != path.identity.device_identity.get() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            value[24..28].copy_from_slice(&assignment.ipv4.octets());
            if let Some(address) = assignment.ipv6 {
                value[28..44].copy_from_slice(&address.octets());
            }
        } else if profile.ready_ipv4 || profile.ready_ipv6 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        value[44..48].copy_from_slice(&PROFILE_MARK_MASK.to_ne_bytes());
        value[48..56].copy_from_slice(&path.identity.network_namespace.get().to_ne_bytes());
        value[56..64].copy_from_slice(&path.identity.device_identity.get().to_ne_bytes());
        let mut interface = [0u8; 16];
        interface[..8].copy_from_slice(&path.identity.network_namespace.get().to_ne_bytes());
        interface[8..12].copy_from_slice(&path.identity.index.get().to_ne_bytes());
        let mut mark = [0u8; 16];
        mark[..8].copy_from_slice(&path.identity.network_namespace.get().to_ne_bytes());
        mark[8..12].copy_from_slice(&path.mark.to_ne_bytes());
        self.write_runtime(c"interface_profiles", &interface, &path.slot.to_ne_bytes())?;
        self.write_runtime(c"mark_profiles", &mark, &path.slot.to_ne_bytes())?;
        self.write_runtime(
            c"profile_zones",
            &path.slot.to_ne_bytes(),
            &path.zone.to_ne_bytes(),
        )?;
        // Единственный update с ready=1 идет после остальных readback.
        self.write_runtime(c"profiles", &path.slot.to_ne_bytes(), &value)
    }
    pub(crate) fn block_profiles(&mut self) -> io::Result<()> {
        self.emergency_owner()?;
        let fd = self.kernel.map(c"profiles")?;
        if super::super::objects::ObjectInfo::read(fd)?.map_shape() != [1, 4, 64, 256, 0] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut previous: Option<[u8; 4]> = None;
        for _ in 0..257 {
            let mut key = [0u8; 4];
            let status = unsafe {
                bpf_map_get_next_key(
                    fd.as_raw_fd(),
                    previous
                        .as_ref()
                        .map_or(std::ptr::null(), |k| k.as_ptr().cast()),
                    key.as_mut_ptr().cast(),
                )
            };
            if status == -libc::ENOENT {
                return Ok(());
            }
            super::super::image::result(status)?;
            let mut value = [0u8; 64];
            super::super::image::result(unsafe {
                bpf_map_lookup_elem(
                    fd.as_raw_fd(),
                    key.as_ptr().cast(),
                    value.as_mut_ptr().cast(),
                )
            })?;
            value[4..12].fill(0);
            self.write_runtime(c"profiles", &key, &value)?;
            previous = Some(key);
        }
        Err(io::ErrorKind::InvalidData.into())
    }
    pub(crate) fn block_profile(&mut self, slot: u32) -> io::Result<()> {
        self.emergency_owner()?;
        if slot == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fd = self.kernel.map(c"profiles")?;
        let mut value = [0u8; 64];
        let status = unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                (&slot as *const u32).cast(),
                value.as_mut_ptr().cast(),
            )
        };
        if status == -libc::ENOENT {
            return Ok(());
        }
        super::super::image::result(status)?;
        value[4..12].fill(0);
        self.write_runtime(c"profiles", &slot.to_ne_bytes(), &value)
    }
    /// Удаляет индексы закрытых TUN этого профиля, сохраняя остальные профили.
    pub(crate) fn retire_profile_interfaces(&self, slot: u32) -> io::Result<()> {
        self.check_owner()?;
        if slot == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fd = self.kernel.map(c"interface_profiles")?;
        if super::super::objects::ObjectInfo::read(fd)?.map_shape() != [1, 16, 4, 256, 0] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // Сначала собираем ключи. Удаление во время get_next_key начинает обход заново.
        let keys = profile_interface_keys(fd, slot)?;
        for key in keys {
            let mut current = 0u32;
            let code = unsafe {
                bpf_map_lookup_elem(
                    fd.as_raw_fd(),
                    key.as_ptr().cast(),
                    (&mut current as *mut u32).cast(),
                )
            };
            if code == -libc::ENOENT {
                continue;
            }
            super::super::image::result(code)?;
            if current != slot {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            super::super::image::result(unsafe {
                super::bpf_map_delete_elem(fd.as_raw_fd(), key.as_ptr().cast())
            })?;
        }
        Ok(())
    }
    fn emergency_owner(&self) -> io::Result<()> {
        if self.owner_pid != std::process::id() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        super::super::hooks::require_system_namespaces()
    }
    pub(super) fn write_runtime(&self, name: &CStr, key: &[u8], value: &[u8]) -> io::Result<()> {
        let fd = self.kernel.map(name)?;
        let info = super::super::objects::ObjectInfo::read(fd)?;
        if info.words[2] as usize != key.len() || info.words[3] as usize != value.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        super::super::image::result(unsafe {
            super::bpf_map_update_elem(
                fd.as_raw_fd(),
                key.as_ptr().cast(),
                value.as_ptr().cast(),
                0,
            )
        })?;
        let mut actual = vec![0; value.len()];
        super::super::image::result(unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                key.as_ptr().cast(),
                actual.as_mut_ptr().cast(),
            )
        })?;
        if actual != value {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}

fn profile_interface_keys(fd: &OwnedFd, slot: u32) -> io::Result<Vec<[u8; 16]>> {
    let mut previous: Option<[u8; 16]> = None;
    let mut keys = Vec::new();
    for _ in 0..257 {
        let mut key = [0u8; 16];
        let code = unsafe {
            bpf_map_get_next_key(
                fd.as_raw_fd(),
                previous
                    .as_ref()
                    .map_or(std::ptr::null(), |key| key.as_ptr().cast()),
                key.as_mut_ptr().cast(),
            )
        };
        if code == -libc::ENOENT {
            return Ok(keys);
        }
        super::super::image::result(code)?;
        let mut current = 0u32;
        super::super::image::result(unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                key.as_ptr().cast(),
                (&mut current as *mut u32).cast(),
            )
        })?;
        if current == slot {
            keys.push(key);
        }
        previous = Some(key);
    }
    Err(io::ErrorKind::InvalidData.into())
}

unsafe extern "C" {
    fn bpf_map_lookup_elem(fd: i32, key: *const c_void, value: *mut c_void) -> i32;
    fn bpf_map_get_next_key(fd: i32, key: *const c_void, next: *mut c_void) -> i32;
}

struct ServiceDnsSocket {
    cookie: u64,
    protocol: i32,
    expires: u64,
}

fn inspect_service_dns_socket(
    socket: &OwnedFd,
    peer: std::net::SocketAddr,
    netns: u64,
) -> io::Result<ServiceDnsSocket> {
    use crate::linux::transport::property;
    let domain = property::<i32>(socket, libc::SO_DOMAIN)?;
    let kind = property::<i32>(socket, libc::SO_TYPE)?;
    let protocol = property::<i32>(socket, libc::SO_PROTOCOL)?;
    if domain
        != (if peer.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        })
        || !matches!(
            (kind, protocol),
            (libc::SOCK_DGRAM, libc::IPPROTO_UDP) | (libc::SOCK_STREAM, libc::IPPROTO_TCP)
        )
        || property::<u32>(socket, libc::SO_MARK)? != 0
        || property::<u64>(socket, libc::SO_NETNS_COOKIE)? != netns
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(socket.as_raw_fd(), &mut status) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if status.st_uid != 0 || status.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&local) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let wildcard =
        if domain == libc::AF_INET && length as usize == std::mem::size_of::<libc::sockaddr_in>() {
            unsafe {
                (&local as *const libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in>()
                    .read()
                    .sin_addr
                    .s_addr
                    == 0
            }
        } else if domain == libc::AF_INET6
            && length as usize == std::mem::size_of::<libc::sockaddr_in6>()
        {
            unsafe {
                (&local as *const libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in6>()
                    .read()
                    .sin6_addr
                    .s6_addr
                    == [0; 16]
            }
        } else {
            false
        };
    if !wildcard {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    length = std::mem::size_of_val(&local) as libc::socklen_t;
    let connected = unsafe {
        libc::getpeername(
            socket.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if connected == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ENOTCONN) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let cookie = property::<u64>(socket, libc::SO_COOKIE)?;
    if cookie == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let expires = (clock.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(clock.tv_nsec as u64))
        .and_then(|value| value.checked_add(6_000_000_000))
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(ServiceDnsSocket {
        cookie,
        protocol,
        expires,
    })
}
