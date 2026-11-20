//! Адаптеры настроек ОС используют тот же журнал и проверку владельца.
mod changes;
mod dropin;
pub(crate) mod file;
pub(crate) mod nm;
pub(crate) mod resolvconf;
pub(crate) mod resolved;
mod staging;
pub(crate) mod standalone;
use crate::dns::journal::Provider;

pub(super) fn network_manager_manages_dns() -> std::io::Result<bool> {
    match std::fs::symlink_metadata("/run/dbus/system_bus_socket") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let bus = zbus::blocking::connection::Builder::system()
        .map_err(nm::bus_error)?
        .method_timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(nm::bus_error)?;
    let dbus = zbus::blocking::Proxy::new(
        &bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(nm::bus_error)?;
    let present: bool = dbus
        .call("NameHasOwner", &("org.freedesktop.NetworkManager",))
        .map_err(nm::bus_error)?;
    if !present {
        return Ok(false);
    }
    let owner: String = dbus
        .call("GetNameOwner", &("org.freedesktop.NetworkManager",))
        .map_err(nm::bus_error)?;
    let uid: u32 = dbus
        .call("GetConnectionUnixUser", &(owner.as_str(),))
        .map_err(nm::bus_error)?;
    if uid != 0 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let mode: String = zbus::blocking::Proxy::new(
        &bus,
        owner.as_str(),
        "/org/freedesktop/NetworkManager/DnsManager",
        "org.freedesktop.NetworkManager.DnsManager",
    )
    .map_err(nm::bus_error)?
    .get_property("Mode")
    .map_err(nm::bus_error)?;
    Ok(mode != "none")
}

pub(super) enum SystemProvider {
    File(file::FileProvider),
    NetworkManager(nm::NetworkManager),
    Resolved(standalone::Resolved),
    Resolvconf(resolvconf::Resolvconf),
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum Snapshot {
    File(file::Snapshot),
    NetworkManager(nm::Snapshot),
    Resolved(standalone::Snapshot),
    Resolvconf(resolvconf::Snapshot),
}
impl SystemProvider {
    pub(super) fn epoch(&mut self) -> std::io::Result<Option<u64>> {
        match self {
            Self::NetworkManager(provider) => provider.epoch(),
            Self::Resolved(provider) => provider.epoch(),
            Self::File(_) | Self::Resolvconf(_) => Ok(Some(0)),
        }
    }
    pub(super) fn relay_uses_ipv6(&self) -> bool {
        match self {
            Self::NetworkManager(provider) => provider.relay_uses_ipv6(),
            Self::File(_) | Self::Resolved(_) | Self::Resolvconf(_) => true,
        }
    }
    pub(super) fn exclude_owned_tunnel(&mut self, identity: super::InterfaceIdentity) {
        match self {
            Self::NetworkManager(provider) => provider.exclude_owned_tunnel(identity),
            Self::Resolved(provider) => provider.exclude_owned_tunnel(identity),
            Self::File(_) | Self::Resolvconf(_) => {}
        }
    }
    pub(super) fn stub_sockets(&self) -> std::io::Result<Vec<resolved::StubSocket>> {
        match self {
            Self::NetworkManager(provider) => provider.stub_sockets(),
            Self::Resolved(provider) => provider.stub_sockets(),
            Self::File(_) | Self::Resolvconf(_) => Ok(Vec::new()),
        }
    }
}
impl Provider for SystemProvider {
    type Snapshot = Snapshot;
    fn cleanup_restored(&mut self) -> std::io::Result<()> {
        match self {
            Self::File(provider) => provider.cleanup_restored(),
            Self::Resolved(provider) => provider.cleanup_restored(),
            Self::NetworkManager(provider) => provider.cleanup_restored(),
            Self::Resolvconf(_) => Ok(()),
        }
    }
    fn rebind_snapshot(&mut self, saved: &mut Snapshot) -> std::io::Result<()> {
        match (self, saved) {
            (Self::NetworkManager(provider), Snapshot::NetworkManager(saved)) => {
                provider.rebind_snapshot(saved)
            }
            (Self::File(_), Snapshot::File(_))
            | (Self::Resolved(_), Snapshot::Resolved(_))
            | (Self::Resolvconf(_), Snapshot::Resolvconf(_)) => Ok(()),
            _ => Err(std::io::ErrorKind::InvalidData.into()),
        }
    }
    fn runtime_expired(&mut self, before: &Snapshot) -> std::io::Result<bool> {
        match (self, before) {
            (Self::Resolved(provider), Snapshot::Resolved(before)) => {
                provider.runtime_expired(before)
            }
            (Self::Resolvconf(provider), Snapshot::Resolvconf(before)) => {
                provider.runtime_expired(before)
            }
            (Self::NetworkManager(provider), Snapshot::NetworkManager(before)) => {
                provider.runtime_expired(before)
            }
            (Self::File(_), Snapshot::File(_)) => Ok(false),
            _ => Err(std::io::ErrorKind::InvalidData.into()),
        }
    }
    fn resume(&mut self, saved: Option<&Snapshot>) -> std::io::Result<()> {
        match (self, saved) {
            (Self::NetworkManager(provider), Some(Snapshot::NetworkManager(saved))) => {
                provider.resume(Some(saved))
            }
            (Self::NetworkManager(provider), None) => provider.resume(None),
            (Self::Resolved(_), Some(Snapshot::Resolved(_)) | None)
            | (Self::File(_), Some(Snapshot::File(_)) | None)
            | (Self::Resolvconf(_), Some(Snapshot::Resolvconf(_)) | None) => Ok(()),
            _ => Err(std::io::ErrorKind::InvalidData.into()),
        }
    }
    fn current_bootstrap_servers(
        &mut self,
        original: &Snapshot,
        current: &Snapshot,
    ) -> std::io::Result<Option<Vec<std::net::SocketAddr>>> {
        match (self, original, current) {
            (
                Self::Resolved(provider),
                Snapshot::Resolved(original),
                Snapshot::Resolved(current),
            ) => provider.current_bootstrap_servers(original, current),
            (
                Self::NetworkManager(provider),
                Snapshot::NetworkManager(original),
                Snapshot::NetworkManager(current),
            ) => provider.current_bootstrap_servers(original, current),
            (
                Self::Resolvconf(provider),
                Snapshot::Resolvconf(original),
                Snapshot::Resolvconf(current),
            ) => provider.current_bootstrap_servers(original, current),
            (Self::File(_), Snapshot::File(_), Snapshot::File(_)) => Ok(None),
            _ => Err(std::io::ErrorKind::InvalidData.into()),
        }
    }
    fn bootstrap_servers(
        &mut self,
        before: &Snapshot,
    ) -> std::io::Result<Vec<std::net::SocketAddr>> {
        match (self, before) {
            (Self::File(provider), Snapshot::File(before)) => provider.bootstrap_servers(before),
            (Self::NetworkManager(provider), Snapshot::NetworkManager(before)) => {
                provider.bootstrap_servers(before)
            }
            (Self::Resolved(provider), Snapshot::Resolved(before)) => {
                provider.bootstrap_servers(before)
            }
            (Self::Resolvconf(provider), Snapshot::Resolvconf(before)) => {
                provider.bootstrap_servers(before)
            }
            _ => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }
    fn snapshot(&mut self) -> std::io::Result<Snapshot> {
        match self {
            Self::File(p) => p.snapshot().map(Snapshot::File),
            Self::NetworkManager(p) => p.snapshot().map(Snapshot::NetworkManager),
            Self::Resolved(p) => p.snapshot().map(Snapshot::Resolved),
            Self::Resolvconf(p) => p.snapshot().map(Snapshot::Resolvconf),
        }
    }
    fn plan_vpn(&mut self, before: &Snapshot) -> std::io::Result<Snapshot> {
        match (self, before) {
            (Self::File(p), Snapshot::File(v)) => p.plan_vpn(v).map(Snapshot::File),
            (Self::NetworkManager(p), Snapshot::NetworkManager(v)) => {
                p.plan_vpn(v).map(Snapshot::NetworkManager)
            }
            (Self::Resolved(p), Snapshot::Resolved(v)) => p.plan_vpn(v).map(Snapshot::Resolved),
            (Self::Resolvconf(p), Snapshot::Resolvconf(v)) => {
                p.plan_vpn(v).map(Snapshot::Resolvconf)
            }
            _ => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }
    fn plan_restore(
        &mut self,
        current: &Snapshot,
        original: &Snapshot,
    ) -> std::io::Result<Snapshot> {
        match (self, current, original) {
            (Self::File(p), Snapshot::File(v), Snapshot::File(o)) => {
                p.plan_restore(v, o).map(Snapshot::File)
            }
            (Self::NetworkManager(p), Snapshot::NetworkManager(v), Snapshot::NetworkManager(o)) => {
                p.plan_restore(v, o).map(Snapshot::NetworkManager)
            }
            (Self::Resolved(p), Snapshot::Resolved(v), Snapshot::Resolved(o)) => {
                p.plan_restore(v, o).map(Snapshot::Resolved)
            }
            (Self::Resolvconf(p), Snapshot::Resolvconf(v), Snapshot::Resolvconf(o)) => {
                p.plan_restore(v, o).map(Snapshot::Resolvconf)
            }
            _ => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }
    fn apply(&mut self, expected: &Snapshot, planned: &Snapshot) -> std::io::Result<()> {
        match (self, expected, planned) {
            (Self::File(p), Snapshot::File(v), Snapshot::File(o)) => p.apply(v, o),
            (Self::NetworkManager(p), Snapshot::NetworkManager(v), Snapshot::NetworkManager(o)) => {
                p.apply(v, o)
            }
            (Self::Resolved(p), Snapshot::Resolved(v), Snapshot::Resolved(o)) => p.apply(v, o),
            (Self::Resolvconf(p), Snapshot::Resolvconf(v), Snapshot::Resolvconf(o)) => {
                p.apply(v, o)
            }
            _ => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }
    fn can_complete(&self, current: &Snapshot, before: &Snapshot, after: &Snapshot) -> bool {
        match (self, current, before, after) {
            (Self::File(p), Snapshot::File(c), Snapshot::File(b), Snapshot::File(a)) => {
                p.can_complete(c, b, a)
            }
            (
                Self::NetworkManager(p),
                Snapshot::NetworkManager(c),
                Snapshot::NetworkManager(b),
                Snapshot::NetworkManager(a),
            ) => p.can_complete(c, b, a),
            (
                Self::Resolvconf(p),
                Snapshot::Resolvconf(c),
                Snapshot::Resolvconf(b),
                Snapshot::Resolvconf(a),
            ) => p.can_complete(c, b, a),
            (
                Self::Resolved(p),
                Snapshot::Resolved(c),
                Snapshot::Resolved(b),
                Snapshot::Resolved(a),
            ) => p.can_complete(c, b, a),
            _ => false,
        }
    }
}

pub(super) fn network_namespace() -> std::io::Result<u64> {
    use std::os::fd::AsFd;
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    super::transport::property::<u64>(&socket.as_fd().try_clone_to_owned()?, libc::SO_NETNS_COOKIE)
}

pub(super) struct KernelGuard<'a> {
    pub writer: &'a mut super::kernel::KernelWriter,
    pub netns: u64,
}
impl crate::dns::journal::Guard for KernelGuard<'_> {
    fn enable(&mut self) -> std::io::Result<()> {
        self.writer.set_system_dns_guard(self.netns, true)
    }
    fn disable(&mut self) -> std::io::Result<()> {
        self.writer.set_system_dns_guard(self.netns, false)
    }
}
