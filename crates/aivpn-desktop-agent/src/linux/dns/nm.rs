//! Общий DNS NetworkManager сохраняет настройки физических подключений.
mod bootstrap;
mod global;
use super::dropin;
use crate::dns::journal::Provider;
use global::GlobalDns;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    ffi::CString,
    io,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};
use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{
        serialized::{Context, Data},
        to_bytes, DynamicType, OwnedObjectPath, OwnedValue, Type, Value, LE,
    },
};

const SERVICE: &str = "org.freedesktop.NetworkManager";
const ROOT: &str = "/org/freedesktop/NetworkManager";
const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const MAX_DEVICES: usize = 32;
type Settings = HashMap<String, HashMap<String, OwnedValue>>;
type DnsFields = BTreeMap<String, BTreeMap<String, SavedValue>>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DnsMode {
    #[default]
    SystemdResolved,
    Dnsmasq,
    Plain,
}
impl DnsMode {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "systemd-resolved" => Ok(Self::SystemdResolved),
            "dnsmasq" => Ok(Self::Dnsmasq),
            "default" => Ok(Self::Plain),
            _ => Err(io::ErrorKind::Unsupported.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedValue {
    wire: Vec<u8>,
}
impl SavedValue {
    fn capture(value: &OwnedValue) -> io::Result<Self> {
        let data = to_bytes(Context::new_dbus(LE, 0), value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if !data.fds().is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self {
            wire: data.bytes().to_vec(),
        })
    }
    fn new(value: Value<'_>) -> io::Result<Self> {
        let value = value
            .try_to_owned()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Self::capture(&value)
    }
    fn restore(&self) -> io::Result<OwnedValue> {
        let data = Data::new(self.wire.as_slice(), Context::new_dbus(LE, 0));
        let (value, used) = data
            .deserialize::<OwnedValue>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if used != self.wire.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    path: String,
    interface: String,
    ifindex: u32,
    device: u64,
    uuid: String,
    methods: BTreeMap<String, String>,
    dns: DnsFields,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    manager: String,
    #[serde(default)]
    mode: DnsMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    global: Option<GlobalDns>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    configuration: Option<dropin::Snapshot>,
    boot: String,
    namespace: u64,
    links: Vec<Link>,
    #[serde(default)]
    global_scope: bool,
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.manager == other.manager
            && self.mode == other.mode
            && self.global == other.global
            && self.configuration == other.configuration
            && self.boot == other.boot
            && self.namespace == other.namespace
            && self.owns_global() == other.owns_global()
            && (self.owns_global() || self.links == other.links)
    }
}
impl Eq for Snapshot {}
impl Snapshot {
    fn owns_global(&self) -> bool {
        self.global_scope || self.mode == DnsMode::Dnsmasq
    }

    fn rebind(&mut self, current: &Self) -> io::Result<()> {
        if self.boot == current.boot
            && self.manager == current.manager
            && self.namespace == current.namespace
            && self.mode == current.mode
        {
            return Ok(());
        }
        if !self.owns_global()
            || !current.owns_global()
            || self.mode != current.mode
            || self.boot == current.boot && self.namespace != current.namespace
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        // GlobalDnsConfiguration постоянна, но ссылки D-Bus и интерфейсов относятся к текущей ОС.
        self.manager = current.manager.clone();
        self.boot = current.boot.clone();
        self.namespace = current.namespace;
        self.links = current.links.clone();
        Ok(())
    }
}
pub(crate) struct NetworkManager {
    bus: Connection,
    owner: String,
    deadline: Instant,
    owned: Option<(u32, u64)>,
    mode: DnsMode,
    changes: Option<super::changes::Changes>,
    legacy_per_link: bool,
    configuration: Option<dropin::Dropin>,
    legacy_configuration: bool,
}
impl NetworkManager {
    pub(crate) fn open(namespace: [u8; 16]) -> io::Result<Self> {
        let bus = zbus::blocking::connection::Builder::system()
            .map_err(bus_error)?
            .method_timeout(Duration::from_secs(2))
            .build()
            .map_err(bus_error)?;
        let owner = trusted_owner(&bus)?;
        let mut manager = Self {
            bus,
            owner,
            deadline: Instant::now() + Duration::from_secs(5),
            owned: None,
            mode: DnsMode::default(),
            changes: None,
            legacy_per_link: false,
            configuration: None,
            legacy_configuration: false,
        };
        manager.mode = manager.current_mode()?;
        manager.changes = match manager.mode {
            DnsMode::SystemdResolved => Some(super::changes::Changes::open(
                &manager.bus,
                super::resolved::StubService::Resolved,
            )?),
            DnsMode::Dnsmasq => Some(super::changes::Changes::open(
                &manager.bus,
                super::resolved::StubService::NetworkManagerDnsmasq,
            )?),
            DnsMode::Plain => None,
        };
        if manager.mode != DnsMode::SystemdResolved && manager.global_dns()?.is_some() {
            manager.configuration = match dropin::Dropin::open(
                namespace,
                "/etc/NetworkManager/conf.d",
                "network-manager",
            ) {
                Ok(configuration) => Some(configuration),
                Err(error) if error.raw_os_error() == Some(libc::EROFS) => None,
                Err(error) => return Err(error),
            };
        }
        Ok(manager)
    }
    pub(crate) fn epoch(&mut self) -> io::Result<Option<u64>> {
        match &mut self.changes {
            Some(changes) => changes.epoch(),
            None => Ok(Some(0)),
        }
    }
    pub(crate) fn uses_resolved(&self) -> bool {
        self.mode == DnsMode::SystemdResolved
    }
    pub(crate) fn exclude_owned_tunnel(&mut self, identity: crate::linux::InterfaceIdentity) {
        self.owned = Some((identity.index.get(), identity.device_identity.get()));
    }
    pub(crate) fn stub_sockets(&self) -> io::Result<Vec<super::resolved::StubSocket>> {
        let service = match self.mode {
            DnsMode::SystemdResolved => super::resolved::StubService::Resolved,
            DnsMode::Dnsmasq => super::resolved::StubService::NetworkManagerDnsmasq,
            DnsMode::Plain => return Ok(Vec::new()),
        };
        super::resolved::capture_service(&self.bus, service)
    }
    pub(crate) fn relay_uses_ipv6(&self) -> bool {
        self.mode != DnsMode::Dnsmasq
    }
    fn global_dns(&self) -> io::Result<Option<GlobalDns>> {
        GlobalDns::capture(self.property(ROOT, SERVICE, "GlobalDnsConfiguration")?)
    }
    fn restart_dnsmasq(&self) -> io::Result<()> {
        let dbus = Proxy::new(
            &self.bus,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(bus_error)?;
        let name = "org.freedesktop.NetworkManager.dnsmasq";
        let present: bool = dbus.call("NameHasOwner", &(name,)).map_err(bus_error)?;
        let old: Option<String> = if present {
            Some(dbus.call("GetNameOwner", &(name,)).map_err(bus_error)?)
        } else {
            None
        };
        // dnsmasq сохраняет ifindex при повторном использовании записи сервера.
        // DNS_FULL убирает старую привязку без перезапуска сетевых подключений.
        self.call::<_, ()>(ROOT, SERVICE, "Reload", &(4u32,))?;
        loop {
            self.check_owner()?;
            let present: bool = dbus.call("NameHasOwner", &(name,)).map_err(bus_error)?;
            if present {
                let owner: String = dbus.call("GetNameOwner", &(name,)).map_err(bus_error)?;
                if Some(&owner) != old.as_ref() && self.stub_sockets().is_ok() {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn current_mode(&self) -> io::Result<DnsMode> {
        let mode: String = self.property(
            &format!("{ROOT}/DnsManager"),
            "org.freedesktop.NetworkManager.DnsManager",
            "Mode",
        )?;
        DnsMode::parse(&mode)
    }
    fn start(&mut self) -> io::Result<()> {
        self.deadline = Instant::now() + Duration::from_secs(5);
        let owner = trusted_owner(&self.bus)?;
        if owner != self.owner {
            self.owner = owner;
            if self.current_mode()? != self.mode {
                return Err(io::ErrorKind::Unsupported.into());
            }
        }
        self.check_owner()
    }
    fn check_owner(&self) -> io::Result<()> {
        self.budget()?;
        let dbus = Proxy::new(
            &self.bus,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(bus_error)?;
        let actual: String = dbus.call("GetNameOwner", &(SERVICE,)).map_err(bus_error)?;
        if actual != self.owner {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        Ok(())
    }
    fn budget(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
    fn call<B: Serialize + DynamicType, R: DeserializeOwned + Type>(
        &self,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
    ) -> io::Result<R> {
        self.budget()?;
        Proxy::new(&self.bus, self.owner.as_str(), path, interface)
            .map_err(bus_error)?
            .call(method, body)
            .map_err(bus_error)
    }
    fn property<T: TryFrom<OwnedValue>>(
        &self,
        path: &str,
        interface: &str,
        name: &str,
    ) -> io::Result<T> {
        // Properties.Get не использует клиентский кеш и дает свежий readback.
        let value: OwnedValue = self.call(
            path,
            "org.freedesktop.DBus.Properties",
            "Get",
            &(interface, name),
        )?;
        T::try_from(value).map_err(|_| io::ErrorKind::InvalidData.into())
    }
    fn link_identity(&self, path: &str) -> io::Result<(String, u32, u64)> {
        let interface: String = self.property(path, DEVICE, "IpInterface")?;
        if interface.is_empty() || interface.len() >= libc::IFNAMSIZ || interface.contains('/') {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let name = CString::new(interface.as_str()).map_err(|_| io::ErrorKind::InvalidData)?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        let device = std::fs::metadata(format!("/sys/class/net/{interface}"))?.ino();
        Ok((interface, ifindex, device))
    }
    fn read_link(&self, path: &str) -> io::Result<(Link, Settings, u64)> {
        self.read_identified_link(path, self.link_identity(path)?)
    }
    fn read_identified_link(
        &self,
        path: &str,
        identity: (String, u32, u64),
    ) -> io::Result<(Link, Settings, u64)> {
        let (interface, ifindex, device) = identity;
        let (settings, version): (Settings, u64) =
            self.call(path, DEVICE, "GetAppliedConnection", &(0u32,))?;
        if version == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let uuid = setting_string(&settings, "connection", "uuid")?;
        let mut methods = BTreeMap::new();
        for family in ["ipv4", "ipv6"] {
            if settings.contains_key(family) {
                methods.insert(family.into(), setting_string(&settings, family, "method")?);
            }
        }
        let dns = dns_fields(&settings)?;
        Ok((
            Link {
                path: path.into(),
                interface,
                ifindex,
                device,
                uuid,
                methods,
                dns,
            },
            settings,
            version,
        ))
    }
    fn snapshot_inner(&self) -> io::Result<Snapshot> {
        let mode = self.current_mode()?;
        let global = self.global_dns()?;
        if mode != self.mode || (mode == DnsMode::SystemdResolved && global.is_some()) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let paths: Vec<OwnedObjectPath> = self.call(ROOT, SERVICE, "GetDevices", &())?;
        if paths.len() > MAX_DEVICES {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let mut links = Vec::new();
        for path in paths {
            let state: u32 = self.property(path.as_str(), DEVICE, "State")?;
            if state != 100 {
                continue;
            }
            let kind: u32 = self.property(path.as_str(), DEVICE, "DeviceType")?;
            if kind == 32 {
                continue;
            }
            let identity = self.link_identity(path.as_str())?;
            if self.owned == Some((identity.1, identity.2)) {
                continue;
            }
            links.push(self.read_identified_link(path.as_str(), identity)?.0);
        }
        links.sort_by(|a, b| a.path.cmp(&b.path));
        if links.is_empty() && mode == DnsMode::SystemdResolved {
            return Err(io::ErrorKind::NotConnected.into());
        }
        for link in &links {
            if let Some(value) = link
                .dns
                .get("connection")
                .and_then(|s| s.get("dns-over-tls"))
            {
                let mode =
                    i32::try_from(value.restore()?).map_err(|_| io::ErrorKind::InvalidData)?;
                if mode > 0 {
                    return Err(io::ErrorKind::Unsupported.into());
                }
            }
        }
        self.check_owner()?;
        Ok(Snapshot {
            manager: self.owner.clone(),
            mode,
            global,
            configuration: if self.legacy_configuration {
                None
            } else {
                self.configuration
                    .as_ref()
                    .map(dropin::Dropin::snapshot)
                    .transpose()?
            },
            boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
            namespace: std::fs::metadata("/proc/thread-self/ns/net")?.ino(),
            links,
            global_scope: mode != DnsMode::SystemdResolved && !self.legacy_per_link,
        })
    }
}
fn trusted_owner(bus: &Connection) -> io::Result<String> {
    let dbus = Proxy::new(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(bus_error)?;
    let owner: String = dbus.call("GetNameOwner", &(SERVICE,)).map_err(bus_error)?;
    let uid: u32 = dbus
        .call("GetConnectionUnixUser", &(owner.as_str(),))
        .map_err(bus_error)?;
    if uid != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(owner)
}
impl Provider for NetworkManager {
    type Snapshot = Snapshot;
    fn cleanup_restored(&mut self) -> io::Result<()> {
        if let Some(configuration) = &self.configuration {
            configuration.cleanup_restored()?;
        }
        Ok(())
    }
    fn runtime_expired(&mut self, before: &Snapshot) -> io::Result<bool> {
        if before.boot == std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            || !before
                .configuration
                .as_ref()
                .is_some_and(dropin::Snapshot::is_absent)
        {
            return Ok(false);
        }
        match &self.configuration {
            Some(configuration) => Ok(configuration.snapshot()?.is_absent()),
            None => Ok(false),
        }
    }
    fn current_bootstrap_servers(
        &mut self,
        original: &Snapshot,
        current: &Snapshot,
    ) -> io::Result<Option<Vec<std::net::SocketAddr>>> {
        bootstrap::current_servers(self, original, current)
    }
    fn rebind_snapshot(&mut self, saved: &mut Snapshot) -> io::Result<()> {
        self.start()?;
        saved.rebind(&self.snapshot_inner()?)
    }
    fn resume(&mut self, saved: Option<&Snapshot>) -> io::Result<()> {
        if saved.is_some_and(|snapshot| snapshot.mode != self.mode) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.legacy_per_link = saved.is_some_and(|snapshot| !snapshot.owns_global());
        self.legacy_configuration = saved.is_some_and(|snapshot| snapshot.configuration.is_none());
        if saved.is_none() {
            if let Some(configuration) = &self.configuration {
                if !configuration.snapshot()?.is_absent() {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
            }
        }
        Ok(())
    }
    fn bootstrap_servers(&mut self, before: &Snapshot) -> io::Result<Vec<std::net::SocketAddr>> {
        self.start()?;
        if self.snapshot_inner()? != *before {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if let Some(global) = &before.global {
            if let Some(servers) = global.bootstrap_servers()? {
                return Ok(servers);
            }
        }
        let configuration: Vec<HashMap<String, OwnedValue>> = self.property(
            &format!("{ROOT}/DnsManager"),
            "org.freedesktop.NetworkManager.DnsManager",
            "Configuration",
        )?;
        if configuration.len() > MAX_DEVICES {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let mut entries = Vec::new();
        for mut entry in configuration {
            let interface = if let Some(interface) = entry.remove("interface") {
                let interface =
                    String::try_from(interface).map_err(|_| io::ErrorKind::InvalidData)?;
                let Some(link) = before.links.iter().find(|link| link.interface == interface)
                else {
                    continue;
                };
                Some(link.ifindex)
            } else {
                None
            };
            let priority =
                i32::try_from(entry.remove("priority").ok_or(io::ErrorKind::InvalidData)?)
                    .map_err(|_| io::ErrorKind::InvalidData)?;
            let servers = Vec::<String>::try_from(
                entry
                    .remove("nameservers")
                    .ok_or(io::ErrorKind::InvalidData)?,
            )
            .map_err(|_| io::ErrorKind::InvalidData)?;
            if servers.len() > 32 {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            entries.push((priority, servers, interface));
        }
        entries.sort_by_key(|entry| entry.0);
        let mut servers = Vec::new();
        for (_, names, interface) in entries {
            for name in names {
                let server = crate::dns::journal::bootstrap_server(&name, interface)?;
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }
        self.check_owner()?;
        if self.snapshot_inner()? != *before {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        crate::dns::journal::validate_bootstrap_servers(&servers)?;
        Ok(servers)
    }
    fn snapshot(&mut self) -> io::Result<Snapshot> {
        self.start()?;
        self.snapshot_inner()
    }
    fn plan_vpn(&mut self, before: &Snapshot) -> io::Result<Snapshot> {
        let mut after = before.clone();
        if before.owns_global() {
            after.global = Some(GlobalDns::local_relay(before.global.as_ref()));
            if before.configuration.is_some() {
                let configuration = self
                    .configuration
                    .as_ref()
                    .ok_or(io::ErrorKind::InvalidData)?;
                let bytes = after
                    .global
                    .as_ref()
                    .ok_or(io::ErrorKind::InvalidData)?
                    .configuration()?;
                match configuration.plan(bytes.as_bytes()) {
                    Ok(planned) => after.configuration = Some(planned),
                    // Доступный D-Bus остается пригодным при read-only /etc.
                    Err(error) if error.raw_os_error() == Some(libc::EROFS) => (),
                    Err(error) => return Err(error),
                }
            }
            return Ok(after);
        }
        for link in &mut after.links {
            for (family, address) in [("ipv4", "127.0.0.3"), ("ipv6", "::1")] {
                if !link
                    .methods
                    .get(family)
                    .is_some_and(|m| m != "disabled" && m != "ignore")
                {
                    continue;
                }
                let fields = link.dns.entry(family.into()).or_default();
                let legacy = if family == "ipv4" {
                    Value::from(vec![u32::from_ne_bytes([127, 0, 0, 3])])
                } else {
                    Value::from(vec![std::net::Ipv6Addr::LOCALHOST.octets().to_vec()])
                };
                fields.insert("dns".into(), SavedValue::new(legacy)?);
                fields.insert(
                    "dns-data".into(),
                    SavedValue::new(Value::from(vec![address]))?,
                );
                fields.insert(
                    "ignore-auto-dns".into(),
                    SavedValue::new(Value::from(true))?,
                );
                fields.insert(
                    "dns-priority".into(),
                    SavedValue::new(Value::from(i32::MIN))?,
                );
                let mut domains = match fields.get("dns-search") {
                    Some(value) => Vec::<String>::try_from(value.restore()?)
                        .map_err(|_| io::ErrorKind::InvalidData)?,
                    None => Vec::new(),
                };
                if !domains.iter().any(|v| v == "~.") {
                    domains.push("~.".into());
                }
                fields.insert("dns-search".into(), SavedValue::new(Value::from(domains))?);
            }
        }
        Ok(after)
    }
    fn plan_restore(&mut self, current: &Snapshot, original: &Snapshot) -> io::Result<Snapshot> {
        let mut restored = original.clone();
        if original.owns_global() {
            restored.links = current.links.clone();
        }
        Ok(restored)
    }
    fn can_complete(&self, current: &Snapshot, before: &Snapshot, after: &Snapshot) -> bool {
        current.manager == before.manager
            && current.manager == after.manager
            && current.mode == before.mode
            && current.mode == after.mode
            && current.boot == before.boot
            && current.boot == after.boot
            && current.namespace == before.namespace
            && current.namespace == after.namespace
            && (current.global == before.global || current.global == after.global)
            && (current.configuration == before.configuration
                || current.configuration == after.configuration)
            && (before.owns_global() && after.owns_global()
                || current.links.len() == before.links.len()
                    && current.links.len() == after.links.len()
                    && current
                        .links
                        .iter()
                        .zip(&before.links)
                        .zip(&after.links)
                        .all(|((c, b), a)| c == b || c == a))
    }
    fn apply(&mut self, expected: &Snapshot, planned: &Snapshot) -> io::Result<()> {
        self.start()?;
        if !self.can_complete(&self.snapshot_inner()?, expected, planned) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        for (before, after) in expected.links.iter().zip(&planned.links) {
            if planned.owns_global() {
                break;
            }
            let (current, mut settings, version) = self.read_link(&before.path)?;
            if current == *after {
                continue;
            }
            if current != *before {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            for section in ["ipv4", "ipv6", "connection"] {
                let Some(values) = settings.get_mut(section) else {
                    continue;
                };
                values.retain(|key, _| !is_dns(key));
                for (key, value) in after.dns.get(section).into_iter().flatten() {
                    values.insert(key.clone(), value.restore()?);
                }
            }
            self.call::<_, ()>(&before.path, DEVICE, "Reapply", &(settings, version, 1u32))?;
            if self.read_link(&before.path)?.0 != *after {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        if expected.global != planned.global || expected.configuration != planned.configuration {
            let current = self.global_dns()?;
            if current != expected.global && current != planned.global {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            if expected.configuration != planned.configuration {
                let configuration = self
                    .configuration
                    .as_ref()
                    .ok_or(io::ErrorKind::InvalidData)?;
                let before = expected
                    .configuration
                    .as_ref()
                    .ok_or(io::ErrorKind::InvalidData)?;
                let after = planned
                    .configuration
                    .as_ref()
                    .ok_or(io::ErrorKind::InvalidData)?;
                let actual = configuration.snapshot()?;
                if actual != *after {
                    configuration.apply(before, after)?;
                }
                self.call::<_, ()>(ROOT, SERVICE, "Reload", &(1u32,))?;
            } else if current != planned.global {
                let value = GlobalDns::restore(planned.global.as_ref());
                self.check_owner()?;
                self.call::<_, ()>(
                    ROOT,
                    "org.freedesktop.DBus.Properties",
                    "Set",
                    &(SERVICE, "GlobalDnsConfiguration", Value::from(value)),
                )?;
            }
            if self.global_dns()? != planned.global {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if self.mode == DnsMode::Dnsmasq {
                self.restart_dnsmasq()?;
            }
        }
        self.check_owner()
    }
}
fn is_dns(key: &str) -> bool {
    key.starts_with("dns") || key == "ignore-auto-dns"
}

#[cfg(test)]
mod snapshot_equality_tests {
    use super::*;

    fn snapshot(global_scope: bool, uuid: &str) -> Snapshot {
        Snapshot {
            manager: ":1.1".into(),
            mode: DnsMode::Plain,
            global: None,
            configuration: None,
            boot: "boot".into(),
            namespace: 1,
            global_scope,
            links: vec![Link {
                path: "/device/1".into(),
                interface: "wan0".into(),
                ifindex: 2,
                device: 3,
                uuid: uuid.into(),
                methods: BTreeMap::new(),
                dns: BTreeMap::new(),
            }],
        }
    }

    #[test]
    fn legacy_link_and_global_intents_form_separate_equality_classes() {
        let legacy = snapshot(false, "old");
        let global = snapshot(true, "old");
        let next_network = snapshot(true, "new");
        assert_ne!(legacy, global);
        assert_eq!(global, next_network);
        assert_ne!(legacy, next_network);
        assert_ne!(legacy, snapshot(false, "new"));
    }

    #[test]
    fn reboot_rebinds_only_os_references_and_preserves_original_global_dns() {
        let mut original = snapshot(true, "old");
        let mut current = snapshot(true, "new");
        current.boot = "new-boot".into();
        current.manager = ":1.12".into();
        current.namespace = 2;
        current.global = Some(GlobalDns::local_relay(None));
        original.rebind(&current).unwrap();
        assert_eq!(original.boot, current.boot);
        assert_eq!(original.manager, current.manager);
        assert_eq!(original.namespace, current.namespace);
        assert_eq!(original.links, current.links);
        assert_eq!(original.global, None);
        assert_ne!(original, current);
    }

    #[test]
    fn rebinding_rejects_runtime_link_intent_or_a_different_dns_mode() {
        let mut current = snapshot(true, "new");
        current.boot = "new-boot".into();
        assert!(snapshot(false, "old").rebind(&current).is_err());
        let mut different_mode = current.clone();
        different_mode.mode = DnsMode::Dnsmasq;
        assert!(snapshot(true, "old").rebind(&different_mode).is_err());
        current.boot = "boot".into();
        current.manager = ":1.12".into();
        current.namespace = 2;
        assert!(snapshot(true, "old").rebind(&current).is_err());
    }
}
fn setting_string(settings: &Settings, section: &str, key: &str) -> io::Result<String> {
    let value = settings
        .get(section)
        .and_then(|s| s.get(key))
        .ok_or(io::ErrorKind::InvalidData)?;
    <&str>::try_from(value)
        .map(str::to_owned)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}
fn dns_fields(settings: &Settings) -> io::Result<DnsFields> {
    let mut result = BTreeMap::new();
    for section in ["ipv4", "ipv6", "connection"] {
        if let Some(values) = settings.get(section) {
            let fields = values
                .iter()
                .filter(|(key, _)| is_dns(key))
                .map(|(key, value)| Ok((key.clone(), SavedValue::capture(value)?)))
                .collect::<io::Result<BTreeMap<_, _>>>()?;
            if !fields.is_empty() {
                result.insert(section.into(), fields);
            }
        }
    }
    Ok(result)
}
pub(super) fn bus_error(error: zbus::Error) -> io::Error {
    match error {
        zbus::Error::MethodError(name, _, _) => {
            io::Error::other(format!("D-Bus не подтвердил настройку DNS: {name}"))
        }
        _ => io::Error::other("D-Bus не подтвердил настройку DNS"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saved_dns_variants_keep_signatures_and_values() {
        for value in [
            Value::from(vec!["127.0.0.3", "::1"]),
            Value::from(vec![889197254u32]),
            Value::from(vec![std::net::Ipv6Addr::LOCALHOST.octets().to_vec()]),
            Value::from(i32::MIN),
            Value::from(true),
            Value::from(Vec::<String>::new()),
        ] {
            let saved = SavedValue::new(value.try_clone().unwrap()).unwrap();
            let journal = serde_json::to_vec(&saved).unwrap();
            let saved: SavedValue = serde_json::from_slice(&journal).unwrap();
            let restored = saved.restore().unwrap();
            assert_eq!(*restored, value);
        }
    }
    #[test]
    fn saved_dns_variant_rejects_trailing_bytes() {
        let mut saved = SavedValue::new(Value::from(true)).unwrap();
        saved.wire.push(0);
        assert_eq!(
            saved.restore().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
