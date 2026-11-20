//! DNS самостоятельного resolved. Меняются только серверы и домены, не маршруты ОС.
use super::{dropin, nm::bus_error};
use crate::dns::journal::Provider;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    ffi::CString,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};
use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{DynamicType, OwnedObjectPath, OwnedValue, Type},
};
const DIRECTORY: &str = "/run/systemd/resolved.conf.d";

const SERVICE: &str = "org.freedesktop.resolve1";
const ROOT: &str = "/org/freedesktop/resolve1";
const MANAGER: &str = "org.freedesktop.resolve1.Manager";
const LINK: &str = "org.freedesktop.resolve1.Link";
const MAX_LINKS: usize = 32;
type Address = (i32, Vec<u8>, u16, String);
type ScopedAddress = (i32, i32, Vec<u8>, u16, String);

fn read_service_identity<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    // Старый журнал содержал уникальное имя процесса. Оно не является правом обращения к новой службе.
    if value != SERVICE && zbus::names::UniqueName::try_from(value.as_str()).is_err() {
        return Err(serde::de::Error::custom("Неизвестный сервис DNS"));
    }
    Ok(SERVICE.into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Global {
    file: dropin::Snapshot,
    servers: Vec<ScopedAddress>,
    domains: Vec<(String, bool)>,
    tls: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    neutral: Option<dropin::Snapshot>,
}
impl PartialEq for Global {
    fn eq(&self, other: &Self) -> bool {
        self.file == other.file
            && self.servers == other.servers
            && self.domains == other.domains
            && self.tls == other.tls
    }
}
impl Eq for Global {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    path: String,
    name: String,
    index: u32,
    device: u64,
    servers: Vec<Address>,
    domains: Vec<(String, bool)>,
    tls: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    #[serde(alias = "resolved_owner", deserialize_with = "read_service_identity")]
    resolved_service: String,
    boot: String,
    namespace: u64,
    links: Vec<Link>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    global: Option<Global>,
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.resolved_service == other.resolved_service
            && self.boot == other.boot
            && self.namespace == other.namespace
            && self.global == other.global
            && (self.global.is_some() && other.global.is_some() || self.links == other.links)
    }
}
impl Eq for Snapshot {}

pub(crate) struct Resolved {
    bus: Connection,
    owner: String,
    deadline: Instant,
    owned: Option<(u32, u64)>,
    managed: Option<dropin::Dropin>,
    changes: super::changes::Changes,
    observed_epoch: u64,
}

impl Resolved {
    pub(crate) fn open(namespace: [u8; 16]) -> io::Result<Self> {
        let bus = zbus::blocking::connection::Builder::system()
            .map_err(|error| io::Error::other(format!("resolved, адрес системной шины: {error}")))?
            .method_timeout(Duration::from_secs(2))
            .build()
            .map_err(|error| io::Error::other(format!("resolved, подключение к шине: {error}")))?;
        let owner: String = Proxy::new(
            &bus,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(|error| io::Error::other(format!("resolved, прокси владельца: {error}")))?
        .call("GetNameOwner", &(SERVICE,))
        .map_err(|error| io::Error::other(format!("resolved, имя владельца: {error}")))?;
        // Проверяется настоящий процесс resolved и его локальные stub-сокеты.
        let _ = super::resolved::capture(&bus).map_err(|error| {
            io::Error::new(error.kind(), format!("Проверка процесса resolved: {error}"))
        })?;
        let context = |stage: &str, error: io::Error| {
            io::Error::new(error.kind(), format!("resolved, {stage}: {error}"))
        };
        let networkd = super::resolved::networkd_running(&bus)
            .map_err(|error| context("проверка процесса networkd", error))?;
        if networkd {
            super::resolved::require_configuration_reload(&bus)
                .map_err(|error| context("проверка перечитывания конфигурации", error))?;
        }
        let changes = super::changes::Changes::open(&bus, super::resolved::StubService::Resolved)?;
        Ok(Self {
            bus,
            owner,
            deadline: Instant::now() + Duration::from_secs(5),
            owned: None,
            managed: if networkd {
                Some(
                    dropin::Dropin::open(namespace, DIRECTORY, "resolved")
                        .map_err(|error| context("каталог собственной конфигурации", error))?,
                )
            } else {
                None
            },
            changes,
            observed_epoch: 0,
        })
    }

    pub(crate) fn epoch(&mut self) -> io::Result<Option<u64>> {
        let epoch = self.changes.epoch()?;
        if let Some(epoch) = epoch {
            if epoch != self.observed_epoch {
                // Новое уникальное имя используется только после проверки того же системного сервиса.
                self.owner = super::resolved::resolved_owner(&self.bus)?;
                self.observed_epoch = epoch;
            }
        }
        Ok(epoch)
    }

    pub(crate) fn use_managed_configuration(&mut self, namespace: [u8; 16]) -> io::Result<()> {
        super::resolved::require_configuration_reload(&self.bus)?;
        self.managed = Some(dropin::Dropin::open(namespace, DIRECTORY, "resolved")?);
        Ok(())
    }

    pub(crate) fn exclude_owned_tunnel(&mut self, identity: crate::linux::InterfaceIdentity) {
        self.owned = Some((identity.index.get(), identity.device_identity.get()));
    }

    pub(crate) fn stub_sockets(&self) -> io::Result<Vec<super::resolved::StubSocket>> {
        super::resolved::capture(&self.bus)
    }

    fn start(&mut self) -> io::Result<()> {
        self.deadline = Instant::now() + Duration::from_secs(5);
        if self.epoch()?.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.check_owner()
    }

    fn check_owner(&self) -> io::Result<()> {
        self.budget()?;
        let owner: String = Proxy::new(
            &self.bus,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(bus_error)?
        .call("GetNameOwner", &(SERVICE,))
        .map_err(bus_error)?;
        if owner != self.owner {
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
            .map_err(|error| {
                let kind = match &error {
                    zbus::Error::Variant(_) => "не совпал тип ответа",
                    zbus::Error::InvalidReply => "некорректный ответ",
                    _ => "отказ вызова",
                };
                io::Error::other(format!(
                    "resolved {interface}.{method}: {kind}; {}",
                    bus_error(error)
                ))
            })
    }

    fn property<T: TryFrom<OwnedValue>>(
        &self,
        path: &str,
        interface: &str,
        name: &str,
    ) -> io::Result<T> {
        let value: OwnedValue = self.call(
            path,
            "org.freedesktop.DBus.Properties",
            "Get",
            &(interface, name),
        )?;
        T::try_from(value).map_err(|_| io::ErrorKind::InvalidData.into())
    }

    fn read_link(&self, name: &str) -> io::Result<Link> {
        let c_name = CString::new(name).map_err(|_| io::ErrorKind::InvalidData)?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 || index > i32::MAX as u32 {
            return Err(io::ErrorKind::NotFound.into());
        }
        let device = std::fs::metadata(format!("/sys/class/net/{name}"))?.ino();
        let path: OwnedObjectPath = self.call(ROOT, MANAGER, "GetLink", &(index as i32,))?;
        let servers: Vec<Address> = self.property(path.as_str(), LINK, "DNSEx")?;
        let domains: Vec<(String, bool)> = self.property(path.as_str(), LINK, "Domains")?;
        if servers.len() > 32 || domains.len() > 256 {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        for address in &servers {
            server(address, index)?;
        }
        let tls: String = self.property(path.as_str(), LINK, "DNSOverTLS")?;
        if tls != "no" && self.managed.is_none() {
            // Effective mode не различает default и explicit; чужой режим не переписывается.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Для этого адаптера resolved нужен DNS без TLS на локальном relay",
            ));
        }
        Ok(Link {
            path: path.to_string(),
            name: name.into(),
            index,
            device,
            servers,
            domains,
            tls,
        })
    }

    fn read(&self) -> io::Result<Snapshot> {
        let mut servers: Vec<ScopedAddress> = self.property(ROOT, MANAGER, "DNSEx")?;
        let domains: Vec<(i32, String, bool)> = self.property(ROOT, MANAGER, "Domains")?;
        if servers.len() > 1024 || domains.len() > MAX_LINKS * 256 {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let entries = std::fs::read_dir("/sys/class/net")?
            .take(MAX_LINKS + 1)
            .collect::<io::Result<Vec<_>>>()?;
        if entries.len() > MAX_LINKS {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let mut links = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_str().ok_or(io::ErrorKind::InvalidData)?;
            let flags = std::fs::read_to_string(entry.path().join("flags"))?;
            let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
                .map_err(|_| io::ErrorKind::InvalidData)?;
            if flags & libc::IFF_LOOPBACK as u32 != 0 {
                continue;
            }
            let link = self.read_link(name)?;
            // Manager DNSEx использует индекс lo для любого loopback DNS, включая глобальный.
            // Источник определяется вычитанием фактических DNS каждого link, с учетом повторов.
            for address in &link.servers {
                let index = if server(address, link.index)?.ip().is_loopback() {
                    1
                } else {
                    link.index as i32
                };
                let scoped = (
                    index,
                    address.0,
                    address.1.clone(),
                    address.2,
                    address.3.clone(),
                );
                let position = servers
                    .iter()
                    .position(|value| *value == scoped)
                    .ok_or(io::ErrorKind::WouldBlock)?;
                servers.remove(position);
            }
            if self.owned == Some((link.index, link.device)) {
                continue;
            }
            links.push(link);
        }
        links.sort_by_key(|link| link.index);
        if links.is_empty() && self.managed.is_none() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if self.managed.is_none()
            && (!servers.is_empty() || domains.iter().any(|domain| domain.0 == 0))
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Нужен адаптер для глобальной конфигурации resolved",
            ));
        }
        let global = if let Some(managed) = &self.managed {
            for (index, family, address, port, name) in &servers {
                let index = u32::try_from(*index).map_err(|_| io::ErrorKind::InvalidData)?;
                server(&(*family, address.clone(), *port, name.clone()), index)?;
            }
            let mut domains = domains
                .into_iter()
                .filter(|value| value.0 == 0)
                .map(|(_, name, route)| (name, route))
                .collect::<Vec<_>>();
            domains.sort();
            Some(Global {
                file: managed.snapshot()?,
                servers,
                domains,
                tls: self.property(ROOT, MANAGER, "DNSOverTLS")?,
                neutral: None,
            })
        } else {
            None
        };
        self.check_owner()?;
        Ok(Snapshot {
            resolved_service: SERVICE.into(),
            boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
            namespace: std::fs::metadata("/proc/thread-self/ns/net")?.ino(),
            links,
            global,
        })
    }
}

fn server(value: &Address, index: u32) -> io::Result<SocketAddr> {
    let ip = match (value.0, value.1.as_slice()) {
        (libc::AF_INET, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        (libc::AF_INET6, bytes) if bytes.len() == 16 => {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    let port = if value.2 == 0 { 53 } else { value.2 };
    Ok(match ip {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => {
            SocketAddr::V6(SocketAddrV6::new(ip, port, 0, index))
        }
        ip => SocketAddr::new(ip, port),
    })
}

fn compatible(current: &Link, before: &Link, after: &Link) -> bool {
    current.path == before.path
        && current.path == after.path
        && current.name == before.name
        && current.name == after.name
        && current.index == before.index
        && current.index == after.index
        && current.device == before.device
        && current.device == after.device
        && current.tls == before.tls
        && current.tls == after.tls
        && (current.servers == before.servers || current.servers == after.servers)
        && (current.domains == before.domains || current.domains == after.domains)
}

fn bootstrap_addresses(global: Option<&Global>, links: &[Link]) -> io::Result<Vec<SocketAddr>> {
    let mut servers = Vec::new();
    if let Some(global) = global {
        for (index, family, address, port, name) in &global.servers {
            let index = u32::try_from(*index).map_err(|_| io::ErrorKind::InvalidData)?;
            let address = server(&(*family, address.clone(), *port, name.clone()), index)?;
            if !servers.contains(&address) {
                servers.push(address);
            }
        }
    }
    for link in links {
        for address in &link.servers {
            let address = server(address, link.index)?;
            if !servers.contains(&address) {
                servers.push(address);
            }
        }
    }
    crate::dns::journal::validate_bootstrap_servers(&servers)?;
    Ok(servers)
}

impl Provider for Resolved {
    type Snapshot = Snapshot;
    fn cleanup_restored(&mut self) -> io::Result<()> {
        match &self.managed {
            Some(managed) => managed.cleanup_restored(),
            None => Ok(()),
        }
    }

    fn runtime_expired(&mut self, before: &Snapshot) -> io::Result<bool> {
        if std::fs::read_to_string("/proc/sys/kernel/random/boot_id")? == before.boot {
            return Ok(false);
        }
        // Настройки D-Bus и собственный файл в /run не переживают загрузку ОС.
        let current = self.snapshot()?;
        if current
            .global
            .as_ref()
            .is_some_and(|global| !global.file.is_absent())
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(true)
    }

    fn current_bootstrap_servers(
        &mut self,
        original: &Snapshot,
        current: &Snapshot,
    ) -> io::Result<Option<Vec<SocketAddr>>> {
        if current.global.is_none() {
            return Ok(None);
        }
        self.start()?;
        let before = self.read()?;
        if before != *current || before.links != current.links {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let servers = bootstrap_addresses(original.global.as_ref(), &before.links)?;
        let after = self.read()?;
        if after != before || after.links != before.links {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(Some(servers))
    }

    fn snapshot(&mut self) -> io::Result<Snapshot> {
        self.start()?;
        self.read()
    }

    fn bootstrap_servers(&mut self, before: &Snapshot) -> io::Result<Vec<SocketAddr>> {
        self.start()?;
        if self.read()? != *before {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if let Some(global) = &before.global {
            if !global.file.is_absent() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
        }
        bootstrap_addresses(before.global.as_ref(), &before.links)
    }

    fn plan_vpn(&mut self, before: &Snapshot) -> io::Result<Snapshot> {
        let mut planned = before.clone();
        if let Some(global) = &mut planned.global {
            let managed = self.managed.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            global.servers = vec![(1, libc::AF_INET, vec![127, 0, 0, 3], 0, String::new())];
            global.tls = "no".into();
            for link in &before.links {
                for (name, _) in &link.domains {
                    if !global.domains.iter().any(|value| value.0 == *name) {
                        global.domains.push((name.clone(), true));
                    }
                }
            }
            if !global.domains.iter().any(|value| value.0 == ".") {
                global.domains.push((".".into(), true));
            }
            global.domains.sort();
            let mut content =
                String::from("[Resolve]\nDNS=\nDNS=127.0.0.3\nDomains=\nDNSOverTLS=no\n");
            for (name, route) in &global.domains {
                // Имя попадает в конфигурацию только после проверки DNS-синтаксиса.
                if name.len() > 253
                    || name.is_empty()
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                content.push_str("Domains=");
                if *route {
                    content.push('~');
                }
                content.push_str(name);
                content.push('\n');
            }
            global.file = managed.plan(content.as_bytes())?;
            return Ok(planned);
        }
        for link in &mut planned.links {
            // DNSEx возвращает стандартный порт 53 как 0, в том числе после явного SetLinkDNSEx.
            link.servers = vec![(libc::AF_INET, vec![127, 0, 0, 3], 0, String::new())];
            if !link.domains.iter().any(|domain| domain.0 == ".") {
                link.domains.push((".".into(), true));
            }
        }
        Ok(planned)
    }

    fn plan_restore(&mut self, current: &Snapshot, original: &Snapshot) -> io::Result<Snapshot> {
        let mut target = original.clone();
        if target.global.is_some() {
            target.links = current.links.clone();
        }
        if current == original {
            return Ok(target);
        }
        if let Some(global) = &mut target.global {
            if !matches!(global.tls.as_str(), "no" | "opportunistic" | "yes") {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let content = format!("[Resolve]\nDNS=\nDomains=\nDNSOverTLS={}\n", global.tls);
            global.neutral = Some(
                self.managed
                    .as_ref()
                    .ok_or(io::ErrorKind::InvalidData)?
                    .plan(content.as_bytes())?,
            );
        }
        Ok(target)
    }

    fn can_complete(&self, current: &Snapshot, before: &Snapshot, after: &Snapshot) -> bool {
        current.resolved_service == before.resolved_service
            && current.resolved_service == after.resolved_service
            && current.boot == before.boot
            && current.boot == after.boot
            && current.namespace == before.namespace
            && current.namespace == after.namespace
            && match (&current.global, &before.global, &after.global) {
                (None, None, None) => true,
                (Some(c), Some(b), Some(a)) => {
                    (c.file == b.file
                        || c.file == a.file
                        || b.neutral.as_ref() == Some(&c.file)
                        || a.neutral.as_ref() == Some(&c.file))
                        && (c.servers == b.servers
                            || c.servers == a.servers
                            || (b.neutral.is_some() || a.neutral.is_some()) && c.servers.is_empty())
                        && (c.domains == b.domains
                            || c.domains == a.domains
                            || (b.neutral.is_some() || a.neutral.is_some()) && c.domains.is_empty())
                        && (c.tls == b.tls || c.tls == a.tls)
                }
                _ => false,
            }
            && (current.global.is_some() && before.global.is_some() && after.global.is_some()
                || current.links.len() == before.links.len()
                    && current.links.len() == after.links.len()
                    && current
                        .links
                        .iter()
                        .zip(&before.links)
                        .zip(&after.links)
                        .all(|((current, before), after)| compatible(current, before, after)))
    }

    fn apply(&mut self, expected: &Snapshot, planned: &Snapshot) -> io::Result<()> {
        self.start()?;
        if !self.can_complete(&self.read()?, expected, planned) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if let (Some(before), Some(after)) = (&expected.global, &planned.global) {
            if expected.links != planned.links {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let managed = self.managed.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            let mut current_file = before.file.clone();
            if let Some(neutral) = &after.neutral {
                if current_file != after.file {
                    managed.apply(&current_file, neutral)?;
                    super::resolved::reload_configuration(&self.bus)?;
                    loop {
                        let current = self.read()?;
                        if !self.can_complete(&current, expected, planned) {
                            return Err(io::ErrorKind::AlreadyExists.into());
                        }
                        let state = current.global.as_ref().ok_or(io::ErrorKind::InvalidData)?;
                        if state.file == *neutral
                            && state.servers.is_empty()
                            && state.domains.is_empty()
                            && state.tls == after.tls
                        {
                            break;
                        }
                        self.budget()?;
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    current_file = neutral.clone();
                }
            }
            managed.apply(&current_file, &after.file)?;
            super::resolved::reload_configuration(&self.bus)?;
            loop {
                let current = self.read()?;
                if current == *planned {
                    return Ok(());
                }
                if !self.can_complete(&current, expected, planned) {
                    let state = current.global.as_ref().ok_or(io::ErrorKind::InvalidData)?;
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!(
                        "Состояние resolved после перечитывания не принадлежит операции: файл={}, серверы={}, домены={}, TLS={}, интерфейсы={}",
                        state.file == before.file || state.file == after.file,
                        state.servers == before.servers || state.servers == after.servers,
                        state.domains == before.domains || state.domains == after.domains,
                        state.tls == before.tls || state.tls == after.tls,
                        current.links == planned.links,
                    )));
                }
                self.budget()?;
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        for (before, after) in expected.links.iter().zip(&planned.links) {
            let mut current = self.read_link(&before.name)?;
            if !compatible(&current, before, after) {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            if current.servers != after.servers {
                self.call::<_, ()>(
                    ROOT,
                    MANAGER,
                    "SetLinkDNSEx",
                    &(after.index as i32, &after.servers),
                )?;
                current.servers = after.servers.clone();
                if self.read_link(&before.name)? != current {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
            }
            if current.domains != after.domains {
                self.call::<_, ()>(
                    ROOT,
                    MANAGER,
                    "SetLinkDomains",
                    &(after.index as i32, &after.domains),
                )?;
            }
            if self.read_link(&before.name)? != *after {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
        }
        self.check_owner()
    }
}
