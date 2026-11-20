//! Исходные настройки сохраняются до внешнего эффекта и не теряются при повторе.
use crate::{control::ControlStore, state::StateFile};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{io, net::SocketAddr};

const VERSION: u32 = 1;
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsScope {
    pub namespace: [u8; 16],
    pub control_serial: u64,
    pub control_digest: [u8; 32],
    pub profile: String,
}

pub(crate) trait Provider {
    type Snapshot: Clone + Eq + Serialize + DeserializeOwned;
    /// Выбирает прежнюю область владения при продолжении сохраненной операции.
    fn resume(&mut self, _saved: Option<&Self::Snapshot>) -> io::Result<()> {
        Ok(())
    }
    fn snapshot(&mut self) -> io::Result<Self::Snapshot>;
    /// Подтверждает, что временный эффект исчез вместе с прежней загрузкой ОС.
    fn runtime_expired(&mut self, _before: &Self::Snapshot) -> io::Result<bool> {
        Ok(false)
    }
    /// Обновляет проверенную область ОС, сохраняя поля постоянной настройки DNS.
    fn rebind_snapshot(&mut self, _saved: &mut Self::Snapshot) -> io::Result<()> {
        Ok(())
    }
    /// Действующие адреса DHCP/RA не подменяют поля Automatic/Static для восстановления.
    fn bootstrap_servers(&mut self, _before: &Self::Snapshot) -> io::Result<Vec<SocketAddr>> {
        Ok(Vec::new())
    }
    /// Читает DNS новой сети из полей, которые этот адаптер не меняет.
    fn current_bootstrap_servers(
        &mut self,
        _original: &Self::Snapshot,
        _current: &Self::Snapshot,
    ) -> io::Result<Option<Vec<SocketAddr>>> {
        Ok(None)
    }
    /// Готовит точный результат, не подменяя настройки ОС.
    fn plan_vpn(&mut self, before: &Self::Snapshot) -> io::Result<Self::Snapshot>;
    fn plan_restore(
        &mut self,
        current: &Self::Snapshot,
        original: &Self::Snapshot,
    ) -> io::Result<Self::Snapshot>;
    /// Меняет только объект, который по-прежнему равен expected.
    fn apply(&mut self, expected: &Self::Snapshot, planned: &Self::Snapshot) -> io::Result<()>;
    /// Вызывается после durable Restored: прежние временные планы больше не нужны.
    fn cleanup_restored(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Несколько объектов могут остаться между before и after после прерывания.
    fn can_complete(
        &self,
        current: &Self::Snapshot,
        before: &Self::Snapshot,
        after: &Self::Snapshot,
    ) -> bool {
        current == before || current == after
    }
}

pub(crate) trait Guard {
    fn enable(&mut self) -> io::Result<()>;
    fn disable(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Guarded,
    Applying,
    Applied,
    Restoring,
    Restored,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<S> {
    version: u32,
    scope: DnsScope,
    before: S,
    after: Option<S>,
    restored: Option<S>,
    phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bootstrap_servers: Option<Vec<SocketAddr>>,
}

pub(crate) fn validate_bootstrap_servers(servers: &[SocketAddr]) -> io::Result<()> {
    if servers.len() > 32
        || servers.iter().any(|server| {
            server.port() == 0
                || server.ip().is_unspecified()
                || server.ip().is_multicast()
                || server.ip().is_loopback()
                || server.ip() == std::net::Ipv4Addr::BROADCAST
                || matches!(server, SocketAddr::V6(address) if address.ip().is_unicast_link_local() && address.scope_id() == 0)
                || matches!(server.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Неверный исходный DNS для транспорта",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn bootstrap_server(value: &str, interface: Option<u32>) -> io::Result<SocketAddr> {
    let mut address = match value.parse::<std::net::IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, 53),
        Err(_) => match value.parse::<SocketAddr>() {
            Ok(address) => address,
            Err(_) => {
                let (ip, zone) = value.rsplit_once('%').ok_or(io::ErrorKind::Unsupported)?;
                let ip = ip
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(|_| io::ErrorKind::InvalidData)?;
                let scope = match zone.parse::<u32>() {
                    Ok(scope) => scope,
                    Err(_) => {
                        #[cfg(target_os = "linux")]
                        {
                            let zone = std::ffi::CString::new(zone)
                                .map_err(|_| io::ErrorKind::InvalidData)?;
                            unsafe { libc::if_nametoindex(zone.as_ptr()) }
                        }
                        #[cfg(not(target_os = "linux"))]
                        return Err(io::ErrorKind::Unsupported.into());
                    }
                };
                if scope == 0 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                SocketAddr::V6(std::net::SocketAddrV6::new(ip, 53, 0, scope))
            }
        },
    };
    if let SocketAddr::V6(address) = &mut address {
        if address.ip().is_unicast_link_local() && address.scope_id() == 0 {
            address.set_scope_id(interface.ok_or(io::ErrorKind::InvalidData)?);
        }
        if address.scope_id() != 0 && interface.is_some_and(|index| index != address.scope_id()) {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    validate_bootstrap_servers(&[address])?;
    Ok(address)
}

/// Активный журнал нельзя заменять чтением уже переписанного системного DNS.
pub(crate) fn transport_servers<P: Provider>(
    store: &impl ControlStore,
    namespace: [u8; 16],
    provider: &mut P,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(mut record) = load::<P::Snapshot>(store)? {
        if record.scope.namespace != namespace {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if record.phase != Phase::Restored && !provider.runtime_expired(&record.before)? {
            resume_record(provider, &mut record)?;
            if record.phase == Phase::Applied {
                let current = provider.snapshot()?;
                if Some(&current) != record.after.as_ref() {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                if let Some(servers) =
                    provider.current_bootstrap_servers(&record.before, &current)?
                {
                    validate_bootstrap_servers(&servers)?;
                    return Ok(servers);
                }
            }
            return record.bootstrap_servers.ok_or_else(|| {
                io::Error::new(
                io::ErrorKind::NotFound,
                "В прежнем журнале нет исходного DNS. Восстановите DNS перед повторным включением",
            )
            });
        }
    }
    provider.resume(None)?;
    let before = provider.snapshot()?;
    let servers = provider.bootstrap_servers(&before)?;
    validate_bootstrap_servers(&servers)?;
    Ok(servers)
}

fn save<S: Serialize>(store: &mut impl ControlStore, record: &Record<S>) -> io::Result<()> {
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() > MAX_BYTES {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    store.replace(StateFile::DnsJournal, &bytes)?;
    if store.load(StateFile::DnsJournal)?.as_deref() != Some(bytes.as_slice()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn load<S: DeserializeOwned>(store: &impl ControlStore) -> io::Result<Option<Record<S>>> {
    let Some(bytes) = store.load(StateFile::DnsJournal)? else {
        return Ok(None);
    };
    if bytes.len() > MAX_BYTES {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    let record: Record<S> = serde_json::from_slice(&bytes)?;
    if let Some(servers) = &record.bootstrap_servers {
        validate_bootstrap_servers(servers)?;
    }
    if record.version != VERSION
        || record.scope.control_serial == 0
        || record.scope.profile.is_empty()
        || matches!(record.phase, Phase::Applying | Phase::Applied) && record.after.is_none()
        || matches!(record.phase, Phase::Restoring | Phase::Restored) && record.restored.is_none()
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(record))
}

pub(crate) fn require_restored(store: &impl ControlStore) -> io::Result<()> {
    match load::<serde_json::Value>(store)? {
        None
        | Some(Record {
            phase: Phase::Restored,
            ..
        }) => Ok(()),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "DNS еще не восстановлен",
        )),
    }
}

fn compatible(old: &DnsScope, desired: &DnsScope) -> io::Result<()> {
    if old.namespace != desired.namespace
        || old.control_serial > desired.control_serial
        || old.control_serial == desired.control_serial
            && old.control_digest != desired.control_digest
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn resume_record<P: Provider>(
    provider: &mut P,
    record: &mut Record<P::Snapshot>,
) -> io::Result<()> {
    provider.resume(Some(&record.before))?;
    for snapshot in std::iter::once(&mut record.before)
        .chain(record.after.as_mut())
        .chain(record.restored.as_mut())
    {
        provider.rebind_snapshot(snapshot)?;
    }
    Ok(())
}

/// Возвращает успех только после сверки фактических настроек с durable intent.
pub(crate) fn activate<P: Provider>(
    store: &mut impl ControlStore,
    desired: DnsScope,
    provider: &mut P,
    guard: &mut impl Guard,
) -> io::Result<()> {
    if desired.control_serial == 0 || desired.profile.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut existing = match (|| {
        let record = load::<P::Snapshot>(store)?;
        if let Some(record) = &record {
            compatible(&record.scope, &desired)?;
            if provider.runtime_expired(&record.before)? {
                return Ok(None);
            }
        }
        Ok(record)
    })() {
        Ok(record) => record,
        Err(error) => {
            guard.enable()?;
            return Err(error);
        }
    };
    let resumed = match existing
        .as_mut()
        .filter(|record| record.phase != Phase::Restored)
    {
        Some(record) => resume_record(provider, record),
        None => provider.resume(None),
    };
    if let Err(error) = resumed {
        guard.enable()?;
        return Err(error);
    }
    let mut record = match existing {
        Some(record) if record.phase != Phase::Restored => {
            if record.scope.profile != desired.profile || record.phase == Phase::Restoring {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            record
        }
        _ => {
            let before = provider.snapshot()?;
            let servers = provider.bootstrap_servers(&before)?;
            validate_bootstrap_servers(&servers)?;
            let record = Record {
                version: VERSION,
                scope: desired.clone(),
                before,
                after: None,
                restored: None,
                phase: Phase::Prepared,
                bootstrap_servers: Some(servers),
            };
            save(store, &record)?;
            record
        }
    };
    guard.enable()?;
    if record.phase == Phase::Prepared {
        record.phase = Phase::Guarded;
        save(store, &record)?;
    }
    if record.after.is_none() {
        if provider.snapshot()? != record.before {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        record.after = Some(provider.plan_vpn(&record.before)?);
        record.phase = Phase::Applying;
        save(store, &record)?;
    }
    let after = record.after.as_ref().ok_or(io::ErrorKind::InvalidData)?;
    let current = provider.snapshot()?;
    if current != *after {
        if !provider.can_complete(&current, &record.before, after) || record.phase == Phase::Applied
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        provider.apply(&current, after)?;
    }
    if provider.snapshot()? != *after {
        return Err(io::ErrorKind::InvalidData.into());
    }
    record.scope = desired;
    record.phase = Phase::Applied;
    save(store, &record)
}

/// Защита снимается после восстановления и fsync. Чужая правка дает отказ.
pub(crate) fn restore<P: Provider>(
    store: &mut impl ControlStore,
    namespace: [u8; 16],
    provider: &mut P,
    guard: &mut impl Guard,
) -> io::Result<()> {
    let Some(mut record) = (match load::<P::Snapshot>(store) {
        Ok(record) => record,
        Err(error) => {
            guard.enable()?;
            return Err(error);
        }
    }) else {
        return Ok(());
    };
    if record.scope.namespace != namespace {
        return Err(io::ErrorKind::InvalidData.into());
    }
    match provider.runtime_expired(&record.before) {
        Ok(true) => return guard.disable(),
        Ok(false) => {}
        Err(error) => {
            guard.enable()?;
            return Err(error);
        }
    }
    if let Err(error) = resume_record(provider, &mut record) {
        guard.enable()?;
        return Err(error);
    }
    if record.phase == Phase::Restored {
        if Some(provider.snapshot()?) != record.restored {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        provider.cleanup_restored()?;
        return guard.disable();
    }
    guard.enable()?;
    let current = provider.snapshot()?;
    if record.restored.is_none() {
        let expected = record.after.as_ref().unwrap_or(&record.before);
        if !provider.can_complete(&current, &record.before, expected) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        record.restored = Some(provider.plan_restore(&current, &record.before)?);
        record.phase = Phase::Restoring;
        save(store, &record)?;
    }
    let target = record.restored.as_ref().ok_or(io::ErrorKind::InvalidData)?;
    if current != *target {
        let after = record.after.as_ref().unwrap_or(&record.before);
        if !provider.can_complete(&current, &record.before, after)
            && !provider.can_complete(&current, after, target)
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        provider.apply(&current, target)?;
    }
    if provider.snapshot()? != *target {
        return Err(io::ErrorKind::InvalidData.into());
    }
    record.phase = Phase::Restored;
    save(store, &record)?;
    provider.cleanup_restored()?;
    guard.disable()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BootOs {
        epoch: u64,
        persistent: bool,
        os: Os,
    }
    impl Provider for BootOs {
        type Snapshot = (u64, String);
        fn snapshot(&mut self) -> io::Result<Self::Snapshot> {
            Ok((self.epoch, self.os.snapshot()?))
        }
        fn runtime_expired(&mut self, before: &Self::Snapshot) -> io::Result<bool> {
            Ok(!self.persistent && self.epoch != before.0)
        }
        fn rebind_snapshot(&mut self, saved: &mut Self::Snapshot) -> io::Result<()> {
            if self.persistent {
                saved.0 = self.epoch;
            }
            Ok(())
        }
        fn bootstrap_servers(&mut self, before: &Self::Snapshot) -> io::Result<Vec<SocketAddr>> {
            self.os.bootstrap_servers(&before.1)
        }
        fn plan_vpn(&mut self, before: &Self::Snapshot) -> io::Result<Self::Snapshot> {
            Ok((self.epoch, self.os.plan_vpn(&before.1)?))
        }
        fn plan_restore(
            &mut self,
            current: &Self::Snapshot,
            original: &Self::Snapshot,
        ) -> io::Result<Self::Snapshot> {
            Ok((self.epoch, self.os.plan_restore(&current.1, &original.1)?))
        }
        fn apply(&mut self, expected: &Self::Snapshot, planned: &Self::Snapshot) -> io::Result<()> {
            assert_eq!(self.epoch, expected.0);
            assert_eq!(self.epoch, planned.0);
            self.os.apply(&expected.1, &planned.1)
        }
    }

    fn rebooted_dns() -> (Store, Protection, BootOs) {
        let mut os = BootOs {
            epoch: 1,
            persistent: false,
            os: Os::new(),
        };
        let (mut store, mut guard) = (Store::default(), Protection::default());
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        os.epoch = 2;
        os.os.current = "8.8.4.4".into();
        os.os.writes = 0;
        (store, guard, os)
    }

    #[test]
    fn reboot_reapplies_runtime_dns_and_restores_the_new_boot_configuration() {
        let (mut store, mut guard, mut os) = rebooted_dns();
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        assert_eq!(os.os.current, "127.0.0.3");
        assert!(guard.active);
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.os.current, "8.8.4.4");
        assert!(!guard.active);
    }

    #[test]
    fn reboot_transport_dns_reads_the_new_network_instead_of_the_old_journal() {
        let (store, _, mut os) = rebooted_dns();
        assert_eq!(
            transport_servers(&store, [1; 16], &mut os).unwrap(),
            ["8.8.4.4:53".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(os.os.writes, 0);
    }

    #[test]
    fn reboot_restore_keeps_the_new_configuration_without_replaying_old_links() {
        let (mut store, mut guard, mut os) = rebooted_dns();
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.os.current, "8.8.4.4");
        assert_eq!(os.os.writes, 0);
        assert!(!guard.active);
    }

    #[test]
    fn reboot_does_not_adopt_a_journal_from_another_namespace() {
        let (mut store, mut guard, mut os) = rebooted_dns();
        let mut other = scope();
        other.namespace = [2; 16];
        assert!(activate(&mut store, other, &mut os, &mut guard).is_err());
        assert!(transport_servers(&store, [2; 16], &mut os).is_err());
        assert!(restore(&mut store, [2; 16], &mut os, &mut guard).is_err());
        assert_eq!(os.os.current, "8.8.4.4");
        assert_eq!(os.os.writes, 0);
    }

    #[test]
    fn persistent_dns_after_reboot_keeps_original_servers_for_bootstrap_and_restore() {
        let (mut store, mut guard, mut os) = rebooted_dns();
        os.persistent = true;
        os.os.current = "127.0.0.3".into();
        assert_eq!(
            transport_servers(&store, [1; 16], &mut os).unwrap(),
            ["9.9.9.9:53".parse::<SocketAddr>().unwrap()]
        );
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        assert_eq!(os.os.writes, 0);
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.os.current, "9.9.9.9");
        assert_eq!(os.os.writes, 1);
        assert!(!guard.active);
    }

    #[test]
    fn persistent_dns_rebinding_does_not_overwrite_a_foreign_change() {
        let (mut store, mut guard, mut os) = rebooted_dns();
        os.persistent = true;
        assert!(activate(&mut store, scope(), &mut os, &mut guard).is_err());
        assert!(restore(&mut store, [1; 16], &mut os, &mut guard).is_err());
        assert!(transport_servers(&store, [1; 16], &mut os).is_err());
        assert_eq!(os.os.current, "8.8.4.4");
        assert_eq!(os.os.writes, 0);
        assert!(guard.active);
    }
    #[derive(Default)]
    struct Store {
        bytes: Option<Vec<u8>>,
        writes: usize,
        fail: usize,
    }
    impl ControlStore for Store {
        fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
            assert!(matches!(file, StateFile::DnsJournal));
            Ok(self.bytes.clone())
        }
        fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()> {
            assert!(matches!(file, StateFile::DnsJournal));
            self.bytes = Some(bytes.into());
            self.writes += 1;
            if self.writes == self.fail {
                return Err(io::ErrorKind::StorageFull.into());
            }
            Ok(())
        }
        fn clear_pending(&mut self) -> io::Result<()> {
            panic!("DNS не удаляет Pending Control")
        }
    }
    struct Os {
        current: String,
        writes: usize,
        fail_after_apply: bool,
    }
    impl Os {
        fn new() -> Self {
            Self {
                current: "9.9.9.9".into(),
                writes: 0,
                fail_after_apply: false,
            }
        }
    }
    impl Provider for Os {
        type Snapshot = String;
        fn snapshot(&mut self) -> io::Result<String> {
            Ok(self.current.clone())
        }
        fn bootstrap_servers(&mut self, before: &String) -> io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::new(before.parse().unwrap(), 53)])
        }
        fn plan_vpn(&mut self, _: &String) -> io::Result<String> {
            Ok("127.0.0.3".into())
        }
        fn plan_restore(&mut self, _: &String, original: &String) -> io::Result<String> {
            Ok(original.clone())
        }
        fn apply(&mut self, expected: &String, planned: &String) -> io::Result<()> {
            assert_eq!(&self.current, expected);
            self.current = planned.clone();
            self.writes += 1;
            if std::mem::take(&mut self.fail_after_apply) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        }
    }
    #[derive(Default)]
    struct Protection {
        active: bool,
        fail_once: bool,
    }
    impl Guard for Protection {
        fn enable(&mut self) -> io::Result<()> {
            if std::mem::take(&mut self.fail_once) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.active = true;
            Ok(())
        }
        fn disable(&mut self) -> io::Result<()> {
            self.active = false;
            Ok(())
        }
    }
    fn scope() -> DnsScope {
        DnsScope {
            namespace: [1; 16],
            control_serial: 1,
            control_digest: [2; 32],
            profile: "p1".into(),
        }
    }

    #[test]
    fn original_transport_dns_is_saved_before_takeover_and_survives_retry() {
        let (mut store, mut os, mut guard) = (Store::default(), Os::new(), Protection::default());
        os.fail_after_apply = true;
        assert!(activate(&mut store, scope(), &mut os, &mut guard).is_err());
        assert_eq!(os.current, "127.0.0.3");
        let record: serde_json::Value =
            serde_json::from_slice(store.bytes.as_ref().unwrap()).unwrap();
        assert_eq!(
            record["bootstrap_servers"],
            serde_json::json!(["9.9.9.9:53"])
        );
        assert_eq!(
            transport_servers(&store, [1; 16], &mut os).unwrap(),
            ["9.9.9.9:53".parse().unwrap()]
        );
        assert!(transport_servers(&store, [3; 16], &mut os).is_err());
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(store.bytes.as_ref().unwrap()).unwrap();
        assert_eq!(
            record["bootstrap_servers"],
            serde_json::json!(["9.9.9.9:53"])
        );
    }

    #[test]
    fn old_active_journal_does_not_fall_back_to_the_vpn_stub() {
        let (mut store, mut os, mut guard) = (Store::default(), Os::new(), Protection::default());
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        let mut record: serde_json::Value =
            serde_json::from_slice(store.bytes.as_ref().unwrap()).unwrap();
        record.as_object_mut().unwrap().remove("bootstrap_servers");
        store.bytes = Some(serde_json::to_vec(&record).unwrap());
        assert!(transport_servers(&store, [1; 16], &mut os).is_err());
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.current, "9.9.9.9");
    }

    #[test]
    fn invalid_transport_dns_is_rejected_before_any_os_change() {
        for endpoint in [
            "127.0.0.3:53",
            "0.0.0.0:53",
            "[::]:53",
            "[ff02::1]:53",
            "255.255.255.255:53",
            "9.9.9.9:0",
        ] {
            assert!(
                validate_bootstrap_servers(&[endpoint.parse().unwrap()]).is_err(),
                "{endpoint}"
            );
        }
        assert!(validate_bootstrap_servers(&vec!["9.9.9.9:53".parse().unwrap(); 33]).is_err());
        let (mut store, mut os, mut guard) = (Store::default(), Os::new(), Protection::default());
        os.current = "127.0.0.3".into();
        assert!(activate(&mut store, scope(), &mut os, &mut guard).is_err());
        assert_eq!(os.writes, 0);
        assert!(store.bytes.is_none());
        assert!(!guard.active);
    }

    #[test]
    fn link_local_transport_dns_keeps_the_original_interface_scope() {
        assert_eq!(
            bootstrap_server("fe80::53", Some(7)).unwrap(),
            "[fe80::53%7]:53".parse().unwrap()
        );
        assert_eq!(
            bootstrap_server("fe80::53%7", None).unwrap(),
            "[fe80::53%7]:53".parse().unwrap()
        );
        assert!(bootstrap_server("fe80::53", None).is_err());
        assert!(bootstrap_server("[fe80::53%8]:53", Some(7)).is_err());
        assert!(bootstrap_server("::ffff:127.0.0.3", None).is_err());
        assert_eq!(
            bootstrap_server("2001:db8::53", None).unwrap(),
            "[2001:db8::53]:53".parse().unwrap()
        );
    }

    #[test]
    fn uncertain_apply_recovers_without_second_os_write_and_preserves_original() {
        let (mut store, mut os, mut guard) = (Store::default(), Os::new(), Protection::default());
        os.fail_after_apply = true;
        assert!(activate(&mut store, scope(), &mut os, &mut guard).is_err());
        assert!(guard.active);
        assert_eq!(os.current, "127.0.0.3");
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        assert_eq!(os.writes, 1);
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.current, "9.9.9.9");
        assert!(!guard.active);
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.writes, 2);
    }
    #[test]
    fn foreign_dns_is_not_overwritten_or_unprotected() {
        let (mut store, mut os, mut guard) = (Store::default(), Os::new(), Protection::default());
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        os.current = "8.8.8.8".into();
        assert!(restore(&mut store, [1; 16], &mut os, &mut guard).is_err());
        assert_eq!(os.current, "8.8.8.8");
        assert_eq!(os.writes, 1);
        assert!(guard.active);
    }
    #[test]
    fn interrupted_restore_before_first_os_write_can_be_recovered() {
        let (mut store, mut os, mut guard) = (Store::default(), Os::new(), Protection::default());
        guard.fail_once = true;
        assert!(activate(&mut store, scope(), &mut os, &mut guard).is_err());
        assert_eq!(os.current, "9.9.9.9");
        store.fail = 2;
        assert!(restore(&mut store, [1; 16], &mut os, &mut guard).is_err());
        store.fail = 0;
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.current, "9.9.9.9");
        assert!(!guard.active);
    }
    #[test]
    fn interrupted_second_adapter_continues_without_overwriting_first_or_original() {
        struct TwoAdapters {
            current: [u32; 2],
            writes: usize,
            interrupt: bool,
        }
        impl Provider for TwoAdapters {
            type Snapshot = [u32; 2];
            fn snapshot(&mut self) -> io::Result<Self::Snapshot> {
                Ok(self.current)
            }
            fn plan_vpn(&mut self, _: &Self::Snapshot) -> io::Result<Self::Snapshot> {
                Ok([127, 127])
            }
            fn plan_restore(
                &mut self,
                _: &Self::Snapshot,
                original: &Self::Snapshot,
            ) -> io::Result<Self::Snapshot> {
                Ok(*original)
            }
            fn can_complete(
                &self,
                current: &Self::Snapshot,
                before: &Self::Snapshot,
                after: &Self::Snapshot,
            ) -> bool {
                current
                    .iter()
                    .zip(before)
                    .zip(after)
                    .all(|((c, b), a)| c == b || c == a)
            }
            fn apply(
                &mut self,
                expected: &Self::Snapshot,
                planned: &Self::Snapshot,
            ) -> io::Result<()> {
                assert_eq!(&self.current, expected);
                for (actual, value) in self.current.iter_mut().zip(planned) {
                    if actual == value {
                        continue;
                    }
                    *actual = *value;
                    self.writes += 1;
                    if std::mem::take(&mut self.interrupt) {
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                }
                Ok(())
            }
        }
        let mut os = TwoAdapters {
            current: [9, 8],
            writes: 0,
            interrupt: true,
        };
        let (mut store, mut guard) = (Store::default(), Protection::default());
        assert!(activate(&mut store, scope(), &mut os, &mut guard).is_err());
        assert_eq!(os.current, [127, 8]);
        assert!(guard.active);
        activate(&mut store, scope(), &mut os, &mut guard).unwrap();
        assert_eq!(os.current, [127, 127]);
        assert_eq!(os.writes, 2);
        restore(&mut store, [1; 16], &mut os, &mut guard).unwrap();
        assert_eq!(os.current, [9, 8]);
        assert_eq!(os.writes, 4);
        assert!(!guard.active);
    }
}
