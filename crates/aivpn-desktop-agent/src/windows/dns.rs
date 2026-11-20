//! Меняет только заданные DNS-серверы, сохраняя автоматический режим отдельно от DHCP.
mod native;

use crate::dns::journal::Provider;
use serde::{Deserialize, Serialize};
use std::io;

const MAX_LINKS: usize = 32;
const MAX_NAME_UNITS: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    guid: [u8; 16],
    luid: u64,
    index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    identity: Identity,
    // Пустая строка означает Automatic, а не текущий ответ DHCP/RA.
    servers: [String; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    compartment: u32,
    links: Vec<Link>,
}

impl Snapshot {
    fn validate(&self) -> io::Result<()> {
        if self.compartment == 0 || self.links.is_empty() || self.links.len() > MAX_LINKS {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for (i, link) in self.links.iter().enumerate() {
            if link.identity.luid == 0
                || link.identity.index == 0
                || link.identity.guid == [0; 16]
                || link
                    .servers
                    .iter()
                    .any(|s| s.contains('\0') || s.encode_utf16().count() >= MAX_NAME_UNITS)
                || self.links[..i].iter().any(|old| {
                    old.identity.guid == link.identity.guid
                        || old.identity.luid == link.identity.luid
                        || old.identity.index == link.identity.index
                })
                || i > 0 && self.links[i - 1].identity >= link.identity
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        Ok(())
    }
}

pub(crate) struct InterfaceDns;

pub(super) struct KernelGuard<'a> {
    pub driver: &'a super::driver::DriverSession,
    pub compartment: u32,
}
impl crate::dns::journal::Guard for KernelGuard<'_> {
    fn enable(&mut self) -> io::Result<()> {
        self.driver.dns_guard(self.compartment, true)
    }
    fn disable(&mut self) -> io::Result<()> {
        self.driver.dns_guard(self.compartment, false)
    }
}

impl Provider for InterfaceDns {
    type Snapshot = Snapshot;

    fn bootstrap_servers(&mut self, before: &Snapshot) -> io::Result<Vec<std::net::SocketAddr>> {
        before.validate()?;
        if native::snapshot()? != *before {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let servers = native::bootstrap_servers(before)?;
        if native::snapshot()? != *before {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        crate::dns::journal::validate_bootstrap_servers(&servers)?;
        Ok(servers)
    }

    fn snapshot(&mut self) -> io::Result<Snapshot> {
        let snapshot = native::snapshot()?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn plan_vpn(&mut self, before: &Snapshot) -> io::Result<Snapshot> {
        before.validate()?;
        let mut after = before.clone();
        for link in &mut after.links {
            link.servers = ["127.0.0.3".into(), "::1".into()];
        }
        Ok(after)
    }

    fn plan_restore(&mut self, current: &Snapshot, original: &Snapshot) -> io::Result<Snapshot> {
        if !same_links(current, original) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(original.clone())
    }

    fn can_complete(&self, current: &Snapshot, before: &Snapshot, after: &Snapshot) -> bool {
        same_links(current, before)
            && same_links(before, after)
            && current
                .links
                .iter()
                .zip(&before.links)
                .zip(&after.links)
                .all(|((current, before), after)| {
                    (0..2).all(|family| {
                        current.servers[family] == before.servers[family]
                            || current.servers[family] == after.servers[family]
                    })
                })
    }

    fn apply(&mut self, expected: &Snapshot, planned: &Snapshot) -> io::Result<()> {
        if !same_links(expected, planned) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut progress = expected.clone();
        for i in 0..planned.links.len() {
            for family in 0..2 {
                if progress.links[i].servers[family] == planned.links[i].servers[family] {
                    continue;
                }
                // Другой адаптер или чужая правка не превращаются в новый baseline.
                if self.snapshot()? != progress {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                native::set(
                    &planned.links[i].identity,
                    family == 1,
                    &planned.links[i].servers[family],
                )?;
                progress.links[i].servers[family] = planned.links[i].servers[family].clone();
                if self.snapshot()? != progress {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
            }
        }
        if self.snapshot()? != *planned {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(())
    }
}

fn same_links(a: &Snapshot, b: &Snapshot) -> bool {
    a.validate().is_ok()
        && b.validate().is_ok()
        && a.compartment == b.compartment
        && a.links.len() == b.links.len()
        && a.links
            .iter()
            .zip(&b.links)
            .all(|(a, b)| a.identity == b.identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn before() -> Snapshot {
        Snapshot {
            compartment: 1,
            links: vec![Link {
                identity: Identity {
                    guid: [1; 16],
                    luid: 10,
                    index: 4,
                },
                servers: [String::new(), "2001:db8::53".into()],
            }],
        }
    }

    #[test]
    fn interrupted_ipv4_apply_keeps_original_automatic_and_ipv6() {
        let mut provider = InterfaceDns;
        let original = before();
        let desired = provider.plan_vpn(&original).unwrap();
        let mut interrupted = original.clone();
        interrupted.links[0].servers[0] = desired.links[0].servers[0].clone();
        assert!(provider.can_complete(&interrupted, &original, &desired));
        let target = provider.plan_restore(&interrupted, &original).unwrap();
        assert_eq!(target.links[0].servers, ["", "2001:db8::53"]);
        assert!(provider.can_complete(&interrupted, &original, &desired));
    }

    #[test]
    fn foreign_family_or_reused_adapter_is_never_recovered_as_ours() {
        let mut provider = InterfaceDns;
        let original = before();
        let desired = provider.plan_vpn(&original).unwrap();
        let mut foreign = desired.clone();
        foreign.links[0].servers[1] = "2001:db8::54".into();
        assert!(!provider.can_complete(&foreign, &original, &desired));
        foreign = desired.clone();
        foreign.links[0].identity.guid = [2; 16];
        assert!(!provider.can_complete(&foreign, &original, &desired));
        assert!(provider.plan_restore(&foreign, &original).is_err());
    }
}
