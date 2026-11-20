//! Исходные DNS читаются из действующих IP-конфигураций, не из подмененного global DNS.
use super::{Link, NetworkManager, Snapshot, DEVICE};
use std::{collections::HashMap, io, net::SocketAddr};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

pub(super) fn current_servers(
    provider: &mut NetworkManager,
    original: &Snapshot,
    current: &Snapshot,
) -> io::Result<Option<Vec<SocketAddr>>> {
    if !current.owns_global() {
        return Ok(None);
    }
    provider.start()?;
    let before = provider.snapshot_inner()?;
    if before != *current || before.links != current.links {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    if let Some(global) = &original.global {
        // Собственный статический global DNS имеет приоритет над DHCP и RA.
        return global.bootstrap_servers();
    }
    let servers = physical_servers(provider, &before.links)?;
    let checked = physical_servers(provider, &before.links)?;
    let after = provider.snapshot_inner()?;
    if after != before || after.links != before.links || checked != servers {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(Some(servers))
}

fn physical_servers(provider: &NetworkManager, links: &[Link]) -> io::Result<Vec<SocketAddr>> {
    let mut entries = Vec::new();
    for link in links {
        for ipv6 in [false, true] {
            if let Some(entry) = family_servers(provider, link, ipv6)? {
                entries.push(entry);
            }
        }
    }
    ordered_servers(entries)
}

fn family_servers(
    provider: &NetworkManager,
    link: &Link,
    ipv6: bool,
) -> io::Result<Option<(i32, Vec<SocketAddr>)>> {
    let (property, interface) = if ipv6 {
        ("Ip6Config", "org.freedesktop.NetworkManager.IP6Config")
    } else {
        ("Ip4Config", "org.freedesktop.NetworkManager.IP4Config")
    };
    let path: OwnedObjectPath = provider.property(&link.path, DEVICE, property)?;
    if path.as_str() == "/" {
        return Ok(None);
    }
    let priority: i32 = provider.property(path.as_str(), interface, "DnsPriority")?;
    let names = if ipv6 {
        let raw: Vec<Vec<u8>> = provider.property(path.as_str(), interface, "Nameservers")?;
        ipv6_names(raw)?
    } else {
        let raw: Vec<HashMap<String, OwnedValue>> =
            provider.property(path.as_str(), interface, "NameserverData")?;
        ipv4_names(raw)?
    };
    let servers = names
        .iter()
        .map(|name| crate::dns::journal::bootstrap_server(name, Some(link.ifindex)))
        .collect::<io::Result<Vec<_>>>()?;
    Ok((!servers.is_empty()).then_some((priority, servers)))
}

fn ipv4_names(raw: Vec<HashMap<String, OwnedValue>>) -> io::Result<Vec<String>> {
    if raw.len() > 32 {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    raw.into_iter()
        .map(|mut entry| {
            let address =
                String::try_from(entry.remove("address").ok_or(io::ErrorKind::InvalidData)?)
                    .map_err(|_| io::ErrorKind::InvalidData)?;
            Ok(address
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| io::ErrorKind::InvalidData)?
                .to_string())
        })
        .collect()
}

fn ipv6_names(raw: Vec<Vec<u8>>) -> io::Result<Vec<String>> {
    if raw.len() > 32 {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    raw.into_iter()
        .map(|bytes| {
            let address: [u8; 16] = bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?;
            Ok(std::net::Ipv6Addr::from(address).to_string())
        })
        .collect()
}

fn ordered_servers(mut entries: Vec<(i32, Vec<SocketAddr>)>) -> io::Result<Vec<SocketAddr>> {
    entries.sort_by_key(|entry| entry.0);
    let exclusive = entries
        .first()
        .and_then(|entry| (entry.0 < 0).then_some(entry.0));
    let mut servers = Vec::new();
    for (_, addresses) in entries
        .into_iter()
        .filter(|entry| exclusive.is_none_or(|priority| entry.0 == priority))
    {
        for server in addresses {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    crate::dns::journal::validate_bootstrap_servers(&servers)?;
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_dns_priority_excludes_other_networks_and_deduplicates_servers() {
        let chosen = "192.0.2.53:53".parse().unwrap();
        let ignored = "198.51.100.53:53".parse().unwrap();
        assert_eq!(
            ordered_servers(vec![
                (100, vec![ignored]),
                (-10, vec![ignored]),
                (-20, vec![chosen, chosen])
            ])
            .unwrap(),
            [chosen]
        );
        assert_eq!(
            ordered_servers(vec![(100, vec![ignored]), (50, vec![chosen])]).unwrap(),
            [chosen, ignored]
        );
    }

    #[test]
    fn malformed_ipv6_and_loopback_dns_are_rejected() {
        assert!(ipv6_names(vec![vec![0; 15]]).is_err());
        assert!(ipv6_names(vec![vec![0; 17]]).is_err());
        assert!(ordered_servers(vec![(1, vec!["127.0.0.3:53".parse().unwrap()])]).is_err());
    }
}
