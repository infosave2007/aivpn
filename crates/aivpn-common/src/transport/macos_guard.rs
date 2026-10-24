//! Служебные соединения macOS используют исходный интерфейс и его DNS.
use super::{guarded_dns, ResolveFuture, SocketGuard};
use crate::error::Result;
use std::{
    collections::HashSet,
    ffi::CString,
    io,
    net::{IpAddr, SocketAddr},
    process::Command,
    sync::Mutex,
};

#[derive(Default)]
pub struct InterfaceGuard {
    firewall: Mutex<(bool, HashSet<IpAddr>)>,
}

fn output(program: &str, arguments: &[&str]) -> io::Result<String> {
    let result = Command::new(program).args(arguments).output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "{program}: не удалось прочитать сетевые настройки"
        )));
    }
    String::from_utf8(result.stdout).map_err(io::Error::other)
}

fn default_interface(ipv6: bool) -> io::Result<(String, u32)> {
    let routes = output(
        "/usr/sbin/netstat",
        &["-rn", "-f", if ipv6 { "inet6" } else { "inet" }],
    )?;
    for line in routes.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() != Some(&"default") {
            continue;
        }
        // Колонка Netif может сдвигаться между версиями netstat.
        for name in words.iter().skip(3) {
            if name.starts_with("utun") || name.starts_with("tun") || *name == "lo0" {
                continue;
            }
            let Ok(name_c) = CString::new(*name) else {
                continue;
            };
            let index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
            if index != 0 {
                return Ok(((*name).to_owned(), index));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        "нет исходного маршрута macOS",
    ))
}

fn physical_resolvers() -> io::Result<Vec<SocketAddr>> {
    let indices: HashSet<_> = [default_interface(false).ok(), default_interface(true).ok()]
        .into_iter()
        .flatten()
        .map(|(_, index)| index)
        .collect();
    let configuration = output("/usr/sbin/scutil", &["--dns"])?;
    let mut servers = Vec::new();
    for resolver in configuration.split("resolver #").skip(1) {
        let index = resolver.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "if_index")
                .then(|| value.split_whitespace().next()?.parse::<u32>().ok())
                .flatten()
        });
        if !index.is_some_and(|index| indices.contains(&index)) {
            continue;
        }
        for line in resolver.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if !key.trim().starts_with("nameserver[") {
                continue;
            }
            let value = value.trim();
            let (host, scope) = value
                .split_once('%')
                .map_or((value, None), |(host, scope)| (host, Some(scope)));
            let Ok(ip) = host.parse::<IpAddr>() else {
                continue;
            };
            let mut address = SocketAddr::new(ip, 53);
            if let SocketAddr::V6(ref mut v6) = address {
                if v6.ip().is_unicast_link_local() {
                    let scope = scope
                        .and_then(|scope| scope.parse().ok())
                        .or(index)
                        .unwrap_or(0);
                    v6.set_scope_id(scope);
                }
            }
            servers.push(address);
        }
    }
    servers.sort();
    servers.dedup();
    servers.truncate(3);
    Ok(servers)
}

fn update_firewall(action: &str, peers: impl Iterator<Item = IpAddr>) -> io::Result<()> {
    let addresses: Vec<_> = peers.map(|peer| peer.to_string()).collect();
    if addresses.is_empty() && action == "add" {
        return Ok(());
    }
    let action = if addresses.is_empty() {
        "flush"
    } else {
        action
    };
    let result = Command::new("/sbin/pfctl")
        .args(["-a", "aivpn_ks", "-t", "aivpn_transport", "-T", action])
        .args(addresses)
        .output()?;
    if !result.status.success() {
        return Err(io::Error::other(
            "не удалось разрешить служебные адреса в PF",
        ));
    }
    Ok(())
}

impl SocketGuard for InterfaceGuard {
    fn protect(&self, fd: std::os::fd::RawFd) -> Result<()> {
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut size = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if unsafe { libc::getsockname(fd, std::ptr::from_mut(&mut address).cast(), &mut size) } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let (level, option, ipv6) = match address.ss_family as i32 {
            libc::AF_INET => (libc::IPPROTO_IP, libc::IP_BOUND_IF, false),
            libc::AF_INET6 => (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF, true),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "неизвестное семейство сокета",
                )
                .into())
            }
        };
        let (_, index) = default_interface(ipv6)?;
        if unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                std::ptr::from_ref(&index).cast(),
                size_of::<u32>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
                return Ok(vec![SocketAddr::new(ip, port)]);
            }
            let servers = if std::env::var_os("AIVPN_TRANSPORT_DNS").is_some() {
                guarded_dns::system_servers()
            } else {
                tokio::task::spawn_blocking(physical_resolvers)
                    .await
                    .map_err(io::Error::other)??
            };
            guarded_dns::resolve(self, &servers, host, port).await
        })
    }

    fn uses_firewall_table(&self) -> bool {
        true
    }

    fn allow_peer(&self, peer: SocketAddr) -> Result<()> {
        let mut state = self
            .firewall
            .lock()
            .map_err(|_| io::Error::other("состояние PF недоступно"))?;
        if state.1.contains(&peer.ip()) {
            return Ok(());
        }
        if state.1.len() >= 8192 {
            return Err(io::Error::other("лимит служебных адресов PF").into());
        }
        if state.0 {
            update_firewall("add", std::iter::once(peer.ip()))?;
        }
        state.1.insert(peer.ip());
        Ok(())
    }

    fn set_firewall(&self, active: bool) -> Result<()> {
        let mut state = self
            .firewall
            .lock()
            .map_err(|_| io::Error::other("состояние PF недоступно"))?;
        if active {
            update_firewall("replace", state.1.iter().copied())?;
        } else {
            state.1.clear();
        }
        state.0 = active;
        Ok(())
    }
}
