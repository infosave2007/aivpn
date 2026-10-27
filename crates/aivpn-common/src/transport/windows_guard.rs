//! Привязка служебных сокетов и DNS к исходным интерфейсам Windows.
use super::{guarded_dns, FirewallPeerHandler, SocketGuard};
use crate::error::Result;
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::ERROR_BUFFER_OVERFLOW, NetworkManagement::IpHelper::*, Networking::WinSock::*,
};

#[derive(Default)]
pub struct InterfaceGuard {
    firewall: Mutex<(Option<FirewallPeerHandler>, HashSet<SocketAddr>)>,
}

fn physical_interface(family: u16) -> io::Result<u32> {
    let mut table = ptr::null_mut();
    // Память таблицы выделяет IP Helper. Освобождаем ее после копирования индекса.
    let status = unsafe { GetIpForwardTable2(family, &mut table) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if table.is_null() {
        return Err(io::Error::other("пустая таблица маршрутов"));
    }
    let selected = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        rows.iter()
            .filter(|row| row.DestinationPrefix.PrefixLength == 0 && row.ValidLifetime != 0)
            .filter_map(|row| {
                let mut interface = MIB_IPINTERFACE_ROW::default();
                InitializeIpInterfaceEntry(&mut interface);
                interface.Family = family;
                interface.InterfaceIndex = row.InterfaceIndex;
                (GetIpInterfaceEntry(&mut interface) == 0 && interface.Connected).then_some((
                    u64::from(row.Metric) + u64::from(interface.Metric),
                    row.InterfaceIndex,
                ))
            })
            .min()
            .map(|(_, index)| index)
    };
    unsafe {
        FreeMibTable(table.cast());
    }
    selected
        .ok_or_else(|| io::Error::new(io::ErrorKind::NetworkUnreachable, "нет исходного маршрута"))
}

fn physical_resolvers() -> io::Result<Vec<SocketAddr>> {
    let interfaces = [
        physical_interface(AF_INET).ok(),
        physical_interface(AF_INET6).ok(),
    ];
    let mut length = 15_000u32;
    for _ in 0..3 {
        // u64 обеспечивает выравнивание структур, которые возвращает Windows.
        let mut storage = vec![0u64; (length as usize).div_ceil(8)];
        let first = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                ptr::null(),
                first,
                &mut length,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            if length > 4 * 1024 * 1024 {
                return Err(io::Error::other("слишком большой список адаптеров"));
            }
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut servers = Vec::new();
        let mut current = first;
        // Связанные структуры и адреса принадлежат storage до выхода из функции.
        unsafe {
            while let Some(adapter) = current.as_ref() {
                let index4 = adapter.Anonymous1.Anonymous.IfIndex;
                if interfaces
                    .iter()
                    .flatten()
                    .any(|index| *index == index4 || *index == adapter.Ipv6IfIndex)
                {
                    let mut dns = adapter.FirstDnsServerAddress;
                    while let Some(server) = dns.as_ref() {
                        let address = server.Address.lpSockaddr;
                        if !address.is_null() {
                            let ip = match (*address).sa_family {
                                AF_INET
                                    if server.Address.iSockaddrLength as usize
                                        >= size_of::<SOCKADDR_IN>() =>
                                {
                                    let v4 = &*address.cast::<SOCKADDR_IN>();
                                    Some(IpAddr::V4(Ipv4Addr::from(
                                        v4.sin_addr.S_un.S_addr.to_ne_bytes(),
                                    )))
                                }
                                AF_INET6
                                    if server.Address.iSockaddrLength as usize
                                        >= size_of::<SOCKADDR_IN6>() =>
                                {
                                    let v6 = &*address.cast::<SOCKADDR_IN6>();
                                    let mut endpoint = std::net::SocketAddrV6::new(
                                        Ipv6Addr::from(v6.sin6_addr.u.Byte),
                                        53,
                                        0,
                                        v6.Anonymous.sin6_scope_id,
                                    );
                                    if endpoint.ip().is_unicast_link_local()
                                        && endpoint.scope_id() == 0
                                    {
                                        endpoint.set_scope_id(adapter.Ipv6IfIndex);
                                    }
                                    servers.push(SocketAddr::V6(endpoint));
                                    None
                                }
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                servers.push(SocketAddr::new(ip, 53));
                            }
                        }
                        dns = server.Next;
                    }
                }
                current = adapter.Next;
            }
        }
        servers.sort();
        servers.dedup();
        servers.truncate(3);
        return Ok(servers);
    }
    Err(io::Error::other(
        "список адаптеров изменился во время чтения",
    ))
}

impl SocketGuard for InterfaceGuard {
    fn allow_peer(&self, peer: SocketAddr) -> Result<()> {
        let mut state = self
            .firewall
            .lock()
            .map_err(|_| io::Error::other("состояние WFP недоступно"))?;
        if state.1.contains(&peer) {
            return Ok(());
        }
        if state.1.len() >= 8192 {
            return Err(io::Error::other("лимит служебных адресов WFP").into());
        }
        if let Some(handler) = &state.0 {
            handler(peer)?;
        }
        state.1.insert(peer);
        Ok(())
    }

    fn set_firewall_peer_handler(&self, handler: Option<FirewallPeerHandler>) -> Result<()> {
        let mut state = self
            .firewall
            .lock()
            .map_err(|_| io::Error::other("состояние WFP недоступно"))?;
        if let Some(handler) = &handler {
            for peer in &state.1 {
                handler(*peer)?;
            }
        }
        state.0 = handler;
        Ok(())
    }

    fn protect(&self, socket: std::os::windows::io::RawSocket) -> Result<()> {
        let mut protocol = WSAPROTOCOL_INFOW::default();
        let mut length = size_of::<WSAPROTOCOL_INFOW>() as i32;
        let socket = socket as SOCKET;
        if unsafe {
            getsockopt(
                socket,
                SOL_SOCKET,
                SO_PROTOCOL_INFOW,
                ptr::from_mut(&mut protocol).cast(),
                &mut length,
            )
        } == SOCKET_ERROR
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }).into());
        }
        let family = protocol.iAddressFamily as u16;
        let index = physical_interface(family)?;
        let (level, option, value) = match family {
            AF_INET => (IPPROTO_IP, IP_UNICAST_IF, index.to_be()),
            AF_INET6 => (IPPROTO_IPV6, IPV6_UNICAST_IF, index),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "неизвестное семейство сокета",
                )
                .into())
            }
        };
        if unsafe {
            setsockopt(
                socket,
                level,
                option,
                ptr::from_ref(&value).cast(),
                size_of::<u32>() as i32,
            )
        } == SOCKET_ERROR
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }).into());
        }
        Ok(())
    }

    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> super::ResolveFuture<'a> {
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
}
