//! Разрешает фиксированное имя сервера через исходный DNS и точные права сокетов.

use super::{DnsSocket, DnsSocketLease};
use aivpn_common::dns_exchange::{DnsSocketRoute, RoutedSocket};
use std::{io, net::SocketAddr, time::Duration};
use tokio::net::{TcpSocket, UdpSocket};

struct Route<'a, F> {
    servers: &'a [SocketAddr],
    register: F,
}
impl<F> Route<'_, F>
where
    F: Fn(DnsSocket, SocketAddr) -> io::Result<DnsSocketLease> + Send + Sync,
{
    fn register(&self, socket: DnsSocket, peer: SocketAddr) -> io::Result<DnsSocketLease> {
        if !self.servers.contains(&peer) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        (self.register)(socket, peer)
    }
}

impl<F> DnsSocketRoute for Route<'_, F>
where
    F: Fn(DnsSocket, SocketAddr) -> io::Result<DnsSocketLease> + Send + Sync,
{
    type Lease = DnsSocketLease;

    async fn udp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<UdpSocket, Self::Lease>> {
        let socket = UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        #[cfg(unix)]
        let duplicate = {
            use std::os::fd::AsFd;
            socket.as_fd().try_clone_to_owned()?
        };
        #[cfg(windows)]
        let duplicate = {
            use std::os::windows::io::{AsRawSocket, BorrowedSocket};
            unsafe { BorrowedSocket::borrow_raw(socket.as_raw_socket()) }.try_clone_to_owned()?
        };
        let lease = self.register(duplicate, peer)?;
        Ok(RoutedSocket { socket, lease })
    }

    async fn tcp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<TcpSocket, Self::Lease>> {
        let socket = if peer.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        #[cfg(unix)]
        let duplicate = {
            use std::os::fd::AsFd;
            socket.as_fd().try_clone_to_owned()?
        };
        #[cfg(windows)]
        let duplicate = {
            use std::os::windows::io::{AsRawSocket, BorrowedSocket};
            unsafe { BorrowedSocket::borrow_raw(socket.as_raw_socket()) }.try_clone_to_owned()?
        };
        let lease = self.register(duplicate, peer)?;
        Ok(RoutedSocket { socket, lease })
    }
}

pub(crate) fn resolve<F>(
    servers: &[SocketAddr],
    host: &str,
    port: u16,
    timeout: Duration,
    register: F,
) -> io::Result<Vec<SocketAddr>>
where
    F: Fn(DnsSocket, SocketAddr) -> io::Result<DnsSocketLease> + Send + Sync,
{
    super::journal::validate_bootstrap_servers(servers)?;
    if servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Нет исходного DNS для имени сервера",
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let route = Route { servers, register };
    runtime.block_on(async {
        tokio::time::timeout(
            timeout,
            aivpn_common::transport::resolve_dns_with_route(&route, servers, host, port),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Истекло время разрешения имени сервера",
            )
        })?
        .map_err(io::Error::other)
    })
}
