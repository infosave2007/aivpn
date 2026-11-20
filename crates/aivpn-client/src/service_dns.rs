//! Привязывает общий DNS обмен к сокетам, проверенным текущим Control.

use crate::dns_proxy::exchange::{DnsSocketRoute, RoutedSocket};
use aivpn_desktop_agent::dns::{DnsRoutePort, DnsSocket, DnsSocketLease};
#[cfg(target_os = "linux")]
use aivpn_desktop_agent::linux::{LinuxCoordinator as DnsCoordinator, WorkerProgress};
#[cfg(target_os = "windows")]
use aivpn_desktop_agent::windows::{WindowsCoordinator as DnsCoordinator, WorkerProgress};
use std::{io, net::SocketAddr};
use tokio::{
    net::{TcpSocket, UdpSocket},
    sync::oneshot,
};

pub struct ServiceDnsRoute(DnsRoutePort);
impl ServiceDnsRoute {
    pub fn new(port: DnsRoutePort) -> Self {
        Self(port)
    }
    async fn register(&self, socket: DnsSocket, peer: SocketAddr) -> io::Result<DnsSocketLease> {
        if peer != self.0.peer() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let (sender, receiver) = oneshot::channel();
        self.0.register(socket, move |result| {
            let _ = sender.send(result);
        })?;
        receiver.await.map_err(|_| io::ErrorKind::BrokenPipe)?
    }
}
impl DnsSocketRoute for ServiceDnsRoute {
    type Lease = DnsSocketLease;
    async fn udp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<UdpSocket, Self::Lease>> {
        let socket = UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        #[cfg(unix)]
        let descriptor = {
            use std::os::fd::AsFd;
            socket.as_fd().try_clone_to_owned()?
        };
        #[cfg(windows)]
        let descriptor = {
            use std::os::windows::io::AsSocket;
            socket.as_socket().try_clone_to_owned()?
        };
        let lease = self.register(descriptor, peer).await?;
        Ok(RoutedSocket { socket, lease })
    }
    async fn tcp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<TcpSocket, Self::Lease>> {
        let socket = if peer.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        #[cfg(unix)]
        let descriptor = {
            use std::os::fd::AsFd;
            socket.as_fd().try_clone_to_owned()?
        };
        #[cfg(windows)]
        let descriptor = {
            use std::os::windows::io::AsSocket;
            socket.as_socket().try_clone_to_owned()?
        };
        let lease = self.register(descriptor, peer).await?;
        Ok(RoutedSocket { socket, lease })
    }
}

/// DNS службы использует существующий relay и единственный writer координатора.
pub struct DesktopDnsRelay {
    runtime: tokio::runtime::Runtime,
    handle: Option<crate::dns_proxy::relay::DnsRelayHandle>,
    gate: crate::dns_proxy::relay::DnsRelayGate<ServiceDnsRoute>,
    listeners: Vec<DnsSocketLease>,
    upstream: SocketAddr,
    target: Option<([u8; 16], u64)>,
    #[cfg(target_os = "linux")]
    system_epoch: Option<u64>,
}
#[cfg(target_os = "linux")]
pub type LinuxDnsRelay = DesktopDnsRelay;
#[cfg(target_os = "windows")]
pub type WindowsDnsRelay = DesktopDnsRelay;
impl DesktopDnsRelay {
    pub fn bind(upstream: SocketAddr) -> io::Result<Self> {
        Self::bind_listeners(upstream, true)
    }
    #[cfg(target_os = "linux")]
    pub fn bind_for_system(
        upstream: SocketAddr,
        coordinator: &mut DnsCoordinator,
    ) -> io::Result<Self> {
        Self::bind_listeners(upstream, coordinator.dns_relay_uses_ipv6()?)
    }
    fn bind_listeners(upstream: SocketAddr, ipv6: bool) -> io::Result<Self> {
        let mut addresses = vec!["127.0.0.3:53".parse().unwrap()];
        if ipv6 {
            match std::net::UdpSocket::bind("[::1]:0") {
                Ok(_) => addresses.push("[::1]:53".parse().unwrap()),
                Err(error) if ipv6_unavailable(&error) => (),
                Err(error) => return Err(error),
            }
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let gate = crate::dns_proxy::relay::DnsRelayGate::default();
        let handle =
            runtime.block_on(crate::dns_proxy::relay::bind(&addresses, upstream, &gate))?;
        Ok(Self {
            runtime,
            handle: Some(handle),
            gate,
            listeners: Vec::new(),
            upstream,
            target: None,
            #[cfg(target_os = "linux")]
            system_epoch: None,
        })
    }
    pub fn progress(
        &mut self,
        coordinator: &mut DnsCoordinator,
        _event: &WorkerProgress,
    ) -> io::Result<()> {
        let handle = self.handle.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        if handle.is_finished() {
            self.gate.close();
            return match self.runtime.block_on(handle.wait()) {
                Ok(()) => Err(io::ErrorKind::BrokenPipe.into()),
                Err(error) => Err(error),
            };
        }
        let target = coordinator.dns_session_identity(self.upstream)?;
        #[cfg(target_os = "linux")]
        if target.is_some() {
            let epoch = match coordinator.system_dns_epoch() {
                Ok(epoch) => epoch,
                Err(error) => {
                    self.gate.close();
                    self.target = None;
                    return Err(error);
                }
            };
            if epoch != self.system_epoch {
                self.gate.close();
                self.target = None;
                self.listeners.clear();
                self.system_epoch = epoch;
            }
            if epoch.is_none() {
                return Ok(());
            }
        }
        if target != self.target {
            self.gate.close();
            self.target = None;
            if target.is_some() {
                if self.listeners.is_empty() {
                    self.listeners = coordinator.protect_system_dns(handle.duplicate_sockets()?)?;
                }
                self.gate
                    .publish(ServiceDnsRoute::new(coordinator.dns_route(self.upstream)?));
                self.target = target;
            }
        }
        Ok(())
    }
    pub fn close(&mut self) {
        self.gate.close();
        self.target = None;
    }
}
impl Drop for DesktopDnsRelay {
    fn drop(&mut self) {
        self.gate.close();
        if let Some(handle) = self.handle.take() {
            let _ = self.runtime.block_on(handle.shutdown());
        }
        self.listeners.clear();
    }
}

fn ipv6_unavailable(error: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    return matches!(
        error.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
    );
    #[cfg(target_os = "windows")]
    return matches!(
        error.raw_os_error(),
        Some(
            windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT
                | windows_sys::Win32::Networking::WinSock::WSAEADDRNOTAVAIL
        )
    );
}
