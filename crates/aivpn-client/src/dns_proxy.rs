//! DNS-прокси использует общий обмен и путь текущего VPN-сеанса.

use std::{io, net::SocketAddr};
use tokio::net::{TcpSocket, UdpSocket};
use tracing::warn;

pub use aivpn_common::dns_exchange as exchange;
pub mod relay;
use exchange::{DnsSocketRoute, RoutedSocket};

#[derive(Clone, Default)]
pub struct DnsProxyGate(relay::DnsRelayGate<TunnelRoute>);
impl std::fmt::Debug for DnsProxyGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnsProxyGate")
            .finish_non_exhaustive()
    }
}
impl DnsProxyGate {
    pub fn set_tunnel(&self, name: &str) {
        self.0.publish(TunnelRoute(name.into()));
    }
    pub fn session(&self) -> DnsProxySession {
        self.0.close();
        DnsProxySession(self.clone())
    }
}
pub struct DnsProxySession(DnsProxyGate);
impl Drop for DnsProxySession {
    fn drop(&mut self) {
        self.0 .0.close();
    }
}

#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    pub listen_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
}
impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:5300".parse().unwrap(),
            upstream_addr: "1.1.1.1:53".parse().unwrap(),
        }
    }
}
pub struct DnsProxyHandle(tokio::task::JoinHandle<()>);
impl Drop for DnsProxyHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Сохраняет прежний API запуска; новый desktop-путь проверяет bind до настройки ОС.
pub fn spawn_dns_proxy(cfg: DnsProxyConfig, gate: DnsProxyGate) -> DnsProxyHandle {
    DnsProxyHandle(tokio::spawn(async move {
        let result = async {
            let mut proxy = bind_proxy(cfg, &gate).await?;
            drop(gate);
            proxy.wait().await
        }
        .await;
        if let Err(error) = result {
            warn!("DNS proxy stopped: {}", error);
        }
    }))
}
async fn bind_proxy(cfg: DnsProxyConfig, gate: &DnsProxyGate) -> io::Result<relay::DnsRelayHandle> {
    relay::bind_configured(&[cfg.listen_addr], cfg.upstream_addr, &gate.0, false).await
}

struct TunnelRoute(String);
impl DnsSocketRoute for TunnelRoute {
    type Lease = ();
    async fn udp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<UdpSocket, ()>> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(peer),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        bind_tunnel(&socket, &self.0, peer.is_ipv4())?;
        socket.set_nonblocking(true)?;
        let local: SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap();
        socket.bind(&local.into())?;
        Ok(RoutedSocket {
            socket: UdpSocket::from_std(socket.into())?,
            lease: (),
        })
    }
    async fn tcp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<TcpSocket, ()>> {
        let socket = if peer.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        bind_tunnel(&socket2::SockRef::from(&socket), &self.0, peer.is_ipv4())?;
        Ok(RoutedSocket { socket, lease: () })
    }
}

fn bind_tunnel(socket: &socket2::Socket, tunnel: &str, _ipv4: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(tunnel.as_bytes()))
    }
    #[cfg(target_os = "macos")]
    {
        let name = std::ffi::CString::new(tunnel).map_err(io::Error::other)?;
        let index = std::num::NonZeroU32::new(unsafe { libc::if_nametoindex(name.as_ptr()) })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Нет интерфейса DNS"))?;
        if _ipv4 {
            socket.bind_device_by_index_v4(Some(index))
        } else {
            socket.bind_device_by_index_v6(Some(index))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (socket, tunnel);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DNS proxy requires interface binding",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn query(id: u16) -> Vec<u8> {
        let mut wire = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire[..2].copy_from_slice(&id.to_be_bytes());
        wire.extend_from_slice(b"\x04test\x07invalid\0\0\x01\0\x01");
        wire
    }
    async fn proxy(gate: &DnsProxyGate, upstream: SocketAddr) -> relay::DnsRelayHandle {
        bind_proxy(
            DnsProxyConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                upstream_addr: upstream,
            },
            gate,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn dropping_proxy_handle_releases_listener() {
        let gate = DnsProxyGate::default();
        let mut bound = proxy(&gate, "127.0.0.1:9".parse().unwrap()).await;
        let address = bound.addresses()[0];
        let handle = DnsProxyHandle(tokio::spawn(async move {
            let _ = bound.wait().await;
        }));
        tokio::task::yield_now().await;
        assert!(!handle.0.is_finished());
        drop(handle);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(udp) = UdpSocket::bind(address).await {
                    if let Ok(tcp) = TcpListener::bind(address).await {
                        drop((udp, tcp));
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dns_does_not_forward_before_tunnel_ready() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gate = DnsProxyGate::default();
        let handle = proxy(&gate, upstream.local_addr().unwrap()).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&query(1), handle.addresses()[0])
            .await
            .unwrap();
        let mut bytes = [0; 128];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut bytes))
                .await
                .is_err()
        );
        handle.shutdown().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dns_disconnect_cancels_queries_and_blocks_backoff() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gate = DnsProxyGate::default();
        let session = gate.session();
        gate.set_tunnel("lo");
        let handle = proxy(&gate, upstream.local_addr().unwrap()).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = handle.addresses()[0];
        client.send_to(&query(1), address).await.unwrap();
        let mut bytes = [0; 128];
        let (size, peer) =
            tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        drop(session);
        bytes[2] |= 0x80;
        upstream.send_to(&bytes[..size], peer).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv(&mut bytes))
                .await
                .is_err()
        );
        client.send_to(&query(2), address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut bytes))
                .await
                .is_err()
        );
        handle.shutdown().await.unwrap();
    }
}
