//! Lightweight DNS proxy (0.9.0)
//!
//! Listens on a local UDP port, forwards queries to an upstream resolver
//! through the active VPN tunnel, and returns the response to the caller.
//! This prevents DNS leaks on platforms that don't support per-app DNS
//! configuration (e.g., desktop Linux without systemd-resolved).
//!
//! Usage: `--dns-proxy 127.0.0.1:5300 --dns-upstream 1.1.1.1:53`
//!
//! Point /etc/resolv.conf at 127.0.0.1:5300 (or use a stub resolver) and all
//! DNS traffic will flow through the VPN-protected path.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, warn};

const DNS_BUF: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Max concurrent in-flight upstream queries. Each one is a spawned task
/// plus a fresh upstream UDP socket, so an unbounded flood on the listener
/// would exhaust file descriptors. Excess datagrams are dropped — UDP DNS
/// clients retry on their own.
const MAX_IN_FLIGHT: usize = 256;

#[derive(Clone, Debug)]
pub struct DnsProxyGate(watch::Sender<Option<String>>);

impl Default for DnsProxyGate {
    fn default() -> Self {
        Self(watch::channel(None).0)
    }
}

impl DnsProxyGate {
    pub fn set_tunnel(&self, name: &str) {
        self.0.send_replace(Some(name.to_owned()));
    }

    pub fn session(&self) -> DnsProxySession {
        self.0.send_replace(None);
        DnsProxySession(self.clone())
    }
}

pub struct DnsProxySession(DnsProxyGate);

impl Drop for DnsProxySession {
    fn drop(&mut self) {
        self.0 .0.send_replace(None);
    }
}

/// Configuration for the embedded DNS proxy.
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    /// Address to bind the local listener (e.g., "127.0.0.1:5300").
    pub listen_addr: SocketAddr,
    /// Upstream DNS resolver reachable via the VPN (e.g., "1.1.1.1:53").
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

/// Слушатель и запросы завершаются вместе с владельцем прокси.
pub fn spawn_dns_proxy(cfg: DnsProxyConfig, gate: DnsProxyGate) -> DnsProxyHandle {
    DnsProxyHandle(tokio::spawn(async move {
        if let Err(e) = run_dns_proxy(cfg, gate.0.subscribe()).await {
            warn!("DNS proxy stopped: {}", e);
        }
    }))
}

async fn run_dns_proxy(
    cfg: DnsProxyConfig,
    ready: watch::Receiver<Option<String>>,
) -> std::io::Result<()> {
    let listener = Arc::new(UdpSocket::bind(cfg.listen_addr).await?);
    run_dns_proxy_on(cfg, listener, ready).await
}

async fn run_dns_proxy_on(
    cfg: DnsProxyConfig,
    listener: Arc<UdpSocket>,
    mut ready: watch::Receiver<Option<String>>,
) -> std::io::Result<()> {
    tracing::info!(
        "DNS proxy listening on {} → upstream {}",
        cfg.listen_addr,
        cfg.upstream_addr
    );

    let mut buf = vec![0u8; DNS_BUF];
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut queries = tokio::task::JoinSet::new();
    loop {
        let packet = tokio::select! {
            biased;
            changed = ready.changed() => {
                queries.abort_all();
                if changed.is_err() { return Ok(()); }
                continue;
            }
            _ = queries.join_next(), if !queries.is_empty() => continue,
            packet = listener.recv_from(&mut buf) => packet,
        };
        let (len, client_addr) = match packet {
            Ok(v) => v,
            Err(e) => {
                warn!("DNS proxy recv error: {}", e);
                continue;
            }
        };
        let Some(tunnel) = ready.borrow().clone() else {
            continue;
        };
        // Bound concurrent upstream queries (task + fresh socket each);
        // drop the datagram when saturated instead of leaking fd's.
        let permit = match in_flight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!(
                    "DNS proxy: dropping query from {} — {} queries in flight",
                    client_addr, MAX_IN_FLIGHT
                );
                continue;
            }
        };
        let query = buf[..len].to_vec();
        let upstream = cfg.upstream_addr;
        let sock = listener.clone();
        let mut query_ready = ready.clone();
        queries.spawn(async move {
            let _permit = permit;
            let result = tokio::select! {
                biased;
                _ = query_ready.changed() => return,
                result = forward_query(&query, upstream, client_addr, &sock, &tunnel) => result,
            };
            match result {
                Ok(()) => {}
                Err(e) => debug!("DNS forward error for {}: {}", client_addr, e),
            }
        });
    }
}

async fn forward_query(
    query: &[u8],
    upstream: SocketAddr,
    client: SocketAddr,
    out: &UdpSocket,
    tunnel: &str,
) -> std::io::Result<()> {
    if query.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS query too short",
        ));
    }
    let query_txid = [query[0], query[1]];

    let bind_addr = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(upstream),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    bind_tunnel(&socket, tunnel, upstream.is_ipv4())?;
    socket.set_nonblocking(true)?;
    socket.bind(&bind_addr.parse::<SocketAddr>().unwrap().into())?;
    let up_sock = UdpSocket::from_std(socket.into())?;
    // connect() locks the kernel to only accept datagrams from the upstream 4-tuple,
    // preventing off-path response injection (DNS cache poisoning).
    up_sock.connect(upstream).await?;
    up_sock.send(query).await?;

    let mut resp = vec![0u8; DNS_BUF];
    let n = tokio::time::timeout(UPSTREAM_TIMEOUT, up_sock.recv(&mut resp))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS upstream timeout"))??;

    // Verify TXID matches to guard against any residual race on the ephemeral port.
    if n < 2 || resp[0] != query_txid[0] || resp[1] != query_txid[1] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS TXID mismatch",
        ));
    }

    out.send_to(&resp[..n], client).await?;
    Ok(())
}

fn bind_tunnel(socket: &socket2::Socket, tunnel: &str, _ipv4: bool) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(tunnel.as_bytes()))
    }
    #[cfg(target_os = "macos")]
    {
        let name = std::ffi::CString::new(tunnel).map_err(std::io::Error::other)?;
        let index = std::num::NonZeroU32::new(unsafe { libc::if_nametoindex(name.as_ptr()) })
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "DNS tunnel interface missing")
            })?;
        if _ipv4 {
            socket.bind_device_by_index_v4(Some(index))
        } else {
            socket.bind_device_by_index_v6(Some(index))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (socket, tunnel);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DNS proxy requires interface binding",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_proxy_handle_releases_listener() {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = reservation.local_addr().unwrap();
        drop(reservation);
        let handle = spawn_dns_proxy(
            DnsProxyConfig {
                listen_addr: local,
                upstream_addr: local,
            },
            DnsProxyGate::default(),
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                assert!(
                    !handle.0.is_finished(),
                    "DNS listener stopped before binding"
                );
                if UdpSocket::bind(local).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let completion = handle.0.abort_handle();
        drop(handle);
        // abort планирует отмену; сокет освобождается при завершении самой задачи.
        tokio::time::timeout(Duration::from_secs(2), async {
            while !completion.is_finished() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(UdpSocket::bind(local).await.is_ok());
    }

    #[tokio::test]
    async fn dns_does_not_forward_before_tunnel_ready() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = listener.local_addr().unwrap();
        let cfg = DnsProxyConfig {
            listen_addr: local,
            upstream_addr: upstream.local_addr().unwrap(),
        };
        let gate = DnsProxyGate::default();
        let handle = tokio::spawn(run_dns_proxy_on(cfg, listener, gate.0.subscribe()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[1, 2], local).await.unwrap();
        let mut buf = [0; 32];
        let received =
            tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut buf)).await;
        handle.abort();
        assert!(
            received.is_err(),
            "DNS escaped before a verified tunnel existed"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dns_disconnect_cancels_queries_and_blocks_backoff() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = listener.local_addr().unwrap();
        let cfg = DnsProxyConfig {
            listen_addr: local,
            upstream_addr: upstream.local_addr().unwrap(),
        };
        let gate = DnsProxyGate::default();
        let lease = gate.session();
        gate.set_tunnel("lo");
        let handle = tokio::spawn(run_dns_proxy_on(cfg, listener, gate.0.subscribe()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[1, 2], local).await.unwrap();
        let mut buf = [0; 32];
        let (_, peer) = tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        drop(lease);
        upstream.send_to(&[1, 2], peer).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf))
                .await
                .is_err()
        );
        client.send_to(&[3, 4], local).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut buf))
                .await
                .is_err()
        );
        handle.abort();
    }
}
