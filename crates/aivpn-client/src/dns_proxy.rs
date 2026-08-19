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
use tokio::sync::Semaphore;
use tracing::{debug, warn};

const DNS_BUF: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Max concurrent in-flight upstream queries. Each one is a spawned task
/// plus a fresh upstream UDP socket, so an unbounded flood on the listener
/// would exhaust file descriptors. Excess datagrams are dropped — UDP DNS
/// clients retry on their own.
const MAX_IN_FLIGHT: usize = 256;

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

/// Spawn the DNS proxy as a background task. Returns a JoinHandle.
pub fn spawn_dns_proxy(cfg: DnsProxyConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_dns_proxy(cfg).await {
            warn!("DNS proxy stopped: {}", e);
        }
    })
}

async fn run_dns_proxy(cfg: DnsProxyConfig) -> std::io::Result<()> {
    let listener = Arc::new(UdpSocket::bind(cfg.listen_addr).await?);
    tracing::info!(
        "DNS proxy listening on {} → upstream {}",
        cfg.listen_addr,
        cfg.upstream_addr
    );

    let mut buf = vec![0u8; DNS_BUF];
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    loop {
        let (len, client_addr) = match listener.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("DNS proxy recv error: {}", e);
                continue;
            }
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
        tokio::spawn(async move {
            let _permit = permit;
            match forward_query(&query, upstream, client_addr, &sock).await {
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
    let up_sock = UdpSocket::bind(bind_addr).await?;
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
