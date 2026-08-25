//! Client-side server pool — failover and load-balancing across pool nodes.
//!
//! The connection key carries an optional `"pool"` JSON array alongside `"s"`.
//! Old clients ignore the unknown field; new clients use it for failover.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{info, warn};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolMode {
    #[default]
    Failover,
    RoundRobin,
    Weighted,
    LatencyBased,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerEntry {
    /// Accept both "endpoint" (canonical) and "addr" (legacy connection-key format).
    #[serde(alias = "addr")]
    pub endpoint: String,
    #[serde(default)]
    pub priority: u8,
    #[serde(default = "default_weight")]
    pub weight: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

fn default_weight() -> u8 {
    1
}

struct NodeState {
    addr: SocketAddr,
    weight: u8,
    failures: u32,
    last_failure: Option<Instant>,
    rtt_ms: Option<f64>,
}

impl NodeState {
    fn is_healthy(&self) -> bool {
        if self.failures >= 3 {
            return self
                .last_failure
                .map(|t| t.elapsed() > Duration::from_secs(30))
                .unwrap_or(true);
        }
        true
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
    }

    fn record_success(&mut self) {
        self.failures = 0;
        self.last_failure = None;
    }
}

pub struct ServerPool {
    nodes: Mutex<Vec<NodeState>>,
    mode: PoolMode,
    rr_idx: AtomicUsize,
}

impl ServerPool {
    pub fn new(primary: &str, peers: Vec<ServerEntry>, mode: PoolMode) -> Arc<Self> {
        let mut entries = vec![ServerEntry {
            endpoint: primary.to_string(),
            priority: 0,
            weight: 1,
            region: None,
        }];
        entries.extend(peers);
        entries.sort_by_key(|e| e.priority);

        let nodes = entries
            .into_iter()
            .filter_map(|e| {
                e.endpoint.parse::<SocketAddr>().ok().map(|addr| NodeState {
                    addr,
                    weight: e.weight,
                    failures: 0,
                    last_failure: None,
                    rtt_ms: None,
                })
            })
            .collect();

        Arc::new(Self {
            nodes: Mutex::new(nodes),
            mode,
            rr_idx: AtomicUsize::new(0),
        })
    }

    /// Async variant of [`ServerPool::new`] that additionally resolves
    /// hostname endpoints (e.g. "node2.example.com:443") via the system
    /// resolver. `new`'s `parse::<SocketAddr>()` filter silently drops every
    /// non-"IP:port" entry — a pool of hostnames ends up with zero nodes and
    /// failover quietly dead, even though the main connect path supports
    /// hostnames (client/mod.rs uses lookup_host). Unresolvable entries are
    /// skipped with a warning; if nothing resolves at all the pool is empty
    /// and callers fall back to the primary server address, exactly as with
    /// an empty pool before.
    pub async fn resolve_and_new(
        primary: &str,
        peers: Vec<ServerEntry>,
        mode: PoolMode,
    ) -> Arc<Self> {
        let mut entries = vec![ServerEntry {
            endpoint: primary.to_string(),
            priority: 0,
            weight: 1,
            region: None,
        }];
        entries.extend(peers);
        entries.sort_by_key(|e| e.priority);

        let mut nodes = Vec::with_capacity(entries.len());
        for e in entries {
            let addr = match e.endpoint.parse::<SocketAddr>() {
                Ok(addr) => Some(addr),
                Err(_) => {
                    // Mirror the 10 s cap the main connect path puts on DNS
                    // (client/mod.rs) so a hung resolver can't stall startup.
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        tokio::net::lookup_host(&e.endpoint),
                    )
                    .await
                    {
                        Ok(Ok(mut addrs)) => addrs.next(),
                        Ok(Err(err)) => {
                            warn!("Pool: failed to resolve {}: {}", e.endpoint, err);
                            None
                        }
                        Err(_) => {
                            warn!("Pool: DNS lookup timed out for {}", e.endpoint);
                            None
                        }
                    }
                }
            };
            match addr {
                Some(addr) => nodes.push(NodeState {
                    addr,
                    weight: e.weight,
                    failures: 0,
                    last_failure: None,
                    rtt_ms: None,
                }),
                None => warn!(
                    "Pool: skipping {} — not an IP:port endpoint and DNS resolution failed",
                    e.endpoint
                ),
            }
        }

        Arc::new(Self {
            nodes: Mutex::new(nodes),
            mode,
            rr_idx: AtomicUsize::new(0),
        })
    }

    pub fn next_server(&self) -> Option<SocketAddr> {
        let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        if nodes.is_empty() {
            return None;
        }
        match self.mode {
            PoolMode::Failover => nodes
                .iter()
                .find(|n| n.is_healthy())
                .map(|n| n.addr)
                .or_else(|| nodes.first().map(|n| n.addr)),
            PoolMode::RoundRobin => {
                let healthy: Vec<_> = nodes.iter().filter(|n| n.is_healthy()).collect();
                if healthy.is_empty() {
                    return nodes.first().map(|n| n.addr);
                }
                let idx = self.rr_idx.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Some(healthy[idx].addr)
            }
            PoolMode::Weighted => {
                let healthy: Vec<_> = nodes.iter().filter(|n| n.is_healthy()).collect();
                if healthy.is_empty() {
                    return nodes.first().map(|n| n.addr);
                }
                let total: u32 = healthy.iter().map(|n| n.weight as u32).sum::<u32>().max(1);
                let mut bucket = (self.rr_idx.fetch_add(1, Ordering::Relaxed) as u32) % total;
                for n in &healthy {
                    if bucket < n.weight as u32 {
                        return Some(n.addr);
                    }
                    bucket -= n.weight as u32;
                }
                healthy.first().map(|n| n.addr)
            }
            PoolMode::LatencyBased => nodes
                .iter()
                .filter(|n| n.is_healthy())
                .min_by(|a, b| {
                    a.rtt_ms
                        .unwrap_or(f64::MAX)
                        .partial_cmp(&b.rtt_ms.unwrap_or(f64::MAX))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|n| n.addr)
                .or_else(|| nodes.first().map(|n| n.addr)),
        }
    }

    pub fn report_failure(&self, addr: SocketAddr) {
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = nodes.iter_mut().find(|n| n.addr == addr) {
            n.record_failure();
            warn!("Pool: {} failing ({} strikes)", addr, n.failures);
        }
    }

    pub fn report_success(&self, addr: SocketAddr) {
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = nodes.iter_mut().find(|n| n.addr == addr) {
            n.record_success();
        }
    }

    pub fn update_rtt(&self, addr: SocketAddr, rtt_ms: f64) {
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = nodes.iter_mut().find(|n| n.addr == addr) {
            n.rtt_ms = Some(rtt_ms);
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn all_servers(&self) -> Vec<SocketAddr> {
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|n| n.addr)
            .collect()
    }
}

/// Probe latency to a server address via a timed UDP send.
pub async fn probe_latency(addr: SocketAddr) -> Option<f64> {
    use tokio::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let start = Instant::now();
    sock.send_to(b"aivpn-probe", addr).await.ok()?;
    let mut buf = [0u8; 64];
    tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(start.elapsed().as_secs_f64() * 1000.0)
}

/// Probe all pool nodes and update their RTTs.
pub async fn probe_all(pool: Arc<ServerPool>) {
    for addr in pool.all_servers() {
        if let Some(rtt) = probe_latency(addr).await {
            pool.update_rtt(addr, rtt);
            info!("Pool probe {}: {:.1} ms", addr, rtt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(endpoint: &str) -> ServerEntry {
        ServerEntry {
            endpoint: endpoint.to_string(),
            priority: 1,
            weight: 1,
            region: None,
        }
    }

    #[test]
    fn new_drops_hostname_endpoints() {
        // Documents the sync constructor's limitation that resolve_and_new
        // exists to fix: hostname endpoints don't survive parse::<SocketAddr>.
        let pool = ServerPool::new(
            "127.0.0.1:443",
            vec![entry("node2.example.com:443")],
            PoolMode::Failover,
        );
        assert_eq!(pool.node_count(), 1);
    }

    #[tokio::test]
    async fn resolve_and_new_keeps_hostname_endpoints() {
        // Regression test: a pool built from hostname endpoints must not end
        // up empty (failover silently dead).
        let pool = ServerPool::resolve_and_new(
            "localhost:443",
            vec![entry("localhost:444"), entry("127.0.0.1:445")],
            PoolMode::Failover,
        )
        .await;
        assert_eq!(pool.node_count(), 3);
        let ports: Vec<u16> = pool.all_servers().iter().map(|a| a.port()).collect();
        assert!(ports.contains(&443));
        assert!(ports.contains(&444));
        assert!(ports.contains(&445));
        // Failover must actually be able to hand out a node.
        assert!(pool.next_server().is_some());
    }

    #[tokio::test]
    async fn resolve_and_new_skips_unresolvable_endpoints() {
        let pool = ServerPool::resolve_and_new(
            "127.0.0.1:443",
            vec![entry("nonexistent-host.invalid:443")],
            PoolMode::Failover,
        )
        .await;
        // Only the resolvable primary survives; the pool degrades instead of
        // failing startup.
        assert_eq!(pool.node_count(), 1);
        assert_eq!(pool.next_server().unwrap().port(), 443);
    }
}
