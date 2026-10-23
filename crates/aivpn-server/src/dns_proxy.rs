//! DNS over HTTPS (DoH) proxy for VPN clients.
//!
//! Listens on UDP port 53 of the VPN gateway IP, forwards queries to a
//! configured DoH upstream via HTTPS POST (RFC 8484 `application/dns-message`),
//! and returns the response to the client.  Replies are forwarded as-is —
//! the upstream resolver handles caching and DNSSEC validation.
//!
//! When `block_plain_dns` is enabled an nftables rule is added that drops
//! plain-UDP/TCP DNS traffic leaving the server on non-VPN interfaces,
//! preventing DNS leaks from VPN clients that bypass the proxy.
//!
//! # server.json
//! ```json
//! {
//!   "dns": {
//!     "upstream_doh": "https://1.1.1.1/dns-query",
//!     "fallback_doh":  "https://8.8.8.8/dns-query",
//!     "block_plain_dns": true
//!   }
//! }
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const DNS_PORT: u16 = 53;
const MAX_DNS_PACKET: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Max DNS queries per second per VPN client IP before the request is dropped.
const MAX_DNS_RPS: u32 = 100;
/// Max DoH response body size — legitimate DNS responses are ≤65535 bytes.
const MAX_DOH_RESPONSE: usize = 65535;

/// DNS proxy configuration (`"dns"` block in `server.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProxyConfig {
    /// Primary DoH upstream URL (RFC 8484).
    pub upstream_doh: String,
    /// Fallback DoH upstream tried when the primary times out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_doh: Option<String>,
    /// Add nftables rule blocking plain UDP 53 on non-VPN interfaces.
    #[serde(default)]
    pub block_plain_dns: bool,
}

/// Spawn the DNS proxy.  Runs until the socket bind fails.
pub async fn run(config: DnsProxyConfig, bind_ip: IpAddr, _tun_iface: String) {
    let bind_addr = SocketAddr::new(bind_ip, DNS_PORT);

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => {
            info!(
                "DNS proxy listening on {} → DoH {}",
                bind_addr, config.upstream_doh
            );
            Arc::new(s)
        }
        Err(e) => {
            warn!(
                "DNS proxy: bind {} failed: {} — proxy disabled",
                bind_addr, e
            );
            return;
        }
    };

    let http = match reqwest::Client::builder()
        .timeout(UPSTREAM_TIMEOUT)
        .https_only(true)
        .build()
    {
        Ok(c) => Arc::new(c),
        Err(e) => {
            warn!(
                "DNS proxy: HTTP client build failed: {} — proxy disabled",
                e
            );
            return;
        }
    };

    let cfg = Arc::new(config);
    let rate_limits: Arc<DashMap<IpAddr, (u32, Instant)>> = Arc::new(DashMap::new());
    let mut buf = vec![0u8; MAX_DNS_PACKET];

    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("DNS proxy: recv error: {}", e);
                continue;
            }
        };

        // Per-source-IP rate limit: cap at MAX_DNS_RPS queries/second.
        let from_ip = peer.ip();
        {
            let mut entry = rate_limits.entry(from_ip).or_insert((0u32, Instant::now()));
            let (count, since) = entry.value_mut();
            if since.elapsed().as_secs() >= 1 {
                *count = 0;
                *since = Instant::now();
            }
            if *count >= MAX_DNS_RPS {
                debug!("DNS proxy: rate limit exceeded for {}", from_ip);
                continue;
            }
            *count += 1;
        }

        let query = buf[..len].to_vec();
        let sock = socket.clone();
        let http = http.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            match forward(&http, &cfg, &query).await {
                Ok(resp) => {
                    if let Err(e) = sock.send_to(&resp, peer).await {
                        debug!("DNS proxy: send to {} failed: {}", peer, e);
                    }
                }
                Err(e) => debug!("DNS proxy: forward failed for {}: {}", peer, e),
            }
        });
    }
}

async fn forward(
    client: &reqwest::Client,
    cfg: &DnsProxyConfig,
    query: &[u8],
) -> Result<Vec<u8>, String> {
    let result = doh_post(client, &cfg.upstream_doh, query).await;
    if result.is_err() {
        if let Some(ref fb) = cfg.fallback_doh {
            return doh_post(client, fb, query).await;
        }
    }
    result
}

async fn doh_post(client: &reqwest::Client, url: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let mut resp = tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        client
            .post(url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query.to_vec())
            .send(),
    )
    .await
    .map_err(|_| format!("DoH timeout: {}", url))?
    .map_err(|e| format!("DoH request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("DoH HTTP {}", resp.status()));
    }

    if resp
        .content_length()
        .is_some_and(|len| len > MAX_DOH_RESPONSE as u64)
    {
        return Err("DoH response too large".into());
    }
    // Проверяем лимит при чтении, включая ответы без Content-Length.
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("DoH body: {}", e))? {
        if chunk.len() > MAX_DOH_RESPONSE - body.len() {
            return Err("DoH response too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn block_rule_script(tun_iface: &str) -> aivpn_common::error::Result<String> {
    crate::nat::NatForwarder::validate_tun_name(tun_iface)?;
    Ok(format!(
        "add table inet aivpn_dns\n\
         add chain inet aivpn_dns forward {{ type filter hook forward priority -10; policy accept; }}\n\
         flush chain inet aivpn_dns forward\n\
         add rule inet aivpn_dns forward iifname \"{tun_iface}\" udp dport 53 drop\n\
         add rule inet aivpn_dns forward iifname \"{tun_iface}\" tcp dport 53 drop\n"
    ))
}

/// Отдельная таблица блокирует только пересылаемые DNS-запросы VPN-клиентов.
pub fn install_block_rule(tun_iface: &str) -> aivpn_common::error::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let script = block_rule_script(tun_iface)?;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let write_result = child.stdin.take().unwrap().write_all(script.as_bytes());
    let result = child.wait_with_output()?;
    write_result?;
    if !result.status.success() {
        return Err(std::io::Error::other(format!(
            "DNS firewall setup failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn dns_rules_are_scoped_and_cover_udp_and_tcp() {
        let script = block_rule_script("tun0").unwrap();
        assert!(script.contains("add table inet aivpn_dns"));
        assert!(script.contains("iifname \"tun0\" udp dport 53 drop"));
        assert!(script.contains("iifname \"tun0\" tcp dport 53 drop"));
        assert!(block_rule_script("tun0;add").is_err());
    }

    #[tokio::test]
    async fn oversized_doh_body_is_rejected_before_upstream_finishes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            for _ in 0..17 {
                if socket.write_all(b"1000\r\n").await.is_err() {
                    return;
                }
                if socket.write_all(&[0; 4096]).await.is_err() {
                    return;
                }
                if socket.write_all(b"\r\n").await.is_err() {
                    return;
                }
            }
            std::future::pending::<()>().await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            doh_post(
                &reqwest::Client::new(),
                &format!("http://{addr}/dns-query"),
                &[0; 12],
            ),
        )
        .await;
        upstream.abort();
        assert!(result
            .expect("Чтение должно остановиться на лимите размера")
            .unwrap_err()
            .contains("too large"));
    }
}
