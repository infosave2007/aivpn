//! Per-client QoS — userspace token bucket rate limiting and DSCP marking.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

/// QoS settings for a single client (persisted in clients.json).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ClientQos {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_limit_up: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_limit_down: Option<u64>,
    /// DSCP value 0–63 applied to outgoing TUN packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dscp_class: Option<u8>,
    /// Priority hint: 0 = default, 1 = high, 2 = low.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
}

struct TokenBucket {
    capacity: u64,
    tokens: f64,
    rate_bps: u64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate_bps: u64) -> Self {
        let capacity = (rate_bps as f64 * 0.1).max(1500.0) as u64;
        Self {
            capacity,
            tokens: capacity as f64,
            rate_bps,
            last: Instant::now(),
        }
    }

    fn try_consume(&mut self, bytes: u64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate_bps as f64).min(self.capacity as f64);
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

struct ClientBuckets {
    up: Option<TokenBucket>,
    down: Option<TokenBucket>,
    dscp: Option<u8>,
}

/// Thread-safe QoS enforcer, shared across gateway tasks.
#[derive(Clone)]
pub struct QosEnforcer {
    buckets: Arc<DashMap<String, parking_lot::Mutex<ClientBuckets>>>,
}

impl QosEnforcer {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
        }
    }

    pub fn set_client(&self, client_id: &str, qos: &ClientQos) {
        // A limit of 0 means UNLIMITED (same convention as the eBPF path —
        // see `tc_loader::TcQosRule`), not "block everything": a TokenBucket
        // with refill rate 0 would let ~1500 bytes through and then drop
        // every packet forever.
        let entry = ClientBuckets {
            up: qos
                .bandwidth_limit_up
                .filter(|&r| r > 0)
                .map(TokenBucket::new),
            down: qos
                .bandwidth_limit_down
                .filter(|&r| r > 0)
                .map(TokenBucket::new),
            dscp: qos.dscp_class,
        };
        self.buckets
            .insert(client_id.to_string(), parking_lot::Mutex::new(entry));
    }

    pub fn remove_client(&self, client_id: &str) {
        self.buckets.remove(client_id);
    }

    /// Re-sync the enforcer with the persisted client DB: applies each live
    /// client's current QoS settings and drops entries for clients that were
    /// removed or whose QoS was cleared. Called from the clients.json
    /// hot-reload path so QoS edits (CLI `--set-client-qos`, REST, manual
    /// edits) take effect without a server restart.
    pub fn sync_from_db(&self, db: &crate::client_db::ClientDatabase) {
        let clients = db.list_clients();
        let mut live: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(clients.len());
        for client in &clients {
            live.insert(client.id.as_str());
            match client.qos {
                Some(ref qos) => self.set_client(&client.id, qos),
                None => self.remove_client(&client.id),
            }
        }
        self.buckets.retain(|id, _| live.contains(id.as_str()));
    }

    /// Returns `true` if the packet should be forwarded (upstream: client→server).
    pub fn check_upstream(&self, client_id: &str, bytes: u64) -> bool {
        if let Some(entry) = self.buckets.get(client_id) {
            let mut b = entry.lock();
            if let Some(ref mut bucket) = b.up {
                return bucket.try_consume(bytes);
            }
        }
        true
    }

    /// Returns `true` if the packet should be forwarded (downstream: server→client).
    pub fn check_downstream(&self, client_id: &str, bytes: u64) -> bool {
        if let Some(entry) = self.buckets.get(client_id) {
            let mut b = entry.lock();
            if let Some(ref mut bucket) = b.down {
                return bucket.try_consume(bytes);
            }
        }
        true
    }

    pub fn get_dscp(&self, client_id: &str) -> Option<u8> {
        self.buckets.get(client_id).and_then(|e| e.lock().dscp)
    }
}

impl Default for QosEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply DSCP to an IPv4 packet payload (modifies TOS byte in-place).
pub fn apply_dscp_ipv4(pkt: &mut [u8], dscp: u8) -> bool {
    if pkt.len() < 20 {
        return false;
    }
    let dscp = dscp & 0x3F;
    let ecn = pkt[1] & 0x03;
    pkt[1] = (dscp << 2) | ecn;
    pkt[10] = 0;
    pkt[11] = 0;
    let sum = ipv4_checksum(&pkt[..20]);
    pkt[10] = (sum >> 8) as u8;
    pkt[11] = (sum & 0xff) as u8;
    true
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = (header[i] as u32) << 8 | header[i + 1] as u32;
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parse "10M", "500K", "2G" → bytes/sec.
pub fn parse_bandwidth(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mul) = if let Some(r) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        (r, 1_000_000_000u64)
    } else if let Some(r) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        (r, 1_000_000u64)
    } else if let Some(r) = s.strip_suffix('K').or_else(|| s.strip_suffix('k')) {
        (r, 1_000u64)
    } else {
        (s, 1u64)
    };
    num.parse::<f64>().ok().map(|n| (n * mul as f64) as u64)
}

/// DSCP class name → numeric value.
pub fn dscp_by_name(name: &str) -> Option<u8> {
    match name.to_uppercase().as_str() {
        "DEFAULT" | "BE" => Some(0),
        "AF11" => Some(10),
        "AF12" => Some(12),
        "AF13" => Some(14),
        "AF21" => Some(18),
        "AF22" => Some(20),
        "AF23" => Some(22),
        "AF31" => Some(26),
        "AF32" => Some(28),
        "AF33" => Some(30),
        "AF41" => Some(34),
        "AF42" => Some(36),
        "AF43" => Some(38),
        "EF" => Some(46),
        "CS1" => Some(8),
        "CS2" => Some(16),
        "CS3" => Some(24),
        "CS4" => Some(32),
        "CS5" => Some(40),
        "CS6" => Some(48),
        "CS7" => Some(56),
        _ => name.parse::<u8>().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_within_capacity() {
        let mut b = TokenBucket::new(1_000_000);
        assert!(b.try_consume(100));
    }

    /// Regression: a persisted limit of 0 means UNLIMITED (matching
    /// `tc_loader::TcQosRule`'s documented convention), not "drop everything
    /// after the first ~1500 bytes" — which is what a 0-refill TokenBucket
    /// used to do (`--set-client-qos alice --bw-up 0` bricked the client
    /// until restart).
    #[test]
    fn zero_bandwidth_limit_is_unlimited() {
        let enforcer = QosEnforcer::new();
        enforcer.set_client(
            "c1",
            &ClientQos {
                bandwidth_limit_up: Some(0),
                bandwidth_limit_down: Some(0),
                ..Default::default()
            },
        );
        // Far beyond the old 1500-byte dead-end capacity.
        for _ in 0..100 {
            assert!(enforcer.check_upstream("c1", 1500));
            assert!(enforcer.check_downstream("c1", 1500));
        }
    }

    #[test]
    fn sync_from_db_applies_and_removes_qos() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        let db = crate::client_db::ClientDatabase::load(
            &db_path,
            crate::client_db::test_support::test_network_config(),
        )
        .unwrap();
        let alice = db.add_client("alice").unwrap();
        let bob = db.add_client("bob").unwrap();
        db.set_client_qos(
            &alice.id,
            ClientQos {
                bandwidth_limit_up: Some(1_000_000),
                dscp_class: Some(46),
                ..Default::default()
            },
        )
        .unwrap();

        let enforcer = QosEnforcer::new();
        enforcer.sync_from_db(&db);
        assert_eq!(enforcer.get_dscp(&alice.id), Some(46));
        assert_eq!(enforcer.get_dscp(&bob.id), None);

        // QoS cleared + client removed must both propagate.
        db.update_client(
            &alice.id,
            crate::client_db::UpdateClientParams {
                qos: Some(None),
                ..Default::default()
            },
        )
        .unwrap();
        db.remove_client(&bob.id).unwrap();
        enforcer.sync_from_db(&db);
        assert_eq!(enforcer.get_dscp(&alice.id), None);
        assert!(enforcer.buckets.get(&bob.id).is_none());
    }

    #[test]
    fn parse_bandwidth_units() {
        assert_eq!(parse_bandwidth("10M"), Some(10_000_000));
        assert_eq!(parse_bandwidth("500K"), Some(500_000));
        assert_eq!(parse_bandwidth("1G"), Some(1_000_000_000));
    }

    #[test]
    fn dscp_by_name_known() {
        assert_eq!(dscp_by_name("EF"), Some(46));
        assert_eq!(dscp_by_name("AF11"), Some(10));
        assert_eq!(dscp_by_name("46"), Some(46));
    }

    #[test]
    fn apply_dscp_sets_tos() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        apply_dscp_ipv4(&mut pkt, 46);
        assert_eq!(pkt[1] >> 2, 46);
    }
}
