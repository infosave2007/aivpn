//! VPN-IP allocation and pool-wide hard partitioning.
//!
//! Every pool node is confined to a disjoint, contiguous slice of the
//! subnet's host offsets when allocating NEW client VPN IPs (see
//! [`ClientDatabase::set_node_partition`] for the full Wave B-IP
//! rationale), so independent adds on different pool nodes can never
//! collide. `merge_from_json`'s deterministic re-home path (in `merge.rs`)
//! remains the correctness backstop for residual/legacy IP collisions.

use std::net::Ipv4Addr;

use tracing::error;

use aivpn_common::error::{Error, Result};

use super::*;

/// Hard-bounded range of host offsets `[start_offset, end_offset)` (end
/// exclusive) this node is confined to when allocating NEW VPN IPs — see
/// `set_node_partition` / `set_node_partition_explicit`. Existing clients'
/// IPs are never affected by partition bounds, only new allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PartitionBounds {
    pub(crate) start_offset: u32,
    /// Exclusive.
    pub(crate) end_offset: u32,
    /// This node's partition index out of `num_partitions` — see
    /// `set_node_partition`/`set_node_partition_explicit`.
    pub(crate) index: u32,
    /// Total number of partitions the subnet is currently divided into.
    pub(crate) num_partitions: u32,
    /// True iff `index` was pinned via `set_node_partition_explicit`
    /// (`pool.node_ip_partition`) rather than derived from `hash(node_id)`.
    pub(crate) explicit: bool,
}

/// This node's active VPN-IP partition assignment, as exposed by
/// `ClientDatabase::partition_info` — Wave B-IP.2: lets a pool peer
/// announce its partition state (`ControlPayload::PartitionAnnounce`) for
/// operator overlap/mismatch visibility. Mirrors `PartitionBounds` but is
/// `pub` and reports `partition_size` (offsets owned) instead of raw
/// start/end offsets, which are meaningless outside this node's own subnet
/// indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionInfo {
    pub partition_index: u32,
    pub partition_size: u32,
    pub num_partitions: u32,
    pub explicit: bool,
}

impl ClientDatabase {
    /// Log an error for any duplicate VPN IPs found in the client list.
    /// Does not modify the list — the caller decides how to handle duplicates.
    pub(crate) fn warn_duplicate_vpn_ips(clients: &[ClientConfig]) {
        let mut seen: std::collections::HashMap<Ipv4Addr, &str> = std::collections::HashMap::new();
        for client in clients {
            // Tombstones don't hold their IP (it may have been legitimately
            // reassigned by allocate_vpn_ip) and never get a session.
            if client.deleted {
                continue;
            }
            if let Some(first_name) = seen.get(&client.vpn_ip) {
                error!(
                    "Duplicate VPN IP {} assigned to clients '{}' and '{}'. \
                     The second connecting client will evict the first session. \
                     Fix clients.json to resolve this conflict.",
                    client.vpn_ip, first_name, client.name
                );
            } else {
                seen.insert(client.vpn_ip, &client.name);
            }
        }
    }

    /// Allocate the next free VPN IP. When this node has a hard partition
    /// set (`set_node_partition` / `set_node_partition_explicit`), candidates
    /// are confined to `[start_offset, end_offset)` of that partition — an
    /// independent add on a DIFFERENT node's partition can never collide
    /// with one made here, which is the whole point of Wave B-IP (see the
    /// module-level `set_node_partition` doc for the full rationale). With
    /// no partition set (single-node / legacy deployments) this allocates
    /// across the whole subnet exactly as before.
    ///
    /// Existing clients keep whatever IP they were originally given
    /// regardless of partition bounds — partitioning governs only NEW
    /// allocations. The pool-wide `already_used` check (which ignores
    /// tombstones — see the comment below) still scans the *entire* client
    /// list, not just the partition, so an IP synced in from any other node
    /// is never handed out twice.
    pub(crate) fn allocate_vpn_ip(&self, data: &mut ClientDbFile) -> Result<Ipv4Addr> {
        let max_host_offset = self.network_config.max_host_offset();
        if max_host_offset < 1 {
            return Err(Error::Session(
                "Configured VPN subnet has no usable host addresses".into(),
            ));
        }

        let partition = *self.partition.read();
        let (range_start, range_end) = match partition {
            Some(p) => (p.start_offset, p.end_offset),
            None => (1, max_host_offset + 1),
        };
        if range_start >= range_end {
            // Degenerate/misconfigured partition (shouldn't happen —
            // `compute_partition_bounds` always produces start < end when
            // called with num_partitions >= 1 and max_host_offset >= 2 —
            // but fail closed rather than looping forever or spilling out
            // of bounds).
            return Err(Error::Session(
                "node IP partition exhausted; increase subnet size or partition capacity".into(),
            ));
        }
        let range_len = range_end - range_start;

        let mut candidate_offset = if data.next_host_offset == 0
            || !(range_start..range_end).contains(&data.next_host_offset)
        {
            range_start
        } else {
            data.next_host_offset
        };

        for _ in 0..range_len {
            if let Some(candidate_ip) = self.network_config.ip_for_host_offset(candidate_offset) {
                // Tombstoned (revoked) clients don't hold their VPN IP:
                // counting them would permanently leak one address per
                // lifetime revocation and eventually exhaust the subnet with
                // zero active clients. All data-plane lookups
                // (find_by_vpn_ip / find_by_psk) already ignore tombstones,
                // and merge_from_json's IP-conflict check does too, so
                // reusing the address is safe.
                let already_used = data
                    .clients
                    .iter()
                    .any(|client| client.vpn_ip == candidate_ip && !client.deleted);
                if candidate_ip != self.network_config.server_vpn_ip && !already_used {
                    data.next_host_offset = if candidate_offset + 1 >= range_end {
                        range_start
                    } else {
                        candidate_offset + 1
                    };
                    return Ok(candidate_ip);
                }
            }

            candidate_offset = if candidate_offset + 1 >= range_end {
                range_start
            } else {
                candidate_offset + 1
            };
        }

        if partition.is_some() {
            // Deliberately does NOT fall back to the whole subnet — spilling
            // into another node's partition would reintroduce exactly the
            // collision this feature exists to prevent. The operator must
            // grow the subnet or rebalance partition capacity instead.
            Err(Error::Session(format!(
                "node IP partition exhausted (offsets {}..{} of subnet); increase subnet size or partition capacity",
                range_start,
                range_end - 1
            )))
        } else {
            Err(Error::Session(
                "No more VPN IPs available in configured subnet".into(),
            ))
        }
    }

    /// Target number of pool nodes the default partition sizing aims to
    /// support. Chosen as a sensible default for this project's typical
    /// pool sizes (a handful of nodes, not hundreds) — see `default_num_partitions`.
    const TARGET_NUM_PARTITIONS: u32 = 8;
    /// Floor on `partition_size` (offsets per node) — below this,
    /// partitioning stops being useful (a node could exhaust its slice after
    /// a handful of clients), so small subnets shrink `num_partitions`
    /// instead of shrinking below this floor.
    const MIN_PARTITION_SIZE: u32 = 8;
    /// Ceiling on `partition_size` — keeps a single node from hogging an
    /// oversized chunk of a very large subnet, leaving room for more nodes
    /// to join the pool later without reconfiguring existing ones.
    const MAX_PARTITION_SIZE: u32 = 254;

    /// Compute this deployment's default number of partitions from the
    /// configured subnet size. Aims for `TARGET_NUM_PARTITIONS` (8) nodes,
    /// each capped at `MAX_PARTITION_SIZE` (254) clients — e.g. on a /16
    /// (`max_host_offset` ~65534) this yields partition_size=254 and
    /// ~258 possible partitions (room for far more than 8 nodes, each
    /// capped at 254 clients, matching a "big subnet -> generous per-node
    /// cap" target). On the project's default /24 (`max_host_offset` =
    /// 254) it yields partition_size=31 and 8 partitions (8 nodes x ~31
    /// clients each). On a subnet too small to give every one of the 8
    /// target partitions at least `MIN_PARTITION_SIZE` (8) offsets, this
    /// shrinks below 8 partitions (down to 1 = "no partitioning") rather
    /// than handing out partitions too small to be useful.
    fn default_num_partitions(&self) -> u32 {
        let max_host_offset = self.network_config.max_host_offset();
        if max_host_offset < 2 {
            return 1;
        }
        let partition_size = (max_host_offset / Self::TARGET_NUM_PARTITIONS)
            .clamp(Self::MIN_PARTITION_SIZE, Self::MAX_PARTITION_SIZE);
        (max_host_offset / partition_size).max(1)
    }

    /// 2b/Wave B-IP: pool-wide VPN-IP coordination via HARD per-node
    /// partitioning. Every pool node is confined to a disjoint, contiguous
    /// slice of the subnet's host offsets (see `compute_partition_bounds`);
    /// `allocate_vpn_ip` only ever hands out offsets from THIS node's slice.
    /// Two admins independently adding a client on two different pool
    /// nodes — the common case this exists to fix: e.g. provisioning two
    /// nodes' web panels around the same time, before any pool_sync round
    /// has run — therefore CANNOT collide anymore (previously, both nodes'
    /// allocators counted from the same/overlapping range and handed out
    /// the identical vpn_ip). This also eliminates the connection-key churn
    /// the old best-effort start-offset nudge could still cause: a client's
    /// vpn_ip (embedded in its issued connection key) is never silently
    /// reassigned by a later pool_sync round just because its node's
    /// counter walked into another node's territory.
    ///
    /// The partition index is `hash(node_id) % num_partitions` — a stable,
    /// deterministic, non-cryptographic hash (`fnv1a_hash`) of the operator-
    /// assigned `pool.node_id`, so unrelated nodes are very likely (but,
    /// with enough nodes, not provably) spread across disjoint partitions.
    /// Operators who want to rule out even a hash collision (or who are
    /// running more nodes than fit `default_num_partitions`) can instead
    /// pin an explicit index via `set_node_partition_explicit` (wired from
    /// `pool.node_ip_partition` in server config).
    ///
    /// `merge_from_json`'s deterministic re-home path (`ip_conflict` branch)
    /// remains the correctness backstop for the two residual/legacy cases
    /// this hard partition does not by itself prevent: (a) a genuine hash
    /// collision between two nodes' `node_id`s, or an explicit-override
    /// misconfiguration onto the same index, and (b) clients that predate
    /// partitioning (allocated back when every node shared the whole
    /// subnet). It never fires for the common case of two nodes in
    /// DIFFERENT partitions.
    ///
    /// Idempotent and safe to call once at startup, unconditionally, whether
    /// or not pool sync is configured (a `None` `node_id` is simply skipped
    /// by the caller) — a database with `max_host_offset < 2` or a
    /// `default_num_partitions() <= 1` (subnet too small to partition
    /// meaningfully) leaves `self.partition` at `None`, reproducing
    /// whole-subnet legacy behavior exactly.
    pub fn set_node_partition(&self, node_id: &str) {
        let num_partitions = self.default_num_partitions();
        if num_partitions <= 1 {
            return;
        }
        let index = (fnv1a_hash(node_id.as_bytes()) % num_partitions as u64) as u32;
        self.apply_partition(index, num_partitions, false);
    }

    /// Explicit-override form of `set_node_partition`: the operator pins
    /// this node's partition `index` directly (from `pool.node_ip_partition`
    /// in server config) instead of deriving it from a hash of `node_id`,
    /// eliminating even the small residual risk of a hash collision between
    /// two nodes. `num_partitions` defaults to `default_num_partitions()`
    /// when `None`, matching `set_node_partition`'s sizing; pass `Some(n)`
    /// to also override the total partition count (e.g. to shrink per-node
    /// capacity on a larger pool than the default target supports).
    /// `index` is taken modulo the resolved `num_partitions`, so any value
    /// (e.g. a simple incrementing counter across nodes: 0, 1, 2, …) is safe
    /// to pass without the operator needing to know the exact partition
    /// count.
    pub fn set_node_partition_explicit(&self, index: u32, num_partitions: Option<u32>) {
        let num_partitions = num_partitions.unwrap_or_else(|| self.default_num_partitions());
        if num_partitions <= 1 {
            return;
        }
        self.apply_partition(index % num_partitions, num_partitions, true);
    }

    fn apply_partition(&self, index: u32, num_partitions: u32, explicit: bool) {
        let max_host_offset = self.network_config.max_host_offset();
        if max_host_offset < 2 || num_partitions <= 1 {
            return;
        }
        let bounds = compute_partition_bounds(max_host_offset, num_partitions, index, explicit);
        *self.partition.write() = Some(bounds);
    }

    /// This node's active VPN-IP partition assignment, if pool sync is
    /// configured and the subnet is large enough to partition — `None`
    /// otherwise (single-node / legacy / too-small-subnet deployments).
    /// Wave B-IP.2: lets a pool peer announce this over
    /// `ControlPayload::PartitionAnnounce` for operator overlap/mismatch
    /// visibility — see `crate::pool_partition::check_partition`.
    pub fn partition_info(&self) -> Option<PartitionInfo> {
        let bounds = *self.partition.read();
        bounds.map(|b| PartitionInfo {
            partition_index: b.index,
            partition_size: b.end_offset.saturating_sub(b.start_offset),
            num_partitions: b.num_partitions,
            explicit: b.explicit,
        })
    }

    /// Deterministic re-home target for `merge_from_json`'s IP-conflict
    /// backstop: derives a candidate offset purely from `client_id` (via
    /// `fnv1a_hash`), confined to this node's active partition when one is
    /// set (else the whole subnet), then linearly probes from there for the
    /// first offset not already held by a live (non-tombstoned) client in
    /// `data`. Being a pure function of `client_id` + this node's partition
    /// bounds + `data`'s current contents — never of mutable allocator
    /// state like `next_host_offset` — is what lets two independent nodes
    /// reach the SAME reassignment for the SAME losing client without a
    /// coordinator: see `merge_from_json`'s `ip_conflict` branch for the
    /// full convergence argument.
    pub(crate) fn deterministic_reassign_offset(
        &self,
        client_id: &str,
        data: &ClientDbFile,
    ) -> Option<Ipv4Addr> {
        let max_host_offset = self.network_config.max_host_offset();
        if max_host_offset < 1 {
            return None;
        }
        let partition = *self.partition.read();
        let (range_start, range_end) = match partition {
            Some(p) => (p.start_offset, p.end_offset),
            None => (1, max_host_offset + 1),
        };
        if range_start >= range_end {
            return None;
        }
        let range_len = range_end - range_start;

        let seed = fnv1a_hash(client_id.as_bytes());
        let mut offset = range_start + (seed % range_len as u64) as u32;
        for _ in 0..range_len {
            if let Some(candidate_ip) = self.network_config.ip_for_host_offset(offset) {
                let already_used = data
                    .clients
                    .iter()
                    .any(|c| c.vpn_ip == candidate_ip && !c.deleted);
                if candidate_ip != self.network_config.server_vpn_ip && !already_used {
                    return Some(candidate_ip);
                }
            }
            offset = if offset + 1 >= range_end {
                range_start
            } else {
                offset + 1
            };
        }
        None
    }
}

/// Compute the contiguous, disjoint `[start_offset, end_offset)` slice of
/// host offsets `1..=max_host_offset` owned by partition `index` out of
/// `num_partitions` total, evenly dividing `max_host_offset` by
/// `num_partitions` and folding the remainder into the LAST partition (so
/// every offset in `1..=max_host_offset` belongs to exactly one partition,
/// with no gaps and no overlap). `index` is NOT taken modulo
/// `num_partitions` here — callers must do that themselves (both current
/// callers do).
fn compute_partition_bounds(
    max_host_offset: u32,
    num_partitions: u32,
    index: u32,
    explicit: bool,
) -> PartitionBounds {
    debug_assert!(num_partitions >= 1);
    debug_assert!(index < num_partitions);
    let partition_size = (max_host_offset / num_partitions).max(1);
    let start_offset = (1 + index.saturating_mul(partition_size)).min(max_host_offset);
    let end_offset = if index + 1 >= num_partitions {
        max_host_offset + 1
    } else {
        (start_offset + partition_size).min(max_host_offset + 1)
    };
    PartitionBounds {
        start_offset,
        end_offset,
        index,
        num_partitions,
        explicit,
    }
}

/// Small deterministic non-cryptographic hash (FNV-1a) used only to spread
/// pool nodes' VPN-IP allocation starting offsets — see `set_node_partition`.
/// Not security-sensitive: worst case of a collision is the pre-existing
/// re-home-on-conflict path in `merge_from_json` doing a little more work.
fn fnv1a_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_db::test_support::test_network_config;

    /// Wave B-IP: distinct pool `node_id`s must land in DIFFERENT hard
    /// partitions (the common case), and clients added INDEPENDENTLY on the
    /// two nodes must never collide on vpn_ip — no coordinator, no lucky
    /// timing required. Also verifies a full bidirectional merge afterward
    /// converges with 0 collisions, 0 dropped clients, and — critically —
    /// no client's vpn_ip ever changes (the hard partition means the
    /// deterministic re-home backstop never has to fire for this case,
    /// which is exactly what prevents connection-key churn).
    #[test]
    fn distinct_node_ids_get_disjoint_partitions_and_never_collide() {
        let dir = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir.path().join("a.json"), test_network_config()).unwrap();
        let db_b = ClientDatabase::load(&dir.path().join("b.json"), test_network_config()).unwrap();

        let num_partitions = db_a.default_num_partitions();
        assert!(
            num_partitions > 1,
            "test config must yield >1 partitions for this test to be meaningful"
        );
        let index_of = |id: &str| (fnv1a_hash(id.as_bytes()) % num_partitions as u64) as u32;
        let node_a = "node-alpha";
        let node_b = [
            "node-beta",
            "node-gamma",
            "node-delta",
            "node-epsilon",
            "node-zeta",
        ]
        .into_iter()
        .find(|c| index_of(c) != index_of(node_a))
        .expect("fixture must yield a node_id landing in a different partition");

        db_a.set_node_partition(node_a);
        db_b.set_node_partition(node_b);

        let clients_a: Vec<_> = (0..5)
            .map(|i| db_a.add_client(&format!("a-client-{i}")).unwrap())
            .collect();
        let clients_b: Vec<_> = (0..5)
            .map(|i| db_b.add_client(&format!("b-client-{i}")).unwrap())
            .collect();

        for ca in &clients_a {
            for cb in &clients_b {
                assert_ne!(
                    ca.vpn_ip, cb.vpn_ip,
                    "independently-allocated IPs on different partitions must never collide"
                );
            }
        }

        let original_a_ips: std::collections::HashMap<String, Ipv4Addr> =
            clients_a.iter().map(|c| (c.id.clone(), c.vpn_ip)).collect();
        let original_b_ips: std::collections::HashMap<String, Ipv4Addr> =
            clients_b.iter().map(|c| (c.id.clone(), c.vpn_ip)).collect();

        // Bidirectional merge.
        let json_a = db_a.export_json().unwrap();
        let json_b = db_b.export_json().unwrap();
        let merged_into_b = db_b.merge_from_json(&json_a).unwrap();
        let merged_into_a = db_a.merge_from_json(&json_b).unwrap();

        assert_eq!(
            merged_into_b,
            clients_a.len(),
            "0 dropped clients merging A's clients into B"
        );
        assert_eq!(
            merged_into_a,
            clients_b.len(),
            "0 dropped clients merging B's clients into A"
        );

        // No client's vpn_ip changed anywhere — no re-home ever fired.
        for c in &clients_a {
            assert_eq!(
                db_a.find_by_id(&c.id).unwrap().vpn_ip,
                original_a_ips[&c.id]
            );
            assert_eq!(
                db_b.find_by_id(&c.id).unwrap().vpn_ip,
                original_a_ips[&c.id]
            );
        }
        for c in &clients_b {
            assert_eq!(
                db_b.find_by_id(&c.id).unwrap().vpn_ip,
                original_b_ips[&c.id]
            );
            assert_eq!(
                db_a.find_by_id(&c.id).unwrap().vpn_ip,
                original_b_ips[&c.id]
            );
        }

        // Pool-wide: still 0 collisions after both merges converge.
        for db in [&db_a, &db_b] {
            let all = db.list_clients();
            for x in &all {
                for y in &all {
                    if x.id != y.id {
                        assert_ne!(x.vpn_ip, y.vpn_ip, "no collision after merge convergence");
                    }
                }
            }
        }
    }

    /// Wave B-IP: when two nodes are (mis)configured onto the SAME explicit
    /// partition index — the forced-collision backstop case, e.g. a
    /// `node_ip_partition` typo, or a `node_id` hash collision on the
    /// unforced path — independent adds CAN still collide. Merging must then
    /// deterministically re-home the loser and both nodes must converge to
    /// the IDENTICAL final assignment without a coordinator: the winner
    /// (earlier `created_at`) keeps its original vpn_ip unchanged on BOTH
    /// nodes, and the loser lands on the SAME reassigned vpn_ip on BOTH
    /// nodes. Zero clients dropped.
    #[test]
    fn same_partition_forced_collision_converges_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir.path().join("a.json"), test_network_config()).unwrap();
        let db_b = ClientDatabase::load(&dir.path().join("b.json"), test_network_config()).unwrap();

        let num_partitions = db_a.default_num_partitions();
        assert!(num_partitions > 1);
        // Forced onto the SAME partition index on both nodes — this is the
        // scenario the deterministic re-home backstop exists for.
        db_a.set_node_partition_explicit(0, Some(num_partitions));
        db_b.set_node_partition_explicit(0, Some(num_partitions));

        // Both nodes' allocators start at the same offset within the shared
        // partition, so their first independently-added client collides —
        // exactly the pre-hard-partition bug, reproduced deliberately here.
        let x = db_a.add_client("x-on-a").unwrap();
        let y = db_b.add_client("y-on-b").unwrap();
        assert_eq!(
            x.vpn_ip, y.vpn_ip,
            "test setup: same explicit partition on both nodes must force a collision"
        );

        // Winner is whichever has the earlier created_at; x was created
        // first in this test, so x must win on both sides.
        let json_a = db_a.export_json().unwrap();
        let json_b = db_b.export_json().unwrap();
        let merged_into_b = db_b.merge_from_json(&json_a).unwrap();
        let merged_into_a = db_a.merge_from_json(&json_b).unwrap();
        assert_eq!(
            merged_into_b, 1,
            "colliding client must still merge into B, not be dropped"
        );
        assert_eq!(
            merged_into_a, 1,
            "colliding client must still merge into A, not be dropped"
        );

        let x_on_a = db_a.find_by_id(&x.id).unwrap();
        let x_on_b = db_b.find_by_id(&x.id).unwrap();
        let y_on_a = db_a.find_by_id(&y.id).unwrap();
        let y_on_b = db_b.find_by_id(&y.id).unwrap();

        assert_eq!(
            x_on_a.vpn_ip, x.vpn_ip,
            "winner x must keep its original vpn_ip on its home node A"
        );
        assert_eq!(
            x_on_b.vpn_ip, x.vpn_ip,
            "winner x must keep the IDENTICAL vpn_ip on node B — no churn"
        );
        assert_ne!(
            y_on_a.vpn_ip, x.vpn_ip,
            "loser y must be re-homed off the winner's vpn_ip"
        );
        assert_eq!(
            y_on_a.vpn_ip, y_on_b.vpn_ip,
            "both nodes must converge to the IDENTICAL reassigned vpn_ip for the loser"
        );
    }

    /// Wave B-IP: a node confined to a hard partition must return a clear,
    /// typed error when that partition is full — never silently spill into
    /// another node's territory (that would reintroduce the exact collision
    /// class this feature exists to prevent), and never panic.
    #[test]
    fn partition_exhaustion_returns_clear_error_not_spill() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        // Explicit override with num_partitions == max_host_offset gives
        // each partition exactly 1 usable offset. Index 1 avoids index 0,
        // whose single offset coincides with the server's own VPN IP.
        let max = test_network_config().max_host_offset();
        db.set_node_partition_explicit(1, Some(max));

        let first = db.add_client("only-slot").unwrap();
        let expected_ip = test_network_config().ip_for_host_offset(2).unwrap();
        assert_eq!(
            first.vpn_ip, expected_ip,
            "test setup: partition 1 must be exactly offset 2"
        );

        let err = db
            .add_client("no-room")
            .expect_err("a second client must fail once the 1-offset partition is full");
        let msg = err.to_string();
        assert!(
            msg.contains("partition"),
            "error must clearly describe partition exhaustion, got: {msg}"
        );

        // No spill: the only live client is still exactly at the partition's
        // single offset.
        assert_eq!(db.list_clients().len(), 1);
    }

    /// Wave B-IP regression: with no partition configured (single-node /
    /// legacy deployments, `set_node_partition` never called), allocation
    /// must still range across the WHOLE subnet exactly as before — no
    /// artificial ceiling introduced by the partitioning feature.
    #[test]
    fn no_partition_set_allocates_across_whole_subnet() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let partition_size_if_it_were_set = {
            let np = db.default_num_partitions();
            test_network_config().max_host_offset() / np
        };
        // Allocate more clients than a single partition would hold, proving
        // this un-partitioned node draws from the whole subnet, not some
        // partition-sized slice.
        let n = partition_size_if_it_were_set + 5;
        let clients: Vec<_> = (0..n)
            .map(|i| db.add_client(&format!("client-{i}")).unwrap())
            .collect();
        assert_eq!(clients.len(), n as usize);
        let unique_ips: std::collections::HashSet<_> = clients.iter().map(|c| c.vpn_ip).collect();
        assert_eq!(
            unique_ips.len(),
            n as usize,
            "all allocated IPs must be distinct"
        );
    }

    /// Wave B-IP: a client that was allocated an IP BEFORE this node had a
    /// partition configured (or synced in from a peer, from outside this
    /// node's partition entirely) must keep that IP unchanged forever —
    /// partitioning governs only NEW allocations, never rewrites existing
    /// ones. New allocations after the partition is applied must fall
    /// within the partition's bounds.
    #[test]
    fn existing_out_of_partition_client_keeps_ip_new_allocations_use_partition() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        // Added before any partition is configured — drawn from the whole
        // subnet's default starting offset.
        let legacy = db.add_client("legacy-client").unwrap();

        // Now confine this node to a partition that deliberately EXCLUDES
        // the legacy client's offset, to make the "keeps its IP" assertion
        // meaningful rather than incidental.
        let num_partitions = db.default_num_partitions();
        assert!(num_partitions > 1);
        let legacy_offset = test_network_config().host_offset(legacy.vpn_ip);
        let excluding_index = (0..num_partitions)
            .find(|&idx| {
                let bounds_start =
                    1 + idx * (test_network_config().max_host_offset() / num_partitions);
                bounds_start > legacy_offset
            })
            .expect("fixture must have a partition strictly after the legacy client's offset");
        db.set_node_partition_explicit(excluding_index, Some(num_partitions));

        // Legacy client is untouched.
        assert_eq!(db.find_by_id(&legacy.id).unwrap().vpn_ip, legacy.vpn_ip);

        // A fresh allocation now falls inside the configured partition,
        // strictly after the legacy client's out-of-partition offset.
        let fresh = db.add_client("fresh-client").unwrap();
        let fresh_offset = test_network_config().host_offset(fresh.vpn_ip);
        assert!(
            fresh_offset > legacy_offset,
            "new allocation ({fresh_offset}) must fall within the partition, \
             which starts strictly after the legacy client's offset ({legacy_offset})"
        );

        // Legacy client still untouched after the new allocation too.
        assert_eq!(db.find_by_id(&legacy.id).unwrap().vpn_ip, legacy.vpn_ip);
    }
}
