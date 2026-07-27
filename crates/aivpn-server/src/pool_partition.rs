//! Wave B-IP.2: pool-node partition-info exchange + conflict detection.
//!
//! Wave B-IP (`ClientDatabase::set_node_partition`/`_explicit`) already makes
//! two independent pool nodes' NEW-VPN-IP allocations disjoint by
//! construction — this module does not change that correctness guarantee.
//! It exists purely for OPERATOR VISIBILITY: pool nodes exchange their
//! `{subnet_cidr, partition_index, num_partitions, explicit}` over
//! `ControlPayload::PartitionAnnounce` (see `aivpn_common::protocol`) and log
//! a warning/error when the exchange reveals something the hash-derived
//! scheme cannot fully rule out on its own (a hash collision between two
//! nodes' `hash(node_id) % num_partitions`) or that only an operator can fix
//! (two nodes configured with different VPN subnets entirely).
//!
//! [`check_partition`] is the pure decision function — unit-testable without
//! any network/session/`ClientDatabase` plumbing. [`log_partition_check`] is
//! the thin logging wrapper both `gateway.rs` (server/receiving side) and
//! `pool_dialer.rs` (dialer/anti-entropy side) call, gated by a per-peer
//! "did the decision change since last time" latch at each call site so a
//! persistently-conflicting pair logs once per state transition, not on
//! every anti-entropy beacon.

use tracing::{debug, error, warn};

/// Outcome of comparing this node's own partition/subnet state against a
/// peer's `ControlPayload::PartitionAnnounce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionCheck {
    /// No conflict: the peer is on a different partition index of the same
    /// subnet, or one/both sides have no partition configured at all.
    Ok,
    /// Both sides claim the SAME partition index on the SAME subnet.
    /// `explicit` is true iff EITHER side pinned its index via
    /// `pool.node_ip_partition` — an explicit collision is an operator
    /// misconfiguration (error-worthy); a purely hash-derived collision is a
    /// low-probability accident that Wave B-IP's `merge_from_json`
    /// deterministic re-home already self-heals (warn-worthy, not an error).
    IndexConflict { explicit: bool },
    /// The peer's subnet CIDR does not match ours — pool-wide partitioning
    /// is incoherent regardless of index; every node must agree on the VPN
    /// subnet for the disjoint-slice guarantee to mean anything.
    SubnetMismatch,
}

/// Decode a peer's announced `PartitionAnnounce` numeric fields back into
/// the `Option<(partition_index, explicit)>` shape [`check_partition`]
/// expects. An UNPARTITIONED node announces the self-describing sentinel
/// `{partition_index: 0, partition_size: 0, num_partitions: 1}` (rather
/// than skipping the announce) — that must decode to `None`, not to a
/// literal `Some((0, _))`: a genuinely partitioned receiver holding index 0
/// would otherwise flag a spurious `IndexConflict` against every
/// unpartitioned peer, exactly the false alarm `check_partition`'s
/// "one side unpartitioned never conflicts" contract rules out. A real
/// partition always has `partition_size >= 1`.
pub fn decode_peer_partition(
    partition_index: u32,
    partition_size: u32,
    num_partitions: u32,
    explicit: bool,
) -> Option<(u32, bool)> {
    if partition_size == 0 && num_partitions <= 1 {
        None
    } else {
        Some((partition_index, explicit))
    }
}

/// Compare this node's own `(subnet_cidr, Option<(partition_index,
/// explicit)>)` against a peer's announced values. Subnet mismatch is
/// checked first and wins outright (an index comparison across two
/// different subnets is meaningless). An index collision only fires when
/// BOTH sides actually have a partition configured — a node running
/// unpartitioned (single-node / subnet too small to partition) never flags
/// a spurious collision against a genuinely partitioned peer's index.
pub fn check_partition(
    local_cidr: &str,
    local_partition: Option<(u32, bool)>,
    peer_cidr: &str,
    peer_partition: Option<(u32, bool)>,
) -> PartitionCheck {
    if local_cidr != peer_cidr {
        return PartitionCheck::SubnetMismatch;
    }
    match (local_partition, peer_partition) {
        (Some((local_index, local_explicit)), Some((peer_index, peer_explicit)))
            if local_index == peer_index =>
        {
            PartitionCheck::IndexConflict {
                explicit: local_explicit || peer_explicit,
            }
        }
        _ => PartitionCheck::Ok,
    }
}

/// Log `check` at the level appropriate for its severity, scoped to
/// `peer_desc` (a node_id when verified, otherwise a hashed address).
/// Callers are responsible for only invoking this when the decision has
/// actually changed since the last call for this peer (see the module doc)
/// — this function itself does no rate-limiting/dedup.
pub fn log_partition_check(
    check: PartitionCheck,
    peer_desc: &str,
    local_cidr: &str,
    peer_cidr: &str,
) {
    match check {
        PartitionCheck::Ok => {
            debug!(
                "pool_partition: peer {} partition ok (subnet={})",
                peer_desc, local_cidr
            );
        }
        PartitionCheck::SubnetMismatch => {
            warn!(
                "pool_partition: pool peer {} has mismatched VPN subnet (peer={}, local={}); \
                 partitioning is incoherent — all pool nodes must share the same VPN subnet",
                peer_desc, peer_cidr, local_cidr
            );
        }
        PartitionCheck::IndexConflict { explicit: true } => {
            error!(
                "pool_partition: explicit partition index collision with peer {} — \
                 operator must assign distinct pool.node_ip_partition values",
                peer_desc
            );
        }
        PartitionCheck::IndexConflict { explicit: false } => {
            warn!(
                "pool_partition: partition index collision with peer {} (hash-derived); \
                 set an explicit pool.node_ip_partition=<free index> on one node to avoid IP re-homing",
                peer_desc
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_subnet_different_index_is_ok() {
        let check = check_partition(
            "10.0.0.0/24",
            Some((2, false)),
            "10.0.0.0/24",
            Some((5, false)),
        );
        assert_eq!(check, PartitionCheck::Ok);
    }

    #[test]
    fn same_subnet_same_index_hash_derived_is_index_conflict_not_explicit() {
        let check = check_partition(
            "10.0.0.0/24",
            Some((3, false)),
            "10.0.0.0/24",
            Some((3, false)),
        );
        assert_eq!(check, PartitionCheck::IndexConflict { explicit: false });
    }

    #[test]
    fn same_subnet_same_index_local_explicit_is_index_conflict_explicit() {
        let check = check_partition(
            "10.0.0.0/24",
            Some((3, true)),
            "10.0.0.0/24",
            Some((3, false)),
        );
        assert_eq!(check, PartitionCheck::IndexConflict { explicit: true });
    }

    #[test]
    fn same_subnet_same_index_peer_explicit_is_index_conflict_explicit() {
        let check = check_partition(
            "10.0.0.0/24",
            Some((3, false)),
            "10.0.0.0/24",
            Some((3, true)),
        );
        assert_eq!(check, PartitionCheck::IndexConflict { explicit: true });
    }

    #[test]
    fn different_subnet_is_mismatch_even_with_same_index() {
        let check = check_partition(
            "10.0.0.0/24",
            Some((3, false)),
            "10.0.1.0/24",
            Some((3, false)),
        );
        assert_eq!(check, PartitionCheck::SubnetMismatch);
    }

    #[test]
    fn subnet_mismatch_takes_priority_over_index_conflict() {
        // Different subnets AND same index — must report SubnetMismatch,
        // not IndexConflict; an index comparison across subnets is
        // meaningless.
        let check = check_partition(
            "10.0.0.0/24",
            Some((0, true)),
            "10.0.1.0/24",
            Some((0, true)),
        );
        assert_eq!(check, PartitionCheck::SubnetMismatch);
    }

    #[test]
    fn one_side_unpartitioned_never_conflicts_on_index() {
        let check = check_partition("10.0.0.0/24", None, "10.0.0.0/24", Some((0, false)));
        assert_eq!(check, PartitionCheck::Ok);

        let check = check_partition("10.0.0.0/24", Some((0, false)), "10.0.0.0/24", None);
        assert_eq!(check, PartitionCheck::Ok);
    }

    #[test]
    fn both_sides_unpartitioned_same_subnet_is_ok() {
        let check = check_partition("10.0.0.0/24", None, "10.0.0.0/24", None);
        assert_eq!(check, PartitionCheck::Ok);
    }

    #[test]
    fn decode_peer_partition_maps_unpartitioned_sentinel_to_none() {
        // The exact sentinel both announce senders emit for "no partition
        // configured": {index: 0, size: 0, num_partitions: 1}.
        assert_eq!(decode_peer_partition(0, 0, 1, false), None);
        // explicit flag is irrelevant for the sentinel shape.
        assert_eq!(decode_peer_partition(0, 0, 1, true), None);
        // num_partitions: 0 (degenerate) with size 0 is also "no partition".
        assert_eq!(decode_peer_partition(0, 0, 0, false), None);
    }

    #[test]
    fn decode_peer_partition_keeps_real_partitions() {
        assert_eq!(decode_peer_partition(0, 50, 4, false), Some((0, false)));
        assert_eq!(decode_peer_partition(3, 50, 4, true), Some((3, true)));
    }

    #[test]
    fn partitioned_index_zero_vs_unpartitioned_sentinel_is_ok_not_conflict() {
        // Regression: node A partitioned with index 0, node B unpartitioned
        // (announcing the sentinel). Decoding the sentinel as a literal
        // Some((0, _)) used to raise a spurious IndexConflict here.
        let peer = decode_peer_partition(0, 0, 1, false);
        let check = check_partition("10.0.0.0/24", Some((0, true)), "10.0.0.0/24", peer);
        assert_eq!(check, PartitionCheck::Ok);
    }
}
