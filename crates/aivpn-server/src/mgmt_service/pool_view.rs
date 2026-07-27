//! Read-only pool topology views (Wave B1) — `GET /api/v1/pool/{nodes,
//! health,links}`, served both in-tunnel (`tunnel_router::dispatch`) and
//! over REST (`management_api.rs`). Pure data-merge logic
//! (`build_pool_snapshot`), no I/O and no `MgmtCtx` dependency — see the
//! doc comments on the individual types below for the merge-key semantics.
//!
//! Split out of `mgmt_service` (ЭТАП 1 decomposition, pure move — see that
//! module's doc comment for the full design rationale).

use serde::{Deserialize, Serialize};

// ── Pool topology views (Wave B1) ───────────────────────────────────────
//
// Read-only pool topology exposed over the SAME curated mgmt path as
// client-CRUD (Phase A): `GET /api/v1/pool/{nodes,health,links}`, both
// in-tunnel (`gateway.rs`'s `dispatch_mgmt_request`) and REST
// (`management_api.rs`'s `ApiState::mgmt_ctx`). Built by MERGING three
// independently-sourced views of "who is in the pool":
//
//   - configured membership (`PoolDialer::peers()` — `host:port` addresses,
//     this node's self-filtered masked-transport dial set);
//   - crypto identity (`NodeRegistry::list()`/`list_revoked()` — `node_id ->
//     pubkey` bindings, keyed by `node_id`, which by convention SHOULD equal
//     a peer's `host:port` but isn't guaranteed to — see `PoolSyncConfig::
//     node_id`'s doc comment);
//   - live/retained sync state (`PoolDialer::pool_status_snapshot()` —
//     connected/converged/last-seen, keyed by the dialed peer address).
//
// The merge key is simply the string itself: an address that happens to
// equal a bound `node_id` merges into one [`PoolNodeInfo`] entry with both
// `address` and `verified: true` populated; anything that doesn't match
// still shows up as its own (partial) entry rather than being dropped —
// "represent what you can" per the module's design brief, never silently
// hide a peer just because the two identity systems don't line up.
//
// **Legacy-transport degradation**: [`PoolDialer`]/[`crate::node_registry::
// NodeRegistry`] are ONLY ever constructed on a masked-transport node (see
// `main.rs`'s pool-sync wiring) — the legacy, mask-independent `PeerSyncer`
// path has no dialed sessions and therefore no notion of "peer link state"
// at all. A node running legacy pool sync (or no pool sync) simply has no
// `PoolDialer`/`NodeRegistry` to build a snapshot from; both call sites
// detect this and hand `dispatch` a degraded [`PoolSnapshot::empty`]
// (`transport: "legacy"` or `"none"`) instead of attempting to call into
// either type — see those call sites' doc comments for how they tell the
// two degraded cases apart.

/// One pool node as reported by [`build_pool_snapshot`]. `node_id` is
/// always populated (falling back to the address string when no crypto
/// identity is bound for it — see the module doc's merge-key note);
/// `address` is `None` for a node this registry knows about but that isn't
/// (or isn't yet) one of this node's configured dial-set peers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolNodeInfo {
    pub node_id: String,
    pub address: Option<String>,
    /// `true` iff `node_id` has a durable, TOFU/manually-pinned Ed25519
    /// binding in [`crate::node_registry::NodeRegistry`] (i.e. it appears in
    /// `NodeRegistry::list()`).
    pub verified: bool,
    /// `true` iff `node_id` (or the matching address) appears in
    /// `NodeRegistry::list_revoked()`.
    pub revoked: bool,
    /// `true` iff a masked dialed session to this peer is up right now.
    /// Always `false` for a node this registry only knows about via
    /// `NodeRegistry` (we track live sessions only for our own configured
    /// dial-set peers — an inbound-only peer that dials US has no entry in
    /// `PoolDialer::pool_status_snapshot`).
    pub connected: bool,
    pub last_seen_unix: Option<i64>,
}

/// One live/retained sync link, as reported by [`build_pool_snapshot`] —
/// one entry per [`crate::pool_dialer::PeerSyncStatus`] this node has ever
/// observed for a dialed peer (see that type's doc comment for what
/// `connected`/`converged` mean).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolLinkInfo {
    pub peer: String,
    pub connected: bool,
    pub converged: bool,
    pub last_converged_unix: Option<i64>,
    /// Wave B-IP.2: true iff the most recent `ControlPayload::PartitionAnnounce`
    /// exchange with this peer found both nodes claiming the same VPN-IP
    /// partition index on the same subnet — see
    /// `crate::pool_partition::PartitionCheck::IndexConflict`.
    pub partition_conflict: bool,
    /// Wave B-IP.2: true iff the most recent `ControlPayload::PartitionAnnounce`
    /// exchange with this peer found a different VPN subnet CIDR than ours —
    /// see `crate::pool_partition::PartitionCheck::SubnetMismatch`.
    pub subnet_mismatch: bool,
}

/// Aggregate pool-sync health summary, as reported by [`build_pool_snapshot`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolHealth {
    /// `"masked"` (this node runs [`crate::pool_dialer::PoolDialer`]),
    /// `"legacy"` (pool sync is configured but runs the mask-independent
    /// `PeerSyncer`, which has no queryable link state — see the module
    /// doc's legacy-transport note), or `"none"` (pool sync isn't
    /// configured on this node at all).
    pub transport: String,
    pub total_nodes: usize,
    pub connected_peers: usize,
    pub converged_peers: usize,
    /// `true` iff at least one currently-connected peer's last anti-entropy
    /// signal was a mismatch (i.e. `connected && !converged` for some
    /// entry) — a coarse "is anything actively out of sync right now"
    /// summary flag for a dashboard, not a precise count.
    pub diverged: bool,
    /// Wave B-IP.2: true iff any link's `partition_conflict` is set — a
    /// coarse "at least one peer collides with our VPN-IP partition index"
    /// dashboard flag, not a precise count.
    pub partition_conflict: bool,
    /// Wave B-IP.2: true iff any link's `subnet_mismatch` is set — a coarse
    /// "at least one peer disagrees with our VPN subnet" dashboard flag.
    pub subnet_mismatch: bool,
}

impl PoolHealth {
    /// The degraded health view for `transport` `"legacy"` or `"none"` —
    /// see [`PoolSnapshot::empty`].
    pub(crate) fn empty(transport: &str) -> Self {
        Self {
            transport: transport.to_string(),
            total_nodes: 0,
            connected_peers: 0,
            converged_peers: 0,
            diverged: false,
            partition_conflict: false,
            subnet_mismatch: false,
        }
    }
}

/// The full pool topology view returned by `GET /api/v1/pool/{nodes,health,
/// links}` — `dispatch` slices out the field the specific route asked for
/// (see the `Route::Pool*` arms below).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PoolSnapshot {
    pub nodes: Vec<PoolNodeInfo>,
    pub links: Vec<PoolLinkInfo>,
    pub health: PoolHealth,
}

impl PoolSnapshot {
    /// The degraded snapshot a call site hands `MgmtCtx::pool` when there is
    /// no live [`crate::pool_dialer::PoolDialer`] to build a real one from —
    /// `transport` should be `"legacy"` (pool sync configured, but running
    /// the legacy mask-independent transport) or `"none"` (pool sync isn't
    /// configured at all). Never an error condition: the `pool/*` routes
    /// always return `200` for this.
    pub fn empty(transport: &str) -> Self {
        Self {
            nodes: Vec::new(),
            links: Vec::new(),
            health: PoolHealth::empty(transport),
        }
    }
}

/// Inputs to [`build_pool_snapshot`] — a pure function of already-collected
/// data, so it's trivially unit-testable with fake inputs (no `PoolDialer`/
/// `NodeRegistry`/live session needed). Both real call sites
/// (`gateway.rs`'s `dispatch_mgmt_request`, `management_api.rs`'s
/// `ApiState::mgmt_ctx`) collect these from a live `PoolDialer`/
/// `NodeRegistry` pair before calling in.
pub struct PoolSnapshotInputs<'a> {
    /// `PoolDialer::peers()` — this node's configured masked-transport dial
    /// set (addresses).
    pub peers: &'a [String],
    /// `NodeRegistry::list()` — bound `(node_id, pubkey)` pairs.
    pub registry_nodes: &'a [(String, [u8; 32])],
    /// `NodeRegistry::list_revoked()` — revoked `node_id`s.
    pub revoked: &'a [String],
    /// `PoolDialer::pool_status_snapshot()` — retained per-peer sync state,
    /// keyed by dialed peer address.
    pub statuses: &'a [(String, crate::pool_dialer::PeerSyncStatus)],
    /// Always `"masked"` from both real call sites (this function is only
    /// ever called when a live `PoolDialer` exists) — taken as a parameter
    /// rather than hardcoded so a test can exercise the merge logic without
    /// asserting a specific literal.
    pub transport: &'a str,
}

/// Merge [`PoolSnapshotInputs`] into one [`PoolSnapshot`]. Pure and
/// side-effect-free — see that type's doc comment for the merge-key
/// semantics. Node/link ordering is deterministic (nodes sorted by
/// `node_id`, links sorted by `peer`) so callers/tests can compare shapes
/// without normalizing order themselves.
pub fn build_pool_snapshot(inputs: PoolSnapshotInputs) -> PoolSnapshot {
    use std::collections::{BTreeMap, HashSet};

    let revoked_set: HashSet<&str> = inputs.revoked.iter().map(String::as_str).collect();
    let mut nodes: BTreeMap<String, PoolNodeInfo> = BTreeMap::new();

    let blank_node = |key: &str, revoked_set: &HashSet<&str>| PoolNodeInfo {
        node_id: key.to_string(),
        address: None,
        verified: false,
        revoked: revoked_set.contains(key),
        connected: false,
        last_seen_unix: None,
    };

    // 1. Crypto identity: every bound node_id is `verified: true`.
    for (node_id, _pubkey) in inputs.registry_nodes {
        let mut entry = blank_node(node_id, &revoked_set);
        entry.verified = true;
        nodes.insert(node_id.clone(), entry);
    }

    // 2. Revoked node_ids that aren't (or are no longer) bound — `revoke()`
    //    removes the binding, so a revoked identity is typically absent
    //    from `registry_nodes` above; still surface it (verified: false,
    //    revoked: true) rather than silently dropping it.
    for node_id in inputs.revoked {
        nodes
            .entry(node_id.clone())
            .or_insert_with(|| blank_node(node_id, &revoked_set));
    }

    // 3. Configured membership: fill in `address` on a matching identity
    //    entry, or add a new (unverified) one keyed by the address itself.
    for peer in inputs.peers {
        let entry = nodes
            .entry(peer.clone())
            .or_insert_with(|| blank_node(peer, &revoked_set));
        entry.address = Some(peer.clone());
    }

    // 4. Live/retained sync state: merge connected/last_seen onto a
    //    matching node entry (creating one, address-keyed, if none exists —
    //    e.g. an exit_node peer not otherwise in `peers`), and build the
    //    `links` list one-to-one with `statuses`.
    let mut links: Vec<PoolLinkInfo> = Vec::with_capacity(inputs.statuses.len());
    for (peer, status) in inputs.statuses {
        let entry = nodes.entry(peer.clone()).or_insert_with(|| {
            let mut e = blank_node(peer, &revoked_set);
            e.address = Some(peer.clone());
            e
        });
        entry.connected = status.connected;
        entry.last_seen_unix = status.last_seen_unix;

        links.push(PoolLinkInfo {
            peer: peer.clone(),
            connected: status.connected,
            converged: status.converged,
            last_converged_unix: status.last_converged_unix,
            partition_conflict: status.partition_conflict,
            subnet_mismatch: status.subnet_mismatch,
        });
    }
    links.sort_by(|a, b| a.peer.cmp(&b.peer));

    let total_nodes = nodes.len();
    let connected_peers = inputs.statuses.iter().filter(|(_, s)| s.connected).count();
    let converged_peers = inputs.statuses.iter().filter(|(_, s)| s.converged).count();
    let diverged = inputs
        .statuses
        .iter()
        .any(|(_, s)| s.connected && !s.converged);
    let partition_conflict = inputs.statuses.iter().any(|(_, s)| s.partition_conflict);
    let subnet_mismatch = inputs.statuses.iter().any(|(_, s)| s.subnet_mismatch);

    PoolSnapshot {
        nodes: nodes.into_values().collect(),
        links,
        health: PoolHealth {
            transport: inputs.transport.to_string(),
            total_nodes,
            connected_peers,
            converged_peers,
            diverged,
            partition_conflict,
            subnet_mismatch,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt_service::test_support::*;

    /// The core merge case: a peer that is both configured (an address in
    /// `peers`) AND bound in the registry AND has live status all collapse
    /// into ONE node entry — not three separate ones — because its address
    /// happens to equal its `node_id` (the documented convention).
    #[test]
    fn build_pool_snapshot_merges_config_registry_and_status_for_matching_identity() {
        let peers = vec!["node-a:443".to_string()];
        let registry_nodes = vec![("node-a:443".to_string(), [7u8; 32])];
        let revoked: Vec<String> = vec![];
        let statuses = vec![(
            "node-a:443".to_string(),
            sample_status(true, true, Some(1000), Some(1000)),
        )];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert_eq!(
            snap.nodes.len(),
            1,
            "matching address/node_id must merge into one entry"
        );
        let node = &snap.nodes[0];
        assert_eq!(node.node_id, "node-a:443");
        assert_eq!(node.address.as_deref(), Some("node-a:443"));
        assert!(node.verified);
        assert!(!node.revoked);
        assert!(node.connected);
        assert_eq!(node.last_seen_unix, Some(1000));

        assert_eq!(snap.links.len(), 1);
        assert_eq!(snap.links[0].peer, "node-a:443");
        assert!(snap.links[0].converged);
        assert_eq!(snap.links[0].last_converged_unix, Some(1000));

        assert_eq!(snap.health.transport, "masked");
        assert_eq!(snap.health.total_nodes, 1);
        assert_eq!(snap.health.connected_peers, 1);
        assert_eq!(snap.health.converged_peers, 1);
        assert!(!snap.health.diverged);
    }
    /// When identity keys DON'T line up (registry keyed by a `node_id` that
    /// isn't the dial address), the merge must not silently drop or
    /// conflate them — "represent what you can" per the design brief.
    #[test]
    fn build_pool_snapshot_keeps_non_matching_identity_and_address_as_separate_entries() {
        let peers = vec!["203.0.113.5:443".to_string()];
        let registry_nodes = vec![("node-b-identity".to_string(), [9u8; 32])];
        let revoked: Vec<String> = vec![];
        let statuses: Vec<(String, crate::pool_dialer::PeerSyncStatus)> = vec![];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert_eq!(
            snap.nodes.len(),
            2,
            "non-matching identity/address must both be represented"
        );
        let by_id: std::collections::HashMap<&str, &PoolNodeInfo> =
            snap.nodes.iter().map(|n| (n.node_id.as_str(), n)).collect();
        assert!(by_id["node-b-identity"].verified);
        assert!(by_id["node-b-identity"].address.is_none());
        assert!(!by_id["203.0.113.5:443"].verified);
        assert_eq!(
            by_id["203.0.113.5:443"].address.as_deref(),
            Some("203.0.113.5:443")
        );
    }
    /// A revoked node_id no longer present in `registry_nodes` (revoke()
    /// removes the binding) must still surface as its own entry —
    /// `revoked: true`, `verified: false` — rather than vanishing.
    #[test]
    fn build_pool_snapshot_surfaces_revoked_identity_no_longer_bound() {
        let peers: Vec<String> = vec![];
        let registry_nodes: Vec<(String, [u8; 32])> = vec![];
        let revoked = vec!["node-c:443".to_string()];
        let statuses: Vec<(String, crate::pool_dialer::PeerSyncStatus)> = vec![];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert_eq!(snap.nodes.len(), 1);
        assert_eq!(snap.nodes[0].node_id, "node-c:443");
        assert!(snap.nodes[0].revoked);
        assert!(!snap.nodes[0].verified);
    }
    /// `diverged` is true iff some CONNECTED peer's last signal was a
    /// mismatch — a disconnected-and-never-converged peer must not trip it.
    #[test]
    fn build_pool_snapshot_diverged_true_only_for_connected_mismatched_peer() {
        let peers = vec!["p1:443".to_string(), "p2:443".to_string()];
        let registry_nodes: Vec<(String, [u8; 32])> = vec![];
        let revoked: Vec<String> = vec![];
        let statuses = vec![
            (
                "p1:443".to_string(),
                sample_status(true, false, None, Some(500)),
            ),
            (
                "p2:443".to_string(),
                sample_status(false, false, None, Some(100)),
            ),
        ];

        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &peers,
            registry_nodes: &registry_nodes,
            revoked: &revoked,
            statuses: &statuses,
            transport: "masked",
        });

        assert!(snap.health.diverged);
        assert_eq!(snap.health.connected_peers, 1);
        assert_eq!(snap.health.converged_peers, 0);
    }
    /// Empty inputs (no pool sync configured) must build a well-formed,
    /// empty snapshot — never panic on empty slices.
    #[test]
    fn build_pool_snapshot_empty_inputs_yields_empty_snapshot() {
        let snap = build_pool_snapshot(PoolSnapshotInputs {
            peers: &[],
            registry_nodes: &[],
            revoked: &[],
            statuses: &[],
            transport: "masked",
        });
        assert!(snap.nodes.is_empty());
        assert!(snap.links.is_empty());
        assert_eq!(snap.health.total_nodes, 0);
        assert!(!snap.health.diverged);
    }
    /// `PoolSnapshot::empty` — the degraded value both call sites hand
    /// `MgmtCtx::pool` when there's no live `PoolDialer` — must always yield
    /// empty lists and echo the given transport label.
    #[test]
    fn pool_snapshot_empty_has_given_transport_and_empty_lists() {
        for transport in ["legacy", "none"] {
            let snap = PoolSnapshot::empty(transport);
            assert!(snap.nodes.is_empty());
            assert!(snap.links.is_empty());
            assert_eq!(snap.health.transport, transport);
            assert_eq!(snap.health.total_nodes, 0);
        }
    }
}
