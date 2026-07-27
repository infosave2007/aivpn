//! B2b/B2c/P1 (per-client + global masked-transport exit routing): pure
//! decision and diff functions that pick, and keep live, the masked-pool
//! exit target(s) this node dials, factored out of `Gateway`'s methods so
//! both the in-tunnel management path and the REST/Unix-socket management
//! API (`management_api.rs`, which has no `&Gateway`) can share them.

use std::sync::Arc;

use crate::client_db::{ClientConfig, ClientDatabase};

use super::Gateway;

/// B2b (per-client exit routing, data plane): the resolved outcome of
/// picking an uplink masked-exit target for one client's `Data`/FEC-recovered
/// packet, from that client's own `ClientConfig::exit_node` override (B2a)
/// and the node's global default (`pool.exit_node` / `Gateway::masked_exit_addr`).
///
/// Deliberately does not distinguish "which address" beyond the resolved
/// string — the caller (`Gateway::forward_via_exit`) doesn't need to know
/// *why* `addr` was picked, only whether a failed `send_to_peer` may
/// additionally fall back to local TUN egress (`local_fallback`) or must
/// preserve the pre-B2b silent-drop-on-no-live-session behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExitDecision {
    /// Neither a per-client override nor a global default exit is
    /// configured for this packet — masked-transport exit routing does not
    /// apply at all. The caller falls through to the legacy
    /// `chain_forwarder`/local-TUN-egress branch, byte-identical to the
    /// pre-B2b `self.masked_exit_addr.is_none()` case.
    NoExit,
    /// Attempt `PoolDialer::send_to_peer(addr, ChainForward{..})`.
    ///
    /// `local_fallback == false` is the pre-B2b, global-default-only case
    /// (no per-client override involved at all): on a failed send, the
    /// packet is silently dropped exactly as before — REGRESSION INVARIANT,
    /// see `choose_exit`'s doc comment.
    ///
    /// `local_fallback == true` means `addr` was resolved via (or falls
    /// back from) a per-client `exit_node` override: a failed send may
    /// additionally fall back to local TUN/NAT egress instead of dropping,
    /// per B2b's spec — this path never existed before B2b and only
    /// engages for clients that actually have a per-client override
    /// configured.
    Send { addr: String, local_fallback: bool },
}

/// B2b (per-client exit routing, data plane): pure decision function —
/// given `client_exit` (this client's `ClientConfig::exit_node`, already
/// resolved from the cache/DB), `global` (the node-wide default,
/// `Gateway::masked_exit_addr`), and a non-mutating `is_live` liveness check
/// (`PoolDialer::has_live_session`), decides where — if anywhere — to route
/// this client's masked-transport uplink packet.
///
/// Truth table:
/// - `client_exit = None`, `global = None`            → `NoExit`
/// - `client_exit = None`, `global = Some(g)`          → `Send{g, local_fallback:false}`
/// - `client_exit = Some(c)`, `is_live(c)`             → `Send{c, local_fallback:true}`
/// - `client_exit = Some(c)`, `!is_live(c)`, `global=None`     → `NoExit`
/// - `client_exit = Some(c)`, `!is_live(c)`, `global=Some(g)`  → `Send{g, local_fallback:true}`
///
/// REGRESSION INVARIANT (safety-critical): when `client_exit` is always
/// `None` (the current common case — no client has a per-client `exit_node`
/// set), this reduces to exactly the pre-B2b two-way branch on `global`
/// alone (`NoExit` or `Send{global, local_fallback:false}`, which drops —
/// never locally egresses — on a failed send). This function must never be
/// changed in a way that alters that reduction.
pub(crate) fn choose_exit(
    client_exit: Option<&str>,
    global: Option<&str>,
    is_live: impl Fn(&str) -> bool,
) -> ExitDecision {
    match client_exit {
        Some(c) if is_live(c) => ExitDecision::Send {
            addr: c.to_string(),
            local_fallback: true,
        },
        Some(_) => match global {
            Some(g) => ExitDecision::Send {
                addr: g.to_string(),
                local_fallback: true,
            },
            None => ExitDecision::NoExit,
        },
        None => match global {
            Some(g) => ExitDecision::Send {
                addr: g.to_string(),
                local_fallback: false,
            },
            None => ExitDecision::NoExit,
        },
    }
}

/// Wave B2c (runtime dial add-peer): pure collection/diff function —
/// given every client currently in the DB and the set of peer addresses
/// this node is ALREADY dialing (`already`, from
/// `PoolDialer::dialed_peer_addrs()`), returns every distinct, non-empty
/// `exit_node` address referenced by any client that is NOT in `already`.
/// The caller (`Gateway::add_dial_peers_for_client_exits`) then
/// `PoolDialer::add_peer`s each returned address so it goes live without a
/// restart.
///
/// Pure and side-effect-free — testable without a live `PoolDialer` or a
/// real `ClientDatabase` (see the `exits_needing_dial_*` tests below).
/// Deduped and returned as a `Vec` (stable iteration order over `clients`)
/// rather than a `HashSet`, purely so a caller that wants to log "these N
/// addresses are new" gets a deterministic order — the caller doesn't
/// otherwise care about ordering, since `PoolDialer::add_peer` is
/// idempotent per-address regardless of call order.
pub(crate) fn exits_needing_dial(
    clients: &[ClientConfig],
    already: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for c in clients {
        let Some(addr) = c.exit_node.as_deref() else {
            continue;
        };
        let addr = addr.trim();
        if addr.is_empty() || already.contains(addr) {
            continue;
        }
        if seen.insert(addr.to_string()) {
            out.push(addr.to_string());
        }
    }
    out
}

/// P1 (global exit live-swap): pure swap of `masked_exit_addr` to
/// `new_global` plus, on an actual change, a `PoolDialer::add_peer` for the
/// fresh value — no file I/O. Factored out of `Gateway::apply_global_exit_update`
/// so it can also be driven by `apply_global_exit_and_teardown` below
/// (shared by the REST/Unix-socket path), without duplicating the
/// read-modify-write logic. See `Gateway::apply_global_exit_update`'s doc
/// comment for the full behavior contract this preserves byte-for-byte.
pub(crate) fn apply_global_exit_swap(
    masked_exit_addr: &parking_lot::RwLock<Option<String>>,
    pool_dialer: Option<&Arc<crate::pool_dialer::PoolDialer>>,
    new_global: Option<String>,
) {
    let Some(dialer) = pool_dialer else {
        return;
    };
    let changed = {
        let mut current = masked_exit_addr.write();
        if *current == new_global {
            false
        } else {
            *current = new_global.clone();
            true
        }
    };
    if changed {
        if let Some(addr) = new_global {
            dialer.add_peer(addr);
        }
    }
}

/// Wave B2c (runtime dial add-peer): pure `PoolDialer::add_peer` driver —
/// factored out of `Gateway::add_dial_peers_for_client_exits` so
/// `apply_global_exit_and_teardown` below can reuse it. See that method's
/// doc comment for the full behavior contract.
pub(crate) fn add_dial_peers_for_client_exits_for(
    dialer: &Arc<crate::pool_dialer::PoolDialer>,
    clients: &[ClientConfig],
) {
    let already: std::collections::HashSet<String> =
        dialer.dialed_peer_addrs().into_iter().collect();
    for addr in exits_needing_dial(clients, &already) {
        dialer.add_peer(addr);
    }
}

/// Wave 2 (dial-teardown): pure `PoolDialer::remove_peer` driver — factored
/// out of `Gateway::teardown_unused_exit_dials` so `apply_global_exit_and_teardown`
/// below can reuse it. See that method's doc comment for the full behavior
/// contract (referenced set = the current global default plus every
/// distinct per-client `exit_node` in `clients`; never touches a
/// startup-configured `pool.peers`/`pool.exit_node` dial).
pub(crate) fn teardown_unused_exit_dials_for(
    masked_exit_addr: &parking_lot::RwLock<Option<String>>,
    pool_dialer: Option<&Arc<crate::pool_dialer::PoolDialer>>,
    clients: &[ClientConfig],
) {
    let Some(dialer) = pool_dialer else {
        return;
    };
    let mut needed: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(g) = masked_exit_addr.read().as_deref() {
        needed.insert(g.to_string());
    }
    for c in clients {
        if let Some(addr) = c.exit_node.as_deref() {
            let addr = addr.trim();
            if !addr.is_empty() {
                needed.insert(addr.to_string());
            }
        }
    }
    for addr in dialer.runtime_exit_peer_addrs() {
        if !needed.contains(&addr) {
            dialer.remove_peer(&addr);
        }
    }
}

/// P1 REST parity fix: the full global-exit-live-swap side effect —
/// re-read `pool.exit_node` from `server_config_path`
/// (`Gateway::read_global_exit_node`), swap `masked_exit_addr` if it
/// changed (`apply_global_exit_swap`), pick up any newly-referenced
/// per-client `exit_node` (`add_dial_peers_for_client_exits_for`, Wave
/// B2c parity), then prune any now-unreferenced RUNTIME exit dial
/// (`teardown_unused_exit_dials_for`, Wave 2) — bundled into ONE function so
/// both the in-tunnel path (`Gateway::dispatch_mgmt_request`) and the
/// REST/Unix-socket path (`management_api::apply_config`/`confirm_config`,
/// which has no `&Gateway` to call methods on, only the shared handles
/// `AivpnServer::masked_exit_addr()`/`::pool_dialer()`/`::exit_route_cache()`
/// already expose) apply a confirmed `pool.exit_node` change to this node's
/// live routing without a restart, instead of only the tunnel path doing
/// so.
///
/// A no-op — cheaply — when `pool_dialer` is `None` (legacy transport / no
/// masked pool-client dialer on this node), matching every one of the
/// individual steps' own preconditions. `server_config_path: None` (no
/// `server.json` path configured on this node) makes the re-read resolve to
/// `None` (`Gateway::read_global_exit_node`'s own no-panic contract), which
/// is treated exactly like "no global exit configured".
pub(crate) fn apply_global_exit_and_teardown(
    masked_exit_addr: &Arc<parking_lot::RwLock<Option<String>>>,
    pool_dialer: Option<&Arc<crate::pool_dialer::PoolDialer>>,
    server_config_path: Option<&std::path::Path>,
    db: &ClientDatabase,
) {
    let Some(dialer) = pool_dialer else {
        return;
    };
    let new_global = server_config_path.and_then(Gateway::read_global_exit_node);
    apply_global_exit_swap(masked_exit_addr, Some(dialer), new_global);

    let clients = db.list_clients();
    add_dial_peers_for_client_exits_for(dialer, &clients);
    teardown_unused_exit_dials_for(masked_exit_addr, Some(dialer), &clients);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // --- Wave B2b: per-client exit routing (data plane) -----------------

    /// REGRESSION INVARIANT: with no per-client `exit_node` at all (the
    /// current common case), `choose_exit` must reduce to exactly the
    /// pre-B2b two-way branch on the global default alone — `NoExit` when
    /// unset, otherwise `Send{global, local_fallback:false}` (never locally
    /// egresses on a failed send — matches the pre-B2b silent-drop
    /// behavior). `is_live` must not even be consulted in this case.
    #[test]
    fn choose_exit_no_client_override_matches_pre_b2b_behavior() {
        assert_eq!(
            choose_exit(None, None, |_| panic!("is_live must not be called")),
            ExitDecision::NoExit,
            "no client override and no global default — legacy chain_forwarder/local path"
        );
        assert_eq!(
            choose_exit(None, Some("exit.example.com:443"), |_| panic!(
                "is_live must not be called"
            )),
            ExitDecision::Send {
                addr: "exit.example.com:443".to_string(),
                local_fallback: false,
            },
            "no client override — must use the global default with NO local-egress fallback \
             (byte-identical to the pre-B2b masked_exit_addr-only branch)"
        );
    }

    /// A client with a live per-client `exit_node` override routes to its
    /// own exit, regardless of what the global default is (or isn't).
    #[test]
    fn choose_exit_routes_live_client_override_to_its_own_exit() {
        let decision = choose_exit(
            Some("client-exit-a:51820"),
            Some("global-exit:51820"),
            |addr| addr == "client-exit-a:51820",
        );
        assert_eq!(
            decision,
            ExitDecision::Send {
                addr: "client-exit-a:51820".to_string(),
                local_fallback: true,
            }
        );

        // Also true with no global default configured at all.
        let decision_no_global = choose_exit(Some("client-exit-a:51820"), None, |addr| {
            addr == "client-exit-a:51820"
        });
        assert_eq!(
            decision_no_global,
            ExitDecision::Send {
                addr: "client-exit-a:51820".to_string(),
                local_fallback: true,
            }
        );
    }

    /// A client whose per-client `exit_node` override has no live dial
    /// session falls back to the global default, with local-egress fallback
    /// enabled (unlike the plain-global-default case above).
    #[test]
    fn choose_exit_falls_back_to_global_when_client_override_not_live() {
        let decision = choose_exit(
            Some("client-exit-b:51820"),
            Some("global-exit:51820"),
            |_| false, // nothing is live
        );
        assert_eq!(
            decision,
            ExitDecision::Send {
                addr: "global-exit:51820".to_string(),
                local_fallback: true,
            },
            "per-client override not live — falls back to the global default, with local \
             egress permitted if THAT also fails"
        );
    }

    /// A client whose per-client `exit_node` override has no live session
    /// AND there is no global default either — nothing to route to at all;
    /// the caller falls through to local TUN egress via the `NoExit` path.
    #[test]
    fn choose_exit_no_exit_when_client_override_not_live_and_no_global() {
        let decision = choose_exit(Some("client-exit-c:51820"), None, |_| false);
        assert_eq!(decision, ExitDecision::NoExit);
    }

    /// P1 REST parity fix: `apply_global_exit_and_teardown` — the function
    /// shared by BOTH the in-tunnel path (`dispatch_mgmt_request`) and the
    /// REST/Unix-socket path (`management_api::confirm_config`) — must, in
    /// one call: (1) re-read `pool.exit_node` from a real `server.json` and
    /// swap `masked_exit_addr` to the new value, spawning a live dial for
    /// it; (2) pick up a per-client `exit_node` this node has never dialed
    /// before (Wave B2c parity); and (3) tear down a stale RUNTIME exit dial
    /// nothing references any more, while NEVER touching a startup
    /// `pool.peers` pool-sync dial.
    #[tokio::test]
    async fn apply_global_exit_and_teardown_swaps_adds_and_prunes_in_one_call() {
        use crate::client_db::{ClientDatabase, UpdateClientParams};
        use crate::pool_dialer::PoolDialer;
        use crate::pool_sync::PoolSyncConfig;
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 98, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(ClientDatabase::load(&dir.path().join("clients.json"), network).unwrap());

        let still_referenced_client = db.add_client("still-referenced").unwrap();
        db.update_client(
            &still_referenced_client.id,
            UpdateClientParams {
                exit_node: Some(Some("still-referenced-exit:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        let pool_cfg = PoolSyncConfig {
            peers: vec!["startup-pool-sync-peer:443".to_string()],
            node_id: Some("this-node:443".to_string()),
            sync_port: None,
            sync_key: Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32])),
            exit_node: None,
            exit_node_enabled: None,
            sync_beacon_secs: None,
            transport: Some("masked".to_string()),
            allow_auto_add: None,
            node_identity_key: None,
            require_node_enrollment: None,
            node_ip_partition: None,
        };
        let dialer = PoolDialer::new(db.clone(), &pool_cfg, vec![], None, None)
            .expect("dialer constructs with a valid sync_key + node_id");
        dialer.test_mark_started(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        dialer.test_spawn_startup_peer("startup-pool-sync-peer:443");
        // A stale runtime exit nothing references any more — simulates a
        // previous mgmt round-trip's now-abandoned global/per-client exit.
        dialer.add_peer("stale-unreferenced-exit:51820");

        let server_json = dir.path().join("server.json");
        std::fs::write(
            &server_json,
            r#"{"listen_addr":"0.0.0.0:443","pool":{"exit_node":"new-global-exit.example.com:51820"}}"#,
        )
        .unwrap();

        let masked_exit_addr: Arc<parking_lot::RwLock<Option<String>>> =
            Arc::new(parking_lot::RwLock::new(None));

        apply_global_exit_and_teardown(
            &masked_exit_addr,
            Some(&dialer),
            Some(server_json.as_path()),
            &db,
        );

        assert_eq!(
            *masked_exit_addr.read(),
            Some("new-global-exit.example.com:51820".to_string()),
            "the global default must be swapped in from server.json in one call"
        );
        assert!(
            dialer.is_dialed_peer("new-global-exit.example.com:51820"),
            "the new global exit must get a live dial task"
        );
        assert!(
            dialer.is_dialed_peer("still-referenced-exit:51820"),
            "a per-client exit_node must ALSO go live in the same call (Wave B2c parity)"
        );
        assert!(
            !dialer.is_dialed_peer("stale-unreferenced-exit:51820"),
            "an unreferenced runtime exit must be torn down in the same call"
        );
        assert!(
            dialer.is_dialed_peer("startup-pool-sync-peer:443"),
            "CRITICAL: a startup pool-sync peer must NEVER be torn down by this path"
        );
    }

    /// `apply_global_exit_and_teardown` must be a safe, cheap no-op — never
    /// touching `masked_exit_addr` or reading `server_config_path` — when
    /// `pool_dialer` is `None` (legacy transport / no masked pool-client
    /// dialer on this node).
    #[test]
    fn apply_global_exit_and_teardown_noop_without_pool_dialer() {
        let dir = tempfile::tempdir().unwrap();
        let network = aivpn_common::network_config::VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 99, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            ..Default::default()
        };
        let db = Arc::new(
            crate::client_db::ClientDatabase::load(&dir.path().join("clients.json"), network)
                .unwrap(),
        );
        let server_json = dir.path().join("server.json");
        std::fs::write(
            &server_json,
            r#"{"pool":{"exit_node":"should-be-ignored:51820"}}"#,
        )
        .unwrap();

        let masked_exit_addr: Arc<parking_lot::RwLock<Option<String>>> =
            Arc::new(parking_lot::RwLock::new(None));

        apply_global_exit_and_teardown(&masked_exit_addr, None, Some(server_json.as_path()), &db);

        assert_eq!(
            *masked_exit_addr.read(),
            None,
            "without a pool_dialer, the global exit must never be swapped in"
        );
    }

    // ── Wave B2c: runtime dial add-peer ─────────────────────────────────

    /// No clients at all — `exits_needing_dial` must return an empty `Vec`,
    /// not panic.
    #[test]
    fn exits_needing_dial_empty_when_no_clients() {
        let already = std::collections::HashSet::new();
        assert!(exits_needing_dial(&[], &already).is_empty());
    }

    /// A client with no `exit_node` at all (the common case) contributes
    /// nothing to the result.
    #[test]
    fn exits_needing_dial_ignores_clients_without_exit_node() {
        let mut client = test_client_config("no-exit");
        client.exit_node = None;
        let already = std::collections::HashSet::new();
        assert!(exits_needing_dial(&[client], &already).is_empty());
    }

    /// A client whose `exit_node` is already in `already` (this node is
    /// dialing it) must NOT be returned — the whole point of the diff.
    #[test]
    fn exits_needing_dial_excludes_already_dialed_addresses() {
        let mut client = test_client_config("has-exit");
        client.exit_node = Some("exit-a:51820".to_string());
        let mut already = std::collections::HashSet::new();
        already.insert("exit-a:51820".to_string());
        assert!(exits_needing_dial(&[client], &already).is_empty());
    }

    /// A client whose `exit_node` is NOT in `already` must be returned —
    /// the core "this needs a runtime add_peer" case.
    #[test]
    fn exits_needing_dial_returns_new_exit_addresses() {
        let mut client = test_client_config("has-exit");
        client.exit_node = Some("brand-new-exit:51820".to_string());
        let already = std::collections::HashSet::new();
        assert_eq!(
            exits_needing_dial(&[client], &already),
            vec!["brand-new-exit:51820".to_string()]
        );
    }

    /// Two different clients pointed at the SAME new exit address must
    /// only produce that address once — `add_peer` would be idempotent
    /// anyway, but the diff function itself should not hand the caller
    /// duplicate work.
    #[test]
    fn exits_needing_dial_dedupes_shared_new_exit_across_clients() {
        let mut client_a = test_client_config("client-a");
        client_a.exit_node = Some("shared-exit:51820".to_string());
        let mut client_b = test_client_config("client-b");
        client_b.exit_node = Some("shared-exit:51820".to_string());
        let already = std::collections::HashSet::new();

        let result = exits_needing_dial(&[client_a, client_b], &already);
        assert_eq!(result, vec!["shared-exit:51820".to_string()]);
    }

    /// A mix: one client already dialed, one client with a genuinely new
    /// exit, one client with no exit_node at all — only the genuinely new
    /// address must come back.
    #[test]
    fn exits_needing_dial_mixed_scenario_returns_only_new_addresses() {
        let mut already_dialed = test_client_config("already-dialed");
        already_dialed.exit_node = Some("old-exit:51820".to_string());
        let mut new_exit = test_client_config("new-exit-client");
        new_exit.exit_node = Some("fresh-exit:51820".to_string());
        let no_exit = test_client_config("plain-client");

        let mut already = std::collections::HashSet::new();
        already.insert("old-exit:51820".to_string());

        let result = exits_needing_dial(&[already_dialed, new_exit, no_exit], &already);
        assert_eq!(result, vec!["fresh-exit:51820".to_string()]);
    }

    /// An empty/whitespace-only `exit_node` value must be ignored
    /// defensively (shouldn't occur in practice — `validate_exit_node_addr`
    /// rejects it at write time — but the diff function must not treat it
    /// as a real address to dial).
    #[test]
    fn exits_needing_dial_ignores_blank_exit_node() {
        let mut client = test_client_config("blank-exit");
        client.exit_node = Some("   ".to_string());
        let already = std::collections::HashSet::new();
        assert!(exits_needing_dial(&[client], &already).is_empty());
    }

    /// Minimal `ClientConfig` builder for `exits_needing_dial` unit tests —
    /// only `id`/`exit_node` matter to that function, but a real
    /// `ClientConfig` needs the other fields populated to construct at all.
    /// Mirrors the field set client_db.rs's own tests use to hand-build a
    /// `ClientConfig` (e.g. its `peer_client`/`incoming` test fixtures).
    fn test_client_config(id: &str) -> ClientConfig {
        use crate::client_db::{ClientRole, ClientStats};
        ClientConfig {
            id: id.to_string(),
            name: id.to_string(),
            psk: [0u8; 32],
            vpn_ip: Ipv4Addr::new(10, 99, 0, 2),
            enabled: true,
            created_at: chrono::Utc::now(),
            stats: ClientStats::default(),
            qos: None,
            device_pubkey: None,
            one_time: false,
            expires_at: None,
            updated_at: None,
            deleted: false,
            role: ClientRole::User,
            exit_node: None,
        }
    }
}
