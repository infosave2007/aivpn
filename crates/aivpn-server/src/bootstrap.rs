//! Server bootstrap: takes the parsed CLI args and resolved config, wires up
//! logging, the `Gateway`, the management API, pool-sync/site-to-site, and
//! runs the server until exit.
//!
//! Pure extract-function move from `main()` (ÉTAPE 1 decomposition) — the
//! body below is byte-for-byte the tail of the old `main()`, after all
//! early-return CLI branches. Behavior is unchanged; only the resolver
//! helper calls (`resolve_mask_dir`, `resolve_shaping_level`, etc.) and
//! `load_or_generate_node_identity_seed`, which still live in `main.rs`,
//! are now referenced via `crate::` since they're called from this sibling
//! module instead of from `main()` itself.

use aivpn_common::crypto;
use aivpn_common::event_log::{EventBus, EventSinkConfig};
use aivpn_common::mask::MaskProfile;
use aivpn_common::network_config::VpnNetworkConfig;
use aivpn_server::audit_log::AuditLogger;
#[cfg(feature = "dns")]
use aivpn_server::dns_proxy::DnsProxyConfig;
use aivpn_server::gateway::GatewayConfig;
use aivpn_server::node_registry::NodeRegistry;
use aivpn_server::pool_dialer::PoolDialer;
use aivpn_server::pool_sync::{PeerSyncer, PoolSyncConfig};
use aivpn_server::qos::QosEnforcer;
use aivpn_server::server_config::ServerFileConfig;
use aivpn_server::site_sync::SiteToSiteConfig;
use aivpn_server::{AivpnServer, ClientDatabase, ServerArgs};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info};

/// Runs the server: logging init, `Gateway`/`AivpnServer` construction,
/// management API + pool-sync/site-to-site wiring, then blocks on
/// `server.run()` until shutdown or a fatal error (`std::process::exit`).
///
/// `args`/`config_path`/`file_config`/`effective_tun_mtu`/`network_config`/
/// `bootstrap_masks`/`client_db` are exactly the values `main()` had already
/// resolved before reaching this point (config path resolution, network
/// config, bootstrap masks, and the loaded `ClientDatabase`) — all CLI
/// management commands (`--add-client`, `--list-clients`, etc.) return
/// before `main()` ever calls this function.
pub async fn run_server(
    args: ServerArgs,
    config_path: Option<String>,
    file_config: Option<ServerFileConfig>,
    effective_tun_mtu: u16,
    network_config: VpnNetworkConfig,
    bootstrap_masks: Vec<MaskProfile>,
    client_db: Arc<ClientDatabase>,
) {
    // Initialize logging (only for server mode)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("aivpn_server=debug".parse().unwrap())
                .add_directive("aivpn_common=debug".parse().unwrap()),
        )
        .init();

    info!("AIVPN Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Starting server...");
    info!("Listening on: {}", args.listen);
    info!("Registered clients: {}", client_db.list_clients().len());
    info!(
        "Authoritative VPN subnet: {} (server {}, mtu {})",
        network_config.cidr_string(),
        network_config.server_vpn_ip,
        network_config.mtu,
    );

    // Load server private key from file if provided (HIGH-11)
    let server_private_key = if let Some(ref key_file) = args.key_file {
        let key_data = std::fs::read(key_file).unwrap_or_else(|e| {
            error!("Failed to read key file '{}': {}", key_file, e);
            std::process::exit(1);
        });
        if key_data.len() != 32 {
            error!("Key file must be exactly 32 bytes, got {}", key_data.len());
            std::process::exit(1);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data);
        info!("Loaded server key from file");
        let kp = crypto::KeyPair::from_private_key(key);
        let pub_bytes = kp.public_key_bytes();
        info!(
            "Server public key (hex): {}",
            pub_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        key
    } else {
        info!("No --key-file provided, server key will be ephemeral");
        [0u8; 32]
    };

    // Generate random TUN name if not specified (MED-1: avoids fingerprinting)
    let tun_name = args
        .tun_name
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|config| config.tun_name.clone())
        })
        .unwrap_or_else(|| {
            use rand::Rng;
            format!("tun{:04x}", rand::thread_rng().gen::<u16>())
        });

    let listen_addr = crate::config_resolve::resolve_listen_addr(&args, file_config.as_ref());

    // Clone client_db for management API before moving into GatewayConfig
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_db = client_db.clone();
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_socket = args.management_socket.clone().or_else(|| {
        file_config
            .as_ref()
            .and_then(|c| c.management_socket.clone())
    });
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_pub_key = if server_private_key != [0u8; 32] {
        Some(crypto::KeyPair::from_private_key(server_private_key).public_key_bytes())
    } else {
        None
    };
    // Ed25519 signing (verifying) pubkey for the `sk` field of API-issued
    // connection keys — same derivation as the CLI's
    // `load_server_signing_public_key`, so panel-provisioned clients can
    // verify signed server messages exactly like CLI-provisioned ones.
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_signing_pubkey = if server_private_key != [0u8; 32] {
        Some(
            aivpn_server::gateway::derive_server_signing_key(&server_private_key)
                .verifying_key()
                .to_bytes(),
        )
    } else {
        None
    };
    // Not feature/unix-gated (unlike the rest of the `mgmt_*` locals below):
    // both are also consumed by `GatewayConfig::mgmt_server_addr` /
    // `GatewayConfig::audit_log_path` further down, which feed the in-tunnel
    // `MgmtRequest` dispatch path (`mgmt_service` is unconditional — only
    // the Unix-socket REST `management_api` is behind the feature gate).
    let mgmt_server_addr = args.server_ip.as_ref().map(|ip| {
        if ip.parse::<SocketAddr>().is_ok() {
            ip.clone()
        } else {
            let port = listen_addr
                .parse::<SocketAddr>()
                .map(|a| a.port())
                .unwrap_or(443);
            format!("{}:{}", ip, port)
        }
    });
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_config_path = config_path.as_ref().map(std::path::PathBuf::from);
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_clients_db_path = Some(std::path::PathBuf::from(&args.clients_db));
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_mask_dir = crate::config_resolve::resolve_mask_dir(&args, file_config.as_ref());
    let mgmt_audit_log_path = Some(std::path::PathBuf::from(&args.audit_log));
    // P1 (global exit live-swap): same `config_path` computed above (before
    // `#[cfg(...)]`-gated locals) — not feature/unix-gated, like
    // `mgmt_server_addr`/`mgmt_audit_log_path` above, since it feeds
    // `GatewayConfig::server_config_path`, consumed by the unconditional
    // `mgmt_service` in-tunnel path (`Gateway::dispatch_mgmt_request`'s
    // `apply_global_exit_update`), not just the Unix-socket REST API.
    let server_config_path = config_path.as_ref().map(std::path::PathBuf::from);
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_mask_operator_pubkey =
        crate::config_resolve::resolve_mask_operator_pubkey(&args, file_config.as_ref());
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_mask_verify_mode =
        crate::config_resolve::resolve_mask_verify_mode(&args, file_config.as_ref());
    // 3a: optional GID to chown the management socket's group to (config-only —
    // server.json "management_socket_group"; no CLI flag).
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_socket_group = file_config.as_ref().and_then(|c| c.management_socket_group);

    // Build structured event bus (stdout JSONL sink)
    let event_bus = EventBus::new(EventSinkConfig {
        stdout: true,
        webhook_url: None,
    });

    // Audit logger
    let audit_logger = AuditLogger::new(std::path::Path::new(&args.audit_log));
    // Clone for the management API before GatewayConfig consumes the original,
    // so API mutations are audit-logged with AuditActor::Api.
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_audit_log = audit_logger.clone();

    // Wave B1 (pool topology read endpoints): deferred-fill handles for the
    // REST management API's `ServeConfig`. The REST API is spawned (below,
    // right after `AivpnServer::new()`) BEFORE the pool-sync setup block
    // further down actually constructs `NodeRegistry`/`PoolDialer` (only
    // once `pool.transport == "masked"` is confirmed) — reordering that
    // spawn was judged too invasive for this change. These `Arc<Mutex<
    // Option<..>>>` cells are handed to `ServeConfig` now (read at REST
    // request time) and filled in once, later, right where `main.rs`
    // already calls `server.set_node_registry`/`server.set_pool_dialer` —
    // see `management_api::ServeConfig::pool_registry_slot`'s doc comment
    // for why this sidesteps the ordering problem instead of requiring it.
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_pool_registry_slot: std::sync::Arc<
        parking_lot::Mutex<Option<std::sync::Arc<NodeRegistry>>>,
    > = std::sync::Arc::new(parking_lot::Mutex::new(None));
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_pool_dialer_slot: std::sync::Arc<
        parking_lot::Mutex<Option<std::sync::Arc<PoolDialer>>>,
    > = std::sync::Arc::new(parking_lot::Mutex::new(None));

    // Pool sync — start listener + outbound tasks if pool is configured.
    // An EXPLICITLY passed --pool-config must hard-fail on read/parse errors:
    // silently falling back used to disable pool sync on a simple typo.
    let pool_sync_config: Option<PoolSyncConfig> = match args.pool_config.as_deref() {
        Some(p) => {
            let content = std::fs::read_to_string(p).unwrap_or_else(|e| {
                eprintln!("Failed to read pool config '{}': {}", p, e);
                std::process::exit(1);
            });
            Some(serde_json::from_str(&content).unwrap_or_else(|e| {
                eprintln!("Failed to parse pool config '{}': {}", p, e);
                std::process::exit(1);
            }))
        }
        None => file_config.as_ref().and_then(|c| c.pool.clone()),
    };

    // Wave B-IP: confine this node to a hard, disjoint VPN-IP partition so
    // independent adds on different pool nodes can never collide (see
    // `ClientDatabase::set_node_partition` for the full rationale). An
    // explicit `pool.node_ip_partition` index takes priority — it rules out
    // even a hash collision between two nodes' `node_id`s — falling back to
    // the `node_id`-hash-derived index. No-op if pool sync isn't configured
    // (no node_id/config to derive a partition from).
    if let Some(node_ip_partition) = pool_sync_config.as_ref().and_then(|c| c.node_ip_partition) {
        client_db.set_node_partition_explicit(node_ip_partition, None);
    } else if let Some(ref node_id) = pool_sync_config.as_ref().and_then(|c| c.node_id.clone()) {
        client_db.set_node_partition(node_id);
    }

    // Clone client_db for pool sync before it is consumed by GatewayConfig.
    let client_db_for_sync: Option<Arc<ClientDatabase>> =
        pool_sync_config.as_ref().map(|_| client_db.clone());

    // FORK-B pool-sync DIALER: decode `sync_key` once, up front, reused both
    // to derive the gateway's masked-pool-client recognition keys below and
    // to construct `PoolDialer` further down. Only meaningful when
    // `transport = "masked"` — for the default/legacy transport this stays
    // `None` and `GatewayConfig::pool_server_keypair`/`pool_client_psk` stay
    // `None`, reproducing byte-for-byte the pre-existing behavior.
    let pool_masked_sync_key: Option<[u8; 32]> = pool_sync_config
        .as_ref()
        .filter(|c| c.transport_is_masked())
        .and_then(|c| c.sync_key.as_deref())
        .and_then(|k| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(k).ok()
        })
        .and_then(|b| b.try_into().ok())
        .filter(|k: &[u8; 32]| k != &[0u8; 32]);

    // Build per-client QoS enforcer, pre-loaded from the client DB
    let qos_enforcer = {
        let enforcer = Arc::new(QosEnforcer::new());
        for client in client_db.list_clients() {
            if let Some(qos) = client.qos {
                enforcer.set_client(&client.id, &qos);
            }
        }
        enforcer
    };

    // Keep the QoS enforcer in sync with clients.json hot-reloads. The
    // gateway's reload task (gateway/run_loop.rs, 10s interval) refreshes the
    // DB in memory but has no handle to the enforcer, so QoS edits via CLI
    // (`--set-client-qos`), the REST API, or manual clients.json edits used
    // to apply only after a restart. Syncing is idempotent, so it does not
    // need the reload task's mtime gate — this simply mirrors the DB into
    // the enforcer on the same cadence.
    {
        let enforcer = qos_enforcer.clone();
        let db = client_db.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                enforcer.sync_from_db(&db);
            }
        });
    }

    // Extract values needed after GatewayConfig consumes its inputs
    #[cfg(feature = "dns")]
    let vpn_gateway_ip = std::net::IpAddr::V4(network_config.server_vpn_ip);
    #[cfg(feature = "dns")]
    let tun_iface_for_dns = tun_name.clone();
    let s2s_config: Option<SiteToSiteConfig> =
        file_config.as_ref().and_then(|c| c.site_to_site.clone());
    #[cfg(feature = "dns")]
    let dns_config: Option<DnsProxyConfig> = file_config.as_ref().and_then(|c| c.dns.clone());

    // Create config
    let config = GatewayConfig {
        listen_addr,
        per_ip_pps_limit: args.per_ip_pps_limit,
        tun_name,
        tun_addr: network_config.server_ip_string(),
        tun_netmask: network_config.netmask_string(),
        network_config,
        server_private_key,
        signing_key: [0u8; 64],
        enable_nat: true,
        // Neural Resonance (+ inline ML-DPI gate) on unless server.json
        // explicitly sets "neural_enabled": false.
        enable_neural: file_config
            .as_ref()
            .and_then(|c| c.neural_enabled)
            .unwrap_or(true),
        // Neural/ML-DPI tuning: server.json "neural" block overrides defaults.
        neural_config: file_config
            .as_ref()
            .and_then(|c| c.neural.clone())
            .unwrap_or_default(),
        client_db: Some(client_db),
        mask_dir: crate::config_resolve::resolve_mask_dir(&args, file_config.as_ref()),
        session_timeout_secs: file_config.as_ref().and_then(|c| c.session_timeout_secs),
        idle_timeout_secs: file_config.as_ref().and_then(|c| c.idle_timeout_secs),
        bootstrap_masks,
        tun_mtu: effective_tun_mtu,
        event_bus: event_bus.clone(),
        qos_enforcer,
        chain_forwarder: None,
        mtls: file_config.as_ref().and_then(|c| c.mtls.clone()),
        exit_node_enabled: file_config
            .as_ref()
            .and_then(|c| c.pool.as_ref())
            .map_or(false, |p| p.exit_node_enabled.unwrap_or(false)),
        audit_log: audit_logger, // H-S-8: wire audit logger into gateway
        allow_peer_routing: file_config
            .as_ref()
            .and_then(|c| c.allow_peer_routing)
            .unwrap_or(args.allow_peer_routing),
        feedback_report_failure_threshold: file_config
            .as_ref()
            .and_then(|c| c.feedback.as_ref())
            .and_then(|f| f.report_failure_threshold)
            .unwrap_or(aivpn_server::gateway::DEFAULT_FEEDBACK_FAILURE_THRESHOLD),
        feedback_report_interval_secs: file_config
            .as_ref()
            .and_then(|c| c.feedback.as_ref())
            .and_then(|f| f.report_interval_secs)
            .unwrap_or(aivpn_server::gateway::DEFAULT_FEEDBACK_REPORT_INTERVAL_SECS),
        bootstrap_publish: file_config
            .as_ref()
            .and_then(|c| c.bootstrap_publish.clone()),
        polymorphic_all_sessions: file_config
            .as_ref()
            .and_then(|c| c.polymorphic.as_ref())
            .map(|p| p.all_sessions)
            .unwrap_or(false),
        polymorphic_base_mask: file_config
            .as_ref()
            .and_then(|c| c.polymorphic.as_ref())
            .and_then(|p| p.base_mask.clone()),
        downlink_shaping: crate::config_resolve::resolve_shaping_level(&args, file_config.as_ref()),
        // R2 Phase B: operator mask signing + config-gated verification.
        mask_signing_key: crate::config_resolve::resolve_mask_signing_key(
            &args,
            file_config.as_ref(),
        ),
        mask_operator_pubkey: crate::config_resolve::resolve_mask_operator_pubkey(
            &args,
            file_config.as_ref(),
        ),
        mask_verify_mode: crate::config_resolve::resolve_mask_verify_mode(
            &args,
            file_config.as_ref(),
        ),
        // FORK-B pool-sync masked pool-client recognition: `Some` only when
        // `pool.transport = "masked"` and a valid `sync_key` is configured
        // (see `pool_masked_sync_key` above) — every other configuration
        // (transport unset/"legacy", or no pool config at all) leaves both
        // `None`, matching the gateway's pre-existing byte-for-byte behavior.
        pool_server_keypair: pool_masked_sync_key.map(|k| crypto::pool_server_keypair(&k)),
        pool_client_psk: pool_masked_sync_key.map(|k| crypto::pool_client_psk(&k)),
        // P1.2b: same values threaded into the REST API's `ServeConfig`
        // below (`server_addr`/`audit_log_path`) — cloned here since that
        // `#[cfg(all(feature = "management-api", unix))]` block still moves
        // its own copies out of `mgmt_server_addr`/`mgmt_audit_log_path`.
        mgmt_server_addr: mgmt_server_addr.clone(),
        audit_log_path: mgmt_audit_log_path.clone(),
        // P1 (global exit live-swap): see `server_config_path`'s doc comment
        // above and `GatewayConfig::server_config_path`'s own doc comment.
        server_config_path: server_config_path.clone(),
        // Wave B1 (pool topology read endpoints): whether `server.json` has
        // a `pool` block at all, regardless of transport — see
        // `GatewayConfig::pool_configured`'s doc comment.
        pool_configured: pool_sync_config.is_some(),
    };

    // Create and run server
    match AivpnServer::new(config) {
        Ok(mut server) => {
            // Spawn management API (Unix socket, optional). Placed after
            // AivpnServer::new() so ServeConfig can share the SAME live
            // bootstrap_descriptors Arc as the gateway's rotation task —
            // building a separate copy here would silently go stale after
            // the first rotation.
            #[cfg(all(feature = "management-api", unix))]
            {
                let bootstrap_descriptors = Some(server.bootstrap_descriptors());
                // P1.5: share the SAME PendingConfigManager the gateway's
                // cleanup task sweeps — see `AivpnServer::pending_config`'s
                // doc comment.
                let mgmt_pending_config = Some(server.pending_config());
                // B2b parity fix: share the SAME exit-resolution cache the
                // gateway's in-tunnel `dispatch_mgmt_request` clears after
                // every mutating mgmt call (mirrors `bootstrap_descriptors`/
                // `pending_config` above) — without this, a REST/Unix-socket
                // (web-panel/CLI) `exit_node` change would silently never
                // take effect on the live gateway. See
                // `ServeConfig::exit_route_cache`'s doc comment.
                let mgmt_exit_route_cache = Some(server.exit_route_cache());
                // P1 REST parity fix: share the SAME `masked_exit_addr` cell
                // the gateway's in-tunnel `dispatch_mgmt_request` hot-swaps
                // after every mgmt request (mirrors `mgmt_exit_route_cache`
                // above) — without this, a confirmed `pool.exit_node` change
                // over THIS (REST/Unix-socket) transport would persist to
                // `server.json` but never take effect on the live gateway's
                // routing until a restart. See
                // `ServeConfig::masked_exit_addr`'s doc comment.
                let mgmt_masked_exit_addr = Some(server.masked_exit_addr());
                #[cfg(feature = "metrics")]
                let mgmt_metrics = Some(server.metrics());
                if mgmt_socket.is_some() {
                    let db = mgmt_db.clone();
                    let socket = mgmt_socket.clone();
                    // Wave B1: clone the slots (not move) — the originals
                    // are needed again later, at the pool-sync setup block
                    // that fills them in. See their definition's doc comment.
                    let pool_registry_slot_for_api = mgmt_pool_registry_slot.clone();
                    let pool_dialer_slot_for_api = mgmt_pool_dialer_slot.clone();
                    // Copy (bool), not a move of `pool_sync_config` itself —
                    // that `Option<PoolSyncConfig>` is still needed by
                    // reference later, in the pool-sync setup block.
                    let pool_configured_for_api = pool_sync_config.is_some();
                    let handle = tokio::spawn(async move {
                        aivpn_server::management_api::serve(
                            aivpn_server::management_api::ServeConfig {
                                db: Some(db),
                                socket_path: socket,
                                server_pub_key: mgmt_pub_key,
                                server_addr: mgmt_server_addr,
                                server_signing_pubkey: mgmt_signing_pubkey,
                                config_path: mgmt_config_path,
                                clients_db_path: mgmt_clients_db_path,
                                mask_dir: mgmt_mask_dir,
                                audit_log_path: mgmt_audit_log_path,
                                audit_log: Some(mgmt_audit_log),
                                bootstrap_descriptors,
                                mask_operator_pubkey: mgmt_mask_operator_pubkey,
                                mask_verify_mode: mgmt_mask_verify_mode,
                                #[cfg(feature = "metrics")]
                                metrics: mgmt_metrics,
                                socket_group: mgmt_socket_group,
                                pending_config: mgmt_pending_config,
                                pool_configured: pool_configured_for_api,
                                pool_registry_slot: Some(pool_registry_slot_for_api),
                                pool_dialer_slot: Some(pool_dialer_slot_for_api),
                                exit_route_cache: mgmt_exit_route_cache,
                                masked_exit_addr: mgmt_masked_exit_addr,
                            },
                        )
                        .await;
                    });
                    // Keep handle alive; log if the task exits unexpectedly
                    tokio::spawn(async move {
                        if handle.await.is_err() {
                            error!("Management API task exited unexpectedly");
                        }
                    });
                }

                // SIGHUP → reload client database
                {
                    let db = mgmt_db;
                    // B2b: clear the gateway's exit-resolution cache
                    // whenever this reload actually picked up a change —
                    // otherwise an admin editing `exit_node` directly in
                    // `clients.json` and sending SIGHUP wouldn't take
                    // effect until the periodic 10s hot-reload poll (which
                    // performs the same clear) catches up. See
                    // `Gateway::exit_route_cache`'s doc comment.
                    let exit_route_cache = server.exit_route_cache();
                    tokio::spawn(async move {
                        use tokio::signal::unix::{signal, SignalKind};
                        let mut sighup = match signal(SignalKind::hangup()) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!("Failed to register SIGHUP handler: {}", e);
                                return;
                            }
                        };
                        loop {
                            sighup.recv().await;
                            info!("SIGHUP received — reloading client database");
                            let db = db.clone();
                            let changed =
                                tokio::task::spawn_blocking(move || db.reload_if_changed()).await;
                            if matches!(changed, Ok(true)) {
                                exit_route_cache.clear();
                            }
                        }
                    });
                }
            }

            // Start pool sync after session_manager and mask catalog are initialised.
            // Sync packets ride the existing VPN UDP port — no extra TCP port needed.
            //
            // FORK-B: `transport = "masked"` switches to the new `PoolDialer`
            // (each node dials its peers as a masked, headless pool-client and
            // runs bidirectional DB anti-entropy over that session) INSTEAD OF
            // the legacy mask-independent, push-only `PeerSyncer` — the two
            // are mutually exclusive per node. Any other transport value
            // (including unset, the default) keeps running the exact
            // pre-existing `PeerSyncer` path below, unchanged.
            // PHASE 3 (exit / chain-forward over masked transport): set when
            // the masked-transport branch below already wired
            // `server.set_masked_exit(..)` for a configured `exit_node`, so
            // the legacy dedicated-socket `ChainForwarder` block further
            // down skips building a second, redundant exit path. Stays
            // `false` (and the legacy block runs exactly as before) for the
            // default/legacy transport, or when masked transport has no
            // `exit_node` configured.
            let mut masked_exit_wired = false;
            // BUG E1 fix: tracks whether the masked `PoolDialer` actually
            // STARTED (set true only inside the `PoolDialer::new(..) =>
            // Some(dialer)` success branch below), as opposed to merely
            // being configured (`pool.transport == "masked"`). The
            // site-to-site channel selection further down must key off
            // this — not off the config value — so that a bad/missing
            // `pool.sync_key` (or other `PoolDialer::new` failure) falls
            // back to the working legacy `site_sync::start` path instead of
            // going dark.
            let mut masked_dialer_active = false;
            if let (Some(ref pool_cfg), Some(db)) = (&pool_sync_config, client_db_for_sync) {
                if pool_cfg.transport_is_masked() {
                    // PHASE 3 (site-to-site over masked transport): when
                    // site_to_site is ALSO configured, hand this node's
                    // local_subnets to the dialer so it advertises them as
                    // `RouteSync` over the same masked pool-peer sessions —
                    // reusing pool.peers as the dial set. Empty when
                    // site-to-site isn't configured, which makes the dialer's
                    // RouteSync advertise path a no-op (plain pool-sync-only
                    // masked transport, unchanged from Phase 1/2).
                    let site_local_subnets: Vec<String> = s2s_config
                        .as_ref()
                        .map(|c| c.local_subnets.clone())
                        .unwrap_or_default();

                    // PHASE 3 (exit / chain-forward): `pool.exit_node` is an
                    // independent config knob from `pool.peers` — an
                    // operator may point at an exit node that isn't also a
                    // pool-sync peer. Make sure the dialer's dial set
                    // includes it so a masked pool-client session to the
                    // exit node exists for `ChainForward` to ride. A clone
                    // is cheap here (a handful of small strings) and keeps
                    // `PoolDialer::new`'s existing `&PoolSyncConfig`
                    // interface untouched.
                    // B2b (per-client exit routing): pre-seed the dial set
                    // with every CLIENT's `exit_node` override too (not just
                    // the global default above), so a masked pool-client
                    // dial_loop already exists for any per-client exit an
                    // operator configured before this node started. The
                    // dial set is fixed at `PoolDialer::new` construction —
                    // there is no runtime add-peer yet (that's a later
                    // wave); a per-client exit_node added/changed AFTER
                    // startup that isn't already in this union falls back
                    // to the global default (`choose_exit` in gateway.rs)
                    // until this node restarts.
                    let dialer_cfg: PoolSyncConfig = {
                        let mut cfg = pool_cfg.clone();
                        if let Some(ref exit_node) = pool_cfg.exit_node {
                            if !cfg.peers.iter().any(|p| p == exit_node) {
                                cfg.peers.push(exit_node.clone());
                            }
                        }
                        for client in db.list_clients() {
                            if let Some(ref client_exit) = client.exit_node {
                                if !cfg.peers.iter().any(|p| p == client_exit) {
                                    cfg.peers.push(client_exit.clone());
                                }
                            }
                        }
                        cfg
                    };

                    // PHASE 4 (reverse chain-forward): only an entry node
                    // that actually dials an exit (masked transport AND
                    // `pool.exit_node` configured) needs anywhere to deliver
                    // a reverse-direction `ChainForward` reply — every other
                    // masked-transport node (plain pool-sync peer, or an
                    // exit node itself, which routes replies via its own
                    // `chain_reverse_routes` table instead) leaves this
                    // `None` and the dialer's inbound tap for `ChainForward`
                    // simply drops it.
                    let reverse_downlink_tx = pool_cfg
                        .exit_node
                        .is_some()
                        .then(|| server.chain_reverse_downlink_sender());

                    // PHASE 4 (per-node cryptographic identity): resolve
                    // this node's own durable Ed25519 identity — loaded from
                    // `pool.node_identity_key` if configured, else generated
                    // (and persisted) at `node_identity.key` sibling to the
                    // clients-db file — and hand it to the dialer so it can
                    // sign a `NodeEnrollment` proof for every peer it dials.
                    // Also install the pool-node identity registry
                    // (`pool_nodes.json`, likewise sibling to clients-db) so
                    // the gateway's RECEIVE side can bind/verify peers that
                    // dial IN to us. Both are scoped to masked transport
                    // only — the legacy `PeerSyncer` branch below never
                    // reaches this code, so it stays byte-for-byte
                    // unchanged (no identity, no registry).
                    let node_identity_key_path = pool_cfg
                        .node_identity_key
                        .as_ref()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            Path::new(&args.clients_db).with_file_name("node_identity.key")
                        });
                    let node_identity_seed = crate::cli::node::load_or_generate_node_identity_seed(
                        &node_identity_key_path,
                    );
                    let node_signing_key = crypto::node_identity_from_seed(&node_identity_seed);

                    let pool_nodes_path =
                        Path::new(&args.clients_db).with_file_name("pool_nodes.json");
                    let node_registry = Arc::new(NodeRegistry::load(
                        pool_nodes_path,
                        pool_cfg.allow_auto_add(),
                    ));
                    // Wave B1: fill the REST API's deferred-fill slot (see
                    // that variable's doc comment) BEFORE `node_registry` is
                    // moved into `set_node_registry` below.
                    #[cfg(all(feature = "management-api", unix))]
                    {
                        *mgmt_pool_registry_slot.lock() = Some(node_registry.clone());
                    }
                    server.set_node_registry(node_registry);
                    // D1: enforce crypto-proven node identity in route
                    // authorization when the operator opts in
                    // (pool.require_node_enrollment). Default false keeps the
                    // migration-safe behavior (self-asserted node_id trusted
                    // with a warning) until the whole cluster runs Phase 4.
                    server.set_require_node_enrollment(pool_cfg.require_node_enrollment());

                    if let Some(dialer) = PoolDialer::new(
                        db,
                        &dialer_cfg,
                        site_local_subnets,
                        reverse_downlink_tx,
                        Some(node_signing_key),
                    ) {
                        // BUG E1 fix: the masked dialer actually started —
                        // the site-to-site selection below relies on this,
                        // not on the config-only `transport_is_masked()`.
                        masked_dialer_active = true;

                        // P1.3 (priority pool beacon): give the gateway a
                        // `PoolDialer` handle regardless of whether this
                        // node also dials an exit — `set_masked_exit` below
                        // only wires it for the exit-dialing case. Lets the
                        // admin "revoke" mgmt route trigger an immediate
                        // beacon via `Gateway::trigger_priority_pool_beacon`
                        // on every masked pool-sync node, not just exit
                        // nodes.
                        server.set_pool_dialer(dialer.clone());
                        // Wave B1: fill the REST API's deferred-fill slot —
                        // see `mgmt_pool_registry_slot`'s doc comment.
                        #[cfg(all(feature = "management-api", unix))]
                        {
                            *mgmt_pool_dialer_slot.lock() = Some(dialer.clone());
                        }

                        // PHASE 3: wire the masked exit route BEFORE handing
                        // the dialer's Arc off to `start` (which consumes
                        // it) — `exit_addr` here must be byte-for-byte the
                        // same string just ensured above to be in
                        // `dialer_cfg.peers`, since it doubles as the
                        // `PoolDialer::send_to_peer` lookup key.
                        if let Some(ref exit_node) = pool_cfg.exit_node {
                            server.set_masked_exit(dialer.clone(), exit_node.clone());
                            info!(
                                "Multi-hop: chain forwarding to exit node {} over masked \
                                 pool-client transport",
                                exit_node
                            );
                            masked_exit_wired = true;
                        }

                        // No process-wide graceful-shutdown flag exists yet for
                        // background tasks in this server (the legacy
                        // `PeerSyncer::start` loops likewise run until process
                        // exit) — a fresh, never-flipped `AtomicBool` reproduces
                        // that same "runs until the process exits" behavior
                        // while still satisfying `AivpnClient::run`'s shutdown
                        // signature.
                        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        dialer.start(shutdown);
                        info!(
                            "Pool sync active ({} peers, masked pool-client transport)",
                            dialer_cfg.peers.len()
                        );
                    }
                } else if let Some(syncer) = PeerSyncer::new(db, pool_cfg, event_bus.clone()) {
                    syncer.start(server.session_manager());
                    info!(
                        "Pool sync active ({} peers, in-protocol UDP)",
                        pool_cfg.peers.len()
                    );
                }
            }
            // Multi-hop: create the legacy dedicated-socket chain forwarder
            // if exit_node is configured — but only when the masked
            // transport branch above didn't already wire the exit route via
            // `server.set_masked_exit` (`masked_exit_wired`). Under the
            // default/legacy transport this `if` is always true and the
            // block below runs exactly as before, byte-for-byte.
            if !masked_exit_wired {
                if let Some(ref pool_cfg) = pool_sync_config {
                    if let Some(ref exit_node) = pool_cfg.exit_node {
                        use base64::Engine as _;
                        let sync_key_opt: Option<[u8; 32]> = pool_cfg
                            .sync_key
                            .as_deref()
                            .and_then(|k| base64::engine::general_purpose::STANDARD.decode(k).ok())
                            .and_then(|b| b.try_into().ok())
                            .filter(|k: &[u8; 32]| k != &[0u8; 32]);
                        match sync_key_opt {
                            None => {
                                tracing::error!(
                                    "Multi-hop: pool.sync_key is missing, invalid, or all-zero \
                                     — chain forwarder NOT started (exit_node={})",
                                    exit_node
                                );
                            }
                            Some(sync_key) => {
                                match aivpn_server::chain_forwarder::ChainForwarder::new(
                                    exit_node,
                                    sync_key,
                                    pool_cfg.node_id.as_deref(),
                                )
                                .await
                                {
                                    Some(cf) => {
                                        server.set_chain_forwarder(cf);
                                        info!(
                                            "Multi-hop: chain forwarding to exit node {}",
                                            exit_node
                                        );
                                    }
                                    None => {
                                        error!(
                                            "Multi-hop: chain forwarder FAILED to start \
                                             (exit_node={}) — multi-hop is disabled; see the \
                                             preceding warnings for the cause",
                                            exit_node
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Start site-to-site route sync — pass session_manager so peer sessions are registered.
            //
            // PHASE 3: when the masked `PoolDialer` actually STARTED
            // (`masked_dialer_active`), it already advertises
            // `s2s_config.local_subnets` (and installs peers' routes) over
            // the masked pool-peer sessions — see `site_local_subnets`
            // above. Starting the legacy `site_sync::start` path here TOO
            // would double-advertise routes over two independent channels
            // for the same subnets.
            //
            // BUG E1 fix: this selection used to key off the config-only
            // `pool.transport == "masked"` value. If `PoolDialer::new`
            // failed (missing/invalid/zero `pool.sync_key`, or missing
            // `pool.node_id`) the masked dialer never started, yet
            // site-to-site still took the `init_config_only` branch —
            // silently disabling all outbound route advertising with no
            // fallback, even though the legacy `site_sync::start` path
            // (which uses its own independent per-peer sync_key) would have
            // worked fine. Keying off `masked_dialer_active` — set only in
            // the `PoolDialer::new` success branch above — makes this a
            // real fallback: masked dialer up → masked-only advertising;
            // masked dialer absent or failed to start → legacy
            // `site_sync::start`. Under the default/legacy transport
            // (unset or any value other than exactly "masked"),
            // `masked_dialer_active` stays false and `site_sync` starts
            // exactly as before.
            if let Some(ref s2s_cfg) = s2s_config {
                if masked_dialer_active {
                    // Still populate SITE_CONFIG (needed by
                    // `handle_route_sync`'s allowlist lookup for inbound
                    // RouteSync arriving over the masked pool-peer session)
                    // WITHOUT starting the legacy outbound loops/sessions.
                    aivpn_server::site_sync::init_config_only(s2s_cfg);
                    info!(
                        "Site-to-site active ({} peers, advertised over masked pool-client \
                         transport — legacy site_sync channel not started)",
                        s2s_cfg.peers.len()
                    );
                } else {
                    aivpn_server::site_sync::start(s2s_cfg, server.session_manager());
                    info!("Site-to-site active ({} peers)", s2s_cfg.peers.len());
                }
            }

            // Start DNS-over-HTTPS proxy
            #[cfg(feature = "dns")]
            if let Some(dns_cfg) = dns_config {
                let gw_ip = vpn_gateway_ip;
                let iface = tun_iface_for_dns;
                tokio::spawn(async move {
                    aivpn_server::dns_proxy::run(dns_cfg, gw_ip, iface).await;
                });
            }

            info!("Server initialized successfully");
            if let Err(e) = server.run().await {
                error!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to create server: {}", e);
            std::process::exit(1);
        }
    }
}
