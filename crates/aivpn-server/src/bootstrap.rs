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
use aivpn_server::pool_sync::PoolSyncConfig;
use aivpn_server::qos::QosEnforcer;
use aivpn_server::server_config::ServerFileConfig;
use aivpn_server::site_sync::SiteToSiteConfig;
use aivpn_server::{AivpnServer, ClientDatabase, ServerArgs};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info};

/// Wire the event bus to the configured webhook (`AIVPN_EVENT_WEBHOOK`), if
/// any. Delivery is best-effort: `emit()` hands each serialized JSON event
/// line to an unbounded channel (synchronous, never blocks the data path),
/// and a background task POSTs them one at a time with a hard timeout — a
/// failing endpoint only logs, it can never stall or kill the event path.
/// Requires the `event-webhook` cargo feature (pulls in reqwest); without it
/// a configured URL is rejected loudly instead of silently ignored.
#[cfg(feature = "event-webhook")]
fn install_webhook_forwarder(event_bus: &EventBus) {
    let Some(url) = event_bus.webhook_url().map(str::to_owned) else {
        return;
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    event_bus.set_event_sink(Arc::new(move |line: &str| {
        // A closed receiver (forwarder task died) must never fail emit().
        let _ = tx.send(line.to_owned());
    }));
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("event webhook: failed to build HTTP client: {e}");
                return;
            }
        };
        while let Some(line) = rx.recv().await {
            if let Err(e) = client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(line)
                .send()
                .await
            {
                error!("event webhook: POST to {url} failed: {e}");
            }
        }
    });
    info!("event webhook forwarder installed");
}

#[cfg(not(feature = "event-webhook"))]
fn install_webhook_forwarder(event_bus: &EventBus) {
    if event_bus.webhook_url().is_some() {
        error!(
            "AIVPN_EVENT_WEBHOOK is set, but this server build lacks the `event-webhook` \
             feature — webhook delivery is DISABLED (events go to stdout only)"
        );
    }
}

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

    // Build structured event bus (stdout JSONL sink + optional webhook forwarder,
    // the latter from `AIVPN_EVENT_WEBHOOK` — see `install_webhook_forwarder`).
    let event_bus = EventBus::new(EventSinkConfig::from_env());
    install_webhook_forwarder(&event_bus);

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
    let client_db_for_sync: Option<Arc<ClientDatabase>> = (pool_sync_config.is_some()
        || file_config
            .as_ref()
            .is_some_and(|config| config.site_to_site.is_some()))
    .then(|| client_db.clone());

    // Один sync_key задает ключи распознавания шлюза и исходящих соединений пула.
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

    let site_tun_name = tun_name.clone();
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
        mtls: file_config.as_ref().and_then(|c| c.mtls.clone()),
        exit_node_enabled: file_config
            .as_ref()
            .and_then(|c| c.pool.as_ref())
            .is_some_and(|p| p.exit_node_enabled.unwrap_or(false)),
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
            let _passive_receiver = file_config
                .as_ref()
                .and_then(|config| config.passive_distribution.clone())
                .filter(|config| config.enable)
                .map(|config| {
                    let store = server.mask_store().expect("mask store is initialized");
                    aivpn_server::passive_distribution::spawn_receiver(config, store)
                        .unwrap_or_else(|error| {
                            eprintln!("Passive distribution configuration failed: {error}");
                            std::process::exit(1);
                        })
                });
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

            // Межузловой обмен и площадки используют только handshake-сессии.
            if pool_sync_config.is_some() || s2s_config.is_some() {
                use base64::Engine as _;
                let fail = |message: &str| -> ! {
                    error!("Invalid peer configuration: {message}");
                    std::process::exit(1)
                };
                let db = client_db_for_sync
                    .clone()
                    .unwrap_or_else(|| fail("client database is required"));
                let identity_path = pool_sync_config
                    .as_ref()
                    .and_then(|p| p.node_identity_key.as_ref())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        Path::new(&args.clients_db).with_file_name("node_identity.key")
                    });
                let seed = crate::cli::node::load_or_generate_node_identity_seed(&identity_path);
                let identity = crypto::node_identity_from_seed(&seed);
                let registry = Arc::new(NodeRegistry::load(
                    Path::new(&args.clients_db).with_file_name("pool_nodes.json"),
                    pool_sync_config.as_ref().is_none_or(|p| p.allow_auto_add()),
                ));
                server.set_node_registry(registry.clone());
                let local_node_id = pool_sync_config
                    .as_ref()
                    .and_then(|p| p.node_id.clone())
                    .or_else(|| s2s_config.as_ref().and_then(|s| s.local_name.clone()))
                    .unwrap_or_else(|| fail("node_id or site local_name is required"));
                server.set_local_node_identity(identity.clone(), local_node_id.trim().to_string());
                server.set_require_node_enrollment(
                    pool_sync_config
                        .as_ref()
                        .is_none_or(|p| p.require_node_enrollment()),
                );
                #[cfg(all(feature = "management-api", unix))]
                {
                    *mgmt_pool_registry_slot.lock() = Some(registry.clone());
                }
                let local_subnets = s2s_config
                    .as_ref()
                    .map(|s| s.local_subnets.clone())
                    .unwrap_or_default();
                let dialer = if let Some(pool) = pool_sync_config.as_ref() {
                    if !pool.transport_is_masked() {
                        fail("legacy transport removed; use masked");
                    }
                    let mut config = pool.clone();
                    for endpoint in pool
                        .exit_node
                        .iter()
                        .cloned()
                        .chain(db.list_clients().into_iter().filter_map(|c| c.exit_node))
                    {
                        if !config.peers.contains(&endpoint) {
                            config.peers.push(endpoint);
                        }
                    }
                    PoolDialer::new(
                        db,
                        &config,
                        local_subnets,
                        Some(server.chain_reverse_downlink_sender()),
                        Some(identity),
                    )
                    .unwrap_or_else(|| fail("pool requires a nonzero sync_key and node_id"))
                } else {
                    let site = s2s_config.as_ref().unwrap();
                    let name = site
                        .local_name
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| fail("site_to_site.local_name is required"));
                    PoolDialer::site_only(db, name, local_subnets, true, Some(identity))
                        .unwrap_or_else(|| fail("cannot create site dialer"))
                };
                registry
                    .check_health()
                    .unwrap_or_else(|error| fail(&format!("node registry: {error}")));
                dialer.set_node_registry(registry);
                dialer.set_site_tun_tx(server.site_data_sender());
                if let Some(site) = s2s_config.as_ref() {
                    aivpn_server::site_sync::init_config_only(site, &site_tun_name)
                        .unwrap_or_else(|error| fail(&error));
                    for peer in &site.peers {
                        let key: [u8; 32] = base64::engine::general_purpose::STANDARD
                            .decode(&peer.sync_key)
                            .ok()
                            .and_then(|bytes| bytes.try_into().ok())
                            .filter(|key| *key != [0; 32])
                            .unwrap_or_else(|| {
                                fail("each site peer requires a nonzero 32-byte sync_key")
                            });
                        let keypair = crypto::pool_server_keypair(&key);
                        let psk = crypto::pool_client_psk(&key);
                        server
                            .add_masked_peer_key(
                                keypair.clone(),
                                psk,
                                peer.node_id.clone().unwrap_or_else(|| peer.name.clone()),
                            )
                            .unwrap_or_else(|error| fail(&error.to_string()));
                        dialer.queue_site_peer(
                            peer.endpoint.clone(),
                            keypair,
                            psk,
                            peer.node_id.clone().unwrap_or_else(|| peer.name.clone()),
                        );
                    }
                }
                server.set_pool_dialer(dialer.clone());
                #[cfg(all(feature = "management-api", unix))]
                {
                    *mgmt_pool_dialer_slot.lock() = Some(dialer.clone());
                }
                if let Some(exit) = pool_sync_config.as_ref().and_then(|p| p.exit_node.as_ref()) {
                    server.set_masked_exit(dialer.clone(), exit.clone());
                }
                dialer.start(Arc::new(std::sync::atomic::AtomicBool::new(false)));
                info!("Masked peer transport started");
            }

            // Start DNS-over-HTTPS proxy
            #[cfg(feature = "dns")]
            if let Some(dns_cfg) = dns_config {
                let gw_ip = vpn_gateway_ip;
                let iface = tun_iface_for_dns;
                if dns_cfg.block_plain_dns {
                    if let Err(e) = aivpn_server::dns_proxy::install_block_rule(&iface) {
                        error!("Cannot enforce block_plain_dns: {e}");
                        std::process::exit(1);
                    }
                }
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
