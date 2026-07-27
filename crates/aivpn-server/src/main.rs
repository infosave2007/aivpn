//! AIVPN Server Binary

use aivpn_common::crypto;
use aivpn_common::event_log::{EventBus, EventSinkConfig};
use aivpn_common::mask::{IATDistType, MaskProfile, SizeDistType};
use aivpn_common::network_config::{netmask_to_prefix_len, ClientNetworkConfig, VpnNetworkConfig};
use aivpn_server::audit_log::AuditLogger;
use aivpn_server::backup::{export_server, import_server, ExportOptions};
#[cfg(feature = "dns")]
use aivpn_server::dns_proxy::DnsProxyConfig;
use aivpn_server::gateway::GatewayConfig;
use aivpn_server::pool_sync::{PeerSyncer, PoolSyncConfig};
use aivpn_server::qos::{dscp_by_name, parse_bandwidth, ClientQos, QosEnforcer};
use aivpn_server::server_config::{MtuSetting, ServerFileConfig};
use aivpn_server::site_sync::SiteToSiteConfig;
use aivpn_server::{AivpnServer, ClientDatabase, ServerArgs};
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info};

const DEFAULT_SERVER_CONFIG_PATH: &str = "/etc/aivpn/server.json";
const LOCAL_SERVER_CONFIG_PATH: &str = "deploy/config/server.json";
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:443";

/// Probe the outbound-interface MTU via `/sys/class/net` and subtract VPN overhead.
/// Falls back to `DEFAULT_TUN_MTU` on any error.
fn detect_mtu() -> u16 {
    let iface = (|| -> Option<String> {
        let out = std::process::Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // "1.1.1.1 via … dev eth0 …" — extract the token after "dev"
        let mut it = text.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "dev" {
                return it.next().map(|s| s.to_string());
            }
        }
        None
    })();

    let physical_mtu: Option<u16> = iface.as_deref().and_then(|dev| {
        let path = format!("/sys/class/net/{dev}/mtu");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
    });

    match physical_mtu {
        Some(mtu) => {
            // 20 IP + 8 UDP + 8 tag + 1 pad_len + 2 inner_hdr + 16 poly1305 = 55; round to 64
            let overhead: u16 = 64;
            let usable = mtu.saturating_sub(overhead);
            if usable < 576 {
                // Physical MTU below the IPv4 minimum after overhead — almost
                // certainly a mis-detected interface; treat like detection
                // failure rather than configuring an unusable TUN MTU.
                info!(
                    "MTU auto-detection: physical={} (dev={}) leaves only {} usable — \
                     ignoring, using default {}",
                    mtu,
                    iface.as_deref().unwrap_or("?"),
                    usable,
                    aivpn_server::nat::DEFAULT_TUN_MTU
                );
                return aivpn_server::nat::DEFAULT_TUN_MTU;
            }
            // Cap at the default, but never floor ABOVE the usable size: a
            // small physical MTU used to be clamped UP to 1200, producing
            // tunnel packets that could not fit the physical link.
            let effective = usable.min(aivpn_server::nat::DEFAULT_TUN_MTU);
            if effective < 1200 {
                tracing::warn!(
                    "MTU auto-detected below the typical 1200 floor (physical={}, tun={}) — \
                     small-MTU link, throughput may suffer",
                    mtu,
                    effective
                );
            }
            info!(
                "MTU auto-detected: physical={} (dev={}) → tun={}",
                mtu,
                iface.as_deref().unwrap_or("?"),
                effective
            );
            effective
        }
        None => {
            info!(
                "MTU auto-detection failed (iface={:?}), using default {}",
                iface,
                aivpn_server::nat::DEFAULT_TUN_MTU
            );
            aivpn_server::nat::DEFAULT_TUN_MTU
        }
    }
}

#[tokio::main]
async fn main() {
    // Parse arguments first (before logging for CLI commands)
    let args = ServerArgs::parse_from(std::env::args());

    // Mask validation doesn't need the server config or client DB.
    if let Some(ref path) = args.validate_mask {
        handle_validate_mask(path);
        return;
    }

    // mTLS CA management — no config or client DB needed.
    if args.gen_ca {
        handle_gen_ca();
        return;
    }
    // R2 Phase B: operator mask-signing key generation — no config needed.
    if let Some(ref path) = args.gen_mask_signing_key {
        handle_gen_mask_signing_key(path);
        return;
    }
    // R2 Phase B: sign a mask corpus in place, then exit.
    if let Some(ref dir) = args.sign_mask_dir {
        handle_sign_mask_dir(dir, &args);
        return;
    }
    if let Some(ref pubkey_hex) = args.issue_cert {
        handle_issue_cert(pubkey_hex, &args);
        return;
    }

    let config_path = resolve_config_path(&args);
    let file_config = load_server_file_config(config_path.as_deref());
    let effective_tun_mtu: u16 = match file_config.as_ref().and_then(|c| c.tun_mtu.as_ref()) {
        Some(MtuSetting::Fixed(v)) => *v,
        Some(MtuSetting::Auto) | None => detect_mtu(),
    };
    let network_config = resolve_network_config(file_config.as_ref(), effective_tun_mtu)
        .unwrap_or_else(|e| {
            eprintln!("Failed to resolve VPN network config: {}", e);
            std::process::exit(1);
        });
    let bootstrap_masks = load_bootstrap_masks(file_config.as_ref()).unwrap_or_else(|e| {
        eprintln!("Failed to load bootstrap masks: {}", e);
        std::process::exit(1);
    });

    // --list-masks: scan mask directory and print names (no DB needed)
    if args.list_masks {
        handle_list_masks(&args, file_config.as_ref());
        return;
    }

    // --export-bootstrap-descriptor: print signed descriptors, no DB needed
    if args.export_bootstrap_descriptor {
        handle_export_bootstrap_descriptor(&args, &bootstrap_masks);
        return;
    }

    // Load client database
    let clients_db_path = Path::new(&args.clients_db);
    let client_db = match ClientDatabase::load(clients_db_path, network_config.clone()) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Failed to load client database: {}", e);
            std::process::exit(1);
        }
    };

    // Handle CLI management commands (no logging needed)
    if let Some(ref name) = args.add_client {
        handle_add_client(&client_db, name, &args);
        return;
    }
    if let Some(ref name) = args.add_client_one_time {
        handle_add_client_one_time(&client_db, name, &args);
        return;
    }
    if let Some(ref name_or_id) = args.reset_device.clone() {
        handle_reset_device(&client_db, &name_or_id);
        return;
    }
    if let Some(ref id) = args.remove_client {
        handle_remove_client(&client_db, id);
        return;
    }
    if args.list_clients {
        handle_list_clients(&client_db);
        return;
    }
    if let Some(ref id) = args.show_client {
        handle_show_client(&client_db, id, &args);
        return;
    }
    if let Some(ref output_path) = args.export.clone() {
        handle_export(&args, output_path);
        return;
    }
    if let Some(ref archive_path) = args.import.clone() {
        handle_import(archive_path, args.dry_run, &args);
        return;
    }
    if let Some(ref name_or_id) = args.set_client_qos.clone() {
        handle_set_client_qos(&client_db, name_or_id, &args);
        return;
    }
    if let Some(ref name_or_id) = args.set_mask.clone() {
        handle_set_mask(&client_db, name_or_id, &args, file_config.as_ref());
        return;
    }

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

    let listen_addr = resolve_listen_addr(&args, file_config.as_ref());

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
    #[cfg(all(feature = "management-api", unix))]
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
    let mgmt_mask_dir = resolve_mask_dir(&args, file_config.as_ref());
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_audit_log_path = Some(std::path::PathBuf::from(&args.audit_log));
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_mask_operator_pubkey = resolve_mask_operator_pubkey(&args, file_config.as_ref());
    #[cfg(all(feature = "management-api", unix))]
    let mgmt_mask_verify_mode = resolve_mask_verify_mode(&args, file_config.as_ref());

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

    // Clone client_db for pool sync before it is consumed by GatewayConfig.
    let client_db_for_sync: Option<Arc<ClientDatabase>> =
        pool_sync_config.as_ref().map(|_| client_db.clone());

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
        mask_dir: resolve_mask_dir(&args, file_config.as_ref()),
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
        downlink_shaping: file_config
            .as_ref()
            .and_then(|c| c.downlink_shaping)
            .unwrap_or(true),
        // R2 Phase B: operator mask signing + config-gated verification.
        mask_signing_key: resolve_mask_signing_key(&args, file_config.as_ref()),
        mask_operator_pubkey: resolve_mask_operator_pubkey(&args, file_config.as_ref()),
        mask_verify_mode: resolve_mask_verify_mode(&args, file_config.as_ref()),
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
                #[cfg(feature = "metrics")]
                let mgmt_metrics = Some(server.metrics());
                if mgmt_socket.is_some() {
                    let db = mgmt_db.clone();
                    let socket = mgmt_socket.clone();
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
                            let _ =
                                tokio::task::spawn_blocking(move || db.reload_if_changed()).await;
                        }
                    });
                }
            }

            // Start pool sync after session_manager and mask catalog are initialised.
            // Sync packets ride the existing VPN UDP port — no extra TCP port needed.
            if let (Some(ref pool_cfg), Some(db)) = (&pool_sync_config, client_db_for_sync) {
                if let Some(syncer) = PeerSyncer::new(db, pool_cfg, event_bus.clone()) {
                    syncer.start(server.session_manager());
                    info!(
                        "Pool sync active ({} peers, in-protocol UDP)",
                        pool_cfg.peers.len()
                    );
                }
            }
            // Multi-hop: create chain forwarder if exit_node is configured
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
                        Some(sync_key) => match aivpn_server::chain_forwarder::ChainForwarder::new(
                            exit_node,
                            sync_key,
                            pool_cfg.node_id.as_deref(),
                        )
                        .await
                        {
                            Some(cf) => {
                                server.set_chain_forwarder(cf);
                                info!("Multi-hop: chain forwarding to exit node {}", exit_node);
                            }
                            None => {
                                error!(
                                    "Multi-hop: chain forwarder FAILED to start \
                                         (exit_node={}) — multi-hop is disabled; see the \
                                         preceding warnings for the cause",
                                    exit_node
                                );
                            }
                        },
                    }
                }
            }

            // Start site-to-site route sync — pass session_manager so peer sessions are registered.
            if let Some(ref s2s_cfg) = s2s_config {
                aivpn_server::site_sync::start(s2s_cfg, server.session_manager());
                info!("Site-to-site active ({} peers)", s2s_cfg.peers.len());
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

fn load_server_public_key(args: &ServerArgs) -> Option<[u8; 32]> {
    args.key_file.as_ref().and_then(|key_file| {
        let key_data = std::fs::read(key_file).ok()?;
        if key_data.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data);
        let kp = crypto::KeyPair::from_private_key(key);
        Some(kp.public_key_bytes())
    })
}

/// The server's ed25519 signing (verifying) public key, base64-standard encoded,
/// derived deterministically from the server private key. Embedded in connection
/// keys as the `sk` field so clients can verify signed server messages.
fn load_server_signing_public_key(args: &ServerArgs) -> Option<String> {
    use base64::Engine;
    let key_file = args.key_file.as_ref()?;
    let key_data = std::fs::read(key_file).ok()?;
    if key_data.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);
    let signing = aivpn_server::gateway::derive_server_signing_key(&key);
    let verifying = signing.verifying_key().to_bytes();
    Some(base64::engine::general_purpose::STANDARD.encode(verifying))
}

// ─── R2 Phase B: operator mask-signing key handling ──────────────────────────

/// Load the operator Ed25519 mask-signing key seed from a file. Accepts raw
/// 32 bytes, or base64-encoded 32 bytes (whitespace-trimmed). Exits with a
/// clear error on a configured-but-unreadable key: silently skipping it would
/// silently ship unsigned masks.
fn load_mask_signing_seed(path: &str) -> [u8; 32] {
    use base64::Engine;
    let data = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("Failed to read mask signing key '{}': {}", path, e);
        std::process::exit(1);
    });
    let bytes: Vec<u8> = if data.len() == 32 {
        data
    } else {
        let text = String::from_utf8_lossy(&data);
        base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .unwrap_or_else(|e| {
                eprintln!(
                    "Mask signing key '{}' is neither raw 32 bytes nor base64: {}",
                    path, e
                );
                std::process::exit(1);
            })
    };
    if bytes.len() != 32 {
        eprintln!(
            "Mask signing key '{}' must decode to 32 bytes, got {}",
            path,
            bytes.len()
        );
        std::process::exit(1);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    seed
}

/// Resolve the operator mask-signing key seed: CLI/env → server.json.
fn resolve_mask_signing_key(
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) -> Option<[u8; 32]> {
    args.mask_signing_key
        .clone()
        .or_else(|| file_config.and_then(|c| c.mask_signing_key.clone()))
        .map(|path| load_mask_signing_seed(&path))
}

/// Resolve the operator mask-verifying public key: CLI/env → server.json →
/// derived from the signing key. Exits on a malformed configured value.
fn resolve_mask_operator_pubkey(
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) -> Option<[u8; 32]> {
    use base64::Engine;
    let explicit = args
        .mask_operator_pubkey
        .clone()
        .or_else(|| file_config.and_then(|c| c.mask_operator_pubkey.clone()));
    if let Some(b64) = explicit {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .unwrap_or_else(|e| {
                eprintln!("Invalid --mask-operator-pubkey (not base64): {}", e);
                std::process::exit(1);
            });
        if bytes.len() != 32 {
            eprintln!(
                "--mask-operator-pubkey must be 32 bytes, got {}",
                bytes.len()
            );
            std::process::exit(1);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Some(key);
    }
    // Derive from the signing key so a single-host setup needs only one flag.
    resolve_mask_signing_key(args, file_config).map(|seed| {
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
    })
}

/// Resolve the mask verification mode: CLI/env → server.json → default (warn).
fn resolve_mask_verify_mode(
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) -> aivpn_common::mask::MaskVerifyMode {
    let raw = args
        .mask_verify_mode
        .clone()
        .or_else(|| file_config.and_then(|c| c.mask_verify_mode.clone()));
    match raw {
        None => aivpn_common::mask::MaskVerifyMode::default(),
        Some(s) => s.parse().unwrap_or_else(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        }),
    }
}

/// `--gen-mask-signing-key PATH`: generate a fresh operator Ed25519 seed,
/// write it base64-encoded to PATH (0600), print the base64 public key.
fn handle_gen_mask_signing_key(path: &str) {
    use base64::Engine;
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    // MEDIUM (server-sec): create the key file atomically with 0600 already
    // set (O_EXCL + mode in a single open()) instead of write-then-chmod —
    // the latter leaves a window where the key briefly exists with the
    // process umask's (often world/group-readable) permissions before the
    // follow-up chmod lands. `create_new` doubles as the existing
    // don't-overwrite check, so the separate `exists()` probe is removed
    // (it was itself a TOCTOU race against this same open()).
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path);
    match opened {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = f.write_all(b64.as_bytes()) {
                eprintln!("Failed to write '{}': {}", path, e);
                std::process::exit(1);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("Refusing to overwrite existing key file '{}'", path);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to create '{}': {}", path, e);
            std::process::exit(1);
        }
    }
    let pubkey = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    println!("✅ Operator mask-signing key written to {}", path);
    println!(
        "   Public key (base64) — distribute to servers (--mask-operator-pubkey)\n   and clients (--mask-operator-pubkey / config mask_operator_pubkey):\n   {}",
        base64::engine::general_purpose::STANDARD.encode(pubkey)
    );
}

/// `--sign-mask-dir DIR`: sign every `*.json` mask in DIR in place (and its
/// nested reverse profile) with the operator key from `--mask-signing-key`, so
/// the corpus survives `mask_verify_mode=enforce`. The reverse profile is signed
/// first because the outer signature covers it.
fn handle_sign_mask_dir(dir: &str, args: &ServerArgs) {
    // Load server.json first so a config-only `mask_signing_key` works here
    // too (previously only the CLI/env flag was consulted).
    let config_path = resolve_config_path(args);
    let file_config = load_server_file_config(config_path.as_deref());
    let seed = match resolve_mask_signing_key(args, file_config.as_ref()) {
        Some(s) => s,
        None => {
            eprintln!("--sign-mask-dir requires --mask-signing-key (or config mask_signing_key)");
            std::process::exit(1);
        }
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Cannot read directory '{dir}': {e}");
            std::process::exit(1);
        }
    };
    let mut signed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  skip {}: read failed: {e}", path.display());
                continue;
            }
        };
        let mut profile: aivpn_common::mask::MaskProfile = match serde_json::from_str(&data) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  skip {}: not a MaskProfile: {e}", path.display());
                continue;
            }
        };
        if let Some(rev) = profile.reverse_profile.as_deref_mut() {
            rev.sign(&key);
        }
        profile.sign(&key);
        match serde_json::to_string_pretty(&profile) {
            Ok(out) => match std::fs::write(&path, out) {
                Ok(()) => {
                    signed += 1;
                    println!("  signed {}", path.display());
                }
                Err(e) => eprintln!("  FAILED {}: write: {e}", path.display()),
            },
            Err(e) => eprintln!("  FAILED {}: serialize: {e}", path.display()),
        }
    }
    println!("✅ Signed {signed} mask(s) in '{dir}' with the operator key.");
}

/// Build a connection key: aivpn://BASE64({"s":"host:port","k":"...","p":"...","i":"...","n":{...}})
fn build_connection_key(
    args: &ServerArgs,
    server_ip: &str,
    server_pub_b64: &str,
    psk_b64: &str,
    client_network_config: ClientNetworkConfig,
) -> String {
    use base64::Engine;
    let server_addr = build_connection_server_addr(args, server_ip);
    let mut json = serde_json::json!({
        "s": server_addr,
        "k": server_pub_b64,
        "p": psk_b64,
        "i": client_network_config.client_ip,
        "n": client_network_config,
    });
    // Embed the server's ed25519 signing (verifying) public key so the client can
    // authenticate bootstrap descriptors / ServerHello / MaskUpdate out of the box
    // (previously verification was unreachable without a manual --server-signing-key).
    if let Some(sk) = load_server_signing_public_key(args) {
        json["sk"] = serde_json::Value::String(sk);
    }
    // R2 Phase B: embed the operator mask-verifying public key (`mop`) so
    // clients can verify the embedded MaskProfile.signature of pushed masks
    // out of the box (default client mode is `warn` — log-only).
    {
        use base64::Engine as _;
        let config_path = resolve_config_path(args);
        let file_config = load_server_file_config(config_path.as_deref());
        if let Some(mop) = resolve_mask_operator_pubkey(args, file_config.as_ref()) {
            json["mop"] =
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(mop));
        }
    }
    let json_bytes = serde_json::to_string(&json).unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_bytes.as_bytes());
    format!("aivpn://{}", encoded)
}

fn build_connection_server_addr(args: &ServerArgs, server_ip: &str) -> String {
    if server_ip.parse::<SocketAddr>().is_ok() {
        return server_ip.to_string();
    }

    let config_path = resolve_config_path(args);
    let file_config = load_server_file_config(config_path.as_deref());
    let listen_addr = resolve_listen_addr(args, file_config.as_ref());

    let port = listen_addr
        .parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(443);

    format!("{}:{}", server_ip, port)
}

fn handle_add_client(db: &ClientDatabase, name: &str, args: &ServerArgs) {
    match db.add_client(name) {
        Ok(client) => {
            use base64::Engine;
            let psk_b64 = base64::engine::general_purpose::STANDARD.encode(&client.psk);
            let server_pub = load_server_public_key(args);
            let client_network_config = db.network_config().client_config(client.vpn_ip).unwrap();

            println!("✅ Client '{}' created!", name);
            println!("   ID:     {}", client.id);
            println!("   VPN IP: {}", client.vpn_ip);
            println!();

            if let (Some(pub_key), Some(ref server_ip)) = (server_pub, &args.server_ip) {
                let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_key);
                let conn_key = build_connection_key(
                    args,
                    server_ip,
                    &pub_b64,
                    &psk_b64,
                    client_network_config,
                );
                println!("══ Connection Key (paste into app) ══");
                println!();
                println!("{}", conn_key);
                println!();
            } else {
                if server_pub.is_none() {
                    eprintln!("⚠  --key-file not provided, cannot generate connection key");
                }
                if args.server_ip.is_none() {
                    eprintln!("⚠  --server-ip not provided, cannot generate connection key");
                    eprintln!("   Use: --server-ip YOUR_PUBLIC_IP or set AIVPN_SERVER_IP env var");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to add client: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_add_client_one_time(db: &ClientDatabase, name: &str, args: &ServerArgs) {
    match db.add_client_one_time(name) {
        Ok(client) => {
            use base64::Engine;
            let psk_b64 = base64::engine::general_purpose::STANDARD.encode(&client.psk);
            let server_pub = load_server_public_key(args);
            let client_network_config = db.network_config().client_config(client.vpn_ip).unwrap();

            println!("✅ One-time enrollment client '{}' created!", name);
            println!("   ID:     {}", client.id);
            println!("   VPN IP: {}", client.vpn_ip);
            println!("   Mode:   One-time (first device to connect will be bound)");
            println!();

            if let (Some(pub_key), Some(ref server_ip)) = (server_pub, &args.server_ip) {
                let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_key);
                let conn_key = build_connection_key(
                    args,
                    server_ip,
                    &pub_b64,
                    &psk_b64,
                    client_network_config,
                );
                println!("══ Connection Key (single-use — share with one device only) ══");
                println!();
                println!("{}", conn_key);
                println!();
            } else {
                if server_pub.is_none() {
                    eprintln!("⚠  --key-file not provided, cannot generate connection key");
                }
                if args.server_ip.is_none() {
                    eprintln!("⚠  --server-ip not provided, cannot generate connection key");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to add one-time client: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_reset_device(db: &ClientDatabase, name_or_id: &str) {
    let client = db
        .list_clients()
        .into_iter()
        .find(|c| c.id == name_or_id || c.name == name_or_id);

    match client {
        Some(c) => match db.reset_device_binding(&c.id) {
            Ok(()) => {
                println!("✅ Device binding reset for '{}'.", name_or_id);
                println!("   Next connecting device will be auto-bound (one-time enrollment).");
            }
            Err(e) => {
                eprintln!("❌ Failed to reset device binding: {}", e);
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("❌ Client '{}' not found.", name_or_id);
            std::process::exit(1);
        }
    }
}

fn handle_remove_client(db: &ClientDatabase, id: &str) {
    // Allow removal by name too
    let actual_id = db
        .list_clients()
        .iter()
        .find(|c| c.id == id || c.name == id)
        .map(|c| c.id.clone());

    match actual_id {
        Some(cid) => match db.remove_client(&cid) {
            Ok(()) => println!("✅ Client '{}' removed.", id),
            Err(e) => {
                eprintln!("❌ Failed to remove: {}", e);
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("❌ Client '{}' not found.", id);
            std::process::exit(1);
        }
    }
}

fn handle_list_clients(db: &ClientDatabase) {
    let clients = db.list_clients();
    if clients.is_empty() {
        println!("No registered clients.");
        println!();
        println!(
            "Add a client: aivpn-server --add-client \"Phone\" --key-file /etc/aivpn/server.key"
        );
        return;
    }

    println!(
        "{:<18} {:<20} {:<12} {:<8} {:<12} {:<12} {}",
        "ID", "NAME", "VPN IP", "STATUS", "UPLOAD", "DOWNLOAD", "LAST SEEN"
    );
    println!("{}", "-".repeat(100));

    for client in &clients {
        let status = if client.enabled { "active" } else { "disabled" };
        let upload = format_bytes(client.stats.bytes_out);
        let download = format_bytes(client.stats.bytes_in);
        let last_seen = client
            .stats
            .last_connected
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        println!(
            "{:<18} {:<20} {:<12} {:<8} {:<12} {:<12} {}",
            client.id, client.name, client.vpn_ip, status, upload, download, last_seen
        );
    }
    println!();
    println!("Total: {} client(s)", clients.len());
}

fn handle_show_client(db: &ClientDatabase, id: &str, args: &ServerArgs) {
    let client = db
        .list_clients()
        .into_iter()
        .find(|c| c.id == id || c.name == id);

    match client {
        Some(client) => {
            use base64::Engine;
            let psk_b64 = base64::engine::general_purpose::STANDARD.encode(&client.psk);
            let server_pub = load_server_public_key(args);
            let client_network_config = db.network_config().client_config(client.vpn_ip);

            println!("Client: {} ({})", client.name, client.id);
            println!("  VPN IP:      {}", client.vpn_ip);
            println!(
                "  Status:      {}",
                if client.enabled { "active" } else { "disabled" }
            );
            println!(
                "  Created:     {}",
                client.created_at.format("%Y-%m-%d %H:%M")
            );
            println!("  Connections: {}", client.stats.total_connections);
            println!("  Upload:      {}", format_bytes(client.stats.bytes_out));
            println!("  Download:    {}", format_bytes(client.stats.bytes_in));
            println!(
                "  Last seen:   {}",
                client
                    .stats
                    .last_connected
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "never".to_string())
            );

            if let (Some(pub_key), Some(ref server_ip)) = (server_pub, &args.server_ip) {
                match client_network_config {
                    Ok(client_network_config) => {
                        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_key);
                        let conn_key = build_connection_key(
                            args,
                            server_ip,
                            &pub_b64,
                            &psk_b64,
                            client_network_config,
                        );
                        println!();
                        println!("══ Connection Key ══");
                        println!();
                        println!("{}", conn_key);
                        println!();
                    }
                    Err(err) => {
                        eprintln!("⚠  Cannot generate connection key for this client under the current VPN subnet: {}", err);
                        eprintln!("   Client VPN IP: {}", client.vpn_ip);
                        eprintln!(
                            "   Current server subnet: {}",
                            db.network_config().cidr_string()
                        );
                        eprintln!("   Reissue this client in the active subnet to get a new key.");
                    }
                }
            } else if args.server_ip.is_none() {
                eprintln!("⚠  --server-ip not provided, cannot generate connection key");
            }
        }
        None => {
            eprintln!("Client '{}' not found.", id);
            std::process::exit(1);
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn load_server_file_config(path: Option<&str>) -> Option<ServerFileConfig> {
    let path = path?;
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read config file '{}': {}", path, e);
        std::process::exit(1);
    });
    Some(serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Failed to parse config file '{}': {}", path, e);
        std::process::exit(1);
    }))
}

fn resolve_config_path(args: &ServerArgs) -> Option<String> {
    if let Some(path) = &args.config {
        return Some(path.clone());
    }

    // Only auto-select a config file that can actually be opened; an existing
    // but unreadable file (e.g. /etc/aivpn/server.json owned by root) must not
    // trigger a hard exit — the server falls back to defaults instead.
    [DEFAULT_SERVER_CONFIG_PATH, LOCAL_SERVER_CONFIG_PATH]
        .iter()
        .find(|path| std::fs::File::open(path).is_ok())
        .map(|path| path.to_string())
}

fn resolve_network_config(
    file_config: Option<&ServerFileConfig>,
    effective_tun_mtu: u16,
) -> aivpn_common::error::Result<VpnNetworkConfig> {
    let config = if let Some(file_config) = file_config {
        if let Some(jnc) = &file_config.network_config {
            // Resolve MTU: "auto"/absent → follow tun_mtu; fixed → clamp to tun_mtu.
            let raw_mtu = match &jnc.mtu {
                Some(MtuSetting::Fixed(v)) => *v,
                Some(MtuSetting::Auto) | None => effective_tun_mtu,
            };
            let mtu = if raw_mtu > effective_tun_mtu {
                tracing::warn!(
                    "network_config.mtu {} > tun_mtu {}, clamping to tun_mtu",
                    raw_mtu,
                    effective_tun_mtu
                );
                effective_tun_mtu
            } else {
                raw_mtu
            };
            VpnNetworkConfig {
                server_vpn_ip: jnc.server_vpn_ip.unwrap_or(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: jnc.prefix_len.unwrap_or(24),
                mtu,
                keepalive_secs: jnc.keepalive_secs,
                ipv6_enabled: jnc.ipv6_enabled,
                ipv6_prefix: jnc.ipv6_prefix.clone(),
            }
        } else {
            VpnNetworkConfig {
                server_vpn_ip: file_config.tun_addr.unwrap_or(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: netmask_to_prefix_len(
                    file_config
                        .tun_netmask
                        .unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
                )?,
                mtu: effective_tun_mtu,
                keepalive_secs: None,
                ipv6_enabled: false,
                ipv6_prefix: "fd10:cafe::/48".to_string(),
            }
        }
    } else {
        VpnNetworkConfig::default()
    };

    config.validate()?;
    Ok(config)
}

fn resolve_listen_addr(args: &ServerArgs, file_config: Option<&ServerFileConfig>) -> String {
    if args.listen == DEFAULT_LISTEN_ADDR {
        file_config
            .and_then(|config| config.listen_addr.clone())
            .unwrap_or_else(|| args.listen.clone())
    } else {
        args.listen.clone()
    }
}

fn load_bootstrap_masks(
    file_config: Option<&ServerFileConfig>,
) -> Result<Vec<MaskProfile>, String> {
    let Some(files) = file_config.and_then(|config| config.bootstrap_mask_files.clone()) else {
        return Ok(Vec::new());
    };

    let mut masks = Vec::new();
    for file in files {
        let content = std::fs::read_to_string(&file).map_err(|e| format!("{}: {}", file, e))?;

        // Trim whitespace to check if file is empty
        let trimmed = content.trim();
        if trimmed.is_empty() {
            // Skip empty files silently
            continue;
        }

        // Try to parse as a single MaskProfile first
        if let Ok(mask) = serde_json::from_str::<MaskProfile>(trimmed) {
            masks.push(mask);
            continue;
        }

        // Try to parse as an array of MaskProfile
        if let Ok(arr) = serde_json::from_str::<Vec<MaskProfile>>(trimmed) {
            masks.extend(arr);
            continue;
        }

        // If both fail, return an error
        return Err(format!(
            "{}: invalid JSON format, expected MaskProfile object or array of MaskProfile objects",
            file
        ));
    }
    Ok(masks)
}

/// --list-masks: print mask JSON filenames from mask-dir
fn handle_list_masks(args: &ServerArgs, file_config: Option<&ServerFileConfig>) {
    let mask_dir = resolve_mask_dir(args, file_config);
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&mask_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
    }
    names.sort();
    if names.is_empty() {
        println!("No masks found in {}", mask_dir.display());
    } else {
        println!(
            "Available masks in {} ({}):",
            mask_dir.display(),
            names.len()
        );
        for name in &names {
            println!("  {}", name);
        }
    }
}

/// --export-bootstrap-descriptor: print the current signed descriptors as a
/// JSON array (identical shape to what already-connected clients receive),
/// for an operator to manually publish to a CDN/GitHub/Telegram/other
/// channel. Requires --key-file: an ephemeral key would produce a descriptor
/// signed by a key nobody's client trusts, so unlike normal server startup
/// (which tolerates an ephemeral key with just a warning), this exits.
fn handle_export_bootstrap_descriptor(args: &ServerArgs, bootstrap_masks: &[MaskProfile]) {
    let Some(ref key_file) = args.key_file else {
        eprintln!("--export-bootstrap-descriptor requires --key-file (an ephemeral server key cannot be exported — no client trusts it)");
        std::process::exit(1);
    };
    let key_data = std::fs::read(key_file).unwrap_or_else(|e| {
        eprintln!("Failed to read key file '{}': {}", key_file, e);
        std::process::exit(1);
    });
    if key_data.len() != 32 {
        eprintln!("Key file must be exactly 32 bytes, got {}", key_data.len());
        std::process::exit(1);
    }
    let mut server_private_key = [0u8; 32];
    server_private_key.copy_from_slice(&key_data);

    let signing_key = aivpn_server::gateway::derive_server_signing_key(&server_private_key);
    let descriptors = aivpn_server::gateway::build_bootstrap_descriptors(
        &server_private_key,
        &signing_key,
        bootstrap_masks,
    );
    let json = serde_json::to_string_pretty(&descriptors).unwrap_or_else(|e| {
        eprintln!("Failed to serialize bootstrap descriptors: {}", e);
        std::process::exit(1);
    });

    match &args.bootstrap_output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &json) {
                eprintln!("Failed to write {}: {}", path, e);
                std::process::exit(1);
            }
            eprintln!(
                "Wrote {} signed bootstrap descriptor(s) to {}",
                descriptors.len(),
                path
            );
        }
        None => println!("{}", json),
    }
}

/// --set-mask NAME_OR_ID --mask-name MASK_NAME: write a mask override file
fn handle_set_mask(
    client_db: &ClientDatabase,
    name_or_id: &str,
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) {
    let mask_name = match args.mask_name.as_deref() {
        Some(n) if !n.is_empty() => n,
        _ => {
            eprintln!("--mask-name is required with --set-mask");
            std::process::exit(1);
        }
    };
    // Validate client exists
    let client = client_db
        .find_by_name(name_or_id)
        .or_else(|| client_db.find_by_id(name_or_id));
    let client = match client {
        Some(c) => c,
        None => {
            eprintln!("Client '{}' not found", name_or_id);
            std::process::exit(1);
        }
    };
    // Validate mask exists (on disk or as a built-in preset)
    let mask_dir = resolve_mask_dir(args, file_config);
    let on_disk = mask_dir.join(format!("{}.json", mask_name)).exists();
    let is_preset = aivpn_common::mask::preset_masks::by_id(mask_name).is_some();
    if !on_disk && !is_preset {
        eprintln!(
            "Mask '{}' not found in {} or built-in presets",
            mask_name,
            mask_dir.display()
        );
        std::process::exit(1);
    }
    // Write override: <mask_dir>/.overrides/<client-id>.mask
    let overrides_dir = mask_dir.join(".overrides");
    if let Err(e) = std::fs::create_dir_all(&overrides_dir) {
        eprintln!("Failed to create overrides dir: {}", e);
        std::process::exit(1);
    }
    let override_path = overrides_dir.join(format!("{}.mask", client.id));
    if let Err(e) = std::fs::write(&override_path, mask_name) {
        eprintln!("Failed to write mask override: {}", e);
        std::process::exit(1);
    }
    println!(
        "Mask override set: client '{}' ({}) → '{}'",
        client.name, client.id, mask_name
    );
}

/// Resolve mask directory: CLI --mask-dir / env AIVPN_MASK_DIR → server.json "mask_dir" → default
const DEFAULT_MASK_DIR: &str = "/var/lib/aivpn/masks";

fn resolve_mask_dir(args: &ServerArgs, file_config: Option<&ServerFileConfig>) -> PathBuf {
    // CLI/env already handled by clap (env = "AIVPN_MASK_DIR")
    if let Some(ref dir) = args.mask_dir {
        return PathBuf::from(dir);
    }
    // server.json
    if let Some(ref dir) = file_config.and_then(|c| c.mask_dir.clone()) {
        return PathBuf::from(dir);
    }
    PathBuf::from(DEFAULT_MASK_DIR)
}

fn handle_export(args: &ServerArgs, output_path: &str) {
    let opts = ExportOptions {
        include_clients: true,
        include_masks: true,
        include_config: true,
        config_path: Some(PathBuf::from(
            args.config.as_deref().unwrap_or("/etc/aivpn/server.json"),
        )),
        mask_dir: Some(PathBuf::from(
            args.mask_dir.as_deref().unwrap_or("/var/lib/aivpn/masks"),
        )),
        clients_db: Some(PathBuf::from(&args.clients_db)),
    };
    match export_server(&opts, std::path::Path::new(output_path)) {
        Ok(()) => println!("✅ Export complete: {}", output_path),
        Err(e) => {
            eprintln!("❌ Export failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_import(archive_path: &str, dry_run: bool, args: &ServerArgs) {
    let target_dir = args
        .config
        .as_deref()
        .and_then(|p| std::path::Path::new(p).parent())
        .unwrap_or(std::path::Path::new("/etc/aivpn"));
    match import_server(std::path::Path::new(archive_path), target_dir, dry_run) {
        Ok(()) => {
            if dry_run {
                println!("✅ Dry-run complete. No files written.");
            } else {
                println!("✅ Import complete.");
            }
        }
        Err(e) => {
            eprintln!("❌ Import failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_set_client_qos(db: &ClientDatabase, name_or_id: &str, args: &ServerArgs) {
    let client = db
        .list_clients()
        .into_iter()
        .find(|c| c.id == name_or_id || c.name == name_or_id);
    let client = match client {
        Some(c) => c,
        None => {
            eprintln!("❌ Client '{}' not found", name_or_id);
            std::process::exit(1);
        }
    };

    let bw_up = args.bw_up.as_deref().and_then(parse_bandwidth);
    let bw_down = args.bw_down.as_deref().and_then(parse_bandwidth);
    let dscp = args.dscp.as_deref().and_then(dscp_by_name);

    if bw_up.is_none() && bw_down.is_none() && dscp.is_none() && args.dscp.is_none() {
        eprintln!("⚠  No QoS parameters specified. Use --bw-up, --bw-down, and/or --dscp.");
        std::process::exit(1);
    }

    let qos = ClientQos {
        bandwidth_limit_up: bw_up,
        bandwidth_limit_down: bw_down,
        dscp_class: dscp,
        priority: None,
    };

    match db.set_client_qos(&client.id, qos) {
        Ok(()) => {
            println!("✅ QoS updated for '{}' ({})", client.name, client.id);
            if let Some(bw) = args.bw_up.as_deref() {
                println!("   Upload limit:   {}", bw);
            }
            if let Some(bw) = args.bw_down.as_deref() {
                println!("   Download limit: {}", bw);
            }
            if let Some(d) = args.dscp.as_deref() {
                println!("   DSCP class:     {}", d);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to set QoS: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_gen_ca() {
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let priv_hex = hex::encode(sk.to_bytes());
    let pub_hex = hex::encode(pk.to_bytes());
    println!("ca_private_key_hex: {priv_hex}");
    println!("ca_public_key_hex:  {pub_hex}");
    println!();
    println!("Add to server.json:");
    println!("  \"mtls\": {{");
    println!("    \"ca_public_key_hex\": \"{pub_hex}\",");
    println!("    \"required\": false");
    println!("  }}");
    println!();
    println!("Keep ca_private_key_hex offline — it is only needed to run --issue-cert.");
}

fn handle_issue_cert(pubkey_hex: &str, args: &ServerArgs) {
    let pk_bytes: [u8; 32] = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!(
                "error: --issue-cert expects a 64-char hex string (32 bytes), got {pubkey_hex:?}"
            );
            std::process::exit(1);
        }
    };

    let ca_key_hex = match args.ca_key.as_deref() {
        Some(h) => h,
        None => {
            eprintln!("error: --ca-key <HEX> is required with --issue-cert");
            std::process::exit(1);
        }
    };

    let ca_bytes: [u8; 32] = match hex::decode(ca_key_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!("error: --ca-key must be a 64-char hex string (32 bytes)");
            std::process::exit(1);
        }
    };

    let expiry_ts = aivpn_common::crypto::current_timestamp_ms() / 1000 + args.days * 86_400;
    let cert = aivpn_server::mtls::issue_cert(pk_bytes, expiry_ts, &ca_bytes);
    let cert_hex = hex::encode(cert.to_bytes());
    println!("{cert_hex}");
    println!();
    println!(
        "cert_hex ({} chars) — pass to aivpn-client via --mtls-cert",
        cert_hex.len()
    );
    println!("or base64-encode for mobile platforms.");
    println!("Expires: {expiry_ts} unix ({} days)", args.days);
}

fn handle_validate_mask(path: &str) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let profile: MaskProfile = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: JSON parse failed in {path}: {e}");
            std::process::exit(1);
        }
    };

    let mut issues: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // signature_vector
    let sig_len = profile.signature_vector.len();
    if sig_len != 64 {
        issues.push(format!("signature_vector: {sig_len} floats (expected 64)"));
    } else if !profile.signature_vector.iter().all(|v| v.is_finite()) {
        issues.push("signature_vector: contains NaN or Inf".to_string());
    } else {
        let l2: f32 = profile
            .signature_vector
            .iter()
            .map(|v| v * v)
            .sum::<f32>()
            .sqrt();
        if l2 == 0.0 {
            warnings.push(
                "signature_vector is all-zeros — neural resonance inactive for this mask"
                    .to_string(),
            );
        }
    }

    // header_template vs eph_pub_offset
    let hdr_len = profile.header_template.len();
    if hdr_len != profile.eph_pub_offset as usize {
        issues.push(format!(
            "header_template length ({hdr_len}) != eph_pub_offset ({})",
            profile.eph_pub_offset
        ));
    }
    if profile.eph_pub_length != 32 {
        warnings.push(format!(
            "eph_pub_length = {} (expected 32 for X25519)",
            profile.eph_pub_length
        ));
    }
    let eph_end = profile.eph_pub_offset as u32 + profile.eph_pub_length as u32;
    if eph_end > 1350 {
        issues.push(format!(
            "eph region ends at byte {eph_end}, which exceeds 1350"
        ));
    }

    // size distribution bins sum
    if matches!(profile.size_distribution.dist_type, SizeDistType::Histogram) {
        let sum: f32 = profile.size_distribution.bins.iter().map(|b| b.2).sum();
        if (sum - 1.0).abs() > 0.02 {
            issues.push(format!(
                "size_distribution bins sum = {sum:.4} (expected 1.0 ± 0.02)"
            ));
        }
    }

    // FSM integrity
    let state_ids: std::collections::HashSet<u16> =
        profile.fsm_states.iter().map(|s| s.state_id).collect();
    if !state_ids.contains(&profile.fsm_initial_state) {
        issues.push(format!(
            "fsm_initial_state {} not found in fsm_states",
            profile.fsm_initial_state
        ));
    }
    for state in &profile.fsm_states {
        for t in &state.transitions {
            if !state_ids.contains(&t.next_state) {
                issues.push(format!(
                    "FSM state {}: transition to unknown state {}",
                    state.state_id, t.next_state
                ));
            }
        }
    }

    // expiry
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_str = if profile.expires_at == u64::MAX {
        "never".to_string()
    } else if profile.expires_at < now_secs {
        let days = (now_secs - profile.expires_at) / 86400;
        issues.push(format!("mask expired {days} day(s) ago"));
        format!("EXPIRED ({days} days ago)")
    } else {
        let days = (profile.expires_at - now_secs) / 86400;
        format!("{days} days remaining")
    };

    // ── Report ────────────────────────────────────────────────────────────
    println!("═══════════════════════════════════════════════════════");
    println!("Mask:     {} (v{})", profile.mask_id, profile.version);
    println!("Protocol: {:?}", profile.spoof_protocol);
    println!(
        "Header:   {} bytes, eph_pub @ {}..{}",
        hdr_len, profile.eph_pub_offset, eph_end
    );
    println!("Expires:  {expires_str}");

    let l2: f32 = if sig_len == 64 {
        profile
            .signature_vector
            .iter()
            .map(|v| v * v)
            .sum::<f32>()
            .sqrt()
    } else {
        0.0
    };
    println!("Sig vec:  {sig_len} floats, L2={l2:.3}");

    println!("───────────────────────────────────────────────────────");

    match profile.size_distribution.dist_type {
        SizeDistType::Histogram => {
            let bins = &profile.size_distribution.bins;
            let sum: f32 = bins.iter().map(|b| b.2).sum();
            println!("Size:     Histogram ({} bins), sum={sum:.3}", bins.len());
            for (lo, hi, p) in bins {
                println!("          [{lo}–{hi}]: {:.1}%", p * 100.0);
            }
        }
        SizeDistType::Parametric => {
            println!(
                "Size:     Parametric ({:?})",
                profile.size_distribution.parametric_type
            );
        }
    }

    let (jlo, jhi) = profile.iat_distribution.jitter_range_ms;
    let iat_type = match profile.iat_distribution.dist_type {
        IATDistType::Exponential => "Exponential",
        IATDistType::LogNormal => "LogNormal",
        IATDistType::Empirical => "Empirical",
        IATDistType::Gamma => "Gamma",
        IATDistType::Gmm => "GMM",
    };
    println!(
        "IAT:      {} params={:?} jitter=[{jlo:.1}, {jhi:.1}] ms",
        iat_type, profile.iat_distribution.params
    );

    println!(
        "FSM:      {} states, initial={}",
        profile.fsm_states.len(),
        profile.fsm_initial_state
    );
    println!("───────────────────────────────────────────────────────");

    for w in &warnings {
        println!("WARN:  {w}");
    }
    if issues.is_empty() {
        if warnings.is_empty() {
            println!("Result: PASS");
        } else {
            println!("Result: PASS (with warnings)");
        }
    } else {
        for issue in &issues {
            println!("FAIL:  {issue}");
        }
        println!("Result: FAIL ({} issue(s))", issues.len());
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_server::server_config::JsonNetworkConfig;
    use base64::Engine;

    fn test_args(listen: &str) -> ServerArgs {
        ServerArgs {
            listen: listen.to_string(),
            tun_name: None,
            key_file: None,
            config: None,
            clients_db: "/tmp/clients.json".to_string(),
            add_client: None,
            remove_client: None,
            list_clients: false,
            show_client: None,
            server_ip: None,
            per_ip_pps_limit: 1000,
            mask_dir: None,
            validate_mask: None,
            #[cfg(all(feature = "management-api", unix))]
            management_socket: None,
            pool_config: None,
            export: None,
            import: None,
            dry_run: false,
            set_client_qos: None,
            bw_up: None,
            bw_down: None,
            dscp: None,
            audit_log: "/dev/null".to_string(),
            gen_ca: false,
            issue_cert: None,
            ca_key: None,
            days: 365,
            add_client_one_time: None,
            reset_device: None,
            allow_peer_routing: false,
            list_masks: false,
            set_mask: None,
            mask_name: None,
            mask_signing_key: None,
            mask_operator_pubkey: None,
            mask_verify_mode: None,
            gen_mask_signing_key: None,
            sign_mask_dir: None,
            export_bootstrap_descriptor: false,
            bootstrap_output: None,
        }
    }

    #[test]
    fn build_connection_server_addr_keeps_explicit_port() {
        let args = test_args("0.0.0.0:443");
        assert_eq!(
            build_connection_server_addr(&args, "203.0.113.10:8443"),
            "203.0.113.10:8443"
        );
    }

    #[test]
    fn build_connection_server_addr_adds_listen_port_once() {
        let args = test_args("0.0.0.0:443");
        assert_eq!(
            build_connection_server_addr(&args, "203.0.113.10"),
            "203.0.113.10:443"
        );
    }

    #[test]
    fn build_connection_key_embeds_normalized_server_addr() {
        let args = test_args("0.0.0.0:443");
        let key = build_connection_key(
            &args,
            "203.0.113.10:8443",
            "server-key",
            "psk",
            ClientNetworkConfig {
                client_ip: Ipv4Addr::new(10, 0, 0, 2),
                server_vpn_ip: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
                mtu: 1346,
                mdh_len: 20,
                keepalive_secs: None,
                ipv6_address: None,
            },
        );
        let payload = key.strip_prefix("aivpn://").unwrap();
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["s"], "203.0.113.10:8443");
        assert_eq!(json["n"]["prefix_len"], 24);
    }

    #[test]
    fn resolve_network_config_prefers_network_config_block() {
        let file_config = ServerFileConfig {
            listen_addr: None,
            tun_name: None,
            tun_addr: Some(Ipv4Addr::new(10, 0, 0, 1)),
            tun_netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            network_config: Some(JsonNetworkConfig {
                server_vpn_ip: Some(Ipv4Addr::new(10, 150, 0, 1)),
                prefix_len: Some(24),
                mtu: Some(MtuSetting::Fixed(1400)),
                ..Default::default()
            }),
            mask_dir: None,
            bootstrap_mask_files: None,
            session_timeout_secs: None,
            idle_timeout_secs: None,
            tun_mtu: None,
            pool: None,
            ..Default::default()
        };

        // effective_tun_mtu=1400 so fixed 1400 is not clamped.
        let resolved = resolve_network_config(Some(&file_config), 1400).unwrap();
        assert_eq!(resolved.server_vpn_ip, Ipv4Addr::new(10, 150, 0, 1));
        assert_eq!(resolved.mtu, 1400);
    }

    #[test]
    fn resolve_network_config_auto_mtu_follows_tun_mtu() {
        let file_config = ServerFileConfig {
            network_config: Some(JsonNetworkConfig {
                server_vpn_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: Some(24),
                mtu: None, // auto
                ..Default::default()
            }),
            ..Default::default()
        };
        // When MTU is absent (auto), network_config.mtu == effective_tun_mtu.
        let resolved = resolve_network_config(Some(&file_config), 1280).unwrap();
        assert_eq!(resolved.mtu, 1280);
    }

    #[test]
    fn resolve_network_config_clamps_oversized_mtu() {
        let file_config = ServerFileConfig {
            network_config: Some(JsonNetworkConfig {
                server_vpn_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: Some(24),
                mtu: Some(MtuSetting::Fixed(1400)),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Fixed 1400 exceeds effective_tun_mtu=1280 → clamped to 1280.
        let resolved = resolve_network_config(Some(&file_config), 1280).unwrap();
        assert_eq!(resolved.mtu, 1280);
    }

    #[test]
    fn load_bootstrap_masks_handles_empty_file() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir().join("aivpn_test_bootstrap_1");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let empty_file = temp_dir.join("empty.json");
        std::fs::File::create(&empty_file)
            .unwrap()
            .write_all(b"")
            .unwrap();

        let file_config = ServerFileConfig {
            listen_addr: None,
            tun_name: None,
            tun_addr: None,
            tun_netmask: None,
            network_config: None,
            mask_dir: None,
            bootstrap_mask_files: Some(vec![empty_file.to_string_lossy().to_string()]),
            session_timeout_secs: None,
            idle_timeout_secs: None,
            tun_mtu: None,
            pool: None,
            ..Default::default()
        };

        let result = load_bootstrap_masks(Some(&file_config));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn load_bootstrap_masks_handles_empty_array() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir().join("aivpn_test_bootstrap_2");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let array_file = temp_dir.join("array.json");
        std::fs::File::create(&array_file)
            .unwrap()
            .write_all(b"[]")
            .unwrap();

        let file_config = ServerFileConfig {
            listen_addr: None,
            tun_name: None,
            tun_addr: None,
            tun_netmask: None,
            network_config: None,
            mask_dir: None,
            bootstrap_mask_files: Some(vec![array_file.to_string_lossy().to_string()]),
            session_timeout_secs: None,
            idle_timeout_secs: None,
            tun_mtu: None,
            pool: None,
            ..Default::default()
        };

        let result = load_bootstrap_masks(Some(&file_config));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn load_bootstrap_masks_handles_single_object() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir().join("aivpn_test_bootstrap_3");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let single_file = temp_dir.join("single.json");
        // Use a real mask profile from mask-assets (simplified but valid)
        let mask_json = r#"{
            "mask_id": "test_mask",
            "version": 2,
            "created_at": 0,
            "expires_at": 18446744073709551615,
            "spoof_protocol": "QUIC",
            "header_template": [192, 0, 0, 0, 1, 8, 73, 142, 56, 201, 15, 88, 197, 42],
            "eph_pub_offset": 14,
            "eph_pub_length": 32,
            "size_distribution": {
                "dist_type": "Histogram",
                "bins": [[64, 128, 0.3], [256, 512, 0.4], [768, 1200, 0.3]],
                "parametric_type": null,
                "parametric_params": null
            },
            "iat_distribution": {
                "dist_type": "Exponential",
                "params": [0.1],
                "jitter_range_ms": [0.0, 10.0]
            },
            "padding_strategy": "MatchDistribution",
            "fsm_states": [{"state_id": 0, "transitions": []}],
            "fsm_initial_state": 0,
            "signature_vector": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            "reverse_profile": null,
            "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "header_spec": {
                "type": "Structured",
                "fields": [
                    {"kind": "Fixed", "bytes": [192]},
                    {"kind": "Fixed", "bytes": [0, 0, 0, 1]},
                    {"kind": "Fixed", "bytes": [8]},
                    {"kind": "Id", "len": 8, "mode": "Random"}
                ]
            }
        }"#;
        std::fs::File::create(&single_file)
            .unwrap()
            .write_all(mask_json.as_bytes())
            .unwrap();

        let file_config = ServerFileConfig {
            listen_addr: None,
            tun_name: None,
            tun_addr: None,
            tun_netmask: None,
            network_config: None,
            mask_dir: None,
            bootstrap_mask_files: Some(vec![single_file.to_string_lossy().to_string()]),
            session_timeout_secs: None,
            idle_timeout_secs: None,
            tun_mtu: None,
            pool: None,
            ..Default::default()
        };

        let result = load_bootstrap_masks(Some(&file_config));
        assert!(result.is_ok());
        let masks = result.unwrap();
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].mask_id, "test_mask");

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn load_bootstrap_masks_handles_array_of_objects() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir().join("aivpn_test_bootstrap_4");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let array_file = temp_dir.join("array.json");
        // Use a real mask profile from mask-assets (simplified but valid)
        let mask_json = r#"[
            {
                "mask_id": "mask1",
                "version": 2,
                "created_at": 0,
                "expires_at": 18446744073709551615,
                "spoof_protocol": "QUIC",
                "header_template": [192, 0, 0, 0, 1, 8, 73, 142, 56, 201, 15, 88, 197, 42],
                "eph_pub_offset": 14,
                "eph_pub_length": 32,
                "size_distribution": {
                    "dist_type": "Histogram",
                    "bins": [[64, 128, 0.3], [256, 512, 0.4], [768, 1200, 0.3]],
                    "parametric_type": null,
                    "parametric_params": null
                },
                "iat_distribution": {
                    "dist_type": "Exponential",
                    "params": [0.1],
                    "jitter_range_ms": [0.0, 10.0]
                },
                "padding_strategy": "MatchDistribution",
                "fsm_states": [{"state_id": 0, "transitions": []}],
                "fsm_initial_state": 0,
                "signature_vector": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
                "reverse_profile": null,
                "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "header_spec": {
                    "type": "Structured",
                    "fields": [
                        {"kind": "Fixed", "bytes": [192]},
                        {"kind": "Fixed", "bytes": [0, 0, 0, 1]}
                    ]
                }
            },
            {
                "mask_id": "mask2",
                "version": 2,
                "created_at": 0,
                "expires_at": 18446744073709551615,
                "spoof_protocol": "WebRTC_STUN",
                "header_template": [0, 1, 0, 0],
                "eph_pub_offset": 4,
                "eph_pub_length": 32,
                "size_distribution": {
                    "dist_type": "Histogram",
                    "bins": [[256, 512, 0.5], [512, 1024, 0.5]],
                    "parametric_type": null,
                    "parametric_params": null
                },
                "iat_distribution": {
                    "dist_type": "Exponential",
                    "params": [0.2],
                    "jitter_range_ms": [0.0, 20.0]
                },
                "padding_strategy": "MatchDistribution",
                "fsm_states": [{"state_id": 0, "transitions": []}],
                "fsm_initial_state": 0,
                "signature_vector": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
                "reverse_profile": null,
                "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "header_spec": null
            }
        ]"#;
        std::fs::File::create(&array_file)
            .unwrap()
            .write_all(mask_json.as_bytes())
            .unwrap();

        let file_config = ServerFileConfig {
            listen_addr: None,
            tun_name: None,
            tun_addr: None,
            tun_netmask: None,
            network_config: None,
            mask_dir: None,
            bootstrap_mask_files: Some(vec![array_file.to_string_lossy().to_string()]),
            session_timeout_secs: None,
            idle_timeout_secs: None,
            tun_mtu: None,
            pool: None,
            ..Default::default()
        };

        let result = load_bootstrap_masks(Some(&file_config));
        assert!(result.is_ok());
        let masks = result.unwrap();
        assert_eq!(masks.len(), 2);
        assert_eq!(masks[0].mask_id, "mask1");
        assert_eq!(masks[1].mask_id, "mask2");

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    /// §3.2 server.json `"polymorphic"` block — mirrors the existing
    /// `"feedback"` block's parsing shape: an optional nested struct with
    /// its own optional/defaulted fields.
    #[test]
    fn polymorphic_block_parses_all_sessions_and_base_mask() {
        let json = r#"{ "polymorphic": { "all_sessions": true, "base_mask": "webrtc_zoom_v3" } }"#;
        let cfg: ServerFileConfig = serde_json::from_str(json).unwrap();
        let poly = cfg.polymorphic.expect("polymorphic block must parse");
        assert!(poly.all_sessions);
        assert_eq!(poly.base_mask.as_deref(), Some("webrtc_zoom_v3"));
    }

    /// Omitted `"polymorphic"` block, or an empty one, must resolve to the
    /// disabled default (`all_sessions: false`, `base_mask: None`) — this is
    /// what `GatewayConfig::default()`'s `polymorphic_all_sessions: false`
    /// depends on when server.json doesn't mention the feature at all.
    #[test]
    fn polymorphic_block_defaults_to_disabled_when_absent_or_empty() {
        let cfg: ServerFileConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.polymorphic.is_none());

        let cfg: ServerFileConfig = serde_json::from_str(r#"{ "polymorphic": {} }"#).unwrap();
        let poly = cfg
            .polymorphic
            .expect("empty polymorphic block must still parse");
        assert!(!poly.all_sessions);
        assert_eq!(poly.base_mask, None);
    }
}
