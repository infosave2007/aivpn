//! AIVPN Server Binary

use aivpn_server::server_config::MtuSetting;
use aivpn_server::{ClientDatabase, ServerArgs};
use clap::Parser;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

mod bootstrap;
mod cli;
mod config_resolve;

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
        cli::mask::handle_validate_mask(path);
        return;
    }

    // mTLS CA management — no config or client DB needed.
    if args.gen_ca {
        cli::cert::handle_gen_ca();
        return;
    }
    // R2 Phase B: operator mask-signing key generation — no config needed.
    if let Some(ref path) = args.gen_mask_signing_key {
        cli::mask::handle_gen_mask_signing_key(path);
        return;
    }
    // R2 Phase B: sign a mask corpus in place, then exit.
    if let Some(ref dir) = args.sign_mask_dir {
        cli::mask::handle_sign_mask_dir(dir, &args);
        return;
    }
    if let Some(ref pubkey_hex) = args.issue_cert {
        cli::cert::handle_issue_cert(pubkey_hex, &args);
        return;
    }

    let config_path = config_resolve::resolve_config_path(&args);
    let file_config = config_resolve::load_server_file_config(config_path.as_deref());
    let effective_tun_mtu: u16 = match file_config.as_ref().and_then(|c| c.tun_mtu.as_ref()) {
        Some(MtuSetting::Fixed(v)) => *v,
        Some(MtuSetting::Auto) | None => detect_mtu(),
    };
    let network_config =
        config_resolve::resolve_network_config(file_config.as_ref(), effective_tun_mtu)
            .unwrap_or_else(|e| {
                eprintln!("Failed to resolve VPN network config: {}", e);
                std::process::exit(1);
            });
    let bootstrap_masks =
        cli::mask::load_bootstrap_masks(file_config.as_ref()).unwrap_or_else(|e| {
            eprintln!("Failed to load bootstrap masks: {}", e);
            std::process::exit(1);
        });

    // --list-masks: scan mask directory and print names (no DB needed)
    if args.list_masks {
        cli::mask::handle_list_masks(&args, file_config.as_ref());
        return;
    }

    // --export-bootstrap-descriptor: print signed descriptors, no DB needed
    if args.export_bootstrap_descriptor {
        cli::mask::handle_export_bootstrap_descriptor(&args, &bootstrap_masks);
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
        cli::client::handle_add_client(&client_db, name, &args);
        return;
    }
    if let Some(ref name) = args.add_client_one_time {
        cli::client::handle_add_client_one_time(&client_db, name, &args);
        return;
    }
    if let Some(ref name_or_id) = args.reset_device.clone() {
        cli::client::handle_reset_device(&client_db, &name_or_id);
        return;
    }
    if let Some(ref id) = args.remove_client {
        cli::client::handle_remove_client(&client_db, id);
        return;
    }
    if args.list_clients {
        cli::client::handle_list_clients(&client_db);
        return;
    }
    if let Some(ref id) = args.show_client {
        cli::client::handle_show_client(&client_db, id, &args);
        return;
    }
    // PHASE 4 (per-node crypto identity): --list-nodes / --revoke-node
    // operate on the pool-node identity registry (`pool_nodes.json`,
    // resolved as a sibling of --clients-db — same convention `main()`
    // itself uses when wiring up the masked-transport NodeRegistry). These
    // are CLI-only management commands: run, print, and exit before the
    // gateway starts, exactly like --add-client/--show-client above.
    if args.list_nodes {
        let pool_nodes_path = Path::new(&args.clients_db).with_file_name("pool_nodes.json");
        cli::node::handle_list_nodes(&pool_nodes_path);
        return;
    }
    if let Some(ref node_id) = args.revoke_node {
        let pool_nodes_path = Path::new(&args.clients_db).with_file_name("pool_nodes.json");
        cli::node::handle_revoke_node(&pool_nodes_path, node_id);
        return;
    }
    if let Some(ref output_path) = args.export.clone() {
        cli::backup::handle_export(&args, output_path);
        return;
    }
    if let Some(ref archive_path) = args.import.clone() {
        cli::backup::handle_import(archive_path, args.dry_run, &args);
        return;
    }
    if let Some(ref name_or_id) = args.set_client_qos.clone() {
        cli::client::handle_set_client_qos(&client_db, name_or_id, &args);
        return;
    }
    if let Some(ref name_or_id) = args.enable_client.clone() {
        cli::client::handle_set_client_enabled(&client_db, name_or_id, true);
        return;
    }
    if let Some(ref name_or_id) = args.disable_client.clone() {
        cli::client::handle_set_client_enabled(&client_db, name_or_id, false);
        return;
    }
    if let Some(ref name_or_id) = args.set_client_name.clone() {
        cli::client::handle_set_client_name(&client_db, name_or_id, &args);
        return;
    }
    if let Some(ref name_or_id) = args.set_client_expiry.clone() {
        cli::client::handle_set_client_expiry(&client_db, name_or_id, &args);
        return;
    }
    if let Some(ref name_or_id) = args.set_mask.clone() {
        cli::mask::handle_set_mask(&client_db, name_or_id, &args, file_config.as_ref());
        return;
    }

    bootstrap::run_server(
        args,
        config_path,
        file_config,
        effective_tun_mtu,
        network_config,
        bootstrap_masks,
        client_db,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::network_config::VpnNetworkConfig;
    use aivpn_server::server_config::{JsonNetworkConfig, ServerFileConfig};
    use base64::Engine;
    use std::net::Ipv4Addr;

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
            list_nodes: false,
            revoke_node: None,
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
            priority: None,
            enable_client: None,
            disable_client: None,
            set_client_name: None,
            new_name: None,
            set_client_expiry: None,
            expiry: None,
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
            shaping_level: None,
            role: None,
            device_pubkey: None,
        }
    }

    #[test]
    fn decode_device_pubkey_arg_accepts_valid_32_byte_base64() {
        let raw = [0x42u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(cli::client::decode_device_pubkey_arg(&b64).unwrap(), raw);
    }

    #[test]
    fn decode_device_pubkey_arg_trims_whitespace() {
        let raw = [0x99u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let padded = format!("  {}\n", b64);
        assert_eq!(cli::client::decode_device_pubkey_arg(&padded).unwrap(), raw);
    }

    #[test]
    fn decode_device_pubkey_arg_rejects_wrong_length() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([0x11u8; 16]);
        let err = cli::client::decode_device_pubkey_arg(&b64).unwrap_err();
        assert!(err.contains("32 bytes"), "unexpected error: {}", err);
    }

    #[test]
    fn decode_device_pubkey_arg_rejects_invalid_base64() {
        let err = cli::client::decode_device_pubkey_arg("not!!valid==base64??").unwrap_err();
        assert!(err.contains("base64"), "unexpected error: {}", err);
    }

    #[test]
    fn build_connection_server_addr_keeps_explicit_port() {
        let args = test_args("0.0.0.0:443");
        assert_eq!(
            cli::client::build_connection_server_addr(&args, "203.0.113.10:8443"),
            "203.0.113.10:8443"
        );
    }

    #[test]
    fn build_connection_server_addr_adds_listen_port_once() {
        let args = test_args("0.0.0.0:443");
        assert_eq!(
            cli::client::build_connection_server_addr(&args, "203.0.113.10"),
            "203.0.113.10:443"
        );
    }

    #[test]
    fn build_connection_key_embeds_normalized_server_addr() {
        let args = test_args("0.0.0.0:443");
        let dir = tempfile::tempdir().unwrap();
        let network_config = VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 0, 0, 1),
            prefix_len: 24,
            mtu: 1346,
            keepalive_secs: None,
            ..Default::default()
        };
        let db = ClientDatabase::load(&dir.path().join("clients.json"), network_config).unwrap();
        let client = db.add_client("alice").unwrap();

        let key = cli::client::build_connection_key(
            &db,
            &args,
            &client.id,
            "203.0.113.10:8443",
            [7u8; 32],
        )
        .expect("build_connection_key should succeed for a freshly created client");
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
        let resolved = config_resolve::resolve_network_config(Some(&file_config), 1400).unwrap();
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
        let resolved = config_resolve::resolve_network_config(Some(&file_config), 1280).unwrap();
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
        let resolved = config_resolve::resolve_network_config(Some(&file_config), 1280).unwrap();
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

        let result = cli::mask::load_bootstrap_masks(Some(&file_config));
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

        let result = cli::mask::load_bootstrap_masks(Some(&file_config));
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

        let result = cli::mask::load_bootstrap_masks(Some(&file_config));
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

        let result = cli::mask::load_bootstrap_masks(Some(&file_config));
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
