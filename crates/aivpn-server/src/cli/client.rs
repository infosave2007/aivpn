//! CLI handlers for client (device) management: add/remove/list/show clients,
//! device binding, QoS, enable/disable, rename, expiry, and the shared
//! connection-key-building helpers they use.
//!
//! Pure extract-module move from `main.rs` (ÉTAPE 1 decomposition, step 2).

use aivpn_common::crypto;
use aivpn_server::client_db::{ClientRole, UpdateClientParams};
use aivpn_server::qos::{dscp_by_name, parse_bandwidth, ClientQos};
use aivpn_server::{ClientDatabase, ServerArgs};
use std::net::SocketAddr;

pub(crate) fn load_server_public_key(args: &ServerArgs) -> Option<[u8; 32]> {
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
pub(crate) fn load_server_signing_public_key(args: &ServerArgs) -> Option<String> {
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

/// Build a connection key: aivpn://BASE64({"s":"host:port","k":"...","p":"...","i":"...","n":{...}})
///
/// Thin CLI wrapper: resolves CLI/config-file-based inputs (normalized
/// server address via `build_connection_server_addr`, the server's ed25519
/// signing pubkey, the operator mask-verifying pubkey, the mask dir) and
/// delegates the actual `aivpn://` JSON encoding to the single shared
/// implementation, `aivpn_server::mgmt_service::connection_key` — the same
/// function the REST API's `GET .../connection-key` handler calls. This
/// used to duplicate that handler's JSON-building logic independently;
/// now there is exactly one implementation.
pub(crate) fn build_connection_key(
    db: &ClientDatabase,
    args: &ServerArgs,
    client_id: &str,
    server_ip: &str,
    server_pub_key: [u8; 32],
) -> std::result::Result<String, aivpn_server::mgmt_service::MgmtError> {
    use base64::Engine;
    let server_addr = build_connection_server_addr(args, server_ip);
    let config_path = crate::config_resolve::resolve_config_path(args);
    let file_config = crate::config_resolve::load_server_file_config(config_path.as_deref());
    let server_signing_pubkey = load_server_signing_public_key(args).and_then(|b64| {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
    });
    let mask_operator_pubkey =
        crate::config_resolve::resolve_mask_operator_pubkey(args, file_config.as_ref());
    let mask_dir = crate::config_resolve::resolve_mask_dir(args, file_config.as_ref());
    let ctx = aivpn_server::mgmt_service::MgmtCtx {
        db,
        server_pub_key: Some(server_pub_key),
        server_addr: Some(server_addr),
        server_signing_pubkey,
        mask_operator_pubkey,
        audit: None,
        mask_dir: &mask_dir,
        config_path: config_path.as_deref().map(std::path::Path::new),
        audit_log_path: None,
        pending_config: None,
        // CLI connection-key builder only ever calls
        // `mgmt_service::connection_key`, which never reads `ctx.pool`.
        pool: None,
    };
    aivpn_server::mgmt_service::connection_key(&ctx, client_id)
}

pub(crate) fn build_connection_server_addr(args: &ServerArgs, server_ip: &str) -> String {
    if server_ip.parse::<SocketAddr>().is_ok() {
        return server_ip.to_string();
    }

    let config_path = crate::config_resolve::resolve_config_path(args);
    let file_config = crate::config_resolve::load_server_file_config(config_path.as_deref());
    let listen_addr = crate::config_resolve::resolve_listen_addr(args, file_config.as_ref());

    let port = listen_addr
        .parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(443);

    format!("{}:{}", server_ip, port)
}

/// Parses the `--role` CLI value (`user`/`viewer`/`admin`, case-insensitive).
/// Returns `None` for anything else so the caller can warn and skip.
pub(crate) fn parse_client_role(s: &str) -> Option<ClientRole> {
    match s.to_ascii_lowercase().as_str() {
        "user" => Some(ClientRole::User),
        "viewer" => Some(ClientRole::Viewer),
        "admin" => Some(ClientRole::Admin),
        _ => None,
    }
}

/// Decode a `--device-pubkey` CLI value: standard (non-URL-safe) base64,
/// matching the encoding `client_db.rs` uses for `device_pubkey` in
/// clients.json (see `opt_base64_bytes`). Must decode to exactly 32 bytes.
pub(crate) fn decode_device_pubkey_arg(b64: &str) -> std::result::Result<[u8; 32], String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("--device-pubkey is not valid base64: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "--device-pubkey must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn handle_add_client(db: &ClientDatabase, name: &str, args: &ServerArgs) {
    let device_pubkey = match args.device_pubkey.as_deref().map(decode_device_pubkey_arg) {
        Some(Ok(pk)) => Some(pk),
        Some(Err(e)) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
        None => None,
    };
    let add_result = match device_pubkey {
        Some(pk) => db.add_client_bound(name, pk),
        None => db.add_client(name),
    };
    match add_result {
        Ok(client) => {
            let server_pub = load_server_public_key(args);

            println!("✅ Client '{}' created!", name);
            println!("   ID:     {}", client.id);
            println!("   VPN IP: {}", client.vpn_ip);
            println!();

            if let Some(ref role_str) = args.role {
                match parse_client_role(role_str) {
                    Some(role) if role != ClientRole::User => {
                        match db.update_client(
                            &client.id,
                            UpdateClientParams {
                                role: Some(role),
                                ..Default::default()
                            },
                        ) {
                            Ok(_) => println!("   Role:   {:?}", role),
                            Err(e) => eprintln!(
                                "⚠  Could not set role to {:?} (client has no bound device yet): {}",
                                role, e
                            ),
                        }
                    }
                    Some(_) => {}
                    None => eprintln!(
                        "⚠  Invalid --role '{}' (expected user|viewer|admin), leaving role as 'user'",
                        role_str
                    ),
                }
            }

            if let (Some(pub_key), Some(ref server_ip)) = (server_pub, &args.server_ip) {
                match build_connection_key(db, args, &client.id, server_ip, pub_key) {
                    Ok(conn_key) => {
                        println!("══ Connection Key (paste into app) ══");
                        println!();
                        println!("{}", conn_key);
                        println!();
                    }
                    Err(e) => eprintln!("⚠  Could not generate connection key: {}", e),
                }
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

pub(crate) fn handle_add_client_one_time(db: &ClientDatabase, name: &str, args: &ServerArgs) {
    let device_pubkey = match args.device_pubkey.as_deref().map(decode_device_pubkey_arg) {
        Some(Ok(pk)) => Some(pk),
        Some(Err(e)) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
        None => None,
    };
    // With --device-pubkey, bind at creation instead of waiting for the
    // first connect. one_time enforcement still applies afterward: a
    // different device presenting the PSK will be rejected by
    // enroll_device's mismatch check, same as a post-hoc bind would be.
    let add_result = match device_pubkey {
        Some(pk) => db.add_client_one_time_bound(name, pk),
        None => db.add_client_one_time(name),
    };
    match add_result {
        Ok(client) => {
            let server_pub = load_server_public_key(args);

            println!("✅ One-time enrollment client '{}' created!", name);
            println!("   ID:     {}", client.id);
            println!("   VPN IP: {}", client.vpn_ip);
            println!("   Mode:   One-time (first device to connect will be bound)");
            println!();

            if let (Some(pub_key), Some(ref server_ip)) = (server_pub, &args.server_ip) {
                match build_connection_key(db, args, &client.id, server_ip, pub_key) {
                    Ok(conn_key) => {
                        println!("══ Connection Key (single-use — share with one device only) ══");
                        println!();
                        println!("{}", conn_key);
                        println!();
                    }
                    Err(e) => eprintln!("⚠  Could not generate connection key: {}", e),
                }
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

pub(crate) fn handle_reset_device(db: &ClientDatabase, name_or_id: &str) {
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

pub(crate) fn handle_remove_client(db: &ClientDatabase, id: &str) {
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

pub(crate) fn handle_list_clients(db: &ClientDatabase) {
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

pub(crate) fn handle_show_client(db: &ClientDatabase, id: &str, args: &ServerArgs) {
    let client = db
        .list_clients()
        .into_iter()
        .find(|c| c.id == id || c.name == id);

    match client {
        Some(client) => {
            let server_pub = load_server_public_key(args);

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
                match build_connection_key(db, args, &client.id, server_ip, pub_key) {
                    Ok(conn_key) => {
                        println!();
                        println!("══ Connection Key ══");
                        println!();
                        println!("{}", conn_key);
                        println!();
                    }
                    Err(e) => {
                        eprintln!("⚠  Cannot generate connection key for this client: {}", e);
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

pub(crate) fn format_bytes(bytes: u64) -> String {
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

pub(crate) fn handle_set_client_qos(db: &ClientDatabase, name_or_id: &str, args: &ServerArgs) {
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

    if bw_up.is_none()
        && bw_down.is_none()
        && dscp.is_none()
        && args.dscp.is_none()
        && args.priority.is_none()
    {
        eprintln!(
            "⚠  No QoS parameters specified. Use --bw-up, --bw-down, --dscp, and/or --priority."
        );
        std::process::exit(1);
    }

    let qos = ClientQos {
        bandwidth_limit_up: bw_up,
        bandwidth_limit_down: bw_down,
        dscp_class: dscp,
        priority: args.priority,
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
            if let Some(p) = args.priority {
                println!("   Priority:       {}", p);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to set QoS: {}", e);
            std::process::exit(1);
        }
    }
}

/// Resolve a client by name or ID, or print an error and exit(1).
/// Mirrors the lookup style used by `handle_set_client_qos`.
pub(crate) fn resolve_client_or_exit(
    db: &ClientDatabase,
    name_or_id: &str,
) -> aivpn_server::client_db::ClientConfig {
    db.list_clients()
        .into_iter()
        .find(|c| c.id == name_or_id || c.name == name_or_id)
        .unwrap_or_else(|| {
            eprintln!("❌ Client '{}' not found", name_or_id);
            std::process::exit(1);
        })
}

/// `--enable-client` / `--disable-client`: flip a client's `enabled` flag
/// through the same `ClientDatabase::update_client` path the management API's
/// PATCH /api/v1/clients/:id handler uses.
pub(crate) fn handle_set_client_enabled(db: &ClientDatabase, name_or_id: &str, enabled: bool) {
    let client = resolve_client_or_exit(db, name_or_id);
    match db.update_client(
        &client.id,
        UpdateClientParams {
            enabled: Some(enabled),
            ..Default::default()
        },
    ) {
        Ok(_) => println!(
            "✅ Client '{}' ({}) {}",
            client.name,
            client.id,
            if enabled { "enabled" } else { "disabled" }
        ),
        Err(e) => {
            eprintln!("❌ Failed to update client: {}", e);
            std::process::exit(1);
        }
    }
}

/// `--set-client-name` (with `--new-name`): rename an existing client through
/// the same `ClientDatabase::update_client` path the management API uses.
pub(crate) fn handle_set_client_name(db: &ClientDatabase, name_or_id: &str, args: &ServerArgs) {
    let new_name = match args.new_name.as_deref() {
        Some(n) if !n.trim().is_empty() => n,
        _ => {
            eprintln!("❌ --new-name is required with --set-client-name");
            std::process::exit(1);
        }
    };
    let client = resolve_client_or_exit(db, name_or_id);
    match db.update_client(
        &client.id,
        UpdateClientParams {
            name: Some(new_name.to_string()),
            ..Default::default()
        },
    ) {
        Ok(updated) => println!(
            "✅ Client renamed: '{}' → '{}' ({})",
            client.name, updated.name, updated.id
        ),
        Err(e) => {
            eprintln!("❌ Failed to rename client: {}", e);
            std::process::exit(1);
        }
    }
}

/// `--set-client-expiry` (with `--expiry`): set or clear an existing client's
/// expiry through the same `ClientDatabase::update_client` path the
/// management API uses. An empty `--expiry` value clears the expiry.
pub(crate) fn handle_set_client_expiry(db: &ClientDatabase, name_or_id: &str, args: &ServerArgs) {
    let expiry = match args.expiry.as_deref() {
        Some(e) => e,
        None => {
            eprintln!(
                "❌ --expiry is required with --set-client-expiry \
                 (pass an empty string to clear an existing expiry)"
            );
            std::process::exit(1);
        }
    };
    let expires_at = if expiry.trim().is_empty() {
        None
    } else {
        match chrono::DateTime::parse_from_rfc3339(expiry) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(e) => {
                eprintln!(
                    "❌ Invalid --expiry '{}': {} (expected RFC3339, e.g. 2026-12-31T00:00:00Z)",
                    expiry, e
                );
                std::process::exit(1);
            }
        }
    };
    let client = resolve_client_or_exit(db, name_or_id);
    match db.update_client(
        &client.id,
        UpdateClientParams {
            expires_at: Some(expires_at),
            ..Default::default()
        },
    ) {
        Ok(_) => {
            if let Some(dt) = expires_at {
                println!(
                    "✅ Expiry set for '{}' ({}): {}",
                    client.name,
                    client.id,
                    dt.to_rfc3339()
                );
            } else {
                println!("✅ Expiry cleared for '{}' ({})", client.name, client.id);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to set expiry: {}", e);
            std::process::exit(1);
        }
    }
}
