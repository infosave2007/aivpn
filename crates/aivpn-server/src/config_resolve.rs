//! Config resolution: turns CLI args + optional `server.json` into effective
//! values (config path, network config, listen addr, mask dir, mask
//! signing/verify settings, downlink shaping level).
//!
//! Pure extract-module move from `main.rs` (ÉTAPE 1 decomposition, step 2)
//! — bodies are byte-for-byte the former top-level `main.rs` functions of
//! the same name; only visibility (`pub(crate)`) changed so `main.rs`,
//! `bootstrap.rs`, and the `cli::*` submodules can call them.

use aivpn_common::network_config::{netmask_to_prefix_len, VpnNetworkConfig};
use aivpn_server::server_config::{MtuSetting, ServerFileConfig};
use aivpn_server::ServerArgs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

const DEFAULT_SERVER_CONFIG_PATH: &str = "/etc/aivpn/server.json";
const LOCAL_SERVER_CONFIG_PATH: &str = "deploy/config/server.json";
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:443";

// ─── R2 Phase B: operator mask-signing key handling ──────────────────────────

/// Load the operator Ed25519 mask-signing key seed from a file. Accepts raw
/// 32 bytes, or base64-encoded 32 bytes (whitespace-trimmed). Exits with a
/// clear error on a configured-but-unreadable key: silently skipping it would
/// silently ship unsigned masks.
pub(crate) fn load_mask_signing_seed(path: &str) -> [u8; 32] {
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
pub(crate) fn resolve_mask_signing_key(
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
pub(crate) fn resolve_mask_operator_pubkey(
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
pub(crate) fn resolve_mask_verify_mode(
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

/// Resolve the downlink shaping level (1c): CLI/env → server.json → default
/// (`Full`, matching the historical `downlink_shaping: true`/absent behavior).
pub(crate) fn resolve_shaping_level(
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) -> aivpn_server::gateway::ShapingLevel {
    if let Some(s) = &args.shaping_level {
        return s.parse().unwrap_or_else(|e: String| {
            eprintln!("--shaping-level: {}", e);
            std::process::exit(1);
        });
    }
    file_config
        .and_then(|c| c.downlink_shaping)
        .unwrap_or_default()
}

/// Loads and parses `server.json` at startup. Deliberately LENIENT about
/// unknown top-level keys: a config that survived one or more upgrades
/// commonly carries a field a past release removed (e.g. `max_sessions`,
/// `default_mask`), and refusing to boot over that is a deployment-breaking
/// regression, not a useful guard — unlike `PUT /api/v1/config`'s validator
/// in `management_api.rs`, which stays strict because a body submitted there
/// is a live, operator-authored write where a stray key is almost certainly a
/// typo. See `server_config.rs`'s module doc for the full rationale.
///
/// Known fields are still fully type-checked (a wrong-typed value is still a
/// hard parse error, same as before) — only *unrecognized keys* are
/// tolerated, and only after warning about them so the operator can clean up
/// the file.
pub(crate) fn load_server_file_config(path: Option<&str>) -> Option<ServerFileConfig> {
    let path = path?;
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read config file '{}': {}", path, e);
        std::process::exit(1);
    });
    let value: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Failed to parse config file '{}': {}", path, e);
        std::process::exit(1);
    });
    let unknown = aivpn_server::server_config::unknown_top_level_keys(&value);
    if !unknown.is_empty() {
        // `tracing_subscriber` isn't initialized yet this early in `main`
        // (it's set up after config load), so a `tracing::warn!` here would
        // silently vanish. `eprintln!` is guaranteed visible, matching the
        // other startup-time diagnostics in this function.
        eprintln!(
            "Warning: config file '{}' has unknown top-level key(s), ignoring: {}",
            path,
            unknown.join(", ")
        );
    }
    Some(serde_json::from_value(value).unwrap_or_else(|e| {
        eprintln!("Failed to parse config file '{}': {}", path, e);
        std::process::exit(1);
    }))
}

pub(crate) fn resolve_config_path(args: &ServerArgs) -> Option<String> {
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

pub(crate) fn resolve_network_config(
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

pub(crate) fn resolve_listen_addr(
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) -> String {
    if args.listen == DEFAULT_LISTEN_ADDR {
        file_config
            .and_then(|config| config.listen_addr.clone())
            .unwrap_or_else(|| args.listen.clone())
    } else {
        args.listen.clone()
    }
}

/// Resolve mask directory: CLI --mask-dir / env AIVPN_MASK_DIR → server.json "mask_dir" → default
const DEFAULT_MASK_DIR: &str = "/var/lib/aivpn/masks";

pub(crate) fn resolve_mask_dir(
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) -> PathBuf {
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
