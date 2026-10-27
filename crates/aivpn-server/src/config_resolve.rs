//! Постоянные настройки: явный CLI, затем env, server.json и defaults.

use aivpn_common::network_config::{netmask_to_prefix_len, VpnNetworkConfig};
use aivpn_server::server_config::{MtuSetting, ServerFileConfig};
use aivpn_server::ServerArgs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

const DEFAULT_SERVER_CONFIG_PATH: &str = "/etc/aivpn/server.json";
const LOCAL_SERVER_CONFIG_PATH: &str = "deploy/config/server.json";

mod runtime;
pub(crate) use runtime::{collect_environment, resolve_with_env};

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

/// Определить режим проверки: CLI/env имеют приоритет над server.json.
/// production-secure отклоняет off/warn и отсутствие ключа подписи.
pub(crate) fn resolve_mask_verify_mode(
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) -> aivpn_common::mask::MaskVerifyMode {
    let signing = args
        .mask_signing_key
        .clone()
        .or_else(|| file_config.and_then(|c| c.mask_signing_key.clone()));
    let pubkey = args
        .mask_operator_pubkey
        .clone()
        .or_else(|| file_config.and_then(|c| c.mask_operator_pubkey.clone()));
    let mode = args
        .mask_verify_mode
        .clone()
        .or_else(|| file_config.and_then(|c| c.mask_verify_mode.clone()));
    match aivpn_server::server_config::resolved_mask_verify_mode(
        signing.as_deref(),
        pubkey.as_deref(),
        mode.as_deref(),
    ) {
        Ok(resolved) => resolved,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

/// Приоритет политики: CLI/env, server.json, затем adaptive.
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

/// При запуске устаревшие поля файла допустимы, известные поля проверяет resolver.
pub(crate) fn load_server_config_value(path: Option<&str>) -> serde_json::Value {
    let Some(path) = path else {
        return serde_json::json!({});
    };
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read config file '{}': {}", path, e);
        std::process::exit(1);
    });
    let value: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|_| {
        eprintln!("config: неверный JSON в файле");
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
    value
}

pub(crate) fn resolve_config_path(args: &ServerArgs) -> Option<String> {
    if let Some(path) = &args.config {
        return Some(path.clone());
    }
    if let Ok(path) = std::env::var("AIVPN_CONFIG").or_else(|_| std::env::var("AIVPN_CONFIG_PATH"))
    {
        return Some(path);
    }

    // Only auto-select a config file that can actually be opened; an existing
    // but unreadable file (e.g. /etc/aivpn/server.json owned by root) must not
    // trigger a hard exit — the server falls back to defaults instead.
    [DEFAULT_SERVER_CONFIG_PATH, LOCAL_SERVER_CONFIG_PATH]
        .iter()
        .find(|path| std::fs::File::open(path).is_ok())
        .map(|path| path.to_string())
}

/// Восстановление не читает файл, который само должно заменить.
pub(crate) fn apply_restore_env(args: &mut ServerArgs, matches: &clap::ArgMatches) {
    use clap::parser::ValueSource;
    let text = |key: &str, nullable: bool| {
        let raw = match std::env::var(key) {
            Ok(raw) => raw,
            Err(std::env::VarError::NotPresent) => return None,
            Err(std::env::VarError::NotUnicode(_)) => {
                eprintln!("{key}: значение должно быть UTF-8");
                std::process::exit(1);
            }
        };
        match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(serde_json::Value::Null) if nullable => None,
            Ok(serde_json::Value::String(value)) => Some(value),
            _ => Some(raw),
        }
    };
    if matches.value_source("config") != Some(ValueSource::CommandLine) {
        args.config = text("AIVPN_CONFIG", false).or_else(|| text("AIVPN_CONFIG_PATH", false));
    }
    if matches.value_source("clients_db") != Some(ValueSource::CommandLine) {
        if let Some(path) = text("AIVPN_CLIENTS_DB", true) {
            args.clients_db = path;
        }
    }
    if matches.value_source("mask_dir") != Some(ValueSource::CommandLine) {
        args.mask_dir = text("AIVPN_MASK_DIR", true);
    }
}

/// Выбирает только пути назначения recovery. Остальные настройки, ключи и DB
/// могут быть повреждены и не нужны для восстановления из проверенного архива.
pub(crate) fn resolve_import_paths(
    args: &mut ServerArgs,
    matches: &clap::ArgMatches,
) -> Result<(), String> {
    use clap::parser::ValueSource;
    fn environment(name: &str) -> Result<Option<Option<String>>, String> {
        let raw = match std::env::var(name) {
            Ok(raw) => raw,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err(format!("{name}: значение должно быть UTF-8")),
        };
        Ok(Some(
            match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(serde_json::Value::Null) => None,
                Ok(serde_json::Value::String(value)) => Some(value),
                _ => Some(raw),
            },
        ))
    }
    fn target(
        field: &str,
        override_value: Option<Option<String>>,
        file: Option<&serde_json::Map<String, serde_json::Value>>,
        default: Option<String>,
    ) -> Result<Option<String>, String> {
        let value = match override_value {
            Some(value) => value.or(default),
            None => match file.and_then(|file| file.get(field)) {
                None | Some(serde_json::Value::Null) => default,
                Some(serde_json::Value::String(value)) => Some(value.clone()),
                _ => return Err(format!("{field}: нужен путь назначения восстановления")),
            },
        };
        if value.as_ref().is_some_and(|value| value.trim().is_empty()) {
            return Err(format!("{field}: пустой путь назначения восстановления"));
        }
        Ok(value)
    }
    let default_database = args.clients_db.clone();
    let default_masks = args.mask_dir.clone();
    let database_override = if matches.value_source("clients_db") == Some(ValueSource::CommandLine)
    {
        Some(Some(args.clients_db.clone()))
    } else {
        environment("AIVPN_CLIENTS_DB")?
    };
    let masks_override = if matches.value_source("mask_dir") == Some(ValueSource::CommandLine) {
        Some(args.mask_dir.clone())
    } else {
        environment("AIVPN_MASK_DIR")?
    };
    apply_restore_env(args, matches);
    // Для recovery существующий, но нечитаемый файл тоже является источником,
    // который нельзя молча заменить defaults. Обычный startup выбирает иначе.
    let config_path = args.config.clone().unwrap_or_else(|| {
        [DEFAULT_SERVER_CONFIG_PATH, LOCAL_SERVER_CONFIG_PATH]
            .into_iter()
            .find(|path| {
                !matches!(std::fs::symlink_metadata(path), Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound)
            })
            .unwrap_or(DEFAULT_SERVER_CONFIG_PATH)
            .to_string()
    });
    let absent = matches!(std::fs::symlink_metadata(&config_path), Err(error)
        if error.kind() == std::io::ErrorKind::NotFound);
    let file = if absent {
        Some(serde_json::json!({}))
    } else {
        std::fs::read(&config_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .filter(serde_json::Value::is_object)
    };
    let explicit_path = |value: &Option<Option<String>>| {
        value
            .as_ref()
            .and_then(Option::as_ref)
            .is_some_and(|value| !value.trim().is_empty())
    };
    if file.is_none() && !(explicit_path(&database_override) && explicit_path(&masks_override)) {
        return Err("config: пути восстановления неизвестны; задайте явно --clients-db и --mask-dir или AIVPN_CLIENTS_DB и AIVPN_MASK_DIR".to_string());
    }
    let object = file.as_ref().and_then(serde_json::Value::as_object);
    args.clients_db = target(
        "clients_db",
        database_override,
        object,
        Some(default_database),
    )?
    .expect("Для DB всегда задан встроенный путь");
    args.mask_dir = target("mask_dir", masks_override, object, default_masks)?;
    args.config = Some(config_path);
    Ok(())
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
    _file_config: Option<&ServerFileConfig>,
) -> String {
    args.listen.clone()
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
