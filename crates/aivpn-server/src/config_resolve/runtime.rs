use aivpn_server::{
    server_config::{ServerFileConfig, CONFIG_KNOWN_KEYS},
    ServerArgs,
};
use clap::{parser::ValueSource, ArgMatches};
use serde_json::{json, Value};

fn canonical_key(key: &str) -> &str {
    match key {
        "listen" => "listen_addr",
        "shaping_level" => "downlink_shaping",
        "public_endpoint" => "server_ip",
        other => other,
    }
}

fn explicit_cli_for(matches: &ArgMatches, key: &str) -> bool {
    let arg = match key {
        "listen_addr" => "listen",
        "downlink_shaping" => "shaping_level",
        "pool" => "pool_config",
        other => other,
    };
    matches.try_contains_id(arg).is_ok()
        && matches.value_source(arg) == Some(ValueSource::CommandLine)
}

fn environment_path(name: &str) -> Option<(Vec<String>, bool)> {
    let key = if name == "RUST_LOG" {
        "log_level".to_string()
    } else {
        name.strip_prefix("AIVPN_")?.to_ascii_lowercase()
    };
    let mut path: Vec<String> = key.split("__").map(str::to_string).collect();
    let canonical = canonical_key(&path[0]).to_string();
    if !CONFIG_KNOWN_KEYS.contains(&canonical.as_str()) {
        return None;
    }
    let alias = path[0] != canonical || name == "RUST_LOG";
    path[0] = canonical;
    Some((path, alias))
}

/// Чужие переменные не декодируются: окружение процесса может содержать любые байты.
pub(crate) fn collect_environment(matches: &ArgMatches) -> Result<Vec<(String, String)>, String> {
    let mut environment = Vec::new();
    for (name, value) in std::env::vars_os() {
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = if matches!(name, "AIVPN_CONFIG" | "AIVPN_CONFIG_PATH") {
            Some("config".to_string())
        } else {
            environment_path(name).map(|(path, _)| path[0].clone())
        };
        let Some(path) = path else {
            continue;
        };
        if explicit_cli_for(matches, &path) {
            continue;
        }
        let value = value
            .into_string()
            .map_err(|_| format!("{name}: значение должно быть UTF-8"))?;
        environment.push((name.to_string(), value));
    }
    Ok(environment)
}

fn plain_path(path: impl ToString) -> String {
    path.to_string()
        .replace(".?", "")
        .replace('[', ".")
        .replace(']', "")
}

fn source_paths(path: &str, value: &Value, paths: &mut Vec<String>) {
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            source_paths(&format!("{path}.{key}"), value, paths);
        }
    } else {
        paths.push(path.to_string());
    }
}

fn comes_from_env(path: &str, sources: &[String]) -> bool {
    sources.iter().any(|source| {
        path == source
            || path.starts_with(&format!("{source}."))
            || source.starts_with(&format!("{path}."))
    })
}

fn unknown_env_field(
    input: &Value,
    known: &Value,
    path: &str,
    sources: &[String],
) -> Option<String> {
    match (input, known) {
        (Value::Object(input), Value::Object(known)) => {
            for (key, value) in input {
                let path = format!("{path}.{key}");
                match known.get(key) {
                    Some(known) => {
                        if let Some(unknown) = unknown_env_field(value, known, &path, sources) {
                            return Some(unknown);
                        }
                    }
                    None if comes_from_env(&path, sources) => return Some(path),
                    None => {}
                }
            }
        }
        (Value::Array(input), Value::Array(known)) => {
            for (index, (value, known)) in input.iter().zip(known).enumerate() {
                if let Some(unknown) =
                    unknown_env_field(value, known, &format!("{path}.{index}"), sources)
                {
                    return Some(unknown);
                }
            }
        }
        _ => {}
    }
    None
}

/// Объекты дополняют нижний слой, массивы и скаляры заменяют его целиком.
fn merge(base: &mut Value, overlay: Value) {
    if let (Some(base), Value::Object(overlay)) = (base.as_object_mut(), &overlay) {
        for (key, value) in overlay {
            merge(
                base.entry(key.clone()).or_insert(Value::Null),
                value.clone(),
            );
        }
    } else {
        *base = overlay;
    }
}

fn set_path(base: &mut Value, path: &[String], value: Value) -> Result<(), String> {
    fn apply(base: &mut Value, path: &[String], value: Value) -> Result<(), &'static str> {
        let Some((key, rest)) = path.split_first() else {
            merge(base, value);
            return Ok(());
        };
        if let Value::Array(items) = base {
            let index: usize = key.parse().map_err(|_| "нужен индекс массива")?;
            let item = items.get_mut(index).ok_or("индекс вне массива")?;
            return apply(item, rest, value);
        }
        if !base.is_object() {
            *base = json!({});
        }
        let object = base.as_object_mut().expect("объект создан выше");
        apply(
            object.entry(key.clone()).or_insert(Value::Null),
            rest,
            value,
        )
    }
    apply(base, path, value).map_err(|reason| format!("{}: {reason}", path.join(".")))
}

fn decode_with_unknown(value: Value) -> Result<(ServerFileConfig, Vec<String>), String> {
    let mut track = serde_path_to_error::Track::new();
    let deserializer = serde_path_to_error::Deserializer::new(value, &mut track);
    let mut ignored = Vec::new();
    let config = serde_ignored::deserialize(deserializer, |path| {
        ignored.push(plain_path(path));
    })
    .map_err(|_| plain_path(track.path()))?;
    Ok((config, ignored))
}

fn load_pool_file(path: &Value) -> Result<Value, String> {
    let path = path.as_str().ok_or("pool_config: нужен путь к файлу")?;
    let bytes = std::fs::read(path).map_err(|_| "pool_config: не удалось прочитать файл")?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "pool_config: неверный JSON в файле")?;
    if !value.is_object() {
        return Err("pool_config: нужен JSON-объект".to_string());
    }
    Ok(value)
}

/// Собирает постоянные настройки до чтения ключей, открытия DB и запуска задач.
pub(crate) fn resolve_with_env(
    args: &mut ServerArgs,
    matches: &ArgMatches,
    mut file: Value,
    env: impl IntoIterator<Item = (String, String)>,
) -> Result<ServerFileConfig, String> {
    let object = file.as_object_mut().ok_or("config: нужен JSON-объект")?;
    if let Some(endpoint) = object.remove("public_endpoint") {
        if object.insert("server_ip".to_string(), endpoint).is_some() {
            return Err("server_ip: одновременно задан public_endpoint".to_string());
        }
    }
    let mut entries = Vec::new();
    for (name, raw) in env {
        let Some((path, alias)) = environment_path(&name) else {
            continue;
        };
        if explicit_cli_for(matches, &path[0]) {
            continue;
        }
        if path.iter().any(String::is_empty) {
            return Err(format!("{name}: пустое имя вложенного поля"));
        }
        entries.push((path, alias, name, raw));
    }
    if !explicit_cli_for(matches, "pool_config")
        && !entries
            .iter()
            .any(|(path, _, _, _)| path == &["pool_config"])
    {
        if let Some(path) = file.get("pool_config").filter(|v| !v.is_null()) {
            file["pool"] = load_pool_file(path)?;
        }
    }
    // Короткие алиасы раньше канонических имен, блоки раньше вложенных полей.
    entries.sort_by(|a, b| {
        a.0.len()
            .cmp(&b.0.len())
            .then((b.0[0] == "pool_config").cmp(&(a.0[0] == "pool_config")))
            .then(b.1.cmp(&a.1))
            .then(a.2.cmp(&b.2))
    });
    let mut env_paths = Vec::new();
    let mut scalar_fallbacks = Vec::new();
    for (path, _, _, raw) in entries {
        let mut value = if path == ["kernel_downlink"]
            && (matches!(raw.as_str(), "1" | "0")
                || raw.eq_ignore_ascii_case("true")
                || raw.eq_ignore_ascii_case("false"))
        {
            Value::Bool(raw == "1" || raw.eq_ignore_ascii_case("true"))
        } else {
            match serde_json::from_str::<Value>(&raw) {
                Ok(value) => value,
                Err(_) => Value::String(raw.clone()),
            }
        };
        scalar_fallbacks.retain(|(previous, _)| previous != &path);
        if value.is_boolean() || value.is_number() {
            scalar_fallbacks.push((path.clone(), value));
            value = Value::String(raw);
        }
        source_paths(&path.join("."), &value, &mut env_paths);
        if path == ["pool_config"] && !value.is_null() {
            file["pool"] = load_pool_file(&value)?;
            source_paths("pool", &file["pool"], &mut env_paths);
        }
        set_path(&mut file, &path, value)?;
    }

    macro_rules! cli {
        ($field:ident, $key:literal) => {
            if matches.value_source(stringify!($field)) == Some(ValueSource::CommandLine) {
                file[$key] = json!(args.$field);
                scalar_fallbacks.retain(|(path, _)| path[0] != $key);
            }
        };
    }
    cli!(listen, "listen_addr");
    cli!(tun_name, "tun_name");
    cli!(key_file, "key_file");
    cli!(clients_db, "clients_db");
    cli!(server_ip, "server_ip");
    cli!(per_ip_pps_limit, "per_ip_pps_limit");
    cli!(
        per_ip_authenticated_pps_limit,
        "per_ip_authenticated_pps_limit"
    );
    cli!(mask_dir, "mask_dir");
    #[cfg(all(feature = "management-api", unix))]
    cli!(management_socket, "management_socket");
    cli!(pool_config, "pool_config");
    if matches.value_source("pool_config") == Some(ValueSource::CommandLine) {
        file["pool"] = load_pool_file(&file["pool_config"])?;
        scalar_fallbacks.retain(|(path, _)| path[0] != "pool");
    }
    cli!(audit_log, "audit_log");
    cli!(allow_peer_routing, "allow_peer_routing");
    cli!(mask_signing_key, "mask_signing_key");
    cli!(mask_operator_pubkey, "mask_operator_pubkey");
    cli!(mask_verify_mode, "mask_verify_mode");
    cli!(shaping_level, "downlink_shaping");
    cli!(log_level, "log_level");

    let config = loop {
        match decode_with_unknown(file.clone()) {
            Ok((config, unknown)) => {
                if let Some(path) = unknown.iter().find(|path| comes_from_env(path, &env_paths)) {
                    return Err(format!("{path}: неизвестная настройка окружения"));
                }
                break config;
            }
            Err(path) => {
                // Строковые node_id и ключи сохраняют вид; тип числа определяет схема.
                if let Some(index) = scalar_fallbacks
                    .iter()
                    .position(|(parts, _)| parts.join(".") == path)
                {
                    let (parts, value) = scalar_fallbacks.remove(index);
                    set_path(&mut file, &parts, value)?;
                } else {
                    return Err(format!("{path}: неверное значение настройки"));
                }
            }
        }
    };

    // Serde буферизует поля помеченного enum до обхода, скрывая их от serde_ignored.
    // У каналов все поля сериализуются, поэтому виден точный набор принятых имен.
    let known_publish = serde_json::to_value(&config.bootstrap_publish)
        .map_err(|_| "bootstrap_publish: не удалось проверить структуру".to_string())?;
    if let Some(path) = unknown_env_field(
        &file["bootstrap_publish"],
        &known_publish,
        "bootstrap_publish",
        &env_paths,
    ) {
        return Err(format!("{path}: неизвестная настройка окружения"));
    }

    config.validate_runtime()?;
    if let Some(value) = &config.listen_addr {
        args.listen = value.clone();
    }
    if let Some(value) = &config.clients_db {
        args.clients_db = value.clone();
    }
    if let Some(value) = &config.audit_log {
        args.audit_log = value.clone();
    }
    if let Some(value) = config.per_ip_pps_limit {
        args.per_ip_pps_limit = value;
    }
    if let Some(value) = config.per_ip_authenticated_pps_limit {
        args.per_ip_authenticated_pps_limit = value;
    }
    args.key_file = config.key_file.clone();
    args.tun_name = config.tun_name.clone();
    args.server_ip = config.server_ip.clone();
    args.mask_dir = config.mask_dir.clone();
    #[cfg(all(feature = "management-api", unix))]
    {
        args.management_socket = config.management_socket.clone();
    }
    args.pool_config = config.pool_config.clone();
    args.allow_peer_routing = config.allow_peer_routing.unwrap_or(false);
    args.mask_signing_key = config.mask_signing_key.clone();
    args.mask_operator_pubkey = config.mask_operator_pubkey.clone();
    args.mask_verify_mode = config.mask_verify_mode.clone();
    args.shaping_level = None;
    args.log_level = config.log_level.clone();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};
    use serde_json::json;

    fn resolve(
        cli: &[&str],
        mut file: serde_json::Value,
        env: &[(&str, &str)],
    ) -> (ServerArgs, ServerFileConfig) {
        if cfg!(feature = "production-secure") {
            file.as_object_mut()
                .unwrap()
                .entry("mask_signing_key")
                .or_insert(json!("/test/signing.key"));
        }
        let matches = ServerArgs::command().try_get_matches_from(cli).unwrap();
        let mut args = ServerArgs::from_arg_matches(&matches).unwrap();
        let cfg = resolve_with_env(
            &mut args,
            &matches,
            file,
            env.iter().map(|(k, v)| (k.to_string(), v.to_string())),
        )
        .unwrap();
        (args, cfg)
    }

    #[test]
    fn authenticated_ingress_file_limit_is_independent_of_preauth() {
        let (args, cfg) = resolve(
            &["server"],
            json!({"per_ip_pps_limit":3000, "per_ip_authenticated_pps_limit":70000}),
            &[],
        );
        assert_eq!(args.per_ip_pps_limit, 3000);
        assert_eq!(args.per_ip_authenticated_pps_limit, 70_000);
        assert_eq!(cfg.per_ip_authenticated_pps_limit, Some(70_000));
    }

    #[test]
    fn authenticated_ingress_environment_overrides_file() {
        let (args, cfg) = resolve(
            &["server"],
            json!({"per_ip_pps_limit":3000, "per_ip_authenticated_pps_limit":70000}),
            &[("AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT", "80000")],
        );
        assert_eq!(args.per_ip_pps_limit, 3000);
        assert_eq!(args.per_ip_authenticated_pps_limit, 80_000);
        assert_eq!(cfg.per_ip_authenticated_pps_limit, Some(80_000));
    }

    #[test]
    fn authenticated_ingress_explicit_cli_default_and_zero_override_lower_layers() {
        for (cli, expected) in [("100000", 100_000), ("0", 0)] {
            let (args, _) = resolve(
                &["server", "--per-ip-authenticated-pps-limit", cli],
                json!({"per_ip_pps_limit":3000, "per_ip_authenticated_pps_limit":false}),
                &[("AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT", "invalid-lower-rate")],
            );
            assert_eq!(args.per_ip_pps_limit, 3000);
            assert_eq!(args.per_ip_authenticated_pps_limit, expected);
        }
    }

    #[test]
    fn authenticated_ingress_defaults_and_zero_are_preserved() {
        let (args, _) = resolve(&["server"], json!({}), &[]);
        assert_eq!(
            (args.per_ip_pps_limit, args.per_ip_authenticated_pps_limit),
            (5000, 100_000)
        );
        let defaults = aivpn_server::gateway::GatewayConfig::default();
        assert_eq!(
            (
                defaults.per_ip_pps_limit,
                defaults.per_ip_authenticated_pps_limit
            ),
            (5000, 100_000)
        );
        for (file, env) in [
            (json!({"per_ip_authenticated_pps_limit":0}), vec![]),
            (
                json!({"per_ip_authenticated_pps_limit":70000}),
                vec![("AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT", "0")],
            ),
        ] {
            let (args, _) = resolve(&["server"], file, &env);
            assert_eq!(args.per_ip_authenticated_pps_limit, 0);
            assert_eq!(args.per_ip_pps_limit, 5000);
        }
    }

    #[test]
    fn authenticated_ingress_invalid_environment_reports_field_without_value() {
        for value in [
            "invalid-authenticated-rate",
            "-1",
            "true",
            "18446744073709551616",
        ] {
            let matches = ServerArgs::command()
                .try_get_matches_from(["server"])
                .unwrap();
            let mut args = ServerArgs::from_arg_matches(&matches).unwrap();
            let error = resolve_with_env(
                &mut args,
                &matches,
                json!({}),
                [(
                    "AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT".to_string(),
                    value.to_string(),
                )],
            )
            .unwrap_err();
            assert!(error.contains("per_ip_authenticated_pps_limit"));
            assert!(!error.contains(value));
        }
    }

    #[test]
    fn authenticated_ingress_resolution_keeps_neural_and_path_priorities() {
        let (args, cfg) = resolve(
            &["server", "--mask-dir", "/cli/masks"],
            json!({"mask_dir":"/file/masks", "key_file":"/file/server.key", "neural_enabled":true, "neural":{"warning_threshold":0.42}, "per_ip_authenticated_pps_limit":70000}),
            &[
                ("AIVPN_MASK_DIR", "/env/masks"),
                ("AIVPN_KEY_FILE", "/env/server.key"),
                ("AIVPN_NEURAL_ENABLED", "false"),
                ("AIVPN_NEURAL__CHECK_INTERVAL_SECS", "7"),
                ("AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT", "80000"),
            ],
        );
        assert_eq!(args.mask_dir.as_deref(), Some("/cli/masks"));
        assert_eq!(args.key_file.as_deref(), Some("/env/server.key"));
        assert_eq!(cfg.neural_enabled, Some(false));
        let neural = cfg.neural.unwrap();
        assert_eq!(neural.check_interval_secs, 7);
        assert_eq!(neural.warning_threshold, 0.42);
        assert_eq!(args.per_ip_authenticated_pps_limit, 80_000);
    }

    #[test]
    fn explicit_cli_default_and_false_win_over_env_and_file() {
        let (args, cfg) = resolve(
            &[
                "server",
                "--listen",
                "0.0.0.0:443",
                "--per-ip-pps-limit",
                "0",
                "--allow-peer-routing=false",
            ],
            json!({"listen_addr":"0.0.0.0:8443", "allow_peer_routing":true}),
            &[
                ("AIVPN_LISTEN", "0.0.0.0:9443"),
                ("AIVPN_ALLOW_PEER_ROUTING", "true"),
                ("AIVPN_PER_IP_PPS_LIMIT", "9000"),
            ],
        );
        assert_eq!(args.listen, "0.0.0.0:443");
        assert_eq!(args.per_ip_pps_limit, 0);
        assert_eq!(cfg.allow_peer_routing, Some(false));
    }

    #[test]
    fn env_overrides_file_and_merges_nested_blocks() {
        let (args, cfg) = resolve(
            &["server"],
            json!({"listen_addr":"0.0.0.0:8443", "clients_db":"/file/clients.json", "neural":{"warning_threshold":0.42}, "pool":{"node_id":"file-node", "peers":["old:443"]}}),
            &[
                ("AIVPN_LISTEN_ADDR", "[::]:9443"),
                ("AIVPN_CLIENTS_DB", "/env/clients.json"),
                ("AIVPN_POOL", r#"{"exit_node_enabled":true}"#),
                ("AIVPN_POOL__PEERS", r#"["peer.example:443"]"#),
                ("AIVPN_NEURAL__CHECK_INTERVAL_SECS", "0"),
            ],
        );
        assert_eq!(args.listen, "[::]:9443");
        assert_eq!(args.clients_db, "/env/clients.json");
        let pool = cfg.pool.unwrap();
        assert_eq!(pool.node_id.as_deref(), Some("file-node"));
        assert_eq!(pool.peers, ["peer.example:443"]);
        assert_eq!(pool.exit_node_enabled, Some(true));
        assert_eq!(cfg.neural.unwrap().check_interval_secs, 0);
    }

    #[test]
    fn invalid_env_identifies_setting_without_value() {
        let matches = ServerArgs::command()
            .try_get_matches_from(["server"])
            .unwrap();
        let mut args = ServerArgs::from_arg_matches(&matches).unwrap();
        let err = resolve_with_env(
            &mut args,
            &matches,
            json!({}),
            [(
                "AIVPN_POOL__PEERS".to_string(),
                "secret-invalid-array".to_string(),
            )],
        )
        .unwrap_err();
        assert!(err.contains("pool.peers"));
        assert!(!err.contains("secret-invalid-array"));
    }

    #[test]
    fn invalid_mask_trust_mode_never_echoes_environment_value() {
        let matches = ServerArgs::command()
            .try_get_matches_from(["server"])
            .unwrap();
        let mut args = ServerArgs::from_arg_matches(&matches).unwrap();
        let err = resolve_with_env(
            &mut args,
            &matches,
            json!({"mask_signing_key":"/test/signing.key"}),
            [(
                "AIVPN_MASK_VERIFY_MODE".to_string(),
                "private-token".to_string(),
            )],
        )
        .unwrap_err();
        assert!(err.contains("mask_verify_mode"));
        assert!(!err.contains("private-token"));
    }

    #[test]
    fn every_file_key_is_available_from_env() {
        let mut example: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/config/server.json.example"
        )))
        .unwrap();
        if cfg!(feature = "production-secure") {
            example["mask_signing_key"] = json!("/test/signing.key");
            example["mask_verify_mode"] = json!("enforce");
        }
        let env: Vec<_> = example
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (format!("AIVPN_{}", k.to_ascii_uppercase()), v.to_string()))
            .collect();
        let matches = ServerArgs::command()
            .try_get_matches_from(["server"])
            .unwrap();
        let mut args = ServerArgs::from_arg_matches(&matches).unwrap();
        let cfg = resolve_with_env(&mut args, &matches, json!({}), env).unwrap();
        assert!(cfg.network_config.is_some());
        assert!(cfg.pool.is_some());
        assert!(cfg.bootstrap_publish.is_some());
        assert!(cfg.feedback.is_some());
    }

    #[test]
    fn env_keeps_numeric_and_boolean_strings_and_old_kernel_switch() {
        let (_, cfg) = resolve(
            &["server"],
            json!({}),
            &[
                ("AIVPN_POOL__NODE_ID", "123"),
                ("AIVPN_POOL__SYNC_KEY", "true"),
                ("AIVPN_KERNEL_DOWNLINK", "TRUE"),
                ("AIVPN_EVENT_STDOUT", "false"),
            ],
        );
        let pool = cfg.pool.unwrap();
        assert_eq!(pool.node_id.as_deref(), Some("123"));
        assert_eq!(pool.sync_key.as_deref(), Some("true"));
        assert_eq!(cfg.kernel_downlink, Some(true));
        assert_eq!(cfg.event_stdout, Some(false));
    }

    #[test]
    fn rejects_unknown_nested_env_but_keeps_old_file_keys() {
        for env in [
            [("AIVPN_POOL__PEEERS", "[]")],
            [("AIVPN_POOL", r#"{"peeers":[]}"#)],
        ] {
            let matches = ServerArgs::command()
                .try_get_matches_from(["server"])
                .unwrap();
            let mut args = ServerArgs::from_arg_matches(&matches).unwrap();
            let err = resolve_with_env(
                &mut args,
                &matches,
                json!({}),
                env.map(|(k, v)| (k.to_string(), v.to_string())),
            )
            .unwrap_err();
            assert!(err.contains("pool.peeers"), "{err}");
        }
        let (_, cfg) = resolve(
            &["server"],
            json!({"pool":{"old_setting":true}}),
            &[("AIVPN_POOL", r#"{"node_id":"node"}"#)],
        );
        assert_eq!(cfg.pool.unwrap().node_id.as_deref(), Some("node"));
    }

    #[test]
    fn rejects_unknown_env_field_in_publish_channel_enum() {
        let matches = ServerArgs::command()
            .try_get_matches_from(["server"])
            .unwrap();
        let mut args = ServerArgs::from_arg_matches(&matches).unwrap();
        let result = resolve_with_env(&mut args, &matches,
            json!({"mask_signing_key":"/test/signing.key"}),
            [("AIVPN_BOOTSTRAP_PUBLISH".to_string(), r#"{"channels":[{"type":"telegram","bot_token":"fixture","chat_id":"fixture","typo":"fixture"}]}"#.to_string())]);
        let error = result.expect_err("неизвестное поле канала должно быть отклонено");
        assert!(error.contains("bootstrap_publish.channels.0.typo"));
        assert!(!error.contains("fixture"));
    }

    #[test]
    fn cli_overrides_invalid_lower_env_without_parsing_its_value() {
        let (args, _) = resolve(
            &["server", "--per-ip-pps-limit", "5000"],
            json!({"per_ip_pps_limit":false}),
            &[("AIVPN_PER_IP_PPS_LIMIT", "secret-invalid-number")],
        );
        assert_eq!(args.per_ip_pps_limit, 5000);
    }

    #[test]
    fn file_supplies_persistent_paths_and_default_values_remain_explicit() {
        let (args, cfg) = resolve(
            &["server"],
            json!({
                "key_file":"/file/server.key", "clients_db":"/file/clients.json",
                "server_ip":"vpn.example:8443", "audit_log":"/file/audit.log",
                "per_ip_pps_limit":0, "log_level":"info", "enable_nat":false,
                "event_webhook":"https://events.example/path", "kernel_downlink":false
            }),
            &[],
        );
        assert_eq!(args.key_file.as_deref(), Some("/file/server.key"));
        assert_eq!(args.clients_db, "/file/clients.json");
        assert_eq!(args.server_ip.as_deref(), Some("vpn.example:8443"));
        assert_eq!(args.audit_log, "/file/audit.log");
        assert_eq!(args.per_ip_pps_limit, 0);
        assert_eq!(cfg.enable_nat, Some(false));
        let (defaults, _) = resolve(&["server"], json!({}), &[]);
        assert_eq!(defaults.per_ip_pps_limit, 5000);
        assert_eq!(defaults.listen, "0.0.0.0:443");
    }

    #[test]
    fn pool_file_is_loaded_at_its_source_priority() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pool.json");
        std::fs::write(&path, r#"{"node_id":"external","peers":["file:443"]}"#).unwrap();
        let pool_path = path.to_str().unwrap();
        let (_, cfg) = resolve(
            &["server"],
            json!({"pool_config":pool_path}),
            &[("AIVPN_POOL__PEERS", r#"["env:443"]"#)],
        );
        assert_eq!(cfg.pool.unwrap().peers, ["env:443"]);
        let (_, cfg) = resolve(
            &["server", "--pool-config", pool_path],
            json!({"pool_config":"/missing/lower/path"}),
            &[("AIVPN_POOL", "invalid-lower-json")],
        );
        assert_eq!(cfg.pool.unwrap().peers, ["file:443"]);
    }

    #[test]
    fn nested_array_string_override_keeps_numeric_token() {
        let (_, cfg) = resolve(
            &["server"],
            json!({"bootstrap_publish":{"channels":[{"type":"telegram","bot_token":"old","chat_id":"old"}]}}),
            &[("AIVPN_BOOTSTRAP_PUBLISH__CHANNELS__0__CHAT_ID", "123")],
        );
        let channel = serde_json::to_value(cfg.bootstrap_publish.unwrap()).unwrap();
        assert_eq!(channel["channels"][0]["chat_id"], "123");
    }
}
