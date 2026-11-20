//! Общая конфигурация существующего клиента для служебного работника.
use aivpn_client::{client::ClientConfig, tunnel::TunnelConfig};
use base64::Engine;
use std::io;

pub fn runtime() -> io::Result<tokio::runtime::Runtime> {
    // Подтверждение службы не должно останавливать транспортные задачи клиента.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

fn key(value: &serde_json::Value, field: &str) -> io::Result<[u8; 32]> {
    decode_key(
        value[field]
            .as_str()
            .ok_or_else(|| io::Error::other("Нет поля ключа профиля"))?,
    )
}

fn decode_key(encoded: &str) -> io::Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| io::Error::other("Некорректный формат ключа профиля"))?
        .try_into()
        .map_err(|_| io::Error::other("Некорректный размер ключа профиля"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::network_config::{VpnNetworkConfig, DEFAULT_VPN_MTU};

    #[test]
    fn worker_reactor_advances_while_service_confirmation_blocks() {
        let runtime = runtime().unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        runtime.block_on(async {
            let task = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                sender.send(()).unwrap();
            });
            let advanced = receiver.recv_timeout(std::time::Duration::from_secs(2));
            if advanced.is_err() {
                task.abort();
            }
            assert!(
                advanced.is_ok(),
                "Ожидание службы остановило реактор работника"
            );
            task.await.unwrap();
        });
    }

    fn profile() -> serde_json::Value {
        use ed25519_dalek::Signer;
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let now = aivpn_common::mask::current_unix_secs();
        let mut descriptor = aivpn_common::mask::BootstrapDescriptor {
            descriptor_id: "worker-test".into(),
            version: 1,
            created_at: now.saturating_sub(1),
            expires_at: now + 3600,
            base_mask_ids: vec!["webrtc_zoom_v3".into()],
            embedded_masks: Vec::new(),
            candidate_count: 4,
            kdf_salt: [3; 32],
            signature: [0; 64],
        };
        descriptor.signature = signing.sign(&descriptor.signing_bytes()).to_bytes();
        let signing_key =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        serde_json::json!({"s":"192.0.2.1:443","k":key,"sk":signing_key,"p":key,"i":"10.0.0.2","bd":[descriptor],"_desktop_client":{"mask_operator_pubkey":signing_key}})
    }

    #[test]
    fn legacy_address_without_n_keeps_existing_network_defaults() {
        let config = client_config(&profile(), "managed-test".into()).unwrap();
        assert_eq!(config.tun_config.tun_addr, "10.0.0.2");
        assert_eq!(config.tun_config.server_vpn_ip, "10.0.0.1");
        assert_eq!(config.tun_config.prefix_len, 24);
        assert_eq!(config.tun_config.mtu, DEFAULT_VPN_MTU);
        assert!(!config.tun_config.full_tunnel);
        assert!(!config.tun_config.kill_switch);
        assert!(config.tun_config.include_routes.is_empty());
        assert!(config.tun_config.exclude_routes.is_empty());
    }

    #[test]
    fn operator_key_in_connection_profile_keeps_cli_precedence() {
        let mut profile = profile();
        let encoded = profile["_desktop_client"]
            .as_object_mut()
            .unwrap()
            .remove("mask_operator_pubkey")
            .unwrap();
        let expected = decode_key(encoded.as_str().unwrap()).unwrap();
        profile["mop"] = encoded;
        let config = client_config(&profile, "managed-test".into()).unwrap();
        assert_eq!(config.mask_operator_pubkey, Some(expected));

        let explicit = ed25519_dalek::SigningKey::from_bytes(&[71; 32])
            .verifying_key()
            .to_bytes();
        profile["_desktop_client"]["mask_operator_pubkey"] =
            base64::engine::general_purpose::STANDARD
                .encode(explicit)
                .into();
        let config = client_config(&profile, "managed-test".into()).unwrap();
        assert_eq!(config.mask_operator_pubkey, Some(explicit));
        profile["_desktop_client"]["mask_operator_pubkey"] = "invalid".into();
        assert!(client_config(&profile, "managed-test".into()).is_err());
    }

    #[test]
    #[cfg(not(feature = "production-secure"))]
    fn automatic_first_mask_matches_the_shared_client_bootstrap_contract() {
        // Другие сессии в тестовом процессе запоминают успешную маску. Первая
        // попытка проверяется в новом процессе без этого намеренного кеша.
        const FRESH: &str = "AIVPN_TEST_FRESH_BOOTSTRAP";
        if std::env::var_os(FRESH).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "managed_worker_config::tests::automatic_first_mask_matches_the_shared_client_bootstrap_contract", "--nocapture"])
                .env(FRESH, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let mut profile = profile();
        profile.as_object_mut().unwrap().remove("bd");
        for seed in 0..=255u8 {
            let psk = [seed; 32];
            profile["p"] = base64::engine::general_purpose::STANDARD.encode(psk).into();
            let config = client_config(&profile, "managed-test".into()).unwrap();
            let expected = aivpn_common::mask::preset_masks::bootstrap_for_psk(Some(&psk));
            assert_eq!(
                config.initial_mask.mask_id, expected.mask_id,
                "PSK seed {seed}"
            );
        }
    }

    #[test]
    #[cfg(not(feature = "production-secure"))]
    fn local_client_settings_reach_the_existing_client_configuration() {
        let mut profile = profile();
        profile.as_object_mut().unwrap().remove("bd");
        let mask = aivpn_common::mask::preset_masks::all()
            .into_iter()
            .find(|mask| mask.spoof_protocol == aivpn_common::mask::SpoofProtocol::QUIC)
            .unwrap();
        profile["_desktop_client"] = serde_json::json!({"preferred_mask":mask.mask_id,"adaptive_level":2,
            "polymorphic_mask":true,"share_mask_feedback":true,"receive_mask_hints":true,"country_code":"ru",
            "mtls_certificate":base64::engine::general_purpose::STANDARD.encode([1;104])});
        let config = client_config(&profile, "managed-test".into()).unwrap();
        assert_eq!(config.initial_mask.mask_id, mask.mask_id);
        assert_eq!(
            config.initial_adaptive_level,
            aivpn_common::quality::AdaptiveLevel::Aggressive
        );
        assert_eq!(
            config.polymorphic_base.as_deref(),
            Some(mask.mask_id.as_str())
        );
        assert!(config.share_mask_feedback && config.receive_mask_hints);
        assert_eq!(config.country_code, Some(*b"RU"));
        assert_eq!(config.mtls_cert, Some(vec![1; 104]));
    }

    #[test]
    fn invalid_local_options_are_rejected_instead_of_being_ignored() {
        let profile = profile();
        for (field, value) in [
            ("adaptive_level", serde_json::json!(4)),
            ("preferred_mask", serde_json::json!("missing-mask")),
            ("country_code", serde_json::json!("invalid")),
            ("mtls_certificate", serde_json::json!("not-a-certificate")),
            ("full_tunnel", serde_json::json!(true)),
        ] {
            let mut invalid = profile.clone();
            invalid["_desktop_client"][field] = value;
            assert!(
                client_config(&invalid, "managed-test".into()).is_err(),
                "{field}"
            );
        }
        let mut old_key = profile.clone();
        let signing = old_key.as_object_mut().unwrap().remove("sk").unwrap();
        old_key["_desktop_client"]["server_signing_key"] = signing;
        assert!(client_config(&old_key, "managed-test".into())
            .unwrap()
            .server_signing_key
            .is_some());
    }

    #[test]
    fn verified_inline_descriptor_shapes_the_first_worker_packet() {
        let profile = profile();
        let config = client_config(&profile, "managed-test".into()).unwrap();
        assert!(config
            .initial_mask
            .mask_id
            .starts_with("bootstrap:worker-test:"));
        let mut forged = profile.clone();
        forged["bd"][0]["kdf_salt"][0] = 99.into();
        let result = client_config(&forged, "managed-test".into());
        #[cfg(feature = "production-secure")]
        assert!(result.is_err());
        #[cfg(not(feature = "production-secure"))]
        assert!(!result
            .unwrap()
            .initial_mask
            .mask_id
            .starts_with("bootstrap:"));
    }

    #[test]
    fn reconnect_uses_verified_memory_updates_without_reading_user_files() {
        use aivpn_common::mask::{derive_bootstrap_candidate, BootstrapDescriptor};
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let signing_key =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        let mut profile = profile();
        profile["sk"] = signing_key.clone().into();
        profile["_desktop_client"]["mask_operator_pubkey"] = signing_key.into();
        let mut original: BootstrapDescriptor =
            serde_json::from_value(profile["bd"][0].clone()).unwrap();
        original.descriptor_id = "worker-memory-update".into();
        original.signature = signing.sign(&original.signing_bytes()).to_bytes();
        profile["bd"][0] = serde_json::to_value(&original).unwrap();
        let mut updated = original.clone();
        updated.created_at += 1;
        updated.kdf_salt[0] ^= 1;
        updated.signature = signing.sign(&updated.signing_bytes()).to_bytes();
        aivpn_client::bootstrap_cache::remember_descriptor(updated.clone());
        let expected = derive_bootstrap_candidate(&updated, Some(&[7; 32]), 0).unwrap();
        let actual = client_config(&profile, "managed-test".into()).unwrap();
        assert_eq!(actual.initial_mask.mask_id, expected.mask_id);

        let mut forged = updated;
        forged.created_at += 1;
        forged.kdf_salt[0] ^= 1;
        aivpn_client::bootstrap_cache::remember_descriptor(forged);
        let expected = derive_bootstrap_candidate(&original, Some(&[7; 32]), 0).unwrap();
        let actual = client_config(&profile, "managed-test".into()).unwrap();
        assert_eq!(actual.initial_mask.mask_id, expected.mask_id);
    }

    #[test]
    fn reconnect_changes_candidate_resets_after_success_and_stops_after_rejection() {
        let profile = profile();
        let mut state = ReconnectState::default();
        let first = state.config(&profile, "managed-test".into()).unwrap();
        for _ in 0..aivpn_common::mask::HANDSHAKE_FALLBACK_THRESHOLD {
            assert!(state.record(false, false));
        }
        let retry = state.config(&profile, "managed-test".into()).unwrap();
        assert_ne!(retry.initial_mask.mask_id, first.initial_mask.mask_id);
        #[cfg(feature = "production-secure")]
        assert!(retry
            .initial_mask
            .mask_id
            .starts_with("bootstrap:worker-test:"));
        #[cfg(not(feature = "production-secure"))]
        {
            assert!(retry.is_bootstrap_fallback);
            assert!(aivpn_common::mask::preset_masks::by_id(&retry.initial_mask.mask_id).is_some());
        }
        assert!(state.record(true, false));
        assert_eq!(
            state
                .config(&profile, "managed-test".into())
                .unwrap()
                .initial_mask
                .mask_id,
            first.initial_mask.mask_id
        );
        assert!(!state.record(false, true));
        assert!(state.config(&profile, "managed-test".into()).is_err());
        assert!(!state.record(true, false));
    }

    #[test]
    fn manual_family_survives_retries_and_uses_existing_post_pfs_request() {
        let mut profile = profile();
        profile["_desktop_client"]["preferred_mask"] = "quic_https_v2".into();
        let mut state = ReconnectState::default();
        for _ in 0..8 {
            let config = state.config(&profile, "managed-test".into()).unwrap();
            assert!(config
                .initial_mask
                .mask_id
                .starts_with("bootstrap:worker-test:"));
            assert_eq!(config.polymorphic_base.as_deref(), Some("quic_https_v2"));
            assert!(!config.is_bootstrap_fallback);
            assert!(state.record(false, false));
        }
    }

    #[test]
    #[cfg(feature = "production-secure")]
    fn protected_worker_refuses_public_preset_without_a_trusted_descriptor() {
        let mut profile = profile();
        profile.as_object_mut().unwrap().remove("bd");
        assert!(client_config(&profile, "managed-test".into()).is_err());
    }

    #[test]
    fn explicit_network_is_validated_without_falling_back_to_legacy_address() {
        let mut profile = profile();
        let network = VpnNetworkConfig {
            server_vpn_ip: "10.77.0.1".parse().unwrap(),
            ipv6_enabled: true,
            ..Default::default()
        }
        .client_config("10.77.0.2".parse().unwrap())
        .unwrap();
        profile["n"] = serde_json::to_value(&network).unwrap();
        let config = client_config(&profile, "managed-test".into()).unwrap();
        assert_eq!(config.tun_config.tun_addr, "10.77.0.2");
        assert_eq!(config.tun_config.ipv6, network.client_ipv6().unwrap());
        for mtu in [0, 575, 1501, 65535] {
            profile["n"]["mtu"] = mtu.into();
            assert!(
                client_config(&profile, "managed-test".into()).is_err(),
                "MTU {mtu}"
            );
        }
        for address in ["::", "ff02::1", "invalid"] {
            profile["n"] = serde_json::to_value(&network).unwrap();
            profile["n"]["ipv6_address"] = address.into();
            assert!(client_config(&profile, "managed-test".into()).is_err());
        }
        profile["n"] = serde_json::json!({"invalid":true});
        assert!(client_config(&profile, "managed-test".into()).is_err());
    }
}

pub(super) fn device_identity(value: &serde_json::Value) -> io::Result<[u8; 32]> {
    aivpn_desktop_agent::connection::DesktopClientOptions::from_profile(value)?.device_secret()
}

pub(super) fn apply_runtime(
    client: &mut aivpn_client::AivpnClient,
    profile: &serde_json::Value,
) -> io::Result<()> {
    let options = aivpn_desktop_agent::connection::DesktopClientOptions::from_profile(profile)?;
    client.set_upload_shaping(options.runtime.upload_shaping);
    Ok(())
}

#[derive(Default)]
pub(super) struct ReconnectState {
    failures: u32,
    stopped: bool,
}

impl ReconnectState {
    pub(super) fn config(
        &self,
        value: &serde_json::Value,
        name: String,
    ) -> io::Result<ClientConfig> {
        if self.stopped {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Сервер окончательно отклонил подключение",
            ));
        }
        client_config_for_attempt(value, name, self.failures)
    }

    pub(super) fn record(&mut self, ever_connected: bool, terminal_rejected: bool) -> bool {
        self.stopped |= terminal_rejected;
        self.failures = if ever_connected {
            0
        } else {
            self.failures.saturating_add(1)
        };
        !self.stopped
    }
}

pub(super) fn client_config(value: &serde_json::Value, name: String) -> io::Result<ClientConfig> {
    client_config_for_attempt(value, name, 0)
}

fn client_config_for_attempt(
    value: &serde_json::Value,
    name: String,
    failures: u32,
) -> io::Result<ClientConfig> {
    use aivpn_client::bootstrap_cache;
    use aivpn_common::mask::{self, preset_masks};
    let options = aivpn_desktop_agent::connection::DesktopClientOptions::from_profile(value)?;
    if options.adaptive_level > 3 {
        return Err(io::Error::other("Допустимый уровень адаптации: от 0 до 3"));
    }
    let adaptive = aivpn_common::quality::AdaptiveLevel::from_u8(options.adaptive_level);
    let psk = key(value, "p")?;
    let signing_key = match options
        .server_signing_key
        .as_deref()
        .filter(|key| !key.is_empty())
    {
        Some(key) => decode_key(key)?,
        None => key(value, "sk")?,
    };
    let operator_key = options
        .mask_operator_pubkey
        .as_deref()
        .or_else(|| value.get("mop").and_then(serde_json::Value::as_str))
        .map(decode_key)
        .transpose()?;
    let verify_mode = options
        .mask_verify_mode
        .as_deref()
        .map(str::parse::<mask::MaskVerifyMode>)
        .transpose()
        .map_err(|_| io::Error::other("Некорректный режим проверки масок"))?;
    let verify_mode =
        mask::resolve_protected_mask_verify_mode(verify_mode).map_err(io::Error::other)?;
    mask::protected_build_requires_keys(true, operator_key.is_some()).map_err(io::Error::other)?;
    let preferred = options
        .preferred_mask
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty() && *name != "auto");
    if preferred.is_some_and(|name| preset_masks::by_id(name).is_none()) {
        return Err(io::Error::other("Неизвестная встроенная маска"));
    }
    let mut descriptors = value
        .get("bd")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value::<Vec<aivpn_common::mask::BootstrapDescriptor>>)
        .transpose()
        .map_err(|_| io::Error::other("Некорректные дескрипторы профиля"))?
        .unwrap_or_default();
    descriptors.extend(bootstrap_cache::memory_descriptors());
    if failures >= mask::HANDSHAKE_FALLBACK_THRESHOLD {
        bootstrap_cache::LAST_GOOD_MASK
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }
    let candidate = bootstrap_cache::select_descriptor_candidate(
        &descriptors,
        Some(&psk),
        failures,
        Some(&signing_key),
        bootstrap_cache::data_exploration_round(),
        (!options.polymorphic_mask).then_some(preferred).flatten(),
    );
    let mask = match candidate {
        Some(mask) => mask,
        None => {
            #[cfg(feature = "production-secure")]
            return Err(io::Error::other(
                "Для защищенной сборки нужен действующий доверенный дескриптор",
            ));
            #[cfg(not(feature = "production-secure"))]
            preferred
                .and_then(preset_masks::by_id)
                .unwrap_or_else(|| preset_masks::bootstrap_for_psk(Some(&psk)))
        }
    };
    #[allow(unused_mut)]
    let mut is_bootstrap_fallback = false;
    #[cfg(not(feature = "production-secure"))]
    let mask = if preferred.is_none() && failures >= mask::HANDSHAKE_FALLBACK_THRESHOLD {
        is_bootstrap_fallback = true;
        preset_masks::fallback_for_attempt(Some(&psk), failures)
    } else {
        mask
    };
    let mask = if preferred.is_none()
        && !options.polymorphic_mask
        && failures < mask::HANDSHAKE_FALLBACK_THRESHOLD
    {
        bootstrap_cache::LAST_GOOD_MASK
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .unwrap_or(mask)
    } else {
        mask
    };
    let polymorphic_base = mask::post_pfs_mask_preference(
        preferred,
        options.polymorphic_mask.then_some(preferred).flatten(),
        &mask,
    );
    let mut network: aivpn_common::network_config::ClientNetworkConfig =
        if let Some(network) = value.get("n").filter(|network| !network.is_null()) {
            serde_json::from_value(network.clone())
                .map_err(|_| io::Error::other("Некорректные параметры сети профиля"))?
        } else {
            let client_ip = value["i"]
                .as_str()
                .and_then(|address| address.parse().ok())
                .ok_or_else(|| io::Error::other("В профиле нет IPv4 клиента"))?;
            aivpn_common::network_config::ClientNetworkConfig::from_legacy_address(client_ip)
        };
    network
        .validate()
        .map_err(|_| io::Error::other("Некорректные параметры сети профиля"))?;
    if adaptive != aivpn_common::quality::AdaptiveLevel::Off {
        network.mtu = network.mtu.min(if network.ipv6_address.is_some() {
            1280
        } else {
            1200
        });
    }
    let country_code = options
        .country_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            let bytes = value.trim().as_bytes();
            if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_alphabetic) {
                return Err(io::Error::other(
                    "Код страны должен состоять из двух латинских букв",
                ));
            }
            Ok([bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()])
        })
        .transpose()?;
    let mtls_cert = options
        .mtls_certificate
        .as_deref()
        .map(|encoded| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| io::Error::other("Некорректный сертификат mTLS"))?;
            if bytes.len() != 104 {
                return Err(io::Error::other("Некорректный размер сертификата mTLS"));
            }
            Ok(bytes)
        })
        .transpose()?;
    Ok(ClientConfig {
        server_addr: value["s"]
            .as_str()
            .ok_or_else(|| io::Error::other("Нет адреса сервера"))?
            .into(),
        server_public_key: key(value, "k")?,
        server_signing_key: Some(signing_key),
        preshared_key: Some(psk),
        initial_mask: mask,
        tun_config: TunnelConfig::from_network_config(name, network, false),
        proxy_listen: None,
        proxy_dns: Vec::new(),
        mtls_cert,
        initial_adaptive_level: adaptive,
        polymorphic_base,
        share_mask_feedback: options.share_mask_feedback,
        receive_mask_hints: options.receive_mask_hints,
        country_code,
        mask_operator_pubkey: operator_key,
        mask_verify_mode: verify_mode,
        network_change_notify: None,
        is_bootstrap_fallback,
        control_only: false,
        inbound_control_tap: None,
        node_identity: None,
        pool_node_id: None,
        remote_verified_node: None,
        remote_enroll_hook: None,
        transport: None,
    })
}
