use std::io;
use base64::Engine;
use aivpn_client::{client::ClientConfig, tunnel::TunnelConfig};
fn key(value: &serde_json::Value, field: &str) -> io::Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(
            value[field]
                .as_str()
                .ok_or_else(|| io::Error::other("Нет поля ключа профиля"))?,
        )
        .map_err(|_| io::Error::other("Некорректный формат ключа профиля"))?
        .try_into()
        .map_err(|_| io::Error::other("Некорректный размер ключа профиля"))
}

pub fn client_config(value: &serde_json::Value, name: String) -> io::Result<ClientConfig> {
    let psk = key(value, "p")?;
    let presets = aivpn_common::mask::preset_masks::all();
    let hash = blake3::derive_key("aivpn-bootstrap-mask-v1", &psk);
    let mask = presets[hash[0] as usize % presets.len()].clone();
    let network = serde_json::from_value(value["n"].clone()).map_err(io::Error::other)?;
    Ok(ClientConfig {
        server_addr: value["s"]
            .as_str()
            .ok_or_else(|| io::Error::other("Нет адреса сервера"))?
            .into(),
        server_public_key: key(value, "k")?,
        server_signing_key: Some(key(value, "sk")?),
        preshared_key: Some(psk),
        initial_mask: mask,
        tun_config: TunnelConfig::from_network_config(name, network, false),
        proxy_listen: None,
        proxy_dns: Vec::new(),
        mtls_cert: None,
        initial_adaptive_level: aivpn_common::quality::AdaptiveLevel::Off,
        polymorphic_base: None,
        share_mask_feedback: false,
        receive_mask_hints: false,
        country_code: None,
        mask_operator_pubkey: None,
        mask_verify_mode: Default::default(),
        network_change_notify: None,
        is_bootstrap_fallback: false,
        control_only: false,
        inbound_control_tap: None,
        node_identity: None,
        pool_node_id: None,
        remote_verified_node: None,
        remote_enroll_hook: None,
        transport: None,
    })
}
