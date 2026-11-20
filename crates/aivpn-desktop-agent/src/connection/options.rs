//! Локальные настройки клиента не меняют идентичность ключа подключения.
use serde::{Deserialize, Serialize};
use std::{fmt, io};

pub const CLIENT_OPTIONS_FIELD: &str = "_desktop_client";

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DesktopClientOptions {
    pub preferred_mask: Option<String>,
    pub adaptive_level: u8,
    pub polymorphic_mask: bool,
    pub share_mask_feedback: bool,
    pub receive_mask_hints: bool,
    pub country_code: Option<String>,
    pub server_signing_key: Option<String>,
    pub mask_operator_pubkey: Option<String>,
    pub mask_verify_mode: Option<String>,
    pub mtls_certificate: Option<String>,
    pub device_private_key: Option<String>,
    #[cfg(feature = "local-profile")]
    pub runtime: aivpn_common::transport::RuntimeConfig,
}

impl fmt::Debug for DesktopClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DesktopClientOptions([скрыто])")
    }
}

impl DesktopClientOptions {
    pub fn device_secret(&self) -> io::Result<[u8; 32]> {
        use base64::{engine::general_purpose, Engine};
        let encoded = self.device_private_key.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Не передан постоянный ключ устройства",
            )
        })?;
        [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ]
        .iter()
        .find_map(|engine| engine.decode(encoded).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Некорректный постоянный ключ устройства",
            )
        })
    }

    pub fn from_profile(profile: &serde_json::Value) -> io::Result<Self> {
        profile
            .get(CLIENT_OPTIONS_FIELD)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| io::Error::other("Некорректные локальные настройки клиента"))
            .map(Option::unwrap_or_default)
    }
}
