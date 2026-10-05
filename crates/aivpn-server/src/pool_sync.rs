//! Конфиг пула. Живой обмен ведет PoolDialer, синтетический PeerSyncer снят.
//!
//! `transport` пустой или `"masked"` означает masked. Явное `"legacy"` и любое
//! другое значение недопустимы: статический ключ, счетчик nonce и фиксированный
//! framing больше не используются.

use serde::{Deserialize, Serialize};

/// Блок `"pool"` в server.json.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolSyncConfig {
    /// Адреса соседей, `host:vpn_port`.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Идентификатор этого узла. Соседи указывают его у себя в `peers`.
    /// Пустое значение выключает dialer: направленные ключи требуют уникальный id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Устарело. Синхронизация идет в порт VPN, отдельный порт не используется.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_port: Option<u16>,
    /// Общий 32-байтовый ключ BLAKE3, base64. У всех узлов пула один и тот же.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_key: Option<String>,
    /// Выход мультихопа, `host:port`. Вход оборачивает клиентский трафик к нему.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    /// Узел принимает чужой ChainForward. `false` или пусто: отказ, узел не реле.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node_enabled: Option<bool>,
    /// Интервал PoolStateDigest, секунды. Пусто означает 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_beacon_secs: Option<u64>,
    /// Транспорт. Пусто и `"masked"` включают PoolDialer.
    /// `"legacy"` запрещен. Другие строки тоже не принимаются.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Неизвестный `node_id` с верным NodeEnrollment привязывается сам (TOFU).
    /// Пусто означает `true`. `false` требует ручную привязку ключа.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_auto_add: Option<bool>,
    /// Путь к 32-байтовому seed Ed25519 этого узла. Его читает dialer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_identity_key: Option<String>,
    /// RouteSync masked-соседа принимается только с проверенным `verified_node_id`.
    /// Пусто и `false` оставляют прежний допуск самозаявленного id с предупреждением.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_node_enrollment: Option<bool>,
    /// Явный индекс раздела VPN-адресов вместо `hash(node_id) % partitions`.
    /// Значение берется по модулю числа разделов.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_ip_partition: Option<u32>,
}

impl PoolSyncConfig {
    /// Пустой transport и `"masked"` это рабочий режим. Все остальное, включая
    /// явный `"legacy"`, рабочим не является.
    pub fn transport_is_masked(&self) -> bool {
        matches!(self.transport.as_deref(), None | Some("masked"))
    }

    /// Ошибка, если transport задан явно и это не `"masked"`.
    pub fn validate_transport(&self) -> Result<(), &'static str> {
        match self.transport.as_deref() {
            None | Some("masked") => Ok(()),
            Some("legacy") => Err("явный legacy transport запрещен"),
            Some(_) => Err("неизвестный pool transport"),
        }
    }

    /// TOFU для неизвестного узла. Пустое поле означает да.
    pub fn allow_auto_add(&self) -> bool {
        self.allow_auto_add.unwrap_or(true)
    }

    /// Требовать криптографически проверенный node_id для RouteSync.
    /// Пустое поле означает нет.
    pub fn require_node_enrollment(&self) -> bool {
        self.require_node_enrollment.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_transport_is_masked() {
        let cfg: PoolSyncConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.transport.is_none());
        assert!(cfg.transport_is_masked());
        assert!(cfg.validate_transport().is_ok());
        assert!(cfg.allow_auto_add());
        assert!(!cfg.require_node_enrollment());
    }

    #[test]
    fn explicit_masked_is_allowed() {
        let cfg = PoolSyncConfig {
            transport: Some("masked".to_string()),
            allow_auto_add: Some(false),
            require_node_enrollment: Some(true),
            ..PoolSyncConfig::default()
        };
        assert!(cfg.transport_is_masked());
        assert!(cfg.validate_transport().is_ok());
        assert!(!cfg.allow_auto_add());
        assert!(cfg.require_node_enrollment());
    }

    #[test]
    fn explicit_legacy_is_rejected() {
        let cfg: PoolSyncConfig = serde_json::from_str(r#"{"transport":"legacy"}"#).unwrap();
        assert!(!cfg.transport_is_masked());
        assert_eq!(
            cfg.validate_transport(),
            Err("явный legacy transport запрещен")
        );
    }

    #[test]
    fn unknown_transport_is_rejected() {
        let cfg = PoolSyncConfig {
            transport: Some("udp".to_string()),
            ..PoolSyncConfig::default()
        };
        assert!(!cfg.transport_is_masked());
        assert!(cfg.validate_transport().is_err());
    }
}
