//! Client data model: [`ClientRole`], [`ClientConfig`], [`ClientStats`],
//! `exit_node` validation, and the base64 serde helpers used by
//! `ClientConfig`'s binary fields (`psk`, `device_pubkey`).

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use aivpn_common::error::{Error, Result};

/// A client's server-side management role: gates what an in-tunnel
/// `MgmtRequest` (or the REST API acting on its behalf) is allowed to do.
/// `User` (the default) has no management access at all; `Viewer` may only
/// read curated status/list/audit endpoints; `Admin` may perform the full
/// curated allowlist (client CRUD, connection-key issuance, revoke, etc).
/// Ranked so callers can gate with a single `at_least` comparison instead of
/// matching every variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClientRole {
    #[default]
    User,
    Viewer,
    Admin,
}

impl ClientRole {
    /// True if `self` is at least as privileged as `req`.
    pub fn at_least(self, req: ClientRole) -> bool {
        self.rank() >= req.rank()
    }

    pub(crate) fn rank(self) -> u8 {
        match self {
            ClientRole::User => 0,
            ClientRole::Viewer => 1,
            ClientRole::Admin => 2,
        }
    }

    /// Wire representation used by `ControlPayload::Capabilities` and the
    /// in-tunnel `MgmtRequest` authorization gate — `rank()` is private
    /// (an internal ordering detail), this is the public, stable u8 the
    /// protocol and `mgmt_service::authorize` are allowed to depend on.
    /// User=0, Viewer=1, Admin=2 (same values as `rank()` today, but the
    /// two are allowed to diverge — this is the contract, `rank()` is not).
    pub fn as_u8(self) -> u8 {
        self.rank()
    }
}

/// Client configuration and credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Unique client ID (UUID-like hex string)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Pre-shared key (32 bytes, base64-encoded in JSON).
    /// SECURITY: never return `ClientConfig` directly from API handlers — use `ClientResponse`
    /// instead, which explicitly excludes this field.
    #[serde(with = "base64_bytes")]
    pub psk: [u8; 32],
    /// Assigned static VPN IP
    pub vpn_ip: Ipv4Addr,
    /// Whether client is enabled
    pub enabled: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Traffic and connection statistics
    pub stats: ClientStats,
    /// Per-client QoS / bandwidth settings (0.8.0+, optional for backward compat)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos: Option<crate::qos::ClientQos>,
    /// Static X25519 device public key bound to this client (0.9.0+).
    /// None = any device may connect; Some = only the enrolled device may connect.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_base64_bytes"
    )]
    pub device_pubkey: Option<[u8; 32]>,
    /// When true, the first connecting device's static key is auto-bound (one-time enrollment).
    #[serde(default)]
    pub one_time: bool,
    /// Optional expiry timestamp. When set and in the past, the client cannot connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Last-modified timestamp, used for last-writer-wins conflict resolution
    /// in pool sync (`merge_from_json`). `None` on records written by older
    /// versions — treated as "older than any timestamped record".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    /// Tombstone: the client was deleted locally. The record is kept (and
    /// synced) so the deletion propagates convergently through the pool — a
    /// peer's stale live copy must not resurrect a revoked client. Tombstoned
    /// clients are invisible to all lookup/list paths.
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
    /// Server-side management role granted to this client (0.11.0+, optional
    /// for backward compat — absent/older records default to `User`, i.e. no
    /// management access). Elevating to `Viewer`/`Admin` requires the client
    /// to already be device-bound (see `update_client`'s enforcement) — role
    /// is authenticated by the device's static key during the handshake, so
    /// a role on a non-device-bound (PSK-only) client could never actually be
    /// proven to belong to the connecting peer.
    #[serde(default, skip_serializing_if = "is_role_user")]
    pub role: ClientRole,
    /// Optional per-client exit-node override for multi-hop routing (Wave
    /// B2a config layer): when set, this client's egress SHOULD route
    /// through the named pool exit node (`host:port`) instead of the
    /// server's global default (`pool.exit_node` in server.json — see
    /// `mgmt_service::HeavySetting::ExitNode`). `None` (default) falls back
    /// to the global default.
    ///
    /// STORAGE ONLY as of Wave B2a: nothing in the data plane
    /// (`ChainForwarder` / gateway forwarding / `pool_dialer` exit
    /// sessions) reads this field yet — actually routing by it is Wave B2b.
    /// Synced pool-wide via `merge_from_json`'s LWW/tombstone gate exactly
    /// like `role`. Validated on `update_client` (see
    /// `validate_exit_node_addr`) — must be `host:port` or unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_role_user(r: &ClientRole) -> bool {
    *r == ClientRole::User
}

/// Light validation for a client's `exit_node` override: must be `host:port`
/// with a non-empty host and a numeric `u16` port. This is config plumbing
/// (Wave B2a) — it deliberately does NOT attempt any DNS/reachability check,
/// only rejects obviously malformed input before it's persisted and synced
/// pool-wide.
pub fn validate_exit_node_addr(addr: &str) -> Result<()> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| Error::Session("exit_node must be in host:port format".into()))?;
    if host.is_empty() {
        return Err(Error::Session("exit_node host must not be empty".into()));
    }
    port.parse::<u16>()
        .map_err(|_| Error::Session("exit_node port must be a valid number (0-65535)".into()))?;
    Ok(())
}

/// Per-client traffic statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub last_connected: Option<DateTime<Utc>>,
    pub total_connections: u64,
    pub last_handshake: Option<DateTime<Utc>>,
}

/// Custom serde for Option<[u8; 32]> as base64 string or null
mod opt_base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use base64::Engine;
        match bytes {
            Some(b) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(b);
                b64.serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<[u8; 32]>, D::Error> {
        use base64::Engine;
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "device_pubkey must be 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
        }
    }
}

/// Custom serde module for [u8; 32] as base64
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        b64.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<[u8; 32], D::Error> {
        use base64::Engine;
        let s = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "PSK must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- P0.1: ClientRole ---------------------------------------------

    #[test]
    fn client_role_defaults_to_user_and_roundtrips() {
        let json = r#"{"id":"a","name":"n","psk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vpn_ip":"10.0.0.2","enabled":true,"created_at":"2026-01-01T00:00:00Z","stats":{"bytes_in":0,"bytes_out":0,"total_connections":0}}"#;
        let c: ClientConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.role, ClientRole::User);
        let c2 = ClientConfig {
            role: ClientRole::Admin,
            ..c.clone()
        };
        let s = serde_json::to_string(&c2).unwrap();
        let back: ClientConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.role, ClientRole::Admin);
    }

    // --- Wave B2a: per-client exit_node config layer -------------------

    #[test]
    fn client_config_exit_node_defaults_to_none_and_roundtrips() {
        // Absent in the wire JSON (older/pre-B2a record) must default to None.
        let json = r#"{"id":"a","name":"n","psk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vpn_ip":"10.0.0.2","enabled":true,"created_at":"2026-01-01T00:00:00Z","stats":{"bytes_in":0,"bytes_out":0,"total_connections":0}}"#;
        let c: ClientConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.exit_node, None);

        let c2 = ClientConfig {
            exit_node: Some("exit.example.com:51820".to_string()),
            ..c.clone()
        };
        let s = serde_json::to_string(&c2).unwrap();
        assert!(
            s.contains("exit_node"),
            "a set exit_node must be present in the serialized JSON"
        );
        let back: ClientConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.exit_node, Some("exit.example.com:51820".to_string()));

        // None must be omitted entirely (skip_serializing_if), same
        // backward-compat contract as `role`/`qos`/`device_pubkey`.
        let s_none = serde_json::to_string(&c).unwrap();
        assert!(
            !s_none.contains("exit_node"),
            "an unset exit_node must not appear in the serialized JSON"
        );
    }
}
