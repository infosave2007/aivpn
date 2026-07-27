//! `server.json` on-disk schema (`ServerFileConfig`) shared by the binary's
//! startup loader and the management API's `PUT /api/v1/config` validator.
//!
//! Living in the lib (not `main.rs`) is what lets the API validate an uploaded
//! config by deserializing it into the exact struct the next server start will
//! parse — a key-name allowlist here previously drifted out of sync with the
//! real schema and either rejected valid configs or accepted configs that
//! bricked the next start (`load_server_file_config` exits on parse failure).
//!
//! `deny_unknown_fields` makes typo'd top-level keys a hard parse error in
//! both places, so the API rejects them with a clear message instead of the
//! server silently ignoring (or fatally rejecting) them later.

use std::net::Ipv4Addr;

use serde::{Deserialize, Deserializer};

use crate::bootstrap_publish::BootstrapPublishConfig;
#[cfg(feature = "dns")]
use crate::dns_proxy::DnsProxyConfig;
use crate::mtls::MtlsConfig;
use crate::neural::NeuralConfig;
use crate::pool_sync::PoolSyncConfig;
use crate::site_sync::SiteToSiteConfig;

/// `"auto"` or a fixed number in `server.json` `tun_mtu` field.
#[derive(Debug, Clone)]
pub enum MtuSetting {
    Auto,
    Fixed(u16),
}

impl<'de> Deserialize<'de> for MtuSetting {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::String(s) if s == "auto" => Ok(MtuSetting::Auto),
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|n| if n <= 65535 { Some(n as u16) } else { None })
                .map(MtuSetting::Fixed)
                .ok_or_else(|| D::Error::custom("tun_mtu must be 0–65535")),
            _ => Err(D::Error::custom("tun_mtu must be a number or \"auto\"")),
        }
    }
}

/// JSON-only representation of `network_config` that allows `"mtu": "auto"`.
/// Converted to `VpnNetworkConfig` (with a concrete `u16` MTU) in the binary's
/// `resolve_network_config`. Using a separate struct avoids touching
/// `VpnNetworkConfig` which is also used on the wire.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct JsonNetworkConfig {
    pub server_vpn_ip: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
    /// `"auto"` or absent → follow `tun_mtu`; a number → fixed (clamped to ≤ tun_mtu).
    #[serde(default)]
    pub mtu: Option<MtuSetting>,
    #[serde(default)]
    pub keepalive_secs: Option<u8>,
    #[serde(default)]
    pub ipv6_enabled: bool,
    #[serde(default = "default_ipv6_prefix_str")]
    pub ipv6_prefix: String,
}

fn default_ipv6_prefix_str() -> String {
    "fd10:cafe::/48".to_string()
}

/// server.json `"feedback"` block (§2 M3). All optional; omitted keys fall back
/// to the gateway defaults.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FeedbackFileConfig {
    /// Min consecutive failures for a mask before a client records a failure.
    pub report_failure_threshold: Option<u8>,
    /// Min spacing (seconds) between a client's successive feedback sends.
    pub report_interval_secs: Option<u32>,
}

/// server.json `"polymorphic"` block (§3 F). Example:
/// ```json
/// "polymorphic": { "all_sessions": true, "base_mask": "webrtc_zoom_v3" }
/// ```
/// `all_sessions` defaults to `false` (feature disabled) when the block or
/// key is omitted. `base_mask` is optional — when absent, each session uses
/// its own current mask as the polymorphic base instead of a fixed preset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolymorphicFileConfig {
    #[serde(default)]
    pub all_sessions: bool,
    pub base_mask: Option<String>,
}

/// Top-level `server.json` schema. This is THE schema: the management API's
/// `PUT /api/v1/config` accepts a body iff it deserializes into this struct,
/// which is also exactly what the server parses at startup.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFileConfig {
    pub listen_addr: Option<String>,
    pub tun_name: Option<String>,
    pub tun_addr: Option<Ipv4Addr>,
    pub tun_netmask: Option<Ipv4Addr>,
    pub network_config: Option<JsonNetworkConfig>,
    pub mask_dir: Option<String>,
    pub bootstrap_mask_files: Option<Vec<String>>,
    pub session_timeout_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
    pub tun_mtu: Option<MtuSetting>,
    #[serde(default)]
    pub pool: Option<PoolSyncConfig>,
    /// Unix socket path for the management HTTP API (the aivpn-web panel
    /// connects here). CLI `--management-socket` / `AIVPN_MANAGEMENT_SOCKET`
    /// take precedence; this lets the socket be set from server.json too.
    /// Parsed unconditionally (even in builds without `management-api`) so a
    /// config written for a full build never fails schema validation.
    #[serde(default)]
    pub management_socket: Option<String>,
    #[serde(default)]
    pub site_to_site: Option<SiteToSiteConfig>,
    #[serde(default)]
    pub mtls: Option<MtlsConfig>,
    /// DNS-over-HTTPS proxy block. Typed when the `dns` feature is enabled;
    /// accepted as raw JSON otherwise so a `dns`-less build neither rejects
    /// the key at startup nor lets `PUT /api/v1/config` 400 a valid config.
    #[cfg(feature = "dns")]
    #[serde(default)]
    pub dns: Option<DnsProxyConfig>,
    #[cfg(not(feature = "dns"))]
    #[serde(default)]
    pub dns: Option<serde_json::Value>,
    #[serde(default)]
    pub allow_peer_routing: Option<bool>,
    /// A7 downlink shaping parity. Absent = enabled (pad server→client DATA to
    /// the session mask's own size distribution). Set `false` for the
    /// throughput-first profile.
    #[serde(default)]
    pub downlink_shaping: Option<bool>,
    /// Neural Resonance master switch. Absent = enabled (the default). Set
    /// `false` to turn off compromise detection entirely: the gateway skips the
    /// periodic resonance loop, so neither the per-mask autoencoder (MSE) nor
    /// its sibling inline ML-DPI "reads-as-tunnel" gate runs and neither can
    /// trigger a mask rotation. Useful for debugging, perf profiling, or
    /// silencing false positives without a rebuild.
    #[serde(default)]
    pub neural_enabled: Option<bool>,
    /// Neural Resonance / ML-DPI gate tuning. A `"neural"` block whose fields
    /// override `NeuralConfig` defaults (thresholds, check interval, rotation
    /// cooldown). Absent = built-in defaults. Lets operators calibrate detection
    /// (Part 6) and lets tests force a rotation by dropping the thresholds.
    #[serde(default)]
    pub neural: Option<NeuralConfig>,
    #[serde(default)]
    pub bootstrap_publish: Option<BootstrapPublishConfig>,
    /// §2 crowdsourced-feedback tuning, pushed to opted-in clients via
    /// `FeedbackConfig` so thresholds can change without a client release.
    #[serde(default)]
    pub feedback: Option<FeedbackFileConfig>,
    /// §3 F "every session polymorphic" server policy — see
    /// `PolymorphicFileConfig`. Absent = disabled (opt-in `MaskPreference`
    /// remains the only way a client gets a polymorphic mask).
    #[serde(default)]
    pub polymorphic: Option<PolymorphicFileConfig>,
    /// R2 Phase B: path to the operator Ed25519 mask-signing key (32-byte
    /// seed, raw or base64). Signs auto-generated masks post self-test.
    #[serde(default)]
    pub mask_signing_key: Option<String>,
    /// R2 Phase B: operator Ed25519 verifying public key (base64, 32 bytes)
    /// for mask-load verification. Derived from `mask_signing_key` if absent.
    #[serde(default)]
    pub mask_operator_pubkey: Option<String>,
    /// R2 Phase B: mask verification mode on disk load: "off" | "warn"
    /// (default) | "enforce".
    #[serde(default)]
    pub mask_verify_mode: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/config/server.json.example"
    ));

    /// The shipped example config must round-trip through the schema — this is
    /// what `PUT /api/v1/config` validates against, so a regression here means
    /// the panel can no longer save the stock config (the old key-name
    /// allowlist's `bootstrap_publish` bug, generalized).
    #[test]
    fn shipped_example_config_parses() {
        let cfg: ServerFileConfig =
            serde_json::from_str(EXAMPLE).expect("deploy/config/server.json.example must parse");
        assert_eq!(
            cfg.management_socket.as_deref(),
            Some("/run/aivpn/api.sock")
        );
        assert!(cfg.bootstrap_publish.is_some());
        assert!(cfg.polymorphic.is_some());
    }

    /// Typo'd top-level keys must be a parse error (deny_unknown_fields), so
    /// the API rejects them instead of the server silently ignoring them.
    #[test]
    fn unknown_top_level_key_is_rejected() {
        let err = serde_json::from_str::<ServerFileConfig>(r#"{ "listen_adr": "0.0.0.0:443" }"#)
            .unwrap_err();
        assert!(err.to_string().contains("listen_adr"), "{err}");
    }

    /// Wrong-typed values must be a parse error — a valid-key/wrong-type body
    /// previously passed the key-name allowlist and bricked the next start.
    #[test]
    fn wrong_typed_field_is_rejected() {
        assert!(serde_json::from_str::<ServerFileConfig>(r#"{ "listen_addr": 443 }"#).is_err());
        assert!(
            serde_json::from_str::<ServerFileConfig>(r#"{ "idle_timeout_secs": "thirty" }"#)
                .is_err()
        );
        assert!(serde_json::from_str::<ServerFileConfig>(r#"{ "tun_mtu": "fast" }"#).is_err());
    }
}
