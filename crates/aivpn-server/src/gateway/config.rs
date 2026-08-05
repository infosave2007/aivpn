//! Gateway configuration: [`GatewayConfig`] and the downlink [`ShapingLevel`]
//! knob it carries. Moved out of `gateway/mod.rs` verbatim (pure move, no
//! behavior change) as part of the god-file decomposition.

use std::sync::Arc;

use serde::{Deserialize, Deserializer};

use aivpn_common::event_log::EventBus;
use aivpn_common::mask::MaskProfile;
use aivpn_common::network_config::VpnNetworkConfig;

use crate::audit_log::AuditLogger;
use crate::client_db::ClientDatabase;
use crate::neural::NeuralConfig;
use crate::qos::QosEnforcer;

/// Covertness↔throughput tradeoff for server→client (downlink) padding
/// (1c). Sourced from the `"downlink_shaping"` key in server.json (accepts
/// either the legacy bool or one of `"off"`/`"light"`/`"full"`) or
/// `--shaping-level` / `AIVPN_SHAPING_LEVEL` on the CLI.
///
/// * **`Full`** (default, `true`) — pad every downlink DATA packet to the
///   session mask's own size distribution, exactly the historical (only)
///   behavior. Maximizes traffic-shape covertness: uplink and downlink share
///   one size signature on the 5-tuple. Costs the most per packet — a
///   size-distribution sample, a padding-strategy calculation, and the
///   padding bytes themselves go out on the wire.
/// * **`Light`** — still pads (so downlink packets are not trivially
///   distinguishable from uplink by "always exactly the unpadded IP-payload
///   size"), but caps the padding budget far below `Full`'s target, trading
///   most of the covertness for most of the throughput back.
/// * **`Off`** (`false`) — no downlink padding at all, the historical
///   `downlink_shaping: false`. Maximum throughput; downlink packet sizes
///   leak the exact payload size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShapingLevel {
    /// No downlink padding — maximum throughput, least covert.
    Off,
    /// Capped padding budget — partial covertness, most of the throughput.
    Light,
    /// Full mask size-distribution padding (default; matches historical `true`).
    #[default]
    Full,
}

impl std::str::FromStr for ShapingLevel {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "false" => Ok(ShapingLevel::Off),
            "light" => Ok(ShapingLevel::Light),
            "full" | "true" => Ok(ShapingLevel::Full),
            other => Err(format!(
                "invalid shaping level {:?}: expected \"off\", \"light\", or \"full\"",
                other
            )),
        }
    }
}

impl<'de> Deserialize<'de> for ShapingLevel {
    /// Accepts the historical bool (`true`→`Full`, `false`→`Off`) for
    /// backward compatibility with existing `server.json` files, as well as
    /// the new `"off"`/`"light"`/`"full"` strings (case-insensitive).
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::Bool(true) => Ok(ShapingLevel::Full),
            serde_json::Value::Bool(false) => Ok(ShapingLevel::Off),
            serde_json::Value::String(ref s) => s.parse().map_err(D::Error::custom),
            other => Err(D::Error::custom(format!(
                "downlink_shaping must be a bool or one of \"off\"/\"light\"/\"full\", got: {}",
                other
            ))),
        }
    }
}

/// Gateway configuration
#[derive(Clone)]
pub struct GatewayConfig {
    pub listen_addr: String,
    pub per_ip_pps_limit: u64,
    pub tun_name: String,
    pub tun_addr: String,
    pub tun_netmask: String,
    pub network_config: VpnNetworkConfig,
    pub server_private_key: [u8; 32],
    pub signing_key: [u8; 64],
    pub enable_nat: bool,
    /// Enable neural resonance module (Patent 1)
    pub enable_neural: bool,
    /// Neural resonance configuration
    pub neural_config: NeuralConfig,
    /// Client database for PSK-based authentication
    pub client_db: Option<Arc<ClientDatabase>>,
    /// Directory for mask storage (default: /var/lib/aivpn/masks)
    pub mask_dir: std::path::PathBuf,
    /// Session hard timeout in seconds (default: 7 days). `None` uses the default.
    pub session_timeout_secs: Option<u64>,
    /// Session idle timeout in seconds (default: 300). `None` uses the default.
    pub idle_timeout_secs: Option<u64>,
    /// Optional custom bootstrap masks embedded into signed descriptors.
    pub bootstrap_masks: Vec<MaskProfile>,
    /// Server-side NAT TUN MTU. Does not affect client VPN MTU (carried in ServerHello).
    pub tun_mtu: u16,
    /// Structured event bus — emits JSON-lines events to stdout (and optional webhook).
    pub event_bus: EventBus,
    /// Per-client QoS enforcer (token bucket + DSCP).
    pub qos_enforcer: Arc<QosEnforcer>,
    /// Multi-hop exit node forwarder.  When `Some`, client Data packets are
    /// relayed to the exit node instead of being NAT-forwarded locally.
    pub chain_forwarder: Option<Arc<crate::chain_forwarder::ChainForwarder>>,
    /// Optional mTLS certificate policy.  `None` = no cert verification.
    pub mtls: Option<crate::mtls::MtlsConfig>,
    /// When `true`, this node accepts `ChainForward` control messages and
    /// injects them directly into the TUN device (exit-node role).
    /// Must be set explicitly — defaults to `false` to prevent open relay.
    pub exit_node_enabled: bool,
    /// Append-only audit log (H-S-8). Records security-relevant session events.
    /// Defaults to `AuditLogger::disabled()` (writes to /dev/null).
    pub audit_log: AuditLogger,
    /// Allow direct client-to-client packet routing inside the VPN subnet (0.9.0+).
    /// When false (default), VPN-to-VPN traffic is silently dropped at the TUN level.
    pub allow_peer_routing: bool,
    /// Optional auto-publish configuration: pushes freshly-rotated bootstrap
    /// descriptors to external channels (S3-compatible CDN, GitHub release,
    /// Telegram) so brand-new clients without a working connection key yet
    /// can discover them. `None` disables auto-publish entirely.
    pub bootstrap_publish: Option<crate::bootstrap_publish::BootstrapPublishConfig>,
    /// §2 crowdsourced blocking feedback — minimum consecutive failed
    /// connection attempts with the same mask family before a client records a
    /// failure outcome. Pushed to opted-in clients via `FeedbackConfig`.
    /// Sourced from the optional `"feedback"` block in server.json.
    pub feedback_report_failure_threshold: u8,
    /// §2 crowdsourced blocking feedback — minimum spacing (seconds) between a
    /// client's successive `MaskFeedback` sends. Pushed via `FeedbackConfig`.
    pub feedback_report_interval_secs: u32,
    /// §3 F "every session polymorphic" server policy. When `true`, every
    /// session gets a polymorphic mask variant pushed automatically right
    /// after its handshake completes — the client does not need to opt in
    /// via `MaskPreference`. Sourced from the optional `"polymorphic"` block
    /// in server.json (`{"all_sessions": true, "base_mask": "..."}`).
    /// Defaults to `false` (opt-in per-client `MaskPreference` remains the
    /// only way to get a polymorphic mask).
    pub polymorphic_all_sessions: bool,
    /// §3 F policy base mask preset id (e.g. `"webrtc_zoom_v3"`) used as the
    /// input to `MaskProfile::to_polymorphic` when `polymorphic_all_sessions`
    /// is enabled. `None` means "use the session's own current mask as the
    /// base" — the same fallback the client-driven `MaskPreference` path
    /// would use if it deferred to the active mask instead of an explicit
    /// `base_mask_id`.
    pub polymorphic_base_mask: Option<String>,
    /// A7/1c downlink shaping level: the covertness↔throughput tradeoff for
    /// server→client DATA padding. `Full` (default) pads to a size sampled
    /// from the session mask's own size distribution — the same distribution
    /// the client uses for uplink — so uplink and downlink packets share one
    /// size signature on a 5-tuple instead of downlink being systematically
    /// smaller (pad_len=0). `Light` still pads but at a capped budget;
    /// `Off` disables downlink padding entirely (max throughput). Padding is
    /// written into the existing `pad_len` field, which every client already
    /// strips (`parse_downlink_inner`), so every level is wire- and
    /// decode-compatible with all client versions. Sourced from the optional
    /// `"downlink_shaping"` key in server.json (bool or string) or
    /// `--shaping-level`. See [`ShapingLevel`] for the full tradeoff writeup.
    pub downlink_shaping: ShapingLevel,
    /// R2 Phase B: operator Ed25519 mask-signing key SEED (32 bytes). When
    /// `Some`, freshly generated masks are signed after the KS self-test
    /// passes. Separate from `server_private_key`/`signing_key` (transport):
    /// a compromised edge server key must not be able to forge mask
    /// provenance. Sourced from `--mask-signing-key` / server.json
    /// `mask_signing_key` (a key file path). `None` = generate unsigned.
    pub mask_signing_key: Option<[u8; 32]>,
    /// R2 Phase B: operator Ed25519 verifying key for mask artifact
    /// verification on disk load. When `None` but `mask_signing_key` is set,
    /// the public key is derived from it. Sourced from
    /// `--mask-operator-pubkey` / server.json `mask_operator_pubkey` (base64).
    pub mask_operator_pubkey: Option<[u8; 32]>,
    /// R2 Phase B: config-gated verification level for masks loaded from
    /// `mask_dir` (off | warn | enforce). Default `warn` — log-and-accept, so
    /// existing unsigned corpora keep working. Sourced from
    /// `--mask-verify-mode` / server.json `mask_verify_mode`.
    pub mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    /// FORK-B pool-sync redesign: the shared masked-pool-client server
    /// keypair (`crypto::pool_server_keypair(sync_key)`), used to recognize
    /// an incoming masked pool-client handshake from a sibling aivpn node —
    /// the DH side of that handshake is computed against THIS keypair's
    /// public key rather than the real long-term `server_private_key`.
    /// `None` (default) disables all masked-pool-peer handshake recognition;
    /// with it `None` (paired with `pool_client_psk` also `None`) behavior is
    /// byte-for-byte unchanged from before this feature existed.
    pub pool_server_keypair: Option<aivpn_common::crypto::KeyPair>,
    /// FORK-B pool-sync redesign: the shared masked-pool-client PSK
    /// (`crypto::pool_client_psk(sync_key)`), paired with
    /// `pool_server_keypair`. Both must be `Some` for masked pool-client
    /// handshakes to be recognized.
    pub pool_client_psk: Option<[u8; 32]>,
    /// P1.2b: the public `host:port` a client should dial to reach this
    /// server, used to build the `aivpn://` connection key returned by the
    /// in-tunnel `MgmtRequest` `GET .../connection-key` route
    /// (`mgmt_service::MgmtCtx::server_addr`). Mirrors the REST API's
    /// `management_api::ServeConfig::server_addr` — same value, computed
    /// the same way in `main.rs` from `--server-ip` (falling back to the
    /// listen port). `None` (e.g. `--server-ip` not configured) makes that
    /// route return `503 Unavailable`, matching the REST path's behavior.
    pub mgmt_server_addr: Option<String>,
    /// P1.2b: on-disk path to the append-only audit-log JSONL file, read by
    /// the in-tunnel `MgmtRequest` `GET /api/v1/audit-log` route
    /// (`mgmt_service::MgmtCtx::audit_log_path`). Mirrors the REST API's
    /// `management_api::ServeConfig::audit_log_path` — same value, computed
    /// the same way in `main.rs` from `--audit-log`. `None` makes that route
    /// return `404 NotFound`, matching the REST path's behavior.
    pub audit_log_path: Option<std::path::PathBuf>,
    /// P1 (global exit live-swap): on-disk path to `server.json`, used to
    /// re-read `pool.exit_node` from the in-tunnel `MgmtRequest` side-effect
    /// hook (`Gateway::dispatch_mgmt_request`'s call to
    /// `apply_global_exit_and_teardown`) so a confirmed `HeavySetting::ExitNode`
    /// apply (which only persists
    /// the change to disk — see that variant's doc comment) also takes
    /// effect on THIS node's live `masked_exit_addr` without a restart.
    /// Mirrors `mgmt_server_addr`/`audit_log_path` — same value `main.rs`
    /// computes for `management_api::ServeConfig::config_path`/
    /// `mgmt_service::MgmtCtx::config_path`. `None` (e.g. no `--config` and
    /// neither default path exists) makes the re-read a no-op every time —
    /// the global default then stays whatever it was resolved to at
    /// startup, exactly like pre-P1 behavior.
    pub server_config_path: Option<std::path::PathBuf>,
    /// Wave B1 (pool topology read endpoints): whether pool sync is
    /// configured on this node AT ALL — i.e. `server.json`'s `pool` block
    /// is present — regardless of `pool.transport`. `Gateway` only ever
    /// receives a live `node_registry`/`pool_dialer` handle (via
    /// `set_node_registry`/`set_pool_dialer`) on a MASKED-transport node
    /// (see `main.rs`'s pool-sync wiring); the legacy, mask-independent
    /// `PeerSyncer` path runs entirely outside `Gateway` and is invisible to
    /// it. This flag is how `dispatch_mgmt_request` tells "pool configured,
    /// but running the legacy transport with no queryable link state"
    /// (`PoolHealth::transport == "legacy"`) apart from "no pool sync at
    /// all" (`"none"`) when `pool_dialer` is `None` either way. Defaults to
    /// `false`.
    pub pool_configured: bool,
}

/// Default §2 `report_failure_threshold`. Kept in sync with the client's
/// `mask_feedback_log::DEFAULT_FAILURE_THRESHOLD`.
pub const DEFAULT_FEEDBACK_FAILURE_THRESHOLD: u8 = 3;
/// Default §2 `report_interval_secs` (1 hour).
pub const DEFAULT_FEEDBACK_REPORT_INTERVAL_SECS: u32 = 3600;

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".to_string(),
            per_ip_pps_limit: 1000,
            tun_name: "aivpn0".to_string(),
            tun_addr: "10.0.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            network_config: VpnNetworkConfig::default(),
            server_private_key: [0u8; 32],
            signing_key: [0u8; 64],
            enable_nat: true,
            enable_neural: true,
            neural_config: NeuralConfig::default(),
            client_db: None,
            mask_dir: std::path::PathBuf::from("/var/lib/aivpn/masks"),
            session_timeout_secs: None,
            idle_timeout_secs: None,
            bootstrap_masks: Vec::new(),
            tun_mtu: crate::nat::DEFAULT_TUN_MTU,
            event_bus: EventBus::new(aivpn_common::event_log::EventSinkConfig {
                stdout: false,
                webhook_url: None,
            }),
            qos_enforcer: Arc::new(QosEnforcer::new()),
            chain_forwarder: None,
            mtls: None,
            exit_node_enabled: false,
            audit_log: AuditLogger::disabled(),
            allow_peer_routing: false,
            bootstrap_publish: None,
            feedback_report_failure_threshold: DEFAULT_FEEDBACK_FAILURE_THRESHOLD,
            feedback_report_interval_secs: DEFAULT_FEEDBACK_REPORT_INTERVAL_SECS,
            polymorphic_all_sessions: false,
            polymorphic_base_mask: None,
            downlink_shaping: ShapingLevel::Full,
            mask_signing_key: None,
            mask_operator_pubkey: None,
            mask_verify_mode: aivpn_common::mask::MaskVerifyMode::default(),
            pool_server_keypair: None,
            pool_client_psk: None,
            mgmt_server_addr: None,
            audit_log_path: None,
            server_config_path: None,
            pool_configured: false,
        }
    }
}
