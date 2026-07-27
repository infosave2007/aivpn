//! AIVPN Server
//!
//! Main server entry point

use std::sync::Arc;

use tracing_subscriber::{self, EnvFilter};

use clap::Parser;

use crate::gateway::{Gateway, GatewayConfig};
use aivpn_common::error::Result;

/// AIVPN Server - Censorship-resistant VPN gateway
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ServerArgs {
    /// Listen address (host:port). Overridden by listen_addr in server.json. Default: 0.0.0.0:443.
    #[arg(short, long, default_value = "0.0.0.0:443", env = "AIVPN_LISTEN")]
    pub listen: String,

    /// TUN device name (random if not specified — avoids fingerprinting)
    #[arg(long)]
    pub tun_name: Option<String>,

    /// Path to 32-byte server private key file
    #[arg(long)]
    pub key_file: Option<String>,

    /// Config file path
    #[arg(short, long)]
    pub config: Option<String>,

    /// Path to clients database file
    #[arg(long, default_value = "/etc/aivpn/clients.json")]
    pub clients_db: String,

    /// Add a new client with the given name and print config
    #[arg(long, value_name = "NAME")]
    pub add_client: Option<String>,

    /// Remove a client by ID
    #[arg(long, value_name = "ID")]
    pub remove_client: Option<String>,

    /// List all registered clients with stats
    #[arg(long)]
    pub list_clients: bool,

    /// Show client config by ID (for QR / import)
    #[arg(long, value_name = "ID")]
    pub show_client: Option<String>,

    /// Add a new one-time enrollment client (0.9.0+).
    /// The first device to connect will have its static X25519 key bound automatically.
    /// Subsequent connects require the same device key.
    #[arg(long, value_name = "NAME")]
    pub add_client_one_time: Option<String>,

    /// Reset device binding for a client by name or ID (0.9.0+).
    /// Clears the bound device key and re-enables one-time enrollment.
    #[arg(long, value_name = "NAME_OR_ID")]
    pub reset_device: Option<String>,

    /// Management role to assign a client created with `--add-client`
    /// (one of: user, viewer, admin; default: user). Elevating to
    /// `viewer`/`admin` requires the client to already be device-bound,
    /// so this only applies to already-bound clients re-added by name —
    /// for a fresh client, add it first and elevate the role afterwards
    /// once its device has enrolled.
    #[arg(long, value_name = "ROLE")]
    pub role: Option<String>,

    /// Base64-encoded 32-byte X25519 device public key to bind at creation
    /// time, used with `--add-client` (and `--add-client-one-time`). When
    /// given, the new client is created device-bound immediately, so it can
    /// be combined with `--role admin` (or `--role viewer`) to create a
    /// fully elevated client in one shot — no separate enrollment step.
    /// Same base64 alphabet/padding as `device_pubkey` in clients.json
    /// (standard base64, not URL-safe).
    #[arg(long, value_name = "BASE64")]
    pub device_pubkey: Option<String>,

    /// Public IP of this server (embedded into connection keys).
    /// Required when using --add-client or --show-client to generate connection keys.
    #[arg(long, env = "AIVPN_SERVER_IP")]
    pub server_ip: Option<String>,

    /// Per-IP packet rate limit for incoming UDP traffic. Kept generous for
    /// legitimate high-throughput clients but low enough to bound the pre-auth
    /// handshake-scan cost from a single non-spoofed source.
    #[arg(long, env = "AIVPN_PER_IP_PPS_LIMIT", default_value_t = 5000)]
    pub per_ip_pps_limit: u64,

    /// Directory for mask file storage.
    /// Resolved in order: CLI flag → env AIVPN_MASK_DIR → server.json "mask_dir" → default.
    #[arg(long, env = "AIVPN_MASK_DIR")]
    pub mask_dir: Option<String>,

    /// Unix socket path for the management HTTP API.
    /// If not specified, the management API is disabled.
    /// Example: /run/aivpn/api.sock
    #[cfg(all(feature = "management-api", unix))]
    #[arg(long, env = "AIVPN_MANAGEMENT_SOCKET")]
    pub management_socket: Option<String>,

    /// Validate a mask JSON file and print a quality report.
    /// Exits 0 on pass, 1 on structural errors.
    #[arg(long, value_name = "PATH")]
    pub validate_mask: Option<String>,

    /// List all pool nodes bound in the node identity registry
    /// (`pool_nodes.json`, sibling to --clients-db), one node_id + base64
    /// pubkey per line. These are the crypto-proven identities (via
    /// NodeEnrollment) that site-to-site RouteSync authorization trusts.
    #[arg(long)]
    pub list_nodes: bool,

    /// Revoke a bound pool node's identity by node_id, removing it from the
    /// node registry (`pool_nodes.json`, sibling to --clients-db). A
    /// revoked node must re-bind (TOFU, if still allowed) before its
    /// RouteSync adverts are trusted again.
    #[arg(long, value_name = "NODE_ID")]
    pub revoke_node: Option<String>,

    // ── Pool ─────────────────────────────────────────────────────────────────
    /// Pool configuration JSON file path.
    /// Contains: {"peers": ["host:port", ...], "sync_port": 444, "sync_key": "hex"}
    #[arg(long, env = "AIVPN_POOL_CONFIG")]
    pub pool_config: Option<String>,

    // ── Backup / Restore ───────────────────────────────────────────────────────
    /// Export server state (clients DB, masks, config) to a tar.gz archive.
    #[arg(long, value_name = "OUTPUT_PATH")]
    pub export: Option<String>,

    /// Import server state from a tar.gz archive created by --export.
    #[arg(long, value_name = "ARCHIVE_PATH")]
    pub import: Option<String>,

    /// Dry-run mode for --import: print what would change without writing files.
    #[arg(long)]
    pub dry_run: bool,

    // ── Per-client QoS ─────────────────────────────────────────────────────────
    /// Set QoS for a client (by name or ID). Use with --bw-up, --bw-down, --dscp.
    #[arg(long, value_name = "NAME_OR_ID")]
    pub set_client_qos: Option<String>,

    /// Upstream (client→server) bandwidth limit. Example: 10M, 512K, 1G.
    #[arg(long, value_name = "BANDWIDTH")]
    pub bw_up: Option<String>,

    /// Downstream (server→client) bandwidth limit. Example: 50M, 1G.
    #[arg(long, value_name = "BANDWIDTH")]
    pub bw_down: Option<String>,

    /// DSCP traffic class name. Examples: EF, AF41, CS1, BE.
    #[arg(long, value_name = "CLASS")]
    pub dscp: Option<String>,

    /// Priority hint for --set-client-qos: 0 = default, 1 = high, 2 = low.
    #[arg(long, value_name = "0-N")]
    pub priority: Option<u8>,

    // ── Per-client management (enable/disable/rename/expiry) ───────────────────
    /// Enable an existing client (by name or ID).
    #[arg(long, value_name = "NAME_OR_ID")]
    pub enable_client: Option<String>,

    /// Disable an existing client (by name or ID). Disabled clients are
    /// rejected at handshake but keep their record (unlike --remove-client).
    #[arg(long, value_name = "NAME_OR_ID")]
    pub disable_client: Option<String>,

    /// Rename an existing client (by name or ID). Use with --new-name.
    #[arg(long, value_name = "NAME_OR_ID")]
    pub set_client_name: Option<String>,

    /// New name to apply with --set-client-name.
    #[arg(long, value_name = "NAME")]
    pub new_name: Option<String>,

    /// Set or clear an existing client's expiry (by name or ID). Use with --expiry.
    #[arg(long, value_name = "NAME_OR_ID")]
    pub set_client_expiry: Option<String>,

    /// Expiry timestamp in RFC3339 (e.g. 2026-12-31T00:00:00Z) for --set-client-expiry.
    /// Pass an empty string to clear an existing expiry.
    #[arg(long, value_name = "RFC3339-OR-EMPTY")]
    pub expiry: Option<String>,

    // ── Audit Log ──────────────────────────────────────────────────────────────
    /// Path to the append-only admin audit log (JSONL format).
    #[arg(
        long,
        env = "AIVPN_AUDIT_LOG",
        default_value = "/var/log/aivpn/audit.log"
    )]
    pub audit_log: String,

    // ── mTLS CA management ─────────────────────────────────────────────────────
    /// Generate a new ed25519 CA key pair for mTLS client cert signing.
    /// Prints ca_public_key_hex and ca_private_key_hex to stdout, then exits.
    #[arg(long)]
    pub gen_ca: bool,

    /// Sign a client public key with the CA private key and print the cert hex.
    /// Expects a 64-hex-char (32-byte) X25519 public key.
    /// Requires --ca-key.
    #[arg(long, value_name = "PUBKEY_HEX")]
    pub issue_cert: Option<String>,

    /// CA private key hex string (64 hex chars = 32 bytes) for --issue-cert.
    #[arg(long, value_name = "HEX")]
    pub ca_key: Option<String>,

    /// Certificate validity in days (default: 365). Used with --issue-cert.
    #[arg(long, default_value_t = 365)]
    pub days: u64,

    /// Allow direct routing between VPN clients (client-to-client relay, 0.9.0+).
    /// When enabled, packets from one VPN client destined for another VPN IP are
    /// forwarded directly without leaving the server. Disabled by default.
    #[arg(long, env = "AIVPN_ALLOW_PEER_ROUTING")]
    pub allow_peer_routing: bool,

    // ── Mask management ────────────────────────────────────────────────────────
    /// List all mask profiles available in the mask directory.
    #[arg(long)]
    pub list_masks: bool,

    /// Set the preferred mask for a client (by name or ID). Use with --mask-name.
    #[arg(long, value_name = "NAME_OR_ID")]
    pub set_mask: Option<String>,

    /// Mask name to use with --set-mask (e.g. webrtc_zoom_v3, quic_https_v2).
    #[arg(long, value_name = "MASK_NAME")]
    pub mask_name: Option<String>,

    // ── Mask signing / verification (R2 Phase B) ───────────────────────────────
    /// Path to the operator Ed25519 mask-signing PRIVATE key (32-byte seed,
    /// raw or base64). When set, auto-generated masks are signed after the KS
    /// self-test passes. Keep this key SEPARATE from --key-file: it should
    /// live on the signing/operator host, not on every edge node.
    #[arg(long, value_name = "PATH", env = "AIVPN_MASK_SIGNING_KEY")]
    pub mask_signing_key: Option<String>,

    /// Operator Ed25519 mask-verifying PUBLIC key (base64, 32 bytes) used to
    /// verify the embedded signature of masks loaded from --mask-dir.
    /// Derived automatically from --mask-signing-key when omitted.
    #[arg(long, value_name = "BASE64", env = "AIVPN_MASK_OPERATOR_PUBKEY")]
    pub mask_operator_pubkey: Option<String>,

    /// Mask signature verification mode on disk load: off | warn | enforce.
    /// warn (default) logs failures but accepts; enforce rejects unsigned or
    /// badly-signed masks. Overrides server.json "mask_verify_mode".
    #[arg(long, value_name = "MODE", env = "AIVPN_MASK_VERIFY_MODE")]
    pub mask_verify_mode: Option<String>,

    /// Generate a new operator Ed25519 mask-signing key: writes the base64
    /// seed to the given path (0600) and prints the base64 PUBLIC key to
    /// distribute to servers/clients, then exits.
    #[arg(long, value_name = "PATH")]
    pub gen_mask_signing_key: Option<String>,

    /// R2 Phase B: sign every mask JSON in this directory IN PLACE with the
    /// operator key from --mask-signing-key (or config), then exit. Run once
    /// over your mask corpus before turning on mask_verify_mode=enforce.
    #[arg(long, value_name = "DIR")]
    pub sign_mask_dir: Option<String>,

    // ── Bootstrap descriptor distribution ──────────────────────────────────────
    /// Print the current signed bootstrap descriptors (previous/current/next
    /// epoch) as a JSON array, for manual publishing to a CDN/GitHub/Telegram/
    /// other channel. Requires --key-file (an ephemeral server key cannot be
    /// used — nobody's client would trust a descriptor signed by it).
    #[arg(long)]
    pub export_bootstrap_descriptor: bool,

    /// Write --export-bootstrap-descriptor output to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub bootstrap_output: Option<String>,

    /// Downlink padding covertness↔throughput tradeoff: off | light | full
    /// (default full). `full` pads every server→client DATA packet to the
    /// session mask's size distribution (max covertness); `light` pads with a
    /// small capped budget; `off` disables downlink padding (max throughput).
    /// Overrides server.json "downlink_shaping".
    #[arg(long, value_name = "LEVEL", env = "AIVPN_SHAPING_LEVEL")]
    pub shaping_level: Option<String>,
}

/// AIVPN Server instance
pub struct AivpnServer {
    gateway: Gateway,
}

impl AivpnServer {
    /// Create new server instance
    pub fn new(config: GatewayConfig) -> Result<Self> {
        let gateway = Gateway::new(config)?;
        Ok(Self { gateway })
    }

    /// Return a shared reference to the session manager (for pool sync setup).
    pub fn session_manager(&self) -> Arc<crate::session::SessionManager> {
        self.gateway.session_manager()
    }

    /// Return the default MDH bytes from the mask catalog (for pool sync packets).
    pub fn catalog_mdh(&self) -> Vec<u8> {
        self.gateway.catalog_mdh()
    }

    /// Return a live reference to the mask catalog so pool sync reads MDH after rotation.
    pub fn mask_catalog(&self) -> &std::sync::Arc<crate::gateway::MaskCatalog> {
        self.gateway.mask_catalog()
    }

    /// Return a shared handle to the live bootstrap descriptors, kept fresh
    /// by the gateway's rotation task — for the management API's export
    /// endpoint. Must be called before `run()` consumes the gateway.
    pub fn bootstrap_descriptors(
        &self,
    ) -> Arc<parking_lot::RwLock<Vec<aivpn_common::mask::BootstrapDescriptor>>> {
        self.gateway.bootstrap_descriptors()
    }

    /// Return a shared handle to the P1.5 apply-with-rollback tracker, kept
    /// swept by the gateway's periodic cleanup task — for the management
    /// API's `POST /api/v1/config/apply` / `/config/confirm` handlers to
    /// share the SAME `PendingConfigManager` the tunnel path uses. Mirrors
    /// `bootstrap_descriptors()`: must be called before `run()` consumes
    /// the gateway.
    pub fn pending_config(&self) -> Arc<crate::pending_config::PendingConfigManager> {
        self.gateway.pending_config()
    }

    /// B2b (per-client exit routing): shared handle to the gateway's
    /// exit-resolution cache, for callers outside `Gateway`/`AivpnServer`
    /// (`main.rs`'s SIGHUP client-DB-reload handler) that need to
    /// invalidate it after an out-of-band DB change. See
    /// `Gateway::exit_route_cache`'s doc comment.
    pub fn exit_route_cache(&self) -> Arc<dashmap::DashMap<std::net::Ipv4Addr, Option<String>>> {
        self.gateway.exit_route_cache()
    }

    /// P1 REST parity fix: shared handle to the gateway's live
    /// `masked_exit_addr` cell, for `main.rs`'s REST `ServeConfig` — see
    /// `Gateway::masked_exit_addr`'s doc comment. Mirrors
    /// `exit_route_cache()`'s existing sharing pattern.
    pub fn masked_exit_addr(&self) -> Arc<parking_lot::RwLock<Option<String>>> {
        self.gateway.masked_exit_addr()
    }

    /// Set multi-hop chain forwarder.  Must be called before `run()`.
    pub fn set_chain_forwarder(&mut self, cf: Arc<crate::chain_forwarder::ChainForwarder>) {
        self.gateway.set_chain_forwarder(cf);
    }

    /// PHASE 3 (exit / chain-forward over masked transport): wire the
    /// masked pool-client exit route in place of the legacy chain forwarder.
    /// Must be called before `run()`. See `Gateway::set_masked_exit`.
    pub fn set_masked_exit(
        &mut self,
        dialer: Arc<crate::pool_dialer::PoolDialer>,
        exit_addr: String,
    ) {
        self.gateway.set_masked_exit(dialer, exit_addr);
    }

    /// P1.3 (priority pool beacon): install a `PoolDialer` handle for the
    /// admin-revoke immediate beacon, independent of whether this node
    /// dials an exit. See `Gateway::set_pool_dialer`. Must be called
    /// before `run()`.
    pub fn set_pool_dialer(&mut self, dialer: Arc<crate::pool_dialer::PoolDialer>) {
        self.gateway.set_pool_dialer(dialer);
    }

    /// PHASE 4 (reverse chain-forward): hand out a clone of the sender an
    /// exit node's reverse-direction `ChainForward` reply should be pushed
    /// into on this (entry) node. See `Gateway::chain_reverse_downlink_sender`.
    pub fn chain_reverse_downlink_sender(&self) -> tokio::sync::mpsc::Sender<Vec<u8>> {
        self.gateway.chain_reverse_downlink_sender()
    }

    /// PHASE 4 (per-node identity): install the pool-node identity registry.
    /// Must be called before `run()`. See `Gateway::set_node_registry`.
    pub fn set_node_registry(&mut self, registry: Arc<crate::node_registry::NodeRegistry>) {
        self.gateway.set_node_registry(registry);
    }

    /// D1 (Phase 4): enforce crypto-proven node identity in route
    /// authorization (`pool.require_node_enrollment`). See
    /// `Gateway::set_require_node_enrollment`.
    pub fn set_require_node_enrollment(&mut self, require: bool) {
        self.gateway.set_require_node_enrollment(require);
    }

    /// Return a shared handle to the live Prometheus metrics collector, for
    /// the management API's SSE `state` event enrichment. Always
    /// constructible: `MetricsCollector` degrades to a no-op when the crate
    /// is built without the `metrics` feature, so callers on that side don't
    /// need to cfg-gate this accessor — only whether they *use* the values.
    pub fn metrics(&self) -> Arc<crate::metrics::MetricsCollector> {
        self.gateway.metrics().clone()
    }

    /// Run the server
    pub async fn run(self) -> Result<()> {
        self.gateway.run().await
    }
}

/// Initialize logging
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("aivpn_server=debug".parse().unwrap())
                .add_directive("aivpn_common=debug".parse().unwrap()),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        // Create temp mask dir with a preset mask for the test
        let mask_dir = std::path::PathBuf::from("/tmp/aivpn-test-server-masks");
        let _ = std::fs::create_dir_all(&mask_dir);
        let mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let json = serde_json::to_string_pretty(&mask).unwrap();
        std::fs::write(mask_dir.join(format!("{}.json", mask.mask_id)), &json).unwrap();
        std::fs::write(mask_dir.join(format!("{}.stats", mask.mask_id)), "{}").unwrap();

        let mut config = GatewayConfig::default();
        config.mask_dir = mask_dir;
        let server = AivpnServer::new(config);
        assert!(server.is_ok());
    }
}
