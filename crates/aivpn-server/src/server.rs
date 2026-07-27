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

    /// Set multi-hop chain forwarder.  Must be called before `run()`.
    pub fn set_chain_forwarder(&mut self, cf: Arc<crate::chain_forwarder::ChainForwarder>) {
        self.gateway.set_chain_forwarder(cf);
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
