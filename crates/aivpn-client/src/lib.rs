//! AIVPN Client Implementation
//!
//! Client with:
//! - TUN device for packet capture
//! - Mimicry Engine for traffic shaping
//! - Key exchange and session management
//! - Auto Mask Recording CLI support

/// Serialise tests that mutate the `HOME` env var to prevent races when
/// tests run in parallel threads within the same binary.
#[cfg(test)]
pub(crate) static TEST_HOME_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod adaptive;
pub mod bench;
pub mod bootstrap_cache;
pub mod bootstrap_loader;
pub mod client;
pub mod dns_proxy;
pub mod kill_switch;
pub mod mask_catalog;
pub mod mask_feedback_log;
pub mod net_change;
pub mod proxy;
pub mod record_cmd;
pub mod secure_write;
pub mod server_pool;
pub mod tunnel;

pub use aivpn_common::mimicry::MimicryEngine;
// P2.R: QR generation lives in aivpn-common (shared with the mobile FFI
// cores) — re-exported here so existing `crate::qr::...` / `aivpn_client::qr`
// callers keep working unchanged.
pub use aivpn_common::qr;
pub use client::AivpnClient;
pub use tunnel::Tunnel;
