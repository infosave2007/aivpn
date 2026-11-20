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

// Тело клиента переехало сюда из main.rs и обращается к своему же крейту по
// имени (`aivpn_client::…`, 32 места). Псевдоним позволяет этим путям
// продолжать работать изнутри библиотеки, не переписывая их на `crate::`.
extern crate self as aivpn_client;

#[cfg(all(feature = "app-routing", not(any(target_os = "linux", windows))))]
compile_error!("app-routing поддерживается только в desktop-сборках Linux и Windows");

pub mod adaptive;
mod admin_ipc;
pub mod bench;
pub mod bootstrap_cache;
pub mod bootstrap_loader;
pub mod client;
pub mod dns_proxy;
pub mod kill_switch;
pub mod mask_catalog;
pub mod mask_feedback_log;
pub mod net_change;
mod packet_endpoint;
pub mod proxy;
#[cfg(all(
    feature = "desktop-service",
    any(target_os = "linux", target_os = "windows")
))]
pub mod service_dns;
pub mod session_admin;
#[cfg(target_os = "windows")]
pub use packet_endpoint::managed::ManagedChannel;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use packet_endpoint::managed::{ConfirmedAssignment, ManagedEndpoint};
pub mod record_cmd;
pub mod run;
pub mod secure_write;
pub mod server_pool;
#[cfg(feature = "ssh-install")]
pub mod ssh_install_cmd;
pub mod tunnel;

pub use aivpn_common::mimicry::MimicryEngine;
// P2.R: QR generation lives in aivpn-common (shared with the mobile FFI
// cores) — re-exported here so existing `crate::qr::...` / `aivpn_client::qr`
// callers keep working unchanged.
pub use aivpn_common::qr;
// Wave C2a/C2b: the SSH-install client (+ embedded installer bundle,
// high-level orchestration) lives in aivpn-common (shared with the mobile
// FFI cores) — re-exported here so `crate::ssh_install::...` /
// `aivpn_client::ssh_install` callers keep working unchanged. Gated so the
// default build (and the mobile FFI cores, which don't enable this feature)
// never pull in `russh`/`russh-sftp`.
#[cfg(feature = "ssh-install")]
pub use aivpn_common::ssh_install;
pub use client::AivpnClient;
pub use run::run;
pub use tunnel::Tunnel;

#[cfg(target_os = "linux")]
mod transport_routes;

pub mod reconnect;

#[cfg(feature = "cli-runtime")]
pub mod entry;
#[cfg(all(
    feature = "desktop-worker",
    any(target_os = "linux", target_os = "windows")
))]
mod managed_administration;
#[cfg(all(feature = "desktop-worker", target_os = "linux"))]
pub mod managed_worker;
#[cfg(all(feature = "desktop-worker", target_os = "windows"))]
#[path = "managed_worker_windows.rs"]
pub mod managed_worker;
#[cfg(all(
    feature = "desktop-worker",
    any(target_os = "linux", target_os = "windows")
))]
mod managed_worker_config;
#[cfg(target_os = "linux")]
pub mod network_helper;
#[cfg(target_os = "linux")]
pub mod network_session;
#[cfg(all(feature = "desktop-service", target_os = "linux"))]
#[path = "routing_service/linux.rs"]
pub mod routing_service;
#[cfg(all(feature = "desktop-service", target_os = "windows"))]
#[path = "routing_service/windows.rs"]
pub mod routing_service;

#[cfg(all(windows, feature = "cli-runtime"))]
pub mod classic_windows;

#[cfg(all(feature = "cli-runtime", any(target_os = "linux", windows)))]
pub mod installer;

#[cfg(windows)]
mod windows_log;
