//! AIVPN Common Library
//!
//! Shared cryptographic primitives, protocol structures, and utilities
//! for AIVPN client and server implementations.

pub mod client_wire;
pub mod crypto;
pub mod diagnostics;
pub mod dns_candidates;
pub mod error;
pub mod event_log;
pub mod fec;
pub mod fragment;
pub mod handshake_retry;
pub mod identity_file;
pub mod local_admin;
pub mod mask;
pub mod mask_state;
pub mod mimic_protocol;
pub mod network_config;
pub mod protocol;
pub mod quality;
pub mod quic_initial;
pub mod recording;
pub mod stun_wire;

#[cfg(feature = "dpi-gate")]
pub mod dpi_gate;

#[cfg(feature = "client-upload")]
pub mod mgmt;

#[cfg(feature = "client-upload")]
pub mod mimicry;

#[cfg(feature = "client-upload")]
mod h3_mask;
#[cfg(feature = "client-upload")]
pub mod mask_io;
#[cfg(feature = "client-upload")]
pub mod quic_mask;
#[cfg(feature = "client-upload")]
pub mod rtc_carrier;
#[cfg(feature = "client-upload")]
pub mod rtc_mask;
#[cfg(feature = "client-upload")]
pub mod srtp_mask;
#[cfg(feature = "client-upload")]
pub mod turn_mask;
#[cfg(feature = "client-upload")]
pub(crate) mod turn_wire;
#[cfg(feature = "client-upload")]
mod verified_wire;

#[cfg(feature = "transport")]
pub mod transport;

// Descriptor-driven extra settings sections for the GUIs. Data only: a build
// with no descriptor file renders no extra settings. Needs `transport` for
// `TransportConfig`.
#[cfg(feature = "ui-ext")]
pub mod ui_ext;

#[cfg(feature = "client-upload")]
pub mod upload_pipeline;

#[cfg(feature = "mobile-tunnel")]
pub mod mobile_tunnel;

#[cfg(feature = "qr")]
pub mod qr;

#[cfg(feature = "ssh-install")]
pub mod ssh_install;

#[cfg(unix)]
pub mod kernel_accel;

pub use client_wire::*;
pub use crypto::*;
pub use error::*;
pub use mask::*;
pub use mimic_protocol::*;
pub use network_config::*;
pub use protocol::*;
pub use recording::*;

pub mod ip_packet;
