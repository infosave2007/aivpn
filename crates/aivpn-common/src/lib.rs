//! AIVPN Common Library
//!
//! Shared cryptographic primitives, protocol structures, and utilities
//! for AIVPN client and server implementations.

pub mod client_wire;
pub mod crypto;
pub mod error;
pub mod event_log;
pub mod fec;
pub mod mask;
pub mod mimic_protocol;
pub mod network_config;
pub mod protocol;
pub mod quality;
pub mod quic_initial;
pub mod recording;

#[cfg(feature = "dpi-gate")]
pub mod dpi_gate;

#[cfg(feature = "client-upload")]
pub mod mgmt;

#[cfg(feature = "client-upload")]
pub mod mimicry;

#[cfg(feature = "client-upload")]
pub mod upload_pipeline;

#[cfg(feature = "qr")]
pub mod qr;

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
