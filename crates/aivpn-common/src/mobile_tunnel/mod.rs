//! Shared mobile VPN tunnel core (feature `mobile-tunnel`), used by
//! `aivpn-ios-core` and `aivpn-android-core`. Wire protocol and behavior are
//! byte-for-byte those of the former per-platform copies; `android_tunnel.rs`
//! was the source-of-truth text.

pub mod encryptor;
pub mod io;
pub mod state;

pub use encryptor::*;
pub use io::*;
pub use state::*;
