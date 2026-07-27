//! AIVPN Server Implementation - Production v0.3
//!
//! Gateway server with:
//! - UDP listener with O(1) tag validation
//! - Session management
//! - TUN device and NAT forwarding
//! - Mimicry decoding
//! - Neural Resonance Module (Patent 1 — Signal Reconstruction Resonance)
//! - Automatic Mask Rotation (Patent 3 — Self-Expanding Cognitive System)
//! - Mask Catalog with Neural Unpack signatures (Patent 9 — Skill Discovery)
//! - Automatic Key Rotation
//! - Passive Mask Distribution
//! - Prometheus Metrics

pub mod batch_io;
pub mod client_db;
pub mod gateway;
pub mod nat;
pub mod server;
pub mod session;

#[cfg(all(feature = "management-api", unix))]
pub mod management_api;

// Phase 3-5 modules
// The inline ML-DPI gate was moved to aivpn-common (shared with the client
// self-gate); re-export it here so `crate::dpi_gate::…` keeps resolving.
#[cfg(feature = "neural")]
pub use aivpn_common::dpi_gate;
pub mod key_rotation;
pub mod mask_feedback;
pub mod metrics;
pub mod neural;
pub mod passive_distribution;

// Auto Mask Recording modules
pub mod gmm;
pub mod mask_gen;
pub mod mask_repair;
pub mod mask_store;
pub mod recording;

// 0.8.0 modules
pub mod audit_log;
pub mod backup;
pub mod ebpf_observer;
pub mod pool_sync;
pub mod qos;
pub mod tc_loader;

// 0.9.0 modules
pub mod chain_forwarder;
#[cfg(feature = "dns")]
pub mod dns_proxy;
pub mod mtls;
pub mod site_sync;

pub mod bootstrap_publish;

// server.json schema — shared by main.rs startup loading and the management
// API's PUT /api/v1/config type-level validation.
pub mod server_config;

pub use client_db::ClientDatabase;
pub use gateway::{Gateway, GatewayConfig};
pub use nat::NatForwarder;
pub use server::AivpnServer;
pub use server::ServerArgs;
pub use session::SessionManager;

// Phase 3-5 exports
pub use key_rotation::{KeyRotationConfig, KeyRotator};
pub use mask_feedback::MaskFeedbackStore;
pub use metrics::MetricsCollector;
pub use neural::{NeuralConfig, NeuralResonanceModule, ResonanceResult, ResonanceStatus};
pub use passive_distribution::{PassiveDistributionConfig, PassiveMaskReceiver};

// Auto Mask Recording exports
pub use mask_store::MaskStore;
pub use recording::RecordingManager;
