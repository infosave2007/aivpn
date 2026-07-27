//! Tiny helpers shared between the two management-request transports:
//! `mgmt_service.rs` (the unconditional, transport-agnostic core — no
//! feature gate, every server build needs it) and `management_api.rs`
//! (the axum/Unix-socket REST transport, `#[cfg(feature = "management-api",
//! unix)]`-only).
//!
//! This module itself carries NO feature gate — it must compile in the same
//! unconditional builds `mgmt_service.rs` does — so `management_api.rs`
//! (gated, strictly narrower) can always depend on it too. That asymmetry is
//! why these were previously duplicated verbatim in both files rather than
//! one importing from the other.

/// True iff the aivpn kernel module's device node is present.
pub fn kernel_loaded() -> bool {
    std::path::Path::new("/dev/aivpn").exists()
}

/// Deserialises a field that can be absent (don't touch), null (clear), or
/// a value (set) — the standard three-state "PATCH-style optional field"
/// shape used by both the tunnel (`mgmt_service.rs`) and REST
/// (`management_api.rs`) client-PATCH request bodies.
pub fn deserialize_opt_opt<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    use serde::Deserialize as _;
    Ok(Some(Option::<T>::deserialize(de)?))
}
