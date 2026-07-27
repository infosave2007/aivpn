//! Bootstrap-descriptor derivation: the epoch-rotated, ed25519-signed
//! `BootstrapDescriptor`s a client uses to derive its pre-shared handshake
//! candidates before it has ever spoken to this server. Pure functions
//! (no `&Gateway`) factored out of `gateway/mod.rs` — `Gateway::new` and the
//! periodic descriptor-rotation task in `mod.rs` call back into these.

use aivpn_common::mask::{current_unix_secs, BootstrapDescriptor, MaskProfile};

const BOOTSTRAP_ROTATION_SECS: u64 = 24 * 3600;
const BOOTSTRAP_DESCRIPTOR_CANDIDATES: u8 = 4;

/// Descriptor epochs (relative to the current epoch) the server derives and
/// accepts during the handshake candidate scan. See `build_bootstrap_descriptors`
/// for the sizing rationale. Kept as a named constant so the accepted-epoch
/// window and the derived-descriptor set stay in lock-step.
const BOOTSTRAP_EPOCH_WINDOW: [i64; 4] = [-2, -1, 0, 1];

pub(crate) fn bootstrap_epoch(unix_secs: u64) -> u64 {
    unix_secs / BOOTSTRAP_ROTATION_SECS
}

pub fn derive_server_signing_key(server_private_key: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let seed = blake3::derive_key("aivpn-ed25519-signing-v1", server_private_key);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

pub(crate) fn sign_bootstrap_descriptor(
    mut descriptor: BootstrapDescriptor,
    signing_key: &ed25519_dalek::SigningKey,
) -> BootstrapDescriptor {
    use ed25519_dalek::Signer;
    descriptor.signature = signing_key.sign(&descriptor.signing_bytes()).to_bytes();
    descriptor
}

pub(crate) fn build_bootstrap_descriptor(
    server_seed: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    epoch: u64,
    bootstrap_masks: &[MaskProfile],
) -> BootstrapDescriptor {
    let mut hasher = blake3::Hasher::new_keyed(server_seed);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut kdf_salt = [0u8; 32];
    kdf_salt.copy_from_slice(&hash.as_bytes()[..32]);
    let created_at = epoch * BOOTSTRAP_ROTATION_SECS;
    let expires_at = created_at + (2 * BOOTSTRAP_ROTATION_SECS);
    let (base_mask_ids, embedded_masks) = if bootstrap_masks.is_empty() {
        (
            aivpn_common::mask::preset_masks::all()
                .into_iter()
                .map(|mask| mask.mask_id)
                .collect(),
            Vec::new(),
        )
    } else {
        (Vec::new(), bootstrap_masks.to_vec())
    };

    sign_bootstrap_descriptor(
        BootstrapDescriptor {
            descriptor_id: format!("epoch-{}", epoch),
            version: 1,
            created_at,
            expires_at,
            base_mask_ids,
            embedded_masks,
            candidate_count: BOOTSTRAP_DESCRIPTOR_CANDIDATES,
            kdf_salt,
            signature: [0u8; 64],
        },
        signing_key,
    )
}

pub fn build_bootstrap_descriptors(
    server_seed: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    bootstrap_masks: &[MaskProfile],
) -> Vec<BootstrapDescriptor> {
    let epoch = bootstrap_epoch(current_unix_secs());
    // Accept a WINDOW of recent descriptor epochs so a client that reconnects
    // on a slightly stale cached descriptor still matches a LEGITIMATE covert
    // (epoch-rotated, ed25519-signed) mask rather than being forced onto a
    // public preset or into a reconnect loop. With BOOTSTRAP_ROTATION_SECS =
    // 24h, `epoch-2 ..= epoch+1` tolerates a client up to ~48h behind (the
    // client cache retains descriptors for `expires_at + 24h`, i.e. up to two
    // rotations old) plus a +1 slot for a client whose clock runs ahead. This
    // widens the previous `epoch-1 ..= epoch+1` (±24h) window without ever
    // exposing a static/known handshake shape: every candidate here is still a
    // rotated descriptor mask.
    BOOTSTRAP_EPOCH_WINDOW
        .iter()
        .map(|delta| {
            let value = if *delta < 0 {
                epoch.saturating_sub(delta.unsigned_abs())
            } else {
                epoch.saturating_add(*delta as u64)
            };
            build_bootstrap_descriptor(server_seed, signing_key, value, bootstrap_masks)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        bootstrap_epoch, build_bootstrap_descriptors, current_unix_secs, derive_server_signing_key,
        BOOTSTRAP_EPOCH_WINDOW,
    };
    use aivpn_common::mask::preset_masks::webrtc_zoom_v3;

    /// The handshake candidate scan must derive descriptors for a WINDOW of
    /// recent epochs so a client on a slightly stale (but still legitimately
    /// cached) covert descriptor keeps matching a rotated mask instead of being
    /// forced onto a public preset or into a reconnect loop. This pins the
    /// window to `[epoch-2, epoch-1, epoch, epoch+1]` (see BOOTSTRAP_EPOCH_WINDOW):
    /// widening the previous ±1 (24h) window to tolerate a client up to ~48h
    /// behind, without ever emitting a static/known shape (every descriptor is
    /// still epoch-rotated).
    #[test]
    fn bootstrap_descriptor_window_covers_recent_epochs() {
        let seed = [7u8; 32];
        let signing_key = derive_server_signing_key(&seed);
        let masks = [webrtc_zoom_v3()];
        let descriptors = build_bootstrap_descriptors(&seed, &signing_key, &masks);

        let epoch = bootstrap_epoch(current_unix_secs());
        let expected: Vec<String> = BOOTSTRAP_EPOCH_WINDOW
            .iter()
            .map(|delta| {
                let value = if *delta < 0 {
                    epoch.saturating_sub(delta.unsigned_abs())
                } else {
                    epoch.saturating_add(*delta as u64)
                };
                format!("epoch-{}", value)
            })
            .collect();
        let got: Vec<String> = descriptors
            .iter()
            .map(|d| d.descriptor_id.clone())
            .collect();

        assert_eq!(got, expected, "descriptor window must be epoch-2..=epoch+1");
        assert_eq!(descriptors.len(), 4);
        // Two epochs back is now covered (it was NOT under the old ±1 window).
        assert!(got.contains(&format!("epoch-{}", epoch.saturating_sub(2))));
    }
}
