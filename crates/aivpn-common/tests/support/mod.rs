use aivpn_common::mask::{preset_masks, BootstrapDescriptor};
use ed25519_dalek::{Signer, SigningKey};

pub fn signed_bootstrap() -> ([u8; 32], String) {
    let key = SigningKey::from_bytes(&[37; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut mask = preset_masks::webrtc_zoom_v3();
    mask.sign(&key).unwrap();
    let mut descriptor = BootstrapDescriptor {
        descriptor_id: "mobile-transport-test".into(),
        version: 1,
        created_at: now.saturating_sub(1),
        expires_at: now + 3600,
        base_mask_ids: vec![mask.mask_id.clone()],
        embedded_masks: vec![mask],
        candidate_count: 1,
        kdf_salt: [41; 32],
        signature: [0; 64],
    };
    descriptor.signature = key.sign(&descriptor.signing_bytes()).to_bytes();
    (
        key.verifying_key().to_bytes(),
        serde_json::to_string(&vec![descriptor]).unwrap(),
    )
}
