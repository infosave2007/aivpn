//! Подпись тестовых профилей по тем же правилам, что и у генератора.

pub(crate) fn sign(profile: &mut aivpn_common::mask::MaskProfile, key: &ed25519_dalek::SigningKey) {
    profile.sign(key).unwrap();
}
