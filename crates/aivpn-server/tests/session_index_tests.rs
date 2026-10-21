use std::sync::Arc;
use std::time::Instant;

use aivpn_common::crypto::{generate_resonance_tag, KeyPair};
use aivpn_common::mask::preset_masks::webrtc_zoom_v3;
use aivpn_server::SessionManager;

fn manager() -> SessionManager {
    SessionManager::new(
        KeyPair::generate(),
        ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]),
        webrtc_zoom_v3(),
    )
}

#[test]
fn adjacent_time_windows_stay_in_fast_index_for_sequential_packets() {
    let manager = manager();
    let session = manager
        .create_session("203.0.113.7:40000".parse().unwrap(), [7; 32], None, None)
        .unwrap();
    let (initial, ratcheted, tw) = {
        let session = session.lock();
        (
            session.keys.tag_secret,
            session.ratcheted_keys.as_ref().unwrap().tag_secret,
            session.tag_window_tw,
        )
    };
    for secret in [initial, ratcheted] {
        for window in [tw.wrapping_sub(1), tw, tw.wrapping_add(1)] {
            for counter in 1..=30 {
                let tag = generate_resonance_tag(&secret, counter, window);
                let found = manager.get_session_by_tag(&tag);
                assert!(
                    found.is_some(),
                    "Обычный пакет не должен требовать recovery"
                );
                assert!(Arc::ptr_eq(&session, &found.unwrap()));
            }
        }
        for window in [tw.wrapping_sub(2), tw.wrapping_add(2)] {
            let tag = generate_resonance_tag(&secret, 1, window);
            assert!(manager.get_session_by_tag(&tag).is_none());
        }
    }
}

#[test]
fn refreshing_index_replaces_old_counter_band_in_all_time_windows() {
    let manager = manager();
    let session = manager
        .create_session("203.0.113.7:40000".parse().unwrap(), [7; 32], None, None)
        .unwrap();
    let (id, secret, old_tw) = {
        let mut session = session.lock();
        let old_tw = session.tag_window_tw;
        session.mark_tag_received(700);
        session.update_tag_window();
        (session.session_id, session.keys.tag_secret, old_tw)
    };
    manager.refresh_session_tags(&id);
    let tw = session.lock().tag_window_tw;
    for window in [old_tw.wrapping_sub(1), old_tw, old_tw.wrapping_add(1)] {
        assert!(manager
            .get_session_by_tag(&generate_resonance_tag(&secret, 0, window))
            .is_none());
    }
    for window in [tw.wrapping_sub(1), tw, tw.wrapping_add(1)] {
        assert!(manager
            .get_session_by_tag(&generate_resonance_tag(&secret, 701, window))
            .is_some());
    }
}

#[test]
fn removing_session_clears_every_indexed_time_window() {
    let manager = manager();
    let session = manager
        .create_session("203.0.113.7:40000".parse().unwrap(), [7; 32], None, None)
        .unwrap();
    let (id, secret, tw) = {
        let session = session.lock();
        (
            session.session_id,
            session.keys.tag_secret,
            session.tag_window_tw,
        )
    };
    let tags = [tw.wrapping_sub(1), tw, tw.wrapping_add(1)]
        .map(|window| generate_resonance_tag(&secret, 1, window));
    for tag in &tags {
        assert!(manager.get_session_by_tag(tag).is_some());
    }
    assert_eq!(manager.remove_session(&id), Some(id));
    for tag in &tags {
        assert!(manager.get_session_by_tag(tag).is_none());
    }
}

#[test]
fn ratchet_keeps_old_time_windows_only_until_grace_expires() {
    let manager = manager();
    let session = manager
        .create_session("203.0.113.7:40000".parse().unwrap(), [7; 32], None, None)
        .unwrap();
    let (id, old_secret, new_secret, tw) = {
        let session = session.lock();
        (
            session.session_id,
            session.keys.tag_secret,
            session.ratcheted_keys.as_ref().unwrap().tag_secret,
            session.tag_window_tw,
        )
    };
    manager.complete_session_ratchet(&id);
    let old_tags = [tw.wrapping_sub(1), tw, tw.wrapping_add(1)]
        .map(|window| generate_resonance_tag(&old_secret, 1, window));
    let new_tags = [tw.wrapping_sub(1), tw, tw.wrapping_add(1)]
        .map(|window| generate_resonance_tag(&new_secret, 1, window));
    for tag in old_tags.iter().chain(&new_tags) {
        assert!(manager.get_session_by_tag(tag).is_some());
    }
    session.lock().pre_ratchet_expire = Some(Instant::now());
    manager.cleanup_expired();
    for tag in &old_tags {
        assert!(manager.get_session_by_tag(tag).is_none());
    }
    for tag in &new_tags {
        assert!(manager.get_session_by_tag(tag).is_some());
    }
}
