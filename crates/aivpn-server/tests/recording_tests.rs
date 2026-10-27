//! Integration tests for Auto Mask Recording pipeline
//!
//! Tests the full cycle: RecordingSession → RecordingManager → MaskGen → MaskStore
//! without requiring network or TUN devices.

use std::sync::Arc;

use aivpn_common::protocol::ControlPayload;
use aivpn_common::recording::*;
use aivpn_server::gateway::MaskCatalog;
use aivpn_server::mask_store::{MaskEntry, MaskStats, MaskStore};
use aivpn_server::recording::{RecordingManager, RecordingStopOutcome};

/// Generate realistic packet metadata that simulates a video call
fn generate_video_call_packets(count: usize) -> Vec<PacketMetadata> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut packets = Vec::with_capacity(count);
    let start_ns: u64 = 1_000_000_000_000;
    let mut current_ns = start_ns;

    for i in 0..count {
        let direction = if i % 3 == 0 {
            Direction::Uplink
        } else {
            Direction::Downlink
        };

        // Simulate bimodal size distribution (control packets ~80-150, media ~800-1300)
        let size: u16 = if rng.gen_bool(0.3) {
            rng.gen_range(80..150) // control
        } else {
            rng.gen_range(800..1300) // media
        };

        // IAT: ~20ms for media, ~100ms for control
        let iat_ms: f64 = if size > 500 {
            20.0 + rng.gen_range(-5.0..5.0)
        } else {
            100.0 + rng.gen_range(-30.0..30.0)
        };

        current_ns += (iat_ms * 1_000_000.0) as u64;

        // High entropy (encrypted traffic)
        let entropy: f32 = 7.2 + rng.gen_range(-0.3..0.3);

        // Fake QUIC-like header
        let mut header_prefix = vec![0xC0u8; 16]; // QUIC long header pattern
        header_prefix[1] = 0x00;
        header_prefix[2] = 0x00;
        header_prefix[3] = 0x01;

        packets.push(PacketMetadata {
            direction,
            size,
            iat_ms,
            entropy,
            header_prefix,
            timestamp_ns: current_ns,
        });
    }

    packets
}

// ─── Test: RecordingSession ──────────────────────────────────────────────────

#[test]
fn test_recording_session_basic() {
    let session_id = [1u8; 16];
    let mut session = RecordingSession::new(session_id, "test_service".into(), "admin".into());

    assert_eq!(session.total_packets, 0);
    assert_eq!(session.service, "test_service");

    // Record some packets
    let packets = generate_video_call_packets(100);
    for p in &packets {
        session.record(p.clone());
    }

    assert_eq!(session.total_packets, 100);
    assert_eq!(session.packets.len(), 100);
    assert!(session.running_stats.uplink_count > 0);
    assert!(session.running_stats.downlink_count > 0);
    assert!(session.running_stats.mean_entropy() > 6.0);

    println!(
        "✅ RecordingSession: {} packets, entropy={:.2}, uplink={}, downlink={}",
        session.total_packets,
        session.running_stats.mean_entropy(),
        session.running_stats.uplink_count,
        session.running_stats.downlink_count,
    );
}

#[test]
fn test_recording_session_cap() {
    let session_id = [2u8; 16];
    let mut session = RecordingSession::new(session_id, "cap_test".into(), "admin".into());

    // Generate more than MAX_RECORDING_PACKETS
    let packets = generate_video_call_packets(MAX_RECORDING_PACKETS + 1000);
    for p in &packets {
        session.record(p.clone());
    }

    // Stored packets are capped
    assert_eq!(session.packets.len(), MAX_RECORDING_PACKETS);
    // But total_packets tracks the real count
    assert_eq!(session.total_packets, (MAX_RECORDING_PACKETS + 1000) as u64);

    println!(
        "✅ RecordingSession cap: stored={}, total={}",
        session.packets.len(),
        session.total_packets
    );
}

// ─── Test: RunningStats ──────────────────────────────────────────────────────

#[test]
fn test_running_stats_incremental() {
    let mut stats = RunningStats::default();

    let packets = generate_video_call_packets(1000);
    for p in &packets {
        stats.update(p);
    }

    assert!(stats.uplink_count + stats.downlink_count == 1000);
    assert!(stats.mean_entropy() > 6.5);

    println!(
        "✅ RunningStats: up={}, down={}, entropy={:.2}",
        stats.uplink_count,
        stats.downlink_count,
        stats.mean_entropy()
    );
}

// ─── Test: ControlPayload encode/decode roundtrip ────────────────────────────

#[test]
fn test_recording_control_roundtrip() {
    // RecordingStart
    let start = ControlPayload::RecordingStart {
        service: "yandex_telemost".into(),
    };
    let encoded = start.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    match decoded {
        ControlPayload::RecordingStart { service } => {
            assert_eq!(service, "yandex_telemost");
        }
        _ => panic!("Expected RecordingStart"),
    }

    // RecordingAck
    let session_id = [0xABu8; 16];
    let ack = ControlPayload::RecordingAck {
        session_id,
        status: "started".into(),
    };
    let encoded = ack.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    match decoded {
        ControlPayload::RecordingAck {
            session_id: sid,
            status,
        } => {
            assert_eq!(sid, session_id);
            assert_eq!(status, "started");
        }
        _ => panic!("Expected RecordingAck"),
    }

    // RecordingStop
    let stop = ControlPayload::RecordingStop { session_id };
    let encoded = stop.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    match decoded {
        ControlPayload::RecordingStop { session_id: sid } => {
            assert_eq!(sid, session_id);
        }
        _ => panic!("Expected RecordingStop"),
    }

    // RecordingComplete
    let complete = ControlPayload::RecordingComplete {
        service: "zoom".into(),
        mask_id: "auto_zoom_v1".into(),
        confidence: 0.87,
    };
    let encoded = complete.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    match decoded {
        ControlPayload::RecordingComplete {
            service,
            mask_id,
            confidence,
        } => {
            assert_eq!(service, "zoom");
            assert_eq!(mask_id, "auto_zoom_v1");
            assert!((confidence - 0.87).abs() < 0.001);
        }
        _ => panic!("Expected RecordingComplete"),
    }

    // RecordingFailed
    let failed = ControlPayload::RecordingFailed {
        reason: "Too few packets".into(),
    };
    let encoded = failed.encode().unwrap();
    let decoded = ControlPayload::decode(&encoded).unwrap();
    match decoded {
        ControlPayload::RecordingFailed { reason } => {
            assert_eq!(reason, "Too few packets");
        }
        _ => panic!("Expected RecordingFailed"),
    }

    println!("✅ All 5 Recording ControlPayload variants encode/decode correctly");
}

// ─── Test: RecordingManager ──────────────────────────────────────────────────

#[test]
fn test_recording_manager_lifecycle() {
    let catalog = Arc::new(MaskCatalog::new());
    let store = Arc::new(MaskStore::new(
        catalog,
        std::path::PathBuf::from("/tmp/aivpn-test-masks"),
        None,
        None,
        aivpn_common::mask::MaskVerifyMode::default(),
    ));
    let manager = RecordingManager::new(store);

    let session_id = [3u8; 16];

    // Not recording yet
    assert!(!manager.is_recording(&session_id));

    // Start recording
    manager.start(session_id, "test_service".into(), "admin".into());
    assert!(manager.is_recording(&session_id));

    // Record packets
    let packets = generate_video_call_packets(100);
    for p in &packets {
        manager.record_packet(session_id, p.clone());
    }

    // Check status
    let status = manager.status(&session_id);
    assert!(status.is_some());
    let status = status.unwrap();
    assert_eq!(status.total_packets, 100);
    assert_eq!(status.service, "test_service");
    println!(
        "✅ RecordingManager: service='{}', packets={}, up={}, down={}",
        status.service, status.total_packets, status.uplink_count, status.downlink_count,
    );

    // Stop (will fail has_enough_data since duration < 60s and packets < 500)
    let result = manager.stop(session_id);
    assert!(matches!(result, RecordingStopOutcome::Incomplete(_))); // Not enough data

    // No longer recording
    assert!(!manager.is_recording(&session_id));

    println!("✅ RecordingManager lifecycle works correctly");
}

// ─── Test: MaskStore ─────────────────────────────────────────────────────────

#[test]
fn test_mask_store_crud() {
    let _ = std::fs::remove_dir_all("/tmp/aivpn-test-masks-crud");
    let catalog = Arc::new(MaskCatalog::new());
    let store = MaskStore::new(
        catalog.clone(),
        std::path::PathBuf::from("/tmp/aivpn-test-masks-crud"),
        None,
        None,
        aivpn_common::mask::MaskVerifyMode::default(),
    );

    // Create a dummy mask entry
    let profile = aivpn_common::mask::preset_masks::quic_https_v2();
    let mask_id = "test_mask_001".to_string();
    let mut modified_profile = profile.clone();
    modified_profile.mask_id = mask_id.clone();

    let entry = MaskEntry {
        profile: modified_profile,
        stats: MaskStats {
            mask_id: mask_id.clone(),
            times_used: 0,
            times_failed: 0,
            success_rate: 1.0,
            confidence: 0.85,
            is_active: true,
            created_by: "test".into(),
            created_at: 1000,
            last_used: None,
        },
    };

    #[cfg(feature = "production-secure")]
    {
        let err = store
            .add_mask(entry)
            .expect_err("production-secure must reject an unsigned preset written into the store");
        assert!(
            err.to_string().contains("отклонена"),
            "unexpected rejection: {err}"
        );
        assert!(store.get_mask(&mask_id).is_none());
        let _ = std::fs::remove_dir_all("/tmp/aivpn-test-masks-crud");
        return;
    }
    #[cfg(not(feature = "production-secure"))]
    {
        let initial_count = catalog.available_count();
        store.add_mask(entry).unwrap();

        // Check it's in the catalog
        assert!(catalog.available_count() > initial_count);

        // List
        let masks = store.list_masks();
        assert!(!masks.is_empty());
        assert!(masks.iter().any(|m| m.stats.mask_id == mask_id));

        // Get
        let got = store.get_mask(&mask_id);
        assert!(got.is_some());
        assert_eq!(got.unwrap().stats.confidence, 0.85);

        // Record usage
        store.record_usage(&mask_id);
        let got = store.get_mask(&mask_id).unwrap();
        assert_eq!(got.stats.times_used, 1);
        assert_eq!(got.stats.success_rate, 1.0);

        // Record failure
        store.record_failure(&mask_id);
        let got = store.get_mask(&mask_id).unwrap();
        assert_eq!(got.stats.times_used, 2);
        assert_eq!(got.stats.times_failed, 1);
        assert!((got.stats.success_rate - 0.5).abs() < 0.01);

        // Still active (not enough usages for deactivation threshold)
        assert!(got.stats.is_active);

        // Delete
        store.delete_mask(&mask_id).unwrap();
        assert!(store.get_mask(&mask_id).is_none());

        // Cleanup
        let _ = std::fs::remove_dir_all("/tmp/aivpn-test-masks-crud");

        println!("✅ MaskStore CRUD operations work correctly");
    }
}

// ─── Test: Full Pipeline (MaskGen) ───────────────────────────────────────────

#[tokio::test]
async fn test_full_mask_generation_pipeline() {
    let catalog = Arc::new(MaskCatalog::new());
    let storage_dir = std::path::PathBuf::from("/tmp/aivpn-test-mask-gen");
    let _ = std::fs::remove_dir_all(&storage_dir);

    let store = Arc::new(MaskStore::new(
        catalog.clone(),
        storage_dir.clone(),
        None,
        None,
        aivpn_common::mask::MaskVerifyMode::default(),
    ));

    // Generate enough packets for a realistic recording (2000 packets)
    let packets = generate_video_call_packets(2000);

    println!("📊 Test data: {} packets", packets.len());
    println!(
        "   Uplink: {}, Downlink: {}",
        packets
            .iter()
            .filter(|p| p.direction == Direction::Uplink)
            .count(),
        packets
            .iter()
            .filter(|p| p.direction == Direction::Downlink)
            .count(),
    );

    // Run the generation pipeline
    let result =
        aivpn_server::mask_gen::generate_and_store_mask("video_call_test", &packets, &store).await;

    match &result {
        Ok(mask_id) => {
            println!("✅ Mask generated: '{}'", mask_id);

            // Verify it's in the store
            let entry = store.get_mask(mask_id);
            assert!(entry.is_some(), "Mask should be in store after generation");
            let entry = entry.unwrap();

            println!("   mask_id: {}", entry.profile.mask_id);
            println!("   spoof_protocol: {:?}", entry.profile.spoof_protocol);
            println!(
                "   header_template_len: {}",
                entry.profile.header_template.len()
            );
            println!("   fsm_states: {}", entry.profile.fsm_states.len());
            println!(
                "   size_dist_type: {:?}",
                entry.profile.size_distribution.dist_type
            );
            println!(
                "   iat_dist_type: {:?}",
                entry.profile.iat_distribution.dist_type
            );
            println!("   confidence: {:.2}", entry.stats.confidence);
            println!("   is_active: {}", entry.stats.is_active);

            // Verify the profile is valid
            assert!(!entry.profile.mask_id.is_empty());
            assert!(!entry.profile.header_template.is_empty());
            assert!(!entry.profile.fsm_states.is_empty());
            assert!(entry.stats.confidence > 0.0);
            assert!(entry.stats.is_active);

            // Verify it's registered in catalog
            assert!(catalog.available_count() >= 1); // at least the generated mask

            // Test that the mask can sample sizes and IATs
            let mut rng = rand::thread_rng();
            let size = entry.profile.size_distribution.sample(&mut rng);
            let iat = entry.profile.iat_distribution.sample(&mut rng);
            println!("   sample size: {}", size);
            println!("   sample iat: {:.2}ms", iat);
            assert!(size > 0, "Sampled size should be positive");
            assert!(iat >= 0.0, "Sampled IAT should be non-negative");
        }
        Err(e) => {
            println!("❌ Mask generation failed: {}", e);
            // Print detailed diagnostics
            let uplink_count = packets
                .iter()
                .filter(|p| p.direction == Direction::Uplink)
                .count();
            println!("   Uplink packets: {} (need >= 100)", uplink_count);
            println!("   Total packets: {}", packets.len());
        }
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_dir);

    #[cfg(not(feature = "production-secure"))]
    assert!(
        result.is_ok(),
        "Full mask generation pipeline should succeed: {:?}",
        result.err()
    );
    #[cfg(feature = "production-secure")]
    {
        let err = result.expect_err(
            "production-secure generation without a signing key must fail before storing a mask",
        );
        let text = err.to_string();
        assert!(text.contains("production-secure"), "{text}");
    }
}

// ─── Test: End-to-End with RecordingManager ──────────────────────────────────

#[tokio::test]
async fn test_end_to_end_recording() {
    let catalog = Arc::new(MaskCatalog::new());
    let storage_dir = std::path::PathBuf::from("/tmp/aivpn-test-e2e");
    let _ = std::fs::remove_dir_all(&storage_dir);

    let store = Arc::new(MaskStore::new(
        catalog.clone(),
        storage_dir.clone(),
        None,
        None,
        aivpn_common::mask::MaskVerifyMode::default(),
    ));
    let manager = RecordingManager::new(store.clone());

    let session_id = [0xE2u8; 16];

    // 1. Start recording
    manager.start(session_id, "e2e_test_service".into(), "admin".into());
    assert!(manager.is_recording(&session_id));

    // 2. Feed packets directly (simulating what gateway would do)
    let packets = generate_video_call_packets(3000);
    for p in &packets {
        manager.record_packet(session_id, p.clone());
    }

    let status = manager.status(&session_id).unwrap();
    println!(
        "📊 E2E recording status: {} packets, {}s",
        status.total_packets, status.duration_secs
    );

    // 3. Stop — this will fail has_enough_data because duration < 60s
    //    But we can test the direct pipeline
    let stopped = manager.stop(session_id);
    assert!(!manager.is_recording(&session_id));

    // Since duration is < 60s, stop returns Incomplete
    println!(
        "   Stop result: {} (expected Incomplete due to short duration)",
        if matches!(stopped, RecordingStopOutcome::Incomplete(_)) {
            "Incomplete"
        } else {
            "Other"
        }
    );

    // 4. Test direct pipeline instead (bypassing duration check)
    let result =
        aivpn_server::mask_gen::generate_and_store_mask("e2e_test_service", &packets, &store).await;

    #[cfg(not(feature = "production-secure"))]
    {
        assert!(
            result.is_ok(),
            "E2E pipeline should succeed: {:?}",
            result.err()
        );
        let mask_id = result.unwrap();
        println!("✅ E2E mask generated: '{}'", mask_id);

        // 5. Verify stored mask
        let entry = store.get_mask(&mask_id);
        assert!(entry.is_some());
    }
    #[cfg(feature = "production-secure")]
    {
        let err = result
            .expect_err("production-secure recording pipeline must not store an unsigned mask");
        assert!(err.to_string().contains("production-secure"), "{err}");
        assert!(
            store.list_masks().is_empty(),
            "no mask file should appear without a signing key"
        );
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_dir);

    println!("✅ End-to-End recording test passed");
}
