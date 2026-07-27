//! Regression coverage for the Neural Resonance module's discriminative power
//! and the mask-rotation fallback path. The pre-existing neural tests only
//! asserted `mse >= 0.0`; these assert that traffic MATCHING a mask's profile
//! reconstructs with lower error than anomalous traffic, and that a compromised
//! mask yields a distinct fallback. See also the F4 finding: the detector
//! discriminates correctly but its absolute thresholds/feature-scaling are a
//! known calibration limitation tracked separately.

use aivpn_common::mask::preset_masks;
use aivpn_server::neural::{
    encode_features, NeuralConfig, NeuralResonanceModule, ResonanceStatus, TrafficStats,
};

fn mse_for(sizes: &[u16], iat: f64, entropy: f64) -> f32 {
    let mut module = NeuralResonanceModule::new(NeuralConfig::default()).unwrap();
    module.load_model().unwrap();
    let mask = preset_masks::webrtc_zoom_v3();
    let mask_id = mask.mask_id.clone();
    module.register_mask(&mask).unwrap();
    let sid = [0x22u8; 16];
    for i in 0..300usize {
        let sz = sizes[i % sizes.len()];
        module.record_traffic(sid, sz, iat + (i as f64 % 3.0), entropy, i % 2 == 0);
    }
    module.check_resonance(sid, &mask_id).unwrap().mse
}

/// B1: a near-idle window (a handful of keepalives) must be SKIPPED, not scored.
/// A degenerate feature vector from too few packets yields an MSE (~0.28 live)
/// that is noise — above a genuine shape anomaly — so scoring it would both
/// risk a false compromise and poison the per-mask calibration baseline.
#[test]
fn sparse_idle_window_is_skipped_not_scored() {
    let mut module = NeuralResonanceModule::new(NeuralConfig::default()).unwrap();
    module.load_model().unwrap();
    let mask = preset_masks::webrtc_zoom_v3();
    let mask_id = mask.mask_id.clone();
    module.register_mask(&mask).unwrap();
    let sid = [0x33u8; 16];

    // Only a few idle keepalives — below the reliability floor.
    for i in 0..8usize {
        module.record_traffic(sid, 96, 8_000.0, 6.0, i % 2 == 0);
    }
    let result = module.check_resonance(sid, &mask_id).unwrap();
    assert_eq!(
        result.status,
        ResonanceStatus::Skip,
        "a sparse idle window must be skipped, got {:?} (mse {})",
        result.status,
        result.mse
    );

    // Once enough packets accumulate, the check runs normally and stays healthy
    // for matching traffic.
    for i in 0..64usize {
        let sz = [80u16, 120, 160, 100, 200][i % 5];
        module.record_traffic(sid, sz, 12.0 + (i as f64 % 3.0), 6.0, i % 2 == 0);
    }
    let result = module.check_resonance(sid, &mask_id).unwrap();
    assert_ne!(
        result.status,
        ResonanceStatus::Skip,
        "an active window with enough packets must be scored, not skipped"
    );
}

#[test]
fn neural_discriminates_matching_from_anomalous_traffic() {
    // Traffic resembling the webrtc_zoom_v3 profile: small packets, tight IAT.
    let matching = mse_for(&[80, 120, 160, 100, 200], 12.0, 6.0);
    // Bulk-transfer anomaly: large packets near MTU, near-zero IAT.
    let bulk = mse_for(&[1300, 1346, 1200, 1346], 0.2, 7.9);
    // Idle/keepalive anomaly: large inter-arrival gaps.
    let idle = mse_for(&[80, 120], 5000.0, 6.0);

    assert!(
        matching >= 0.0 && bulk >= 0.0 && idle >= 0.0,
        "MSE must be non-negative"
    );
    // The detector must reconstruct matching traffic with strictly lower error
    // than a bulk-transfer anomaly — i.e. it discriminates in the right direction.
    assert!(
        bulk > matching,
        "bulk-transfer MSE ({bulk}) must exceed matching-traffic MSE ({matching})"
    );
    // A large-IAT (idle) pattern must also read as more anomalous than matching.
    assert!(
        idle > matching,
        "idle/large-IAT MSE ({idle}) must exceed matching-traffic MSE ({matching})"
    );
}

/// F4 regression (night-sprint B1): every encoded feature must stay within
/// [-1, 1] even for pathological traffic. Under the old /100 & /1000 linear
/// IAT scaling, an idle/keepalive gap of 8 s produced features of 50–80,
/// which the baked autoencoder could never reconstruct (MSE ≈ 272 → false
/// "compromised"). The saturating x/(x+K) normalization bounds every block.
#[test]
fn features_stay_bounded_for_extreme_traffic() {
    let scenarios: &[(&[u16], f64, f64)] = &[
        // Idle/keepalive: 8-second gaps (the original false-positive trigger).
        (&[80u16, 120], 8_000.0, 6.0),
        // Long silence: minutes between packets.
        (&[100u16], 120_000.0, 5.0),
        // Bulk burst: near-MTU packets, sub-ms IAT.
        (&[1300u16, 1346, 1200], 0.2, 7.9),
        // Jumbo/fragmented sizes above the 1500-byte scale.
        (&[9000u16, 65_535, 4000], 15.0, 7.0),
    ];
    for &(sizes, iat, entropy) in scenarios {
        let mut stats = TrafficStats::new();
        for i in 0..300usize {
            let sz = sizes[i % sizes.len()];
            stats.add_packet(sz, iat + (i as f64 % 3.0), entropy, i % 2 == 0);
        }
        stats.pps = 250_000.0; // pathological rate — must saturate, not explode
        stats.bps = 3.0e9;
        let features = encode_features(&stats);
        for (idx, &f) in features.iter().enumerate() {
            assert!(
                (-1.0..=1.0).contains(&f),
                "feature[{idx}] = {f} out of [-1, 1] for scenario (iat={iat}ms)"
            );
        }
    }
}

/// F4 regression (night-sprint B1): idle/large-IAT traffic must NOT read as a
/// compromised mask. Before the saturating normalization this MSE was ~272 —
/// hundreds of times over the 0.35 threshold — so an idle client triggered a
/// spurious mask rotation.
#[test]
fn idle_traffic_does_not_trigger_false_compromise() {
    let threshold = NeuralConfig::default().compromised_threshold;
    // Keepalive pattern: small packets every 8 s.
    let idle_keepalive = mse_for(&[80, 120], 8_000.0, 6.0);
    // Deep idle: minutes of silence between packets.
    let idle_deep = mse_for(&[100], 120_000.0, 5.0);
    eprintln!("idle_keepalive MSE = {idle_keepalive}, idle_deep MSE = {idle_deep}");
    assert!(
        idle_keepalive < threshold,
        "idle/keepalive MSE ({idle_keepalive}) must stay below the compromise \
         threshold ({threshold}) — large IAT alone is not a DPI fingerprint"
    );
    assert!(
        idle_deep < threshold,
        "deep-idle MSE ({idle_deep}) must stay below the compromise threshold ({threshold})"
    );
}

/// F4 regression (night-sprint B1): a genuine SHAPE anomaly (packet-size
/// distribution unlike the mask) must reconstruct strictly worse than
/// matching traffic — the discriminative signal must survive normalization.
#[test]
fn shape_anomaly_exceeds_matching_mse() {
    // Traffic resembling webrtc_zoom_v3: small packets, tight IAT.
    let matching = mse_for(&[80, 120, 160, 100, 200], 12.0, 6.0);
    // Shape anomaly: bulk transfer, near-MTU packets, high entropy.
    let bulk = mse_for(&[1300, 1346, 1200, 1346], 0.2, 7.9);
    let threshold = NeuralConfig::default().compromised_threshold;
    eprintln!("matching MSE = {matching}, shape-anomaly MSE = {bulk} (threshold {threshold})");
    assert!(
        bulk > matching,
        "shape-anomaly MSE ({bulk}) must exceed matching-traffic MSE ({matching})"
    );
    // NOTE: whether `bulk` also exceeds the absolute compromise threshold is a
    // calibration question — see TODO(night-sprint B1) in neural.rs. The
    // per-mask adaptive calibration (mean + 3σ) is the operative gate after
    // warm-up; telemetry multi-reporter corroboration remains the PRIMARY
    // compromise signal.
}

#[test]
fn neural_rotation_selects_distinct_fallback() {
    use aivpn_server::gateway::MaskCatalog;
    let catalog = MaskCatalog::new();
    for m in preset_masks::all() {
        catalog.register_mask(m);
    }
    let before = catalog.available_count();
    let fallback = catalog.mark_compromised_with_fallback("webrtc_zoom_v3");
    assert!(fallback.is_some(), "a fallback mask must be available");
    assert_ne!(
        fallback.unwrap().mask_id,
        "webrtc_zoom_v3",
        "fallback must differ from the compromised mask"
    );
    assert_eq!(
        catalog.available_count(),
        before - 1,
        "compromising a mask must remove exactly one from rotation"
    );
}
