//! Mask Generator — Analysis, Profile Building, and Self-Testing
//!
//! Analyzes recorded traffic metadata to generate MaskProfile:
//! 1. Statistical analysis (size distribution, IAT patterns, FSM states)
//! 2. Build MaskProfile from analysis results
//! 3. Self-test via Kolmogorov-Smirnov test
//! 4. Store and broadcast

// R2 Phase B: generated masks ARE now signed with the operator Ed25519 key
// (`--mask-signing-key` / server.json `mask_signing_key`) after the KS
// self-test passes — see `generate_and_store_mask`. However the key is still
// OPTIONAL: without it, masks are generated with signature=[0u8;64] exactly as
// before. production-secure stays a compile error until the remaining step
// lands: make the signing key mandatory (refuse to generate unsigned) and
// default `mask_verify_mode` to `enforce` in production-secure builds.
#[cfg(feature = "production-secure")]
compile_error!(
    "mask_gen can still produce MaskProfile with signature=[0u8;64] when no \
    --mask-signing-key is configured. Make the operator signing key mandatory \
    (and default mask_verify_mode to enforce) before enabling production-secure."
);

use std::sync::Arc;

use tracing::{error, info};

use aivpn_common::error::{Error, Result};
use aivpn_common::mask::*;
use aivpn_common::recording::{Direction, PacketMetadata};

use crate::gmm;
use crate::mask_store::{MaskEntry, MaskStats, MaskStore};

// ─── GMM distribution tuning (design-doc §4 R&D bridge) ──────────────────────
//
// When a recording's size / IAT marginal is multimodal, emit a compact
// BIC-selected Gaussian mixture instead of the empirical bin/quantile table.
// The phase2b study (research/mask-generation/phase2b) showed this cuts the
// KS distance to real held-out traffic by 43–89 %. Flip `USE_GMM_DISTRIBUTIONS`
// to false to fall back to the pure-empirical generator (clean rollback).

/// Master switch for GMM-based distributions in generated masks.
const USE_GMM_DISTRIBUTIONS: bool = true;
/// Max mixture components to sweep (BIC picks the best k in 1..=MAX).
const GMM_MAX_COMPONENTS: usize = 8;
/// Minimum samples before a GMM fit is trustworthy; below this keep empirical.
const GMM_MIN_SAMPLES: usize = 40;
/// Drop mixture components lighter than this and renormalise (phase2b's 2 %
/// effective-K filter). If <2 survive, the marginal is treated as unimodal.
const GMM_MIN_COMPONENT_WEIGHT: f64 = 0.02;

// ─── Analysis Result ─────────────────────────────────────────────────────────

/// Result of traffic analysis
#[allow(dead_code)]
struct AnalysisResult {
    uplink: DirectionalAnalysis,
    downlink: DirectionalAnalysis,
    header: HeaderObservation,
    fsm_states: Vec<FSMState>,
    fsm_initial_state: u16,
    /// R3: joint size↔IAT 2-D GMM for the uplink, when correlation is material.
    size_iat_joint: Option<SizeIatGmm2d>,
    mean_entropy: f32,
    total_packets: u64,
    duration_secs: u64,
    confidence: f32,
}

#[allow(dead_code)]
struct DirectionalAnalysis {
    size_modes: Vec<Mode>,
    size_mean: f32,
    size_std: f32,
    iat_mean_ms: f32,
    iat_std_ms: f32,
    periods: Vec<Period>,
    packet_count: usize,
    /// Raw sorted sizes for empirical quantile-based distribution building
    raw_sizes_sorted: Vec<u16>,
    /// Raw sorted IATs for empirical distribution building
    raw_iats_sorted: Vec<f64>,
}

#[allow(dead_code)]
struct HeaderObservation {
    template: Vec<u8>,
    randomize_indices: Vec<usize>,
    header_spec: Option<HeaderSpec>,
    match_rate: f32,
    spec_confidence: f32,
}

/// Statistical mode (peak in distribution)
#[allow(dead_code)]
struct Mode {
    center: f32,
    std_dev: f32,
    weight: f32,
}

/// Periodic IAT pattern
#[allow(dead_code)]
struct Period {
    period_ms: f32,
    jitter_ms: f32,
    weight: f32,
}

/// Self-test result
struct SelfTestResult {
    ks_uplink_size: f32,
    ks_uplink_iat: f32,
    ks_downlink_size: f32,
    ks_downlink_iat: f32,
    header_match: f32,
    fsm_score: f32,
    entropy_penalty: f32,
    passed: bool,
    confidence: f32,
}

fn self_test_passes(
    ks_uplink_size: f32,
    ks_uplink_iat: f32,
    ks_downlink_size: f32,
    ks_downlink_iat: f32,
    header_match: f32,
    fsm_score: f32,
    entropy_penalty: f32,
    downlink_required: bool,
) -> bool {
    // With a correct KS implementation and empirical distributions, KS values
    // should be small (0.02-0.15).  Use generous thresholds to avoid rejecting
    // valid recordings while still catching bad profiles.
    let ks_ok = ks_uplink_size < 0.45
        && ks_uplink_iat < 0.45
        && (!downlink_required || (ks_downlink_size < 0.45 && ks_downlink_iat < 0.45));

    let structural_ok = header_match >= 0.55 && fsm_score >= 0.40 && entropy_penalty < 0.5;

    ks_ok && structural_ok
}

const MIN_ENCRYPTED_ENTROPY: f64 = 6.0;

// ─── Main Pipeline ───────────────────────────────────────────────────────────

/// Generate mask from recorded traffic and store it
pub async fn generate_and_store_mask(
    service: &str,
    packets: &[PacketMetadata],
    store: &Arc<MaskStore>,
) -> Result<String> {
    // 1. Analyze traffic
    let analysis = analyze_traffic(service, packets)?;
    info!(
        "Analysis complete for '{}': {} packets, up={} down={}, confidence={:.2}",
        service,
        analysis.total_packets,
        analysis.uplink.packet_count,
        analysis.downlink.packet_count,
        analysis.confidence
    );

    // 2. Build MaskProfile
    let mut profile = build_mask_profile(service, &analysis)?;

    // 3. Self-test
    let test = self_test(&profile, packets)?;
    if !test.passed {
        return Err(Error::Mask(format!(
            "Self-test failed: up(size={:.3},iat={:.3}) down(size={:.3},iat={:.3}) header={:.3} fsm={:.3} entropy_penalty={:.3}",
            test.ks_uplink_size,
            test.ks_uplink_iat,
            test.ks_downlink_size,
            test.ks_downlink_iat,
            test.header_match,
            test.fsm_score,
            test.entropy_penalty
        )));
    }
    info!(
        "Self-test passed for '{}': up(size={:.3},iat={:.3}) down(size={:.3},iat={:.3}) header={:.2} fsm={:.2}, confidence={:.2}",
        service,
        test.ks_uplink_size,
        test.ks_uplink_iat,
        test.ks_downlink_size,
        test.ks_downlink_iat,
        test.header_match,
        test.fsm_score,
        test.confidence
    );

    // 3b. R2 Phase B: sign with the operator key — ONLY after the self-test
    // gate passed, so a signature attests "this mask went through the gates".
    // Sign the reverse profile first: `signing_message()` serializes the whole
    // struct, so the outer signature then also covers the (already signed)
    // reverse profile, and the reverse profile stays independently verifiable
    // if it is ever extracted standalone.
    if let Some(key) = store.operator_signing_key() {
        if let Some(rev) = profile.reverse_profile.as_mut() {
            rev.sign(key);
        }
        profile.sign(key);
        info!(
            "Mask '{}' signed with operator Ed25519 key",
            profile.mask_id
        );
    }

    // 4. Store
    let mask_id = profile.mask_id.clone();
    store.add_mask(MaskEntry {
        profile,
        stats: MaskStats {
            mask_id: mask_id.clone(),
            times_used: 0,
            times_failed: 0,
            success_rate: 1.0,
            confidence: test.confidence,
            is_active: true,
            created_by: "auto".into(),
            created_at: current_unix_secs(),
            last_used: None,
        },
    })?;

    // 5. Broadcast to clients
    if let Err(e) = store.broadcast_mask_update(&mask_id).await {
        error!("Failed to broadcast mask '{}': {}", mask_id, e);
    }

    Ok(mask_id)
}

// ─── Traffic Analysis ────────────────────────────────────────────────────────

fn analyze_traffic(_service: &str, packets: &[PacketMetadata]) -> Result<AnalysisResult> {
    let uplink: Vec<&PacketMetadata> = packets
        .iter()
        .filter(|p| p.direction == Direction::Uplink)
        .collect();
    let downlink: Vec<&PacketMetadata> = packets
        .iter()
        .filter(|p| p.direction == Direction::Downlink)
        .collect();

    if uplink.len() < 100 {
        return Err(Error::Mask("Too few uplink packets (need >= 100)".into()));
    }

    let uplink_analysis = analyze_direction(&uplink);
    let downlink_analysis = analyze_direction(&downlink);

    // Header consensus
    let headers: Vec<Vec<u8>> = packets.iter().map(|p| p.header_prefix.clone()).collect();
    let header = analyze_headers(&headers);

    // R4: temporal FSM — a Markov chain over the size GMM's components with
    // per-mode size/IAT emission, so the generated stream reproduces the real
    // traffic's autocorrelation instead of drawing each packet i.i.d.
    let uplink_sizes: Vec<u16> = uplink.iter().map(|p| p.size).collect();
    let uplink_iats: Vec<f64> = uplink.iter().map(|p| p.iat_ms).collect();
    let (fsm_states, fsm_initial) = build_temporal_fsm(&uplink_sizes, &uplink_iats);
    // R3: joint size↔IAT model (Some only when correlation is material).
    let size_iat_joint = build_size_iat_joint(&uplink_sizes, &uplink_iats);

    // Entropy
    let entropies: Vec<f32> = packets.iter().map(|p| p.entropy).collect();
    let mean_entropy = mean_f32(&entropies);

    // Confidence score
    let confidence = compute_confidence(
        packets.len(),
        uplink_analysis.packet_count,
        downlink_analysis.packet_count,
        header.match_rate,
        header.spec_confidence,
        mean_entropy,
    );

    // Duration
    let duration_secs = if packets.len() >= 2 {
        let first_ts = packets.first().map(|p| p.timestamp_ns).unwrap_or(0);
        let last_ts = packets.last().map(|p| p.timestamp_ns).unwrap_or(0);
        (last_ts.saturating_sub(first_ts)) / 1_000_000_000
    } else {
        0
    };

    Ok(AnalysisResult {
        uplink: uplink_analysis,
        downlink: downlink_analysis,
        header,
        fsm_states,
        fsm_initial_state: fsm_initial,
        size_iat_joint,
        mean_entropy,
        total_packets: packets.len() as u64,
        duration_secs,
        confidence,
    })
}

fn analyze_direction(packets: &[&PacketMetadata]) -> DirectionalAnalysis {
    let sizes: Vec<u16> = packets.iter().map(|p| p.size).collect();
    let iats: Vec<f64> = packets.iter().map(|p| p.iat_ms).collect();

    let mut raw_sizes_sorted = sizes.clone();
    raw_sizes_sorted.sort();
    let mut raw_iats_sorted = iats.clone();
    raw_iats_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    DirectionalAnalysis {
        size_modes: find_modes_histogram(&sizes, 32),
        size_mean: mean_u16(&sizes),
        size_std: std_dev_u16(&sizes),
        iat_mean_ms: mean_f64(&iats) as f32,
        iat_std_ms: std_dev_f64(&iats) as f32,
        periods: find_periods(&iats),
        packet_count: packets.len(),
        raw_sizes_sorted,
        raw_iats_sorted,
    }
}

// ─── Mode Detection (Histogram) ─────────────────────────────────────────────

fn find_modes_histogram(sizes: &[u16], num_bins: usize) -> Vec<Mode> {
    if sizes.is_empty() {
        return vec![Mode {
            center: 64.0,
            std_dev: 32.0,
            weight: 1.0,
        }];
    }

    let min = *sizes.iter().min().unwrap_or(&0);
    let max = *sizes.iter().max().unwrap_or(&1500);
    let bin_width = ((max - min) as f32 / num_bins as f32).max(1.0);

    let mut bins = vec![0usize; num_bins];
    for &size in sizes {
        let bin = ((size as f32 - min as f32) / bin_width).min(num_bins as f32 - 1.0) as usize;
        bins[bin] += 1;
    }

    let total = sizes.len() as f32;
    let mut modes = Vec::new();

    for i in 1..bins.len().saturating_sub(1) {
        if bins[i] > bins[i - 1] && bins[i] > bins[i + 1] && bins[i] > total as usize / 20 {
            let center = min as f32 + (i as f32 + 0.5) * bin_width;
            let weight = bins[i] as f32 / total;

            // Compute local std dev around this mode
            let mut sum_sq = 0.0f32;
            let mut count = 0usize;
            for (j, &bin_count) in bins.iter().enumerate() {
                if bin_count > 0 {
                    let bc = min as f32 + (j as f32 + 0.5) * bin_width;
                    sum_sq += (bin_count as f32) * (bc - center).powi(2);
                    count += bin_count;
                }
            }
            let std_dev = if count > 0 {
                (sum_sq / count as f32).sqrt()
            } else {
                bin_width
            };
            modes.push(Mode {
                center,
                std_dev,
                weight,
            });
        }
    }

    // Fallback: single mode from mean/std
    if modes.is_empty() {
        let mean = mean_u16(sizes);
        let std = std_dev_u16(sizes);
        modes.push(Mode {
            center: mean,
            std_dev: std,
            weight: 1.0,
        });
    }

    modes
}

// ─── Period Detection (IAT) ─────────────────────────────────────────────────

fn find_periods(iats: &[f64]) -> Vec<Period> {
    if iats.len() < 10 {
        return vec![];
    }

    let mean_iat = mean_f64(iats);
    let std_iat = std_dev_f64(iats);

    if mean_iat < 1e-9 {
        return vec![];
    }

    if std_iat / mean_iat < 0.3 {
        // Stable single period
        vec![Period {
            period_ms: mean_iat as f32,
            jitter_ms: std_iat as f32,
            weight: 1.0,
        }]
    } else {
        // Bimodal — split by median
        let mut sorted = iats.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = sorted[sorted.len() / 2];

        let low: Vec<f64> = iats.iter().filter(|&&x| x <= median).copied().collect();
        let high: Vec<f64> = iats.iter().filter(|&&x| x > median).copied().collect();

        let mut periods = Vec::new();
        if !low.is_empty() {
            periods.push(Period {
                period_ms: mean_f64(&low) as f32,
                jitter_ms: std_dev_f64(&low) as f32,
                weight: low.len() as f32 / iats.len() as f32,
            });
        }
        if !high.is_empty() {
            periods.push(Period {
                period_ms: mean_f64(&high) as f32,
                jitter_ms: std_dev_f64(&high) as f32,
                weight: high.len() as f32 / iats.len() as f32,
            });
        }
        periods
    }
}

// ─── Change Point Detection → FSM ───────────────────────────────────────────

fn build_fsm_from_sizes(sizes: &[u16]) -> (Vec<FSMState>, u16) {
    if sizes.len() < 50 {
        return (
            vec![FSMState {
                state_id: 0,
                transitions: vec![],
            }],
            0,
        );
    }

    // 1. Detect change points (mean shift > 2σ in window of 20)
    let window = 20;
    let _global_mean = mean_u16(sizes);
    let global_std = std_dev_u16(sizes);
    let threshold = 2.0 * global_std;

    let mut change_points = Vec::new();
    for i in window..sizes.len().saturating_sub(window) {
        let before = sizes[i - window..i].iter().map(|&x| x as f32).sum::<f32>() / window as f32;
        let after = sizes[i..i + window].iter().map(|&x| x as f32).sum::<f32>() / window as f32;
        if (before - after).abs() > threshold {
            if change_points.is_empty() || i - *change_points.last().unwrap() > 10 {
                change_points.push(i);
            }
        }
    }

    // 2. Create segments
    let mut segments: Vec<&[u16]> = Vec::new();
    let mut start = 0;
    for &cp in &change_points {
        if cp > start {
            segments.push(&sizes[start..cp]);
        }
        start = cp;
    }
    if start < sizes.len() {
        segments.push(&sizes[start..]);
    }

    // Limit number of segments to avoid explosion
    if segments.is_empty() {
        segments.push(sizes);
    }

    // 3. Cluster segments by mean (threshold 100 bytes)
    let seg_means: Vec<f32> = segments
        .iter()
        .map(|s| s.iter().map(|&x| x as f32).sum::<f32>() / s.len().max(1) as f32)
        .collect();

    let mut clusters: Vec<Vec<usize>> = Vec::new();
    for (i, &seg_mean) in seg_means.iter().enumerate() {
        let mut assigned = false;
        for cluster in &mut clusters {
            let cm: f32 = cluster.iter().map(|&j| seg_means[j]).sum::<f32>() / cluster.len() as f32;
            if (seg_mean - cm).abs() < 100.0 {
                cluster.push(i);
                assigned = true;
                break;
            }
        }
        if !assigned {
            clusters.push(vec![i]);
        }
    }

    // Limit to max 8 FSM states
    clusters.truncate(8);

    // 4. Build FSM states with transitions
    let mut transitions: Vec<Vec<(u16, u32)>> = vec![vec![]; clusters.len()];
    for i in 0..segments.len().saturating_sub(1) {
        let from = clusters.iter().position(|c| c.contains(&i)).unwrap_or(0) as u16;
        let to = clusters
            .iter()
            .position(|c| c.contains(&(i + 1)))
            .unwrap_or(0) as u16;
        if (from as usize) < clusters.len() && (to as usize) < clusters.len() {
            if let Some(e) = transitions[from as usize]
                .iter_mut()
                .find(|(s, _)| *s == to)
            {
                e.1 += 1;
            } else {
                transitions[from as usize].push((to, 1));
            }
        }
    }

    // 5. Convert to FSMState
    let fsm_states: Vec<FSMState> = clusters
        .iter()
        .enumerate()
        .map(|(i, _cluster)| {
            let total: u32 = transitions[i].iter().map(|(_, c)| c).sum();
            let trans: Vec<FSMTransition> = transitions[i]
                .iter()
                .map(|(next, count)| FSMTransition {
                    condition: TransitionCondition::Random(*count as f32 / total.max(1) as f32),
                    next_state: *next,
                    size_override: None,
                    iat_override: None,
                    padding_override: None,
                })
                .collect();

            FSMState {
                state_id: i as u16,
                transitions: trans,
            }
        })
        .collect();

    (fsm_states, 0)
}

/// Local Gaussian pdf (gmm::gaussian_pdf is private to that module).
fn gauss_pdf(x: f64, mean: f64, var: f64) -> f64 {
    let v = var.max(1e-9);
    let d = x - mean;
    (-(d * d) / (2.0 * v)).exp() / (2.0 * std::f64::consts::PI * v).sqrt()
}

/// A single-component GMM `SizeDistribution` centred on (mean, var): an FSM
/// state's per-mode size emission. Flat layout `[k, w, mu, sigma]` per
/// `sample_gaussian_mixture` (sigma = std dev).
fn single_gmm_size(mean: f64, var: f64) -> SizeDistribution {
    SizeDistribution {
        dist_type: SizeDistType::Parametric,
        bins: Vec::new(),
        parametric_type: Some(ParametricType::Gmm),
        parametric_params: Some(vec![1.0, 1.0, mean.max(1.0), var.max(1.0).sqrt()]),
    }
}

/// A single-component GMM `IATDistribution` from one state's inter-arrival
/// samples (ms). `None` when too few samples to estimate — the mask's global
/// IAT distribution then applies.
fn single_gmm_iat(iats: &[f64]) -> Option<IATDistribution> {
    if iats.len() < 5 {
        return None;
    }
    let n = iats.len() as f64;
    let mean = iats.iter().sum::<f64>() / n;
    let var = iats.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    Some(IATDistribution {
        dist_type: IATDistType::Gmm,
        params: vec![1.0, 1.0, mean.max(0.0), var.max(1e-6).sqrt()],
        jitter_range_ms: (0.0, 0.0),
    })
}

/// R4 — temporal FSM: a first-order Markov chain over the size GMM's components.
/// Each component becomes an FSM state whose emission is that component's size /
/// IAT distribution; the transition probabilities are counted from the REAL
/// consecutive-packet component sequence, so the generated stream reproduces the
/// traffic's autocorrelation (bursts, request/response) instead of the i.i.d.
/// draw a bare marginal GMM yields. The transition's overrides carry the
/// DESTINATION mode's emission (applied on entry). Falls back to the size
/// change-point FSM when the sample is too small or unimodal for a mixture.
pub fn build_temporal_fsm(sizes: &[u16], iats: &[f64]) -> (Vec<FSMState>, u16) {
    if sizes.len() < GMM_MIN_SAMPLES {
        return build_fsm_from_sizes(sizes);
    }
    let data: Vec<f64> = sizes.iter().map(|&s| s as f64).collect();
    let fit = match gmm::select_best_bic_min_cluster(
        &data,
        GMM_MAX_COMPONENTS,
        gmm::MIN_CLUSTER_WEIGHT,
    ) {
        Some(f) if f.k() >= 2 => f,
        _ => return build_fsm_from_sizes(sizes),
    };
    let k = fit.k();

    // Assign each packet to its most-likely component (by size).
    let assign: Vec<usize> = data
        .iter()
        .map(|&x| {
            (0..k)
                .map(|c| (c, fit.weights[c] * gauss_pdf(x, fit.means[c], fit.vars[c])))
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(c, _)| c)
                .unwrap_or(0)
        })
        .collect();

    // First-order transition counts + per-component IAT samples.
    let mut trans = vec![vec![0u32; k]; k];
    for w in assign.windows(2) {
        trans[w[0]][w[1]] += 1;
    }
    let mut comp_iats: Vec<Vec<f64>> = vec![Vec::new(); k];
    for (i, &c) in assign.iter().enumerate() {
        if let Some(&iat) = iats.get(i) {
            comp_iats[c].push(iat);
        }
    }

    let states: Vec<FSMState> = (0..k)
        .map(|i| {
            let total: u32 = trans[i].iter().sum::<u32>();
            let transitions: Vec<FSMTransition> = (0..k)
                .filter(|&j| trans[i][j] > 0)
                .map(|j| FSMTransition {
                    condition: TransitionCondition::Random(
                        trans[i][j] as f32 / total.max(1) as f32,
                    ),
                    next_state: j as u16,
                    size_override: Some(single_gmm_size(fit.means[j], fit.vars[j])),
                    iat_override: single_gmm_iat(&comp_iats[j]),
                    padding_override: None,
                })
                .collect();
            FSMState {
                state_id: i as u16,
                transitions,
            }
        })
        .collect();

    let initial = assign.first().copied().unwrap_or(0) as u16;
    (states, initial)
}

/// R3 — fit a JOINT 2-D (size, IAT) Gaussian mixture. Reuses the size GMM's
/// component assignment and estimates each component's full 2×2 covariance from
/// the assigned (size, iat) pairs, then stores the lower-triangular Cholesky
/// factor. Returns `Some` ONLY when at least one component shows a meaningful
/// size↔IAT correlation (the handle the two independent 1-D marginals miss);
/// otherwise `None`, so the marginals remain the model and nothing is spent on
/// covariance a DPI classifier could not exploit anyway.
pub fn build_size_iat_joint(sizes: &[u16], iats: &[f64]) -> Option<SizeIatGmm2d> {
    // Correlation magnitude below which the joint model is not worth emitting.
    const MIN_ABS_CORR: f64 = 0.15;
    if sizes.len() < GMM_MIN_SAMPLES || sizes.len() != iats.len() {
        return None;
    }
    let data: Vec<f64> = sizes.iter().map(|&s| s as f64).collect();
    let fit = match gmm::select_best_bic_min_cluster(
        &data,
        GMM_MAX_COMPONENTS,
        gmm::MIN_CLUSTER_WEIGHT,
    ) {
        Some(f) if f.k() >= 2 => f,
        _ => return None,
    };
    let k = fit.k();
    let assign: Vec<usize> = data
        .iter()
        .map(|&x| {
            (0..k)
                .map(|c| (c, fit.weights[c] * gauss_pdf(x, fit.means[c], fit.vars[c])))
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(c, _)| c)
                .unwrap_or(0)
        })
        .collect();

    let mut params: Vec<f64> = Vec::with_capacity(1 + k * 6);
    params.push(k as f64);
    let mut any_correlated = false;
    for c in 0..k {
        let pts: Vec<(f64, f64)> = assign
            .iter()
            .enumerate()
            .filter(|(_, &a)| a == c)
            .map(|(i, _)| (data[i], iats[i]))
            .collect();
        let n = pts.len() as f64;
        // A component with too few points can't give a stable covariance — fall
        // back to its marginal mean + the mixture's variance, zero correlation.
        if pts.len() < 8 {
            params.extend_from_slice(&[
                fit.weights[c],
                fit.means[c],
                iats.iter().sum::<f64>() / iats.len() as f64,
                fit.vars[c].max(1.0).sqrt(),
                0.0,
                1.0,
            ]);
            continue;
        }
        let mu_s = pts.iter().map(|p| p.0).sum::<f64>() / n;
        let mu_i = pts.iter().map(|p| p.1).sum::<f64>() / n;
        let var_s = pts.iter().map(|p| (p.0 - mu_s).powi(2)).sum::<f64>() / n;
        let var_i = pts.iter().map(|p| (p.1 - mu_i).powi(2)).sum::<f64>() / n;
        let cov = pts.iter().map(|p| (p.0 - mu_s) * (p.1 - mu_i)).sum::<f64>() / n;
        let sd_s = var_s.max(1e-9).sqrt();
        let sd_i = var_i.max(1e-9).sqrt();
        let corr = cov / (sd_s * sd_i);
        if corr.abs() >= MIN_ABS_CORR {
            any_correlated = true;
        }
        // Cholesky of [[var_s, cov],[cov, var_i]] = [[l00,0],[l10,l11]].
        let l00 = sd_s;
        let l10 = cov / l00;
        let l11 = (var_i - l10 * l10).max(1e-9).sqrt();
        params.extend_from_slice(&[fit.weights[c], mu_s, mu_i, l00, l10, l11]);
    }
    if !any_correlated {
        return None;
    }
    let dist = SizeIatGmm2d { params };
    dist.is_valid().then_some(dist)
}

// ─── Header Consensus ────────────────────────────────────────────────────────

fn header_consensus(headers: &[Vec<u8>]) -> Vec<u8> {
    if headers.is_empty() {
        return vec![0u8; 8];
    }

    let len = headers.iter().map(|h| h.len()).min().unwrap_or(8).min(16);
    let mut result = Vec::with_capacity(len);

    for i in 0..len {
        let mut counts = [0u32; 256];
        for h in headers {
            if i < h.len() {
                counts[h[i] as usize] += 1;
            }
        }
        let max_count = counts.iter().max().copied().unwrap_or(0);
        let max_byte = counts.iter().position(|&c| c == max_count).unwrap_or(0) as u8;

        result.push(max_byte);
    }
    result
}

fn analyze_headers(headers: &[Vec<u8>]) -> HeaderObservation {
    let template = header_consensus(headers);
    let randomize_indices = header_randomize_indices(headers);
    let (header_spec, spec_confidence) = infer_header_spec(headers);
    let match_rate = header_spec
        .as_ref()
        .map(|spec| header_match_rate(spec, headers))
        .unwrap_or_else(|| raw_prefix_match_rate(&template, &randomize_indices, headers));

    HeaderObservation {
        template,
        randomize_indices,
        header_spec,
        match_rate,
        spec_confidence,
    }
}

fn header_randomize_indices(headers: &[Vec<u8>]) -> Vec<usize> {
    if headers.is_empty() {
        return vec![];
    }
    let max_len = headers.iter().map(|h| h.len()).min().unwrap_or(0).min(16);
    let mut randomize = Vec::new();
    for i in 0..max_len {
        let mut counts = [0u32; 256];
        for h in headers {
            if i < h.len() {
                counts[h[i] as usize] += 1;
            }
        }
        let max_count = counts.iter().max().copied().unwrap_or(0);
        let ratio = max_count as f32 / headers.len() as f32;
        if ratio < 0.85 {
            randomize.push(i);
        }
    }
    randomize
}

// ─── HeaderSpec Inference (Issue #30 fix) ─────────────────────────────────────

/// Infer HeaderSpec from observed traffic patterns
///
/// Analyzes the consistency of header bytes across packets to determine
/// if the traffic matches known protocol patterns (STUN, QUIC, DNS, TLS)
/// and generates an appropriate HeaderSpec for dynamic per-packet generation.
fn infer_header_spec(headers: &[Vec<u8>]) -> (Option<HeaderSpec>, f32) {
    if headers.is_empty() {
        return (None, 0.0);
    }

    // Analyze byte consistency at each position
    let max_len = headers.iter().map(|h| h.len()).max().unwrap_or(0).min(20);
    if max_len < 4 {
        return (None, 0.0); // Not enough data
    }

    // Calculate consistency ratio for each byte position
    let mut consistency: Vec<f32> = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let mut counts = [0u32; 256];
        for h in headers {
            if i < h.len() {
                counts[h[i] as usize] += 1;
            }
        }
        let max_count = counts.iter().max().copied().unwrap_or(0);
        let ratio = max_count as f32 / headers.len() as f32;
        consistency.push(ratio);
    }

    let candidates = [
        score_stun(headers, &consistency),
        score_quic(headers, &consistency),
        score_dns(headers, &consistency),
        score_tls(headers, &consistency),
    ];

    let mut ranked: Vec<(HeaderSpec, f32)> = candidates.into_iter().flatten().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    if let Some((spec, score)) = ranked.first().cloned() {
        let second_best = ranked.get(1).map(|(_, score)| *score).unwrap_or(0.0);
        if score >= 0.72 && score - second_best >= 0.08 {
            return (Some(spec), score);
        }
    }

    // Fallback: use RawPrefix with randomization for variable bytes
    if headers.len() >= 4 {
        let template = headers[0].clone();
        let randomize_indices: Vec<usize> = consistency
            .iter()
            .enumerate()
            .filter(|(_, &c)| c < 0.7) // Randomize positions with <70% consistency
            .map(|(i, _)| i)
            .collect();

        if !randomize_indices.is_empty() && randomize_indices.len() < template.len() {
            return (
                Some(HeaderSpec::RawPrefix {
                    prefix_hex: hex::encode(&template),
                    randomize_indices,
                }),
                0.55,
            );
        }
    }

    // No pattern detected
    (None, 0.0)
}

fn score_stun(headers: &[Vec<u8>], consistency: &[f32]) -> Option<(HeaderSpec, f32)> {
    if headers.is_empty()
        || headers.iter().filter(|h| h.len() >= 20).count() * 10 < headers.len() * 7
    {
        return None;
    }

    let type_ratio = headers
        .iter()
        .filter(|h| h.len() >= 2 && h[0..2] == [0x00, 0x01])
        .count() as f32
        / headers.len() as f32;
    let cookie_ratio = headers
        .iter()
        .filter(|h| h.len() >= 8 && h[4..8] == [0x21, 0x12, 0xA4, 0x42])
        .count() as f32
        / headers.len() as f32;
    let len_sane_ratio = headers
        .iter()
        .filter(|h| h.len() >= 4 && h[2] & 0b1100_0000 == 0)
        .count() as f32
        / headers.len() as f32;
    let penalty = if headers
        .iter()
        .any(|h| !h.is_empty() && (0xC0..=0xCF).contains(&h[0]))
    {
        0.15
    } else {
        0.0
    };

    let score = (0.35 * type_ratio
        + 0.35 * cookie_ratio
        + 0.15 * len_sane_ratio
        + 0.15 * consistency.get(4).copied().unwrap_or(0.0))
        - penalty;

    if score > 0.45 {
        Some((
            HeaderSpec::stun_binding_with_cookie(cookie_ratio > 0.5),
            score.clamp(0.0, 1.0),
        ))
    } else {
        None
    }
}

fn score_quic(headers: &[Vec<u8>], consistency: &[f32]) -> Option<(HeaderSpec, f32)> {
    if headers.is_empty() {
        return None;
    }

    let long_header_ratio = headers
        .iter()
        .filter(|h| !h.is_empty() && (0xC0..=0xCF).contains(&h[0]))
        .count() as f32
        / headers.len() as f32;
    let version_ratio = headers
        .iter()
        .filter(|h| h.len() >= 5 && h[1..5] == [0x00, 0x00, 0x00, 0x01])
        .count() as f32
        / headers.len() as f32;
    let dcid_len_ratio = headers
        .iter()
        .filter(|h| h.len() >= 6 && (8..=20).contains(&h[5]))
        .count() as f32
        / headers.len() as f32;
    let penalty = if headers
        .iter()
        .filter(|h| h.len() >= 8 && h[4..8] == [0x21, 0x12, 0xA4, 0x42])
        .count() as f32
        / headers.len() as f32
        > 0.2
    {
        0.2
    } else {
        0.0
    };
    let score = (0.35 * long_header_ratio
        + 0.35 * version_ratio
        + 0.20 * dcid_len_ratio
        + 0.10 * consistency.get(0).copied().unwrap_or(0.0))
        - penalty;

    if score > 0.45 {
        Some((
            HeaderSpec::quic_initial(0x00000001, 8),
            score.clamp(0.0, 1.0),
        ))
    } else {
        None
    }
}

fn score_dns(headers: &[Vec<u8>], consistency: &[f32]) -> Option<(HeaderSpec, f32)> {
    if headers.is_empty()
        || headers.iter().filter(|h| h.len() >= 12).count() * 10 < headers.len() * 7
    {
        return None;
    }

    let flags_ratio = headers
        .iter()
        .filter(|h| h.len() >= 4 && h[2..4] == [0x01, 0x00])
        .count() as f32
        / headers.len() as f32;
    let counts_ratio = headers
        .iter()
        .filter(|h| h.len() >= 12 && h[4..12] == [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .count() as f32
        / headers.len() as f32;
    let txid_variability = 1.0
        - consistency
            .get(0)
            .copied()
            .unwrap_or(1.0)
            .min(consistency.get(1).copied().unwrap_or(1.0));
    let penalty = if headers
        .iter()
        .any(|h| !h.is_empty() && (0xC0..=0xCF).contains(&h[0]))
    {
        0.15
    } else {
        0.0
    };
    let score = (0.35 * flags_ratio
        + 0.35 * counts_ratio
        + 0.20 * txid_variability
        + 0.10 * consistency.get(2).copied().unwrap_or(0.0))
        - penalty;

    if score > 0.45 {
        Some((HeaderSpec::dns_query(0x0100), score.clamp(0.0, 1.0)))
    } else {
        None
    }
}

fn score_tls(headers: &[Vec<u8>], consistency: &[f32]) -> Option<(HeaderSpec, f32)> {
    if headers.is_empty()
        || headers.iter().filter(|h| h.len() >= 5).count() * 10 < headers.len() * 7
    {
        return None;
    }

    let content_ratio = headers
        .iter()
        .filter(|h| h.len() >= 1 && matches!(h[0], 0x14 | 0x15 | 0x16 | 0x17))
        .count() as f32
        / headers.len() as f32;
    let version_ratio = headers
        .iter()
        .filter(|h| h.len() >= 3 && matches!(h[1..3], [0x03, 0x01] | [0x03, 0x02] | [0x03, 0x03]))
        .count() as f32
        / headers.len() as f32;
    let len_variability = 1.0
        - consistency
            .get(3)
            .copied()
            .unwrap_or(1.0)
            .min(consistency.get(4).copied().unwrap_or(1.0));
    let penalty = if headers
        .iter()
        .filter(|h| h.len() >= 8 && h[4..8] == [0x21, 0x12, 0xA4, 0x42])
        .count() as f32
        / headers.len() as f32
        > 0.2
    {
        0.15
    } else {
        0.0
    };
    let score = (0.35 * content_ratio
        + 0.35 * version_ratio
        + 0.15 * len_variability
        + 0.15 * consistency.get(0).copied().unwrap_or(0.0))
        - penalty;

    if score > 0.45 {
        let content_type = if headers
            .iter()
            .filter(|h| !h.is_empty() && h[0] == 0x17)
            .count()
            >= headers
                .iter()
                .filter(|h| !h.is_empty() && h[0] == 0x16)
                .count()
        {
            0x17
        } else {
            0x16
        };
        Some((
            HeaderSpec::tls_record(content_type, 0x0303),
            score.clamp(0.0, 1.0),
        ))
    } else {
        None
    }
}

// ─── Confidence Scoring ─────────────────────────────────────────────────────

fn compute_confidence(
    total_packets: usize,
    uplink_packets: usize,
    downlink_packets: usize,
    header_match_rate: f32,
    spec_confidence: f32,
    mean_entropy: f32,
) -> f32 {
    let mut score = 0.0f32;
    let min_dir = uplink_packets.min(downlink_packets) as f32;
    let max_dir = uplink_packets.max(downlink_packets).max(1) as f32;
    let direction_balance = min_dir / max_dir;

    if total_packets >= 10_000 {
        score += 0.3;
    } else if total_packets >= 5_000 {
        score += 0.25;
    } else if total_packets >= 1_000 {
        score += 0.2;
    } else if total_packets >= 500 {
        score += 0.15;
    }

    score += 0.2 * direction_balance.min(1.0);
    score += 0.2 * header_match_rate.min(1.0);
    score += 0.15 * spec_confidence.min(1.0);

    if mean_entropy > 7.0 {
        score += 0.15;
    } else if mean_entropy > 6.0 {
        score += 0.1;
    }

    score.min(1.0)
}

// ─── MaskProfile Builder ─────────────────────────────────────────────────────

/// Sanitise a recording service label into a filesystem-safe slug.
///
/// The generated `mask_id` becomes a filename in the mask store
/// (`<mask_dir>/<mask_id>.json` / `.stats`). The `service` string arrives over
/// the control plane from a recording-admin client, so an unsanitised value
/// containing `/` or `..` would let the resulting write escape the mask
/// directory — an arbitrary file write as root. Map every non-alphanumeric
/// character to `_`, lowercase the rest, bound the length, and never return an
/// empty slug.
fn sanitize_service_slug(service: &str) -> String {
    let slug: String = service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    if slug.trim_matches('_').is_empty() {
        "unnamed".to_string()
    } else {
        slug
    }
}

/// Derive the 64-float `signature_vector` for a generated mask by running the
/// SAME feature encoder the live neural detector uses (`neural::encode_features`)
/// over the recorded traffic of one direction. Auto-masks previously shipped an
/// all-zero vector, which bakes a degenerate all-zero MLP so the detector cannot
/// distinguish the mask's own traffic from a DPI-fingerprinted anomaly (the mask
/// was effectively invisible to Neural Resonance).
///
/// The recording only retains SORTED raw samples (`raw_sizes_sorted`,
/// `raw_iats_sorted`), so feeding them in order would give artificially
/// monotonic temporal features (lag-1 autocorrelation ≈ 1, a strong trend) that
/// live, unsorted traffic never exhibits — the baked MLP would then flag normal
/// traffic. We deterministically shuffle a copy first (fixed seed → reproducible
/// builds) so the distributional features (size histogram, IAT/entropy
/// percentiles, means, fractions) stay exact while the order-dependent features
/// reflect a stationary, de-trended stream, much closer to what the live encoder
/// actually sees. `rx`/`tx` and `pps`/`bps` come from the whole session so the
/// direction-ratio and throughput features are representative.
fn derive_signature_vector(
    dir: &DirectionalAnalysis,
    mean_entropy: f32,
    pps: f64,
    bps: f64,
    rx: u64,
    tx: u64,
) -> Vec<f32> {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    // Fixed seed: identical recordings must yield identical signatures so a
    // rebuilt mask bakes the same encoder (matches the self-test RNG convention).
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x51_6E_A7_04_5E_ED_00_01);
    let mut sizes = dir.raw_sizes_sorted.clone();
    let mut iats = dir.raw_iats_sorted.clone();
    sizes.shuffle(&mut rng);
    iats.shuffle(&mut rng);

    let mut stats = crate::neural::TrafficStats::new();
    stats.pps = pps;
    stats.bps = bps;
    stats.rx_packets = rx;
    stats.tx_packets = tx;
    // TrafficStats keeps its last 256 samples; feed the newest 256 so the
    // signature reflects the same window size the live encoder operates on.
    let take = sizes.len().min(iats.len());
    let skip = take.saturating_sub(256);
    for i in skip..take {
        stats.packet_sizes.push_back(sizes[i]);
        stats.inter_arrivals.push_back(iats[i]);
        // Only the mean entropy is retained by the recording; use it for every
        // sample so the entropy block reflects the recorded average (variance 0).
        stats.entropy_samples.push_back(mean_entropy as f64);
    }

    crate::neural::encode_features(&stats).to_vec()
}

fn build_mask_profile(service: &str, analysis: &AnalysisResult) -> Result<MaskProfile> {
    let mask_id = format!("auto_{}_v1", sanitize_service_slug(service));

    // Recorded traffic matching a known DPI-classifiable protocol (STUN,
    // QUIC) gets the new embedded-tag wire layout with a canonical header for
    // that protocol; everything else keeps the legacy tag-prefix layout.
    let mimic = derive_mimic_fields(&analysis.header);

    let size_distribution = build_size_distribution(&analysis.uplink);
    let iat_distribution = build_iat_distribution(&analysis.uplink);

    let reverse_profile = build_reverse_profile(&mask_id, analysis);

    // Neural signature: encode the uplink traffic through the live detector's
    // feature extractor so Neural Resonance can actually watch this mask.
    let pps = if analysis.duration_secs > 0 {
        analysis.total_packets as f64 / analysis.duration_secs as f64
    } else {
        0.0
    };
    let bps = pps * analysis.uplink.size_mean as f64;
    let signature_vector = derive_signature_vector(
        &analysis.uplink,
        analysis.mean_entropy,
        pps,
        bps,
        analysis.uplink.packet_count as u64,
        analysis.downlink.packet_count as u64,
    );

    Ok(MaskProfile {
        mask_id,
        version: 2, // Version 2 for HeaderSpec support
        created_at: current_unix_secs(),
        expires_at: current_unix_secs() + 365 * 24 * 3600, // 1 year
        spoof_protocol: mimic.spoof_protocol,
        header_template: mimic.header_template,
        eph_pub_offset: mimic.eph_pub_offset,
        eph_pub_length: 32,
        size_distribution,
        iat_distribution,
        size_iat_joint: analysis.size_iat_joint.clone(),
        padding_strategy: PaddingStrategy::RandomUniform { min: 0, max: 64 },
        fsm_states: analysis.fsm_states.clone(),
        fsm_initial_state: analysis.fsm_initial_state,
        signature_vector,
        reverse_profile,
        // Signed post-self-test in generate_and_store_mask when an operator
        // key is configured (R2 Phase B); zeros = unsigned/legacy otherwise.
        signature: [0u8; 64],
        header_spec: mimic.header_spec,
        perturbation_bounds: None,
        tag_offset: mimic.tag_offset,
        generated: true,
    })
}

fn build_reverse_profile(mask_id: &str, analysis: &AnalysisResult) -> Option<Box<MaskProfile>> {
    if analysis.downlink.packet_count < 50 {
        return None;
    }

    let mimic = derive_mimic_fields(&analysis.header);
    let size_distribution = build_size_distribution(&analysis.downlink);
    let iat_distribution = build_iat_distribution(&analysis.downlink);

    let pps = if analysis.duration_secs > 0 {
        analysis.total_packets as f64 / analysis.duration_secs as f64
    } else {
        0.0
    };
    let bps = pps * analysis.downlink.size_mean as f64;
    let signature_vector = derive_signature_vector(
        &analysis.downlink,
        analysis.mean_entropy,
        pps,
        bps,
        analysis.uplink.packet_count as u64,
        analysis.downlink.packet_count as u64,
    );

    Some(Box::new(MaskProfile {
        mask_id: format!("{}_reverse", mask_id),
        version: 2,
        created_at: current_unix_secs(),
        expires_at: current_unix_secs() + 365 * 24 * 3600,
        spoof_protocol: mimic.spoof_protocol,
        header_template: mimic.header_template,
        eph_pub_offset: mimic.eph_pub_offset,
        eph_pub_length: 32,
        size_distribution,
        iat_distribution,
        // Downlink is server-shaped (A7); the joint model is applied to uplink
        // client shaping, so the reverse profile keeps the 1-D marginals.
        size_iat_joint: None,
        padding_strategy: PaddingStrategy::RandomUniform { min: 0, max: 64 },
        fsm_states: vec![FSMState {
            state_id: 0,
            transitions: vec![],
        }],
        fsm_initial_state: 0,
        signature_vector,
        reverse_profile: None,
        signature: [0u8; 64],
        header_spec: mimic.header_spec,
        perturbation_bounds: None,
        tag_offset: mimic.tag_offset,
        generated: true,
    }))
}

fn build_size_distribution(direction: &DirectionalAnalysis) -> SizeDistribution {
    // Frequency-weighted point bins: one bin per unique size value with
    // weight = frequency / total.  Sampling picks a bin by weight and returns
    // exactly that size value (min == max), perfectly reproducing the real CDF.
    // This avoids the uniform-within-range artefact of quantile range bins
    // that fills gaps between discrete packet sizes (MTU, ack, etc.).
    let sorted = &direction.raw_sizes_sorted;
    if sorted.is_empty() {
        return SizeDistribution {
            dist_type: SizeDistType::Histogram,
            bins: vec![(64, 512, 1.0)],
            parametric_type: None,
            parametric_params: None,
        };
    }

    // Prefer a compact multimodal GMM when the marginal is clearly multimodal
    // (design-doc §4 bridge). Falls through to the faithful empirical point-bin
    // histogram for unimodal or small-sample recordings.
    if USE_GMM_DISTRIBUTIONS && sorted.len() >= GMM_MIN_SAMPLES {
        let data: Vec<f64> = sorted.iter().map(|&s| s as f64).collect();
        if let Some(fit) =
            gmm::select_best_bic_min_cluster(&data, GMM_MAX_COMPONENTS, gmm::MIN_CLUSTER_WEIGHT)
        {
            if fit.k() >= 2 {
                if let Some(flat) = fit.to_flat_params(GMM_MIN_COMPONENT_WEIGHT) {
                    return SizeDistribution {
                        dist_type: SizeDistType::Parametric,
                        bins: Vec::new(),
                        parametric_type: Some(ParametricType::Gmm),
                        parametric_params: Some(flat),
                    };
                }
            }
        }
    }

    let total = sorted.len() as f32;
    let mut bins: Vec<(u16, u16, f32)> = Vec::new();

    // Count frequencies via run-length on sorted data
    let mut i = 0;
    while i < sorted.len() {
        let val = sorted[i];
        let mut count = 0usize;
        while i < sorted.len() && sorted[i] == val {
            count += 1;
            i += 1;
        }
        bins.push((val, val, count as f32 / total));
    }

    SizeDistribution {
        dist_type: SizeDistType::Histogram,
        bins,
        parametric_type: None,
        parametric_params: None,
    }
}

fn build_iat_distribution(direction: &DirectionalAnalysis) -> IATDistribution {
    // Empirical quantile-based distribution: sample N evenly-spaced quantile
    // values from the sorted real IATs.  The Empirical sampler picks uniformly
    // among these stored values, faithfully reproducing the recorded CDF.
    let sorted = &direction.raw_iats_sorted;
    if sorted.is_empty() || sorted.len() < 10 {
        return IATDistribution {
            dist_type: IATDistType::LogNormal,
            params: vec![
                (direction.iat_mean_ms.max(1.0)).ln() as f64,
                (direction.iat_std_ms / direction.iat_mean_ms.max(1.0)).max(0.1) as f64,
            ],
            jitter_range_ms: symmetric_jitter_range(10.0),
        };
    }

    // Prefer a compact multimodal GMM when the IAT marginal is multimodal
    // (audio cadence + control tail, DNS req/resp asymmetry, QUIC ACK-vs-data).
    // Falls through to the empirical quantile sampler otherwise.
    if USE_GMM_DISTRIBUTIONS && sorted.len() >= GMM_MIN_SAMPLES {
        if let Some(fit) =
            gmm::select_best_bic_min_cluster(sorted, GMM_MAX_COMPONENTS, gmm::MIN_CLUSTER_WEIGHT)
        {
            if fit.k() >= 2 {
                if let Some(flat) = fit.to_flat_params(GMM_MIN_COMPONENT_WEIGHT) {
                    let jitter = (direction.iat_std_ms.max(0.1) as f64) * 0.02;
                    return IATDistribution {
                        dist_type: IATDistType::Gmm,
                        params: flat,
                        jitter_range_ms: symmetric_jitter_range(jitter),
                    };
                }
            }
        }
    }

    let num_quantiles = 200usize.min(sorted.len());
    let mut quantile_values: Vec<f64> = Vec::with_capacity(num_quantiles);
    for i in 0..num_quantiles {
        let idx = (i as f64 / (num_quantiles - 1).max(1) as f64 * (sorted.len() - 1) as f64).round()
            as usize;
        quantile_values.push(sorted[idx.min(sorted.len() - 1)]);
    }

    // Tiny jitter around quantile values to avoid exact duplicates
    let jitter = (direction.iat_std_ms.max(0.1) as f64) * 0.02;

    IATDistribution {
        dist_type: IATDistType::Empirical,
        params: quantile_values,
        jitter_range_ms: symmetric_jitter_range(jitter),
    }
}

fn symmetric_jitter_range(amplitude_ms: f64) -> (f64, f64) {
    let amplitude_ms = amplitude_ms.max(0.0);
    (-amplitude_ms, amplitude_ms)
}

// ─── Self-Test (Kolmogorov-Smirnov) ─────────────────────────────────────────

fn self_test(profile: &MaskProfile, packets: &[PacketMetadata]) -> Result<SelfTestResult> {
    // Generate synthetic samples from the mask profile. Use a FIXED seed so mask
    // acceptance/confidence is reproducible: a mask whose true KS sits near the
    // 0.45 gate must not pass on one run and fail on the next (masks may be
    // signed and are distributed, so acceptance must be deterministic).
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xA1_5E_1F_7E);
    let uplink_count = packets
        .iter()
        .filter(|p| p.direction == Direction::Uplink)
        .count()
        .min(5000);
    let downlink_count = packets
        .iter()
        .filter(|p| p.direction == Direction::Downlink)
        .count()
        .min(5000);

    let synthetic_uplink_sizes: Vec<f64> = (0..uplink_count)
        .map(|_| profile.size_distribution.sample(&mut rng) as f64)
        .collect();
    let synthetic_uplink_iats: Vec<f64> = (0..uplink_count)
        .map(|_| profile.iat_distribution.sample(&mut rng))
        .collect();
    let synthetic_downlink_sizes: Vec<f64> = if let Some(ref reverse) = profile.reverse_profile {
        (0..downlink_count)
            .map(|_| reverse.size_distribution.sample(&mut rng) as f64)
            .collect()
    } else {
        vec![]
    };
    let synthetic_downlink_iats: Vec<f64> = if let Some(ref reverse) = profile.reverse_profile {
        (0..downlink_count)
            .map(|_| reverse.iat_distribution.sample(&mut rng))
            .collect()
    } else {
        vec![]
    };

    // Real data
    let real_uplink_sizes: Vec<f64> = packets
        .iter()
        .filter(|p| p.direction == Direction::Uplink)
        .take(5000)
        .map(|p| p.size as f64)
        .collect();
    let real_uplink_iats: Vec<f64> = packets
        .iter()
        .filter(|p| p.direction == Direction::Uplink)
        .take(5000)
        .map(|p| p.iat_ms)
        .collect();
    let real_downlink_sizes: Vec<f64> = packets
        .iter()
        .filter(|p| p.direction == Direction::Downlink)
        .take(5000)
        .map(|p| p.size as f64)
        .collect();
    let real_downlink_iats: Vec<f64> = packets
        .iter()
        .filter(|p| p.direction == Direction::Downlink)
        .take(5000)
        .map(|p| p.iat_ms)
        .collect();

    // KS tests
    let ks_uplink_size = ks_test(&synthetic_uplink_sizes, &real_uplink_sizes);
    let ks_uplink_iat = ks_test(&synthetic_uplink_iats, &real_uplink_iats);
    let ks_downlink_size =
        if !real_downlink_sizes.is_empty() && !synthetic_downlink_sizes.is_empty() {
            ks_test(&synthetic_downlink_sizes, &real_downlink_sizes)
        } else {
            1.0
        };
    let ks_downlink_iat = if !real_downlink_iats.is_empty() && !synthetic_downlink_iats.is_empty() {
        ks_test(&synthetic_downlink_iats, &real_downlink_iats)
    } else {
        1.0
    };

    // Entropy match
    let real_entropy: f64 =
        packets.iter().map(|p| p.entropy as f64).sum::<f64>() / packets.len().max(1) as f64;
    // Encrypted traffic entropy is length-sensitive for short packets, so use a
    // minimum floor instead of forcing an exact match to 7.0.
    let entropy_penalty = entropy_penalty(real_entropy);
    let headers: Vec<Vec<u8>> = packets.iter().map(|p| p.header_prefix.clone()).collect();
    let header_match = profile
        .header_spec
        .as_ref()
        .map(|spec| header_match_rate(spec, &headers))
        .unwrap_or_else(|| raw_prefix_match_rate(&profile.header_template, &[], &headers));
    let fsm_score = fsm_plausibility_score(profile, packets);
    let uplink = uplink_count as f32;
    let downlink = downlink_count as f32;
    let direction_balance = uplink.min(downlink.max(1.0)) / uplink.max(downlink).max(1.0);

    let downlink_required = downlink_count >= 100;
    let ks_threshold = 0.4;
    let passed = self_test_passes(
        ks_uplink_size,
        ks_uplink_iat,
        ks_downlink_size,
        ks_downlink_iat,
        header_match,
        fsm_score,
        entropy_penalty,
        downlink_required,
    );
    let confidence = if passed {
        let downlink_quality = if downlink_required {
            1.0 - ((ks_downlink_size + ks_downlink_iat) / 2.0 / 0.45).min(1.0)
        } else {
            0.25
        };
        let uplink_quality = 1.0 - ((ks_uplink_size + ks_uplink_iat) / 2.0 / ks_threshold).min(1.0);
        (0.45 * uplink_quality
            + 0.20 * downlink_quality
            + 0.20 * header_match
            + 0.10 * fsm_score
            + 0.03 * direction_balance.min(1.0)
            + 0.02 * (1.0 - entropy_penalty))
            .max(0.1)
    } else {
        0.0
    };

    Ok(SelfTestResult {
        ks_uplink_size,
        ks_uplink_iat,
        ks_downlink_size,
        ks_downlink_iat,
        header_match,
        fsm_score,
        entropy_penalty,
        passed,
        confidence,
    })
}

fn fsm_plausibility_score(profile: &MaskProfile, packets: &[PacketMetadata]) -> f32 {
    if profile.fsm_states.is_empty() {
        return 0.0;
    }

    let uplink_sizes: Vec<u16> = packets
        .iter()
        .filter(|p| p.direction == Direction::Uplink)
        .map(|p| p.size)
        .collect();
    if uplink_sizes.len() < 50 {
        return 0.5;
    }

    let (observed_states, observed_initial) = build_fsm_from_sizes(&uplink_sizes);
    let observed_count = observed_states.len().max(1) as f32;
    let profile_count = profile.fsm_states.len().max(1) as f32;
    let state_count_match =
        1.0 - ((observed_count - profile_count).abs() / observed_count.max(profile_count));

    let initial_match = if profile.fsm_initial_state == observed_initial {
        1.0
    } else {
        0.5
    };
    let has_valid_initial = if profile
        .fsm_states
        .iter()
        .any(|s| s.state_id == profile.fsm_initial_state)
    {
        1.0
    } else {
        0.0
    };
    let transition_mass = profile
        .fsm_states
        .iter()
        .map(|state| {
            let sum: f32 = state
                .transitions
                .iter()
                .map(|t| match t.condition {
                    TransitionCondition::Random(p) => p.max(0.0),
                    _ => 0.25,
                })
                .sum();
            (1.0 - (sum - 1.0).abs()).clamp(0.0, 1.0)
        })
        .sum::<f32>()
        / profile.fsm_states.len() as f32;

    (0.40 * state_count_match.max(0.0)
        + 0.25 * initial_match
        + 0.20 * has_valid_initial
        + 0.15 * transition_mass)
        .clamp(0.0, 1.0)
}

fn header_match_rate(spec: &HeaderSpec, headers: &[Vec<u8>]) -> f32 {
    if headers.is_empty() {
        return 0.0;
    }
    let matched = headers
        .iter()
        .filter(|header| header_matches_spec(spec, header))
        .count();
    matched as f32 / headers.len() as f32
}

fn raw_prefix_match_rate(template: &[u8], randomize_indices: &[usize], headers: &[Vec<u8>]) -> f32 {
    if headers.is_empty() {
        return 0.0;
    }
    let matched = headers
        .iter()
        .filter(|header| {
            let len = template.len().min(header.len());
            (0..len).all(|idx| randomize_indices.contains(&idx) || header[idx] == template[idx])
        })
        .count();
    matched as f32 / headers.len() as f32
}

fn header_matches_spec(spec: &HeaderSpec, header: &[u8]) -> bool {
    let fields = spec.fields();
    let total_len: usize = fields
        .iter()
        .map(|field| match field {
            HeaderField::Fixed { bytes } => bytes.len(),
            HeaderField::Random { len }
            | HeaderField::Length { len, .. }
            | HeaderField::Id { len, .. }
            | HeaderField::CounterLike { len, .. } => *len,
        })
        .sum();
    if header.len() < total_len {
        return false;
    }

    let mut cursor = 0usize;
    for field in fields {
        match field {
            HeaderField::Fixed { bytes } => {
                if header[cursor..cursor + bytes.len()] != bytes {
                    return false;
                }
                cursor += bytes.len();
            }
            HeaderField::Random { len } => {
                cursor += len;
            }
            HeaderField::Length { len, .. } => {
                cursor += len;
            }
            HeaderField::Id { len, mode } => {
                if matches!(mode, IdFieldMode::Zero)
                    && header[cursor..cursor + len].iter().any(|&b| b != 0)
                {
                    return false;
                }
                cursor += len;
            }
            HeaderField::CounterLike { len, .. } => {
                cursor += len;
            }
        }
    }
    true
}

// ─── DPI-Plausible Mimic-Protocol Detection ─────────────────────────────────

/// Detect whether a recorded header prefix carries a byte-exact fingerprint
/// of a protocol aivpn has a working DPI-mimicry path for today (see
/// `crates/aivpn-common/src/mimic_protocol.rs`), returning the protocol to
/// spoof and the byte offset at which the 8-byte resonance tag should be
/// embedded in the mask's header (Variant A embedded-tag wire layout —
/// [`MaskProfile::tag_offset`]).
///
/// Deliberately narrower and cheaper than [`infer_header_spec`]'s scored,
/// multi-candidate inference: it only recognizes the two protocols with a
/// real DPI fixup implemented (STUN's message-length patch, QUIC's
/// constructed RFC 9001 Initial), and only on the single byte range that is
/// actually load-bearing for each protocol's real-DPI classifier
/// (nDPI's `is_stun` / `ndpi_search_quic`). Returns `None` for anything else,
/// leaving the caller to fall back to the legacy tag-prefix layout.
fn detect_mimic_protocol(recorded_header_prefix: &[u8]) -> Option<(SpoofProtocol, u16)> {
    // STUN (RFC 5389): magic cookie 0x2112A442 at offset 4..8. This is the
    // byte range nDPI's STUN dissector keys off; a recording whose header
    // consistently carries it at this offset is almost certainly STUN.
    if recorded_header_prefix.len() >= 8 && recorded_header_prefix[4..8] == [0x21, 0x12, 0xA4, 0x42]
    {
        return Some((SpoofProtocol::WebRTC_STUN, 8));
    }

    // QUIC v1 (RFC 9000): long-header form (high bit of the first byte set)
    // with version 1 at offset 1..5.
    if recorded_header_prefix.len() >= 5
        && recorded_header_prefix[0] & 0x80 != 0
        && recorded_header_prefix[1..5] == [0x00, 0x00, 0x00, 0x01]
    {
        return Some((SpoofProtocol::QUIC, 6));
    }

    None
}

/// Canonical STUN `HeaderSpec` for detected-protocol masks: mirrors the
/// hand-authored `webrtc_zoom_v3` preset's structure exactly — binding
/// request type@0 (2 bytes), STUN message-length@2 (a `Length` field, 2
/// bytes big-endian), magic cookie@4 (4 bytes), an 8-byte tag-carrier slot@8,
/// and the remaining 4-byte transaction-id tail@16 (20 bytes total).
///
/// A raw recorded header cannot be trusted as-is: `MimicProtocol::Stun`'s
/// post-assembly fixup (`MaskProfile::patch_stun_length`) needs a `Length`
/// field at a known offset to satisfy nDPI's `is_stun` invariant
/// (`msg_len + 20 == udp_payload_len`), which recorded bytes have no reason
/// to expose correctly. The empirical value of the recording (size/IAT/FSM
/// distributions) is kept; only the header structure is replaced with this
/// known-valid one.
fn canonical_stun_header_spec() -> HeaderSpec {
    HeaderSpec::structured(vec![
        HeaderField::Fixed {
            bytes: vec![0x00, 0x01],
        },
        HeaderField::Length {
            len: 2,
            endian: HeaderEndian::Big,
        },
        HeaderField::Fixed {
            bytes: vec![0x21, 0x12, 0xA4, 0x42],
        },
        HeaderField::Id {
            len: 8,
            mode: IdFieldMode::Random,
        },
        HeaderField::Id {
            len: 4,
            mode: IdFieldMode::Random,
        },
    ])
}

/// Header/protocol/tag-layout fields derived for a generated `MaskProfile`.
struct MimicFields {
    spoof_protocol: SpoofProtocol,
    header_spec: Option<HeaderSpec>,
    header_template: Vec<u8>,
    eph_pub_offset: u16,
    tag_offset: u16,
}

/// Derive the `spoof_protocol` / `header_spec` / `header_template` /
/// `eph_pub_offset` / `tag_offset` fields for a mask built from `header`.
///
/// If [`detect_mimic_protocol`] recognizes the recorded header as a known
/// DPI-classifiable protocol, the mask switches to the new embedded-tag wire
/// layout (Variant A) with a CANONICAL header for that protocol — not the
/// raw recorded bytes — so the mask's traffic actually passes that
/// protocol's real DPI validation. Otherwise the legacy tag-prefix layout
/// (`tag_offset == u16::MAX`) is kept exactly as before, using whatever
/// [`infer_header_spec`] produced during analysis.
fn derive_mimic_fields(header: &HeaderObservation) -> MimicFields {
    if let Some((spoof_protocol, tag_offset)) = detect_mimic_protocol(&header.template) {
        let header_spec = match spoof_protocol {
            SpoofProtocol::WebRTC_STUN => canonical_stun_header_spec(),
            // QUIC's mimicry is fully CONSTRUCTED at packet-build time by
            // `MimicProtocol::Quic::emit` (the header below is only used for
            // eph_pub_offset bookkeeping and the handshake-packet fallback
            // layout — see mimicry.rs), so the hand-authored canonical
            // constructor is all that's needed here.
            _ => HeaderSpec::quic_initial(0x0000_0001, 8),
        };
        let header_template = header_spec.generate_static();
        let eph_pub_offset = header_spec.min_length() as u16;
        return MimicFields {
            spoof_protocol,
            header_spec: Some(header_spec),
            header_template,
            eph_pub_offset,
            tag_offset,
        };
    }

    // No recognized protocol: legacy tag-prefix layout, unchanged behavior.
    let header_template = header
        .header_spec
        .as_ref()
        .map(HeaderSpec::generate_static)
        .unwrap_or_else(|| header.template.clone());
    let eph_pub_offset = if let Some(ref spec) = header.header_spec {
        spec.min_length() as u16
    } else {
        header_template.len().min(4) as u16
    };
    let spoof_protocol = header
        .header_spec
        .as_ref()
        .map(header_spec_protocol)
        .unwrap_or(SpoofProtocol::QUIC);

    MimicFields {
        spoof_protocol,
        header_spec: header.header_spec.clone(),
        header_template,
        eph_pub_offset,
        tag_offset: u16::MAX,
    }
}

fn header_spec_protocol(spec: &HeaderSpec) -> SpoofProtocol {
    match spec {
        HeaderSpec::RawPrefix { .. } => SpoofProtocol::QUIC,
        HeaderSpec::Structured { fields } => {
            if fields.len() >= 4
                && matches!(fields.first(), Some(HeaderField::Fixed { bytes }) if bytes == &vec![0x00, 0x01])
            {
                SpoofProtocol::WebRTC_STUN
            } else if fields.len() >= 4
                && matches!(fields.first(), Some(HeaderField::Fixed { bytes }) if bytes == &vec![0xC0])
            {
                SpoofProtocol::QUIC
            } else if fields.len() >= 3
                && matches!(fields.get(1), Some(HeaderField::Fixed { bytes }) if bytes == &vec![0x01, 0x00])
            {
                SpoofProtocol::DNS_over_UDP
            } else if fields.len() >= 3
                && matches!(fields.first(), Some(HeaderField::Fixed { bytes }) if bytes == &vec![0x16] || bytes == &vec![0x17] || bytes == &vec![0x15] || bytes == &vec![0x14])
            {
                SpoofProtocol::HTTPS_H2
            } else {
                SpoofProtocol::QUIC
            }
        }
    }
}

fn entropy_penalty(real_entropy: f64) -> f32 {
    if real_entropy >= MIN_ENCRYPTED_ENTROPY {
        0.0
    } else {
        (MIN_ENCRYPTED_ENTROPY - real_entropy).min(1.0) as f32
    }
}

/// Two-sample Kolmogorov-Smirnov test statistic
///
/// Correct merge-walk that handles tied values: at each unique value,
/// advance BOTH pointers past all duplicates before comparing CDFs.
fn ks_test(sample1: &[f64], sample2: &[f64]) -> f32 {
    if sample1.is_empty() || sample2.is_empty() {
        return 1.0;
    }

    let mut s1 = sample1.to_vec();
    let mut s2 = sample2.to_vec();
    s1.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s2.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n1 = s1.len() as f64;
    let n2 = s2.len() as f64;
    let mut max_diff: f64 = 0.0;

    let mut i = 0usize;
    let mut j = 0usize;

    while i < s1.len() || j < s2.len() {
        let v1 = if i < s1.len() { s1[i] } else { f64::INFINITY };
        let v2 = if j < s2.len() { s2[j] } else { f64::INFINITY };
        let current = v1.min(v2);

        // Advance both pointers past all elements <= current
        while i < s1.len() && s1[i] <= current {
            i += 1;
        }
        while j < s2.len() && s2[j] <= current {
            j += 1;
        }

        let cdf1 = i as f64 / n1;
        let cdf2 = j as f64 / n2;
        max_diff = max_diff.max((cdf1 - cdf2).abs());
    }

    max_diff as f32
}

// ─── Statistical Helpers ─────────────────────────────────────────────────────

fn mean_u16(data: &[u16]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().map(|&x| x as f32).sum::<f32>() / data.len() as f32
}

fn std_dev_u16(data: &[u16]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let m = mean_u16(data);
    let variance = data.iter().map(|&x| (x as f32 - m).powi(2)).sum::<f32>() / data.len() as f32;
    variance.sqrt()
}

fn mean_f64(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<f64>() / data.len() as f64
}

fn std_dev_f64(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let m = mean_f64(data);
    let variance = data.iter().map(|x| (x - m).powi(2)).sum::<f64>() / data.len() as f64;
    variance.sqrt()
}

fn mean_f32(data: &[f32]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<f32>() / data.len() as f32
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_traffic, build_iat_distribution, build_mask_profile, detect_mimic_protocol,
        entropy_penalty, header_consensus, header_match_rate, infer_header_spec, ks_test,
        sanitize_service_slug, self_test_passes, DirectionalAnalysis, Period,
    };
    use aivpn_common::mask::{HeaderSpec, IATDistType, SpoofProtocol};
    use aivpn_common::mimic_protocol::MimicProtocol;
    use aivpn_common::recording::{Direction, PacketMetadata};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn entropy_penalty_accepts_short_encrypted_packets() {
        assert_eq!(entropy_penalty(6.03), 0.0);
        assert_eq!(entropy_penalty(7.8), 0.0);
        assert!(entropy_penalty(5.2) > 0.5);
    }

    #[test]
    fn multi_period_iat_distribution_preserves_spread_without_positive_bias() {
        // Generate synthetic IATs from two periods to test empirical quantile builder
        let mut raw_iats: Vec<f64> = Vec::new();
        // 60% near 20ms
        for i in 0..240 {
            raw_iats.push(15.0 + (i as f64 % 10.0));
        }
        // 40% near 100ms
        for i in 0..160 {
            raw_iats.push(70.0 + (i as f64 % 60.0));
        }
        raw_iats.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let direction = DirectionalAnalysis {
            size_modes: vec![],
            size_mean: 900.0,
            size_std: 120.0,
            iat_mean_ms: 52.0,
            iat_std_ms: 28.0,
            periods: vec![
                Period {
                    period_ms: 20.0,
                    jitter_ms: 5.0,
                    weight: 0.6,
                },
                Period {
                    period_ms: 100.0,
                    jitter_ms: 30.0,
                    weight: 0.4,
                },
            ],
            packet_count: 400,
            raw_sizes_sorted: vec![],
            raw_iats_sorted: raw_iats,
        };

        let dist = build_iat_distribution(&direction);
        // With enough multimodal samples the builder now emits a BIC-selected
        // GMM (design-doc §4 bridge) instead of the empirical quantile table.
        assert_eq!(dist.dist_type, IATDistType::Gmm);
        let k = dist.params[0] as usize;
        assert!(k >= 2, "expected multimodal GMM, got k={k}");
        // Component means (params[2 + c*3]) must straddle the two real modes.
        let means: Vec<f64> = (0..k).map(|c| dist.params[2 + c * 3]).collect();
        assert!(
            means.iter().any(|&m| m < 30.0),
            "no fast (~20ms) mode in {means:?}"
        );
        assert!(
            means.iter().any(|&m| m > 60.0),
            "no slow (~100ms) mode in {means:?}"
        );
        // No positive bias: sampled mean should sit near the true mean (~52ms),
        // not be inflated. Both modes must be populated.
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let samples: Vec<f64> = (0..5000).map(|_| dist.sample(&mut rng)).collect();
        let sample_mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(
            (30.0..75.0).contains(&sample_mean),
            "sampled mean {sample_mean:.1} unexpectedly biased"
        );
        assert!(samples.iter().any(|&v| v < 30.0), "fast mode unpopulated");
        assert!(samples.iter().any(|&v| v > 60.0), "slow mode unpopulated");
        assert!(dist.jitter_range_ms.0 < 0.0);
        assert!(dist.jitter_range_ms.1 > 0.0);
    }

    /// End-to-end product-path validation on the design-doc §4 R&D corpus:
    /// real recorded protocol traffic → `analyze_traffic` → `build_mask_profile`
    /// → the generated mask emits a GMM and resamples close to the real IAT
    /// marginal, and the whole MaskProfile survives JSON round-trip (masks are
    /// distributed as JSON). Sudo-free: no TUN/tunnel needed. SKIPS when the
    /// git-ignored corpus is absent (CI).
    #[test]
    fn end_to_end_generates_and_validates_gmm_mask_from_real_corpus() {
        use super::{analyze_traffic, build_mask_profile, ks_test};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../research/mask-generation/phase2b/corpus/features.json");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("SKIP end_to_end: corpus absent at {}", path.display());
            return;
        };
        let features: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // DNS has the most packets and a strongly multimodal IAT marginal.
        let proto = "dns";
        let mut pairs: Vec<(f64, f64)> = Vec::new();
        for key in ["train", "test"] {
            if let Some(arr) = features[proto][key].as_array() {
                for p in arr {
                    if let Some(a) = p.as_array() {
                        if a.len() >= 2 {
                            pairs
                                .push((a[0].as_f64().unwrap_or(0.0), a[1].as_f64().unwrap_or(0.0)));
                        }
                    }
                }
            }
        }
        assert!(
            pairs.len() >= 100,
            "need >=100 packets, got {}",
            pairs.len()
        );

        // Synthesize an uplink recording from the real (size, iat) pairs.
        let mut ts: u64 = 0;
        let packets: Vec<PacketMetadata> = pairs
            .iter()
            .map(|&(size, iat)| {
                ts = ts.saturating_add((iat.max(0.0) * 1_000_000.0) as u64);
                PacketMetadata {
                    direction: Direction::Uplink,
                    size: size.round().clamp(1.0, u16::MAX as f64) as u16,
                    iat_ms: iat.max(0.0),
                    entropy: 7.6, // encrypted-looking payload
                    header_prefix: vec![0u8; 16],
                    timestamp_ns: ts,
                }
            })
            .collect();

        let analysis = analyze_traffic(proto, &packets).expect("analysis");
        let profile = build_mask_profile(proto, &analysis).expect("profile");

        // The generated mask must use the GMM IAT distribution (multimodal).
        assert_eq!(
            profile.iat_distribution.dist_type,
            IATDistType::Gmm,
            "expected GMM IAT distribution from multimodal real corpus"
        );

        // Resample and confirm the mask reproduces the real IAT marginal well.
        let mut rng = StdRng::seed_from_u64(7);
        let real_iats: Vec<f64> = pairs.iter().map(|&(_, i)| i.max(0.0)).collect();
        let sampled: Vec<f64> = (0..4000)
            .map(|_| profile.iat_distribution.sample(&mut rng))
            .collect();
        let ks = ks_test(&sampled, &real_iats);
        assert!(
            ks < 0.2,
            "generated GMM mask IAT KS vs real = {ks:.3} (too far)"
        );

        // Full MaskProfile JSON round-trip (masks ship as JSON).
        let json = serde_json::to_string(&profile).unwrap();
        let back: aivpn_common::mask::MaskProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.iat_distribution.dist_type, IATDistType::Gmm);
        assert_eq!(
            back.iat_distribution.params,
            profile.iat_distribution.params
        );
        eprintln!("end_to_end dns: generated GMM mask, resample KS vs real IAT = {ks:.3}");
    }

    #[test]
    fn small_multimodal_sample_keeps_empirical_path() {
        // Below GMM_MIN_SAMPLES the builder must stay on the faithful empirical
        // quantile sampler (a GMM fit is untrustworthy at tiny N).
        let mut raw_iats: Vec<f64> = Vec::new();
        for i in 0..12 {
            raw_iats.push(15.0 + (i as f64 % 5.0));
        }
        for i in 0..8 {
            raw_iats.push(90.0 + (i as f64 % 20.0));
        }
        raw_iats.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let direction = DirectionalAnalysis {
            size_modes: vec![],
            size_mean: 800.0,
            size_std: 100.0,
            iat_mean_ms: 45.0,
            iat_std_ms: 30.0,
            periods: vec![],
            packet_count: 20,
            raw_sizes_sorted: vec![],
            raw_iats_sorted: raw_iats,
        };
        let dist = build_iat_distribution(&direction);
        assert_eq!(dist.dist_type, IATDistType::Empirical);
    }

    #[test]
    fn self_test_accepts_good_empirical_profile() {
        // With correct KS + empirical distributions, values should be small
        assert!(self_test_passes(
            0.05, 0.12, 0.08, 0.10, 1.000, 1.000, 0.000, true,
        ));
    }

    #[test]
    fn self_test_accepts_moderate_ks_with_good_structure() {
        // Some noise in IAT but still within bounds
        assert!(self_test_passes(
            0.15, 0.35, 0.20, 0.30, 0.80, 0.90, 0.000, true,
        ));
    }

    #[test]
    fn self_test_accepts_weak_header_above_threshold() {
        assert!(self_test_passes(
            0.10, 0.20, 0.15, 0.25, 0.60, 0.80, 0.000, true,
        ));
    }

    #[test]
    fn self_test_rejects_high_ks() {
        // KS > 0.45 should be rejected
        assert!(!self_test_passes(
            0.50, 0.60, 0.70, 0.80, 1.000, 1.000, 0.000, true,
        ));
    }

    #[test]
    fn self_test_still_rejects_broad_statistical_mismatch() {
        assert!(!self_test_passes(
            0.310, 0.820, 0.610, 0.590, 1.000, 1.000, 0.000, true,
        ));
    }

    #[test]
    fn ks_test_identical_samples_returns_zero() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(ks_test(&data, &data), 0.0);
    }

    #[test]
    fn ks_test_identical_constant_returns_zero() {
        // This was the critical bug: all-same values caused KS ≈ 1.0
        let data: Vec<f64> = vec![1346.0; 5000];
        assert_eq!(ks_test(&data, &data), 0.0);
    }

    #[test]
    fn ks_test_similar_distributions_small() {
        let s1: Vec<f64> = (0..1000).map(|i| (i as f64) * 1.5).collect();
        let s2: Vec<f64> = (0..1000).map(|i| (i as f64) * 1.5 + 0.1).collect();
        let ks = ks_test(&s1, &s2);
        assert!(
            ks < 0.05,
            "KS for near-identical distributions should be small, got {}",
            ks
        );
    }

    #[test]
    fn header_consensus_is_deterministic_for_variable_bytes() {
        let headers = vec![
            vec![0x16, 0x03, 0x03, 0x00, 0x10],
            vec![0x16, 0x03, 0x03, 0x00, 0x20],
            vec![0x16, 0x03, 0x03, 0x00, 0x30],
        ];
        let c1 = header_consensus(&headers);
        let c2 = header_consensus(&headers);
        assert_eq!(c1, c2);
        assert_eq!(&c1[0..4], &[0x16, 0x03, 0x03, 0x00]);
    }

    #[test]
    fn infer_header_spec_rejects_random_noise() {
        let headers = vec![
            vec![0x91, 0x44, 0xF2, 0x7A, 0x19, 0x88, 0x01, 0x33],
            vec![0x6E, 0x10, 0xA3, 0x54, 0xC8, 0x92, 0x17, 0x45],
            vec![0x2D, 0xFF, 0x73, 0x0A, 0xB1, 0x4E, 0xC0, 0x18],
            vec![0x57, 0x28, 0x99, 0x61, 0x0F, 0xCD, 0xA4, 0x72],
        ];
        let (spec, confidence) = infer_header_spec(&headers);
        match spec {
            Some(HeaderSpec::RawPrefix { .. }) | None => {}
            other => panic!("unexpected protocol inference for noise: {:?}", other),
        }
        assert!(confidence <= 0.55);
    }

    #[test]
    fn infer_header_spec_detects_stun_and_matches_headers() {
        let headers = vec![
            vec![
                0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                12,
            ],
            vec![
                0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24,
            ],
            vec![
                0x00, 0x01, 0x00, 0x10, 0x21, 0x12, 0xA4, 0x42, 25, 26, 27, 28, 29, 30, 31, 32, 33,
                34, 35, 36,
            ],
        ];
        let (spec, confidence) = infer_header_spec(&headers);
        let spec = spec.expect("stun should be inferred");
        assert!(confidence > 0.6);
        assert!(matches!(spec, HeaderSpec::Structured { .. }));
        assert!(header_match_rate(&spec, &headers) > 0.9);
    }

    #[test]
    fn service_slug_blocks_path_traversal() {
        // A malicious/mistyped recording service name must never escape the
        // mask directory when it is turned into a `<mask_id>.json` filename.
        for evil in [
            "../../etc/cron.d/evil",
            "/etc/passwd",
            "..\\..\\windows",
            "a/b/c",
            "..",
        ] {
            let slug = sanitize_service_slug(evil);
            let mask_id = format!("auto_{}_v1", slug);
            assert!(
                mask_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "mask_id '{mask_id}' from '{evil}' contains unsafe chars"
            );
            assert!(!mask_id.contains(".."));
            assert!(!mask_id.contains('/'));
        }
    }

    #[test]
    fn service_slug_preserves_normal_names() {
        assert_eq!(sanitize_service_slug("Zoom"), "zoom");
        assert_eq!(sanitize_service_slug("youtube 4k"), "youtube_4k");
    }

    // ─── detect_mimic_protocol / DPI-plausible recorded masks ───────────────

    #[test]
    fn detect_mimic_protocol_recognizes_stun_cookie() {
        let mut header = vec![0u8; 16];
        header[0..2].copy_from_slice(&[0x00, 0x01]);
        header[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(
            detect_mimic_protocol(&header),
            Some((SpoofProtocol::WebRTC_STUN, 8))
        );
    }

    #[test]
    fn detect_mimic_protocol_recognizes_quic_v1_long_header() {
        let mut header = vec![0u8; 16];
        header[0] = 0xC0; // long header form, fixed bit set
        header[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
        assert_eq!(
            detect_mimic_protocol(&header),
            Some((SpoofProtocol::QUIC, 6))
        );
    }

    #[test]
    fn detect_mimic_protocol_returns_none_for_random_bytes() {
        let header = vec![
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        assert_eq!(detect_mimic_protocol(&header), None);
    }

    #[test]
    fn detect_mimic_protocol_handles_short_headers_without_panicking() {
        assert_eq!(detect_mimic_protocol(&[]), None);
        assert_eq!(detect_mimic_protocol(&[0xC0, 0x00]), None);
        assert_eq!(detect_mimic_protocol(&[0x00, 0x01, 0x00, 0x00]), None);
    }

    fn fake_packet(
        direction: Direction,
        header_prefix: Vec<u8>,
        size: u16,
        iat_ms: f64,
        timestamp_ns: u64,
    ) -> PacketMetadata {
        PacketMetadata {
            direction,
            size,
            iat_ms,
            entropy: 7.5,
            header_prefix,
            timestamp_ns,
        }
    }

    /// A synthetic recording (150 uplink + 80 downlink packets, all sharing
    /// `header_prefix`) large enough for `analyze_traffic` to accept.
    fn recording_with_header(header_prefix: [u8; 16]) -> Vec<PacketMetadata> {
        let mut packets = Vec::new();
        let mut ts = 0u64;
        for i in 0..150u32 {
            ts += 5_000_000;
            let size = 200 + (i % 40) as u16;
            packets.push(fake_packet(
                Direction::Uplink,
                header_prefix.to_vec(),
                size,
                5.0,
                ts,
            ));
        }
        for i in 0..80u32 {
            ts += 5_000_000;
            let size = 300 + (i % 40) as u16;
            packets.push(fake_packet(
                Direction::Downlink,
                header_prefix.to_vec(),
                size,
                5.0,
                ts,
            ));
        }
        packets
    }

    /// A recording that PASSES the generation self-test gate — required by the
    /// Phase B signing tests, which need `generate_and_store_mask` to succeed.
    /// Mirrors the proven-passing `recording_tests::generate_video_call_packets`
    /// shape but deterministically: a QUIC-like header (reproduces faithfully,
    /// unlike an embedded-tag STUN header whose tag bytes break header_match), a
    /// bimodal control/media size distribution, and size-correlated varied IAT
    /// (a constant IAT fits a spread distribution and fails the IAT KS test).
    fn signable_recording() -> Vec<PacketMetadata> {
        let mut header = vec![0xC0u8; 16];
        header[1] = 0x00;
        header[2] = 0x00;
        header[3] = 0x01;
        let mut packets = Vec::with_capacity(300);
        let mut ts: u64 = 1_000_000_000_000;
        for i in 0..300u32 {
            let dir = if i % 3 == 0 {
                Direction::Uplink
            } else {
                Direction::Downlink
            };
            // Deterministic ~30% control / ~70% media split.
            let control = (i.wrapping_mul(2_654_435_761) >> 28) % 10 < 3;
            let size: u16 = if control {
                80 + (i % 70) as u16
            } else {
                800 + (i % 500) as u16
            };
            let iat_ms: f64 = if size > 500 {
                18.0 + (i % 9) as f64
            } else {
                80.0 + (i % 40) as f64
            };
            ts += (iat_ms * 1_000_000.0) as u64;
            let entropy: f32 = 7.1 + (i % 5) as f32 * 0.1;
            packets.push(PacketMetadata {
                direction: dir,
                size,
                iat_ms,
                entropy,
                header_prefix: header.clone(),
                timestamp_ns: ts,
            });
        }
        packets
    }

    #[test]
    fn generated_mask_has_nonzero_neural_signature() {
        // Regression: auto-masks used to ship signature_vector = [0.0; 64],
        // which bakes a degenerate all-zero MLP so Neural Resonance is blind to
        // the mask. The signature must now be the encoded fingerprint of the
        // recorded traffic — 64 floats, not all zero — for both the mask and
        // its reverse (downlink) profile.
        let mut header = [0u8; 16];
        header[0..2].copy_from_slice(&[0x00, 0x01]);
        header[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let packets = recording_with_header(header);
        let analysis = analyze_traffic("sig_test", &packets).expect("analysis");
        let mask = build_mask_profile("sig_test", &analysis).expect("mask");

        assert_eq!(mask.signature_vector.len(), 64);
        assert!(
            mask.signature_vector.iter().any(|&f| f != 0.0),
            "signature_vector must not be all-zero"
        );
        let reverse = mask.reverse_profile.expect("reverse profile present");
        assert_eq!(reverse.signature_vector.len(), 64);
        assert!(
            reverse.signature_vector.iter().any(|&f| f != 0.0),
            "reverse signature_vector must not be all-zero"
        );
    }

    #[tokio::test]
    async fn phase_b_generated_mask_is_signed_when_key_configured() {
        // R2 Phase B: with an operator signing key on the store, the generated
        // mask (and its reverse profile) must carry a real, verifiable
        // Ed25519 signature — applied only after the self-test gate passed.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let dir = std::env::temp_dir().join(format!(
            "aivpn-maskgen-signed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let store = std::sync::Arc::new(crate::mask_store::MaskStore::new(
            std::sync::Arc::new(crate::gateway::MaskCatalog::new()),
            dir.clone(),
            Some(sk),
            Some(pk),
            aivpn_common::mask::MaskVerifyMode::Warn,
        ));

        let packets = signable_recording();
        let mask_id = super::generate_and_store_mask("phaseb_sig", &packets, &store)
            .await
            .expect("generation must succeed");

        let entry = store.get_mask(&mask_id).expect("mask stored");
        assert!(!entry.profile.is_unsigned(), "mask must be signed");
        assert!(
            entry.profile.verify_signature(&pk).unwrap(),
            "outer signature must verify against the operator pubkey"
        );
        let rev = entry.profile.reverse_profile.as_ref().expect("reverse");
        assert!(
            rev.verify_signature(&pk).unwrap(),
            "reverse profile must be independently verifiable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn phase_b_generated_mask_unsigned_without_key() {
        // No operator key configured → exactly the legacy behavior: all-zero
        // signature, generation still succeeds.
        let dir = std::env::temp_dir().join(format!(
            "aivpn-maskgen-unsigned-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let store = std::sync::Arc::new(crate::mask_store::MaskStore::new(
            std::sync::Arc::new(crate::gateway::MaskCatalog::new()),
            dir.clone(),
            None,
            None,
            aivpn_common::mask::MaskVerifyMode::Warn,
        ));
        let packets = signable_recording();
        let mask_id = super::generate_and_store_mask("phaseb_unsig", &packets, &store)
            .await
            .expect("generation must succeed");
        let entry = store.get_mask(&mask_id).expect("mask stored");
        assert!(entry.profile.is_unsigned());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_signature_is_deterministic() {
        // A rebuilt mask from the same recording must bake an identical encoder,
        // so builds are reproducible (fixed-seed shuffle).
        let mut header = [0u8; 16];
        header[0..2].copy_from_slice(&[0x00, 0x01]);
        header[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let packets = recording_with_header(header);
        let a1 = analyze_traffic("det", &packets).expect("analysis");
        let m1 = build_mask_profile("det", &a1).expect("mask");
        let a2 = analyze_traffic("det", &packets).expect("analysis");
        let m2 = build_mask_profile("det", &a2).expect("mask");
        assert_eq!(m1.signature_vector, m2.signature_vector);
    }

    #[test]
    fn baked_signature_discriminates_own_traffic_from_shape_anomaly() {
        // End-to-end: bake the generated mask's signature into the encoder and
        // confirm the mask's OWN feature vector reconstructs with lower error
        // than a shape-anomalous stream (all tiny packets, no jitter — a crude
        // DPI-visible tunnel signature). This is the property a zero signature
        // could never provide: with [0.0; 64] every input reconstructs to zero,
        // so anomalies are invisible.
        use crate::neural::{encode_features, BakedMaskEncoder, TrafficStats};
        use std::collections::VecDeque;

        let mut header = [0u8; 16];
        header[0..2].copy_from_slice(&[0x00, 0x01]);
        header[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let packets = recording_with_header(header);
        let analysis = analyze_traffic("disc", &packets).expect("analysis");
        let mask = build_mask_profile("disc", &analysis).expect("mask");

        let encoder = BakedMaskEncoder::from_signature(&mask.signature_vector, 128);

        // The mask's own feature vector (its signature) should reconstruct well.
        let own_sig: [f32; 64] = mask.signature_vector[..64]
            .try_into()
            .expect("signature is 64 floats");
        let own_mse = encoder.reconstruction_error(&own_sig);

        // A shape anomaly: uniform 40-byte packets at a fixed 1 ms cadence.
        let mut anomaly = TrafficStats {
            packet_sizes: VecDeque::from(vec![40u16; 200]),
            inter_arrivals: VecDeque::from(vec![1.0f64; 200]),
            entropy_samples: VecDeque::from(vec![7.5f64; 200]),
            ..TrafficStats::new()
        };
        anomaly.rx_packets = 200;
        let anomaly_feats = encode_features(&anomaly);
        let anomaly_mse = encoder.reconstruction_error(&anomaly_feats);

        assert!(
            anomaly_mse > own_mse,
            "shape anomaly MSE ({anomaly_mse}) must exceed own-traffic MSE ({own_mse})"
        );
    }

    #[test]
    fn recorded_stun_traffic_produces_dpi_plausible_mask() {
        let mut header = [0u8; 16];
        header[0..2].copy_from_slice(&[0x00, 0x01]);
        header[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let packets = recording_with_header(header);

        let analysis = analyze_traffic("zoom_stun", &packets).expect("analysis should succeed");
        let mask = build_mask_profile("zoom_stun", &analysis).expect("mask should build");

        assert_eq!(mask.spoof_protocol, SpoofProtocol::WebRTC_STUN);
        assert_eq!(mask.tag_offset, 8);
        assert_eq!(mask.embedded_tag_offset(), Some(8));

        let spec = mask
            .header_spec
            .as_ref()
            .expect("STUN mask must carry a header_spec");
        let generated = spec.generate_static();
        assert_eq!(
            generated.len(),
            20,
            "canonical STUN header must be exactly 20 bytes"
        );
        assert_eq!(
            &generated[4..8],
            &[0x21, 0x12, 0xA4, 0x42],
            "magic cookie must sit at offset 4"
        );

        // Run the real post-assembly STUN fixup (`MimicProtocol::Stun::finalize`)
        // on a simulated [mdh][ciphertext] packet and verify nDPI's is_stun
        // invariant (msg_len + 20 == udp_payload_len).
        let proto = MimicProtocol::for_spoof(mask.spoof_protocol);
        assert_eq!(proto, MimicProtocol::Stun);

        let mut packet = generated.clone();
        packet.extend_from_slice(&[0xABu8; 137]); // stand-in ciphertext tail
        proto.finalize(&mut packet, &mask);

        let msg_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        assert_eq!(
            msg_len + 20,
            packet.len(),
            "nDPI is_stun invariant must hold after finalize"
        );
    }

    #[test]
    fn recorded_quic_traffic_gets_embedded_tag_layout() {
        let mut header = [0u8; 16];
        header[0] = 0xC0;
        header[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        let packets = recording_with_header(header);

        let analysis = analyze_traffic("game_quic", &packets).expect("analysis should succeed");
        let mask = build_mask_profile("game_quic", &analysis).expect("mask should build");

        assert_eq!(mask.spoof_protocol, SpoofProtocol::QUIC);
        assert_eq!(mask.tag_offset, 6);
        assert_eq!(mask.embedded_tag_offset(), Some(6));

        let proto = MimicProtocol::for_spoof(mask.spoof_protocol);
        assert_eq!(proto, MimicProtocol::Quic);
        // QUIC is fully constructed at build time (RFC 9001 Initial); the
        // detector only needs to route the mask to that path.
        assert!(proto.is_constructed());
    }

    #[test]
    fn recorded_unrecognized_traffic_stays_legacy_layout() {
        let header = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let packets = recording_with_header(header);

        let analysis = analyze_traffic("mystery_udp", &packets).expect("analysis should succeed");
        let mask = build_mask_profile("mystery_udp", &analysis).expect("mask should build");

        assert_eq!(mask.tag_offset, u16::MAX);
        assert_eq!(mask.embedded_tag_offset(), None);
    }
}
