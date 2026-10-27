//! Neural Resonance Module — Baked Mask Encoder
//!
//! Implements Signal Reconstruction Resonance (Patent 1) using a lightweight
//! hand-rolled MLP instead of a full LLM. Each mask's signature_vector is
//! "baked" into a tiny neural network (64 → 128 → 64) whose weights are
//! derived deterministically from the mask's 64-float signature.
//!
//! Memory per mask: ~66 KB (vs ~400 MB for Qwen-0.5B).
//! Total for 100 masks: ~6.6 MB — fits any VPS.
//!
//! The baked encoder learns the mask's traffic fingerprint:
//! - Input: 64-dim feature vector extracted from live traffic
//! - Output: 64-dim reconstruction vector
//! - MSE(input, output) = reconstruction error = resonance score
//!
//! Low MSE → traffic matches the mask → healthy
//! High MSE → traffic deviates from mask signature → DPI compromise detected

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use aivpn_common::mask::MaskProfile;

// ── Configuration ────────────────────────────────────────────────────────────

/// Neural Resonance Module configuration
///
/// `#[serde(default)]` (container level) lets `server.json` override any subset
/// of these via a `"neural"` block; omitted fields fall back to `Default`. This
/// is how operators calibrate thresholds without a rebuild (Part 6) and how the
/// e2e harness forces a rotation (drop `compromised_threshold` /
/// `dpi_gate_threshold` low).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NeuralConfig {
    /// Hidden layer size for baked MLP
    pub hidden_size: usize,

    /// Resonance check interval (seconds)
    pub check_interval_secs: u64,

    /// MSE threshold for compromised mask
    pub compromised_threshold: f32,

    /// MSE threshold for warning
    pub warning_threshold: f32,

    /// Enable anomaly detection
    pub enable_anomaly_detection: bool,

    /// Minimum seconds between mask rotations (0 = no cooldown)
    pub rotation_cooldown_secs: u64,

    /// R2 Phase D — inline ML-DPI "reads-as-tunnel" gate decision threshold.
    /// A per-session packet window whose modelled tunnel-probability exceeds this
    /// trips the SAME mask-rotation path as a neural-MSE compromise (a sibling
    /// signal, see `dpi_gate.rs`). Only consulted when the `neural` cargo feature
    /// is built. Default 0.5: the GBDT is calibrated so masked target-protocol
    /// flows score ~0 and tunnels ~1, so the midpoint is a wide-margin cut.
    /// Lower it to rotate more eagerly (more false positives / churn); raise it
    /// to demand higher confidence before rotating.
    #[serde(default = "default_dpi_gate_threshold")]
    pub dpi_gate_threshold: f32,
}

/// Default decision threshold for the inline ML-DPI gate (R2 Phase D).
fn default_dpi_gate_threshold() -> f32 {
    0.5
}

impl Default for NeuralConfig {
    fn default() -> Self {
        Self {
            hidden_size: 128,
            check_interval_secs: 30,
            // Calibrated (night-sprint B1 / Part 6) against the realcap2
            // real-capture corpora (research/mask-generation/realcap2:
            // real_webrtc_inner.pcap 3978 pkts → 7 WebRTC_STUN masks,
            // real_quicbulk_inner.pcap 6720 pkts → 4 QUIC masks) replayed
            // through every bundled mask's baked encoder exactly as the
            // gateway feeds it (uplink-only, wire size, ciphertext-level
            // entropy, real IATs; see examples/neural_calib.rs). Healthy
            // (uncompromised) traffic measured, 54 385 sliding windows:
            //   webrtc family: mean 0.1894, p99 0.1977, max 0.2026
            //   quic   family: mean 0.2486, p99 0.2600, max 0.2608
            //   overall:       mean 0.2185, p99 0.2598, max 0.2608
            // A live stand additionally observed healthy WebRTC at ~0.31
            // (messier windows than the harness), so margins are taken from
            // that upper anchor, not just the harness p99:
            //   warning     0.35 = live 0.31 + ~13% (log-only signal)
            //   compromised 0.50 = live 0.31 + ~61% / harness p99 + ~92%
            // Cross-family replay (wrong corpus through a mask) lands in the
            // SAME 0.17–0.25 band as matched traffic — the raw MSE of the
            // untrained baked encoder is not an absolute discriminator, so
            // these warm-up defaults exist ONLY to prevent false rotations;
            // genuine compromise detection is the per-mask adaptive
            // calibration (mean + 3σ / + 1.5σ) that takes over after
            // MIN_CALIBRATION_SAMPLES. See calibration_tests below.
            compromised_threshold: 0.50,
            warning_threshold: 0.35,
            enable_anomaly_detection: true,
            rotation_cooldown_secs: 60,
            dpi_gate_threshold: default_dpi_gate_threshold(),
        }
    }
}

// ── Traffic Statistics ───────────────────────────────────────────────────────

/// Traffic statistics for neural analysis
#[derive(Debug, Clone, Default)]
pub struct TrafficStats {
    /// Packet sizes (last N packets)
    pub packet_sizes: VecDeque<u16>,
    /// Inter-arrival times (ms)
    pub inter_arrivals: VecDeque<f64>,
    /// Byte-level entropy samples
    pub entropy_samples: VecDeque<f64>,
    /// Packets per second
    pub pps: f64,
    /// Bytes per second
    pub bps: f64,
    /// Packets received from client (uplink direction)
    pub rx_packets: u64,
    /// Packets sent to client (downlink direction)
    pub tx_packets: u64,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            packet_sizes: VecDeque::with_capacity(256),
            inter_arrivals: VecDeque::with_capacity(256),
            entropy_samples: VecDeque::with_capacity(256),
            pps: 0.0,
            bps: 0.0,
            rx_packets: 0,
            tx_packets: 0,
        }
    }

    /// Add packet sample. `is_rx` = true for client→server (uplink), false for server→client.
    pub fn add_packet(&mut self, size: u16, iat_ms: f64, entropy: f64, is_rx: bool) {
        self.packet_sizes.push_back(size);
        self.inter_arrivals.push_back(iat_ms);
        self.entropy_samples.push_back(entropy);
        if is_rx {
            self.rx_packets += 1;
        } else {
            self.tx_packets += 1;
        }
        // Keep last 256 samples
        if self.packet_sizes.len() > 256 {
            self.packet_sizes.pop_front();
            self.inter_arrivals.pop_front();
            self.entropy_samples.pop_front();
        }
    }

    /// Clear stats
    pub fn clear(&mut self) {
        self.packet_sizes.clear();
        self.inter_arrivals.clear();
        self.entropy_samples.clear();
        self.pps = 0.0;
        self.bps = 0.0;
        self.rx_packets = 0;
        self.tx_packets = 0;
    }
}

// ── Baked Mask Encoder (the tiny neural network) ─────────────────────────────

/// Feature dimension (= mask signature_vector length)
const FEAT_DIM: usize = 64;

/// A tiny MLP whose weights are deterministically "baked" from a mask's
/// 64-float signature_vector.
///
/// Architecture: Linear(64→H) → ReLU → Linear(H→64)
///
/// Weight derivation (fully deterministic, no training needed):
/// - Each weight is seeded by BLAKE3 hash of the signature, ensuring
///   structurally unique encoders per mask.
///
/// Memory: (64*H + H + H*64 + 64) * 4 bytes ≈ 66 KB for H=128
pub struct BakedMaskEncoder {
    w1: Vec<f32>, // [hidden × FEAT_DIM] row-major
    b1: Vec<f32>, // [hidden]
    w2: Vec<f32>, // [FEAT_DIM × hidden] row-major
    b2: Vec<f32>, // [FEAT_DIM]
    hidden: usize,
}

impl BakedMaskEncoder {
    /// Bake an encoder from a mask's signature vector.
    pub fn from_signature(signature: &[f32], hidden: usize) -> Self {
        if signature.len() < FEAT_DIM {
            warn!(
                "mask signature too short ({} < {}) — encoder may be less accurate",
                signature.len(),
                FEAT_DIM
            );
        }

        // Deterministic seed: BLAKE3 hash of the signature serialized as LE f32s.
        // The XOF is expanded to give every weight an independent pseudo-random
        // value — this produces full-rank W1/W2 (the previous scheme made every
        // row a scalar multiple of signature[], collapsing to a rank-1 matrix).
        let sig_bytes: Vec<u8> = signature.iter().flat_map(|f| f.to_le_bytes()).collect();

        let mut w1 = vec![0.0f32; hidden * FEAT_DIM];
        let mut b1 = vec![0.0f32; hidden];
        let mut w2 = vec![0.0f32; FEAT_DIM * hidden];
        let mut b2 = vec![0.0f32; FEAT_DIM];

        let scale = (2.0 / (FEAT_DIM + hidden) as f32).sqrt();
        let total = (hidden * FEAT_DIM + hidden + FEAT_DIM * hidden + FEAT_DIM) * 2;
        let mut xof_buf = vec![0u8; total];
        blake3::Hasher::new()
            .update(&sig_bytes)
            .finalize_xof()
            .fill(&mut xof_buf);
        let mut cur = 0usize;

        for i in 0..hidden {
            for j in 0..FEAT_DIM {
                let v = i16::from_le_bytes([xof_buf[cur], xof_buf[cur + 1]]) as f32;
                w1[i * FEAT_DIM + j] = v / i16::MAX as f32 * scale;
                cur += 2;
            }
            let v = i16::from_le_bytes([xof_buf[cur], xof_buf[cur + 1]]) as f32;
            b1[i] = v / i16::MAX as f32 * 0.01;
            cur += 2;
        }
        for j in 0..FEAT_DIM {
            for i in 0..hidden {
                let v = i16::from_le_bytes([xof_buf[cur], xof_buf[cur + 1]]) as f32;
                w2[j * hidden + i] = v / i16::MAX as f32 * scale;
                cur += 2;
            }
            let v = i16::from_le_bytes([xof_buf[cur], xof_buf[cur + 1]]) as f32;
            b2[j] = v / i16::MAX as f32 * 0.01;
            cur += 2;
        }

        Self {
            w1,
            b1,
            w2,
            b2,
            hidden,
        }
    }

    /// Forward pass: x → Linear → ReLU → Linear → output
    pub fn forward(&self, input: &[f32; FEAT_DIM]) -> [f32; FEAT_DIM] {
        // Layer 1: hidden = ReLU(W1 · input + b1)
        let mut h = vec![0.0f32; self.hidden];
        for i in 0..self.hidden {
            let mut sum = self.b1[i];
            let row = &self.w1[i * FEAT_DIM..(i + 1) * FEAT_DIM];
            for j in 0..FEAT_DIM {
                sum += row[j] * input[j];
            }
            h[i] = sum.max(0.0); // ReLU
        }

        // Layer 2: output = W2 · hidden + b2
        let mut output = [0.0f32; FEAT_DIM];
        for j in 0..FEAT_DIM {
            let mut sum = self.b2[j];
            let row = &self.w2[j * self.hidden..(j + 1) * self.hidden];
            for i in 0..self.hidden {
                sum += row[i] * h[i];
            }
            output[j] = sum;
        }
        output
    }

    /// Reconstruction error (MSE) between input features and reconstruction
    pub fn reconstruction_error(&self, features: &[f32; FEAT_DIM]) -> f32 {
        let recon = self.forward(features);
        let mut mse = 0.0f32;
        for i in 0..FEAT_DIM {
            let diff = features[i] - recon[i];
            mse += diff * diff;
        }
        mse / FEAT_DIM as f32
    }

    /// Memory usage in bytes
    pub fn memory_bytes(&self) -> usize {
        (self.w1.len() + self.b1.len() + self.w2.len() + self.b2.len()) * 4
    }
}

// ── Feature Encoding ─────────────────────────────────────────────────────────

/// Saturation constant for millisecond-scale IAT features: `x / (x + K)`.
/// K = 100 ms puts typical interactive/streaming IATs (1–100 ms) in the
/// steep, discriminative part of the curve while mapping any idle gap
/// (keepalive 8 s, minutes of silence) asymptotically below 1.0.
const IAT_SAT_MS: f64 = 100.0;

/// Saturation constant for tail IAT features (max/min), which previously used
/// a /1000 scale — K = 1000 ms keeps their resolution centred on second-scale
/// gaps while still bounding them below 1.0.
const IAT_TAIL_SAT_MS: f64 = 1000.0;

/// Saturating normalization: maps [0, ∞) → [0, 1). Monotonic, so ordering of
/// inputs is preserved; `k` is the half-way point (x = k → 0.5).
///
/// Rationale (night-sprint B1 / F4): the previous linear /100 and /1000
/// scaling let large-IAT (idle/keepalive) samples produce features of 50–80,
/// which the baked autoencoder can never reconstruct — MSE exploded to ~272
/// and idle traffic read as a false "compromise", while genuine shape
/// anomalies stayed near ~0.29. Saturation keeps every feature block
/// (size histogram, IAT, entropy, temporal) on a comparable [0, 1) scale.
#[inline]
fn saturate(x: f64, k: f64) -> f32 {
    let x = x.max(0.0);
    (x / (x + k)) as f32
}

/// Encode traffic stats into a 64-dim feature vector
pub fn encode_features(stats: &TrafficStats) -> [f32; FEAT_DIM] {
    let mut features = [0.0f32; FEAT_DIM];

    // Block 1 (0–15): Packet size histogram (16 bins)
    if !stats.packet_sizes.is_empty() {
        let bins: [usize; 16] = [
            0, 64, 128, 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 896, 1024, 1280,
        ];
        for &size in &stats.packet_sizes {
            let mut binned = false;
            for j in 0..15 {
                if (size as usize) >= bins[j] && (size as usize) < bins[j + 1] {
                    features[j] += 1.0;
                    binned = true;
                    break;
                }
            }
            if !binned {
                features[15] += 1.0; // sizes >= 1280
            }
        }
        let n = stats.packet_sizes.len() as f32;
        for f in features[0..16].iter_mut() {
            *f /= n;
        }
    }

    // Block 2 (16–31): IAT statistics
    if !stats.inter_arrivals.is_empty() {
        let n = stats.inter_arrivals.len() as f64;
        let mean = stats.inter_arrivals.iter().sum::<f64>() / n;
        let variance = stats
            .inter_arrivals
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / n;
        let std_dev = variance.sqrt();
        let max_val = stats
            .inter_arrivals
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let min_val = stats
            .inter_arrivals
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);

        // Saturating x/(x+K) normalization — see `saturate` docs (F4 fix):
        // idle/large-IAT samples must stay in [0, 1) like every other block.
        features[16] = saturate(mean, IAT_SAT_MS);
        features[17] = saturate(std_dev, IAT_SAT_MS);
        features[18] = saturate(max_val, IAT_TAIL_SAT_MS);
        features[19] = saturate(min_val, IAT_TAIL_SAT_MS);
        // Percentiles
        let mut sorted: Vec<f64> = stats.inter_arrivals.iter().cloned().collect();
        sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        features[20] = saturate(sorted[sorted.len() / 4], IAT_SAT_MS);
        features[21] = saturate(sorted[sorted.len() / 2], IAT_SAT_MS);
        features[22] = saturate(sorted[sorted.len() * 3 / 4], IAT_SAT_MS);
        // Coefficient of variation is dimensionless but unbounded — saturate at K=1
        // (CV = 1, i.e. exponential-like dispersion, maps to 0.5).
        features[23] = if mean > 0.0 {
            saturate(std_dev / mean, 1.0)
        } else {
            0.0
        };

        // Block 2b (24-31): skewness, kurtosis, lag-1 autocorrelation, burst/gap
        // fractions, mean-absolute jitter, p10, p90 — reuses sorted from above.
        if std_dev > 1e-9 {
            let skew = stats
                .inter_arrivals
                .iter()
                .map(|&x| ((x - mean) / std_dev).powi(3))
                .sum::<f64>()
                / n;
            features[24] = (skew / 10.0).clamp(-1.0, 1.0) as f32;
            let kurt = stats
                .inter_arrivals
                .iter()
                .map(|&x| ((x - mean) / std_dev).powi(4))
                .sum::<f64>()
                / n
                - 3.0;
            features[25] = (kurt / 10.0).clamp(-1.0, 1.0) as f32;
        }
        let ns_iat = stats.inter_arrivals.len();
        if ns_iat >= 2 {
            let ac: f64 = stats
                .inter_arrivals
                .iter()
                .zip(stats.inter_arrivals.iter().skip(1))
                .map(|(&a, &b)| (a - mean) * (b - mean))
                .sum::<f64>()
                / (ns_iat - 1) as f64;
            features[26] = (ac / (variance + 1e-9)).clamp(-1.0, 1.0) as f32;
            if mean > 1e-9 {
                let jitter = stats
                    .inter_arrivals
                    .iter()
                    .zip(stats.inter_arrivals.iter().skip(1))
                    .map(|(&a, &b)| (a - b).abs())
                    .sum::<f64>()
                    / (ns_iat - 1) as f64;
                features[29] = (jitter / mean).clamp(0.0, 10.0) as f32 / 10.0;
            }
        }
        features[27] = stats.inter_arrivals.iter().filter(|&&t| t < 2.0).count() as f32 / n as f32;
        features[28] =
            stats.inter_arrivals.iter().filter(|&&t| t > 500.0).count() as f32 / n as f32;
        let ns_s = sorted.len();
        features[30] = saturate(sorted[ns_s / 10], IAT_SAT_MS);
        features[31] = saturate(sorted[(ns_s * 9 / 10).min(ns_s - 1)], IAT_SAT_MS);
    }

    // Block 3 (32–47): Entropy features
    if !stats.entropy_samples.is_empty() {
        let n = stats.entropy_samples.len() as f64;
        let mean = stats.entropy_samples.iter().sum::<f64>() / n;
        let variance = stats
            .entropy_samples
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / n;
        features[32] = (mean / 8.0) as f32;
        features[33] = (variance.sqrt() / 8.0) as f32;
        let max_val = stats
            .entropy_samples
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let min_val = stats
            .entropy_samples
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        features[34] = (max_val / 8.0) as f32;
        features[35] = (min_val / 8.0) as f32;

        // Block 3b (36-47): entropy percentiles, high/low fractions, skewness,
        // lag-1 autocorrelation, trend, IAT-entropy Pearson correlation.
        let mut ent_sorted: Vec<f64> = stats.entropy_samples.iter().cloned().collect();
        ent_sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let ns_e = ent_sorted.len();
        features[36] = (ent_sorted[ns_e / 4] / 8.0) as f32;
        features[37] = (ent_sorted[ns_e / 2] / 8.0) as f32;
        features[38] = (ent_sorted[ns_e * 3 / 4] / 8.0) as f32;
        features[39] = stats.entropy_samples.iter().filter(|&&e| e > 7.5).count() as f32 / n as f32;
        features[40] = stats.entropy_samples.iter().filter(|&&e| e < 4.0).count() as f32 / n as f32;
        if variance > 1e-18 {
            let std_e = variance.sqrt();
            let skew = stats
                .entropy_samples
                .iter()
                .map(|&x| ((x - mean) / std_e).powi(3))
                .sum::<f64>()
                / n;
            features[41] = (skew / 3.0).clamp(-1.0, 1.0) as f32;
            if ns_e >= 2 {
                let ac: f64 = stats
                    .entropy_samples
                    .iter()
                    .zip(stats.entropy_samples.iter().skip(1))
                    .map(|(&a, &b)| (a - mean) * (b - mean))
                    .sum::<f64>()
                    / (ns_e - 1) as f64;
                features[42] = (ac / (variance + 1e-9)).clamp(-1.0, 1.0) as f32;
            }
        }
        if ns_e >= 4 {
            let half = ns_e / 2;
            let first: f64 = stats.entropy_samples.iter().take(half).sum::<f64>() / half as f64;
            let second: f64 =
                stats.entropy_samples.iter().skip(ns_e - half).sum::<f64>() / half as f64;
            features[43] = ((second - first) / 8.0) as f32;
        }
        if !stats.inter_arrivals.is_empty() {
            let m = stats.inter_arrivals.len().min(ns_e);
            let im = stats.inter_arrivals.iter().take(m).sum::<f64>() / m as f64;
            let em = stats.entropy_samples.iter().take(m).sum::<f64>() / m as f64;
            let cov = stats
                .inter_arrivals
                .iter()
                .take(m)
                .zip(stats.entropy_samples.iter().take(m))
                .map(|(&a, &b)| (a - im) * (b - em))
                .sum::<f64>()
                / m as f64;
            let iv = stats
                .inter_arrivals
                .iter()
                .take(m)
                .map(|&a| (a - im).powi(2))
                .sum::<f64>()
                / m as f64;
            let ev = stats
                .entropy_samples
                .iter()
                .take(m)
                .map(|&b| (b - em).powi(2))
                .sum::<f64>()
                / m as f64;
            let denom = (iv * ev).sqrt();
            features[44] = if denom > 1e-9 {
                (cov / denom).clamp(-1.0, 1.0) as f32
            } else {
                0.0
            };
        }
        // [45]: direction ratio — rx/(rx+tx); asymmetric traffic is a GFW/RKN DPI signal
        let total_dir = (stats.rx_packets + stats.tx_packets) as f32;
        features[45] = if total_dir > 0.0 {
            stats.rx_packets as f32 / total_dir
        } else {
            0.5
        };

        // [46-47]: burst features — computed from IAT (burst = consecutive IATs < 5 ms)
        // GFW/RKN DPI detects "data burst + silence" patterns typical of tunneled traffic.
        if !stats.inter_arrivals.is_empty() {
            let burst_thresh = 5.0_f64;
            let mut burst_count = 0u32;
            let mut total_burst_pkts = 0u32;
            let mut in_burst = false;
            for &iat in &stats.inter_arrivals {
                if iat < burst_thresh {
                    if !in_burst {
                        burst_count += 1;
                        in_burst = true;
                    }
                    total_burst_pkts += 1;
                } else {
                    in_burst = false;
                }
            }
            let n_iat = stats.inter_arrivals.len() as f32;
            // Burst frequency: bursts per packet (normalized)
            features[46] = burst_count as f32 / n_iat;
            // Mean burst length, normalized to [0, 1] with ceiling of 20 packets
            features[47] = if burst_count > 0 {
                (total_burst_pkts as f32 / burst_count as f32 / 20.0).min(1.0)
            } else {
                0.0
            };
        }
    }

    // Block 4 (48–63): Temporal features
    // pps/bps are unbounded rates — saturate so a burst cannot push these
    // features outside [0, 1) (K = previous linear scale: 1000 pps / 1 MB/s).
    features[48] = saturate(stats.pps, 1000.0);
    features[49] = saturate(stats.bps, 1_000_000.0);
    if !stats.packet_sizes.is_empty() {
        let n = stats.packet_sizes.len() as f32;
        let mean_size: f32 = stats.packet_sizes.iter().map(|&s| s as f32).sum::<f32>() / n;
        // Size features: /1500 (MTU) linear scale, clamped — jumbo/fragmented
        // sizes (u16 up to 65535) must not escape the [0, 1] feature range.
        features[50] = (mean_size / 1500.0).min(1.0);
        let var: f32 = stats
            .packet_sizes
            .iter()
            .map(|&s| (s as f32 - mean_size).powi(2))
            .sum::<f32>()
            / n;
        features[51] = (var.sqrt() / 1500.0).min(1.0);
    }

    // Block 4b (52-63): packet size fractions, adjacent-size variation,
    // size percentiles (p10/p25/p75/p90), timing regularity index,
    // interactive-range IAT fraction, throughput proxy.
    if !stats.packet_sizes.is_empty() {
        let n = stats.packet_sizes.len() as f32;
        features[52] = stats.packet_sizes.iter().filter(|&&s| s > 1000).count() as f32 / n;
        features[53] = stats.packet_sizes.iter().filter(|&&s| s < 100).count() as f32 / n;
        features[54] = (1.0 - features[52] - features[53]).max(0.0);
        let ns_ps = stats.packet_sizes.len();
        if ns_ps >= 2 {
            features[55] = (stats
                .packet_sizes
                .iter()
                .zip(stats.packet_sizes.iter().skip(1))
                .map(|(&a, &b)| (a as f32 - b as f32).abs() / 1500.0)
                .sum::<f32>()
                / (ns_ps - 1) as f32)
                .min(1.0);
        }
        let mut sz_sorted: Vec<f32> = stats.packet_sizes.iter().map(|&s| s as f32).collect();
        sz_sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let ns_sz = sz_sorted.len();
        features[56] = (sz_sorted[ns_sz / 10] / 1500.0).min(1.0);
        features[57] = (sz_sorted[ns_sz / 4] / 1500.0).min(1.0);
        features[58] = (sz_sorted[ns_sz * 3 / 4] / 1500.0).min(1.0);
        features[59] = (sz_sorted[(ns_sz * 9 / 10).min(ns_sz - 1)] / 1500.0).min(1.0);
    }
    if !stats.inter_arrivals.is_empty() {
        let n = stats.inter_arrivals.len() as f64;
        let mean = stats.inter_arrivals.iter().sum::<f64>() / n;
        let variance = stats
            .inter_arrivals
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / n;
        if mean > 1e-9 {
            features[60] = (1.0 - variance.sqrt() / mean).clamp(0.0, 1.0) as f32;
        }
        // Fraction of IATs in the 10–100 ms range (interactive traffic indicator)
        features[61] = stats
            .inter_arrivals
            .iter()
            .filter(|&&t| (10.0..=100.0).contains(&t))
            .count() as f32
            / n as f32;
        if !stats.packet_sizes.is_empty() {
            let mean_sz = stats.packet_sizes.iter().map(|&s| s as f32).sum::<f32>()
                / stats.packet_sizes.len() as f32;
            features[62] = (stats.pps as f32 * mean_sz / 1_000_000.0).clamp(0.0, 1.0);
        }
        // [63]: timing periodicity index — fraction of IATs within ±20% of the median.
        // High periodicity (many IATs clustered near one value) indicates a heartbeat
        // pattern that GFW/RKN DPI can fingerprint as a tunnel keepalive.
        if !stats.inter_arrivals.is_empty() {
            let mut sorted_p: Vec<f64> = stats.inter_arrivals.iter().cloned().collect();
            sorted_p.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let median = sorted_p[sorted_p.len() / 2];
            if median > 1.0 {
                let lo = median * 0.8;
                let hi = median * 1.2;
                let near = stats
                    .inter_arrivals
                    .iter()
                    .filter(|&&t| t >= lo && t <= hi)
                    .count();
                features[63] = near as f32 / stats.inter_arrivals.len() as f32;
            }
        }
    }

    features
}

// ── Per-mask MSE Auto-calibration ────────────────────────────────────────────

/// Minimum samples before the adaptive threshold is used instead of the
/// configured default.  500 packets ≈ a few seconds of typical VPN traffic.
const MIN_CALIBRATION_SAMPLES: u64 = 500;

/// Minimum packet samples in the current window before an MSE is trusted at all
/// (B1). The 64-float feature vector (16-bin size histogram, IAT/entropy
/// percentiles) is only meaningful with enough packets; a near-idle window of a
/// handful of keepalives yields a degenerate vector whose reconstruction error
/// (~0.28 on the live stand, ABOVE a genuine shape anomaly at ~0.25) is noise,
/// not a DPI signal. Below this floor `check_resonance` skips entirely — it
/// neither raises an anomaly nor feeds the sample into the per-mask calibration
/// baseline, so idle traffic can neither false-trigger nor desensitize the
/// shared threshold for active clients on the same mask.
const MIN_SAMPLES_FOR_CHECK: usize = 32;

/// Running MSE statistics for one mask, using Welford's online algorithm for
/// numerically stable mean and variance without storing raw samples.
#[derive(Debug, Default)]
struct MaskCalibration {
    count: u64,
    mean: f64,
    m2: f64,
}

/// Absolute ceiling applied to an MSE sample BEFORE it feeds the per-mask
/// calibration baseline. Healthy same-mask traffic reconstructs at MSE ~0.1–0.3;
/// this cap is far above that but bounds pathological inputs (e.g. an
/// unnormalized large-IAT sample) so one observation cannot blow up the running
/// mean/σ. Detection still uses the RAW mse, so genuine high-MSE compromise is
/// unaffected — only the *baseline* is protected.
const CALIBRATION_SAMPLE_CEILING: f64 = 2.0;

/// Once the baseline is established, an MSE more than this many σ above the mean
/// is treated as an anomaly to DETECT, not a sample to CALIBRATE on. Without this
/// a client with a valid PSK could stream deliberately anomalous traffic to
/// inflate the shared per-mask threshold and desensitize DPI-compromise
/// detection for every other client on that mask (a cross-tenant safeguard
/// bypass). 8σ is permissive enough that ordinary traffic variance never trips it.
const CALIBRATION_OUTLIER_SIGMA: f64 = 8.0;

impl MaskCalibration {
    fn update(&mut self, mse: f32) {
        // Reject gross outliers from the baseline once it is established, so an
        // adversarial session cannot steer the shared threshold (poisoning).
        if self.count >= MIN_CALIBRATION_SAMPLES {
            let s = self.std_dev();
            if s > 0.0 && (mse as f64) > self.mean + CALIBRATION_OUTLIER_SIGMA * s {
                return;
            }
        }
        // Bound any single sample's magnitude so a pathological value cannot
        // dominate the running statistics (also caps early-warmup poisoning).
        let x = (mse as f64).clamp(0.0, CALIBRATION_SAMPLE_CEILING);
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        self.m2 += delta * (x - self.mean);
    }

    fn std_dev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        (self.m2 / (self.count - 1) as f64).sqrt()
    }

    /// Returns `(compromised, warning)` adaptive thresholds once enough
    /// samples are collected:
    ///   compromised = mean + 3σ
    ///   warning     = mean + 1.5σ
    fn adaptive_thresholds(&self) -> Option<(f32, f32)> {
        if self.count < MIN_CALIBRATION_SAMPLES {
            return None;
        }
        let s = self.std_dev();
        Some(((self.mean + 3.0 * s) as f32, (self.mean + 1.5 * s) as f32))
    }
}

// ── Anomaly Detector ─────────────────────────────────────────────────────────

/// Minimum number of DISTINCT authenticated reporters that must each observe an
/// anomalous sample before a client-telemetry-driven anomaly is believed. The
/// telemetry that feeds this detector is client-reported (`TelemetryResponse`),
/// so without corroboration a single authenticated client could push forged
/// packet-loss/RTT to mark a shared mask compromised for everyone — a
/// cross-tenant DoS. Server-MEASURED compromise (neural resonance MSE) is a
/// separate, trusted path and is unaffected by this gate.
const MIN_ANOMALY_REPORTERS: usize = 3;

/// Anomaly detector for DPI fingerprinting
pub struct AnomalyDetector {
    mask_packet_loss: HashMap<String, VecDeque<f64>>,
    mask_rtt: HashMap<String, VecDeque<f64>>,
    /// Distinct reporters (session ids) that submitted an anomalous sample for
    /// each mask. Gates `is_anomalous` so one client cannot forge a compromise.
    anomalous_reporters: HashMap<String, HashSet<[u8; 16]>>,
    baseline_loss: f64,
    baseline_rtt: f64,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            mask_packet_loss: HashMap::new(),
            mask_rtt: HashMap::new(),
            anomalous_reporters: HashMap::new(),
            baseline_loss: 0.01,
            baseline_rtt: 50.0,
        }
    }

    pub fn record_metrics(
        &mut self,
        mask_id: &str,
        reporter: [u8; 16],
        packet_loss: f64,
        rtt_ms: f64,
    ) {
        let losses = self
            .mask_packet_loss
            .entry(mask_id.to_string())
            .or_default();
        losses.push_back(packet_loss);
        if losses.len() > 100 {
            losses.pop_front();
        }

        let rtts = self.mask_rtt.entry(mask_id.to_string()).or_default();
        rtts.push_back(rtt_ms);
        if rtts.len() > 100 {
            rtts.pop_front();
        }

        // If THIS reporter's own sample looks anomalous, count it toward the
        // distinct-reporter corroboration set (bounded so it can't grow without
        // limit under a flood of spoofed-but-authenticated sessions).
        if packet_loss > self.baseline_loss * 5.0 || rtt_ms > self.baseline_rtt * 3.0 {
            let reporters = self
                .anomalous_reporters
                .entry(mask_id.to_string())
                .or_default();
            if reporters.len() < 256 {
                reporters.insert(reporter);
            }
        }
    }

    pub fn is_anomalous(&self, mask_id: &str) -> bool {
        // Require corroboration from multiple distinct reporters — one client's
        // telemetry alone must never mark a shared mask compromised.
        let distinct_reporters = self
            .anomalous_reporters
            .get(mask_id)
            .map(|r| r.len())
            .unwrap_or(0);
        if distinct_reporters < MIN_ANOMALY_REPORTERS {
            return false;
        }

        if let Some(losses) = self.mask_packet_loss.get(mask_id) {
            if losses.len() >= 10 {
                let avg = losses.iter().sum::<f64>() / losses.len() as f64;
                if avg > self.baseline_loss * 5.0 {
                    return true;
                }
            }
        }
        if let Some(rtts) = self.mask_rtt.get(mask_id) {
            if rtts.len() >= 10 {
                let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
                if avg > self.baseline_rtt * 3.0 {
                    return true;
                }
            }
        }
        false
    }

    /// Clear anomaly state for a mask after it has been rotated away from, so a
    /// stale reporter set can't re-trigger on a mask that's no longer active.
    pub fn clear_mask(&mut self, mask_id: &str) {
        self.mask_packet_loss.remove(mask_id);
        self.mask_rtt.remove(mask_id);
        self.anomalous_reporters.remove(mask_id);
    }
}

// ── Neural Resonance Module ──────────────────────────────────────────────────

/// Neural Resonance Module
///
/// Uses Baked Mask Encoders instead of an external LLM.
/// Each mask's signature_vector is baked into a tiny MLP (~66KB).
/// Total memory: O(num_masks * 66KB) — fits any VPS.
pub struct NeuralResonanceModule {
    config: NeuralConfig,

    /// Baked encoders per mask (mask_id -> encoder)
    encoders: HashMap<String, BakedMaskEncoder>,

    /// Per-session traffic stats
    session_stats: dashmap::DashMap<[u8; 16], TrafficStats>,

    /// Anomaly detection state
    anomaly_detector: AnomalyDetector,

    /// Per-mask MSE calibration (auto-updates adaptive threshold)
    mask_calibration: dashmap::DashMap<String, MaskCalibration>,

    /// Per-mask last rotation timestamp — enforces rotation_cooldown_secs
    last_rotation_time: dashmap::DashMap<String, Instant>,

    /// FIFO of mask_ids baked ON DEMAND via `ensure_encoder` (per-session
    /// bootstrap/polymorphic variants), oldest first. The static mask-dir
    /// catalog registered at startup via `register_mask` is NOT tracked here and
    /// is never evicted. Bounds `encoders`/`mask_calibration` growth: dynamic
    /// variant ids are session-unique (e.g. `polymorphic:{base}:{prng-derived}`),
    /// so an attacker reconnecting repeatedly under `polymorphic_all_sessions`
    /// would otherwise grow both maps without bound (~66 KB/encoder).
    dynamic_encoder_ids: VecDeque<String>,

    /// Whether the module is loaded
    loaded: bool,
}

/// Cap on ON-DEMAND (bootstrap/polymorphic) baked encoders kept in memory.
/// ~66 KB each → ≤ ~34 MB. The static mask-dir catalog is separate and uncapped.
const MAX_DYNAMIC_ENCODERS: usize = 512;

/// Resonance check result
#[derive(Debug, Clone)]
pub struct ResonanceResult {
    pub mse: f32,
    pub status: ResonanceStatus,
    pub message: Option<String>,
}

impl ResonanceResult {
    fn skip(msg: &str) -> Self {
        Self {
            mse: 0.0,
            status: ResonanceStatus::Skip,
            message: Some(msg.to_string()),
        }
    }
}

/// Resonance status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResonanceStatus {
    Healthy,
    Warning,
    Compromised,
    Skip,
}

impl NeuralResonanceModule {
    /// Create new neural module
    pub fn new(config: NeuralConfig) -> Result<Self, String> {
        Ok(Self {
            config,
            encoders: HashMap::new(),
            session_stats: dashmap::DashMap::new(),
            anomaly_detector: AnomalyDetector::new(),
            mask_calibration: dashmap::DashMap::new(),
            last_rotation_time: dashmap::DashMap::new(),
            dynamic_encoder_ids: VecDeque::new(),
            loaded: false,
        })
    }

    /// Load model (marks as ready — no external model files needed)
    pub fn load_model(&mut self) -> Result<(), String> {
        self.loaded = true;
        info!(
            "Baked Mask Encoder ready (hidden={}, ~{}KB per mask)",
            self.config.hidden_size,
            (FEAT_DIM * self.config.hidden_size * 2 + self.config.hidden_size + FEAT_DIM) * 4
                / 1024
        );
        Ok(())
    }

    /// Register mask — bakes its signature into a dedicated MLP encoder
    /// True if a baked encoder already exists for this mask id.
    pub fn has_encoder(&self, mask_id: &str) -> bool {
        self.encoders.contains_key(mask_id)
    }

    /// Bake an encoder for `mask` only if one is not already registered. Used by
    /// the resonance loop to cover per-session bootstrap/polymorphic masks whose
    /// dynamically-derived `mask_id` is not among the static mask-dir encoders
    /// baked at startup — without which the neural check is inert for any session
    /// on such a mask (i.e. the common case).
    pub fn ensure_encoder(&mut self, mask: &MaskProfile) -> Result<(), String> {
        if self.encoders.contains_key(&mask.mask_id) {
            return Ok(());
        }
        self.register_mask(mask)?;
        // Track this on-demand encoder and evict the oldest ones past the cap so
        // session-unique dynamic mask_ids can't grow memory without bound. Static
        // catalog encoders never enter this deque, so they are never evicted.
        self.dynamic_encoder_ids.push_back(mask.mask_id.clone());
        while self.dynamic_encoder_ids.len() > MAX_DYNAMIC_ENCODERS {
            if let Some(old) = self.dynamic_encoder_ids.pop_front() {
                self.encoders.remove(&old);
                self.mask_calibration.remove(&old);
                self.last_rotation_time.remove(&old);
            }
        }
        Ok(())
    }

    pub fn register_mask(&mut self, mask: &MaskProfile) -> Result<(), String> {
        if mask.signature_vector.len() < FEAT_DIM {
            return Err(format!(
                "Mask '{}' signature_vector too short: {} < {}",
                mask.mask_id,
                mask.signature_vector.len(),
                FEAT_DIM
            ));
        }
        let encoder =
            BakedMaskEncoder::from_signature(&mask.signature_vector, self.config.hidden_size);
        debug!(
            "Baked encoder for mask '{}' ({} bytes)",
            mask.mask_id,
            encoder.memory_bytes()
        );
        self.encoders.insert(mask.mask_id.clone(), encoder);
        Ok(())
    }

    /// Record traffic sample for session.
    /// `is_rx` = true for client→server packets, false for server→client.
    pub fn record_traffic(
        &self,
        session_id: [u8; 16],
        packet_size: u16,
        iat_ms: f64,
        entropy: f64,
        is_rx: bool,
    ) {
        if let Some(mut stats) = self.session_stats.get_mut(&session_id) {
            stats.add_packet(packet_size, iat_ms, entropy, is_rx);
        } else {
            let mut stats = TrafficStats::new();
            stats.add_packet(packet_size, iat_ms, entropy, is_rx);
            self.session_stats.insert(session_id, stats);
        }
    }

    /// Returns true if enough time has passed since the last rotation for this mask.
    pub fn can_rotate(&self, mask_id: &str) -> bool {
        let cooldown = Duration::from_secs(self.config.rotation_cooldown_secs);
        if cooldown.is_zero() {
            return true;
        }
        self.last_rotation_time
            .get(mask_id)
            .map(|t| t.elapsed() >= cooldown)
            .unwrap_or(true)
    }

    /// Record that a rotation was triggered for this mask (starts the cooldown).
    pub fn record_rotation(&self, mask_id: &str) {
        self.last_rotation_time
            .insert(mask_id.to_string(), Instant::now());
    }

    /// Perform resonance check (Patent 1: Signal Reconstruction Resonance)
    ///
    /// Encodes live traffic into a 64-dim feature vector, passes it through
    /// the mask's baked encoder, and computes reconstruction MSE.
    pub fn check_resonance(
        &self,
        session_id: [u8; 16],
        mask_id: &str,
    ) -> Result<ResonanceResult, String> {
        if !self.loaded {
            return Ok(ResonanceResult::skip("Model not loaded"));
        }

        let Some(stats) = self.session_stats.get(&session_id) else {
            return Ok(ResonanceResult::skip("No traffic stats"));
        };

        let Some(encoder) = self.encoders.get(mask_id) else {
            return Ok(ResonanceResult::skip("Mask encoder not found"));
        };

        // B1: too few packets → the feature vector is degenerate and its MSE is
        // noise. Skip WITHOUT calibrating so idle windows neither false-trigger
        // nor poison the per-mask baseline.
        if stats.packet_sizes.len() < MIN_SAMPLES_FOR_CHECK {
            return Ok(ResonanceResult::skip(
                "Insufficient samples for reliable MSE",
            ));
        }

        let features = encode_features(&stats);
        let mse = encoder.reconstruction_error(&features);

        // Update per-mask calibration and log when it first completes.
        {
            let mut cal = self
                .mask_calibration
                .entry(mask_id.to_string())
                .or_default();
            cal.update(mse);
            if cal.count == MIN_CALIBRATION_SAMPLES {
                if let Some((comp, warn)) = cal.adaptive_thresholds() {
                    info!(
                        "neural: mask '{}' calibrated — compromised={:.4} warning={:.4} (n={})",
                        mask_id, comp, warn, cal.count
                    );
                }
            }
        }

        // Use adaptive thresholds once calibrated; fall back to config values.
        let (comp_thresh, warn_thresh) = self
            .mask_calibration
            .get(mask_id)
            .and_then(|c| c.adaptive_thresholds())
            .unwrap_or((
                self.config.compromised_threshold,
                self.config.warning_threshold,
            ));

        let status = if mse > comp_thresh {
            ResonanceStatus::Compromised
        } else if mse > warn_thresh {
            ResonanceStatus::Warning
        } else {
            ResonanceStatus::Healthy
        };

        Ok(ResonanceResult {
            mse,
            status,
            message: None,
        })
    }

    /// Record client-reported telemetry for anomaly detection. `reporter` is the
    /// authenticated session id, used to require multi-reporter corroboration
    /// before a client-driven anomaly is believed (anti-DoS).
    pub fn record_telemetry(
        &mut self,
        mask_id: &str,
        reporter: [u8; 16],
        packet_loss: f64,
        rtt_ms: f64,
    ) {
        if self.config.enable_anomaly_detection {
            self.anomaly_detector
                .record_metrics(mask_id, reporter, packet_loss, rtt_ms);
        }
    }

    /// Check if mask is anomalous (possible DPI blocking)
    pub fn is_mask_anomalous(&self, mask_id: &str) -> bool {
        self.anomaly_detector.is_anomalous(mask_id)
    }

    /// Clear anomaly state for a rotated-away mask (see `AnomalyDetector::clear_mask`).
    pub fn clear_mask_anomaly(&mut self, mask_id: &str) {
        self.anomaly_detector.clear_mask(mask_id);
    }

    /// Get or create session stats
    pub fn get_or_create_stats(&self, session_id: [u8; 16]) -> TrafficStats {
        self.session_stats
            .entry(session_id)
            .or_insert_with(TrafficStats::new)
            .clone()
    }

    /// Cleanup old session stats
    pub fn cleanup_stats(&self, session_id: [u8; 16]) {
        self.session_stats.remove(&session_id);
    }

    /// Total memory usage for all baked encoders
    pub fn total_memory_bytes(&self) -> usize {
        self.encoders.values().map(|e| e.memory_bytes()).sum()
    }

    /// Number of registered mask encoders
    pub fn encoder_count(&self) -> usize {
        self.encoders.len()
    }

    /// Calibration status for a mask: `(samples_seen, mean_mse, adaptive_threshold)`.
    /// Returns `None` if no data yet.  `adaptive_threshold` is 0.0 until
    /// MIN_CALIBRATION_SAMPLES are collected (config default is used until then).
    pub fn calibration_status(&self, mask_id: &str) -> Option<(u64, f32, f32)> {
        self.mask_calibration.get(mask_id).map(|c| {
            let thresh = c.adaptive_thresholds().map(|(t, _)| t).unwrap_or(0.0);
            (c.count, c.mean as f32, thresh)
        })
    }
}

#[cfg(test)]
mod calibration_tests {
    //! Warm-up-threshold calibration guard (night-sprint B1 / Part 6).
    //!
    //! Replays the realcap2 real-capture corpora through every bundled mask's
    //! baked encoder the way the gateway does and asserts healthy traffic
    //! never crosses the default `compromised_threshold` — i.e. normal
    //! traffic cannot false-trigger a mask rotation during the warm-up
    //! window (before per-mask adaptive calibration takes over).
    //!
    //! The corpora live under `research/` which is gitignored; the test
    //! self-skips when they are absent (e.g. in CI) so it only guards
    //! machines that actually hold the capture data.

    use super::*;
    use std::path::{Path, PathBuf};

    /// Minimal libpcap reader → (orig_len, ts_ns) per record. Supports the
    /// classic µs and ns magics in either byte order (realcap2 files are
    /// LE-µs, linktype 101 = RAW IP, so orig_len is the inner IP size).
    fn read_pcap_sizes(path: &Path) -> Option<Vec<(u32, u64)>> {
        let data = std::fs::read(path).ok()?;
        if data.len() < 24 {
            return None;
        }
        let (be, nanos) = match &data[0..4] {
            [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
            [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
            [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
            [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
            _ => return None,
        };
        let rd32 = |b: &[u8]| -> u32 {
            if be {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }
        };
        let mut out = Vec::new();
        let mut off = 24usize;
        while off + 16 <= data.len() {
            let ts_sec = rd32(&data[off..off + 4]) as u64;
            let ts_frac = rd32(&data[off + 4..off + 8]) as u64;
            let incl = rd32(&data[off + 8..off + 12]) as usize;
            let orig = rd32(&data[off + 12..off + 16]);
            off += 16;
            if off + incl > data.len() {
                break;
            }
            let ts_ns = ts_sec * 1_000_000_000 + if nanos { ts_frac } else { ts_frac * 1_000 };
            out.push((orig, ts_ns));
            off += incl;
        }
        Some(out)
    }

    /// Deterministic stand-in for encrypted-payload Shannon entropy: the
    /// gateway measures `compute_entropy(encrypted_payload)`; ciphertext is
    /// indistinguishable from uniform random bytes, so BLAKE3-XOF bytes of
    /// the same length reproduce the size-dependent entropy curve.
    fn ciphertext_entropy(pkt_index: u64, len: usize) -> f64 {
        if len == 0 {
            return 0.0;
        }
        let mut buf = vec![0u8; len];
        blake3::Hasher::new()
            .update(b"neural-calib-entropy")
            .update(&pkt_index.to_le_bytes())
            .finalize_xof()
            .fill(&mut buf);
        let mut counts = [0u32; 256];
        for &b in &buf {
            counts[b as usize] += 1;
        }
        let n = len as f64;
        let mut h = 0.0f64;
        for &c in counts.iter() {
            if c > 0 {
                let p = c as f64 / n;
                h -= p * p.log2();
            }
        }
        h
    }

    /// Representative tunnel wire overhead over the inner IP packet: mask MDH
    /// header (14–20 B) + pad_len(1) + inner header(4) + Poly1305 tag(16).
    const WIRE_OVERHEAD: u16 = 40;

    #[test]
    fn realcap_healthy_traffic_stays_below_compromised_threshold() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let realcap = root.join("research/mask-generation/realcap2");
        let masks_dir = root.join("assets/masks");

        let Some(webrtc) = read_pcap_sizes(&realcap.join("real_webrtc_inner.pcap")) else {
            eprintln!("realcap2 corpus not present — skipping calibration guard");
            return;
        };
        let Some(quic) = read_pcap_sizes(&realcap.join("real_quicbulk_inner.pcap")) else {
            eprintln!("realcap2 corpus not present — skipping calibration guard");
            return;
        };
        assert!(webrtc.len() > 1000 && quic.len() > 1000, "corpus too small");

        let cfg = NeuralConfig::default();
        let mut checked_masks = 0usize;
        for entry in std::fs::read_dir(&masks_dir).expect("assets/masks") {
            let path = entry.expect("dir entry").path();
            if path.extension().map(|x| x != "json").unwrap_or(true) {
                continue;
            }
            let mask: MaskProfile =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("read mask"))
                    .expect("parse bundled mask");
            let corpus = match mask.spoof_protocol {
                aivpn_common::mask::SpoofProtocol::WebRTC_STUN => &webrtc,
                aivpn_common::mask::SpoofProtocol::QUIC => &quic,
                _ => continue,
            };
            let encoder = BakedMaskEncoder::from_signature(&mask.signature_vector, cfg.hidden_size);

            let mut stats = TrafficStats::new();
            let mut prev_ns: Option<u64> = None;
            let mut max_mse = 0.0f32;
            let mut windows = 0usize;
            for (i, (orig, ts_ns)) in corpus.iter().enumerate() {
                let iat_ms = match prev_ns {
                    Some(p) if *ts_ns >= p => (*ts_ns - p) as f64 / 1_000_000.0,
                    _ => 0.0,
                };
                prev_ns = Some(*ts_ns);
                let wire_size =
                    (*orig).min(u16::MAX as u32 - WIRE_OVERHEAD as u32) as u16 + WIRE_OVERHEAD;
                let entropy = ciphertext_entropy(i as u64, wire_size as usize);
                // Gateway feeds uplink only (is_rx = true) into neural stats.
                stats.add_packet(wire_size, iat_ms, entropy, true);
                // Evaluate on a stride to keep the debug-mode test fast; the
                // full-resolution distribution is examples/neural_calib.rs.
                if stats.packet_sizes.len() >= MIN_SAMPLES_FOR_CHECK && i % 16 == 0 {
                    let mse = encoder.reconstruction_error(&encode_features(&stats));
                    max_mse = max_mse.max(mse);
                    windows += 1;
                    assert!(
                        mse < cfg.compromised_threshold,
                        "mask '{}': healthy realcap window #{i} MSE {mse:.4} >= \
                         compromised_threshold {} — warm-up default would \
                         false-trigger a rotation on normal traffic",
                        mask.mask_id,
                        cfg.compromised_threshold
                    );
                }
            }
            assert!(
                windows > 0,
                "mask '{}' produced no MSE windows",
                mask.mask_id
            );
            // The warm-up warning threshold should also clear the healthy max
            // (warnings are log-only, but a constantly-warning healthy stream
            // means the default is miscalibrated).
            assert!(
                max_mse < cfg.warning_threshold,
                "mask '{}': healthy max MSE {max_mse:.4} >= warning_threshold {}",
                mask.mask_id,
                cfg.warning_threshold
            );
            checked_masks += 1;
        }
        assert!(
            checked_masks >= 10,
            "expected to check the bundled mask set, got {checked_masks}"
        );
    }
}

#[cfg(test)]
mod anomaly_tests {
    use super::AnomalyDetector;

    #[test]
    fn single_reporter_cannot_forge_anomaly() {
        let mut det = AnomalyDetector::new();
        let attacker = [1u8; 16];
        // One reporter floods 50 high-loss samples for a mask.
        for _ in 0..50 {
            det.record_metrics("webrtc_zoom_v3", attacker, 0.9, 500.0);
        }
        // Aggregate is way over threshold, but only ONE distinct reporter →
        // must NOT be treated as anomalous (anti cross-tenant DoS).
        assert!(!det.is_anomalous("webrtc_zoom_v3"));
    }

    #[test]
    fn corroborated_anomaly_is_detected() {
        let mut det = AnomalyDetector::new();
        // Three distinct reporters each observe sustained loss.
        for r in 0u8..3 {
            let reporter = [r; 16];
            for _ in 0..10 {
                det.record_metrics("quic_https_v2", reporter, 0.9, 500.0);
            }
        }
        assert!(det.is_anomalous("quic_https_v2"));
    }

    #[test]
    fn clear_mask_resets_state() {
        let mut det = AnomalyDetector::new();
        for r in 0u8..3 {
            for _ in 0..10 {
                det.record_metrics("m", [r; 16], 0.9, 500.0);
            }
        }
        assert!(det.is_anomalous("m"));
        det.clear_mask("m");
        assert!(!det.is_anomalous("m"));
    }
}
