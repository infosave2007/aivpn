//! Deterministic 1-D Gaussian-Mixture-Model fitter (EM + BIC model selection).
//!
//! This is the production bridge for the design-doc §4 R&D result: the
//! `research/mask-generation/phase2b` study proved that a BIC-selected Gaussian
//! mixture reproduces real per-protocol packet-size / inter-arrival marginals
//! *far* better than the single-Gaussian (unimodal) model milestone-1 used
//! (KS distance cut 43–89 % across DNS / QUIC / WebRTC).  `mask_gen` calls
//! [`select_best_bic`] on the recorded size and IAT marginals; when the data is
//! multimodal it emits a compact parametric GMM into the `MaskProfile` instead
//! of a large empirical bin/quantile table.  The mixture is resample-able,
//! generalises to unseen-but-plausible values (an empirical replay cannot), and
//! lets the mask FSM signal which behavioural mode is active.
//!
//! The fit is **fully deterministic** (quantile-seeded init, no RNG) so a mask
//! generated from the same recording is byte-reproducible — important because
//! masks are distributed and may be signed.

/// A fitted 1-D Gaussian mixture: `k` components each `(weight, mean, var)`.
#[derive(Debug, Clone)]
pub struct Gmm1d {
    pub weights: Vec<f64>,
    pub means: Vec<f64>,
    pub vars: Vec<f64>,
    /// Total log-likelihood of the training data under this fit.
    pub loglik: f64,
    /// Bayesian Information Criterion (lower is better).
    pub bic: f64,
    /// Number of training points.
    pub n: usize,
}

impl Gmm1d {
    pub fn k(&self) -> usize {
        self.weights.len()
    }

    /// Encode as the flat `[k, w0, mu0, sigma0, w1, mu1, sigma1, ...]` layout
    /// consumed by `aivpn_common::mask` GMM samplers (sigma = sqrt(var)).
    ///
    /// Components whose weight falls below `min_weight` (numerically dead modes,
    /// mirroring phase2b's 2 %-effective-K filter) are dropped and the remaining
    /// weights renormalised.  Returns `None` if that leaves fewer than 2 real
    /// components — the caller should then keep the unimodal representation.
    pub fn to_flat_params(&self, min_weight: f64) -> Option<Vec<f64>> {
        let mut comps: Vec<(f64, f64, f64)> = self
            .weights
            .iter()
            .zip(&self.means)
            .zip(&self.vars)
            .filter(|((w, _), _)| **w >= min_weight)
            .map(|((w, m), v)| (*w, *m, v.max(1e-12).sqrt()))
            .collect();
        if comps.len() < 2 {
            return None;
        }
        // Renormalise surviving weights to sum to 1.
        let wsum: f64 = comps.iter().map(|(w, _, _)| *w).sum();
        if wsum <= 0.0 || !wsum.is_finite() {
            return None;
        }
        for c in &mut comps {
            c.0 /= wsum;
        }
        let mut flat = Vec::with_capacity(1 + comps.len() * 3);
        flat.push(comps.len() as f64);
        for (w, m, s) in comps {
            flat.push(w);
            flat.push(m);
            flat.push(s);
        }
        Some(flat)
    }
}

const MAX_ITER: usize = 200;
const CONVERGENCE_TOL: f64 = 1e-6;

fn gaussian_pdf(x: f64, mean: f64, var: f64) -> f64 {
    let d = x - mean;
    (-(d * d) / (2.0 * var)).exp() / (2.0 * std::f64::consts::PI * var).sqrt()
}

/// Fit a `k`-component 1-D GMM to `data` via EM.  Deterministic:
/// means are seeded at evenly-spaced quantiles of the sorted data.
/// `var_floor` prevents a component collapsing onto a single point.
fn fit_k(data: &[f64], sorted: &[f64], k: usize, var_floor: f64) -> Gmm1d {
    let n = data.len();
    let nf = n as f64;

    // Deterministic quantile-seeded init.
    let mut means = vec![0.0; k];
    for (c, m) in means.iter_mut().enumerate() {
        let q = (c as f64 + 0.5) / k as f64;
        let idx = ((q * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
        *m = sorted[idx];
    }
    let global_mean = data.iter().sum::<f64>() / nf;
    let global_var =
        (data.iter().map(|x| (x - global_mean).powi(2)).sum::<f64>() / nf).max(var_floor);
    let mut vars = vec![global_var; k];
    let mut weights = vec![1.0 / k as f64; k];

    let mut resp = vec![0.0f64; n * k]; // row-major [i*k + c]
    let mut prev_loglik = f64::NEG_INFINITY;
    let mut loglik = f64::NEG_INFINITY;

    for _ in 0..MAX_ITER {
        // E-step + running log-likelihood.
        loglik = 0.0;
        for i in 0..n {
            let x = data[i];
            let mut row_sum = 0.0;
            for c in 0..k {
                let p = weights[c] * gaussian_pdf(x, means[c], vars[c]);
                resp[i * k + c] = p;
                row_sum += p;
            }
            if row_sum <= 0.0 || !row_sum.is_finite() {
                // Point is astronomically far from every component; assign it
                // uniformly rather than producing NaNs.
                for c in 0..k {
                    resp[i * k + c] = 1.0 / k as f64;
                }
                loglik += (1e-300f64).ln();
            } else {
                for c in 0..k {
                    resp[i * k + c] /= row_sum;
                }
                loglik += row_sum.ln();
            }
        }

        // M-step.
        for c in 0..k {
            let mut nk = 0.0;
            let mut mean_acc = 0.0;
            for i in 0..n {
                let r = resp[i * k + c];
                nk += r;
                mean_acc += r * data[i];
            }
            if nk <= 1e-12 {
                // Dead component — keep its previous params, tiny weight.
                weights[c] = 1e-12;
                continue;
            }
            let mean = mean_acc / nk;
            let mut var_acc = 0.0;
            for i in 0..n {
                var_acc += resp[i * k + c] * (data[i] - mean).powi(2);
            }
            weights[c] = nk / nf;
            means[c] = mean;
            vars[c] = (var_acc / nk).max(var_floor);
        }
        // Renormalise weights (dead components perturbed the sum).
        let wsum: f64 = weights.iter().sum();
        if wsum > 0.0 {
            for w in &mut weights {
                *w /= wsum;
            }
        }

        if (loglik - prev_loglik).abs() < CONVERGENCE_TOL * (1.0 + loglik.abs()) {
            break;
        }
        prev_loglik = loglik;
    }

    // BIC = -2 L + p ln n, with p = 3k-1 free params (k means, k vars, k-1 weights).
    let p = (3 * k).saturating_sub(1) as f64;
    let bic = -2.0 * loglik + p * nf.ln();

    Gmm1d {
        weights,
        means,
        vars,
        loglik,
        bic,
        n,
    }
}

/// Fit GMMs for `k = 1..=max_k` and return them all (index 0 == k=1).
/// Returns an empty vec when there is too little data to fit meaningfully.
pub fn fit_sweep(data: &[f64], max_k: usize) -> Vec<Gmm1d> {
    let n = data.len();
    if n < 2 || max_k == 0 {
        return Vec::new();
    }
    let mut sorted = data.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Variance floor scaled to the data so components can't collapse to a
    // delta on one repeated packet size.
    let global_mean = data.iter().sum::<f64>() / n as f64;
    let global_var = data.iter().map(|x| (x - global_mean).powi(2)).sum::<f64>() / n as f64;
    let var_floor = (global_var * 1e-4).max(1e-6);

    // Never ask for more components than we have distinct-ish points.
    let effective_max = max_k.min(n / 5).max(1);

    (1..=effective_max)
        .map(|k| fit_k(data, &sorted, k, var_floor))
        .collect()
}

/// Fit `k = 1..=max_k` and return the BIC-optimal fit (the multimodality
/// detector: BIC prefers `k>1` only when the data really is multimodal).
/// `None` when the data is too small to fit.
pub fn select_best_bic(data: &[f64], max_k: usize) -> Option<Gmm1d> {
    let sweep = fit_sweep(data, max_k);
    sweep
        .into_iter()
        .filter(|g| g.bic.is_finite())
        .min_by(|a, b| {
            a.bic
                .partial_cmp(&b.bic)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

/// R6a min-cluster component floor for production mask selection. A component
/// carrying less than this fraction of the mass is a spurious mode the BIC
/// sweep over-fit, not a behaviour a DPI adversary would ever see repeated —
/// see `research/mask-generation/phase2b/report/r6_report.md`.
pub const MIN_CLUSTER_WEIGHT: f64 = 0.05;

/// Like [`select_best_bic`], but enforces the R6a min-cluster constraint
/// *during* selection instead of pruning spurious modes post-hoc: among the
/// swept fits, keep only those whose **smallest** component weight is at least
/// `min_cluster_weight`, then take argmin BIC among the admissible `k`.
///
/// Rationale (R6a, `phase2b/report/r6_report.md`): plain argmin-BIC with a
/// full-covariance 1-D sweep keeps decreasing to the top of the range (k*=7-8)
/// by adding <5 %-weight micro-modes, then relies on `to_flat_params`'s
/// post-hoc prune to hide them — but the surviving components were still fit
/// under the over-K model, so the reported mask is dishonest. Rejecting the
/// whole `k` up front yields the honest interior optimum (DNS 4, QUIC 5,
/// WebRTC 2 on the study corpus) whose held-out KS fit is equal-or-better,
/// with cleaner modes that a flow-statistics classifier finds *harder* to
/// separate from real traffic, not easier.
///
/// `k=1` always has a single weight of 1.0, so it is always admissible: this
/// degrades gracefully to the unimodal fit when no multimodal `k` clears the
/// floor, and never returns `None` on data [`select_best_bic`] would fit.
pub fn select_best_bic_min_cluster(
    data: &[f64],
    max_k: usize,
    min_cluster_weight: f64,
) -> Option<Gmm1d> {
    let sweep = fit_sweep(data, max_k);
    let admissible: Vec<Gmm1d> = sweep
        .into_iter()
        .filter(|g| {
            g.bic.is_finite()
                && g.weights.iter().cloned().fold(f64::INFINITY, f64::min) >= min_cluster_weight
        })
        .collect();
    admissible.into_iter().min_by(|a, b| {
        a.bic
            .partial_cmp(&b.bic)
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn sample_bimodal(n: usize, seed: u64) -> Vec<f64> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            // Box-Muller standard normal.
            let u1: f64 = rng.gen::<f64>().max(1e-12);
            let u2: f64 = rng.gen();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            if rng.gen::<f64>() < 0.5 {
                out.push(50.0 + 4.0 * z); // mode A ~ N(50, 16)
            } else {
                out.push(200.0 + 8.0 * z); // mode B ~ N(200, 64)
            }
        }
        out
    }

    #[test]
    fn bic_selects_two_components_for_clear_bimodal() {
        let data = sample_bimodal(2000, 42);
        let best = select_best_bic(&data, 8).expect("fit");
        assert!(best.k() >= 2, "expected multimodal fit, got k={}", best.k());
        // The two dominant means should straddle the real modes (~50 and ~200).
        let mut means = best.means.clone();
        means.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let lo = means.first().unwrap();
        let hi = means.last().unwrap();
        assert!(*lo < 100.0, "low mode {lo} not near 50");
        assert!(*hi > 150.0, "high mode {hi} not near 200");
    }

    #[test]
    fn bic_prefers_single_component_for_unimodal() {
        // Tight single Gaussian — a second component should not lower BIC.
        let mut rng = StdRng::seed_from_u64(7);
        let data: Vec<f64> = (0..1500)
            .map(|_| {
                let u1: f64 = rng.gen::<f64>().max(1e-12);
                let u2: f64 = rng.gen();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                100.0 + 5.0 * z
            })
            .collect();
        let best = select_best_bic(&data, 8).expect("fit");
        assert_eq!(
            best.k(),
            1,
            "unimodal data should pick k=1, got {}",
            best.k()
        );
    }

    #[test]
    fn to_flat_params_roundtrips_and_prunes() {
        let data = sample_bimodal(2000, 99);
        let best = select_best_bic(&data, 8).expect("fit");
        let flat = best.to_flat_params(0.02).expect("multimodal flat params");
        let k = flat[0] as usize;
        assert!(k >= 2);
        assert_eq!(flat.len(), 1 + k * 3);
        // Weights (flat[1], flat[4], ...) must sum to ~1 after renormalisation.
        let wsum: f64 = (0..k).map(|c| flat[1 + c * 3]).sum();
        assert!((wsum - 1.0).abs() < 1e-9, "weights sum {wsum}");
        // Sigmas must be positive and finite.
        for c in 0..k {
            let sigma = flat[3 + c * 3];
            assert!(sigma > 0.0 && sigma.is_finite());
        }
    }

    #[test]
    fn deterministic_fit() {
        let data = sample_bimodal(1000, 3);
        let a = select_best_bic(&data, 8).unwrap();
        let b = select_best_bic(&data, 8).unwrap();
        assert_eq!(a.k(), b.k());
        assert_eq!(a.means, b.means);
        assert_eq!(a.vars, b.vars);
        assert_eq!(a.weights, b.weights);
    }

    #[test]
    fn min_cluster_rejects_spurious_tiny_modes() {
        // 98 % of the mass in one tight Gaussian, 2 % scattered far away — a
        // plain argmin-BIC sweep is tempted to spend a <5 %-weight component on
        // the outlier smear. The min-cluster rule must refuse any k whose
        // smallest weight is under the floor, so every surviving component of
        // the chosen fit carries real mass.
        let mut rng = StdRng::seed_from_u64(11);
        let mut data: Vec<f64> = Vec::new();
        for _ in 0..1960 {
            let u1: f64 = rng.gen::<f64>().max(1e-12);
            let u2: f64 = rng.gen();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            data.push(100.0 + 5.0 * z);
        }
        for _ in 0..40 {
            data.push(1200.0 + rng.gen::<f64>() * 400.0); // 2 % far outliers
        }
        let best = select_best_bic_min_cluster(&data, 8, MIN_CLUSTER_WEIGHT).expect("fit");
        let min_w = best.weights.iter().cloned().fold(f64::INFINITY, f64::min);
        assert!(
            min_w >= MIN_CLUSTER_WEIGHT,
            "selected fit has a sub-floor component (min weight {min_w}, k={})",
            best.k()
        );
    }

    #[test]
    fn min_cluster_still_finds_clear_bimodal() {
        // Two well-separated 50/50 modes clear the floor comfortably, so the
        // constrained selector must still pick a multimodal fit.
        let data = sample_bimodal(2000, 42);
        let best = select_best_bic_min_cluster(&data, 8, MIN_CLUSTER_WEIGHT).expect("fit");
        assert!(best.k() >= 2, "expected multimodal fit, got k={}", best.k());
        let min_w = best.weights.iter().cloned().fold(f64::INFINITY, f64::min);
        assert!(min_w >= MIN_CLUSTER_WEIGHT);
    }

    #[test]
    fn min_cluster_falls_back_to_unimodal_not_none() {
        // Clean single Gaussian: no multimodal k clears the floor, but k=1
        // (weight 1.0) always does — must return a unimodal fit, never None.
        let mut rng = StdRng::seed_from_u64(7);
        let data: Vec<f64> = (0..1500)
            .map(|_| {
                let u1: f64 = rng.gen::<f64>().max(1e-12);
                let u2: f64 = rng.gen();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                100.0 + 5.0 * z
            })
            .collect();
        let best = select_best_bic_min_cluster(&data, 8, MIN_CLUSTER_WEIGHT).expect("fit");
        assert_eq!(
            best.k(),
            1,
            "unimodal data should pick k=1, got {}",
            best.k()
        );
    }

    #[test]
    fn tiny_input_is_safe() {
        assert!(select_best_bic(&[], 8).is_none());
        assert!(select_best_bic(&[5.0], 8).is_none());
        // A handful of points must not panic and must not over-fit.
        let best = select_best_bic(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 8);
        if let Some(g) = best {
            assert!(g.k() >= 1);
        }
    }
}
