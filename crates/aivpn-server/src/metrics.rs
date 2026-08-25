//! Prometheus Metrics (Phase 5)
//!
//! Implements monitoring and metrics export for AIVPN
//!
//! Features:
//! - Session count and state
//! - Packet processing rates
//! - Bandwidth usage
//! - Mask rotation events
//! - Neural module health
//! - DPI attack detection

#[cfg(feature = "metrics")]
use prometheus::{Counter, Encoder, Gauge, Histogram, HistogramOpts, Opts, Registry, TextEncoder};
#[cfg(feature = "metrics")]
use std::sync::Arc;
#[cfg(feature = "metrics")]
use tracing::warn;

/// Metrics collector
pub struct MetricsCollector {
    #[cfg(feature = "metrics")]
    registry: Registry,

    #[cfg(feature = "metrics")]
    sessions_total: Gauge,

    #[cfg(feature = "metrics")]
    sessions_active: Gauge,

    #[cfg(feature = "metrics")]
    packets_received: Counter,

    #[cfg(feature = "metrics")]
    packets_sent: Counter,

    #[cfg(feature = "metrics")]
    bytes_received: Counter,

    #[cfg(feature = "metrics")]
    bytes_sent: Counter,

    #[cfg(feature = "metrics")]
    packet_processing_time: Histogram,

    #[cfg(feature = "metrics")]
    tag_validation_time: Histogram,

    #[cfg(feature = "metrics")]
    mask_rotations: Counter,

    #[cfg(feature = "metrics")]
    key_rotations: Counter,

    #[cfg(feature = "metrics")]
    neural_checks_total: Counter,

    #[cfg(feature = "metrics")]
    neural_checks_failed: Counter,

    #[cfg(feature = "metrics")]
    dpi_attacks_detected: Counter,

    // ── §2 crowdsourced mask feedback ────────────────────────────────────
    #[cfg(feature = "metrics")]
    mask_feedback_received: Counter,

    #[cfg(feature = "metrics")]
    regional_hints_sent: Counter,

    #[cfg(feature = "metrics")]
    feedback_buckets: Gauge,

    #[cfg(feature = "metrics")]
    feedback_regions: Gauge,

    // ── §3 polymorphic masks ─────────────────────────────────────────────
    #[cfg(feature = "metrics")]
    mask_preference_requests: Counter,

    #[cfg(feature = "metrics")]
    polymorphic_variants_pushed: Counter,

    #[cfg(feature = "metrics")]
    polymorphic_sessions_active: Gauge,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        #[cfg(feature = "metrics")]
        {
            let registry = Registry::new();

            // Session metrics
            let sessions_total = Gauge::with_opts(Opts::new(
                "aivpn_sessions_total",
                "Total number of sessions",
            ))
            .unwrap();
            registry.register(Box::new(sessions_total.clone())).unwrap();

            let sessions_active = Gauge::with_opts(Opts::new(
                "aivpn_sessions_active",
                "Number of active sessions",
            ))
            .unwrap();
            registry
                .register(Box::new(sessions_active.clone()))
                .unwrap();

            // Packet metrics
            let packets_received = Counter::with_opts(Opts::new(
                "aivpn_packets_received_total",
                "Total packets received",
            ))
            .unwrap();
            registry
                .register(Box::new(packets_received.clone()))
                .unwrap();

            let packets_sent =
                Counter::with_opts(Opts::new("aivpn_packets_sent_total", "Total packets sent"))
                    .unwrap();
            registry.register(Box::new(packets_sent.clone())).unwrap();

            // Bandwidth metrics
            let bytes_received = Counter::with_opts(Opts::new(
                "aivpn_bytes_received_total",
                "Total bytes received",
            ))
            .unwrap();
            registry.register(Box::new(bytes_received.clone())).unwrap();

            let bytes_sent =
                Counter::with_opts(Opts::new("aivpn_bytes_sent_total", "Total bytes sent"))
                    .unwrap();
            registry.register(Box::new(bytes_sent.clone())).unwrap();

            // Performance metrics.
            // HistogramOpts is required here — Histogram::with_opts does not accept plain Opts.
            let packet_processing_time = Histogram::with_opts(HistogramOpts::new(
                "aivpn_packet_processing_seconds",
                "Packet processing time",
            ))
            .unwrap();
            registry
                .register(Box::new(packet_processing_time.clone()))
                .unwrap();

            let tag_validation_time = Histogram::with_opts(HistogramOpts::new(
                "aivpn_tag_validation_seconds",
                "Tag validation time",
            ))
            .unwrap();
            registry
                .register(Box::new(tag_validation_time.clone()))
                .unwrap();

            // Rotation metrics
            let mask_rotations = Counter::with_opts(Opts::new(
                "aivpn_mask_rotations_total",
                "Total mask rotations",
            ))
            .unwrap();
            registry.register(Box::new(mask_rotations.clone())).unwrap();

            let key_rotations = Counter::with_opts(Opts::new(
                "aivpn_key_rotations_total",
                "Total key rotations",
            ))
            .unwrap();
            registry.register(Box::new(key_rotations.clone())).unwrap();

            // Neural module metrics
            let neural_checks_total = Counter::with_opts(Opts::new(
                "aivpn_neural_checks_total",
                "Total neural resonance checks",
            ))
            .unwrap();
            registry
                .register(Box::new(neural_checks_total.clone()))
                .unwrap();

            let neural_checks_failed = Counter::with_opts(Opts::new(
                "aivpn_neural_checks_failed_total",
                "Failed neural resonance checks",
            ))
            .unwrap();
            registry
                .register(Box::new(neural_checks_failed.clone()))
                .unwrap();

            // Security metrics
            let dpi_attacks_detected = Counter::with_opts(Opts::new(
                "aivpn_dpi_attacks_detected_total",
                "DPI attacks detected",
            ))
            .unwrap();
            registry
                .register(Box::new(dpi_attacks_detected.clone()))
                .unwrap();

            // §2 crowdsourced mask feedback metrics
            let mask_feedback_received = Counter::with_opts(Opts::new(
                "aivpn_mask_feedback_received_total",
                "Total MaskFeedback control messages received with reportable entries",
            ))
            .unwrap();
            registry
                .register(Box::new(mask_feedback_received.clone()))
                .unwrap();

            let regional_hints_sent = Counter::with_opts(Opts::new(
                "aivpn_regional_hints_sent_total",
                "Total RegionalMaskHints replies sent to clients",
            ))
            .unwrap();
            registry
                .register(Box::new(regional_hints_sent.clone()))
                .unwrap();

            let feedback_buckets = Gauge::with_opts(Opts::new(
                "aivpn_feedback_buckets",
                "Total (country_code, mask_id) buckets currently held in the feedback store",
            ))
            .unwrap();
            registry
                .register(Box::new(feedback_buckets.clone()))
                .unwrap();

            let feedback_regions = Gauge::with_opts(Opts::new(
                "aivpn_feedback_regions",
                "Distinct countries with at least one feedback bucket",
            ))
            .unwrap();
            registry
                .register(Box::new(feedback_regions.clone()))
                .unwrap();

            // §3 polymorphic mask metrics
            let mask_preference_requests = Counter::with_opts(Opts::new(
                "aivpn_mask_preference_requests_total",
                "Total MaskPreference control messages received from clients",
            ))
            .unwrap();
            registry
                .register(Box::new(mask_preference_requests.clone()))
                .unwrap();

            let polymorphic_variants_pushed = Counter::with_opts(Opts::new(
                "aivpn_polymorphic_variants_pushed_total",
                "Total polymorphic mask variants pushed to clients via MaskUpdate",
            ))
            .unwrap();
            registry
                .register(Box::new(polymorphic_variants_pushed.clone()))
                .unwrap();

            let polymorphic_sessions_active = Gauge::with_opts(Opts::new(
                "aivpn_polymorphic_sessions_active",
                "Sessions whose current mask is a polymorphic variant",
            ))
            .unwrap();
            registry
                .register(Box::new(polymorphic_sessions_active.clone()))
                .unwrap();

            Self {
                registry,
                sessions_total,
                sessions_active,
                packets_received,
                packets_sent,
                bytes_received,
                bytes_sent,
                packet_processing_time,
                tag_validation_time,
                mask_rotations,
                key_rotations,
                neural_checks_total,
                neural_checks_failed,
                dpi_attacks_detected,
                mask_feedback_received,
                regional_hints_sent,
                feedback_buckets,
                feedback_regions,
                mask_preference_requests,
                polymorphic_variants_pushed,
                polymorphic_sessions_active,
            }
        }

        #[cfg(not(feature = "metrics"))]
        Self {}
    }

    /// Update session count
    pub fn update_session_count(&self, total: usize, active: usize) {
        #[cfg(feature = "metrics")]
        {
            // Gauge::set takes f64
            self.sessions_total.set(total as f64);
            self.sessions_active.set(active as f64);
        }

        #[cfg(not(feature = "metrics"))]
        let _ = (total, active);
    }

    /// Record packet received
    pub fn record_packet_received(&self, bytes: usize) {
        #[cfg(feature = "metrics")]
        {
            self.packets_received.inc();
            // Counter::inc_by takes f64
            self.bytes_received.inc_by(bytes as f64);
        }

        #[cfg(not(feature = "metrics"))]
        let _ = bytes;
    }

    /// Record packet sent
    pub fn record_packet_sent(&self, bytes: usize) {
        #[cfg(feature = "metrics")]
        {
            self.packets_sent.inc();
            // Counter::inc_by takes f64
            self.bytes_sent.inc_by(bytes as f64);
        }

        #[cfg(not(feature = "metrics"))]
        let _ = bytes;
    }

    /// Record packet processing time
    pub fn record_processing_time(&self, _seconds: f64) {
        #[cfg(feature = "metrics")]
        {
            self.packet_processing_time.observe(_seconds);
        }
    }

    /// Record tag validation time
    pub fn record_tag_validation_time(&self, _seconds: f64) {
        #[cfg(feature = "metrics")]
        {
            self.tag_validation_time.observe(_seconds);
        }
    }

    /// Record mask rotation
    pub fn record_mask_rotation(&self) {
        #[cfg(feature = "metrics")]
        {
            self.mask_rotations.inc();
        }
    }

    /// Record key rotation
    pub fn record_key_rotation(&self) {
        #[cfg(feature = "metrics")]
        {
            self.key_rotations.inc();
        }
    }

    /// Record neural check
    pub fn record_neural_check(&self, _failed: bool) {
        #[cfg(feature = "metrics")]
        {
            self.neural_checks_total.inc();
            if _failed {
                self.neural_checks_failed.inc();
            }
        }
    }

    /// Record DPI attack detection
    pub fn record_dpi_attack(&self) {
        #[cfg(feature = "metrics")]
        {
            self.dpi_attacks_detected.inc();
            warn!("DPI attack detected!");
        }
    }

    // ── §2 crowdsourced mask feedback ────────────────────────────────────

    /// Record a `MaskFeedback` control message with reportable entries.
    pub fn record_mask_feedback_received(&self) {
        #[cfg(feature = "metrics")]
        {
            self.mask_feedback_received.inc();
        }
    }

    /// Record a `RegionalMaskHints` reply sent to a client.
    pub fn record_regional_hints_sent(&self) {
        #[cfg(feature = "metrics")]
        {
            self.regional_hints_sent.inc();
        }
    }

    /// Set the current total bucket count held by `MaskFeedbackStore`.
    pub fn set_feedback_buckets(&self, _count: usize) {
        #[cfg(feature = "metrics")]
        {
            self.feedback_buckets.set(_count as f64);
        }
    }

    /// Set the current distinct-region count held by `MaskFeedbackStore`.
    pub fn set_feedback_regions(&self, _count: usize) {
        #[cfg(feature = "metrics")]
        {
            self.feedback_regions.set(_count as f64);
        }
    }

    // ── §3 polymorphic masks ─────────────────────────────────────────────

    /// Record a `MaskPreference` control message received from a client.
    pub fn record_mask_preference_request(&self) {
        #[cfg(feature = "metrics")]
        {
            self.mask_preference_requests.inc();
        }
    }

    /// Record a polymorphic mask variant actually pushed to a client
    /// (client-requested `MaskPreference` or the server-policy "all
    /// sessions polymorphic" path).
    pub fn record_polymorphic_variant_pushed(&self) {
        #[cfg(feature = "metrics")]
        {
            self.polymorphic_variants_pushed.inc();
        }
    }

    /// Set the current count of sessions whose active/pending mask is a
    /// polymorphic variant (mask_id starts with `"polymorphic:"`).
    ///
    /// Maintained by periodically recomputing the count (see the gateway's
    /// mask-feedback sweep task, which now also refreshes this gauge every
    /// 300s) rather than incrementally on every push/session-end. A session
    /// can leave a polymorphic mask in more ways than just "session ended"
    /// (neural-triggered rotation onto a non-polymorphic fallback, a fresh
    /// `MaskPreference` deriving from a different base, etc.), so an
    /// incremental increment/decrement pair would need a guard at every one
    /// of those call sites to stay correct. A periodic O(active sessions)
    /// recomputation is simple, always correct, and cheap at the documented
    /// `MAX_SESSIONS = 500` scale.
    pub fn set_polymorphic_sessions_active(&self, _count: usize) {
        #[cfg(feature = "metrics")]
        {
            self.polymorphic_sessions_active.set(_count as f64);
        }
    }

    // ── Typed getters (web panel live dashboard) ────────────────────────────
    //
    // These read the current value straight off the typed Prometheus handles
    // instead of round-tripping through the text exposition format — cheaper
    // and avoids a text-parse step on every SSE tick. Each getter is always
    // callable; it returns 0.0 when built without the `metrics` feature so
    // callers don't need to sprinkle cfg-gating through their own logic (the
    // management API still cfg-gates whether it *calls* these at all, so the
    // SSE payload omits the fields entirely rather than sending zeros when
    // metrics are disabled).

    /// Number of currently active sessions.
    pub fn active_sessions(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.sessions_active.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative bytes received since server start.
    pub fn bytes_received_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.bytes_received.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative bytes sent since server start.
    pub fn bytes_sent_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.bytes_sent.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative packets received since server start.
    pub fn packets_received_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.packets_received.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative packets sent since server start.
    pub fn packets_sent_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.packets_sent.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative mask rotations since server start.
    pub fn mask_rotations_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.mask_rotations.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative key rotations since server start.
    pub fn key_rotations_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.key_rotations.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative neural resonance checks performed.
    pub fn neural_checks_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.neural_checks_total.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative neural resonance checks that failed (mask fingerprinted).
    pub fn neural_checks_failed_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.neural_checks_failed.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative DPI attacks detected.
    pub fn dpi_attacks_detected_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.dpi_attacks_detected.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative `MaskFeedback` messages received with reportable entries.
    pub fn mask_feedback_received_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.mask_feedback_received.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative `RegionalMaskHints` replies sent.
    pub fn regional_hints_sent_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.regional_hints_sent.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Current total buckets held by the feedback store.
    pub fn feedback_buckets(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.feedback_buckets.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Current distinct-region count held by the feedback store.
    pub fn feedback_regions(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.feedback_regions.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative `MaskPreference` messages received from clients.
    pub fn mask_preference_requests_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.mask_preference_requests.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Cumulative polymorphic mask variants pushed to clients.
    pub fn polymorphic_variants_pushed_total(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.polymorphic_variants_pushed.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Current count of sessions on a polymorphic mask variant.
    pub fn polymorphic_sessions_active(&self) -> f64 {
        #[cfg(feature = "metrics")]
        {
            self.polymorphic_sessions_active.get()
        }
        #[cfg(not(feature = "metrics"))]
        {
            0.0
        }
    }

    /// Approximate p50/p95 packet-processing latency in milliseconds.
    ///
    /// Method: Prometheus histograms only expose cumulative counts per
    /// bucket boundary, not raw samples, so an exact percentile isn't
    /// available without re-implementing PromQL's `histogram_quantile`
    /// linear interpolation. This walks the (ascending, cumulative) bucket
    /// list and returns the upper bound (in ms) of the first bucket whose
    /// cumulative count reaches the target rank (0.50 / 0.95 of the total
    /// sample count). That's a coarse, bucket-quantized estimate — good
    /// enough for a live dashboard sparkline, not for SLA-grade analysis.
    /// Falls back to the mean latency (sample_sum / sample_count) if no
    /// bucket satisfies the target (shouldn't happen once the +Inf bucket
    /// is reached, but guards against an empty/degenerate histogram).
    pub fn packet_processing_percentiles_ms(&self) -> (f64, f64) {
        #[cfg(feature = "metrics")]
        {
            use prometheus::core::Collector;
            // Histogram doesn't expose bucket internals directly; go through
            // the same Collector::collect() snapshot the text exporter uses.
            let families = self.packet_processing_time.collect();
            let Some(metric) = families.first().and_then(|f| f.get_metric().first()) else {
                return (0.0, 0.0);
            };
            let hist = metric.get_histogram();
            let total = hist.get_sample_count();
            if total == 0 {
                return (0.0, 0.0);
            }
            let p50_target = ((total as f64) * 0.50).ceil() as u64;
            let p95_target = ((total as f64) * 0.95).ceil() as u64;
            let mut p50_ms = 0.0f64;
            let mut p95_ms = 0.0f64;
            for bucket in hist.get_bucket() {
                let cumulative = bucket.cumulative_count();
                let upper_ms = bucket.upper_bound() * 1000.0;
                if p50_ms == 0.0 && cumulative >= p50_target {
                    p50_ms = upper_ms;
                }
                if p95_ms == 0.0 && cumulative >= p95_target {
                    p95_ms = upper_ms;
                }
            }
            // If a percentile's rank falls above the largest *finite* bucket
            // boundary (prometheus 0.13.4 does not emit the synthetic `+Inf`
            // bucket from `collect()`, so the walk simply never assigns a value
            // and `p_ms` stays at the 0.0 sentinel), fall back to the finite
            // mean latency so the metric doesn't vanish during the exact
            // overload it should show. The `!is_finite()` guard is defensive
            // belt-and-suspenders in case a future prometheus version does
            // surface an `+Inf` upper bound (which would serialize to JSON
            // `null`); today only the `== 0.0` path can actually fire.
            if !p50_ms.is_finite() || p50_ms == 0.0 || !p95_ms.is_finite() || p95_ms == 0.0 {
                let mean_ms = (hist.get_sample_sum() / total as f64) * 1000.0;
                if !p50_ms.is_finite() || p50_ms == 0.0 {
                    p50_ms = mean_ms;
                }
                if !p95_ms.is_finite() || p95_ms == 0.0 {
                    p95_ms = mean_ms;
                }
            }
            (p50_ms, p95_ms)
        }
        #[cfg(not(feature = "metrics"))]
        {
            (0.0, 0.0)
        }
    }

    /// Export metrics in Prometheus text exposition format (Content-Type: text/plain; version=0.0.4)
    pub fn gather(&self) -> String {
        #[cfg(feature = "metrics")]
        {
            let encoder = TextEncoder::new();
            let metric_families = self.registry.gather();
            // encode() writes to impl Write; use a Vec<u8> buffer then convert to String.
            let mut buf = Vec::new();
            encoder
                .encode(&metric_families, &mut buf)
                .unwrap_or_default();
            String::from_utf8(buf).unwrap_or_default()
        }

        #[cfg(not(feature = "metrics"))]
        {
            String::new()
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the current Prometheus metrics in text exposition format.
/// The caller is responsible for serving this as HTTP with
/// Content-Type: text/plain; version=0.0.4
#[cfg(feature = "metrics")]
pub async fn metrics_handler(collector: Arc<MetricsCollector>) -> String {
    collector.gather()
}

#[cfg(test)]
mod tests {
    use super::MetricsCollector;

    /// §2/§3 typed getters: start at zero, and reflect exactly what was
    /// recorded through the corresponding `record_*` / `set_*` methods —
    /// same shape as the pre-existing §1 getters (`active_sessions`,
    /// `mask_rotations_total`, etc.), just for the newly added metrics.
    /// Without the `metrics` feature every getter is a hardcoded `0.0`, so
    /// this test is meaningful under both build configurations: it either
    /// proves the Prometheus-backed values round-trip correctly, or proves
    /// the feature-off stubs stay at their 0.0 sentinel.
    #[test]
    fn feedback_and_polymorphic_getters_reflect_recorded_values() {
        let collector = MetricsCollector::new();

        assert_eq!(collector.mask_feedback_received_total(), 0.0);
        assert_eq!(collector.regional_hints_sent_total(), 0.0);
        assert_eq!(collector.feedback_buckets(), 0.0);
        assert_eq!(collector.feedback_regions(), 0.0);
        assert_eq!(collector.mask_preference_requests_total(), 0.0);
        assert_eq!(collector.polymorphic_variants_pushed_total(), 0.0);
        assert_eq!(collector.polymorphic_sessions_active(), 0.0);

        collector.record_mask_feedback_received();
        collector.record_mask_feedback_received();
        collector.record_regional_hints_sent();
        collector.set_feedback_buckets(42);
        collector.set_feedback_regions(7);
        collector.record_mask_preference_request();
        collector.record_polymorphic_variant_pushed();
        collector.record_polymorphic_variant_pushed();
        collector.record_polymorphic_variant_pushed();
        collector.set_polymorphic_sessions_active(3);

        #[cfg(feature = "metrics")]
        {
            assert_eq!(collector.mask_feedback_received_total(), 2.0);
            assert_eq!(collector.regional_hints_sent_total(), 1.0);
            assert_eq!(collector.feedback_buckets(), 42.0);
            assert_eq!(collector.feedback_regions(), 7.0);
            assert_eq!(collector.mask_preference_requests_total(), 1.0);
            assert_eq!(collector.polymorphic_variants_pushed_total(), 3.0);
            assert_eq!(collector.polymorphic_sessions_active(), 3.0);
        }
        #[cfg(not(feature = "metrics"))]
        {
            assert_eq!(collector.mask_feedback_received_total(), 0.0);
            assert_eq!(collector.regional_hints_sent_total(), 0.0);
            assert_eq!(collector.feedback_buckets(), 0.0);
            assert_eq!(collector.feedback_regions(), 0.0);
            assert_eq!(collector.mask_preference_requests_total(), 0.0);
            assert_eq!(collector.polymorphic_variants_pushed_total(), 0.0);
            assert_eq!(collector.polymorphic_sessions_active(), 0.0);
        }
    }
}
