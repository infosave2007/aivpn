//! ML-DPI по окну из 24 проверенных внешних UDP-кадров.
//!
//! GBDT приближает офлайн-вердикт nDPI: целевой QUIC/STUN либо
//! туннель/Unknown. Neural Resonance отдельно отслеживает отклонение
//! статистики от эталона маски; оба детектора могут запросить ее смену.
//!
//! Обучение и проверка находятся в tools/dpi, результаты и происхождение
//! данных в assets/dpi. Захваты разделены по сессиям; ограничения переноса
//! на другой трафик описаны в отчете обучения. IAT не входит в 23 признака:
//! временные характеристики обучающих сессий не задают эталон сети клиента.
//!
//! Выборка берет первый кадр и затем каждый шестнадцатый. Признаки включают
//! длины, энтропию и поля внешних заголовков. Модель содержит 120 деревьев
//! глубины 3. Сервер включает модуль через neural, клиент через client-dpi-gate.

use dashmap::DashMap;
use std::collections::VecDeque;

mod model;

/// One flattened GradientBoosting node.
///
/// Internal node: `feature >= 0` — descend `left` if `x[feature] <= threshold`,
/// else `right`. Leaf: `feature == -1` — contribute `value` to the raw score.
/// The whole ensemble is a single flat [`model::NODES`] table indexed per tree
/// by [`model::TREE_OFFSETS`]; this mirrors how `neural.rs` bakes MLP weights as
/// const arrays, but for a tree ensemble.
#[derive(Clone, Copy)]
pub struct GbdtNode {
    pub feature: i16,
    pub threshold: f32,
    pub left: u16,
    pub right: u16,
    pub value: f32,
}

/// Sliding window length in packets. Matches `features.py` (`N = 24`): the model
/// was trained on 24-packet windows, so a verdict is only meaningful once a full
/// window has accumulated.
pub const WINDOW: usize = 24;

/// Size histogram bins `[lo, hi)`, identical to `features.py::SIZE_BINS`.
const SIZE_BINS: [(u32, u32); 6] = [
    (0, 100),
    (100, 300),
    (300, 600),
    (600, 1000),
    (1000, 1400),
    (1400, 65535),
];

/// Cheap per-packet metadata — everything the 23 features need, with no payload
/// retained. Populated once from the wire bytes a DPI box would see and pushed
/// into a bounded per-session ring.
#[derive(Clone, Copy, Debug)]
pub struct PacketMeta {
    len: u16,
    byte0: u8,
    /// Packet had at least one byte (byte-0 stats denominator, matching
    /// `features.py`'s `[p[0] for p in payloads if p]`).
    has_byte0: bool,
    /// STUN message type at offset 0 (`00 01` / `01 01` / `00 03` / `01 11`)
    /// with the two top bits of byte 0 clear (STUN/RTP demux bit).
    stun_type: bool,
    /// STUN magic cookie `21 12 A4 42` at offset 4.
    magic_ok: bool,
    /// STUN length-consistency: `msg_len + 20 == payload_len` (nDPI's killer
    /// `is_stun()` predicate; the R1 root-cause check).
    stun_lenok: bool,
    /// Rough DNS query heuristic: `qdcount == 1 && ancount <= 16`.
    dns_ok: bool,
    /// Shannon entropy (bits/byte) of the first 16 wire bytes.
    ent16: f32,
    /// Shannon entropy (bits/byte) of the whole wire packet.
    ent_full: f32,
}

impl PacketMeta {
    /// Extract metadata from the observable wire bytes of one packet — exactly
    /// what nDPI / a DPI box inspects. For aivpn this is the full UDP datagram
    /// (`[header/tag bytes][ciphertext]`); embedded-tag masks place the protocol
    /// header bytes at the wire offsets checked below.
    pub fn from_wire(p: &[u8]) -> Self {
        let len = p.len();
        let byte0 = p.first().copied().unwrap_or(0);

        let stun_type = len >= 2
            && (p[0] & 0xC0) == 0
            && matches!(
                [p[0], p[1]],
                [0x00, 0x01] | [0x01, 0x01] | [0x00, 0x03] | [0x01, 0x11]
            );

        let magic_ok = len >= 8 && p[4..8] == [0x21, 0x12, 0xA4, 0x42];

        let stun_lenok = len >= 4 && {
            let msg_len = ((p[2] as usize) << 8) | (p[3] as usize);
            msg_len + 20 == len
        };

        let dns_ok = len >= 12 && {
            let qd = ((p[4] as usize) << 8) | (p[5] as usize);
            let an = ((p[6] as usize) << 8) | (p[7] as usize);
            qd == 1 && an <= 16
        };

        let n16 = len.min(16);
        Self {
            len: len.min(u16::MAX as usize) as u16,
            byte0,
            has_byte0: len > 0,
            stun_type,
            magic_ok,
            stun_lenok,
            dns_ok,
            ent16: shannon_entropy(&p[..n16]) as f32,
            ent_full: shannon_entropy(p) as f32,
        }
    }
}

/// Shannon entropy in bits/byte over `data`. Identical to `features.py::_entropy`
/// and `gateway::compute_entropy`.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Round-half-to-even (banker's rounding), matching Python's built-in `round`
/// used by `features.py::_pct`. This is load-bearing: at the p10/p50/p90
/// percentile indices the fractional part lands exactly on `.5` for common
/// window sizes (e.g. `0.9 * 5 == 4.5`), and half-away-from-zero rounding would
/// pick the wrong sample and silently diverge from the training features.
fn round_half_even(x: f64) -> f64 {
    let f = x.floor();
    let diff = x - f;
    if diff < 0.5 {
        f
    } else if diff > 0.5 {
        f + 1.0
    } else if (f as i64) % 2 == 0 {
        f
    } else {
        f + 1.0
    }
}

/// Percentile of a sorted size slice, matching `features.py::_pct`:
/// `idx = clamp(round_half_even(q * (n - 1)), 0, n - 1)`.
fn pct(sorted: &[u32], q: f64) -> f32 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = round_half_even(q * (sorted.len() - 1) as f64) as usize;
    sorted[idx.min(sorted.len() - 1)] as f32
}

/// Extract the 23-feature vector from a packet window, in the exact order the
/// embedded model consumes it (a Rust port of `features.py::vector` with the two
/// IAT features dropped). Returns all-zero for an empty window.
pub fn extract_features(window: &[PacketMeta]) -> [f32; model::N_FEATURES] {
    let mut f = [0.0f32; model::N_FEATURES];
    let n = window.len();
    if n == 0 {
        return f;
    }
    let nf = n as f32;

    // Size moments + percentiles.
    let mut sizes: Vec<u32> = window.iter().map(|m| m.len as u32).collect();
    let sum: f64 = sizes.iter().map(|&s| s as f64).sum();
    let mean = sum / n as f64;
    let var = sizes
        .iter()
        .map(|&s| (s as f64 - mean).powi(2))
        .sum::<f64>()
        / n as f64;
    sizes.sort_unstable();

    f[0] = nf; // n_pkts
    f[1] = mean as f32; // sz_mean
    f[2] = var.sqrt() as f32; // sz_std (population)
    f[3] = sizes[0] as f32; // sz_min
    f[4] = sizes[n - 1] as f32; // sz_max
    f[5] = pct(&sizes, 0.5); // sz_med
    f[6] = pct(&sizes, 0.10); // sz_p10
    f[7] = pct(&sizes, 0.90); // sz_p90

    // Size histogram fractions (bin assignment is order-independent).
    let mut binc = [0u32; SIZE_BINS.len()];
    for m in window {
        let s = m.len as u32;
        for (i, (lo, hi)) in SIZE_BINS.iter().enumerate() {
            if s >= *lo && s < *hi {
                binc[i] += 1;
                break;
            }
        }
    }
    for i in 0..SIZE_BINS.len() {
        f[8 + i] = binc[i] as f32 / nf; // szfrac_*
    }

    // Entropy means (accumulate in f64 to match the Python reference).
    f[14] = (window.iter().map(|m| m.ent16 as f64).sum::<f64>() / n as f64) as f32; // ent_first16
    f[15] = (window.iter().map(|m| m.ent_full as f64).sum::<f64>() / n as f64) as f32; // ent_full

    // Byte-0 / header-form statistics (denominator = packets with >= 1 byte).
    let mut b0_sum = 0u64;
    let mut b0_n = 0u32;
    let mut b0_msb = 0u32;
    let mut quic_long = 0u32;
    for m in window {
        if m.has_byte0 {
            b0_sum += m.byte0 as u64;
            b0_n += 1;
            if m.byte0 & 0x80 != 0 {
                b0_msb += 1;
            }
            if (m.byte0 & 0xC0) == 0xC0 {
                quic_long += 1;
            }
        }
    }
    if b0_n > 0 {
        f[16] = b0_sum as f32 / b0_n as f32; // byte0_mean
        f[17] = b0_msb as f32 / b0_n as f32; // byte0_msb_frac
        f[18] = quic_long as f32 / b0_n as f32; // quic_longform_frac
    }

    // STUN structural + DNS fractions (denominator = all packets).
    f[19] = window.iter().filter(|m| m.stun_type).count() as f32 / nf; // stun_type_frac
    f[20] = window.iter().filter(|m| m.magic_ok).count() as f32 / nf; // stun_magic_frac
    f[21] = window.iter().filter(|m| m.stun_lenok).count() as f32 / nf; // stun_lenconsistent_frac
    f[22] = window.iter().filter(|m| m.dns_ok).count() as f32 / nf; // dns_looksdns_frac

    f
}

/// Run the embedded GradientBoosting ensemble and return the probability that
/// the window "reads as tunnel" (nDPI `Unknown`). `raw = INIT + lr * Σ leaf`,
/// then a logistic squash — the exact inverse of sklearn's `decision_function`.
pub fn tunnel_probability(x: &[f32; model::N_FEATURES]) -> f32 {
    let mut raw = model::INIT;
    for t in 0..model::N_TREES {
        let mut i = model::TREE_OFFSETS[t] as usize;
        loop {
            let node = &model::NODES[i];
            if node.feature < 0 {
                raw += model::LEARNING_RATE * node.value;
                break;
            }
            i = if x[node.feature as usize] <= node.threshold {
                node.left as usize
            } else {
                node.right as usize
            };
        }
    }
    1.0 / (1.0 + (-raw).exp())
}

/// A gate verdict for one session's current window.
#[derive(Debug, Clone, Copy)]
pub struct DpiVerdict {
    /// Modelled probability the window reads as an obfuscated tunnel (`Unknown`).
    pub tunnel_prob: f32,
    /// `tunnel_prob > threshold` — the advisory "rotate this mask" signal.
    pub reads_as_tunnel: bool,
}

/// Approximate embedded model size in bytes (const table footprint).
pub fn embedded_model_bytes() -> usize {
    model::NODES.len() * std::mem::size_of::<GbdtNode>()
        + std::mem::size_of_val(&model::TREE_OFFSETS)
}

/// Per-session inline ML-DPI gate. Holds a bounded ring of recent packet
/// metadata per session and produces a window verdict on demand. Cheap enough to
/// be always-on; the model itself is a const table baked into the binary.
pub struct DpiGate {
    /// Probability above which a full window is judged "reads-as-tunnel".
    threshold: f32,
    windows: DashMap<[u8; 16], VecDeque<PacketMeta>>,
}

impl DpiGate {
    /// Create a gate with the given decision threshold (see
    /// `NeuralConfig::dpi_gate_threshold`).
    pub fn new(threshold: f32) -> Self {
        Self {
            threshold,
            windows: DashMap::new(),
        }
    }

    /// Record one outbound wire packet for a session (O(1) amortised). Keeps only
    /// the last [`WINDOW`] packets.
    pub fn record_wire(&self, session_id: [u8; 16], wire: &[u8]) {
        let meta = PacketMeta::from_wire(wire);
        let mut ring = self.windows.entry(session_id).or_default();
        ring.push_back(meta);
        while ring.len() > WINDOW {
            ring.pop_front();
        }
    }

    /// Verdict for a session, or `None` until a full window has accumulated (an
    /// under-full window is a degenerate feature vector — never judge on it, to
    /// avoid false rotations on a barely-active session).
    pub fn verdict(&self, session_id: &[u8; 16]) -> Option<DpiVerdict> {
        let ring = self.windows.get(session_id)?;
        if ring.len() < WINDOW {
            return None;
        }
        let win: Vec<PacketMeta> = ring.iter().copied().collect();
        let x = extract_features(&win);
        let prob = tunnel_probability(&x);
        Some(DpiVerdict {
            tunnel_prob: prob,
            reads_as_tunnel: prob > self.threshold,
        })
    }

    /// Configured decision threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Drop a session's ring (call on session teardown, like
    /// `NeuralResonanceModule::cleanup_stats`).
    pub fn cleanup(&self, session_id: &[u8; 16]) {
        self.windows.remove(session_id);
    }
}

// ──────────────────── Client-side self-detection gate ───────────────────────

/// Client-side inline "reads-as-tunnel" self-check (R2 Phase D, client edition).
///
/// The server runs [`DpiGate`] over *inbound* client packets and rotates the
/// mask when a flow starts reading as a tunnel. This is the symmetric client
/// half: it watches the client's OWN outbound shaped wire bytes and, when they
/// start reading as a tunnel, proactively raises a rotate-request so the client
/// can ask to change mask *before* the server's own neural/GBDT fires.
///
/// It wraps a single-session [`DpiGate`] and adds three things the server's
/// call site handles itself: (1) 1-in-`stride` packet sampling (mirroring the
/// gateway's 1-in-16 neural sampling — a verdict is per-window, not per-packet),
/// (2) a fire cooldown so one persistently-tunnel-looking flow raises at most
/// one request per window, and (3) the rotate-request payload to emit. It
/// implements [`crate::upload_pipeline::OutboundInspector`] so it drops straight
/// into `run_upload_loop` with no new wire message — the returned
/// [`ControlPayload::MaskPreference`] travels the client's existing mask-change
/// request path (the same message the polymorphic-mask retry task already sends).
#[cfg(feature = "client-dpi-gate")]
pub struct ClientSelfGate {
    gate: DpiGate,
    /// Base mask family to request a fresh variant of on a tunnel verdict.
    base_mask_id: String,
    /// Sample 1-in-`stride` outbound packets into the window.
    stride: u32,
    /// Rolling packet counter for the stride sampler.
    seen: u32,
    /// After a request is raised, suppress further requests for this many
    /// evaluated windows (avoids a request storm while a rotation is in flight).
    cooldown_windows: u32,
    /// Remaining suppressed windows.
    cooldown_left: u32,
}

#[cfg(feature = "client-dpi-gate")]
impl ClientSelfGate {
    /// Fixed synthetic session id — the client self-gate only ever tracks its
    /// own single flow, so one stable key into the underlying [`DpiGate`] ring.
    const SELF_SESSION: [u8; 16] = [0u8; 16];

    /// Первый внешний кадр и затем каждый шестнадцатый, как на сервере.
    pub const DEFAULT_STRIDE: u32 = 16;

    /// Number of evaluated windows to stay quiet after raising a request.
    pub const DEFAULT_COOLDOWN_WINDOWS: u32 = 8;

    /// Create a client self-gate that requests a fresh variant of `base_mask_id`
    /// when its own outbound flow reads as a tunnel above `threshold`.
    pub fn new(threshold: f32, base_mask_id: impl Into<String>) -> Self {
        Self {
            gate: DpiGate::new(threshold),
            base_mask_id: base_mask_id.into(),
            stride: Self::DEFAULT_STRIDE,
            seen: 0,
            cooldown_windows: Self::DEFAULT_COOLDOWN_WINDOWS,
            cooldown_left: 0,
        }
    }

    /// Override the 1-in-N outbound sampling stride (min 1).
    pub fn with_stride(mut self, stride: u32) -> Self {
        self.stride = stride.max(1);
        self
    }

    /// Override the post-request cooldown, in evaluated windows.
    pub fn with_cooldown_windows(mut self, windows: u32) -> Self {
        self.cooldown_windows = windows;
        self
    }

    /// Feed one outbound wire datagram. Returns the tunnel probability of the
    /// window that just crossed the threshold (i.e. `Some` only when a
    /// rotate-request should be raised), else `None`. Sampling + cooldown are
    /// applied internally so the caller can call this on every packet cheaply.
    pub fn observe_wire(&mut self, wire: &[u8]) -> Option<f32> {
        // Та же выборка, что у проверенных внешних кадров сервера:
        // первый кадр и затем каждый stride-й, без второго прореживания.
        let sample = self.seen.is_multiple_of(self.stride);
        self.seen = self.seen.wrapping_add(1);
        if !sample {
            return None;
        }
        self.gate.record_wire(Self::SELF_SESSION, wire);

        if self.cooldown_left > 0 {
            self.cooldown_left -= 1;
            return None;
        }

        let verdict = self.gate.verdict(&Self::SELF_SESSION)?;
        if verdict.reads_as_tunnel {
            self.cooldown_left = self.cooldown_windows;
            Some(verdict.tunnel_prob)
        } else {
            None
        }
    }

    /// The rotate-request control payload to send on a tunnel verdict — the
    /// client's existing `MaskPreference` mask-change request, not a new message.
    pub fn rotate_request(&self) -> crate::protocol::ControlPayload {
        crate::protocol::ControlPayload::MaskPreference {
            base_mask_id: self.base_mask_id.clone(),
        }
    }
}

#[cfg(feature = "client-dpi-gate")]
impl crate::upload_pipeline::OutboundInspector for ClientSelfGate {
    fn observe(&mut self, wire: &[u8]) -> Option<crate::protocol::ControlPayload> {
        match self.observe_wire(wire) {
            Some(prob) => {
                tracing::warn!(
                    "client ML-DPI self-gate: own outbound flow reads as tunnel \
                     (p={:.3}) — requesting mask rotation (MaskPreference base='{}')",
                    prob,
                    self.base_mask_id
                );
                Some(self.rotate_request())
            }
            None => None,
        }
    }
}

#[cfg(all(test, feature = "client-dpi-gate"))]
impl ClientSelfGate {
    /// One already-normalized window. Live packets still enter through
    /// [`ClientSelfGate::observe_wire`]. Tests use this to inject a shipped
    /// feature vector without adding that vector to training.
    fn observe_features(
        &mut self,
        x: &[f32; model::N_FEATURES],
    ) -> Option<crate::protocol::ControlPayload> {
        if self.cooldown_left > 0 {
            self.cooldown_left -= 1;
            return None;
        }
        let prob = tunnel_probability(x);
        if prob > self.gate.threshold() {
            self.cooldown_left = self.cooldown_windows;
            Some(self.rotate_request())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── features.py reference generators (ported verbatim) ───────────────────
    fn stun_pkt(msg_len: usize, total: usize) -> Vec<u8> {
        let mut p = vec![
            0x00,
            0x01,
            ((msg_len >> 8) & 0xff) as u8,
            (msg_len & 0xff) as u8,
            0x21,
            0x12,
            0xa4,
            0x42,
        ];
        for i in 0..(total - 8) {
            p.push(((i * 37 + 11) & 0xff) as u8);
        }
        p.truncate(total);
        p
    }
    fn rnd_pkt(total: usize, seed: usize) -> Vec<u8> {
        (0..total)
            .map(|i| ((seed * 131 + i * 97 + 7) & 0xff) as u8)
            .collect()
    }

    /// Feature extraction must reproduce `tools/dpi/features.py` on this window.
    #[test]
    fn feature_extraction_matches_python_reference() {
        let window: Vec<PacketMeta> = [
            stun_pkt(56, 76), // msg_len 56 + 20 == 76  -> lenok
            stun_pkt(20, 40), // 20 + 20 == 40          -> lenok
            stun_pkt(8, 28),  // 8 + 20 == 28           -> lenok
            rnd_pkt(1100, 3), // tunnel, large
            rnd_pkt(1200, 9), // tunnel, large
            rnd_pkt(200, 21), // tunnel, small
        ]
        .iter()
        .map(|p| PacketMeta::from_wire(p))
        .collect();

        let got = extract_features(&window);
        // From features.py on the identical window (IAT features dropped):
        assert_eq!(model::N_FEATURES, 23);
        assert_eq!(WINDOW, 24);
        let want: [f32; model::N_FEATURES] = [
            6.0,
            440.666_67,
            505.476_23,
            28.0,
            1200.0,
            76.0,
            28.0,
            1100.0,
            0.5,
            0.166_666_67,
            0.0,
            0.0,
            0.333_333_34,
            0.0,
            3.9375,
            6.625_917_5,
            84.0,
            0.5,
            0.166_666_67,
            0.5,
            0.5,
            0.5,
            0.0,
        ];
        for i in 0..model::N_FEATURES {
            let tol = 1e-3 * want[i].abs().max(1.0);
            assert!(
                (got[i] - want[i]).abs() <= tol,
                "feature {} ({}): got {} want {}",
                i,
                FEATURE_NAMES[i],
                got[i],
                want[i]
            );
        }
    }

    const FEATURE_NAMES: [&str; model::N_FEATURES] = [
        "n_pkts",
        "sz_mean",
        "sz_std",
        "sz_min",
        "sz_max",
        "sz_med",
        "sz_p10",
        "sz_p90",
        "szfrac_0_100",
        "szfrac_100_300",
        "szfrac_300_600",
        "szfrac_600_1000",
        "szfrac_1000_1400",
        "szfrac_1400p",
        "ent_first16",
        "ent_full",
        "byte0_mean",
        "byte0_msb_frac",
        "quic_longform_frac",
        "stun_type_frac",
        "stun_magic_frac",
        "stun_lenconsistent_frac",
        "dns_looksdns_frac",
    ];

    /// Per-packet structural flags line up with nDPI's checks.
    #[test]
    fn packet_meta_flags() {
        let stun = PacketMeta::from_wire(&stun_pkt(56, 76));
        assert!(stun.stun_type && stun.magic_ok && stun.stun_lenok);
        let junk = PacketMeta::from_wire(&rnd_pkt(1100, 3));
        assert!(!junk.stun_type && !junk.magic_ok);
    }

    fn feature_row(value: &serde_json::Value) -> [f32; model::N_FEATURES] {
        let items = value.as_array().expect("feature vector");
        assert_eq!(items.len(), model::N_FEATURES);
        let mut out = [0.0f32; model::N_FEATURES];
        for (index, item) in items.iter().enumerate() {
            out[index] = item.as_f64().expect("feature") as f32;
        }
        out
    }

    fn windows() -> Vec<serde_json::Value> {
        include_str!("../../../assets/dpi/windows.jsonl")
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("windows.jsonl"))
            .collect()
    }

    #[test]
    fn independent_wireguard_captures_are_detected_without_training_on_them() {
        use sha2::{Digest, Sha256};
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "../../../assets/dpi/external_vpn_fixtures.json"
        ))
        .unwrap();
        assert_eq!(evidence["training_use"], false);
        assert_eq!(evidence["training_overlap_checked"], true);
        assert_eq!(
            evidence["model_sha256"],
            format!("{:x}", Sha256::digest(include_bytes!("dpi_gate/model.rs")))
        );
        assert_eq!(
            evidence["training_provenance_sha256"],
            format!(
                "{:x}",
                Sha256::digest(include_bytes!("../../../assets/dpi/provenance.json"))
            )
        );
        assert_eq!(evidence["captures"].as_array().unwrap().len(), 3);
        let mut windows = 0;
        for capture in evidence["captures"].as_array().unwrap() {
            assert!(capture["teacher_protocols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|protocol| protocol == "WireGuard"));
            for row in capture["rows"].as_array().unwrap() {
                let probability = tunnel_probability(&feature_row(&row["x"]));
                assert!((probability - row["p"].as_f64().unwrap() as f32).abs() < 1e-6);
                assert!(probability > 0.5);
                windows += 1;
            }
        }
        assert_eq!(windows, 15);
        assert_eq!(evidence["detected"], windows);
    }

    /// Shipped session-holdout windows keep the reported probability and class.
    /// The model must beat the train-majority constant by a margin fixed before
    /// scoring. Stale hand-written vectors are not part of this check.
    #[test]
    fn heldout_fixtures_match_model_and_beat_constant() {
        const MATERIAL: f32 = 0.05;
        let heldout: serde_json::Value =
            serde_json::from_str(include_str!("../../../assets/dpi/heldout_fixtures.json"))
                .unwrap();
        assert_eq!(heldout["schema"].as_u64(), Some(2));
        assert!((heldout["threshold"].as_f64().unwrap() as f32 - 0.5).abs() < 1e-6);
        assert!((heldout["material_margin"].as_f64().unwrap() as f32 - MATERIAL).abs() < 1e-6);
        let gate = DpiGate::new(0.5);
        let rows = windows();
        let train: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|row| row["partition"].as_str() == Some("train"))
            .collect();
        let train_tunnel = train
            .iter()
            .filter(|row| row["y"].as_i64().unwrap() == 1)
            .count();
        assert_eq!(train.len() as u64, heldout["train_count"].as_u64().unwrap());
        assert_eq!(
            train_tunnel as u64,
            heldout["train_tunnel_count"].as_u64().unwrap()
        );
        let majority_tunnel = train_tunnel * 2 >= train.len();
        let shipped = heldout["rows"].as_array().unwrap();
        let test_rows: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|row| row["partition"].as_str() == Some("test"))
            .collect();
        assert_eq!(test_rows.len(), shipped.len());
        let mut masks = std::collections::BTreeSet::new();
        let mut correct = 0usize;
        let mut benign = 0usize;
        let mut false_tunnel = 0usize;
        let mut tunnel_rows = 0usize;
        for row in &test_rows {
            assert_eq!(row["stride"].as_u64(), Some(24));
            masks.insert(row["mask_id"].as_str().unwrap().to_string());
            let matched = shipped.iter().find(|item| {
                item["mask_id"] == row["mask_id"]
                    && item["role"] == row["role"]
                    && item["variant"] == row["variant"]
                    && item["start"] == row["start"]
            });
            let matched = matched.expect("heldout row missing");
            let features = feature_row(&row["x"]);
            assert_eq!(features, feature_row(&matched["x"]));
            let reported = matched["p"].as_f64().unwrap() as f32;
            let got = tunnel_probability(&features);
            assert!(
                (got - reported).abs() <= 1e-4,
                "{} got {got} reported {reported}",
                row["capture_id"]
            );
            assert_eq!(got > gate.threshold(), reported > gate.threshold());
            let pred = got > gate.threshold();
            let is_tunnel = row["y"].as_i64().unwrap() == 1;
            if pred == is_tunnel {
                correct += 1;
            }
            if is_tunnel {
                tunnel_rows += 1;
            } else {
                benign += 1;
                if pred {
                    false_tunnel += 1;
                }
            }
        }
        assert_eq!(
            masks.len(),
            10,
            "every family must appear in the test capture"
        );
        let n = test_rows.len() as f32;
        let model_acc = correct as f32 / n;
        let model_fp = false_tunnel as f32 / benign as f32;
        let majority_acc = if majority_tunnel {
            tunnel_rows as f32 / n
        } else {
            (test_rows.len() - tunnel_rows) as f32 / n
        };
        let majority_fp = if majority_tunnel { 1.0 } else { 0.0 };
        assert!(
            model_acc > majority_acc + MATERIAL,
            "accuracy {model_acc} does not beat constant {majority_acc} by {MATERIAL}"
        );
        assert!(
            model_fp + MATERIAL < majority_fp,
            "false tunnel rate {model_fp} is not materially below constant {majority_fp}"
        );
    }

    /// Ring buffers to WINDOW and only judges once full.
    #[test]
    fn gate_window_fill_and_verdict() {
        let gate = DpiGate::new(0.5);
        let sid = [7u8; 16];
        for _ in 0..(WINDOW - 1) {
            gate.record_wire(sid, &stun_pkt(56, 76));
        }
        assert!(
            gate.verdict(&sid).is_none(),
            "under-full window must abstain"
        );
        gate.record_wire(sid, &stun_pkt(56, 76));
        let verdict = gate.verdict(&sid).expect("full window must judge");
        assert_eq!(
            verdict.reads_as_tunnel,
            verdict.tunnel_prob > gate.threshold()
        );
        gate.cleanup(&sid);
        assert!(gate.verdict(&sid).is_none());
    }

    /// The baked ensemble is small (well under the neural MLP's per-mask 66 KB).
    #[test]
    fn embedded_model_is_small() {
        let bytes = embedded_model_bytes();
        assert!(
            bytes < 64 * 1024,
            "embedded model unexpectedly large: {bytes}"
        );
    }

    #[cfg(feature = "client-dpi-gate")]
    fn heldout_side(above: bool) -> [f32; model::N_FEATURES] {
        let heldout: serde_json::Value =
            serde_json::from_str(include_str!("../../../assets/dpi/heldout_fixtures.json"))
                .unwrap();
        let row = heldout["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| (row["p"].as_f64().unwrap() > 0.5) == above)
            .expect("heldout has no window on this side of 0.5");
        feature_row(&row["x"])
    }

    /// A shipped below-threshold window stays quiet. A shipped above-threshold
    /// window raises one rotate request and then honors the cooldown.
    #[cfg(feature = "client-dpi-gate")]
    #[test]
    fn client_self_gate_follows_shipped_window() {
        use crate::protocol::ControlPayload;

        let below = heldout_side(false);
        let mut quiet = ClientSelfGate::new(0.5, "quic-web").with_cooldown_windows(1);
        for _ in 0..4 {
            assert!(quiet.observe_features(&below).is_none());
        }

        let above = heldout_side(true);
        let mut gate = ClientSelfGate::new(0.5, "quic-web").with_cooldown_windows(4);
        match gate.observe_features(&above) {
            Some(ControlPayload::MaskPreference { base_mask_id }) => {
                assert_eq!(base_mask_id, "quic-web");
            }
            other => panic!("expected a rotate request, got {other:?}"),
        }
        for _ in 0..4 {
            assert!(gate.observe_features(&above).is_none());
        }
        assert!(gate.observe_features(&above).is_some());
    }

    #[cfg(feature = "client-dpi-gate")]
    #[test]
    fn client_evaluates_the_first_complete_sampled_window() {
        let mut client = ClientSelfGate::new(0.0, "base").with_cooldown_windows(0);
        let server = DpiGate::new(0.0);
        for index in 0..(WINDOW * ClientSelfGate::DEFAULT_STRIDE as usize) {
            let packet = rnd_pkt(1200, index + 1);
            if index % ClientSelfGate::DEFAULT_STRIDE as usize == 0 {
                server.record_wire(ClientSelfGate::SELF_SESSION, &packet);
            }
            let verdict = client.observe_wire(&packet);
            if index == (WINDOW - 1) * ClientSelfGate::DEFAULT_STRIDE as usize {
                assert_eq!(
                    verdict,
                    Some(
                        server
                            .verdict(&ClientSelfGate::SELF_SESSION)
                            .unwrap()
                            .tunnel_prob
                    )
                );
            } else {
                assert!(verdict.is_none());
            }
        }
    }

    /// Fewer than WINDOW sampled packets never raises, whatever the model
    /// would say about a full window of those bytes.
    #[cfg(feature = "client-dpi-gate")]
    #[test]
    fn client_self_gate_abstains_before_full_window() {
        let mut gate = ClientSelfGate::new(0.5, "base").with_stride(1);
        for _ in 0..(WINDOW - 1) {
            assert!(gate.observe_wire(&rnd_pkt(1200, 5)).is_none());
        }
    }
}
