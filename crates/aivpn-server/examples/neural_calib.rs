//! neural_calib — Neural Resonance MSE threshold calibration (night-sprint B1 / Part 6).
//!
//! Feeds the REAL-capture corpora under `research/mask-generation/realcap2/`
//! through each bundled mask's baked autoencoder exactly the way the gateway
//! does (uplink-only sampling, encrypted-payload entropy, real inter-arrival
//! gaps) and reports the reconstruction-MSE distribution of HEALTHY
//! (uncompromised) traffic. The warm-up defaults `compromised_threshold` /
//! `warning_threshold` in `NeuralConfig::default()` must sit safely ABOVE the
//! healthy p99 so normal traffic can never false-trigger a mask rotation
//! before the per-mask adaptive calibration (mean+3σ) takes over.
//!
//! Corpus↔mask matching: WebRTC_STUN masks ← real_webrtc_inner.pcap,
//! QUIC masks ← real_quicbulk_inner.pcap.
//!
//! Usage:
//!   cargo run --release -p aivpn-server --example neural_calib
//!     [masks_dir] [realcap2_dir]
//! Defaults: assets/masks and research/mask-generation/realcap2 relative to
//! the workspace root (two levels above CARGO_MANIFEST_DIR).

use std::path::{Path, PathBuf};

use aivpn_common::mask::{MaskProfile, SpoofProtocol};
use aivpn_server::neural::{encode_features, BakedMaskEncoder, TrafficStats};

/// Mirror of `neural::MIN_SAMPLES_FOR_CHECK` (private const): the minimum
/// window size before `check_resonance` trusts an MSE at all.
const MIN_SAMPLES_FOR_CHECK: usize = 32;

/// Representative tunnel wire overhead added to each inner-packet size:
/// mask MDH header (14–20 B incl. embedded tag) + pad_len(1) + inner
/// header(4) + Poly1305 tag(16) ≈ 40 B. The gateway records
/// `packet_data.len()` (the full wire datagram), not the inner IP size.
const WIRE_OVERHEAD: u16 = 40;

/// Minimal libpcap reader (LE/BE, µs/ns). Returns (orig_len, ts_ns) per
/// record — same parsing pattern as examples/pcap2mask.rs (linktype 101 =
/// RAW IP, no L2 header to strip; sizes come from orig_len).
fn read_pcap_sizes(path: &Path) -> Result<Vec<(u32, u64)>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if data.len() < 24 {
        return Err("pcap shorter than global header".into());
    }
    let (be, nanos) = match &data[0..4] {
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        m => return Err(format!("unknown pcap magic {m:02x?}")),
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
    Ok(out)
}

/// Deterministic stand-in for the encrypted wire payload's Shannon entropy:
/// the gateway computes `compute_entropy(encrypted_payload)` — ciphertext is
/// computationally indistinguishable from uniform random bytes, so generate
/// `len` pseudo-random bytes from a per-packet BLAKE3 XOF and measure their
/// entropy. This reproduces the size-dependent entropy curve (small packets
/// cannot reach 8 bits/byte) without needing real ciphertext.
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

/// Feed a corpus through one mask's encoder; return the MSE of every
/// evaluation point once the window holds ≥ MIN_SAMPLES_FOR_CHECK samples
/// (window then slides at the TrafficStats-native 256-sample capacity —
/// exactly the buffer `check_resonance` sees at an arbitrary check instant).
fn mse_windows(encoder: &BakedMaskEncoder, corpus: &[(u32, u64)]) -> Vec<f32> {
    let mut stats = TrafficStats::new();
    let mut prev_ns: Option<u64> = None;
    let mut out = Vec::with_capacity(corpus.len());
    for (i, (orig, ts_ns)) in corpus.iter().enumerate() {
        let iat_ms = match prev_ns {
            Some(p) if *ts_ns >= p => (*ts_ns - p) as f64 / 1_000_000.0,
            _ => 0.0,
        };
        prev_ns = Some(*ts_ns);
        let wire_size = (*orig).min(u16::MAX as u32 - WIRE_OVERHEAD as u32) as u16 + WIRE_OVERHEAD;
        let entropy = ciphertext_entropy(i as u64, wire_size as usize);
        // Gateway records uplink only (is_rx=true) into the neural stats.
        stats.add_packet(wire_size, iat_ms, entropy, true);
        if stats.packet_sizes.len() >= MIN_SAMPLES_FOR_CHECK {
            let features = encode_features(&stats);
            out.push(encoder.reconstruction_error(&features));
        }
    }
    out
}

struct Dist {
    n: usize,
    min: f32,
    mean: f32,
    median: f32,
    p90: f32,
    p99: f32,
    max: f32,
    std: f32,
}

fn dist(mses: &[f32]) -> Dist {
    let mut s: Vec<f32> = mses.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    let mean = s.iter().sum::<f32>() / n as f32;
    let var = s.iter().map(|x| (x - mean) * (x - mean)).sum::<f32>() / n as f32;
    let q = |p: f64| s[((n as f64 - 1.0) * p).round() as usize];
    Dist {
        n,
        min: s[0],
        mean,
        median: q(0.5),
        p90: q(0.90),
        p99: q(0.99),
        max: s[n - 1],
        std: var.sqrt(),
    }
}

fn print_dist(label: &str, d: &Dist) {
    println!(
        "{label:<28} n={:<6} min={:.4} mean={:.4} median={:.4} p90={:.4} p99={:.4} max={:.4} std={:.4}",
        d.n, d.min, d.mean, d.median, d.p90, d.p99, d.max, d.std
    );
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let args: Vec<String> = std::env::args().collect();
    let masks_dir = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("assets/masks"));
    let realcap = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("research/mask-generation/realcap2"));

    let webrtc = read_pcap_sizes(&realcap.join("real_webrtc_inner.pcap")).expect("webrtc pcap");
    let quic = read_pcap_sizes(&realcap.join("real_quicbulk_inner.pcap")).expect("quic pcap");
    println!(
        "corpora: webrtc={} pkts, quicbulk={} pkts (wire overhead +{WIRE_OVERHEAD}B)",
        webrtc.len(),
        quic.len()
    );

    let mut all: Vec<f32> = Vec::new();
    let mut fam_webrtc: Vec<f32> = Vec::new();
    let mut fam_quic: Vec<f32> = Vec::new();
    let mut cross: Vec<f32> = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(&masks_dir)
        .expect("masks dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort();

    for path in entries {
        let mask: MaskProfile =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read mask"))
                .expect("parse mask");
        let (corpus, other, fam) = match mask.spoof_protocol {
            SpoofProtocol::WebRTC_STUN
            | SpoofProtocol::WebRTC_DTLS_SRTP
            | SpoofProtocol::WebRTC_TURN_DTLS_SRTP
            | SpoofProtocol::WebRTC_SDES_SRTP => (&webrtc, &quic, "webrtc"),
            SpoofProtocol::QUIC => (&quic, &webrtc, "quic"),
            _ => {
                println!("{:<28} skipped (no matching corpus)", mask.mask_id);
                continue;
            }
        };
        let encoder = BakedMaskEncoder::from_signature(&mask.signature_vector, 128);
        let mses = mse_windows(&encoder, corpus);
        let d = dist(&mses);
        print_dist(&format!("{} [{}]", mask.mask_id, fam), &d);
        match fam {
            "webrtc" => fam_webrtc.extend_from_slice(&mses),
            _ => fam_quic.extend_from_slice(&mses),
        }
        all.extend_from_slice(&mses);
        // Cross-family (WRONG corpus through this mask) — approximates the MSE
        // of shape-anomalous traffic, i.e. the separation headroom available.
        cross.extend_from_slice(&mse_windows(&encoder, other));
    }

    println!("──");
    print_dist("FAMILY webrtc (all masks)", &dist(&fam_webrtc));
    print_dist("FAMILY quic   (all masks)", &dist(&fam_quic));
    print_dist("OVERALL healthy (matched)", &dist(&all));
    print_dist("CROSS (mismatched corpus)", &dist(&cross));
}
