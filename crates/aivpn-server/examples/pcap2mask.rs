//! pcap2mask — e2e harness helper (Part 2).
//!
//! Reads a libpcap capture of a real target protocol (e.g. the WebRTC/QUIC/DNS
//! corpora under `research/mask-generation/realcap2/`), turns each packet into a
//! `PacketMetadata`, and runs the production `mask_gen::generate_and_store_mask`
//! pipeline — the same code the gateway runs when a `RecordingManager` capture
//! finishes. It then reports whether the generated mask carries R3
//! (`size_iat_joint`) and R4 (`fsm_states`), and writes the mask JSON to a
//! `--mask-dir` so eval-gate/nDPI and a live server can consume it.
//!
//! Usage:
//!   cargo run --release -p aivpn-server --example pcap2mask -- \
//!     <capture.pcap> <service_name> <out_mask_dir>
//!
//! Exit codes: 0 = mask generated (prints R3/R4 presence), 1 = generation
//! failed, 2 = usage / unreadable pcap.

use std::path::Path;
use std::sync::Arc;

use aivpn_common::mask::MaskVerifyMode;
use aivpn_common::recording::{Direction, PacketMetadata};
use aivpn_server::gateway::MaskCatalog;
use aivpn_server::mask_gen::generate_and_store_mask;
use aivpn_server::mask_store::MaskStore;

/// Minimal little-/big-endian libpcap reader. Returns (orig_len, captured
/// bytes, timestamp_ns) per record. Supports the classic 0xa1b2c3d4 (µs) and
/// 0xa1b23c4d (ns) magics in either byte order.
fn read_pcap(path: &Path) -> Result<Vec<(u32, Vec<u8>, u64)>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if data.len() < 24 {
        return Err("pcap shorter than global header".into());
    }
    let magic = &data[0..4];
    let (be, nanos) = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        _ => return Err(format!("unknown pcap magic {magic:02x?}")),
    };
    let rd32 = |b: &[u8]| -> u32 {
        if be {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let link_type = rd32(&data[20..24]);
    // Bytes to strip to reach the IP/UDP payload we want to size-model. TUN/raw
    // IP (101/12/14) start at IP; Ethernet (1) has a 14-byte header.
    let l2 = match link_type {
        1 => 14,
        _ => 0,
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
        let payload_start = (off + l2).min(data.len());
        let payload = data[payload_start..off + incl].to_vec();
        out.push((orig, payload, ts_ns));
        off += incl;
    }
    Ok(out)
}

fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f32 / n;
            h -= p * p.log2();
        }
    }
    h
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: pcap2mask <capture.pcap> <service_name> <out_mask_dir>");
        std::process::exit(2);
    }
    let pcap = Path::new(&args[1]);
    let service = &args[2];
    let mask_dir = &args[3];

    let records = match read_pcap(pcap) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("pcap2mask: {e}");
            std::process::exit(2);
        }
    };
    if records.is_empty() {
        eprintln!("pcap2mask: no packets in {}", pcap.display());
        std::process::exit(2);
    }

    // These realcap2 captures are the raw PLAINTEXT target protocol. Model them
    // as the RecordingManager would see them once carried through the tunnel:
    //  * size / iat: the real target-protocol values — the signal R3 (size↔iat
    //    joint) and R4 (temporal FSM) are derived from.
    //  * header_prefix: a SINGLE consistent template. A mask reproduces one MDH
    //    template per protocol, so use the corpus's modal application-header
    //    prefix (raw IPv4/UDP linktype → skip IPv4(20)+UDP(8)=28 B). Real
    //    WebRTC/QUIC headers vary packet-to-packet; the mode is the representative
    //    the mask would carry, and keeping it consistent is what the self-test's
    //    header_match measures.
    //  * entropy: the tunnel packet is ENCRYPTED, so clamp to encrypted-level
    //    (≥6.5) — a low-entropy plaintext protocol like DNS still rides an
    //    encrypted, high-entropy tunnel packet whose only mimicry is the MDH.
    let app_prefix = |payload: &[u8]| -> Vec<u8> {
        let off = if payload.len() > 28 { 28 } else { 0 };
        payload[off..].iter().take(16).copied().collect()
    };
    // Modal application-header prefix across the corpus.
    let mut prefix_counts: std::collections::HashMap<Vec<u8>, usize> =
        std::collections::HashMap::new();
    for (_, payload, _) in &records {
        *prefix_counts.entry(app_prefix(payload)).or_insert(0) += 1;
    }
    let modal_prefix = prefix_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(p, _)| p)
        .unwrap_or_default();

    let mut packets = Vec::with_capacity(records.len());
    let mut prev_ns: Option<u64> = None;
    for (orig, payload, ts_ns) in &records {
        let iat_ms = match prev_ns {
            Some(p) if *ts_ns >= p => (*ts_ns - p) as f64 / 1_000_000.0,
            _ => 0.0,
        };
        prev_ns = Some(*ts_ns);
        packets.push(PacketMetadata {
            direction: Direction::Uplink,
            size: (*orig).min(u16::MAX as u32) as u16,
            iat_ms,
            entropy: shannon_entropy(payload).max(6.5),
            header_prefix: modal_prefix.clone(),
            timestamp_ns: *ts_ns,
        });
    }

    println!(
        "pcap2mask: {} packets from {} (service='{}')",
        packets.len(),
        pcap.display(),
        service
    );

    // add_mask (called inside generate_and_store_mask) persists to storage_dir.
    let store = Arc::new(MaskStore::new(
        Arc::new(MaskCatalog::new()),
        std::path::PathBuf::from(mask_dir),
        None,
        None,
        MaskVerifyMode::default(),
    ));
    match generate_and_store_mask(service, &packets, &store).await {
        Ok(mask_id) => {
            let entry = store
                .get_mask(&mask_id)
                .expect("mask in store after generation");
            let p = &entry.profile;
            let r3 = p.size_iat_joint.is_some();
            println!("MASK_ID={mask_id}");
            println!("SPOOF_PROTOCOL={:?}", p.spoof_protocol);
            println!("R3_size_iat_joint={r3}");
            println!("R4_fsm_states_count={}", p.fsm_states.len());
            println!(
                "size_dist={:?} iat_dist={:?} confidence={:.2}",
                p.size_distribution.dist_type, p.iat_distribution.dist_type, entry.stats.confidence
            );
            // generate_and_store_mask -> add_mask -> save_to_disk already
            // persisted <mask_dir>/<mask_id>.json.
            println!("SAVED={}/{}.json", mask_dir, mask_id);
        }
        Err(e) => {
            eprintln!("pcap2mask: generation failed: {e}");
            std::process::exit(1);
        }
    }
}
