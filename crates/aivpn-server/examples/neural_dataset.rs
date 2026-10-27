//! Готовит выборки MLP из PCAP: neural_dataset MASK PCAP WIRE_OVERHEAD.
//! JSON идет в stdout, описание разделения без данных пакетов - в stderr.

use std::path::Path;

use aivpn_common::mask::MaskProfile;
use aivpn_server::neural_corpus::{feature_windows, read_capture};
use aivpn_server::neural_training::read_bounded_file;

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("Использование: neural_dataset MASK.json CAPTURE.pcap WIRE_OVERHEAD".into());
    }
    let overhead: u16 = args[2]
        .parse()
        .map_err(|_| "Некорректная надбавка к размеру")?;
    if overhead > 512 {
        return Err("Надбавка не должна превышать 512 байт".into());
    }
    let mask_bytes = read_bounded_file(Path::new(&args[0]), 8 * 1024 * 1024)
        .map_err(|error| error.to_string())?;
    let mask: MaskProfile =
        serde_json::from_slice(&mask_bytes).map_err(|error| error.to_string())?;
    if mask.signature_vector.len() != 64
        || mask.signature_vector.iter().any(|value| !value.is_finite())
    {
        return Err("Профиль должен содержать 64 конечных значения сигнатуры".into());
    }
    let signature: Vec<_> = mask
        .signature_vector
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let capture = read_capture(Path::new(&args[1]), overhead)?;
    let count = capture.packets.len();
    // Буферы статистики начинаются заново. Между частями дополнительно
    // пропускаются по 256 исходных пакетов, чтобы разнести соседние серии.
    let middle = count / 2;
    let last = count * 3 / 4;
    if middle < 128 || last < middle + 256 || count < last + 128 {
        return Err("Запись слишком короткая для трех независимых частей".into());
    }
    let ranges = [
        (0, middle - 128),
        (middle + 128, last - 128),
        (last + 128, count),
    ];
    let parts: Vec<_> = ranges
        .iter()
        .map(|&(start, end)| feature_windows(&capture.packets[start..end]))
        .collect();
    if parts.iter().any(|part| part.len() < 16) {
        return Err(
            "В каждой части нужны хотя бы 16 окон признаков; используйте более длинную запись"
                .into(),
        );
    }
    eprintln!(
        "{}",
        serde_json::json!({
            "mask_id": mask.mask_id,
            "capture_digest": capture.digest,
            "source_packets": count,
            "partition_ranges": ranges,
            "partition_windows": parts.iter().map(Vec::len).collect::<Vec<_>>(),
            "sampling_stride": 16,
            "wire_overhead": overhead,
            "entropy_source": "deterministic uniform ciphertext of observed length",
            "split": "chronological 50/25/25 with disjoint packets and 256-packet embargo",
        })
    );
    let dataset = serde_json::json!({
        "schema_version": 1,
        "feature_version": 1,
        "signature_hash": blake3::hash(&signature).to_hex().to_string(),
        "signature": mask.signature_vector,
        "train": parts[0],
        "validation": parts[1],
        "test": parts[2],
    });
    serde_json::to_writer(std::io::stdout().lock(), &dataset).map_err(|error| error.to_string())?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
