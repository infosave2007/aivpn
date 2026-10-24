//! Подготовка признаков из записанного трафика без экспорта содержимого пакетов.

use std::path::Path;

use crate::neural::{encode_features, TrafficStats};

const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKETS: usize = 1_000_000;

#[derive(Clone, Copy, Debug)]
pub struct CorpusPacket {
    pub size: u16,
    pub timestamp_ns: u64,
}

pub struct Capture {
    pub digest: String,
    pub packets: Vec<CorpusPacket>,
}

/// Читает classic PCAP. Надбавка задается явно: внутренний IP-пакет и
/// наблюдение сервером шифрованной датаграммы имеют разные размеры.
pub fn read_capture(path: &Path, wire_overhead: u16) -> Result<Capture, String> {
    let data = crate::neural_training::read_bounded_file(path, MAX_CAPTURE_BYTES)
        .map_err(|error| error.to_string())?;
    parse_capture(&data, wire_overhead)
}

fn parse_capture(data: &[u8], wire_overhead: u16) -> Result<Capture, String> {
    if data.len() < 24 {
        return Err("Оборван заголовок PCAP".into());
    }
    let (big_endian, nanoseconds) = match &data[..4] {
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        _ => return Err("Нужен classic PCAP с микросекундами или наносекундами".into()),
    };
    let word = |bytes: &[u8]| {
        let bytes: [u8; 4] = bytes.try_into().expect("проверенный размер поля PCAP");
        if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };
    let linktype = word(&data[20..24]);
    if linktype != 101 {
        return Err("Для внутреннего трафика нужен PCAP с linktype RAW (101)".into());
    }
    let mut packets = Vec::new();
    let mut offset = 24usize;
    while offset < data.len() {
        if data.len() - offset < 16 {
            return Err("Оборван заголовок пакета PCAP".into());
        }
        let header = &data[offset..offset + 16];
        let seconds = word(&header[..4]) as u64;
        let fraction = word(&header[4..8]) as u64;
        let captured = word(&header[8..12]) as usize;
        let original = word(&header[12..16]);
        offset += 16;
        if captured > original as usize || captured > data.len() - offset {
            return Err("Оборвана или повреждена запись пакета PCAP".into());
        }
        if fraction
            >= if nanoseconds {
                1_000_000_000
            } else {
                1_000_000
            }
        {
            return Err("Некорректная доля секунды PCAP".into());
        }
        if original == 0 || original > (u16::MAX - wire_overhead) as u32 {
            return Err("Размер пакета не помещается в наблюдение VPN".into());
        }
        let timestamp_ns = seconds * 1_000_000_000 + fraction * if nanoseconds { 1 } else { 1000 };
        if packets
            .last()
            .is_some_and(|previous: &CorpusPacket| previous.timestamp_ns > timestamp_ns)
        {
            return Err("Временные метки PCAP идут в обратном порядке".into());
        }
        if packets.len() == MAX_PACKETS {
            return Err("Слишком много пакетов PCAP".into());
        }
        packets.push(CorpusPacket {
            size: original as u16 + wire_overhead,
            timestamp_ns,
        });
        offset += captured;
    }
    if packets.is_empty() {
        return Err("PCAP не содержит пакетов".into());
    }
    Ok(Capture {
        digest: blake3::hash(data).to_hex().to_string(),
        packets,
    })
}

/// Энтропия шифрованной части моделируется равномерными байтами той же длины.
/// Из PCAP берутся реальные размеры и время; полезная нагрузка не экспортируется.
fn ciphertext_entropy(index: usize, length: usize) -> f64 {
    let mut bytes = vec![0; length];
    blake3::Hasher::new()
        .update(b"aivpn-neural-corpus-v1")
        .update(&(index as u64).to_le_bytes())
        .finalize_xof()
        .fill(&mut bytes);
    let mut histogram = [0u32; 256];
    for byte in bytes {
        histogram[byte as usize] += 1;
    }
    histogram
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length as f64;
            -probability * probability.log2()
        })
        .sum()
}

/// Каждая фаза повторяет серверную выборку каждого 16-го пакета. Соседние
/// признаки одной части могут перекрываться; между частями состояние не переносится.
pub fn feature_windows(packets: &[CorpusPacket]) -> Vec<Vec<f32>> {
    let entropy: Vec<_> = packets
        .iter()
        .enumerate()
        .map(|(index, packet)| ciphertext_entropy(index, packet.size as usize))
        .collect();
    let mut output = Vec::new();
    for phase in 0..16 {
        let mut statistics = TrafficStats::new();
        for index in (phase..packets.len()).step_by(16) {
            let packet = packets[index];
            let gap = if index == 0 {
                0.0
            } else {
                (packet.timestamp_ns - packets[index - 1].timestamp_ns) as f64 / 1_000_000.0
            };
            statistics.add_packet(packet.size, gap, entropy[index], true);
            if statistics.packet_sizes.len() >= 32 {
                output.push(encode_features(&statistics).to_vec());
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncation_and_invalid_timestamps_without_reading_payload() {
        let mut capture = vec![0; 24];
        capture[..4].copy_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        capture[20..24].copy_from_slice(&101u32.to_le_bytes());
        capture.extend_from_slice(&1u32.to_le_bytes());
        capture.extend_from_slice(&0u32.to_le_bytes());
        capture.extend_from_slice(&1u32.to_le_bytes());
        capture.extend_from_slice(&100u32.to_le_bytes());
        assert!(parse_capture(&capture, 40).is_err());
        capture.push(0);
        let parsed = parse_capture(&capture, 40).unwrap();
        assert_eq!(parsed.packets[0].size, 140);
        capture[28..32].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(parse_capture(&capture, 40).is_err());
    }

    #[test]
    fn windows_are_deterministic_and_use_only_the_requested_partition() {
        let packets: Vec<_> = (0..1024)
            .map(|index| CorpusPacket {
                size: 100 + (index % 10) as u16,
                timestamp_ns: index * 10_000_000,
            })
            .collect();
        let first = feature_windows(&packets[..600]);
        assert!(!first.is_empty());
        assert_eq!(first, feature_windows(&packets[..600]));
        assert!(first
            .iter()
            .flatten()
            .all(|value| value.is_finite() && (-1.0..=1.0).contains(value)));
        assert!(feature_windows(&packets[600..]).is_empty());
    }
}
