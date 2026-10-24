//! Ограниченная сборка фрагментов после проверки AEAD и защиты от повтора.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::fec::FecMetadata;
use crate::protocol::InnerType;

pub const FRAGMENT_DATA_SIZE: usize = 900;
pub const MAX_REASSEMBLED_SIZE: usize =
    crate::protocol::MAX_MGMT_BODY_SIZE + crate::protocol::MAX_MGMT_PATH_SIZE + 12;
const HEADER_SIZE: usize = 20;
const FEC_META_SIZE: usize = 4;
const MAX_IN_FLIGHT: usize = 4;
const MAX_DATA_IN_FLIGHT: usize = 8;
const ASSEMBLY_TTL: Duration = Duration::from_secs(10);

struct Assembly {
    kind: InnerType,
    fec: Option<FecMetadata>,
    total: usize,
    created: Instant,
    chunks: HashMap<usize, Vec<u8>>,
    received: usize,
}

pub struct Reassembled {
    pub kind: InnerType,
    pub payload: Vec<u8>,
    pub fec: Option<FecMetadata>,
}

#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<u64, Assembly>,
}

/// Каждый фрагмент шифруется отдельно с собственными nonce и sequence number.
pub fn split(kind: InnerType, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    if !matches!(
        kind,
        InnerType::Data | InnerType::Control | InnerType::FecRepair
    ) || payload.is_empty()
        || payload.len() > MAX_REASSEMBLED_SIZE
    {
        return Err(Error::InvalidPacket("Invalid fragmented payload"));
    }
    let id: u64 = rand::random();
    Ok(payload
        .chunks(FRAGMENT_DATA_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            let mut bytes = Vec::with_capacity(HEADER_SIZE + chunk.len());
            bytes.extend_from_slice(&[1, kind as u8, 0, 0]);
            bytes.extend_from_slice(&id.to_be_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&((index * FRAGMENT_DATA_SIZE) as u32).to_be_bytes());
            bytes.extend_from_slice(chunk);
            bytes
        })
        .collect())
}

/// Любой пакет под FEC уходит фрагментом, даже если он короче 900 байт.
/// Иначе ядро примет короткий Data напрямую и группа разъедется.
/// Номер группы и позиция добавляются после основного заголовка.
/// Случайный id сохраняет все 64 бита и не зависит от оборота номера группы.
pub fn split_fec_data(payload: &[u8], meta: FecMetadata) -> Result<Vec<Vec<u8>>> {
    if meta.group_size == 0 || meta.index >= meta.group_size {
        return Err(Error::InvalidPacket("Invalid FEC metadata"));
    }
    if payload.len() > crate::protocol::MAX_PACKET_SIZE {
        return Err(Error::InvalidPacket("FEC data exceeds packet budget"));
    }
    let mut packets = split(InnerType::Data, payload)?;
    let group = meta.group_seq.to_be_bytes();
    for packet in &mut packets {
        packet[2] = 1;
        packet[3] = FEC_META_SIZE as u8;
        packet.splice(
            HEADER_SIZE..HEADER_SIZE,
            [group[0], group[1], meta.group_size, meta.index],
        );
    }
    Ok(packets)
}

/// Метаданные из заголовка фрагмента. Полные offset и длину проверяет сборщик.
pub fn fec_metadata(bytes: &[u8]) -> Option<FecMetadata> {
    if bytes.len() < HEADER_SIZE + FEC_META_SIZE
        || bytes[0] != 1
        || bytes[1] != InnerType::Data as u8
        || bytes[2] != 1
        || bytes[3] != FEC_META_SIZE as u8
    {
        return None;
    }
    let group_size = bytes[HEADER_SIZE + 2];
    let index = bytes[HEADER_SIZE + 3];
    if group_size == 0 || index >= group_size {
        return None;
    }
    Some(FecMetadata {
        group_seq: u16::from_be_bytes([bytes[HEADER_SIZE], bytes[HEADER_SIZE + 1]]),
        group_size,
        index,
    })
}

impl Reassembler {
    /// Снимает только незавершенные FEC Data этой группы.
    /// Control, Repair и обычный Data остаются нетронутыми.
    pub fn discard_fec_group(&mut self, group_seq: u16) {
        self.pending.retain(|_, assembly| {
            !assembly
                .fec
                .is_some_and(|metadata| metadata.group_seq == group_seq)
        });
    }

    pub fn accept(&mut self, bytes: &[u8], now: Instant) -> Result<Option<(InnerType, Vec<u8>)>> {
        Ok(self
            .accept_detailed(bytes, now)?
            .map(|message| (message.kind, message.payload)))
    }

    pub fn accept_detailed(&mut self, bytes: &[u8], now: Instant) -> Result<Option<Reassembled>> {
        self.pending
            .retain(|_, assembly| now.saturating_duration_since(assembly.created) < ASSEMBLY_TTL);
        if bytes.len() <= HEADER_SIZE || bytes[0] != 1 || bytes[2] & !1 != 0 {
            return Err(Error::InvalidPacket("Invalid fragment header"));
        }
        let kind = match InnerType::from_u16(bytes[1] as u16) {
            Some(kind @ (InnerType::Data | InnerType::Control | InnerType::FecRepair)) => kind,
            _ => return Err(Error::InvalidPacket("Invalid fragment type")),
        };
        let flagged = bytes[2] == 1;
        if flagged && kind != InnerType::Data {
            return Err(Error::InvalidPacket("FEC flag requires data fragments"));
        }
        let header_size = HEADER_SIZE + if flagged { FEC_META_SIZE } else { 0 };
        if bytes.len() <= header_size || bytes[3] as usize != header_size - HEADER_SIZE {
            return Err(Error::InvalidPacket("Invalid fragment header extension"));
        }
        let id = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        let fec = if flagged {
            Some(fec_metadata(bytes).ok_or(Error::InvalidPacket("Invalid FEC fragment metadata"))?)
        } else {
            None
        };
        let total = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let offset = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let data = &bytes[header_size..];
        if total == 0
            || (kind == InnerType::Data && total > crate::protocol::MAX_PACKET_SIZE)
            || (kind == InnerType::FecRepair && total > crate::protocol::MAX_PACKET_SIZE + 3)
            || total > MAX_REASSEMBLED_SIZE
            || offset >= total
            || !offset.is_multiple_of(FRAGMENT_DATA_SIZE)
            || data.len() != FRAGMENT_DATA_SIZE.min(total - offset)
        {
            return Err(Error::InvalidPacket("Invalid fragment bounds"));
        }
        if !self.pending.contains_key(&id) {
            let control = kind == InnerType::Control;
            let count = self
                .pending
                .values()
                .filter(|assembly| (assembly.kind == InnerType::Control) == control)
                .count();
            let limit = if control {
                MAX_IN_FLIGHT
            } else {
                MAX_DATA_IN_FLIGHT
            };
            if count >= limit {
                if control {
                    return Err(Error::InvalidPacket("Too many fragmented messages"));
                }
                // Потерянная часть IP-пакета не блокирует новые данные до TTL.
                let oldest = self
                    .pending
                    .iter()
                    .filter(|(_, assembly)| assembly.kind != InnerType::Control)
                    .min_by_key(|(_, assembly)| assembly.created)
                    .map(|(id, _)| *id);
                if let Some(oldest) = oldest {
                    self.pending.remove(&oldest);
                }
            }
        }
        let assembly = self.pending.entry(id).or_insert_with(|| Assembly {
            kind,
            fec,
            total,
            created: now,
            chunks: HashMap::new(),
            received: 0,
        });
        if assembly.kind != kind || assembly.total != total || assembly.fec != fec {
            self.pending.remove(&id);
            return Err(Error::InvalidPacket("Conflicting fragment metadata"));
        }
        if let Some(previous) = assembly.chunks.get(&offset) {
            if previous != data {
                self.pending.remove(&id);
                return Err(Error::InvalidPacket("Conflicting duplicate fragment"));
            }
            return Ok(None);
        }
        assembly.received += data.len();
        assembly.chunks.insert(offset, data.to_vec());
        if assembly.received != total {
            return Ok(None);
        }
        let assembly = self.pending.remove(&id).unwrap();
        let mut payload = Vec::with_capacity(total);
        for offset in (0..total).step_by(FRAGMENT_DATA_SIZE) {
            payload.extend_from_slice(&assembly.chunks[&offset]);
        }
        let fec = assembly.fec;
        Ok(Some(Reassembled { kind, payload, fec }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_control_reassembles_out_of_order_with_duplicates() {
        let payload: Vec<u8> = (0..262_160).map(|i| (i % 251) as u8).collect();
        let packets = split(InnerType::Control, &payload).unwrap();
        let now = Instant::now();
        let mut receiver = Reassembler::default();
        assert!(receiver.accept(&packets[0], now).unwrap().is_none());
        assert!(receiver.accept(&packets[0], now).unwrap().is_none());
        let mut result = None;
        for packet in packets[1..].iter().rev() {
            result = receiver.accept(packet, now).unwrap().or(result);
        }
        assert_eq!(result, Some((InnerType::Control, payload)));
        assert!(receiver.pending.is_empty());
    }

    #[test]
    fn malformed_conflicting_and_excessive_fragments_are_bounded() {
        let packets = split(InnerType::Control, &[42; 2000]).unwrap();
        let now = Instant::now();
        let mut receiver = Reassembler::default();
        receiver.accept(&packets[0], now).unwrap();
        let mut conflict = packets[0].clone();
        conflict[HEADER_SIZE] ^= 1;
        assert!(receiver.accept(&conflict, now).is_err());
        assert!(receiver.pending.is_empty());
        for _ in 0..MAX_IN_FLIGHT {
            let packet = split(InnerType::Control, &[42; 2000]).unwrap();
            receiver.accept(&packet[0], now).unwrap();
        }
        assert!(receiver.accept(&packets[0], now).is_err());
        assert!(receiver.accept(&packets[0], now + ASSEMBLY_TTL).is_ok());
        let mut huge = packets[0].clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(receiver.accept(&huge, now).is_err());
        assert!(split(InnerType::Fragment, &[0]).is_err());
        assert!(split(InnerType::Control, &vec![0; MAX_REASSEMBLED_SIZE + 1]).is_err());
    }

    #[test]
    fn incomplete_message_never_reaches_dispatch() {
        let packets = split(InnerType::Control, &[7; 2500]).unwrap();
        let mut receiver = Reassembler::default();
        let now = Instant::now();
        assert!(receiver.accept(&packets[0], now).unwrap().is_none());
        assert!(receiver.accept(&packets[2], now).unwrap().is_none());
        assert!(receiver
            .accept(&packets[1], now + ASSEMBLY_TTL)
            .unwrap()
            .is_none());
    }
    #[test]
    fn fec_metadata_is_authenticated_consistent_and_size_bounded() {
        let meta = FecMetadata {
            group_seq: 7,
            group_size: 3,
            index: 1,
        };
        let mut receiver = Reassembler::default();
        let now = Instant::now();
        let parts = split_fec_data(&[7; 1500], meta).unwrap();
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|part| fec_metadata(part) == Some(meta)));
        assert!(receiver.accept_detailed(&parts[0], now).unwrap().is_none());
        let mut changed = parts[1].clone();
        changed[HEADER_SIZE + 3] = 2;
        assert!(receiver.accept_detailed(&changed, now).is_err());
        assert!(receiver.pending.is_empty());
        for part in &parts[..parts.len() - 1] {
            receiver.accept_detailed(part, now).unwrap();
        }
        let message = receiver
            .accept_detailed(parts.last().unwrap(), now)
            .unwrap()
            .unwrap();
        assert!(message.fec.is_some());
        assert_eq!(message.fec, Some(meta));
        assert_eq!(message.payload, vec![7; 1500]);
        let parity = split(InnerType::FecRepair, &[9; 1503]).unwrap();
        for part in &parity[..parity.len() - 1] {
            receiver.accept_detailed(part, now).unwrap();
        }
        let message = receiver
            .accept_detailed(parity.last().unwrap(), now)
            .unwrap()
            .unwrap();
        assert_eq!(message.kind, InnerType::FecRepair);
        assert!(message.fec.is_none());
        assert!(message.fec.is_none());
        assert_eq!(message.payload, vec![9; 1503]);
        let mut bad = parity[0].clone();
        bad[2] = 1;
        assert!(receiver.accept_detailed(&bad, now).is_err());
        bad[2] = 2;
        assert!(receiver.accept_detailed(&bad, now).is_err());
        assert!(split_fec_data(&[0; 1501], meta).is_err());
        assert!(split_fec_data(&[], meta).is_err());
        assert!(split_fec_data(
            &[1],
            FecMetadata {
                group_seq: 0,
                group_size: 0,
                index: 0
            }
        )
        .is_err());
        assert!(split_fec_data(
            &[1],
            FecMetadata {
                group_seq: 0,
                group_size: 1,
                index: 1
            }
        )
        .is_err());
    }
    #[test]
    fn lost_data_fragments_do_not_block_new_data_or_large_control() {
        let now = Instant::now();
        let mut receiver = Reassembler::default();
        for _ in 0..MAX_IN_FLIGHT {
            let parts = split(InnerType::Control, &[1; 2000]).unwrap();
            receiver.accept(&parts[0], now).unwrap();
        }
        for index in 0..MAX_DATA_IN_FLIGHT * 3 {
            let parts = split_fec_data(
                &[2; 1500],
                FecMetadata {
                    group_seq: index as u16,
                    group_size: 4,
                    index: 0,
                },
            )
            .unwrap();
            assert!(receiver
                .accept(&parts[0], now + Duration::from_millis(index as u64))
                .unwrap()
                .is_none());
        }
        assert_eq!(receiver.pending.len(), MAX_IN_FLIGHT + MAX_DATA_IN_FLIGHT);
        let parts = split_fec_data(
            &[3; 1500],
            FecMetadata {
                group_seq: 400,
                group_size: 4,
                index: 1,
            },
        )
        .unwrap();
        receiver
            .accept(&parts[0], now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            receiver
                .accept(&parts[1], now + Duration::from_secs(1))
                .unwrap(),
            Some((InnerType::Data, vec![3; 1500]))
        );
        let too_large = split(InnerType::Data, &[0; 1501]).unwrap();
        assert!(receiver.accept(&too_large[0], now).is_err());
    }

    #[test]
    fn short_fec_fragment_carries_metadata_and_discard_is_selective() {
        let meta = FecMetadata {
            group_seq: u16::MAX,
            group_size: 255,
            index: 254,
        };
        let short = split_fec_data(&[4; 50], meta).unwrap();
        assert_eq!(short.len(), 1);
        assert!(short[0].len() < FRAGMENT_DATA_SIZE);
        assert_eq!(short[0][0], 1);
        assert_eq!(short[0][1], InnerType::Data as u8);
        assert_eq!(short[0][2], 1);
        let another = split_fec_data(&[4; 50], meta).unwrap();
        assert_ne!(&short[0][4..12], &another[0][4..12]);
        let high_ids: std::collections::HashSet<Vec<u8>> = (0..8)
            .map(|_| split_fec_data(&[4; 50], meta).unwrap()[0][4..8].to_vec())
            .collect();
        assert!(
            high_ids.len() > 1,
            "Метаданные FEC не должны заменять старшие биты случайного id"
        );
        assert_eq!(short[0][3], FEC_META_SIZE as u8);
        assert_eq!(fec_metadata(&short[0]), Some(meta));
        assert!(fec_metadata(&short[0][..HEADER_SIZE + FEC_META_SIZE - 1]).is_none());
        assert!(fec_metadata(&split(InnerType::Data, &[4; 50]).unwrap()[0]).is_none());
        let mut bad = short[0].clone();
        bad[HEADER_SIZE + 3] = 255;
        assert!(fec_metadata(&bad).is_none());

        let now = Instant::now();
        let mut receiver = Reassembler::default();
        let message = receiver.accept_detailed(&short[0], now).unwrap().unwrap();
        assert_eq!(message.payload, vec![4; 50]);
        assert_eq!(message.fec, Some(meta));
        assert!(message.fec.is_some());

        let mut control = split(InnerType::Control, &[1; 1000]).unwrap().remove(0);
        let control_id = (5u64 << 48) | 0x10;
        control[4..12].copy_from_slice(&control_id.to_be_bytes());
        let mut plain = split(InnerType::Data, &[2; 1000]).unwrap().remove(0);
        let plain_id = (5u64 << 48) | 0x20;
        plain[4..12].copy_from_slice(&plain_id.to_be_bytes());
        let mut repair = split(InnerType::FecRepair, &[3; 1000]).unwrap().remove(0);
        let repair_id = (5u64 << 48) | 0x30;
        repair[4..12].copy_from_slice(&repair_id.to_be_bytes());
        let keep = split_fec_data(
            &[4; 1000],
            FecMetadata {
                group_seq: 6,
                group_size: 2,
                index: 0,
            },
        )
        .unwrap();
        let keep_id = u64::from_be_bytes(keep[0][4..12].try_into().unwrap());
        let drop_parts = split_fec_data(
            &[5; 1000],
            FecMetadata {
                group_seq: 5,
                group_size: 2,
                index: 1,
            },
        )
        .unwrap();
        let drop_id = u64::from_be_bytes(drop_parts[0][4..12].try_into().unwrap());
        for packet in [&control, &plain, &repair, &keep[0], &drop_parts[0]] {
            assert!(receiver.accept(packet, now).unwrap().is_none());
        }
        receiver.discard_fec_group(5);
        assert!(!receiver.pending.contains_key(&drop_id));
        assert!(receiver.pending.contains_key(&keep_id));
        assert!(receiver.pending.contains_key(&control_id));
        assert!(receiver.pending.contains_key(&plain_id));
        assert!(receiver.pending.contains_key(&repair_id));
        let mut invalid = drop_parts[1].clone();
        invalid[HEADER_SIZE + 2] = 0;
        invalid[2] = 1;
        assert!(fec_metadata(&invalid).is_none());
        assert!(receiver.accept_detailed(&invalid, now).is_err());
        assert!(receiver.pending.contains_key(&keep_id));
        assert!(receiver.pending.contains_key(&control_id));
    }
}
