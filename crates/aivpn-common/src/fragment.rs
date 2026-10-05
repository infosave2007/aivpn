//! Ограниченная сборка фрагментов после проверки AEAD и защиты от повтора.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::protocol::InnerType;

pub const FRAGMENT_DATA_SIZE: usize = 900;
pub const MAX_REASSEMBLED_SIZE: usize = 512 * 1024;
const HEADER_SIZE: usize = 20;
const MAX_IN_FLIGHT: usize = 4;
const ASSEMBLY_TTL: Duration = Duration::from_secs(10);

struct Assembly {
    kind: InnerType,
    total: usize,
    created: Instant,
    chunks: HashMap<usize, Vec<u8>>,
    received: usize,
}

#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<u64, Assembly>,
}

/// Каждый фрагмент шифруется отдельно с собственными nonce и sequence number.
pub fn split(kind: InnerType, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    if !matches!(kind, InnerType::Data | InnerType::Control)
        || payload.is_empty()
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

impl Reassembler {
    pub fn accept(&mut self, bytes: &[u8], now: Instant) -> Result<Option<(InnerType, Vec<u8>)>> {
        self.pending
            .retain(|_, assembly| now.saturating_duration_since(assembly.created) < ASSEMBLY_TTL);
        if bytes.len() <= HEADER_SIZE || bytes[0] != 1 || bytes[2..4] != [0, 0] {
            return Err(Error::InvalidPacket("Invalid fragment header"));
        }
        let kind = match InnerType::from_u16(bytes[1] as u16) {
            Some(kind @ (InnerType::Data | InnerType::Control)) => kind,
            _ => return Err(Error::InvalidPacket("Invalid fragment type")),
        };
        let id = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        let total = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let offset = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let data = &bytes[HEADER_SIZE..];
        if total == 0
            || total > MAX_REASSEMBLED_SIZE
            || offset >= total
            || !offset.is_multiple_of(FRAGMENT_DATA_SIZE)
            || data.len() != FRAGMENT_DATA_SIZE.min(total - offset)
        {
            return Err(Error::InvalidPacket("Invalid fragment bounds"));
        }
        if !self.pending.contains_key(&id) && self.pending.len() >= MAX_IN_FLIGHT {
            return Err(Error::InvalidPacket("Too many fragmented messages"));
        }
        let assembly = self.pending.entry(id).or_insert_with(|| Assembly {
            kind,
            total,
            created: now,
            chunks: HashMap::new(),
            received: 0,
        });
        if assembly.kind != kind || assembly.total != total {
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
        Ok(Some((kind, payload)))
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
        let packets = split(InnerType::Data, &[7; 2500]).unwrap();
        let mut receiver = Reassembler::default();
        let now = Instant::now();
        assert!(receiver.accept(&packets[0], now).unwrap().is_none());
        assert!(receiver.accept(&packets[2], now).unwrap().is_none());
        assert!(receiver
            .accept(&packets[1], now + ASSEMBLY_TTL)
            .unwrap()
            .is_none());
    }
}
