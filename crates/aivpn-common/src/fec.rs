//! XOR Forward Error Correction (FEC) encoder/decoder (0.9.0)
//!
//! Every N data packets one repair packet is emitted = XOR of those N packets.
//! If exactly one packet from the group is lost, it can be recovered.
//! Overhead: 1/N extra packets. N configured via AdaptiveLevel::fec_n().

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::protocol::MAX_PACKET_SIZE;

/// Encodes a stream of data packets into groups, emitting a repair per group.
#[derive(Debug, Clone)]
pub struct FecEncoder {
    xor_buf: Vec<u8>,
    max_len: usize,
    count: u8,
    group_size: u8,
    group_seq: u16,
}

impl FecEncoder {
    pub fn new(group_size: u8, max_payload: usize) -> Self {
        assert!(group_size > 0);
        Self {
            xor_buf: vec![0u8; max_payload],
            max_len: 0,
            count: 0,
            group_size,
            group_seq: 0,
        }
    }

    /// Feed a data payload. Returns `Some(repair)` when the group is complete.
    pub fn feed(&mut self, payload: &[u8]) -> Option<FecRepair> {
        let len = payload.len().min(self.xor_buf.len());
        for (a, b) in self.xor_buf[..len].iter_mut().zip(&payload[..len]) {
            *a ^= b;
        }
        if len > self.max_len {
            self.max_len = len;
        }
        self.count = self.count.wrapping_add(1);
        if self.count >= self.group_size {
            let repair = FecRepair {
                group_seq: self.group_seq,
                group_size: self.group_size,
                xor_data: self.xor_buf[..self.max_len].to_vec(),
            };
            self.xor_buf.iter_mut().for_each(|b| *b = 0);
            self.max_len = 0;
            self.count = 0;
            self.group_seq = self.group_seq.wrapping_add(1);
            Some(repair)
        } else {
            None
        }
    }

    pub fn reset(&mut self) {
        self.xor_buf.iter_mut().for_each(|b| *b = 0);
        self.max_len = 0;
        self.count = 0;
    }
}

/// A FEC repair packet carrying the XOR of a group of N data packets.
#[derive(Debug, Clone)]
pub struct FecRepair {
    pub group_seq: u16,
    pub group_size: u8,
    pub xor_data: Vec<u8>,
}

impl FecRepair {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + self.xor_data.len());
        buf.extend_from_slice(&self.group_seq.to_le_bytes());
        buf.push(self.group_size);
        buf.extend_from_slice(&self.xor_data);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        if data[2] == 0 {
            return None;
        }
        Some(Self {
            group_seq: u16::from_le_bytes([data[0], data[1]]),
            group_size: data[2],
            xor_data: data[3..].to_vec(),
        })
    }

    /// Recover a missing packet given the XOR of all received siblings.
    pub fn recover(&self, received_xor: &[u8]) -> Vec<u8> {
        let len = self.xor_data.len().max(received_xor.len());
        (0..len)
            .map(|i| {
                self.xor_data.get(i).copied().unwrap_or(0)
                    ^ received_xor.get(i).copied().unwrap_or(0)
            })
            .collect()
    }
}

/// Позиция исходного IP-пакета внутри одной группы XOR.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FecMetadata {
    pub group_seq: u16,
    pub group_size: u8,
    pub index: u8,
}

/// Общий отправитель FEC для desktop и мобильного ядра.
#[derive(Default)]
pub struct FecSender {
    encoder: Option<FecEncoder>,
    pending: std::collections::VecDeque<Vec<u8>>,
    requested_group: u8,
    next_group_seq: u16,
}

impl FecSender {
    pub fn set_group(&mut self, size: u8) {
        self.requested_group = size;
        self.apply_group_at_boundary();
    }

    fn apply_group_at_boundary(&mut self) {
        if self
            .encoder
            .as_ref()
            .is_some_and(|encoder| encoder.count != 0)
        {
            return;
        }
        if let Some(encoder) = &self.encoder {
            self.next_group_seq = encoder.group_seq;
            if encoder.group_size == self.requested_group {
                return;
            }
        }
        self.encoder = (self.requested_group > 0).then(|| {
            let mut encoder =
                FecEncoder::new(self.requested_group, crate::protocol::MAX_PACKET_SIZE);
            encoder.group_seq = self.next_group_seq;
            encoder
        });
    }

    pub fn enabled_for(&self, len: usize) -> bool {
        self.encoder.is_some() && len > 0 && len <= crate::protocol::MAX_PACKET_SIZE
    }

    /// Номер группы, размер и индекс текущего кодера до feed.
    /// После feed счетчик уже сдвинут, поэтому слот читают заранее.
    pub fn metadata_for(&self, len: usize) -> Option<FecMetadata> {
        if !self.enabled_for(len) {
            return None;
        }
        let encoder = self.encoder.as_ref()?;
        if encoder.group_size == 0 || encoder.count >= encoder.group_size {
            return None;
        }
        Some(FecMetadata {
            group_seq: encoder.group_seq,
            group_size: encoder.group_size,
            index: encoder.count,
        })
    }

    /// Группа содержит исходные IP-пакеты и может пережить смену маски.
    /// Готовые шифротексты старой маски при этом отправлять уже нельзя.
    pub fn discard_pending(&mut self) {
        self.pending.clear();
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    pub fn feed(
        &mut self,
        payload: &[u8],
        payload_limit: usize,
        mut encrypt: impl FnMut(crate::protocol::InnerType, &[u8]) -> crate::error::Result<Vec<u8>>,
    ) {
        use crate::protocol::InnerType;
        if !self.enabled_for(payload.len()) {
            return;
        }
        let Some(repair) = self
            .encoder
            .as_mut()
            .and_then(|encoder| encoder.feed(payload))
        else {
            return;
        };
        // Новая настройка применяется после завершения прежней группы.
        // Даже отключение FEC не оставляет на сервере незавершенный XOR.
        self.apply_group_at_boundary();
        let bytes = repair.encode();
        let parts = if bytes.len() <= payload_limit {
            vec![(InnerType::FecRepair, bytes)]
        } else {
            let Ok(parts) = crate::fragment::split(InnerType::FecRepair, &bytes) else {
                return;
            };
            parts
                .into_iter()
                .map(|part| (InnerType::Fragment, part))
                .collect()
        };
        let mut packets = Vec::with_capacity(parts.len());
        for (kind, payload) in parts {
            let Ok(packet) = encrypt(kind, &payload) else {
                return;
            };
            packets.push(packet);
        }
        // Uploader забирает всю группу сразу. Прямой пользователь API также
        // не может накопить неограниченную очередь ремонтных пакетов.
        if self.pending.len() + packets.len() > 8 {
            self.pending.clear();
        }
        self.pending.extend(packets);
    }
}

const MAX_PENDING_GROUPS: usize = 8;
const COMPLETED_GROUPS: usize = 512;
const RETIRED_GROUPS: usize = 512;
const PENDING_TTL: Duration = Duration::from_secs(10);

/// Итог приема одного исходного пакета или ремонта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecRxResult {
    /// Исходный пакет можно переслать. Повтор уже виденного индекса - нет.
    pub accepted: bool,
    pub recovered: Option<Vec<u8>>,
    pub complete: bool,
}

/// Не больше 8 незавершенных групп. В группе XOR до 1500 байт, маска индексов
/// и не больше одного ремонта. Сами IP-пакеты не хранятся.
/// Последние 512 завершенных номеров переживают простой, поэтому поздний
/// оригинал отбрасывается и не начинает группу заново.
/// Истекшая или вытесненная незавершенная группа хранит только размер и маску
/// уже виденных индексов, тоже не больше 512 развернутых позиций. XOR и ремонт
/// при этом сбрасываются: новый индекс пересылается один раз и больше не
/// восстанавливается, повтор уже виденного индекса отбрасывается.
#[derive(Default)]
pub struct FecReceiver {
    pending: HashMap<u64, PendingGroup>,
    completed: VecDeque<u64>,
    completed_set: HashSet<u64>,
    retired: HashMap<u64, RetiredGroup>,
    retired_order: VecDeque<u64>,
    highest_group: Option<u64>,
    next_ticket: u64,
    #[cfg(test)]
    clock_offset: Duration,
}

struct PendingGroup {
    group_size: u8,
    xor_buf: [u8; MAX_PACKET_SIZE],
    xor_len: usize,
    seen: [u64; 4],
    count: u8,
    repair: Option<StoredRepair>,
    created: Instant,
    ticket: u64,
}

struct StoredRepair {
    data: [u8; MAX_PACKET_SIZE],
    len: usize,
}

/// Незавершенная группа после TTL или вытеснения. Без XOR и без ремонта,
/// чтобы поздний пакет не собрал уже доставленный IP заново.
struct RetiredGroup {
    group_size: u8,
    seen: [u64; 4],
}

impl std::fmt::Debug for FecReceiver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FecReceiver")
            .field("pending", &self.pending.len())
            .field("completed", &self.completed.len())
            .field("retired", &self.retired.len())
            .finish()
    }
}

impl FecReceiver {
    pub fn record(&mut self, meta: FecMetadata, payload: &[u8]) -> Result<FecRxResult> {
        validate_member(meta, payload.len())?;
        let now = self.now();
        self.sweep(now);
        let position = self.advance(meta.group_seq);
        if self.completed_set.contains(&position) {
            return Ok(ignored());
        }
        if let Some(result) = self.accept_retired(position, meta.group_size, meta.index)? {
            return Ok(result);
        }
        {
            let group = self.ensure_group(position, meta.group_size, now)?;
            if group.seen(meta.index) {
                return Ok(ignored());
            }
            if group
                .repair
                .as_ref()
                .is_some_and(|repair| repair.len < payload.len())
            {
                return Err(Error::InvalidPacket("FEC data exceeds repair length"));
            }
            group.absorb(payload);
            group.mark(meta.index);
            group.count = group.count.saturating_add(1);
        }
        Ok(self.finish(position, true))
    }

    pub fn repair(&mut self, repair: FecRepair) -> Result<FecRxResult> {
        if repair.group_size == 0 {
            return Err(Error::InvalidPacket("Invalid FEC group size"));
        }
        if repair.xor_data.is_empty() || repair.xor_data.len() > MAX_PACKET_SIZE {
            return Err(Error::InvalidPacket("FEC repair exceeds packet budget"));
        }
        let now = self.now();
        self.sweep(now);
        let position = self.advance(repair.group_seq);
        if self.completed_set.contains(&position) {
            return Ok(ignored());
        }
        if let Some(group_size) = self.retired.get(&position).map(|group| group.group_size) {
            if group_size != repair.group_size {
                return Err(Error::InvalidPacket("Conflicting FEC group size"));
            }
            // Ремонт истекшей группы не хранится и ничего не восстанавливает.
            return Ok(ignored());
        }
        {
            let group = self.ensure_group(position, repair.group_size, now)?;
            if let Some(existing) = &group.repair {
                let same = existing.len == repair.xor_data.len()
                    && existing.data[..existing.len] == repair.xor_data[..];
                if !same {
                    return Err(Error::InvalidPacket("Conflicting FEC repair"));
                }
                return Ok(ignored());
            }
            if repair.xor_data.len() < group.xor_len {
                return Err(Error::InvalidPacket("FEC repair is shorter than data"));
            }
            group.store_repair(&repair.xor_data);
        }
        Ok(self.finish(position, true))
    }

    pub fn is_duplicate(&self, meta: FecMetadata) -> bool {
        let position = self.position(meta.group_seq);
        if self.completed_set.contains(&position) {
            return true;
        }
        if let Some(group) = self.pending.get(&position) {
            return group.group_size == meta.group_size && group.seen(meta.index);
        }
        let Some(group) = self.retired.get(&position) else {
            return false;
        };
        group.group_size == meta.group_size && group.seen(meta.index)
    }

    // Сохраняем эпоху после оборота u16. Старое завершение группы 0
    // не должно блокировать новую группу 0 после длинной серии потерь.
    fn position(&self, seq: u16) -> u64 {
        let Some(highest) = self.highest_group else {
            return 65536 + u64::from(seq);
        };
        let distance = seq.wrapping_sub(highest as u16);
        if distance < 0x8000 {
            highest.saturating_add(u64::from(distance))
        } else {
            highest.saturating_sub(u64::from(0u16.wrapping_sub(distance)))
        }
    }

    fn advance(&mut self, seq: u16) -> u64 {
        let position = self.position(seq);
        self.highest_group = Some(self.highest_group.unwrap_or(position).max(position));
        position
    }

    fn ensure_group(
        &mut self,
        seq: u64,
        group_size: u8,
        now: Instant,
    ) -> Result<&mut PendingGroup> {
        if self.pending.contains_key(&seq) {
            let group = self.pending.get_mut(&seq).unwrap();
            if group.group_size != group_size {
                return Err(Error::InvalidPacket("Conflicting FEC group size"));
            }
            return Ok(group);
        }
        if self.pending.len() >= MAX_PENDING_GROUPS {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(_, group)| (group.created, group.ticket))
                .map(|(seq, _)| *seq);
            if let Some(oldest) = oldest {
                self.retire(oldest);
            }
        }
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1);
        self.pending.insert(
            seq,
            PendingGroup {
                group_size,
                xor_buf: [0; MAX_PACKET_SIZE],
                xor_len: 0,
                seen: [0; 4],
                count: 0,
                repair: None,
                created: now,
                ticket,
            },
        );
        Ok(self.pending.get_mut(&seq).unwrap())
    }

    fn finish(&mut self, seq: u64, accepted: bool) -> FecRxResult {
        let (all_here, repair_ready) = {
            let Some(group) = self.pending.get(&seq) else {
                return ignored();
            };
            let repair_ready = group
                .group_size
                .checked_sub(1)
                .is_some_and(|need| group.count == need && group.repair.is_some());
            (group.count == group.group_size, repair_ready)
        };
        if all_here {
            self.complete_group(seq);
            return FecRxResult {
                accepted,
                recovered: None,
                complete: true,
            };
        }
        if repair_ready {
            let recovered = self
                .pending
                .get(&seq)
                .and_then(PendingGroup::missing_packet);
            self.complete_group(seq);
            return FecRxResult {
                accepted,
                recovered,
                complete: true,
            };
        }
        FecRxResult {
            accepted,
            recovered: None,
            complete: false,
        }
    }

    fn complete_group(&mut self, seq: u64) {
        self.pending.remove(&seq);
        if self.completed_set.insert(seq) {
            self.completed.push_back(seq);
            if self.completed.len() > COMPLETED_GROUPS {
                if let Some(old) = self.completed.pop_front() {
                    self.completed_set.remove(&old);
                }
            }
        }
    }

    fn sweep(&mut self, now: Instant) {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, group)| now.saturating_duration_since(group.created) >= PENDING_TTL)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in expired {
            self.retire(seq);
        }
    }

    /// Уже виденный индекс истекшей группы - дубль. Новый индекс пересылается
    /// один раз и не попадает обратно в XOR.
    fn accept_retired(
        &mut self,
        position: u64,
        group_size: u8,
        index: u8,
    ) -> Result<Option<FecRxResult>> {
        let Some((stored_size, seen)) = self
            .retired
            .get(&position)
            .map(|group| (group.group_size, group.seen(index)))
        else {
            return Ok(None);
        };
        if stored_size != group_size {
            return Err(Error::InvalidPacket("Conflicting FEC group size"));
        }
        if seen {
            return Ok(Some(ignored()));
        }
        self.retired
            .get_mut(&position)
            .expect("группа только что найдена")
            .mark(index);
        Ok(Some(FecRxResult {
            accepted: true,
            recovered: None,
            complete: false,
        }))
    }

    fn retire(&mut self, seq: u64) {
        let Some(group) = self.pending.remove(&seq) else {
            return;
        };
        self.remember_incomplete(seq, group.group_size, group.seen);
    }

    fn remember_incomplete(&mut self, seq: u64, group_size: u8, seen: [u64; 4]) {
        if let Some(existing) = self.retired.get_mut(&seq) {
            if existing.group_size == group_size {
                for (dst, src) in existing.seen.iter_mut().zip(seen) {
                    *dst |= src;
                }
            }
            return;
        }
        self.retired.insert(seq, RetiredGroup { group_size, seen });
        self.retired_order.push_back(seq);
        while self.retired_order.len() > RETIRED_GROUPS {
            if let Some(old) = self.retired_order.pop_front() {
                self.retired.remove(&old);
            }
        }
    }

    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            Instant::now() + self.clock_offset
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }
}

fn ignored() -> FecRxResult {
    FecRxResult {
        accepted: false,
        recovered: None,
        complete: false,
    }
}

fn validate_member(meta: FecMetadata, len: usize) -> Result<()> {
    if meta.group_size == 0 || meta.index >= meta.group_size {
        return Err(Error::InvalidPacket("Invalid FEC metadata"));
    }
    if len == 0 || len > MAX_PACKET_SIZE {
        return Err(Error::InvalidPacket("FEC data exceeds packet budget"));
    }
    Ok(())
}

fn bitmap_seen(seen: &[u64; 4], index: u8) -> bool {
    let index = usize::from(index);
    seen[index / 64] & (1u64 << (index % 64)) != 0
}

fn bitmap_mark(seen: &mut [u64; 4], index: u8) {
    let index = usize::from(index);
    seen[index / 64] |= 1u64 << (index % 64);
}

impl PendingGroup {
    fn seen(&self, index: u8) -> bool {
        bitmap_seen(&self.seen, index)
    }

    fn mark(&mut self, index: u8) {
        bitmap_mark(&mut self.seen, index);
    }

    fn absorb(&mut self, payload: &[u8]) {
        for (dst, src) in self.xor_buf.iter_mut().zip(payload) {
            *dst ^= *src;
        }
        self.xor_len = self.xor_len.max(payload.len());
    }

    fn store_repair(&mut self, xor_data: &[u8]) {
        let mut data = [0u8; MAX_PACKET_SIZE];
        data[..xor_data.len()].copy_from_slice(xor_data);
        self.repair = Some(StoredRepair {
            data,
            len: xor_data.len(),
        });
    }

    fn missing_packet(&self) -> Option<Vec<u8>> {
        let repair = self.repair.as_ref()?;
        let len = repair.len.max(self.xor_len);
        let mut out = vec![0u8; len];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = repair.data[index] ^ self.xor_buf[index];
        }
        Some(out)
    }
}

impl RetiredGroup {
    fn seen(&self, index: u8) -> bool {
        bitmap_seen(&self.seen, index)
    }

    fn mark(&mut self, index: u8) {
        bitmap_mark(&mut self.seen, index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_group_changes_finish_the_current_group_and_preserve_sequence() {
        let mut sender = FecSender::default();
        let feed = |sender: &mut FecSender, value| {
            sender.feed(&[value; 32], 1140, |_, bytes| Ok(bytes.to_vec()));
        };
        assert!(sender.metadata_for(32).is_none());
        sender.set_group(4);
        assert_eq!(
            sender.metadata_for(32),
            Some(FecMetadata {
                group_seq: 0,
                group_size: 4,
                index: 0
            })
        );
        assert!(sender.metadata_for(MAX_PACKET_SIZE + 1).is_none());
        feed(&mut sender, 1);
        assert_eq!(
            sender.metadata_for(32),
            Some(FecMetadata {
                group_seq: 0,
                group_size: 4,
                index: 1
            })
        );
        sender.set_group(2);
        assert_eq!(
            sender.metadata_for(32),
            Some(FecMetadata {
                group_seq: 0,
                group_size: 4,
                index: 1
            })
        );
        feed(&mut sender, 2);
        assert!(sender.take_packet().is_none());
        feed(&mut sender, 4);
        feed(&mut sender, 8);
        let first = FecRepair::decode(&sender.take_packet().unwrap()).unwrap();
        assert_eq!((first.group_seq, first.group_size), (0, 4));
        assert_eq!(first.xor_data, [15; 32]);
        assert_eq!(
            sender.metadata_for(32),
            Some(FecMetadata {
                group_seq: 1,
                group_size: 2,
                index: 0
            })
        );
        feed(&mut sender, 16);
        sender.set_group(0);
        assert!(sender.enabled_for(1500));
        assert_eq!(
            sender.metadata_for(1500),
            Some(FecMetadata {
                group_seq: 1,
                group_size: 2,
                index: 1
            })
        );
        feed(&mut sender, 32);
        let second = FecRepair::decode(&sender.take_packet().unwrap()).unwrap();
        assert_eq!((second.group_seq, second.group_size), (1, 2));
        assert_eq!(second.xor_data, [48; 32]);
        assert!(!sender.enabled_for(1500));
        assert!(sender.metadata_for(32).is_none());
        sender.set_group(3);
        assert_eq!(
            sender.metadata_for(32),
            Some(FecMetadata {
                group_seq: 2,
                group_size: 3,
                index: 0
            })
        );
        for value in [64, 128, 255] {
            feed(&mut sender, value);
        }
        let third = FecRepair::decode(&sender.take_packet().unwrap()).unwrap();
        assert_eq!((third.group_seq, third.group_size), (2, 3));
        assert_eq!(third.xor_data, [63; 32]);
        assert!(sender.take_packet().is_none());
        assert_eq!(
            sender.metadata_for(32),
            Some(FecMetadata {
                group_seq: 3,
                group_size: 3,
                index: 0
            })
        );
    }

    #[test]
    fn failed_fragment_encryption_does_not_publish_a_partial_repair() {
        use crate::protocol::InnerType;
        let mut sender = FecSender::default();
        sender.set_group(1);
        let mut calls = 0;
        sender.feed(&vec![7; 1500], 1140, |kind, bytes| {
            assert_eq!(kind, InnerType::Fragment);
            calls += 1;
            if calls == 2 {
                Err(crate::error::Error::InvalidPacket("Тест ошибки шифрования"))
            } else {
                Ok(bytes.to_vec())
            }
        });
        assert_eq!(calls, 2);
        assert!(sender.take_packet().is_none());
        sender.feed(&[1; 32], 1140, |_, bytes| Ok(bytes.to_vec()));
        let repair = FecRepair::decode(&sender.take_packet().unwrap()).unwrap();
        assert_eq!(repair.group_seq, 1);
        assert_eq!(repair.xor_data, [1; 32]);
        assert!(sender.take_packet().is_none());
    }

    #[test]
    fn an_undrained_sender_keeps_only_bounded_complete_repairs() {
        let mut sender = FecSender::default();
        sender.set_group(1);
        for value in 0..255u8 {
            sender.feed(&vec![value; 1500], 1140, |_, bytes| Ok(bytes.to_vec()));
        }
        let mut reassembler = crate::fragment::Reassembler::default();
        let mut packets = 0;
        let mut groups = Vec::new();
        while let Some(packet) = sender.take_packet() {
            packets += 1;
            if let Some((kind, bytes)) = reassembler
                .accept(&packet, std::time::Instant::now())
                .unwrap()
            {
                assert_eq!(kind, crate::protocol::InnerType::FecRepair);
                groups.push(FecRepair::decode(&bytes).unwrap().group_seq);
            }
        }
        assert!(packets <= 8);
        assert!(!groups.is_empty());
        assert_eq!(groups.last(), Some(&254));
        assert_eq!(packets, groups.len() * 2);
    }

    fn meta(group_seq: u16, group_size: u8, index: u8) -> FecMetadata {
        FecMetadata {
            group_seq,
            group_size,
            index,
        }
    }

    fn body(seed: u8, len: usize) -> Vec<u8> {
        vec![seed; len]
    }

    fn repair_of(group_seq: u16, group_size: u8, packets: &[Vec<u8>]) -> FecRepair {
        let len = packets.iter().map(Vec::len).max().unwrap_or(0);
        let mut xor_data = vec![0u8; len];
        for packet in packets {
            for (dst, src) in xor_data.iter_mut().zip(packet) {
                *dst ^= *src;
            }
        }
        FecRepair {
            group_seq,
            group_size,
            xor_data,
        }
    }

    #[test]
    fn equal_length_groups_do_not_mix_or_fabricate_a_packet() {
        let group_a = [body(1, 200), body(2, 200), body(3, 200), body(4, 200)];
        let group_b = [body(5, 200), body(6, 200), body(7, 200), body(8, 200)];
        let mut rx = FecReceiver::default();
        rx.record(meta(0, 4, 0), &group_a[0]).unwrap();
        rx.record(meta(0, 4, 1), &group_a[1]).unwrap();
        rx.record(meta(1, 4, 0), &group_b[0]).unwrap();
        let mixed = rx.repair(repair_of(0, 4, &group_a)).unwrap();
        assert_eq!(
            mixed,
            FecRxResult {
                accepted: true,
                recovered: None,
                complete: false
            }
        );
        assert!(!rx.is_duplicate(meta(0, 4, 2)));
        assert!(rx.is_duplicate(meta(1, 4, 0)));

        let mut rx = FecReceiver::default();
        for index in [0u8, 2, 3] {
            let result = rx
                .record(meta(0, 4, index), &group_a[usize::from(index)])
                .unwrap();
            assert!(result.accepted);
            assert!(result.recovered.is_none());
        }
        rx.record(meta(1, 4, 0), &group_b[0]).unwrap();
        rx.record(meta(1, 4, 3), &group_b[3]).unwrap();
        let recovered = rx.repair(repair_of(0, 4, &group_a)).unwrap();
        assert_eq!(recovered.recovered, Some(group_a[1].clone()));
        assert!(recovered.complete);
        assert!(rx.is_duplicate(meta(0, 4, 1)));
        assert!(!rx.is_duplicate(meta(1, 4, 1)));
        let late = rx.record(meta(0, 4, 1), &group_a[1]).unwrap();
        assert!(!late.accepted);
        assert!(late.recovered.is_none());
    }

    #[test]
    fn two_missing_members_are_not_recovered() {
        let packets = [body(1, 64), body(2, 64), body(3, 64), body(4, 64)];
        let mut rx = FecReceiver::default();
        rx.record(meta(4, 4, 0), &packets[0]).unwrap();
        rx.record(meta(4, 4, 3), &packets[3]).unwrap();
        let result = rx.repair(repair_of(4, 4, &packets)).unwrap();
        assert!(result.recovered.is_none());
        assert!(!result.complete);
        let third = rx.record(meta(4, 4, 1), &packets[1]).unwrap();
        assert_eq!(third.recovered, Some(packets[2].clone()));
        assert!(third.complete);
        assert!(third.accepted);
    }

    #[test]
    fn repair_before_data_recovers_the_missing_member_and_stops_at_n() {
        let packets = [body(9, 40), body(8, 40), body(7, 40)];
        let mut rx = FecReceiver::default();
        let parked = rx.repair(repair_of(2, 3, &packets)).unwrap();
        assert!(parked.recovered.is_none());
        assert!(!parked.complete);
        assert!(rx
            .record(meta(2, 3, 2), &packets[2])
            .unwrap()
            .recovered
            .is_none());
        let recovered = rx.record(meta(2, 3, 0), &packets[0]).unwrap();
        assert_eq!(recovered.recovered, Some(packets[1].clone()));
        assert!(recovered.complete);
        let late = rx.record(meta(2, 3, 1), &packets[1]).unwrap();
        assert!(!late.accepted);
        assert!(late.recovered.is_none());

        let mut rx = FecReceiver::default();
        for (index, packet) in packets.iter().enumerate() {
            let result = rx.record(meta(2, 3, index as u8), packet).unwrap();
            assert!(result.recovered.is_none());
            assert_eq!(result.complete, index == 2);
        }
        let repair = rx.repair(repair_of(2, 3, &packets)).unwrap();
        assert!(repair.recovered.is_none());
        assert!(!repair.complete);
        assert!(rx.is_duplicate(meta(2, 3, 0)));
    }

    #[test]
    fn duplicate_member_and_conflicting_repair_do_not_corrupt_recovery() {
        let packets = [body(1, 4), body(2, 4), body(4, 4)];
        let mut rx = FecReceiver::default();
        assert!(rx.record(meta(0, 3, 0), &packets[0]).unwrap().accepted);
        let duplicate = rx.record(meta(0, 3, 0), &body(7, 4)).unwrap();
        assert!(!duplicate.accepted);
        assert!(duplicate.recovered.is_none());
        let good = repair_of(0, 3, &packets);
        assert!(rx.repair(good.clone()).unwrap().recovered.is_none());
        assert!(rx
            .repair(FecRepair {
                group_seq: 0,
                group_size: 3,
                xor_data: body(9, 4),
            })
            .is_err());
        assert!(rx.repair(good).unwrap().recovered.is_none());
        let recovered = rx.record(meta(0, 3, 2), &packets[2]).unwrap();
        assert_eq!(recovered.recovered, Some(packets[1].clone()));
        assert!(rx.record(meta(0, 1, 0), &body(1, 1501)).is_err());
        assert!(rx.record(meta(0, 1, 1), &body(1, 1)).is_err());
        assert!(rx
            .repair(FecRepair {
                group_seq: 8,
                group_size: 0,
                xor_data: vec![1],
            })
            .is_err());
        assert!(rx
            .repair(FecRepair {
                group_seq: 8,
                group_size: 1,
                xor_data: vec![1; 1501],
            })
            .is_err());
        assert!(rx.record(meta(1, 4, 0), &body(1, 8)).unwrap().accepted);
        assert!(rx.record(meta(1, 2, 0), &body(2, 8)).is_err());
        assert!(rx.is_duplicate(meta(1, 4, 0)));
        assert!(rx
            .repair(FecRepair {
                group_seq: 1,
                group_size: 2,
                xor_data: body(3, 8),
            })
            .is_err());
    }

    #[test]
    fn shorter_member_recovers_with_zero_tail_without_parsing() {
        let short = vec![7, 8, 9];
        let long = vec![1, 2, 3, 4, 5];
        let mut rx = FecReceiver::default();
        rx.repair(repair_of(0, 2, &[short.clone(), long.clone()]))
            .unwrap();
        let result = rx.record(meta(0, 2, 1), &long).unwrap();
        assert_eq!(result.recovered, Some(vec![7, 8, 9, 0, 0]));
    }

    #[test]
    fn group_of_one_recovers_from_the_repair_alone() {
        let packet = body(9, 20);
        let mut rx = FecReceiver::default();
        let result = rx.repair(repair_of(3, 1, &[packet.clone()])).unwrap();
        assert_eq!(result.recovered, Some(packet.clone()));
        assert!(result.complete);
        assert!(rx.is_duplicate(meta(3, 1, 0)));
        let late = rx.record(meta(3, 1, 0), &packet).unwrap();
        assert!(!late.accepted);
        assert!(late.recovered.is_none());

        let mut rx = FecReceiver::default();
        let direct = rx.record(meta(4, 1, 0), &packet).unwrap();
        assert!(direct.accepted);
        assert!(direct.recovered.is_none());
        assert!(direct.complete);
        assert!(rx
            .repair(repair_of(4, 1, &[packet]))
            .unwrap()
            .recovered
            .is_none());
    }

    #[test]
    fn eviction_drops_the_oldest_group_without_mixing_xor() {
        let mut rx = FecReceiver::default();
        for seq in 0..8u16 {
            rx.record(meta(seq, 4, 0), &body(seq as u8 + 1, 16))
                .unwrap();
            rx.record(meta(seq, 4, 1), &body(seq as u8 + 2, 16))
                .unwrap();
            rx.record(meta(seq, 4, 2), &body(seq as u8 + 3, 16))
                .unwrap();
        }
        rx.record(meta(8, 4, 0), &body(40, 16)).unwrap();
        // Вытеснение сбрасывает XOR, но не уже доставленные индексы.
        // Невиденный хвост при этом не считается дублем.
        assert!(rx.is_duplicate(meta(0, 4, 0)));
        assert!(rx.is_duplicate(meta(0, 4, 2)));
        assert!(!rx.is_duplicate(meta(0, 4, 3)));
        let kept = rx
            .repair(repair_of(
                1,
                4,
                &[body(2, 16), body(3, 16), body(4, 16), body(5, 16)],
            ))
            .unwrap();
        assert_eq!(kept.recovered, Some(body(5, 16)));
        assert!(kept.complete);
        assert!(rx.is_duplicate(meta(1, 4, 3)));
        let restarted = rx
            .repair(repair_of(
                0,
                4,
                &[body(1, 16), body(2, 16), body(3, 16), body(4, 16)],
            ))
            .unwrap();
        assert!(restarted.recovered.is_none());
        assert!(!restarted.complete);
    }

    #[test]
    fn late_original_stays_dropped_across_idle_and_history_is_bounded() {
        let mut rx = FecReceiver::default();
        let packet = body(6, 24);
        assert!(rx.record(meta(5, 1, 0), &packet).unwrap().complete);
        rx.clock_offset = Duration::from_secs(30);
        assert!(rx.is_duplicate(meta(5, 1, 0)));
        let late = rx.record(meta(5, 1, 0), &packet).unwrap();
        assert!(!late.accepted);
        assert!(late.recovered.is_none());
        assert!(!late.complete);

        let mut rx = FecReceiver::default();
        for seq in 0..COMPLETED_GROUPS as u16 {
            assert!(rx.record(meta(seq, 1, 0), &body(1, 1)).unwrap().complete);
            assert!(rx.is_duplicate(meta(seq, 1, 0)));
        }
        assert!(
            rx.record(meta(COMPLETED_GROUPS as u16, 1, 0), &body(1, 1))
                .unwrap()
                .complete
        );
        assert!(!rx.is_duplicate(meta(0, 1, 0)));
        assert!(rx.is_duplicate(meta(1, 1, 0)));
        assert!(rx.is_duplicate(meta(COMPLETED_GROUPS as u16, 1, 0)));
        assert!(rx.pending.is_empty());
        assert_eq!(rx.completed.len(), COMPLETED_GROUPS);
    }

    #[test]
    fn sparse_completion_history_does_not_confuse_a_new_sequence_epoch() {
        let mut rx = FecReceiver::default();
        assert!(rx.record(meta(0, 1, 0), &[1]).unwrap().complete);
        for seq in 1..=u16::MAX {
            assert!(rx.record(meta(seq, 2, 0), &[2]).unwrap().accepted);
        }
        assert!(!rx.is_duplicate(meta(0, 1, 0)));
        let next = rx.record(meta(0, 1, 0), &[9]).unwrap();
        assert!(next.accepted && next.complete);
        assert!(rx.is_duplicate(meta(0, 1, 0)));
        // Опоздавшая прежняя группа еще принимается в своей эпохе.
        let previous = rx.record(meta(u16::MAX, 2, 1), &[3]).unwrap();
        assert!(previous.accepted && previous.complete);
        assert!(rx.is_duplicate(meta(0, 1, 0)));
    }

    #[test]
    fn a_repair_cannot_be_shorter_than_one_of_its_members() {
        let mut rx = FecReceiver::default();
        rx.record(meta(0, 2, 0), &[1; 20]).unwrap();
        assert!(rx
            .repair(FecRepair {
                group_seq: 0,
                group_size: 2,
                xor_data: vec![0; 10]
            })
            .is_err());
        let mut rx = FecReceiver::default();
        rx.repair(FecRepair {
            group_seq: 0,
            group_size: 2,
            xor_data: vec![0; 10],
        })
        .unwrap();
        assert!(rx.record(meta(0, 2, 0), &[1; 20]).is_err());
    }

    #[test]
    fn pending_group_expires_without_joining_the_next_group() {
        let mut rx = FecReceiver::default();
        rx.record(meta(0, 2, 0), &body(1, 8)).unwrap();
        rx.record(meta(1, 2, 0), &body(3, 8)).unwrap();
        assert!(rx.is_duplicate(meta(0, 2, 0)));
        rx.clock_offset = Duration::from_secs(9);
        assert!(rx.is_duplicate(meta(0, 2, 0)));
        assert!(rx.is_duplicate(meta(1, 2, 0)));
        rx.clock_offset = Duration::from_secs(10);
        assert!(rx.is_duplicate(meta(0, 2, 0)));
        assert!(!rx.is_duplicate(meta(0, 2, 1)));
        let restarted = rx.record(meta(0, 2, 0), &body(2, 8)).unwrap();
        assert!(!restarted.accepted);
        assert!(restarted.recovered.is_none());
        assert!(rx.pending.is_empty());
        let result = rx
            .repair(repair_of(0, 2, &[body(2, 8), body(9, 8)]))
            .unwrap();
        assert!(result.recovered.is_none());
        assert!(!result.accepted);
        assert!(!result.complete);
        let tail = rx.record(meta(0, 2, 1), &body(9, 8)).unwrap();
        assert!(tail.accepted);
        assert!(tail.recovered.is_none());
        assert!(!tail.complete);
        assert!(rx.is_duplicate(meta(0, 2, 1)));
        let repeated = rx.record(meta(0, 2, 1), &body(4, 8)).unwrap();
        assert!(!repeated.accepted);
        // Соседняя группа истекла отдельно и не восстановилась чужим ремонтом.
        assert!(rx.is_duplicate(meta(1, 2, 0)));
        assert!(!rx.is_duplicate(meta(1, 2, 1)));
        let neighbor = rx
            .repair(repair_of(1, 2, &[body(3, 8), body(5, 8)]))
            .unwrap();
        assert!(neighbor.recovered.is_none());
        assert!(!neighbor.complete);
    }

    #[test]
    fn expired_group_forwards_unseen_tail_once_and_does_not_recover() {
        let packets = [body(1, 16), body(2, 16), body(3, 16), body(4, 16)];
        let mut rx = FecReceiver::default();
        let first = rx.record(meta(7, 4, 0), &packets[0]).unwrap();
        assert!(first.accepted);
        assert!(first.recovered.is_none());
        rx.clock_offset = Duration::from_secs(9);
        assert!(rx.is_duplicate(meta(7, 4, 0)));
        rx.clock_offset = Duration::from_secs(11);
        assert!(rx.is_duplicate(meta(7, 4, 0)));
        assert!(!rx.is_duplicate(meta(7, 4, 1)));
        let duplicate = rx.record(meta(7, 4, 0), &packets[0]).unwrap();
        assert!(!duplicate.accepted);
        assert!(duplicate.recovered.is_none());
        assert!(rx.pending.is_empty());
        assert_eq!(rx.retired.len(), 1);
        for index in 1..4u8 {
            let result = rx
                .record(meta(7, 4, index), &packets[usize::from(index)])
                .unwrap();
            assert!(result.accepted);
            assert!(result.recovered.is_none());
            assert!(!result.complete);
            assert!(rx.is_duplicate(meta(7, 4, index)));
            let again = rx
                .record(meta(7, 4, index), &packets[usize::from(index)])
                .unwrap();
            assert!(!again.accepted);
            assert!(again.recovered.is_none());
        }
        assert!(rx.pending.is_empty());
        let repair = rx.repair(repair_of(7, 4, &packets)).unwrap();
        assert!(!repair.accepted);
        assert!(repair.recovered.is_none());
        assert!(!repair.complete);
        rx.clock_offset = Duration::from_secs(40);
        assert!(rx.is_duplicate(meta(7, 4, 0)));
        assert!(rx.is_duplicate(meta(7, 4, 3)));
        let repair_again = rx.repair(repair_of(7, 4, &packets)).unwrap();
        assert!(repair_again.recovered.is_none());
        assert!(!repair_again.complete);
        assert_eq!(rx.retired.len(), 1);
        assert!(rx.record(meta(7, 2, 0), &body(9, 16)).is_err());
        assert!(rx.is_duplicate(meta(7, 4, 0)));
    }

    #[test]
    fn expired_repair_does_not_rebuild_delivered_or_missing_packets() {
        let packets = [body(1, 16), body(2, 16), body(3, 16), body(4, 16)];
        let mut rx = FecReceiver::default();
        for index in 0..3u8 {
            assert!(
                rx.record(meta(3, 4, index), &packets[usize::from(index)])
                    .unwrap()
                    .accepted
            );
        }
        rx.clock_offset = Duration::from_secs(10);
        let repair = rx.repair(repair_of(3, 4, &packets)).unwrap();
        assert!(!repair.accepted);
        assert!(repair.recovered.is_none());
        let missing = rx.record(meta(3, 4, 3), &packets[3]).unwrap();
        assert!(missing.accepted);
        assert!(missing.recovered.is_none());
        assert!(!missing.complete);
        assert!(!rx.record(meta(3, 4, 0), &packets[0]).unwrap().accepted);

        let parked = [body(4, 8), body(5, 8), body(6, 8)];
        let mut rx = FecReceiver::default();
        assert!(rx
            .repair(repair_of(2, 3, &parked))
            .unwrap()
            .recovered
            .is_none());
        rx.clock_offset = Duration::from_secs(10);
        for (index, packet) in parked.iter().enumerate() {
            let result = rx.record(meta(2, 3, index as u8), packet).unwrap();
            assert!(result.accepted);
            assert!(result.recovered.is_none());
            assert!(!result.complete);
        }
        assert!(rx
            .repair(repair_of(2, 3, &parked))
            .unwrap()
            .recovered
            .is_none());
        assert!(rx.is_duplicate(meta(2, 3, 1)));
        assert!(!rx.record(meta(2, 3, 1), &parked[1]).unwrap().accepted);
    }

    #[test]
    fn evicted_group_forwards_unseen_tail_once_and_does_not_recover() {
        let mut rx = FecReceiver::default();
        assert!(rx.record(meta(0, 4, 0), &body(1, 16)).unwrap().accepted);
        for seq in 1..=8u16 {
            assert!(
                rx.record(meta(seq, 4, 0), &body(10 + seq as u8, 16))
                    .unwrap()
                    .accepted
            );
        }
        assert_eq!(rx.pending.len(), MAX_PENDING_GROUPS);
        assert_eq!(rx.retired.len(), 1);
        assert!(rx.is_duplicate(meta(0, 4, 0)));
        assert!(!rx.is_duplicate(meta(0, 4, 1)));
        assert!(rx.record(meta(0, 2, 0), &body(1, 16)).is_err());
        assert!(rx
            .repair(FecRepair {
                group_seq: 0,
                group_size: 3,
                xor_data: body(1, 16),
            })
            .is_err());
        assert!(rx.is_duplicate(meta(0, 4, 0)));
        let repeated = rx.record(meta(0, 4, 0), &body(9, 16)).unwrap();
        assert!(!repeated.accepted);
        assert!(repeated.recovered.is_none());
        for (index, seed) in [(1u8, 2u8), (2, 3), (3, 4)] {
            let result = rx.record(meta(0, 4, index), &body(seed, 16)).unwrap();
            assert!(result.accepted);
            assert!(result.recovered.is_none());
            assert!(!result.complete);
            let again = rx
                .record(meta(0, 4, index), &body(seed.wrapping_add(1), 16))
                .unwrap();
            assert!(!again.accepted);
            assert!(again.recovered.is_none());
        }
        assert_eq!(rx.pending.len(), MAX_PENDING_GROUPS);
        assert_eq!(rx.retired.len(), 1);
        let repair = rx
            .repair(repair_of(
                0,
                4,
                &[body(1, 16), body(2, 16), body(3, 16), body(4, 16)],
            ))
            .unwrap();
        assert!(!repair.accepted);
        assert!(repair.recovered.is_none());
        assert!(!repair.complete);
        assert!(rx.record(meta(8, 4, 1), &body(21, 16)).unwrap().accepted);
        assert!(rx.record(meta(8, 4, 2), &body(22, 16)).unwrap().accepted);
        let recovered = rx
            .repair(repair_of(
                8,
                4,
                &[body(18, 16), body(21, 16), body(22, 16), body(23, 16)],
            ))
            .unwrap();
        assert_eq!(recovered.recovered, Some(body(23, 16)));
        assert!(recovered.complete);
        assert!(rx.is_duplicate(meta(0, 4, 0)));
        assert!(rx.is_duplicate(meta(0, 4, 3)));
    }

    #[test]
    fn evicted_parked_repair_is_discarded() {
        let packets = [body(1, 8), body(2, 8), body(3, 8)];
        let mut rx = FecReceiver::default();
        assert!(rx
            .repair(repair_of(0, 3, &packets))
            .unwrap()
            .recovered
            .is_none());
        assert!(rx.record(meta(0, 3, 0), &packets[0]).unwrap().accepted);
        for seq in 1..=8u16 {
            rx.record(meta(seq, 3, 0), &body(seq as u8, 8)).unwrap();
        }
        assert!(rx.is_duplicate(meta(0, 3, 0)));
        assert!(!rx.is_duplicate(meta(0, 3, 1)));
        for (index, packet) in packets.iter().enumerate().skip(1) {
            let result = rx.record(meta(0, 3, index as u8), packet).unwrap();
            assert!(result.accepted);
            assert!(result.recovered.is_none());
            assert!(!result.complete);
        }
        assert!(rx
            .repair(repair_of(0, 3, &packets))
            .unwrap()
            .recovered
            .is_none());
        assert!(!rx.record(meta(0, 3, 0), &packets[0]).unwrap().accepted);
    }

    #[test]
    fn fresh_group_still_recovers_before_pending_ttl() {
        let packets = [body(1, 8), body(2, 8), body(3, 8), body(4, 8)];
        let mut rx = FecReceiver::default();
        for index in 0..3u8 {
            let result = rx
                .record(meta(3, 4, index), &packets[usize::from(index)])
                .unwrap();
            assert!(result.accepted);
            assert!(result.recovered.is_none());
            assert!(!result.complete);
        }
        rx.clock_offset = Duration::from_secs(9);
        let recovered = rx.repair(repair_of(3, 4, &packets)).unwrap();
        assert_eq!(recovered.recovered, Some(packets[3].clone()));
        assert!(recovered.complete);
        assert!(recovered.accepted);
        assert!(rx.is_duplicate(meta(3, 4, 3)));
        rx.clock_offset = Duration::from_secs(40);
        let late = rx.record(meta(3, 4, 3), &packets[3]).unwrap();
        assert!(!late.accepted);
        assert!(late.recovered.is_none());
    }

    #[test]
    fn retired_incomplete_history_is_bounded_without_dropping_completed() {
        let mut rx = FecReceiver::default();
        assert!(rx.record(meta(0, 1, 0), &[7]).unwrap().complete);
        let flooded = RETIRED_GROUPS as u16 + 16;
        for seq in 1..=flooded {
            assert!(rx.record(meta(seq, 2, 0), &[2]).unwrap().accepted);
        }
        assert_eq!(rx.pending.len(), MAX_PENDING_GROUPS);
        assert_eq!(rx.retired.len(), RETIRED_GROUPS);
        assert_eq!(rx.completed.len(), 1);
        assert!(rx.is_duplicate(meta(0, 1, 0)));
        assert!(!rx.record(meta(0, 1, 0), &[7]).unwrap().accepted);
        assert!(!rx.is_duplicate(meta(1, 2, 0)));
        assert!(!rx.is_duplicate(meta(1, 2, 1)));
        assert!(!rx.is_duplicate(meta(8, 2, 0)));
        let oldest_kept = 9u16;
        assert!(rx.is_duplicate(meta(oldest_kept, 2, 0)));
        assert!(!rx.is_duplicate(meta(oldest_kept, 2, 1)));
        let tail = rx.record(meta(oldest_kept, 2, 1), &[4]).unwrap();
        assert!(tail.accepted);
        assert!(tail.recovered.is_none());
        assert!(!tail.complete);
        assert!(rx.is_duplicate(meta(oldest_kept, 2, 1)));
        assert!(!rx.record(meta(oldest_kept, 2, 0), &[5]).unwrap().accepted);
        assert!(!rx.record(meta(oldest_kept, 2, 1), &[5]).unwrap().accepted);
        assert_eq!(rx.pending.len(), MAX_PENDING_GROUPS);
        assert_eq!(rx.retired.len(), RETIRED_GROUPS);
        let oldest_pending = flooded - (MAX_PENDING_GROUPS as u16 - 1);
        let recovered = rx
            .repair(repair_of(oldest_pending, 2, &[vec![2], vec![9]]))
            .unwrap();
        assert_eq!(recovered.recovered, Some(vec![9]));
        assert!(recovered.complete);
        assert!(rx.is_duplicate(meta(0, 1, 0)));
    }

    #[test]
    fn retired_seen_index_tracks_unwrapped_position_across_wrap() {
        let mut rx = FecReceiver::default();
        assert!(rx.record(meta(65534, 4, 0), &body(1, 8)).unwrap().accepted);
        for seq in [65535u16, 0, 1, 2, 3, 4, 5, 6] {
            assert!(rx.record(meta(seq, 4, 0), &body(2, 8)).unwrap().accepted);
        }
        assert!(rx.is_duplicate(meta(65534, 4, 0)));
        assert!(!rx.is_duplicate(meta(65534, 4, 1)));
        let tail = rx.record(meta(65534, 4, 1), &body(3, 8)).unwrap();
        assert!(tail.accepted);
        assert!(tail.recovered.is_none());
        assert!(!tail.complete);
        assert!(!rx.record(meta(65534, 4, 0), &body(1, 8)).unwrap().accepted);
        assert!(rx.is_duplicate(meta(65534, 4, 1)));
        let repair = rx
            .repair(repair_of(
                65534,
                4,
                &[body(1, 8), body(3, 8), body(4, 8), body(5, 8)],
            ))
            .unwrap();
        assert!(repair.recovered.is_none());
        assert!(!repair.accepted);
        assert!(rx.record(meta(6, 4, 1), &body(6, 8)).unwrap().accepted);
        assert!(rx.record(meta(6, 4, 2), &body(7, 8)).unwrap().accepted);
        let recovered = rx
            .repair(repair_of(
                6,
                4,
                &[body(2, 8), body(6, 8), body(7, 8), body(8, 8)],
            ))
            .unwrap();
        assert_eq!(recovered.recovered, Some(body(8, 8)));
        assert!(recovered.complete);
        assert!(rx.is_duplicate(meta(65534, 4, 0)));
    }

    #[test]
    fn sender_metadata_roundtrips_through_fragment_before_feed() {
        let mut sender = FecSender::default();
        sender.set_group(4);
        let payload = body(9, 1000);
        let meta = sender.metadata_for(payload.len()).unwrap();
        assert_eq!(meta.index, 0);
        let parts = crate::fragment::split_fec_data(&payload, meta).unwrap();
        assert!(parts.len() > 1);
        let mut reassembler = crate::fragment::Reassembler::default();
        let now = Instant::now();
        let mut message = None;
        for part in &parts {
            assert_eq!(crate::fragment::fec_metadata(part), Some(meta));
            message = reassembler.accept_detailed(part, now).unwrap().or(message);
        }
        let message = message.unwrap();
        assert_eq!(message.payload, payload);
        assert_eq!(message.fec, Some(meta));
        assert!(message.fec.is_some());
        sender.feed(&payload, 1140, |_, bytes| Ok(bytes.to_vec()));
        assert_eq!(
            sender.metadata_for(payload.len()),
            Some(FecMetadata {
                group_seq: meta.group_seq,
                group_size: meta.group_size,
                index: 1
            })
        );
    }
}
