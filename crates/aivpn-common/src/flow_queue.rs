//! Ограниченная очередь IP-потоков перед планировщиком интервалов маски.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Flow {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    ports: [u8; 4],
}

fn flow(packet: &[u8]) -> Option<Flow> {
    let ip = crate::ip_packet::IpPacket::parse(packet)?;
    let (protocol, offset, fragmented) = if packet[0] >> 4 == 4 {
        (
            packet[9],
            usize::from(packet[0] & 15) * 4,
            u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0,
        )
    } else {
        ipv6_transport(&packet[..ip.length]).unwrap_or((packet[6], 40, true))
    };
    let mut ports = [0; 4];
    if !fragmented && matches!(protocol, 6 | 17) && offset + 4 <= ip.length {
        ports.copy_from_slice(&packet[offset..offset + 4]);
    } else if !fragmented && matches!(protocol, 1 | 58) && offset + 8 <= ip.length {
        ports[..2].copy_from_slice(&packet[offset + 4..offset + 6]);
    }
    Some(Flow {
        source: ip.source,
        destination: ip.destination,
        protocol,
        ports,
    })
}

fn ipv6_transport(packet: &[u8]) -> Option<(u8, usize, bool)> {
    let mut protocol = packet[6];
    let mut offset = 40;
    // Ограничиваем и число заголовков, и длину каждого по фактическому пакету.
    for _ in 0..16 {
        let length = match protocol {
            0 | 43 | 60 => (usize::from(*packet.get(offset + 1)?) + 1) * 8,
            51 => (usize::from(*packet.get(offset + 1)?) + 2) * 4,
            44 => {
                let fragment = packet.get(offset..offset + 8)?;
                // Первый и последующие фрагменты сохраняют один ключ потока.
                return Some((fragment[0], offset + 8, true));
            }
            _ => return Some((protocol, offset, false)),
        };
        let header = packet.get(offset..offset + length)?;
        protocol = header[0];
        offset += length;
    }
    None
}

pub struct FairQueue<T> {
    lanes: HashMap<Option<Flow>, VecDeque<T>>,
    active: VecDeque<Option<Flow>>,
    len: usize,
    capacity: usize,
}

impl<T> FairQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            lanes: HashMap::new(),
            active: VecDeque::new(),
            len: 0,
            capacity: capacity.max(1),
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn clear(&mut self) {
        self.lanes.clear();
        self.active.clear();
        self.len = 0;
    }
    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        self.lanes.retain(|_, lane| {
            lane.retain(|item| keep(item));
            !lane.is_empty()
        });
        self.active.retain(|key| self.lanes.contains_key(key));
        self.len = self.lanes.values().map(VecDeque::len).sum();
    }
    /// При заполнении новый поток вытесняет хвост самого длинного потока.
    pub fn push(&mut self, item: T, packet: impl FnOnce(&T) -> &[u8]) -> Result<Option<T>, T> {
        let key = flow(packet(&item));
        let mut evicted = None;
        if self.len == self.capacity {
            if self.lanes.contains_key(&key) {
                return Err(item);
            }
            let victim = *self
                .lanes
                .iter()
                .max_by_key(|(_, lane)| lane.len())
                .unwrap()
                .0;
            let lane = self.lanes.get_mut(&victim).unwrap();
            evicted = lane.pop_back();
            self.len -= 1;
            if lane.is_empty() {
                self.lanes.remove(&victim);
                self.active.retain(|candidate| *candidate != victim);
            }
        }
        let lane = self.lanes.entry(key).or_insert_with(|| {
            self.active.push_back(key);
            VecDeque::new()
        });
        lane.push_back(item);
        self.len += 1;
        Ok(evicted)
    }
    /// Возраст старейшего пакета среди голов IP-потоков.
    pub fn oldest(&self, timestamp: impl Fn(&T) -> Instant) -> Option<Instant> {
        self.lanes
            .values()
            .filter_map(|lane| lane.front())
            .map(timestamp)
            .min()
    }

    pub fn pop(&mut self) -> Option<T> {
        let key = self.active.pop_front()?;
        let lane = self.lanes.get_mut(&key).unwrap();
        let item = lane.pop_front().unwrap();
        self.len -= 1;
        if lane.is_empty() {
            self.lanes.remove(&key);
        } else {
            self.active.push_back(key);
        }
        Some(item)
    }
}

pub(crate) struct FlowQueue(FairQueue<(Vec<u8>, Instant)>, Duration);
impl FlowQueue {
    pub fn new(capacity: usize) -> Self {
        Self(FairQueue::new(capacity), Duration::ZERO)
    }
    fn push(&mut self, packet: Vec<u8>) {
        let _ = self.0.push((packet, Instant::now()), |item| &item.0);
    }
    fn pop(&mut self) -> Option<Vec<u8>> {
        let now = Instant::now();
        self.1 = self
            .0
            .oldest(|item| item.1)
            .map(|at| now.saturating_duration_since(at))
            .unwrap_or_default();
        self.0.pop().map(|item| item.0)
    }

    pub fn queue_wait(&self) -> Duration {
        self.1
    }

    pub fn try_next(
        &mut self,
        rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<Vec<u8>, mpsc::error::TryRecvError> {
        let mut empty = mpsc::error::TryRecvError::Empty;
        // Остаток остается в канале: его backpressure не дает терять пачку
        // при переносе в уже заполненную очередь потоков.
        for _ in self.0.len()..self.0.capacity {
            match rx.try_recv() {
                Ok(packet) => self.push(packet),
                Err(error) => {
                    empty = error;
                    break;
                }
            }
        }
        self.pop().ok_or(empty)
    }

    pub async fn next(&mut self, rx: &mut mpsc::Receiver<Vec<u8>>) -> Option<Vec<u8>> {
        match self.try_next(rx) {
            Ok(packet) => Some(packet),
            Err(mpsc::error::TryRecvError::Disconnected) => None,
            Err(mpsc::error::TryRecvError::Empty) => {
                self.push(rx.recv().await?);
                self.try_next(rx).ok()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn draining_a_burst_preserves_every_accepted_packet() {
        let (tx, mut rx) = mpsc::channel(16);
        for sequence in 0..12 {
            tx.send(packet(443, sequence)).await.unwrap();
        }
        drop(tx);
        let mut queue = FlowQueue::new(4);
        let mut received = Vec::new();
        while let Some(packet) = queue.next(&mut rx).await {
            received.push(packet[28]);
        }
        assert_eq!(received, (0..12).collect::<Vec<_>>());
    }
    fn packet(port: u16, sequence: u8) -> Vec<u8> {
        let mut p = vec![0; 29];
        p[0] = 0x45;
        p[3] = 29;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[1, 1, 1, 1]);
        p[20..22].copy_from_slice(&5000u16.to_be_bytes());
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p[28] = sequence;
        p
    }
    #[test]
    fn clear_retain_and_single_slot_eviction_keep_queue_consistent() {
        let mut queue = FairQueue::new(0);
        assert!(queue.is_empty());
        assert!(queue.push(packet(443, 1), |p| p).unwrap().is_none());
        assert!(!queue.is_empty());
        assert_eq!(
            queue.push(packet(53, 2), |p| p).unwrap(),
            Some(packet(443, 1))
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop(), Some(packet(53, 2)));
        assert!(queue.is_empty());
        assert!(queue.pop().is_none());

        let mut queue = FairQueue::new(8);
        for p in [packet(443, 1), packet(443, 2), packet(53, 3)] {
            queue.push(p, |p| p).unwrap();
        }
        queue.retain(|p| p[28] == 2);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop(), Some(packet(443, 2)));
        assert!(queue.pop().is_none());
        queue.push(packet(80, 4), |p| p).unwrap();
        queue.clear();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert!(queue.pop().is_none());
        queue.push(packet(53, 5), |p| p).unwrap();
        assert_eq!(queue.pop(), Some(packet(53, 5)));
    }

    #[test]
    fn short_transport_headers_and_icmp_identifiers_are_bounded() {
        for length in 20..=29 {
            for protocol in [1, 6, 17, 58, 99] {
                let mut p = packet(443, 1);
                p.truncate(length);
                p[3] = length as u8;
                p[9] = protocol;
                if length >= 28 {
                    p[24..26].copy_from_slice(&[0x12, 0x34]);
                }
                let classified = flow(&p).unwrap();
                let expected = match protocol {
                    6 | 17 if length >= 24 => [0x13, 0x88, 0x01, 0xbb],
                    1 | 58 if length >= 28 => [0x12, 0x34, 0, 0],
                    _ => [0; 4],
                };
                assert_eq!(
                    classified.ports, expected,
                    "длина {length}, протокол {protocol}"
                );
                p[6] = 0x20;
                assert_eq!(flow(&p).unwrap().ports, [0; 4]);
            }
        }
        for length in 40..=48 {
            for protocol in [6, 17, 58, 99] {
                let mut p = vec![0; length];
                p[0] = 0x60;
                p[5] = (length - 40) as u8;
                p[6] = protocol;
                if length >= 44 {
                    p[40..44].copy_from_slice(&[1, 2, 3, 4]);
                }
                if length >= 48 {
                    p[44..46].copy_from_slice(&[5, 6]);
                }
                if length == 40 {
                    assert!(flow(&p).is_none());
                    continue;
                }
                let expected = match protocol {
                    6 | 17 if length >= 44 => [1, 2, 3, 4],
                    58 if length >= 48 => [5, 6, 0, 0],
                    _ => [0; 4],
                };
                assert_eq!(flow(&p).unwrap().ports, expected);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_flow_does_not_hide_the_age_of_a_persistent_backlog() {
        let mut queue = FlowQueue::new(8);
        queue.push(packet(443, 0));
        queue.push(packet(443, 1));
        tokio::time::advance(Duration::from_millis(75)).await;
        queue.push(packet(53, 2));
        assert_eq!(queue.pop(), Some(packet(443, 0)));
        assert_eq!(queue.queue_wait(), Duration::from_millis(75));
        assert_eq!(queue.pop(), Some(packet(53, 2)));
        assert_eq!(queue.queue_wait(), Duration::from_millis(75));
    }

    #[test]
    fn full_bulk_queue_admits_new_flow_and_preserves_surviving_order() {
        let mut queue = FlowQueue::new(4);
        for n in 0..4 {
            queue.push(packet(443, n));
        }
        queue.push(packet(53, 9));
        assert_eq!(queue.0.len(), 4);
        assert_eq!(queue.pop(), Some(packet(443, 0)));
        assert_eq!(queue.pop(), Some(packet(53, 9)));
        assert_eq!(queue.pop(), Some(packet(443, 1)));
        assert_eq!(queue.pop(), Some(packet(443, 2)));
        assert!(queue.pop().is_none());
    }
    #[test]
    fn congested_existing_flow_does_not_displace_other_flows() {
        let mut queue = FlowQueue::new(2);
        queue.push(packet(443, 0));
        queue.push(packet(53, 1));
        queue.push(packet(443, 2));
        assert_eq!(queue.pop(), Some(packet(443, 0)));
        assert_eq!(queue.pop(), Some(packet(53, 1)));
        assert!(queue.pop().is_none());
    }
    #[test]
    fn closed_channel_drains_each_flow_in_order() {
        let (tx, mut rx) = mpsc::channel(4);
        for p in [packet(443, 0), packet(443, 1), packet(53, 2)] {
            tx.try_send(p).unwrap();
        }
        drop(tx);
        let mut queue = FlowQueue::new(4);
        assert_eq!(queue.try_next(&mut rx).unwrap(), packet(443, 0));
        assert_eq!(queue.try_next(&mut rx).unwrap(), packet(53, 2));
        assert_eq!(queue.try_next(&mut rx).unwrap(), packet(443, 1));
        assert_eq!(
            queue.try_next(&mut rx).unwrap_err(),
            mpsc::error::TryRecvError::Disconnected
        );
    }
    #[tokio::test(start_paused = true)]
    async fn open_empty_channel_drains_lanes_and_fresh_packet_has_no_old_wait() {
        let (tx, mut rx) = mpsc::channel(4);
        for p in [packet(443, 0), packet(443, 1), packet(53, 2)] {
            tx.try_send(p).unwrap();
        }
        let mut queue = FlowQueue::new(4);
        assert_eq!(queue.try_next(&mut rx).unwrap(), packet(443, 0));
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(queue.try_next(&mut rx).unwrap(), packet(53, 2));
        assert_eq!(queue.queue_wait(), Duration::from_millis(100));
        assert_eq!(queue.try_next(&mut rx).unwrap(), packet(443, 1));
        assert_eq!(
            queue.try_next(&mut rx),
            Err(mpsc::error::TryRecvError::Empty)
        );
        tx.try_send(packet(443, 3)).unwrap();
        assert_eq!(queue.try_next(&mut rx).unwrap(), packet(443, 3));
        assert_eq!(queue.queue_wait(), Duration::ZERO);
    }

    #[test]
    fn ipv6_extension_headers_do_not_merge_dns_with_bulk() {
        for extension in [0, 43, 60, 51] {
            let mut bulk = vec![0; 80];
            bulk[0] = 0x60;
            bulk[5] = 40;
            bulk[6] = extension;
            bulk[40] = 17;
            // Заголовок 16 байт, с ненулевым полем длины по формату протокола.
            bulk[41] = if extension == 51 { 2 } else { 1 };
            bulk[56..60].copy_from_slice(&[1, 2, 1, 187]);
            let mut dns = bulk.clone();
            dns[58..60].copy_from_slice(&53u16.to_be_bytes());
            assert_ne!(
                flow(&bulk),
                flow(&dns),
                "DNS должен иметь свою очередь после расширения {extension}"
            );
            for end in 40..48 {
                let mut short = bulk[..end].to_vec();
                short[5] = (end - 40) as u8;
                let _ = flow(&short);
            }
        }
    }

    #[test]
    fn ipv6_fragments_keep_packet_order() {
        let mut queue = FairQueue::new(8);
        for sequence in 0..8 {
            let mut packet = vec![0; 56];
            packet[0] = 0x60;
            packet[5] = 16;
            packet[6] = 44;
            packet[40] = 17;
            packet[42..44]
                .copy_from_slice(&((sequence as u16 * 8) | u16::from(sequence != 7)).to_be_bytes());
            packet[48..52].fill(sequence);
            packet[55] = sequence;
            assert_eq!(flow(&packet).unwrap().protocol, 17);
            assert!(queue.push(packet, |packet| packet).is_ok());
        }
        assert_eq!(queue.lanes.len(), 1);
        for sequence in 0..8 {
            assert_eq!(queue.pop().unwrap()[55], sequence);
        }
    }

    #[test]
    fn bounded_extension_chain_still_separates_transport_ports() {
        let mut packet = vec![0; 40 + 15 * 8 + 8];
        packet[0] = 0x60;
        packet[5] = (packet.len() - 40) as u8;
        packet[6] = 60;
        for index in 0..15 {
            packet[40 + index * 8] = if index == 14 { 17 } else { 60 };
        }
        packet[160..164].copy_from_slice(&[1, 2, 0, 53]);
        assert_eq!(flow(&packet).unwrap().ports, [1, 2, 0, 53]);
        // Более длинная цепочка не обходится бесконечно и остается одной очередью.
        packet[152] = 60;
        assert_eq!(flow(&packet).unwrap().ports, [0; 4]);
    }

    #[test]
    fn eviction_preserves_the_short_lane_and_oldest_bulk_packets() {
        let mut queue = FairQueue::new(4);
        for sequence in 0..3 {
            assert!(queue.push(packet(443, sequence), |p| p).is_ok());
        }
        queue.push(packet(53, 9), |p| p).unwrap();
        assert_eq!(
            queue.push(packet(80, 8), |p| p).unwrap(),
            Some(packet(443, 2))
        );
        let remaining: Vec<_> = std::iter::from_fn(|| queue.pop()).collect();
        assert_eq!(remaining.len(), 4);
        assert!(remaining.contains(&packet(53, 9)));
        assert!(remaining.contains(&packet(80, 8)));
        let bulk: Vec<_> = remaining
            .iter()
            .filter(|p| p[22..24] == 443u16.to_be_bytes())
            .cloned()
            .collect();
        assert_eq!(bulk, [packet(443, 0), packet(443, 1)]);
    }

    #[test]
    fn fragments_stay_in_one_lane_and_unknown_packets_remain_fifo() {
        let mut first = packet(443, 1);
        first[6] = 0x20;
        let mut later = first.clone();
        later[6] = 0;
        later[7] = 1;
        later[22] = 99;
        assert_eq!(flow(&first), flow(&later));
        let mut queue = FlowQueue::new(4);
        queue.push(vec![1]);
        queue.push(vec![2]);
        assert_eq!(queue.pop(), Some(vec![1]));
        assert_eq!(queue.pop(), Some(vec![2]));
    }
}
