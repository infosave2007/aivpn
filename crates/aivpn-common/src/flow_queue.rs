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
        // Расширенные и фрагментированные IPv6-пакеты остаются в одном потоке.
        (packet[6], 40, false)
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
        for _ in 0..self.0.capacity {
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
