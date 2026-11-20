//! Тестовые IP-пакеты проходят те же очереди, padding и FEC, что и обычные данные.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub const DATA_BYTES: usize = 1024;
pub const WINDOW: u64 = 2048;
pub const MAX_BYTES: u64 = 512 * 1024 * 1024;
pub const BATCH: usize = 64;
const PORT: u16 = 65120;
const MAGIC: &[u8; 8] = b"AIVPNB2\0";
const HEADER: usize = 61;
const HISTORY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upload = 1,
    Download = 2,
}

pub struct Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub id: [u8; 16],
    pub direction: Direction,
    pub sequence: u64,
    pub payload: &'a [u8],
}

impl Packet<'_> {
    pub fn verify(&self, seed: &[u8; 32]) -> bool {
        let mut expected = [0; DATA_BYTES];
        fill(seed, self.direction, self.sequence, &mut expected);
        self.payload == expected
    }
}

pub fn packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    id: [u8; 16],
    seed: &[u8; 32],
    direction: Direction,
    sequence: u64,
) -> Vec<u8> {
    let length = HEADER + DATA_BYTES;
    let mut bytes = vec![0; length];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    let checksum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes[20..22].copy_from_slice(&PORT.to_be_bytes());
    bytes[22..24].copy_from_slice(&PORT.to_be_bytes());
    bytes[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
    bytes[28..36].copy_from_slice(MAGIC);
    bytes[36..52].copy_from_slice(&id);
    bytes[52] = direction as u8;
    bytes[53..61].copy_from_slice(&sequence.to_be_bytes());
    fill(seed, direction, sequence, &mut bytes[HEADER..]);
    bytes
}

fn fill(seed: &[u8; 32], direction: Direction, sequence: u64, bytes: &mut [u8]) {
    blake3::Hasher::new_derive_key("aivpn diagnostic data v2")
        .update(seed)
        .update(&[direction as u8])
        .update(&sequence.to_be_bytes())
        .finalize_xof()
        .fill(bytes);
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn parse(bytes: &[u8]) -> Option<Packet<'_>> {
    if bytes.len() != HEADER + DATA_BYTES
        || bytes[0] != 0x45
        || bytes[9] != 17
        || bytes[6] & 0x3f != 0
        || bytes[7] != 0
        || u16::from_be_bytes(bytes[2..4].try_into().ok()?) as usize != bytes.len()
        || checksum(&bytes[..20]) != 0
        || bytes[20..22] != PORT.to_be_bytes()
        || bytes[22..24] != PORT.to_be_bytes()
        || u16::from_be_bytes(bytes[24..26].try_into().ok()?) as usize != bytes.len() - 20
        || &bytes[28..36] != MAGIC
    {
        return None;
    }
    let direction = match bytes[52] {
        1 => Direction::Upload,
        2 => Direction::Download,
        _ => return None,
    };
    Some(Packet {
        source: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).ok()?),
        destination: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).ok()?),
        id: bytes[36..52].try_into().ok()?,
        direction,
        sequence: u64::from_be_bytes(bytes[53..61].try_into().ok()?),
        payload: &bytes[HEADER..],
    })
}

#[derive(Debug)]
pub struct Receipts {
    pub credit: u64,
    pub bytes: u64,
    seen: [u64; HISTORY / 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub id: [u8; 16],
    pub seed: [u8; 32],
    pub direction: Direction,
    pub response_id: u32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub version: u8,
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    #[serde(default)]
    pub download_limit_kbps: Option<u64>,
}

impl Capabilities {
    pub fn download_may_be_limited(&self, kbps: f64) -> bool {
        self.download_limit_kbps
            .is_some_and(|limit| limit > 0 && kbps >= limit as f64 * 0.8)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pull {
    pub id: [u8; 16],
    pub count: usize,
}

/// Состояние одной короткой фазы. Тел тестовых блоков здесь нет.
#[derive(Debug)]
pub struct ServerState {
    pub request: Start,
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub receipts: Receipts,
    expires: Instant,
    next_download: u64,
    acknowledged: u64,
    last_ack: Instant,
}

impl ServerState {
    pub fn new(
        request: Start,
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        now: Instant,
    ) -> Option<Self> {
        if request.duration_ms == 0 || request.duration_ms > 15_000 || request.response_id == 0 {
            return None;
        }
        Some(Self {
            expires: now + Duration::from_millis(request.duration_ms),
            request,
            client_ip,
            server_ip,
            receipts: Receipts::default(),
            next_download: 0,
            acknowledged: 0,
            last_ack: now,
        })
    }

    pub fn active(&self, id: &[u8; 16], now: Instant) -> bool {
        self.request.id == *id && now < self.expires
    }

    pub fn finish(&mut self, now: Instant) {
        self.expires = now;
    }

    pub fn upload(&mut self, packet: &Packet<'_>, now: Instant) -> Option<Vec<u8>> {
        if !self.active(&packet.id, now)
            || self.request.direction != Direction::Upload
            || packet.direction != Direction::Upload
            || packet.source != self.client_ip
            || packet.destination != self.server_ip
            || !packet.verify(&self.request.seed)
            || !self.receipts.accept(packet.sequence)
        {
            return None;
        }
        if self.receipts.credit - self.acknowledged >= 16
            || now.saturating_duration_since(self.last_ack) >= Duration::from_millis(40)
        {
            self.acknowledged = self.receipts.credit;
            self.last_ack = now;
            Some(receipt(
                self.request.id,
                self.receipts.credit,
                self.receipts.bytes,
            ))
        } else {
            None
        }
    }

    pub fn download(&mut self, now: Instant) -> Option<Vec<u8>> {
        if !self.active(&self.request.id, now)
            || self.request.direction != Direction::Download
            || self.next_download >= MAX_BYTES / DATA_BYTES as u64
        {
            return None;
        }
        let packet = packet(
            self.server_ip,
            self.client_ip,
            self.request.id,
            &self.request.seed,
            Direction::Download,
            self.next_download,
        );
        self.next_download += 1;
        Some(packet)
    }
}

pub fn receipt(id: [u8; 16], credit: u64, bytes: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(&id);
    body.extend_from_slice(&credit.to_be_bytes());
    body.extend_from_slice(&bytes.to_be_bytes());
    body
}

pub fn parse_receipt(body: &[u8], id: &[u8; 16]) -> Option<(u64, u64)> {
    if body.len() != 32 || body[..16] != *id {
        return None;
    }
    let credit = u64::from_be_bytes(body[16..24].try_into().ok()?);
    let bytes = u64::from_be_bytes(body[24..32].try_into().ok()?);
    (credit <= MAX_BYTES / DATA_BYTES as u64 && bytes <= credit * DATA_BYTES as u64)
        .then_some((credit, bytes))
}

#[cfg(feature = "client-upload")]
pub struct Receiver {
    pub request: Start,
    pub capabilities: Capabilities,
    pub counters: std::sync::Mutex<Receipts>,
    pub wake: tokio::sync::Notify,
    pub sending: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "client-upload")]
impl Receiver {
    pub fn new(request: Start, capabilities: Capabilities) -> Self {
        Self {
            request,
            capabilities,
            counters: std::sync::Mutex::new(Receipts::default()),
            wake: tokio::sync::Notify::new(),
            sending: std::sync::atomic::AtomicBool::new(true),
        }
    }

    pub fn receive(&self, packet: &Packet<'_>) {
        if self.request.direction != Direction::Download
            || packet.id != self.request.id
            || packet.direction != Direction::Download
            || packet.source != self.capabilities.server_ip
            || packet.destination != self.capabilities.client_ip
            || !packet.verify(&self.request.seed)
        {
            return;
        }
        if self
            .counters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accept(packet.sequence)
        {
            self.wake.notify_one();
        }
    }

    pub fn acknowledge(&self, body: &[u8]) {
        if self.request.direction != Direction::Upload {
            return;
        }
        let Some((credit, bytes)) = parse_receipt(body, &self.request.id) else {
            return;
        };
        let mut counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        counters.credit = counters.credit.max(credit);
        counters.bytes = counters.bytes.max(bytes);
        drop(counters);
        self.wake.notify_one();
    }

    pub fn snapshot(&self) -> (u64, u64) {
        let counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        (counters.credit, counters.bytes)
    }
}

impl Default for Receipts {
    fn default() -> Self {
        Self {
            credit: 0,
            bytes: 0,
            seen: [0; HISTORY / 64],
        }
    }
}

impl Receipts {
    pub fn accept(&mut self, sequence: u64) -> bool {
        if sequence >= MAX_BYTES / DATA_BYTES as u64
            || sequence.saturating_add(HISTORY as u64) < self.credit
        {
            return false;
        }
        if sequence >= self.credit {
            if sequence - self.credit >= HISTORY as u64 {
                self.seen.fill(0);
            } else {
                for next in self.credit..=sequence {
                    let slot = next as usize % HISTORY;
                    self.seen[slot / 64] &= !(1 << (slot % 64));
                }
            }
            self.credit = sequence + 1;
        }
        let slot = sequence as usize % HISTORY;
        let bit = 1 << (slot % 64);
        if self.seen[slot / 64] & bit != 0 {
            return false;
        }
        self.seen[slot / 64] |= bit;
        self.bytes += DATA_BYTES as u64;
        true
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn advertised_limit_is_optional_and_marks_saturated_downloads() {
        let old: super::Capabilities =
            serde_json::from_str(r#"{"version":2,"client_ip":"10.0.0.2","server_ip":"10.0.0.1"}"#)
                .unwrap();
        assert!(!old.download_may_be_limited(100_000.0));
        let limited = super::Capabilities {
            download_limit_kbps: Some(67_108),
            ..old
        };
        assert!(!limited.download_may_be_limited(30_000.0));
        assert!(limited.download_may_be_limited(65_000.0));
    }
    use super::*;

    #[test]
    fn test_packet_preserves_addresses_and_rejects_corrupt_content() {
        let source = Ipv4Addr::new(10, 0, 0, 2);
        let destination = Ipv4Addr::new(10, 0, 0, 1);
        let mut bytes = packet(
            source,
            destination,
            [3; 16],
            &[7; 32],
            Direction::Upload,
            123,
        );
        assert!(
            (1052..=1200).contains(&bytes.len()),
            "Тест должен использовать обычный IP-пакет без крупного RPC"
        );
        assert_eq!(&bytes[12..20], &[10, 0, 0, 2, 10, 0, 0, 1]);
        let decoded = parse(&bytes).expect("Нужен корректный тестовый пакет");
        assert_eq!((decoded.source, decoded.destination), (source, destination));
        assert_eq!(decoded.id, [3; 16]);
        assert_eq!(decoded.direction, Direction::Upload);
        assert_eq!(decoded.sequence, 123);
        assert!(decoded.verify(&[7; 32]));
        *bytes.last_mut().unwrap() ^= 1;
        assert!(!parse(&bytes).unwrap().verify(&[7; 32]));
    }

    #[test]
    fn receipt_credit_advances_over_loss_without_counting_duplicates() {
        let mut receipts = Receipts::default();
        assert!(receipts.accept(0));
        assert!(receipts.accept(2));
        assert_eq!(receipts.credit, 3);
        assert_eq!(receipts.bytes, 2048);
        assert!(!receipts.accept(2));
        assert!(receipts.accept(1));
        assert_eq!(receipts.bytes, 3072);
        assert_eq!(receipts.credit, 3);
        assert!(receipts.accept(10_000));
        assert!(!receipts.accept(0));
        assert_eq!(receipts.bytes, 4096);
        assert!(!receipts.accept(u64::MAX));
    }

    #[test]
    fn server_phase_expires_and_rejects_wrong_session_or_content() {
        let now = Instant::now();
        let client = Ipv4Addr::new(10, 0, 0, 2);
        let server = Ipv4Addr::new(10, 0, 0, 1);
        let request = Start {
            id: [3; 16],
            seed: [7; 32],
            direction: Direction::Upload,
            response_id: 42,
            duration_ms: 1000,
        };
        let mut state = ServerState::new(request.clone(), client, server, now).unwrap();
        for (id, seed, source) in [
            ([4; 16], [7; 32], client),
            ([3; 16], [8; 32], client),
            ([3; 16], [7; 32], server),
        ] {
            let bytes = packet(source, server, id, &seed, Direction::Upload, 0);
            assert!(state.upload(&parse(&bytes).unwrap(), now).is_none());
        }
        assert_eq!(state.receipts.bytes, 0);
        for sequence in 0..16 {
            let bytes = packet(
                client,
                server,
                request.id,
                &request.seed,
                Direction::Upload,
                sequence,
            );
            let ack = state.upload(&parse(&bytes).unwrap(), now);
            if sequence == 15 {
                assert_eq!(
                    parse_receipt(&ack.unwrap(), &request.id),
                    Some((16, 16 * DATA_BYTES as u64))
                );
            }
        }
        let bytes = packet(
            client,
            server,
            request.id,
            &request.seed,
            Direction::Upload,
            16,
        );
        assert!(state
            .upload(&parse(&bytes).unwrap(), now + Duration::from_secs(1))
            .is_none());
        assert_eq!(state.receipts.credit, 16);
        assert!(!state.active(&request.id, now + Duration::from_secs(1)));
        let mut invalid = request;
        invalid.duration_ms = 15_001;
        assert!(ServerState::new(invalid, client, server, now).is_none());
    }

    #[test]
    fn download_has_a_byte_limit_and_cannot_outlive_its_phase() {
        let now = Instant::now();
        let request = Start {
            id: [1; 16],
            seed: [2; 32],
            direction: Direction::Download,
            response_id: 1,
            duration_ms: 500,
        };
        let mut state =
            ServerState::new(request, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, now).unwrap();
        state.next_download = MAX_BYTES / DATA_BYTES as u64 - 1;
        assert!(state.download(now).is_some());
        assert!(state.download(now).is_none());
        state.next_download = 0;
        assert!(state.download(now + Duration::from_millis(500)).is_none());
        assert!(parse_receipt(
            &receipt([1; 16], WINDOW, WINDOW * DATA_BYTES as u64 + 1),
            &[1; 16]
        )
        .is_none());
    }
}
