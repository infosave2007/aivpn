//! Состояние TURN внутри маски. Сеть и UDP-сокет принадлежат вызывающему коду.

use crate::{turn_wire::TurnMessage, Error, Result};
use rand::{rngs::OsRng, Rng, RngCore};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};
use stun::{attributes::*, integrity::MessageIntegrity};
use zeroize::Zeroize;

const QUEUE: usize = 64;
const SETUP: Duration = Duration::from_secs(10);
const LIFETIME: Duration = Duration::from_secs(600);
const PERMISSION_TIME: Duration = Duration::from_secs(300);
const REFRESH_AFTER: Duration = Duration::from_secs(180);
const CHANNEL: u16 = 0x4000;

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Allocate,
    Refresh,
    Permission,
    Bind,
}

impl Phase {
    fn method(self) -> u16 {
        match self {
            Self::Allocate => 3,
            Self::Refresh => 4,
            Self::Permission => 8,
            Self::Bind => 9,
        }
    }
}

struct Transaction {
    phase: Phase,
    id: [u8; 12],
    wire: Vec<u8>,
    started: Instant,
    next: Instant,
    rto: Duration,
    attempts: u8,
}

struct Reply {
    id: [u8; 12],
    request: blake3::Hash,
    wire: Vec<u8>,
}

pub struct TurnMask {
    server: bool,
    username: String,
    realm: String,
    integrity: MessageIntegrity,
    nonce: Vec<u8>,
    local: SocketAddr,
    peer: SocketAddr,
    relayed: SocketAddr,
    created: Instant,
    last_now: Instant,
    established: bool,
    closed: bool,
    allocation: Option<Instant>,
    permission: Option<Instant>,
    channel: Option<Instant>,
    refresh: Option<Instant>,
    transaction: Option<Transaction>,
    replies: VecDeque<Reply>,
    wire: VecDeque<Vec<u8>>,
    payloads: VecDeque<Vec<u8>>,
    pending: VecDeque<Vec<u8>>,
}

impl Drop for TurnMask {
    fn drop(&mut self) {
        self.integrity.0.zeroize();
    }
}
pub struct TurnMaskOutput {
    pub wire: Vec<Vec<u8>>,
    pub payloads: Vec<Vec<u8>>,
    pub ready: bool,
}

impl TurnMask {
    pub fn client(
        username: &str,
        password: &str,
        realm: &str,
        server: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        let mut mask = Self::new(false, username, password, realm, server, server, now)?;
        mask.begin(Phase::Allocate, now)?;
        Ok(mask)
    }

    /// Сервер создается только для уже допущенной PFS-сессии AIVPN.
    /// Релейная сторона заканчивается во внутреннем движке маски. Новый
    /// сетевой адрес или сокет из XOR-атрибутов здесь не открывается.
    pub fn server(
        username: &str,
        password: &str,
        realm: &str,
        local: SocketAddr,
        peer: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        Self::new(true, username, password, realm, local, peer, now)
    }

    fn new(
        server: bool,
        username: &str,
        password: &str,
        realm: &str,
        local: SocketAddr,
        peer: SocketAddr,
        now: Instant,
    ) -> Result<Self> {
        let text = |value: &str| value.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
        if !(4..=64).contains(&username.len())
            || !(22..=128).contains(&password.len())
            || !(1..=64).contains(&realm.len())
            || !text(username)
            || !text(password)
            || !text(realm)
            || username.contains(':')
            || realm.contains(':')
            || local.port() == 0
            || peer.port() == 0
            || local.ip().is_unspecified()
            || local.ip().is_multicast()
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
        {
            return Err(Error::InvalidPacket("Недопустимые параметры TURN"));
        }
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let nonce = if server {
            hex::encode(random).into_bytes()
        } else {
            vec![]
        };
        Ok(Self {
            server,
            username: username.into(),
            realm: realm.into(),
            integrity: MessageIntegrity::new_long_term_integrity(
                username.into(),
                realm.into(),
                password.into(),
            ),
            nonce,
            local,
            peer,
            relayed: SocketAddr::new(local.ip(), OsRng.gen_range(49152..=65535)),
            created: now,
            last_now: now,
            established: false,
            closed: false,
            allocation: None,
            permission: None,
            channel: None,
            refresh: None,
            transaction: None,
            replies: VecDeque::new(),
            wire: VecDeque::new(),
            payloads: VecDeque::new(),
            pending: VecDeque::new(),
        })
    }

    pub fn ready(&self, now: Instant) -> bool {
        !self.closed
            && self.established
            && [self.allocation, self.permission, self.channel]
                .iter()
                .all(|end| end.is_some_and(|end| end > now))
    }

    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed
    }

    pub fn deadline(&self) -> Option<Instant> {
        if self.ready(self.last_now) && !self.pending.is_empty() {
            return Some(self.last_now + Duration::from_millis(1));
        }
        let setup = (!self.established).then_some(self.created + SETUP);
        [
            setup,
            self.transaction.as_ref().map(|pending| pending.next),
            self.refresh,
            self.allocation,
            self.permission,
            self.channel,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn poll(&mut self, now: Instant) -> Result<TurnMaskOutput> {
        let now = now.max(self.last_now);
        self.last_now = now;
        if (self.closed && self.wire.is_empty())
            || (!self.established && now.saturating_duration_since(self.created) >= SETUP)
        {
            return Err(Error::Session(
                "TURN закрыт или истек срок согласования".into(),
            ));
        }
        if self.allocation.is_some_and(|end| end <= now) {
            self.closed = true;
            if self.wire.is_empty() {
                return Err(Error::Session("Истек срок allocation TURN".into()));
            }
        }
        if self.permission.is_some_and(|end| end <= now) {
            self.permission = None;
        }
        if self.channel.is_some_and(|end| end <= now) {
            self.channel = None;
        }
        if !self.server && self.refresh.is_some_and(|at| at <= now) && self.transaction.is_none() {
            self.refresh = None;
            self.begin(Phase::Refresh, now)?;
        }
        if let Some(transaction) = self
            .transaction
            .as_mut()
            .filter(|pending| pending.next <= now)
        {
            if transaction.attempts >= 7
                || now.saturating_duration_since(transaction.started) >= SETUP
            {
                return Err(Error::Session("Нет ответа на TURN control".into()));
            }
            if self.wire.len() < QUEUE {
                self.wire.push_back(transaction.wire.clone());
            }
            transaction.rto = (transaction.rto * 2).min(Duration::from_secs(2));
            transaction.next = now + transaction.rto;
            transaction.attempts += 1;
        }
        if self.ready(now) {
            while self.wire.len() < QUEUE {
                let Some(payload) = self.pending.pop_front() else {
                    break;
                };
                self.channel_packet(&payload)?;
            }
        }
        Ok(TurnMaskOutput {
            wire: self.wire.drain(..).collect(),
            payloads: self.payloads.drain(..).collect(),
            ready: self.ready(now),
        })
    }

    pub fn receive(&mut self, wire: &[u8], now: Instant) -> Result<()> {
        let now = now.max(self.last_now);
        self.last_now = now;
        if self.closed || wire.is_empty() || wire.len() > 1380 {
            return Ok(());
        }
        if wire[0] & 0xc0 == 0x40 {
            if self.ready(now)
                && wire.len() >= 4
                && u16::from_be_bytes([wire[0], wire[1]]) == CHANNEL
            {
                let length = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
                if (1..=1376).contains(&length)
                    && (wire.len() == length + 4 || wire.len() == length.next_multiple_of(4) + 4)
                    && self.payloads.len() < QUEUE
                {
                    self.payloads.push_back(wire[4..4 + length].to_vec());
                }
            }
            return Ok(());
        }
        let Ok(mut message) = TurnMessage::parse(wire) else {
            return Ok(());
        };
        let result = if self.server {
            self.request(&mut message, wire, now)
        } else {
            self.response(&mut message, now)
        };
        match result {
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            result => result,
        }
    }

    pub fn send(&mut self, payload: &[u8], now: Instant) -> Result<()> {
        let now = now.max(self.last_now);
        self.last_now = now;
        if self.closed || payload.is_empty() || payload.len() > 1376 {
            return Err(Error::InvalidPacket("Пакет не вмещается в TURN-маску"));
        }
        if self.ready(now) {
            self.channel_packet(payload)
        } else if self.pending.len() < QUEUE {
            self.pending.push_back(payload.to_vec());
            Ok(())
        } else {
            Err(Error::Io(std::io::ErrorKind::WouldBlock.into()))
        }
    }

    fn channel_packet(&mut self, payload: &[u8]) -> Result<()> {
        let mut wire = Vec::with_capacity(payload.len() + 4);
        wire.extend_from_slice(&CHANNEL.to_be_bytes());
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(payload);
        self.push(wire)
    }

    fn push(&mut self, packet: Vec<u8>) -> Result<()> {
        if self.wire.len() >= QUEUE {
            return Err(Error::Io(std::io::ErrorKind::WouldBlock.into()));
        }
        self.wire.push_back(packet);
        Ok(())
    }

    fn begin(&mut self, phase: Phase, now: Instant) -> Result<()> {
        let mut id = [0; 12];
        OsRng.fill_bytes(&mut id);
        let mut attributes = match phase {
            Phase::Allocate => vec![
                (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
                (ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
            Phase::Refresh => vec![(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec())],
            Phase::Permission => vec![TurnMessage::address_attribute(
                ATTR_XOR_PEER_ADDRESS,
                self.local,
                id,
            )?],
            Phase::Bind => vec![
                (ATTR_CHANNEL_NUMBER, vec![0x40, 0, 0, 0]),
                TurnMessage::address_attribute(ATTR_XOR_PEER_ADDRESS, self.local, id)?,
            ],
        };
        let authenticated = !self.nonce.is_empty();
        if authenticated {
            attributes.extend([
                (ATTR_USERNAME, self.username.as_bytes().to_vec()),
                (ATTR_REALM, self.realm.as_bytes().to_vec()),
                (ATTR_NONCE, self.nonce.clone()),
            ]);
        }
        let wire = TurnMessage::build(
            phase.method(),
            id,
            &attributes,
            authenticated.then_some(&self.integrity),
        )?;
        self.push(wire.clone())?;
        self.transaction = Some(Transaction {
            phase,
            id,
            wire,
            started: now,
            next: now + Duration::from_millis(250),
            rto: Duration::from_millis(250),
            attempts: 1,
        });
        Ok(())
    }

    fn response(&mut self, message: &mut TurnMessage, now: Instant) -> Result<()> {
        let Some(pending) = self
            .transaction
            .as_ref()
            .filter(|pending| pending.id == message.message.transaction_id.0)
        else {
            return Ok(());
        };
        let phase = pending.phase;
        let typ = message.message.typ.value();
        if typ == phase.method() | 0x0110 {
            let code = message.message.get(ATTR_ERROR_CODE).unwrap_or_default();
            let error = if code.len() >= 4 {
                u16::from(code[2]) * 100 + u16::from(code[3])
            } else {
                0
            };
            if (error == 401 && self.nonce.is_empty()) || error == 438 {
                let realm = message.message.get(ATTR_REALM).unwrap_or_default();
                let nonce = message.message.get(ATTR_NONCE).unwrap_or_default();
                if realm == self.realm.as_bytes()
                    && (16..=128).contains(&nonce.len())
                    && nonce.iter().all(|byte| (0x21..=0x7e).contains(byte))
                {
                    self.nonce = nonce;
                    self.begin(phase, now)?;
                }
            }
            return Ok(());
        }
        if typ != phase.method() | 0x0100 || message.authenticate(&self.integrity).is_err() {
            return Ok(());
        }
        self.transaction = None;
        match phase {
            Phase::Allocate | Phase::Refresh => {
                let lifetime = message.message.get(ATTR_LIFETIME).unwrap_or_default();
                if lifetime.len() != 4 {
                    return Err(Error::InvalidPacket("Нет lifetime в ответе TURN"));
                }
                let lifetime = u32::from_be_bytes(lifetime.try_into().unwrap());
                if !(1..=3600).contains(&lifetime) {
                    return Err(Error::InvalidPacket("Некорректный lifetime TURN"));
                }
                if phase == Phase::Allocate {
                    let relayed = message.address(ATTR_XOR_RELAYED_ADDRESS)?;
                    if relayed.port() == 0
                        || relayed.ip().is_unspecified()
                        || relayed.ip().is_multicast()
                    {
                        return Err(Error::InvalidPacket("Некорректный relay TURN"));
                    }
                    self.relayed = relayed;
                }
                self.allocation = Some(now + Duration::from_secs(u64::from(lifetime)));
                self.begin(Phase::Permission, now)?;
            }
            Phase::Permission => {
                self.permission = Some(now + PERMISSION_TIME);
                self.begin(Phase::Bind, now)?;
            }
            Phase::Bind => {
                self.permission = Some(now + PERMISSION_TIME);
                self.channel = Some(now + LIFETIME);
                self.established = true;
                self.refresh = Some(now + REFRESH_AFTER);
            }
        }
        Ok(())
    }

    fn request(&mut self, message: &mut TurnMessage, wire: &[u8], now: Instant) -> Result<()> {
        let typ = message.message.typ.value();
        if ![3, 4, 8, 9].contains(&typ) {
            return Ok(());
        }
        let id = message.message.transaction_id.0;
        let digest = blake3::hash(wire);
        if let Some(previous) = self.replies.iter().find(|previous| previous.id == id) {
            return if previous.request == digest {
                self.push(previous.wire.clone())
            } else {
                Ok(())
            };
        }
        let authenticated = message.message.get(ATTR_USERNAME).ok().as_deref()
            == Some(self.username.as_bytes())
            && message.message.get(ATTR_REALM).ok().as_deref() == Some(self.realm.as_bytes())
            && message.authenticate(&self.integrity).is_ok();
        let nonce_valid =
            message.message.get(ATTR_NONCE).ok().as_deref() == Some(self.nonce.as_slice());
        let mut error = if !authenticated {
            Some(401u16)
        } else if !nonce_valid {
            Some(438)
        } else {
            None
        };
        let mut attributes = Vec::new();
        if error.is_none() {
            match typ {
                3 => {
                    if message
                        .message
                        .get(ATTR_REQUESTED_TRANSPORT)
                        .ok()
                        .as_deref()
                        != Some([17, 0, 0, 0].as_slice())
                    {
                        error = Some(442);
                    } else if self.allocation.is_some() {
                        error = Some(437);
                    } else {
                        self.allocation = Some(now + LIFETIME);
                        attributes.extend([
                            TurnMessage::address_attribute(
                                ATTR_XOR_RELAYED_ADDRESS,
                                self.relayed,
                                id,
                            )?,
                            TurnMessage::address_attribute(ATTR_XORMAPPED_ADDRESS, self.peer, id)?,
                            (ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
                        ]);
                    }
                }
                4 if self.allocation.is_some() => {
                    let value = message
                        .message
                        .get(ATTR_LIFETIME)
                        .unwrap_or_else(|_| 600u32.to_be_bytes().to_vec());
                    if value.len() != 4 {
                        error = Some(400);
                    } else {
                        let requested = u32::from_be_bytes(value.try_into().unwrap()).min(600);
                        self.allocation = Some(now + Duration::from_secs(u64::from(requested)));
                        self.closed = requested == 0;
                        attributes.push((ATTR_LIFETIME, requested.to_be_bytes().to_vec()));
                    }
                }
                8 | 9 if self.allocation.is_some() => {
                    if message.address(ATTR_XOR_PEER_ADDRESS).ok() != Some(self.local) {
                        error = Some(403);
                    } else if typ == 9
                        && message.message.get(ATTR_CHANNEL_NUMBER).ok().as_deref()
                            != Some([0x40, 0, 0, 0].as_slice())
                    {
                        error = Some(400);
                    } else {
                        self.permission = Some(now + PERMISSION_TIME);
                        if typ == 9 {
                            self.channel = Some(now + LIFETIME);
                            self.established = true;
                        }
                    }
                }
                _ => error = Some(437),
            }
        }
        if let Some(code) = error {
            attributes.clear();
            let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
            value.extend_from_slice(match code {
                401 => b"Unauthorized".as_slice(),
                438 => b"Stale Nonce".as_slice(),
                _ => b"Request rejected".as_slice(),
            });
            attributes.push((ATTR_ERROR_CODE, value));
            if matches!(code, 401 | 438) {
                attributes.extend([
                    (ATTR_REALM, self.realm.as_bytes().to_vec()),
                    (ATTR_NONCE, self.nonce.clone()),
                ]);
            }
        }
        let response = TurnMessage::build(
            typ | if error.is_some() { 0x0110 } else { 0x0100 },
            id,
            &attributes,
            (authenticated && error != Some(401) && error != Some(438)).then_some(&self.integrity),
        )?;
        if authenticated && nonce_valid {
            if self.replies.len() == 8 {
                self.replies.pop_front();
            }
            self.replies.push_back(Reply {
                id,
                request: digest,
                wire: response.clone(),
            });
        }
        self.push(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{HashSet, VecDeque},
        time::Duration,
    };

    fn pair(now: Instant) -> (TurnMask, TurnMask) {
        let address = "192.0.2.1:443".parse().unwrap();
        let peer = "192.0.2.2:50000".parse().unwrap();
        let password = "0123456789abcdef0123456789abcdef";
        (
            TurnMask::client("client0123456789", password, "turn.example", address, now).unwrap(),
            TurnMask::server(
                "client0123456789",
                password,
                "turn.example",
                address,
                peer,
                now,
            )
            .unwrap(),
        )
    }

    fn exchange(left: &mut TurnMask, right: &mut TurnMask, now: Instant) -> HashSet<u16> {
        let mut types = HashSet::new();
        for _ in 0..8 {
            let output = left.poll(now).unwrap();
            for wire in output.wire {
                types.insert(u16::from_be_bytes([wire[0], wire[1]]));
                right.receive(&wire, now).unwrap();
            }
            let output = right.poll(now).unwrap();
            for wire in output.wire {
                types.insert(u16::from_be_bytes([wire[0], wire[1]]));
                left.receive(&wire, now).unwrap();
            }
            if left.ready(now) && right.ready(now) && left.transaction.is_none() {
                break;
            }
        }
        types
    }

    #[test]
    fn wrong_credentials_and_foreign_relay_target_cannot_open_channel() {
        let now = Instant::now();
        let (mut client, mut server) = pair(now);
        let initial = client.poll(now).unwrap().wire.remove(0);
        server.receive(&initial, now).unwrap();
        let challenge = server.poll(now).unwrap().wire.remove(0);
        client.receive(&challenge, now).unwrap();
        let parsed = TurnMessage::parse(&client.poll(now).unwrap().wire.remove(0)).unwrap();
        let attributes = [
            ATTR_USERNAME,
            ATTR_REALM,
            ATTR_NONCE,
            ATTR_REQUESTED_TRANSPORT,
        ]
        .into_iter()
        .map(|kind| (kind, parsed.message.get(kind).unwrap()))
        .collect::<Vec<_>>();
        let wrong_key = MessageIntegrity::new_long_term_integrity(
            server.username.clone(),
            server.realm.clone(),
            "wrong-password0123456789".into(),
        );
        let request = TurnMessage::build(
            3,
            parsed.message.transaction_id.0,
            &attributes,
            Some(&wrong_key),
        )
        .unwrap();
        server.receive(&request, now).unwrap();
        assert!(server.allocation.is_none());
        assert!(server.poll(now).unwrap().payloads.is_empty());

        let (mut client, mut server) = pair(now);
        exchange(&mut client, &mut server, now);
        server.permission = None;
        server.channel = None;
        let id = [13; 12];
        let attrs = vec![
            (ATTR_USERNAME, server.username.as_bytes().to_vec()),
            (ATTR_REALM, server.realm.as_bytes().to_vec()),
            (ATTR_NONCE, server.nonce.clone()),
            (ATTR_CHANNEL_NUMBER, vec![0x40, 0, 0, 0]),
            TurnMessage::address_attribute(
                ATTR_XOR_PEER_ADDRESS,
                "127.0.0.1:22".parse().unwrap(),
                id,
            )
            .unwrap(),
        ];
        let request = TurnMessage::build(9, id, &attrs, Some(&server.integrity)).unwrap();
        server.receive(&request, now).unwrap();
        assert!(server.permission.is_none() && server.channel.is_none());
        let output = server.poll(now).unwrap();
        assert!(!output.ready && output.payloads.is_empty());
        let response = TurnMessage::parse(&output.wire[0]).unwrap();
        assert_eq!(response.message.typ.value(), 0x0119);
        assert_eq!(
            &response.message.get(ATTR_ERROR_CODE).unwrap()[..4],
            &[0, 0, 4, 3]
        );
    }

    #[test]
    fn refresh_renews_allocation_permission_and_channel_for_long_sessions() {
        let start = Instant::now();
        let (mut left, mut right) = pair(start);
        exchange(&mut left, &mut right, start);
        assert!(left.ready(start) && right.ready(start));
        for round in 1..=5 {
            let now = start + Duration::from_secs(181 * round);
            let types = exchange(&mut left, &mut right, now);
            assert!(types.is_superset(&HashSet::from([4, 0x0104, 8, 0x0108, 9, 0x0109])));
            assert!(left.ready(now) && right.ready(now));
        }
    }

    #[test]
    fn queued_payloads_keep_progress_without_another_received_packet() {
        let now = Instant::now();
        let (mut left, mut right) = pair(now);
        for _ in 0..QUEUE {
            right.send(&[0x80; 32], now).unwrap();
        }
        exchange(&mut left, &mut right, now);
        assert!(right.ready(now));
        assert_eq!(
            right.pending.len(),
            1,
            "Ответ ChannelBind занимает один слот выхода"
        );
        assert!(
            right.deadline().unwrap() <= now + Duration::from_millis(1),
            "Остаток очереди застрял до фонового таймера"
        );
        assert_eq!(
            right
                .poll(now + Duration::from_millis(1))
                .unwrap()
                .wire
                .len(),
            1
        );
    }

    #[test]
    fn unauthenticated_noise_cannot_evict_authenticated_allocate_reply() {
        let now = Instant::now();
        let address = "192.0.2.1:443".parse().unwrap();
        let peer = "192.0.2.2:50000".parse().unwrap();
        let mut server = TurnMask::server(
            "client0123456789",
            "0123456789abcdef0123456789abcdef",
            "turn.example",
            address,
            peer,
            now,
        )
        .unwrap();
        let attrs = vec![
            (ATTR_USERNAME, server.username.as_bytes().to_vec()),
            (ATTR_REALM, server.realm.as_bytes().to_vec()),
            (ATTR_NONCE, server.nonce.clone()),
            (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
        ];
        let request = TurnMessage::build(3, [9; 12], &attrs, Some(&server.integrity)).unwrap();
        server.receive(&request, now).unwrap();
        let expected = server.poll(now).unwrap().wire;
        assert_eq!(u16::from_be_bytes([expected[0][0], expected[0][1]]), 0x0103);
        for id in 10..42u8 {
            let noise = TurnMessage::build(3, [id; 12], &[], None).unwrap();
            server.receive(&noise, now).unwrap();
            let output = server.poll(now).unwrap();
            assert!(!output.ready);
            assert!(output.payloads.is_empty());
        }
        server.receive(&request, now).unwrap();
        assert_eq!(
            server.poll(now).unwrap().wire,
            expected,
            "Шум вытеснил кеш и изменил ответ на корректный retry"
        );
        assert!(server.permission.is_none() && server.channel.is_none());
    }

    #[test]
    fn unauthenticated_flood_is_bounded_without_terminating_session() {
        let now = Instant::now();
        let mut server = TurnMask::server(
            "client0123456789",
            "0123456789abcdef0123456789abcdef",
            "turn.example",
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.2:50000".parse().unwrap(),
            now,
        )
        .unwrap();
        for value in 0..1000u32 {
            let mut id = [0; 12];
            id[..4].copy_from_slice(&value.to_be_bytes());
            server
                .receive(&TurnMessage::build(3, id, &[], None).unwrap(), now)
                .unwrap();
        }
        let output = server.poll(now).unwrap();
        assert!(output.wire.len() <= QUEUE);
        assert!(!output.ready && output.payloads.is_empty());
        assert!(server.replies.is_empty() && server.allocation.is_none());
    }

    #[test]
    fn full_turn_auth_permission_channel_loss_duplicates_and_mtu() {
        let start = Instant::now();
        let server: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let peer: SocketAddr = "192.0.2.2:50000".parse().unwrap();
        let password = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut left =
            TurnMask::client("client0123456789", password, "turn.example", server, start).unwrap();
        let mut right = TurnMask::server(
            "client0123456789",
            password,
            "turn.example",
            server,
            peer,
            start,
        )
        .unwrap();
        let mut wire = VecDeque::<(bool, Vec<u8>)>::new();
        let mut types = HashSet::new();
        let mut dropped = false;
        let mut wrote = false;
        let mut received = [vec![], vec![]];
        for step in 0..10_000 {
            let now = start + Duration::from_millis(step);
            while let Some((to_right, packet)) = wire.pop_front() {
                let target = if to_right { &mut right } else { &mut left };
                target.receive(&packet, now).unwrap();
                // STUN-транзакция идемпотентна, ChannelData сохраняет семантику UDP.
                if packet[0] & 0xc0 == 0 {
                    target.receive(&packet, now).unwrap();
                }
            }
            let mut both_ready = true;
            for (index, target) in [&mut left, &mut right].into_iter().enumerate() {
                let output = target.poll(now).unwrap();
                both_ready &= output.ready;
                received[index].extend(output.payloads);
                for packet in output.wire {
                    assert!(packet.len() <= 1380);
                    if packet[0] & 0xc0 == 0 {
                        let typ = u16::from_be_bytes([packet[0], packet[1]]);
                        types.insert(typ);
                        if !dropped && typ == 0x0113 {
                            dropped = true;
                            continue;
                        }
                    }
                    assert!(wire.len() < 64);
                    wire.push_back((index == 0, packet));
                }
            }
            if both_ready && !wrote {
                left.send(&vec![0x80; 1376], now).unwrap();
                right.send(&vec![0x81; 1376], now).unwrap();
                wrote = true;
            }
            if received.iter().all(|packets| !packets.is_empty()) {
                break;
            }
        }
        assert!(wrote && dropped);
        assert_eq!(received[0], vec![vec![0x81; 1376]]);
        assert_eq!(received[1], vec![vec![0x80; 1376]]);
        assert!(types.is_superset(&HashSet::from([
            0x0003, 0x0113, 0x0103, 0x0008, 0x0108, 0x0009, 0x0109
        ])));
        assert!(left
            .send(&vec![0; 1377], start + Duration::from_secs(11))
            .is_err());
    }
}
