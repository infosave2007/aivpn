//! HTTP/3 внутри QUIC-маски: SETTINGS, CONNECT-UDP и контекст DATAGRAM.
//! Логический UDP peer заканчивается в маске, публичного proxy здесь нет.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use qpack::{decode_stateless, encode_stateless, HeaderField};
use quinn_proto::{coding::Codec, Connection, Dir, ReadError, StreamId, WriteError};

use crate::{Error, Result};

const LIMIT: usize = 4096;
const STREAMS: usize = 4;
const PATH: &[u8] = b"/.well-known/masque/udp/192.0.2.1/443/";

#[derive(Default)]
struct Incoming {
    kind: Option<u64>,
    bytes: Vec<u8>,
    headers: bool,
}

pub(crate) struct H3Mask {
    server: bool,
    authority: String,
    started: bool,
    settings: bool,
    control: Option<StreamId>,
    qpack: [Option<StreamId>; 2],
    request: Option<StreamId>,
    ready: bool,
    incoming: HashMap<StreamId, Incoming>,
    outgoing: VecDeque<(StreamId, Bytes)>,
    early: VecDeque<Vec<u8>>,
    read_pending: bool,
}

impl H3Mask {
    pub fn new(server: bool, authority: String) -> Self {
        Self {
            server,
            authority,
            started: false,
            settings: false,
            control: None,
            qpack: [None, None],
            request: None,
            ready: false,
            incoming: HashMap::new(),
            outgoing: VecDeque::new(),
            early: VecDeque::new(),
            read_pending: false,
        }
    }

    pub fn ready(&self) -> bool {
        self.ready
    }

    pub fn read_pending(&self) -> bool {
        self.read_pending
    }

    pub fn set_authority(&mut self, authority: &str) -> Result<()> {
        if self.started {
            return Ok(());
        }
        if !valid_authority(authority.as_bytes()) {
            return Err(Error::InvalidPacket("Недопустимый authority HTTP/3"));
        }
        self.authority = authority.to_owned();
        Ok(())
    }

    pub fn datagram(payload: &[u8]) -> Bytes {
        let mut framed = Vec::with_capacity(payload.len() + 2);
        // Единственный запрос имеет stream id 0, единственный UDP context id 0.
        framed.extend_from_slice(&[0, 0]);
        framed.extend_from_slice(payload);
        Bytes::from(framed)
    }

    pub fn poll(
        &mut self,
        conn: &mut Connection,
        connected: bool,
        payloads: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        if !connected {
            return Ok(());
        }
        self.read_pending = false;
        if !self.started {
            self.start(conn)?;
        }
        for direction in [Dir::Uni, Dir::Bi] {
            while let Some(id) = conn.streams().accept(direction) {
                if self.incoming.len() >= STREAMS
                    || (direction == Dir::Bi
                        && (!self.server || self.request.is_some() || u64::from(id) != 0))
                {
                    return Err(Error::InvalidPacket("Лишний поток HTTP/3"));
                }
                if direction == Dir::Bi {
                    self.request = Some(id);
                }
                self.incoming.insert(
                    id,
                    Incoming {
                        kind: (direction == Dir::Bi).then_some(0x100),
                        ..Default::default()
                    },
                );
            }
        }
        let mut ids = self.incoming.keys().copied().collect::<Vec<_>>();
        ids.sort_by_key(|id| (u64::from(*id) & 2 == 0, u64::from(*id)));
        for id in ids {
            if u64::from(id) & 2 == 0 && !self.settings {
                continue;
            }
            let mut incoming = self.incoming.remove(&id).unwrap();
            let outcome = self.read_stream(conn, id, &mut incoming);
            self.incoming.insert(id, incoming);
            outcome?;
        }
        if self.settings && !self.server && self.request.is_none() {
            let id = conn
                .streams()
                .open(Dir::Bi)
                .ok_or(Error::InvalidPacket("Нет потока CONNECT-UDP"))?;
            if u64::from(id) != 0 {
                return Err(Error::InvalidPacket(
                    "CONNECT-UDP имеет неожиданный stream id",
                ));
            }
            self.request = Some(id);
            let fields = self.request_headers();
            self.queue_headers(id, fields)?;
            self.incoming.insert(
                id,
                Incoming {
                    kind: Some(0x100),
                    ..Default::default()
                },
            );
        }
        self.flush(conn)?;
        while let Some(bytes) = conn.datagrams().recv() {
            let Some((stream, used)) = varint(&bytes) else {
                return Err(Error::InvalidPacket("Обрезан HTTP/3 DATAGRAM"));
            };
            if stream > (1u64 << 60) - 1 {
                return Err(Error::InvalidPacket("Слишком большой HTTP/3 stream id"));
            }
            if stream != 0 || self.request.is_none() {
                continue;
            }
            let Some((context, context_len)) = varint(&bytes[used..]) else {
                return Err(Error::InvalidPacket("Обрезан UDP context"));
            };
            if context != 0 {
                continue;
            }
            let payload = &bytes[used + context_len..];
            if payload.is_empty() || payload.len() > 1320 {
                continue;
            }
            if self.ready {
                payloads.push(payload.to_vec());
            } else if self.early.len() < 64 {
                self.early.push_back(payload.to_vec());
            }
        }
        if self.ready {
            payloads.extend(self.early.drain(..));
        }
        Ok(())
    }

    fn start(&mut self, conn: &mut Connection) -> Result<()> {
        for kind in [0, 2, 3] {
            let id = conn
                .streams()
                .open(Dir::Uni)
                .ok_or(Error::InvalidPacket("Нет управляющего потока HTTP/3"))?;
            let mut data = vec![kind];
            if kind == 0 {
                let mut settings = vec![];
                for (key, value) in [(1, 0), (6, LIMIT as u64), (7, 0), (8, 1), (0x33, 1)] {
                    put_varint(&mut settings, key);
                    put_varint(&mut settings, value);
                }
                data.extend(frame(4, &settings));
                conn.send_stream(id)
                    .set_priority(32)
                    .map_err(|_| Error::InvalidPacket("Поток HTTP/3 уже закрыт"))?;
            }
            self.outgoing.push_back((id, data.into()));
        }
        self.started = true;
        Ok(())
    }

    fn read_stream(
        &mut self,
        conn: &mut Connection,
        id: StreamId,
        incoming: &mut Incoming,
    ) -> Result<()> {
        let mut stream = conn.recv_stream(id);
        let mut chunks = stream
            .read(true)
            .map_err(|_| Error::InvalidPacket("Поток HTTP/3 недоступен"))?;
        let mut outcome = Ok(());
        for step in 0..8 {
            match chunks.next(1024) {
                Ok(Some(chunk)) => {
                    if incoming.bytes.len() + chunk.bytes.len() > LIMIT {
                        outcome = Err(Error::InvalidPacket("Превышен буфер потока HTTP/3"));
                        break;
                    }
                    incoming.bytes.extend_from_slice(&chunk.bytes);
                    if let Err(error) = self.consume(id, incoming) {
                        outcome = Err(error);
                        break;
                    }
                    if step == 7 {
                        self.read_pending = true;
                    }
                }
                Err(ReadError::Blocked) => break,
                Ok(None) | Err(ReadError::Reset(_)) => {
                    outcome = Err(Error::InvalidPacket("Поток маски HTTP/3 закрыт"));
                    break;
                }
            }
        }
        let _ = chunks.finalize();
        outcome
    }

    fn consume(&mut self, id: StreamId, incoming: &mut Incoming) -> Result<()> {
        if incoming.kind.is_none() {
            let Some((kind, length)) = varint(&incoming.bytes) else {
                return Ok(());
            };
            match kind {
                0 if self.control.is_none() => self.control = Some(id),
                2 | 3 if self.qpack[(kind - 2) as usize].is_none() => {
                    self.qpack[(kind - 2) as usize] = Some(id)
                }
                _ => return Err(Error::InvalidPacket("Лишний управляющий поток HTTP/3")),
            }
            incoming.kind = Some(kind);
            incoming.bytes.drain(..length);
        }
        if matches!(incoming.kind, Some(2 | 3)) {
            return if incoming.bytes.is_empty() {
                Ok(())
            } else {
                Err(Error::InvalidPacket("Динамический QPACK выключен"))
            };
        }
        loop {
            let Some((typ, type_len)) = varint(&incoming.bytes) else {
                return Ok(());
            };
            let Some((length, length_len)) = varint(&incoming.bytes[type_len..]) else {
                return Ok(());
            };
            if length > LIMIT as u64 {
                return Err(Error::InvalidPacket("Слишком большой кадр HTTP/3"));
            }
            let start = type_len + length_len;
            let end = start + length as usize;
            if incoming.bytes.len() < end {
                return Ok(());
            }
            let payload = &incoming.bytes[start..end];
            if incoming.kind == Some(0) {
                if !self.settings {
                    if typ != 4 {
                        return Err(Error::InvalidPacket("Первый кадр HTTP/3 не SETTINGS"));
                    }
                    self.check_settings(payload)?;
                    self.settings = true;
                } else if matches!(typ, 0 | 1 | 4 | 5 | 0xd) {
                    return Err(Error::InvalidPacket(
                        "Недопустимый кадр управляющего потока HTTP/3",
                    ));
                }
            } else if typ == 1 && !incoming.headers {
                if !self.settings {
                    return Err(Error::InvalidPacket("HTTP/3 HEADERS до SETTINGS"));
                }
                self.check_headers(payload)?;
                incoming.headers = true;
                if self.server {
                    self.queue_headers(
                        id,
                        vec![
                            HeaderField::new(":status", "200"),
                            HeaderField::new("capsule-protocol", "?1"),
                        ],
                    )?;
                }
                self.ready = true;
            } else if typ == 0 && incoming.headers {
                // Зарегистрированные контексты передают данные только DATAGRAM.
                // Не создаем неподтвержденный второй путь через DATA/capsules.
                if !payload.is_empty() {
                    return Err(Error::InvalidPacket("Неожиданные capsule-данные HTTP/3"));
                }
            } else {
                return Err(Error::InvalidPacket(
                    "Недопустимая последовательность HTTP/3",
                ));
            }
            incoming.bytes.drain(..end);
        }
    }

    fn check_settings(&self, mut payload: &[u8]) -> Result<()> {
        let mut settings = HashMap::new();
        while !payload.is_empty() {
            let (id, used) = varint(payload).ok_or(Error::InvalidPacket("Обрезан SETTINGS id"))?;
            payload = &payload[used..];
            let (value, used) =
                varint(payload).ok_or(Error::InvalidPacket("Обрезан SETTINGS value"))?;
            payload = &payload[used..];
            if settings.len() >= 32 || settings.insert(id, value).is_some() || matches!(id, 2..=5) {
                return Err(Error::InvalidPacket("Недопустимые SETTINGS HTTP/3"));
            }
        }
        if settings.get(&0x33) != Some(&1)
            || settings.get(&8) != Some(&1)
            || settings.get(&1).copied().unwrap_or(0) != 0
            || settings.get(&7).copied().unwrap_or(0) != 0
        {
            return Err(Error::InvalidPacket(
                "HTTP/3 peer не согласовал режим DATAGRAM",
            ));
        }
        Ok(())
    }

    fn request_headers(&self) -> Vec<HeaderField> {
        vec![
            HeaderField::new(":method", "CONNECT"),
            HeaderField::new(":protocol", "connect-udp"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":authority", self.authority.as_bytes()),
            HeaderField::new(":path", PATH),
            HeaderField::new("capsule-protocol", "?1"),
        ]
    }

    fn check_headers(&self, payload: &[u8]) -> Result<()> {
        // Stateless decoder библиотеки не проверяет prefix при capacity 0.
        // У нас нет динамической таблицы: required insert count и base равны 0.
        if !payload.starts_with(&[0, 0]) || payload.len() > LIMIT {
            return Err(Error::InvalidPacket(
                "Недопустимый prefix QPACK без динамической таблицы",
            ));
        }
        let mut input = payload;
        let decoded = decode_stateless(&mut input, LIMIT as u64)
            .map_err(|_| Error::InvalidPacket("Некорректный QPACK HTTP/3"))?;
        let mut expected = if self.server {
            self.request_headers()
        } else {
            vec![
                HeaderField::new(":status", "200"),
                HeaderField::new("capsule-protocol", "?1"),
            ]
        };
        if self.server && self.authority.is_empty() {
            let authority = decoded
                .fields
                .iter()
                .find(|field| field.name.as_ref() == b":authority")
                .filter(|field| valid_authority(&field.value))
                .ok_or(Error::InvalidPacket(
                    "Нет корректного authority CONNECT-UDP",
                ))?;
            expected
                .iter_mut()
                .find(|field| field.name.as_ref() == b":authority")
                .unwrap()
                .value = authority.value.clone();
        }
        let mut remaining = expected;
        let mut ordinary = false;
        for field in decoded.fields {
            if field.name.starts_with(b":") {
                if ordinary {
                    return Err(Error::InvalidPacket(
                        "Псевдополе после обычного поля HTTP/3",
                    ));
                }
            } else {
                ordinary = true;
            }
            let index = remaining
                .iter()
                .position(|expected| *expected == field)
                .ok_or(Error::InvalidPacket("Не согласован CONNECT-UDP HTTP/3"))?;
            remaining.remove(index);
        }
        if !remaining.is_empty() {
            return Err(Error::InvalidPacket("Не согласован CONNECT-UDP HTTP/3"));
        }
        Ok(())
    }

    fn queue_headers(&mut self, id: StreamId, fields: Vec<HeaderField>) -> Result<()> {
        let mut encoded = vec![];
        encode_stateless(&mut encoded, fields)
            .map_err(|_| Error::InvalidPacket("Не удалось собрать QPACK HTTP/3"))?;
        if self.outgoing.len() >= STREAMS {
            return Err(Error::InvalidPacket("Очередь HTTP/3 заполнена"));
        }
        self.outgoing.push_back((id, frame(1, &encoded).into()));
        Ok(())
    }

    fn flush(&mut self, conn: &mut Connection) -> Result<()> {
        while let Some((id, bytes)) = self.outgoing.front_mut() {
            match conn.send_stream(*id).write(bytes) {
                Ok(used) if used > 0 => {
                    let _ = bytes.split_to(used);
                }
                Ok(_) | Err(WriteError::Blocked) => break,
                Err(_) => return Err(Error::InvalidPacket("Закрыт исходящий поток HTTP/3")),
            }
            if bytes.is_empty() {
                self.outgoing.pop_front();
            }
        }
        Ok(())
    }
}

fn valid_authority(authority: &[u8]) -> bool {
    !authority.is_empty()
        && authority.len() <= 253
        && authority
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(b))
}

fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![];
    put_varint(&mut output, kind);
    put_varint(&mut output, payload.len() as u64);
    output.extend_from_slice(payload);
    output
}

fn put_varint(output: &mut Vec<u8>, value: u64) {
    let value = quinn_proto::VarInt::from_u64(value).expect("Ограниченный HTTP/3 varint");
    value.encode(output);
}

fn varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let length = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for byte in input.get(1..length)? {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_require_datagrams_and_connect_without_duplicates() {
        let mask = H3Mask::new(false, "localhost".into());
        mask.check_settings(&[8, 1, 0x33, 1]).unwrap();
        for invalid in [
            &[8, 1][..],
            &[0x33, 1],
            &[8, 1, 0x33, 2],
            &[8, 1, 0x33, 1, 0x33, 1],
            &[8, 1, 0x33, 1, 2, 0],
            &[0x40],
        ] {
            assert!(mask.check_settings(invalid).is_err());
        }
    }

    #[test]
    fn partial_control_frames_are_bounded_and_duplicate_streams_rejected() {
        let mut mask = H3Mask::new(true, "localhost".into());
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Uni, 0);
        let mut incoming = Incoming::default();
        let mut wire = vec![0];
        wire.extend(frame(4, &[8, 1, 0x33, 1]));
        for byte in wire {
            incoming.bytes.push(byte);
            mask.consume(id, &mut incoming).unwrap();
        }
        assert!(mask.settings && incoming.bytes.is_empty());
        incoming.bytes.extend(frame(4, &[8, 1, 0x33, 1]));
        assert!(mask.consume(id, &mut incoming).is_err());
        let mut extra = Incoming {
            bytes: vec![0],
            ..Default::default()
        };
        assert!(mask
            .consume(
                StreamId::new(quinn_proto::Side::Client, Dir::Uni, 1),
                &mut extra
            )
            .is_err());
        incoming.bytes = vec![0x21, 0x7f, 0xff];
        assert!(mask.consume(id, &mut incoming).is_err());
    }

    #[test]
    fn headers_reject_truncation_duplicates_bad_values_and_arbitrary_input_without_panic() {
        use rand::{RngCore, SeedableRng};
        let mask = H3Mask::new(true, "localhost".into());
        let fields = mask.request_headers();
        let mut encoded = vec![];
        encode_stateless(&mut encoded, &fields).unwrap();
        for n in 0..encoded.len() {
            assert!(mask.check_headers(&encoded[..n]).is_err());
        }
        let mut reordered = fields.clone();
        reordered.swap(0, 1);
        let mut valid = vec![];
        encode_stateless(&mut valid, reordered).unwrap();
        mask.check_headers(&valid).unwrap();
        for invalid in [
            {
                let mut f = fields.clone();
                f.push(f[0].clone());
                f
            },
            {
                let mut f = fields.clone();
                f[4] = HeaderField::new(":path", "/foreign/");
                f
            },
            {
                let mut f = fields;
                f.swap(0, 5);
                f
            },
        ] {
            let mut wire = vec![];
            encode_stateless(&mut wire, invalid).unwrap();
            assert!(mask.check_headers(&wire).is_err());
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4833515041434b);
        for n in 0..4096 {
            let mut wire = vec![0; n % 512];
            rng.fill_bytes(&mut wire);
            if wire.len() >= 2 {
                wire[..2].copy_from_slice(&[0, 0]);
            }
            let _ = mask.check_headers(&wire);
        }
    }

    #[test]
    fn dynamic_qpack_prefix_is_rejected_when_capacity_is_zero() {
        let mask = H3Mask::new(true, "localhost".into());
        let mut encoded = vec![];
        encode_stateless(&mut encoded, mask.request_headers()).unwrap();
        mask.check_headers(&encoded).unwrap();
        for prefix in [[1, 0], [0, 1], [0, 0x80]] {
            let mut bad = encoded.clone();
            bad[..2].copy_from_slice(&prefix);
            assert!(
                mask.check_headers(&bad).is_err(),
                "Некорректный QPACK prefix принят: {prefix:?}"
            );
        }
    }
}
