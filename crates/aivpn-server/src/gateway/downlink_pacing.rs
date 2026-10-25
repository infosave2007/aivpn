//! Планировщик нисходящих RAW IP пакетов до QoS, шифрования, nonce и учета.
//!
//! У каждой сессии одна активная голова в общем индексе сроков. Остальные
//! пакеты этой сессии чередуются по IP-потокам. После паузы
//! следующий срок ставится от текущего момента, без догоняющей серии.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use aivpn_common::flow_queue::FairQueue;
use aivpn_common::mask::{MaskProfile, PaddingStrategy};
use aivpn_common::mimicry::MimicryEngine;
use aivpn_common::protocol::MAX_PACKET_SIZE;
use tokio::time::Instant;

const MAX_PACKETS_PER_SESSION: usize = 64;
const MAX_PACKETS_TOTAL: usize = 4096;
const MAX_CACHED_STREAMS: usize = 1024;
const LIGHT_MAX_DELAY: Duration = Duration::from_millis(2);

/// RAW пакет, который можно отдавать воркеру. `session_id` тот же, с которым
/// пакет положили в очередь: воркер сверяет его перед доставкой.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacedData {
    pub session_id: [u8; 16],
    pub packet: Vec<u8>,
    pub target_size: u16,
    pub padding_override: Option<PaddingStrategy>,
    profile_key: ProfileKey,
}

impl PacedData {
    pub fn matches_profile(&self, mask: &MaskProfile) -> bool {
        self.profile_key.matches(mask)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileKey {
    mask_id: String,
    version: u16,
    signature: [u8; 64],
    reverse: Option<(String, u16, [u8; 64])>,
}

impl ProfileKey {
    fn new(profile: &MaskProfile) -> Self {
        Self {
            mask_id: profile.mask_id.clone(),
            version: profile.version,
            signature: profile.signature,
            reverse: profile
                .reverse_profile
                .as_ref()
                .map(|reverse| (reverse.mask_id.clone(), reverse.version, reverse.signature)),
        }
    }

    fn matches(&self, profile: &MaskProfile) -> bool {
        self.version == profile.version
            && self.signature == profile.signature
            && self.mask_id == profile.mask_id
            && match (&self.reverse, &profile.reverse_profile) {
                (None, None) => true,
                (Some((id, version, signature)), Some(reverse)) => {
                    id == &reverse.mask_id
                        && *version == reverse.version
                        && *signature == reverse.signature
                }
                _ => false,
            }
    }
}

#[derive(Clone, Copy)]
enum DelayMode {
    Profile,
    Light,
    Immediate,
}

struct Pending {
    packet: Vec<u8>,
    mode: DelayMode,
}

struct Head {
    packet: Vec<u8>,
    target_size: u16,
    padding_override: Option<PaddingStrategy>,
    deadline: Instant,
}

struct Stream {
    engine: MimicryEngine,
    profile_key: ProfileKey,
    /// Пакеты позади головы с сохранением порядка каждого IP-потока.
    fifo: FairQueue<Pending>,
    head: Option<Head>,
    last_sent: Option<Instant>,
    last_use: Instant,
}

impl Stream {
    fn new(profile: MaskProfile, key: ProfileKey, now: Instant) -> Self {
        Self {
            engine: MimicryEngine::new(profile),
            profile_key: key,
            fifo: FairQueue::new(MAX_PACKETS_PER_SESSION - 1),
            head: None,
            last_sent: None,
            last_use: now,
        }
    }

    fn len_packets(&self) -> usize {
        self.fifo.len() + usize::from(self.head.is_some())
    }

    fn is_idle(&self) -> bool {
        self.head.is_none() && self.fifo.is_empty()
    }
}

enum Placement {
    Head {
        packet: Vec<u8>,
        target_size: u16,
        padding_override: Option<PaddingStrategy>,
        deadline: Instant,
    },
    Queued {
        replaced: bool,
    },
}

/// Планировщик отдельных сессий. В индексе сроков одна голова на сессию.
pub struct DownlinkPacer {
    streams: HashMap<[u8; 16], Stream>,
    ready: BTreeMap<(Instant, [u8; 16]), ()>,
    total: usize,
}

impl DownlinkPacer {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            ready: BTreeMap::new(),
            total: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.ready
            .first_key_value()
            .map(|((deadline, _), _)| *deadline)
    }

    /// Кладет сырой пакет. `false`, если пакет длиннее лимита, сессия или общий
    /// буфер уже полны, либо для новой сессии нет места в кэше.
    pub fn enqueue(
        &mut self,
        session_id: [u8; 16],
        mask: &MaskProfile,
        packet: Vec<u8>,
        now: Instant,
        light: bool,
    ) -> bool {
        self.enqueue_mode(
            session_id,
            mask,
            packet,
            now,
            if light {
                DelayMode::Light
            } else {
                DelayMode::Profile
            },
        )
    }

    pub fn enqueue_unpaced(
        &mut self,
        session_id: [u8; 16],
        mask: &MaskProfile,
        packet: Vec<u8>,
        now: Instant,
    ) -> bool {
        self.enqueue_mode(session_id, mask, packet, now, DelayMode::Immediate)
    }

    fn enqueue_mode(
        &mut self,
        session_id: [u8; 16],
        mask: &MaskProfile,
        packet: Vec<u8>,
        now: Instant,
        mode: DelayMode,
    ) -> bool {
        if packet.len() > MAX_PACKET_SIZE {
            return false;
        }
        // Для размера и паузы берется обратный профиль, заголовки не нужны.
        let source = mask.reverse_profile.as_deref().unwrap_or(mask);
        self.sync_profile(session_id, mask);

        if self.streams.contains_key(&session_id) {
            let occupied = self
                .streams
                .get(&session_id)
                .map(Stream::len_packets)
                .unwrap_or(0);
            if self.total >= MAX_PACKETS_TOTAL && occupied < MAX_PACKETS_PER_SESSION {
                return false;
            }
        } else if self.total >= MAX_PACKETS_TOTAL || !self.make_room_for_new_stream() {
            return false;
        } else {
            self.streams.insert(
                session_id,
                Stream::new(source.clone(), ProfileKey::new(mask), now),
            );
        }

        self.push_packet(session_id, packet, now, mode)
    }

    /// Неготовая маска сохраняет голову FIFO и не задерживает чужие сессии.
    pub fn pop_ready_when(
        &mut self,
        now: Instant,
        mut can_send: impl FnMut(&[u8; 16]) -> bool,
    ) -> Option<PacedData> {
        loop {
            let (&(deadline, session_id), _) = self.ready.first_key_value()?;
            if deadline > now {
                return None;
            }
            if can_send(&session_id) {
                return self.pop_ready(now);
            }
            self.ready.remove(&(deadline, session_id));
            if let Some(head) = self
                .streams
                .get_mut(&session_id)
                .and_then(|stream| stream.head.as_mut())
            {
                head.deadline = saturate_add(now, Duration::from_millis(20));
                self.ready.insert((head.deadline, session_id), ());
            }
        }
    }

    pub fn pop_ready(&mut self, now: Instant) -> Option<PacedData> {
        let (deadline, session_id) = {
            let ((deadline, session_id), _) = self.ready.first_key_value()?;
            if *deadline > now {
                return None;
            }
            (*deadline, *session_id)
        };

        let outcome = if let Some(stream) = self.streams.get_mut(&session_id) {
            if let Some(head) = stream.head.take() {
                stream.last_sent = Some(now);
                stream.last_use = now;
                let next_deadline = if let Some(pending) = stream.fifo.pop() {
                    let (target_size, delay, padding_override) =
                        sample_shape(&mut stream.engine, pending.mode);
                    // Срок следующего пакета считается от now, а не от старого срока.
                    let next_deadline = saturate_add(now, delay);
                    stream.head = Some(Head {
                        packet: pending.packet,
                        target_size,
                        padding_override,
                        deadline: next_deadline,
                    });
                    Some(next_deadline)
                } else {
                    None
                };
                Some((
                    head.packet,
                    head.target_size,
                    head.padding_override,
                    next_deadline,
                ))
            } else {
                None
            }
        } else {
            None
        };
        self.ready.remove(&(deadline, session_id));
        let Some((packet, target_size, padding_override, next_deadline)) = outcome else {
            self.debug_check();
            return None;
        };
        self.total = self.total.saturating_sub(1);
        if let Some(next_deadline) = next_deadline {
            self.ready.insert((next_deadline, session_id), ());
        }
        self.debug_check();
        Some(PacedData {
            session_id,
            packet,
            target_size,
            padding_override,
            profile_key: self.streams[&session_id].profile_key.clone(),
        })
    }

    fn sync_profile(&mut self, session_id: [u8; 16], mask: &MaskProfile) {
        let changed = self
            .streams
            .get(&session_id)
            .map(|stream| !stream.profile_key.matches(mask))
            .unwrap_or(false);
        if !changed {
            return;
        }
        // Смена id, version или подписи: старая очередь не переносится.
        self.drop_queued(session_id);
        if let Some(stream) = self.streams.get_mut(&session_id) {
            let source = mask.reverse_profile.as_deref().unwrap_or(mask);
            stream.engine = MimicryEngine::new(source.clone());
            stream.profile_key = ProfileKey::new(mask);
        }
    }

    fn drop_queued(&mut self, session_id: [u8; 16]) {
        let removed = if let Some(stream) = self.streams.get_mut(&session_id) {
            let count = stream.len_packets();
            let deadline = stream.head.take().map(|head| head.deadline);
            stream.fifo.clear();
            Some((count, deadline))
        } else {
            None
        };
        let Some((count, deadline)) = removed else {
            return;
        };
        self.total = self.total.saturating_sub(count);
        if let Some(deadline) = deadline {
            self.ready.remove(&(deadline, session_id));
        }
    }

    fn make_room_for_new_stream(&mut self) -> bool {
        if self.streams.len() < MAX_CACHED_STREAMS {
            return true;
        }
        let victim = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.is_idle())
            .min_by_key(|(_, stream)| stream.last_use)
            .map(|(session_id, _)| *session_id);
        let Some(session_id) = victim else {
            return false;
        };
        self.streams.remove(&session_id);
        true
    }

    fn push_packet(
        &mut self,
        session_id: [u8; 16],
        packet: Vec<u8>,
        now: Instant,
        mode: DelayMode,
    ) -> bool {
        let placement = {
            let stream = self
                .streams
                .get_mut(&session_id)
                .expect("stream exists before push");
            stream.last_use = now;
            if stream.head.is_none() {
                let (target_size, delay, padding_override) = sample_shape(&mut stream.engine, mode);
                let anchor = stream.last_sent.unwrap_or(now);
                let deadline = max_instant(now, saturate_add(anchor, delay));
                Placement::Head {
                    packet,
                    target_size,
                    padding_override,
                    deadline,
                }
            } else {
                match stream
                    .fifo
                    .push(Pending { packet, mode }, |pending| &pending.packet)
                {
                    Ok(evicted) => Placement::Queued {
                        replaced: evicted.is_some(),
                    },
                    Err(_) => return false,
                }
            }
        };
        let replaced = matches!(placement, Placement::Queued { replaced: true });
        if let Placement::Head {
            packet,
            target_size,
            padding_override,
            deadline,
        } = placement
        {
            let stream = self
                .streams
                .get_mut(&session_id)
                .expect("stream exists before head");
            stream.head = Some(Head {
                packet,
                target_size,
                padding_override,
                deadline,
            });
            self.ready.insert((deadline, session_id), ());
        }
        if !replaced {
            self.total += 1;
        }
        self.debug_check();
        true
    }

    fn debug_check(&self) {
        debug_assert!(self.total <= MAX_PACKETS_TOTAL);
        debug_assert!(self.streams.len() <= MAX_CACHED_STREAMS);
        let queued: usize = self.streams.values().map(Stream::len_packets).sum();
        debug_assert_eq!(self.total, queued);
        let heads = self
            .streams
            .values()
            .filter(|stream| stream.head.is_some())
            .count();
        debug_assert_eq!(self.ready.len(), heads);
        for (session_id, stream) in &self.streams {
            debug_assert!(stream.len_packets() <= MAX_PACKETS_PER_SESSION);
            if let Some(head) = &stream.head {
                debug_assert!(self.ready.contains_key(&(head.deadline, *session_id)));
            }
        }
    }
}

impl Default for DownlinkPacer {
    fn default() -> Self {
        Self::new()
    }
}

fn sample_shape(
    engine: &mut MimicryEngine,
    mode: DelayMode,
) -> (u16, Duration, Option<PaddingStrategy>) {
    let (size, delay) = engine.take_data_shape();
    let padding_override = engine.padding_override().cloned();
    engine.update_fsm();
    let delay = match mode {
        DelayMode::Profile => delay,
        DelayMode::Light => delay.min(LIGHT_MAX_DELAY),
        DelayMode::Immediate => Duration::ZERO,
    };
    (size, delay, padding_override)
}

fn saturate_add(base: Instant, delay: Duration) -> Instant {
    base.checked_add(delay).unwrap_or(base)
}

fn max_instant(left: Instant, right: Instant) -> Instant {
    if left >= right {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiting_for_rtc_preserves_fifo_without_delaying_ready_sessions() {
        let now = Instant::now();
        let mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let blocked = [1; 16];
        let live = [2; 16];
        let mut pacer = DownlinkPacer::new();
        assert!(pacer.enqueue_unpaced(blocked, &mask, vec![1], now));
        assert!(pacer.enqueue_unpaced(blocked, &mask, vec![2], now));
        assert!(pacer.enqueue_unpaced(live, &mask, vec![3], now));
        let available = pacer
            .pop_ready_when(now, |session| *session == live)
            .unwrap();
        assert_eq!(available.packet, vec![3]);
        assert!(pacer.pop_ready_when(now, |_| false).is_none());
        assert!(!pacer.is_empty());
        let ready = now + Duration::from_millis(20);
        assert_eq!(
            pacer.pop_ready_when(ready, |_| true).unwrap().packet,
            vec![1]
        );
        assert_eq!(pacer.next_deadline(), Some(ready));
        assert_eq!(
            pacer.pop_ready_when(ready, |_| true).unwrap().packet,
            vec![2]
        );
        assert!(pacer.is_empty());
    }
    use aivpn_common::mask::{
        IATDistType, IATDistribution, PaddingStrategy, SizeDistType, SizeDistribution,
        SpoofProtocol,
    };

    fn sid_at(n: u32) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&n.to_le_bytes());
        id
    }

    /// Та же формула, что у `MimicryEngine::prepare_data_delay`.
    fn sampled_delay(milliseconds: f64) -> Duration {
        Duration::from_secs_f64(milliseconds.clamp(0.0, 1000.0) / 1000.0)
    }

    fn profile(id: &str, version: u16, signature_byte: u8, size: u16, iat_ms: f64) -> MaskProfile {
        MaskProfile {
            mask_id: id.into(),
            version,
            created_at: 0,
            expires_at: 0,
            spoof_protocol: SpoofProtocol::None,
            header_template: vec![0xAB],
            eph_pub_offset: 0,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Histogram,
                bins: vec![(size, size, 1.0)],
                parametric_type: None,
                parametric_params: None,
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::Empirical,
                params: vec![iat_ms],
                jitter_range_ms: (0.0, 0.0),
            },
            size_iat_joint: None,
            padding_strategy: PaddingStrategy::Fixed { size },
            fsm_states: vec![],
            fsm_initial_state: 0,
            signature_vector: vec![0.0],
            reverse_profile: None,
            signature: [signature_byte; 64],
            header_spec: None,
            perturbation_bounds: None,
            tag_offset: u16::MAX,
            generated: false,
        }
    }

    #[test]
    fn fresh_dns_reply_does_not_wait_for_a_bulk_flow_backlog() {
        let packet = |port: u16| {
            let mut p = vec![0; 28];
            p[0] = 0x45;
            p[3] = 28;
            p[9] = 17;
            p[12..16].copy_from_slice(&[1, 1, 1, 1]);
            p[16..20].copy_from_slice(&[10, 0, 0, 2]);
            p[20..22].copy_from_slice(&port.to_be_bytes());
            p[22..24].copy_from_slice(&5000u16.to_be_bytes());
            p
        };
        let now = Instant::now();
        let mask = profile("fairness", 1, 1, 400, 30.0);
        let mut queue = DownlinkPacer::new();
        for _ in 0..MAX_PACKETS_PER_SESSION {
            assert!(queue.enqueue(sid_at(1), &mask, packet(443), now, false));
        }
        assert!(queue.enqueue(sid_at(1), &mask, packet(53), now, false));
        let mut seen_dns = false;
        for step in 1..=4 {
            let p = queue
                .pop_ready(now + Duration::from_millis(step * 30))
                .unwrap();
            seen_dns |= p.packet[20..22] == 53u16.to_be_bytes();
        }
        assert!(seen_dns, "DNS-ответ остался за фоновой очередью");
    }

    #[test]
    fn sampled_packet_keeps_fsm_padding_override_and_profile_generation() {
        let now = Instant::now();
        let session = sid_at(1);
        let mut mask = profile("fsm", 1, 1, 400, 10.0);
        mask.fsm_states = vec![aivpn_common::mask::FSMState {
            state_id: 0,
            transitions: vec![aivpn_common::mask::FSMTransition {
                condition: aivpn_common::mask::TransitionCondition::AfterPackets(0),
                next_state: 0,
                size_override: None,
                iat_override: None,
                padding_override: Some(PaddingStrategy::Fixed { size: 17 }),
            }],
        }];
        let mut pacer = DownlinkPacer::new();
        pacer.enqueue(session, &mask, vec![1], now, false);
        pacer.enqueue(session, &mask, vec![2], now, false);
        let first = pacer.pop_ready(now + Duration::from_millis(10)).unwrap();
        assert_eq!(first.padding_override, None);
        let second = pacer.pop_ready(now + Duration::from_millis(20)).unwrap();
        assert_eq!(
            second.padding_override,
            Some(PaddingStrategy::Fixed { size: 17 })
        );
        assert!(second.matches_profile(&mask));
    }

    #[test]
    fn queued_shape_is_stale_after_profile_changes_without_new_enqueue() {
        let now = Instant::now();
        let mut mask = profile("old", 1, 1, 400, 10.0);
        let mut pacer = DownlinkPacer::new();
        pacer.enqueue(sid_at(1), &mask, vec![1], now, false);
        mask.version += 1;
        let old = pacer.pop_ready(now + Duration::from_millis(10)).unwrap();
        assert!(
            !old.matches_profile(&mask),
            "Старый план применяется к новой маске до следующего enqueue"
        );
    }

    #[test]
    fn saturated_fifo_keeps_iat() {
        let t0 = Instant::now();
        let delay = sampled_delay(25.0);
        let mask = profile("fifo", 1, 1, 400, 25.0);
        let mut pacer = DownlinkPacer::new();
        let session = sid_at(7);
        for n in 0..10u8 {
            assert!(pacer.enqueue(session, &mask, vec![n], t0, false));
        }
        assert!(!pacer.is_empty());
        assert_eq!(pacer.next_deadline(), Some(t0 + delay));
        assert!(pacer.pop_ready(t0).is_none());

        let mut cursor = t0;
        for n in 0..10u8 {
            cursor += delay;
            assert_eq!(pacer.next_deadline(), Some(cursor));
            let item = pacer.pop_ready(cursor).expect("packet due");
            assert_eq!(item.session_id, session);
            assert_eq!(item.packet, vec![n]);
            assert_eq!(item.target_size, 400);
            assert!(pacer.pop_ready(cursor).is_none());
        }
        assert!(pacer.is_empty());
        assert!(pacer.next_deadline().is_none());

        // Поток жив: пауза считается от последней отправки, а не заново от нуля.
        let again = cursor + delay / 2;
        assert!(pacer.enqueue(session, &mask, vec![9], again, false));
        assert_eq!(pacer.next_deadline(), Some(cursor + delay));
        assert!(pacer.pop_ready(again).is_none());
        let item = pacer.pop_ready(cursor + delay).unwrap();
        assert_eq!(item.packet, vec![9]);
        assert_eq!(item.target_size, 400);
    }

    #[test]
    fn slow_session_does_not_block_fast() {
        let t0 = Instant::now();
        let slow_delay = sampled_delay(200.0);
        let fast_delay = sampled_delay(10.0);
        let slow_mask = profile("slow", 1, 2, 300, 200.0);
        let fast_mask = profile("fast", 1, 3, 120, 10.0);
        let mut pacer = DownlinkPacer::new();
        let slow = sid_at(1);
        let fast = sid_at(2);
        assert!(pacer.enqueue(slow, &slow_mask, vec![0x51], t0, false));
        for n in 0..3u8 {
            assert!(pacer.enqueue(fast, &fast_mask, vec![0xA0 + n], t0, false));
        }

        let mut cursor = t0;
        for n in 0..3u8 {
            cursor += fast_delay;
            assert!(cursor < t0 + slow_delay);
            let item = pacer.pop_ready(cursor).expect("fast packet");
            assert_eq!(item.session_id, fast);
            assert_eq!(item.packet, vec![0xA0 + n]);
            assert_eq!(item.target_size, 120);
            assert!(pacer.pop_ready(cursor).is_none());
        }
        assert!(pacer
            .pop_ready(t0 + slow_delay - Duration::from_millis(1))
            .is_none());
        let item = pacer.pop_ready(t0 + slow_delay).unwrap();
        assert_eq!(item.session_id, slow);
        assert_eq!(item.packet, vec![0x51]);
        assert_eq!(item.target_size, 300);
        assert!(pacer.is_empty());
    }

    #[test]
    fn time_skip_does_not_burst() {
        let t0 = Instant::now();
        let delay = sampled_delay(30.0);
        let mask = profile("pause", 1, 4, 250, 30.0);
        let mut pacer = DownlinkPacer::new();
        let session = sid_at(4);
        for n in 0..5u8 {
            assert!(pacer.enqueue(session, &mask, vec![n], t0, false));
        }
        let paused = t0 + Duration::from_secs(3600);
        let first = pacer.pop_ready(paused).unwrap();
        assert_eq!(first.packet, vec![0]);
        assert_eq!(first.target_size, 250);
        assert_eq!(pacer.next_deadline(), Some(paused + delay));
        assert!(pacer.pop_ready(paused).is_none());

        let mut cursor = paused;
        for n in 1..5u8 {
            cursor += delay;
            assert!(pacer.pop_ready(cursor - Duration::from_nanos(1)).is_none());
            let item = pacer.pop_ready(cursor).unwrap();
            assert_eq!(item.session_id, session);
            assert_eq!(item.packet, vec![n]);
        }
        assert!(pacer.is_empty());
    }

    #[test]
    fn light_caps_delay_per_packet() {
        let t0 = Instant::now();
        let full = sampled_delay(100.0);
        let light = Duration::from_millis(2);
        let mask = profile("light", 1, 5, 180, 100.0);
        let mut pacer = DownlinkPacer::new();
        let session = sid_at(5);
        assert!(pacer.enqueue(session, &mask, vec![1], t0, false));
        assert!(pacer.enqueue(session, &mask, vec![2], t0, true));
        assert!(full > light);
        assert_eq!(pacer.next_deadline(), Some(t0 + full));
        assert!(pacer.pop_ready(t0 + light).is_none());
        let first = pacer.pop_ready(t0 + full).unwrap();
        assert_eq!(first.packet, vec![1]);
        assert_eq!(first.target_size, 180);
        assert_eq!(pacer.next_deadline(), Some(t0 + full + light));
        assert!(pacer.pop_ready(t0 + full).is_none());
        let second = pacer.pop_ready(t0 + full + light).unwrap();
        assert_eq!(second.packet, vec![2]);
        assert_eq!(second.target_size, 180);
    }

    #[test]
    fn queue_and_size_limits() {
        let t0 = Instant::now();
        let mask = profile("lim", 1, 6, 200, 10.0);
        let mask_b = profile("lim-b", 2, 7, 220, 10.0);
        let mut pacer = DownlinkPacer::new();
        let first = sid_at(1);
        assert!(!pacer.enqueue(first, &mask, vec![0u8; MAX_PACKET_SIZE + 1], t0, false));
        assert!(pacer.is_empty());
        assert!(pacer.enqueue(first, &mask, vec![0u8; MAX_PACKET_SIZE], t0, false));
        let due = t0 + sampled_delay(10.0);
        assert_eq!(pacer.pop_ready(due).unwrap().packet.len(), MAX_PACKET_SIZE);

        for n in 0..64 {
            assert!(pacer.enqueue(first, &mask, vec![n as u8], due, false));
        }
        assert!(!pacer.enqueue(first, &mask, vec![99], due, false));
        for session in 2..65u32 {
            for n in 0..64u8 {
                assert!(pacer.enqueue(sid_at(session), &mask, vec![n], due, false));
            }
        }
        assert!(!pacer.enqueue(sid_at(65), &mask, vec![1], due, false));
        assert!(!pacer.enqueue(first, &mask, vec![1], due, false));

        // Смена профиля освобождает 64 места и уменьшает общий счетчик.
        assert!(pacer.enqueue(first, &mask_b, vec![7], due, false));
        assert!(pacer.enqueue(sid_at(65), &mask, vec![1], due, false));
        let changed = pacer.pop_ready(due + sampled_delay(10.0)).unwrap();
        assert_eq!(changed.session_id, first);
        assert_eq!(changed.packet, vec![7]);
        assert_eq!(changed.target_size, 220);
    }

    #[test]
    fn profile_and_session_change_does_not_carry_packets() {
        let t0 = Instant::now();
        let mask_a = profile("a", 1, 8, 111, 15.0);
        let mask_b = profile("b", 2, 9, 222, 40.0);
        let mut pacer = DownlinkPacer::new();
        let left = sid_at(10);
        let right = sid_at(11);
        for n in 0..3u8 {
            assert!(pacer.enqueue(left, &mask_a, vec![0x10 + n], t0, false));
        }
        assert!(pacer.enqueue(right, &mask_b, vec![0x20], t0, false));
        assert!(pacer.enqueue(left, &mask_b, vec![0x30], t0, false));

        let left_due = t0 + sampled_delay(40.0);
        let right_due = t0 + sampled_delay(40.0);
        assert_eq!(left_due, right_due);
        let mut got = Vec::new();
        while let Some(item) = pacer.pop_ready(left_due) {
            got.push((item.session_id, item.packet, item.target_size));
        }
        got.sort_by_key(|(session_id, _, _)| *session_id);
        assert_eq!(
            got,
            vec![(left, vec![0x30], 222), (right, vec![0x20], 222),]
        );
        assert!(pacer.is_empty());

        // Новая сессия не видит пакеты старой, даже если та еще не пуста.
        let mut pacer = DownlinkPacer::new();
        assert!(pacer.enqueue(left, &mask_a, vec![0x41], t0, false));
        assert!(pacer.enqueue(right, &mask_a, vec![0x42], t0, false));
        let due = t0 + sampled_delay(15.0);
        let first = pacer.pop_ready(due).unwrap();
        let second = pacer.pop_ready(due).unwrap();
        assert_eq!(first.session_id, left);
        assert_eq!(first.packet, vec![0x41]);
        assert_eq!(second.session_id, right);
        assert_eq!(second.packet, vec![0x42]);
        assert!(pacer.pop_ready(due).is_none());
    }

    #[test]
    fn reverse_profile_sets_size_and_iat() {
        let t0 = Instant::now();
        let mut outer = profile("outer", 1, 1, 111, 80.0);
        let mut reverse = profile("rev", 3, 3, 640, 17.0);
        outer.header_template = vec![1, 2, 3, 4];
        reverse.header_template = vec![9, 9, 9];
        outer.reverse_profile = Some(Box::new(reverse));
        let mut pacer = DownlinkPacer::new();
        let session = sid_at(12);
        assert!(pacer.enqueue(session, &outer, vec![1], t0, false));
        let sent = t0 + sampled_delay(17.0);
        assert_eq!(pacer.next_deadline(), Some(sent));
        assert_ne!(pacer.next_deadline(), Some(t0 + sampled_delay(80.0)));
        let item = pacer.pop_ready(sent).unwrap();
        assert_eq!(item.packet, vec![1]);
        assert_eq!(item.target_size, 640);
        assert_ne!(item.target_size, 111);

        let mut reverse = profile("rev2", 4, 4, 900, 25.0);
        reverse.header_template = vec![7];
        outer.reverse_profile = Some(Box::new(reverse));
        assert!(pacer.enqueue(session, &outer, vec![2], sent, false));
        let next = sent + sampled_delay(25.0);
        assert_eq!(pacer.next_deadline(), Some(next));
        assert!(pacer.pop_ready(sent).is_none());
        let item = pacer.pop_ready(next).unwrap();
        assert_eq!(item.session_id, session);
        assert_eq!(item.packet, vec![2]);
        assert_eq!(item.target_size, 900);
        assert!(pacer.is_empty());
    }

    #[test]
    fn empty_cache_slot_does_not_drop_busy_session() {
        let t0 = Instant::now();
        let delay = sampled_delay(20.0);
        let mask = profile("cache", 1, 11, 128, 20.0);
        let mut pacer = DownlinkPacer::new();
        for n in 0..1024u32 {
            assert!(pacer.enqueue(sid_at(n), &mask, vec![1], t0, false));
        }
        assert!(!pacer.enqueue(sid_at(5000), &mask, vec![9], t0, false));

        let due = t0 + delay;
        let first = pacer.pop_ready(due).unwrap();
        assert_eq!(first.session_id, sid_at(0));
        assert_eq!(first.packet, vec![1]);
        assert!(pacer.enqueue(sid_at(5000), &mask, vec![9], due, false));

        let mut busy = 0usize;
        while pacer.pop_ready(due).is_some() {
            busy += 1;
        }
        assert_eq!(busy, 1023);
        // Старый поток вытеснен. Новая сессия с тем же id получает только новый пакет.
        assert!(pacer.enqueue(sid_at(0), &mask, vec![8], due, false));

        let later = due + delay;
        let mut rest = Vec::new();
        while let Some(item) = pacer.pop_ready(later) {
            rest.push((item.session_id, item.packet, item.target_size));
        }
        rest.sort_by_key(|(session_id, _, _)| *session_id);
        assert_eq!(
            rest,
            vec![(sid_at(0), vec![8], 128), (sid_at(5000), vec![9], 128),]
        );
        assert!(pacer.is_empty());
    }
}
