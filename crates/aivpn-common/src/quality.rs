//! Connection quality scoring and RTT tracking (0.9.0)
//!
//! Computes a 0–100 quality score from RTT, jitter, packet loss, and neural MSE.

const EWMA_ALPHA_INV: u64 = 8;

pub const RECEIVER_LOSS_WINDOW: usize = 4096;
pub const RECEIVER_LOSS_MIN_SPAN: u64 = 32;
pub const PEER_RECEIVER_FEEDBACK_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Отдельное наблюдение потерь. Не участвует в решении о replay или допуске.
#[derive(Debug, Clone)]
pub struct ReceiverLossWindow {
    highest: Option<u64>,
    span: u16,
    received: u16,
    words: [u64; RECEIVER_LOSS_WINDOW / 64],
}

impl Default for ReceiverLossWindow {
    fn default() -> Self {
        Self {
            highest: None,
            span: 0,
            received: 0,
            words: [0; RECEIVER_LOSS_WINDOW / 64],
        }
    }
}

impl ReceiverLossWindow {
    /// Вызывать только после AEAD, replay claim и определения монотонной эпохи.
    pub fn observe(&mut self, counter: u64) {
        if let Some(highest) = self.highest {
            if counter > highest {
                let delta = counter - highest;
                if delta >= RECEIVER_LOSS_WINDOW as u64 {
                    self.words.fill(0);
                    self.received = 0;
                    self.span = RECEIVER_LOSS_WINDOW as u16;
                } else {
                    let start = ((highest as usize & (RECEIVER_LOSS_WINDOW - 1)) + 1)
                        % RECEIVER_LOSS_WINDOW;
                    self.clear_slots(start, delta as usize);
                    self.span =
                        (u64::from(self.span) + delta).min(RECEIVER_LOSS_WINDOW as u64) as u16;
                }
                self.highest = Some(counter);
            } else {
                let distance = highest - counter;
                if distance >= RECEIVER_LOSS_WINDOW as u64 {
                    return;
                }
                self.span = self.span.max((distance + 1) as u16);
            }
        } else {
            self.highest = Some(counter);
            self.span = 1;
        }
        let index = counter as usize & (RECEIVER_LOSS_WINDOW - 1);
        let bit = 1u64 << (index % 64);
        if self.words[index / 64] & bit == 0 {
            self.words[index / 64] |= bit;
            self.received += 1;
        }
    }

    fn clear_slots(&mut self, mut index: usize, mut length: usize) {
        while length > 0 {
            let offset = index % 64;
            let count = length.min(64 - offset);
            let mask = if count == 64 {
                u64::MAX
            } else {
                ((1u64 << count) - 1) << offset
            };
            let word = &mut self.words[index / 64];
            self.received -= (*word & mask).count_ones() as u16;
            *word &= !mask;
            length -= count;
            index = (index + count) % RECEIVER_LOSS_WINDOW;
        }
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
    pub fn counts(&self) -> (u64, u64) {
        (u64::from(self.received), u64::from(self.span))
    }
    pub fn loss_ppm(&self) -> Option<u32> {
        (u64::from(self.span) >= RECEIVER_LOSS_MIN_SPAN).then(|| {
            (u64::from(self.span - self.received) * 1_000_000 / u64::from(self.span)) as u32
        })
    }
}

/// Отчет удаленного приемника влияет только на FEC нашего направления отправки.
#[derive(Debug, Clone, Default)]
pub struct PeerReceiverFeedback {
    last_counter: Option<u64>,
    observation: Option<(u32, web_time::Instant)>,
}

impl PeerReceiverFeedback {
    pub fn record(&mut self, counter: u64, loss_ppm: u32, now: web_time::Instant) -> bool {
        if self
            .last_counter
            .is_some_and(|previous| counter <= previous)
        {
            return false;
        }
        self.last_counter = Some(counter);
        self.observation = Some((loss_ppm.min(1_000_000), now));
        true
    }
    pub fn reset(&mut self) {
        *self = Self::default();
    }
    /// Оценка приемника, а не гарантия восстановления: одна XOR repair на N IP.
    pub fn fec_group(&self, level: AdaptiveLevel, now: web_time::Instant) -> u8 {
        match self.observation {
            Some((loss, recorded))
                if now.saturating_duration_since(recorded) < PEER_RECEIVER_FEEDBACK_TTL =>
            {
                match loss {
                    0 => 0,
                    1..=9_999 => 16,
                    10_000..=49_999 => 8,
                    _ => 4,
                }
            }
            _ => level.fec_n(),
        }
    }
}

#[cfg(test)]
mod window_tests {
    use super::*;

    #[test]
    fn late_packets_close_gaps_and_a_new_epoch_starts_a_fresh_window() {
        let mut window = crate::client_wire::RecvWindow::new();
        let mut quality = QualityTracker::new();
        for (counter, expected_loss) in [(100, 0), (103, 500_000), (101, 250_000), (102, 0)] {
            window.mark(counter);
            let (received, span) = window.observation_counts();
            quality.record_window(received, span);
            assert_eq!(quality.loss_ppm(), expected_loss);
        }
        window.reset();
        window.mark(80_000);
        let (received, span) = window.observation_counts();
        quality.record_window(received, span);
        assert_eq!(quality.loss_ppm(), 0);
    }

    #[test]
    fn kernel_replay_window_counts_data_and_control_together() {
        let mut words = [u64::MAX; 8];
        words[3] &= !(1 << 20);
        assert_eq!(replay_observation_counts(&words), (511, 512));
        words[3] |= 1 << 20;
        assert_eq!(replay_observation_counts(&words), (512, 512));
        assert_eq!(replay_observation_counts(&[0; 8]), (0, 0));
    }
}

/// Считаем пропуски между крайними полученными пакетами рабочего replay-окна.
pub fn replay_observation_counts(words: &[u64]) -> (u64, u64) {
    let received = words.iter().map(|word| word.count_ones() as u64).sum();
    let span = words
        .iter()
        .rposition(|word| *word != 0)
        .map(|index| index as u64 * 64 + 64 - words[index].leading_zeros() as u64)
        .unwrap_or(0);
    (received, span)
}

/// Per-session quality tracker — updated on each keepalive exchange.
#[derive(Debug, Clone, Default)]
pub struct QualityTracker {
    /// EWMA RTT in microseconds
    rtt_us: u64,
    /// EWMA jitter in microseconds (mean absolute deviation of RTT)
    jitter_us: u64,
    /// Sent packet count since last reset
    sent: u64,
    /// Lost packet count estimate (gaps in seq_num)
    lost: u64,
    /// Latest neural MSE [0.0, 1.0]
    pub neural_mse: f32,
}

impl QualityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new RTT sample in microseconds.
    pub fn record_rtt(&mut self, sample_us: u64) {
        if self.rtt_us == 0 {
            self.rtt_us = sample_us;
        } else {
            let dev = sample_us.abs_diff(self.rtt_us);
            self.jitter_us = (self.jitter_us * (EWMA_ALPHA_INV - 1) + dev) / EWMA_ALPHA_INV;
            self.rtt_us = (self.rtt_us * (EWMA_ALPHA_INV - 1) + sample_us) / EWMA_ALPHA_INV;
        }
    }

    /// Record a packet sequence gap (potential loss).
    pub fn record_gap(&mut self, gap: u32) {
        self.lost = self.lost.saturating_add(gap.saturating_sub(1) as u64);
        self.sent = self.sent.saturating_add(gap as u64);
    }

    /// Record a successfully received packet.
    pub fn record_received(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }

    /// Поздний пакет закрывает пропуск, а смена ключевой эпохи начинает новое окно.
    pub fn record_window(&mut self, received: u64, span: u64) {
        self.sent = span;
        self.lost = span.saturating_sub(received);
    }

    /// RTT in milliseconds (EWMA).
    pub fn rtt_ms(&self) -> u16 {
        (self.rtt_us / 1000).min(u16::MAX as u64) as u16
    }

    /// Jitter in milliseconds (EWMA).
    pub fn jitter_ms(&self) -> u16 {
        (self.jitter_us / 1000).min(u16::MAX as u64) as u16
    }

    /// Loss in parts-per-million.
    pub fn loss_ppm(&self) -> u32 {
        if self.sent == 0 {
            return 0;
        }
        ((self.lost * 1_000_000) / self.sent).min(1_000_000) as u32
    }

    /// Compute 0–100 quality score.
    ///
    /// RTT 40pts (0ms=40, ≥300ms=0) + Jitter 20pts + Loss 30pts + Neural 10pts.
    pub fn score(&self) -> u8 {
        let rtt_pts = {
            let rtt = self.rtt_ms() as u32;
            if rtt >= 300 {
                0
            } else {
                40 * (300 - rtt) / 300
            }
        };
        let jitter_pts = {
            let j = self.jitter_ms() as u32;
            if j >= 100 {
                0
            } else {
                20 * (100 - j) / 100
            }
        };
        let loss_pts = {
            let l = self.loss_ppm();
            if l >= 50_000 {
                0
            } else {
                30 * (50_000 - l) / 50_000
            }
        };
        let neural_pts = {
            let mse = self.neural_mse;
            if mse >= 0.35 {
                0
            } else {
                (10.0 * (0.35 - mse) / 0.35) as u32
            }
        };
        (rtt_pts + jitter_pts + loss_pts + neural_pts).min(100) as u8
    }

    /// Reset loss counters (call on reconnect).
    pub fn reset_loss(&mut self) {
        self.sent = 0;
        self.lost = 0;
    }
}

/// Adaptive mode level — controls keepalive, FEC, and timeout aggressiveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AdaptiveLevel {
    #[default]
    Off = 0,
    Light = 1,
    Aggressive = 2,
    Satellite = 3,
}

impl AdaptiveLevel {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Light,
            2 => Self::Aggressive,
            3 => Self::Satellite,
            _ => Self::Off,
        }
    }

    pub fn keepalive_secs(&self) -> u64 {
        match self {
            Self::Off => 8,
            Self::Light => 6,
            Self::Aggressive => 4,
            Self::Satellite => 15,
        }
    }

    /// FEC redundancy (1 repair per N data packets; 0 = disabled).
    pub fn fec_n(&self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Light => 16,
            Self::Aggressive => 8,
            Self::Satellite => 4,
        }
    }

    pub fn suggest(score: u8) -> Self {
        match score {
            80..=100 => Self::Off,
            50..=79 => Self::Light,
            20..=49 => Self::Aggressive,
            _ => Self::Satellite,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_connection_scores_high() {
        let mut qt = QualityTracker::new();
        qt.record_rtt(5_000);
        qt.record_received();
        assert!(qt.score() >= 90);
    }

    #[test]
    fn high_rtt_lowers_score() {
        let mut qt = QualityTracker::new();
        qt.record_rtt(400_000);
        // RTT ≥ 300 ms → 0 RTT points; score can be at most 60 (jitter+loss+neural)
        assert!(qt.score() <= 60);
    }

    #[test]
    fn adaptive_suggestions() {
        assert_eq!(AdaptiveLevel::suggest(10), AdaptiveLevel::Satellite);
        assert_eq!(AdaptiveLevel::suggest(60), AdaptiveLevel::Light);
        assert_eq!(AdaptiveLevel::suggest(95), AdaptiveLevel::Off);
    }
}

#[cfg(test)]
mod fec_receiver_feedback_tests {
    use super::*;
    use std::time::Duration;
    use web_time::Instant;

    #[test]
    fn fec_receiver_window_keeps_span_across_jump_reorder_and_reset() {
        let mut window = ReceiverLossWindow::default();
        assert_eq!(window.loss_ppm(), None);
        window.observe(100);
        assert_eq!(window.counts(), (1, 1));
        window.observe(103);
        assert_eq!(window.counts(), (2, 4));
        window.observe(101);
        window.observe(102);
        window.observe(102);
        assert_eq!(window.counts(), (4, 4));
        window.observe(10_000);
        assert_eq!(window.counts(), (1, RECEIVER_LOSS_WINDOW as u64));
        assert!(
            window.loss_ppm().unwrap() > 990_000,
            "Большой скачок не дает ложный clean report"
        );
        window.observe(9_999);
        assert_eq!(window.counts(), (2, RECEIVER_LOSS_WINDOW as u64));
        window.reset();
        for counter in 0..RECEIVER_LOSS_MIN_SPAN - 1 {
            window.observe(counter);
        }
        assert_eq!(window.loss_ppm(), None);
        window.observe(RECEIVER_LOSS_MIN_SPAN - 1);
        assert_eq!(window.loss_ppm(), Some(0));
        window.reset();
        for counter in u64::MAX - 31..=u64::MAX {
            window.observe(counter);
        }
        assert_eq!(window.counts(), (32, 32));
        assert_eq!(window.loss_ppm(), Some(0));
        window.observe(0);
        assert_eq!(window.counts(), (32, 32));
    }

    #[test]
    fn fec_receiver_ring_matches_set_at_word_wrap_and_max_boundaries() {
        use std::collections::BTreeSet;
        for counters in [
            vec![4095, 0, 4096, 1, 4159, 4223, 4288, 8383, 12_479, 16_576],
            vec![0, 63, 64, 65, 4095, 4096, 4097, 8192, 8191, 12_289],
            vec![
                u64::MAX - 4097,
                u64::MAX - 4096,
                u64::MAX - 65,
                u64::MAX - 64,
                u64::MAX - 63,
                u64::MAX,
                0,
            ],
        ] {
            let mut window = ReceiverLossWindow::default();
            let mut highest = None::<u64>;
            let mut lower = 0u64;
            let mut seen = BTreeSet::new();
            for counter in counters {
                let next_highest = highest.map_or(counter, |previous| previous.max(counter));
                let floor = next_highest.saturating_sub(RECEIVER_LOSS_WINDOW as u64 - 1);
                lower = if highest.is_none() {
                    counter
                } else {
                    lower.max(floor)
                };
                if counter >= floor {
                    seen.insert(counter);
                    lower = lower.min(counter);
                }
                seen.retain(|counter| *counter >= floor);
                highest = Some(next_highest);
                window.observe(counter);
                assert_eq!(
                    window.counts(),
                    (seen.len() as u64, next_highest - lower + 1),
                    "counter={counter}"
                );
                assert_eq!(
                    window
                        .words
                        .iter()
                        .map(|word| word.count_ones() as u64)
                        .sum::<u64>(),
                    window.counts().0
                );
            }
        }
    }

    #[test]
    fn fec_receiver_peer_feedback_is_ordered_expires_and_resets() {
        let now = Instant::now();
        let mut feedback = PeerReceiverFeedback::default();
        for level in [
            AdaptiveLevel::Off,
            AdaptiveLevel::Light,
            AdaptiveLevel::Aggressive,
            AdaptiveLevel::Satellite,
        ] {
            assert_eq!(feedback.fec_group(level, now), level.fec_n());
        }
        assert!(feedback.record(20, 25_000, now));
        assert_eq!(
            feedback.fec_group(AdaptiveLevel::Off, now),
            8,
            "UL loss включает TX FEC при хорошем DL"
        );
        assert!(!feedback.record(19, 0, now + Duration::from_secs(1)));
        assert!(!feedback.record(20, 0, now + Duration::from_secs(1)));
        assert_eq!(
            feedback.fec_group(AdaptiveLevel::Satellite, now + Duration::from_secs(1)),
            8
        );
        assert!(feedback.record(21, 0, now + Duration::from_secs(2)));
        assert_eq!(
            feedback.fec_group(AdaptiveLevel::Satellite, now + Duration::from_secs(2)),
            0
        );
        let expired = now + Duration::from_secs(32);
        assert_eq!(feedback.fec_group(AdaptiveLevel::Light, expired), 16);
        assert!(!feedback.record(19, 0, expired));
        assert_eq!(feedback.fec_group(AdaptiveLevel::Light, expired), 16);
        feedback.reset();
        assert!(feedback.record(0, 1, expired));
        assert_eq!(feedback.fec_group(AdaptiveLevel::Off, expired), 16);
        feedback.reset();
        assert!(feedback.record(u64::MAX, 50_000, expired));
        assert!(!feedback.record(0, 0, expired));
        assert_eq!(feedback.fec_group(AdaptiveLevel::Off, expired), 4);
    }

    #[test]
    fn fec_receiver_positive_loss_thresholds_do_not_follow_local_level() {
        let now = Instant::now();
        for (counter, loss, expected) in [
            (1, 0, 0),
            (2, 1, 16),
            (3, 9_999, 16),
            (4, 10_000, 8),
            (5, 49_999, 8),
            (6, 50_000, 4),
            (7, u32::MAX, 4),
        ] {
            let mut feedback = PeerReceiverFeedback::default();
            feedback.record(counter, loss, now);
            assert_eq!(
                feedback.fec_group(AdaptiveLevel::Light, now),
                expected,
                "loss={loss}"
            );
        }
    }

    #[cfg(feature = "client-upload")]
    #[test]
    fn fec_receiver_clean_feedback_keeps_mtu1000_single_packet_and_flushes_partial_xor() {
        use crate::upload_pipeline::{PacketEncryptor, ZeroMdhEncryptor};
        let keys = crate::crypto::derive_session_keys(&[75; 32], None, &[76; 32]);
        let mut encoder = ZeroMdhEncryptor::new(keys.clone(), 0, 0);
        let mut ip = vec![0; 1000];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&1000u16.to_be_bytes());
        encoder.set_fec_group(AdaptiveLevel::Light.fec_n());
        for _ in 0..2 {
            assert_eq!(encoder.encrypt_data_packets(&ip, 1140).unwrap().len(), 2);
        }
        let now = Instant::now();
        let mut feedback = PeerReceiverFeedback::default();
        feedback.record(1, 0, now);
        let mut clean = ZeroMdhEncryptor::new(keys, 1000, 0);
        clean.set_fec_group(feedback.fec_group(AdaptiveLevel::Light, now));
        assert_eq!(
            clean.encrypt_data_packets(&ip, 1140).unwrap().len(),
            1,
            "Clean UL не должен дробить MTU1000 ради FEC"
        );
        encoder.set_fec_group(0);
        for _ in 2..16 {
            assert_eq!(encoder.encrypt_data_packets(&ip, 1140).unwrap().len(), 2);
        }
        assert!(
            encoder.take_fec_repair().is_some(),
            "Смена16->0 дозавершает прежнюю XOR группу"
        );
        assert_eq!(encoder.encrypt_data_packets(&ip, 1140).unwrap().len(), 1);
    }
}
