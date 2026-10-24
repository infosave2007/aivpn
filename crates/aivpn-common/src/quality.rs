//! Connection quality scoring and RTT tracking (0.9.0)
//!
//! Computes a 0–100 quality score from RTT, jitter, packet loss, and neural MSE.

const EWMA_ALPHA_INV: u64 = 8;

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
