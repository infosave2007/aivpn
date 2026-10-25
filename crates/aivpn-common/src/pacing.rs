//! Регулировка IAT по времени ожидания в очереди перед шифрованием.

use std::time::{Duration, Instant};

use serde::Deserialize;

const CONTROL_INTERVAL: Duration = Duration::from_millis(100);
const HIGH_WAIT: Duration = Duration::from_millis(50);
const LOW_WAIT: Duration = Duration::from_millis(10);
const MIN_INTERVAL: Duration = Duration::from_millis(1);
const MAX_SPEEDUP: f64 = 64.0;
const SPEEDUP_STEP: f64 = 1.5;
const RECOVERY_STEP: f64 = 0.8;

/// Локальная политика пауз. Размеры, маска и шифрование от нее не зависят.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PacingMode {
    #[default]
    Adaptive,
    Full,
    Off,
}

/// Один регулятор на направление сессии. Ускорение ограничено, а следующий
/// срок вызывающий всегда отсчитывает от фактической отправки, без догоняния.
pub struct AdaptivePacer {
    mode: PacingMode,
    speedup: f64,
    window_start: Option<Instant>,
    min_wait: Option<Duration>,
}

impl AdaptivePacer {
    pub fn new(mode: PacingMode) -> Self {
        Self {
            mode,
            speedup: 1.0,
            window_start: None,
            min_wait: None,
        }
    }

    pub fn reset(&mut self) {
        self.speedup = 1.0;
        self.window_start = None;
        self.min_wait = None;
    }

    /// `queue_wait` измеряется с приема сырого пакета в очередь планировщика.
    /// Минимум за окно отличает устойчивый затор от единичной длинной паузы.
    pub fn delay(&mut self, profile: Duration, queue_wait: Duration, now: Instant) -> Duration {
        match self.mode {
            PacingMode::Full => return profile,
            PacingMode::Off => return Duration::ZERO,
            PacingMode::Adaptive => {}
        }
        let start = *self.window_start.get_or_insert(now);
        let elapsed = now.saturating_duration_since(start);
        let observed = self.min_wait.unwrap_or(queue_wait).min(queue_wait);
        if elapsed >= CONTROL_INTERVAL {
            let previous = self.speedup;
            if observed > HIGH_WAIT {
                // Даже после долгой остановки повышаем темп только на один шаг.
                self.speedup = (self.speedup * SPEEDUP_STEP).min(MAX_SPEEDUP);
            } else if queue_wait < LOW_WAIT && observed < LOW_WAIT {
                // Во время простоя темп успевает вернуться к исходному.
                let steps = (elapsed.as_secs_f64() / CONTROL_INTERVAL.as_secs_f64())
                    .floor()
                    .min(64.0);
                self.speedup = (self.speedup * RECOVERY_STEP.powf(steps)).max(1.0);
            }
            if previous != self.speedup {
                tracing::debug!(
                    speedup = self.speedup,
                    wait_ms = observed.as_millis() as u64,
                    "Изменен темп адаптивного шейпинга"
                );
            }
            self.window_start = Some(now);
            self.min_wait = Some(queue_wait);
        } else {
            self.min_wait = Some(observed);
        }
        if profile.is_zero() || self.speedup == 1.0 {
            profile
        } else {
            profile.div_f64(self.speedup).max(MIN_INTERVAL).min(profile)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_traffic_keeps_profile_and_explicit_modes_ignore_backlog() {
        let now = Instant::now();
        let interval = Duration::from_millis(30);
        for (mode, expected) in [
            (PacingMode::Adaptive, interval),
            (PacingMode::Full, interval),
            (PacingMode::Off, Duration::ZERO),
        ] {
            let mut pacer = AdaptivePacer::new(mode);
            for n in 0..20 {
                let wait = if mode == PacingMode::Adaptive {
                    Duration::ZERO
                } else {
                    Duration::from_secs(5)
                };
                assert_eq!(
                    pacer.delay(interval, wait, now + CONTROL_INTERVAL * n),
                    expected
                );
            }
        }
    }

    #[test]
    fn persistent_backlog_accelerates_gradually_with_a_floor_and_ceiling() {
        let now = Instant::now();
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        let interval = Duration::from_millis(30);
        assert_eq!(pacer.delay(interval, HIGH_WAIT * 2, now), interval);
        let first = pacer.delay(interval, HIGH_WAIT * 2, now + CONTROL_INTERVAL);
        assert_eq!(first, Duration::from_millis(20));
        for n in 2..100 {
            let delay = pacer.delay(interval, HIGH_WAIT * 2, now + CONTROL_INTERVAL * n);
            assert!(delay >= MIN_INTERVAL && delay <= first);
        }
        assert_eq!(pacer.speedup, MAX_SPEEDUP);
        assert_eq!(
            pacer.delay(
                Duration::from_secs(1),
                HIGH_WAIT * 2,
                now + Duration::from_secs(10)
            ),
            Duration::from_micros(15_625)
        );
        assert_eq!(
            pacer.delay(
                Duration::from_micros(100),
                HIGH_WAIT * 2,
                now + Duration::from_secs(10)
            ),
            Duration::from_micros(100)
        );
    }

    #[test]
    fn single_spike_does_not_accelerate_and_idle_recovers() {
        let now = Instant::now();
        let interval = Duration::from_millis(30);
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        pacer.delay(interval, Duration::ZERO, now);
        assert_eq!(
            pacer.delay(interval, Duration::from_secs(2), now + CONTROL_INTERVAL),
            interval
        );
        for n in 2..20 {
            pacer.delay(interval, HIGH_WAIT * 2, now + CONTROL_INTERVAL * n);
        }
        let accelerated = pacer.speedup;
        pacer.delay(interval, Duration::ZERO, now + CONTROL_INTERVAL * 20);
        assert!(pacer.speedup < accelerated && pacer.speedup > 1.0);
        assert_eq!(
            pacer.delay(interval, Duration::ZERO, now + Duration::from_secs(10)),
            interval
        );
        pacer.reset();
        assert_eq!(
            pacer.delay(interval, HIGH_WAIT * 2, now + Duration::from_secs(11)),
            interval
        );
    }

    #[test]
    fn policy_rejects_unknown_values() {
        for text in ["adaptive", "full", "off"] {
            assert!(serde_json::from_str::<PacingMode>(&format!("\"{text}\"")).is_ok());
        }
        assert!(serde_json::from_str::<PacingMode>("\"automatic\"").is_err());
    }
}
