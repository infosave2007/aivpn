//! Регулировка IAT по времени ожидания в очереди перед шифрованием.

use std::time::{Duration, Instant};

use serde::Deserialize;

const CONTROL_INTERVAL: Duration = Duration::from_millis(100);
const HIGH_WAIT: Duration = Duration::from_millis(5);
const LOW_WAIT: Duration = Duration::from_millis(1);
const BATCH_INTERVAL: Duration = Duration::from_millis(1);
const MAX_BATCH_PACKETS: usize = 64;
const MAX_SPEEDUP: f64 = 4096.0;
const SPEEDUP_STEP: f64 = 1.5;
const RECOVERY_STEP: f64 = 0.8;

#[cfg(feature = "client-upload")]
/// Истекший срок готов сразу: он не требует округленного тика таймера Tokio.
pub async fn wait_until(deadline: tokio::time::Instant) {
    if deadline > tokio::time::Instant::now() {
        tokio::time::sleep_until(deadline).await;
    }
}

/// Локальная политика пауз. Размеры, маска и шифрование от нее не зависят.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PacingMode {
    #[default]
    Adaptive,
    Full,
    Off,
}

/// Один регулятор на направление сессии. Сроки учитывают фактическую отправку,
/// а ускоренные серии ограничены одним квантом без догоняния старого долга.
pub struct AdaptivePacer {
    mode: PacingMode,
    speedup: f64,
    window_start: Option<Instant>,
    min_wait: Option<Duration>,
    batch_start: Option<Instant>,
    batch_cost: Duration,
    batch_packets: usize,
    pending_cost: Option<Duration>,
}

impl AdaptivePacer {
    pub fn new(mode: PacingMode) -> Self {
        Self {
            mode,
            speedup: 1.0,
            window_start: None,
            min_wait: None,
            batch_start: None,
            batch_cost: Duration::ZERO,
            batch_packets: 0,
            pending_cost: None,
        }
    }

    pub fn reset(&mut self) {
        self.speedup = 1.0;
        self.window_start = None;
        self.min_wait = None;
        self.clear_batch();
        self.pending_cost = None;
    }

    pub fn mode(&self) -> PacingMode {
        self.mode
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
            profile.div_f64(self.speedup).max(Duration::from_nanos(1))
        }
    }

    fn clear_batch(&mut self) {
        self.batch_start = None;
        self.batch_cost = Duration::ZERO;
        self.batch_packets = 0;
    }

    /// Подтверждает выдачу одного RAW IP-пакета. Планирование будущего срока
    /// само по себе не расходует квант, который еще не наступил.
    pub fn sent(&mut self, now: Instant) {
        let Some(cost) = self.pending_cost.take() else {
            return;
        };
        if self
            .batch_start
            .is_some_and(|start| now.saturating_duration_since(start) >= BATCH_INTERVAL)
        {
            self.clear_batch();
        }
        self.batch_start.get_or_insert(now);
        self.batch_cost = self.batch_cost.saturating_add(cost);
        self.batch_packets += 1;
    }

    /// Короткие интервалы объединяются в ограниченный квант. Истекшие кванты
    /// не дают кредита: после задержки доступна только одна новая серия.
    pub fn schedule(
        &mut self,
        profile: Duration,
        queue_wait: Duration,
        now: Instant,
        last_sent: Option<Instant>,
    ) -> Instant {
        let delay = self.delay(profile, queue_wait, now);
        self.pending_cost = (self.mode == PacingMode::Adaptive).then_some(delay);
        let profile_deadline = last_sent
            .unwrap_or(now)
            .checked_add(delay)
            .unwrap_or(now)
            .max(now);
        if self.mode != PacingMode::Adaptive {
            self.clear_batch();
            return profile_deadline;
        }
        let start = self.batch_start.unwrap_or(now);
        if now.saturating_duration_since(start) >= BATCH_INTERVAL {
            self.clear_batch();
        }
        let start = self.batch_start.unwrap_or(now);
        let deadline = if self.speedup == 1.0 || delay >= BATCH_INTERVAL {
            profile_deadline
        } else {
            now
        };
        if self.batch_packets >= MAX_BATCH_PACKETS
            || (self.batch_packets > 0 && self.batch_cost.saturating_add(delay) > BATCH_INTERVAL)
        {
            return start
                .checked_add(BATCH_INTERVAL)
                .unwrap_or(now)
                .max(deadline);
        }
        deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "client-upload")]
    #[test]
    fn elapsed_deadline_is_ready_without_registering_a_timer() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let mut future = Box::pin(wait_until(tokio::time::Instant::now()));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(())
        ));
    }

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
    fn persistent_backlog_accelerates_gradually_with_a_ceiling() {
        let now = Instant::now();
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        let interval = Duration::from_millis(30);
        assert_eq!(pacer.delay(interval, HIGH_WAIT * 2, now), interval);
        let first = pacer.delay(interval, HIGH_WAIT * 2, now + CONTROL_INTERVAL);
        assert_eq!(first, Duration::from_millis(20));
        for n in 2..100 {
            let delay = pacer.delay(interval, HIGH_WAIT * 2, now + CONTROL_INTERVAL * n);
            assert!(delay > Duration::ZERO && delay <= first);
        }
        assert_eq!(pacer.speedup, MAX_SPEEDUP);
        assert_eq!(
            pacer.delay(
                Duration::from_secs(1),
                HIGH_WAIT * 2,
                now + Duration::from_secs(10)
            ),
            Duration::from_nanos(244_141)
        );
        assert_eq!(
            pacer.delay(
                Duration::from_micros(100),
                HIGH_WAIT * 2,
                now + Duration::from_secs(10)
            ),
            Duration::from_nanos(24)
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

    #[test]
    fn sustained_short_backlog_can_reach_broadband_packet_rates() {
        let start = Instant::now();
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        let mut delay = Duration::ZERO;
        for n in 0..30 {
            delay = pacer.delay(
                Duration::from_millis(30),
                Duration::from_millis(10),
                start + CONTROL_INTERVAL * n,
            );
        }
        assert!(
            delay < Duration::from_micros(50),
            "Устойчивая очередь ограничена интервалом {delay:?} на пакет"
        );
    }

    #[test]
    fn accelerated_batches_are_bounded_and_do_not_accumulate_idle_credit() {
        let start = Instant::now();
        let profile = Duration::from_millis(30);
        let backlog = Duration::from_millis(10);
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        for n in 0..30 {
            pacer.delay(profile, backlog, start + CONTROL_INTERVAL * n);
        }
        let now = start + Duration::from_secs(3);
        for _ in 0..MAX_BATCH_PACKETS {
            assert_eq!(pacer.schedule(profile, backlog, now, Some(now)), now);
            pacer.sent(now);
        }
        assert_eq!(
            pacer.schedule(profile, backlog, now, Some(now)),
            now + BATCH_INTERVAL
        );
        let resumed = now + Duration::from_secs(60);
        pacer.sent(resumed);
        for _ in 1..MAX_BATCH_PACKETS {
            assert_eq!(
                pacer.schedule(profile, backlog, resumed, Some(now)),
                resumed
            );
            pacer.sent(resumed);
        }
        assert_eq!(
            pacer.schedule(profile, backlog, resumed, Some(resumed)),
            resumed + BATCH_INTERVAL
        );
        pacer.sent(resumed + BATCH_INTERVAL);
        let idle = resumed + Duration::from_secs(60);
        assert_eq!(
            pacer.schedule(profile, Duration::ZERO, idle, Some(resumed)),
            idle
        );
        pacer.sent(idle);
        assert_eq!(
            pacer.schedule(profile, Duration::ZERO, idle, Some(idle)),
            idle + profile
        );
        pacer.reset();
        assert_eq!(pacer.schedule(profile, backlog, idle, None), idle + profile);
    }

    #[test]
    fn batching_accounts_for_interval_cost_and_keeps_strict_mode() {
        let start = Instant::now();
        let mut adaptive = AdaptivePacer::new(PacingMode::Adaptive);
        for n in 0..30 {
            adaptive.delay(
                Duration::from_millis(30),
                Duration::from_millis(10),
                start + CONTROL_INTERVAL * n,
            );
        }
        let now = start + Duration::from_secs(3);
        // При максимальном ускорении этот профиль требует 250 мкс на пакет.
        let profile = Duration::from_millis(1024);
        for _ in 0..4 {
            assert_eq!(
                adaptive.schedule(profile, Duration::from_millis(10), now, Some(now)),
                now
            );
            adaptive.sent(now);
        }
        assert_eq!(
            adaptive.schedule(profile, Duration::from_millis(10), now, Some(now)),
            now + BATCH_INTERVAL
        );
        for mode in [PacingMode::Full, PacingMode::Off] {
            let mut pacer = AdaptivePacer::new(mode);
            let interval = Duration::from_micros(10);
            let expected = if mode == PacingMode::Full {
                interval
            } else {
                Duration::ZERO
            };
            for _ in 0..100 {
                assert_eq!(
                    pacer.schedule(interval, Duration::from_secs(5), now, Some(now)),
                    now + expected
                );
                pacer.sent(now + expected);
            }
        }
    }

    #[test]
    fn late_wakeup_counts_the_previously_pending_packet_in_the_new_batch() {
        let start = Instant::now();
        let profile = Duration::from_millis(30);
        let backlog = Duration::from_millis(10);
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        for n in 0..30 {
            pacer.delay(profile, backlog, start + CONTROL_INTERVAL * n);
        }
        let now = start + Duration::from_secs(3);
        for _ in 0..MAX_BATCH_PACKETS {
            assert_eq!(pacer.schedule(profile, backlog, now, Some(now)), now);
            pacer.sent(now);
        }
        assert_eq!(
            pacer.schedule(profile, backlog, now, Some(now)),
            now + BATCH_INTERVAL
        );
        let late = now + BATCH_INTERVAL * 2;
        pacer.sent(late);
        let mut released = 1;
        for _ in 0..MAX_BATCH_PACKETS {
            if pacer.schedule(profile, backlog, late, Some(late)) > late {
                break;
            }
            released += 1;
            pacer.sent(late);
        }
        assert!(
            released <= MAX_BATCH_PACKETS,
            "После позднего пробуждения выдано {released} IP-пакетов"
        );
    }

    #[test]
    fn each_scheduled_cost_is_committed_once_and_reset_cancels_it() {
        let start = Instant::now();
        let profile = Duration::from_millis(30);
        let backlog = Duration::from_millis(10);
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        for n in 0..30 {
            pacer.delay(profile, backlog, start + CONTROL_INTERVAL * n);
        }
        let now = start + Duration::from_secs(3);
        for _ in 0..MAX_BATCH_PACKETS {
            assert_eq!(pacer.schedule(profile, backlog, now, Some(now)), now);
            pacer.sent(now);
            pacer.sent(now);
        }
        assert_eq!(
            pacer.schedule(profile, backlog, now, Some(now)),
            now + BATCH_INTERVAL
        );
        pacer.reset();
        pacer.sent(now + BATCH_INTERVAL);
        assert_eq!(pacer.batch_packets, 0);
        assert!(pacer.pending_cost.is_none());
    }

    #[test]
    fn zero_iat_does_not_erase_packet_quota() {
        let start = Instant::now();
        let backlog = Duration::from_millis(10);
        let profile = Duration::from_millis(30);
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        for n in 0..30 {
            pacer.delay(profile, backlog, start + CONTROL_INTERVAL * n);
        }
        let now = start + Duration::from_secs(3);
        for _ in 0..MAX_BATCH_PACKETS {
            assert_eq!(pacer.schedule(profile, backlog, now, Some(now)), now);
            pacer.sent(now);
        }
        assert_eq!(
            pacer.schedule(Duration::ZERO, backlog, now, Some(now)),
            now + BATCH_INTERVAL,
            "Нулевая выборка сбрасывает уже заполненный квант"
        );
        let mut zero = AdaptivePacer::new(PacingMode::Adaptive);
        let mut ready = 0;
        for _ in 0..MAX_BATCH_PACKETS * 2 {
            if zero.schedule(Duration::ZERO, backlog, now, Some(now)) > now {
                break;
            }
            zero.sent(now);
            ready += 1;
        }
        assert_eq!(ready, MAX_BATCH_PACKETS);
    }

    #[test]
    fn mixed_submillisecond_iat_respects_quota_before_acceleration() {
        let now = Instant::now();
        let mut pacer = AdaptivePacer::new(PacingMode::Adaptive);
        for _ in 0..MAX_BATCH_PACKETS {
            assert_eq!(
                pacer.schedule(Duration::ZERO, Duration::ZERO, now, Some(now)),
                now
            );
            pacer.sent(now);
        }
        let interval = Duration::from_micros(100);
        let next = pacer.schedule(interval, Duration::ZERO, now, Some(now));
        assert_eq!(next, now + BATCH_INTERVAL);
        pacer.sent(next);
        assert_eq!(pacer.batch_packets, 1);
        assert_eq!(
            pacer.schedule(interval, Duration::ZERO, next, Some(next)),
            next + interval
        );
        assert_eq!(
            pacer.schedule(Duration::ZERO, Duration::ZERO, next, Some(next)),
            next
        );
    }
}
