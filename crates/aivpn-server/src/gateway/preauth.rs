use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Бюджет времени одного ядра. Дорогая попытка переносит долг на следующие секунды.
pub(super) struct PreauthBudget {
    credit_ns: i128,
    updated: Instant,
    busy: bool,
}

impl PreauthBudget {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            credit_ns: 100_000_000,
            updated: now,
            busy: false,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos() as i128;
        self.credit_ns = self.credit_ns.saturating_add(elapsed / 10).min(100_000_000);
        self.updated = now;
    }

    pub(super) fn try_begin(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.busy || self.credit_ns <= 0 {
            return false;
        }
        self.busy = true;
        true
    }

    pub(super) fn finish(&mut self, now: Instant, cost: Duration) {
        self.refill(now);
        self.credit_ns = self.credit_ns.saturating_sub(cost.as_nanos() as i128);
        self.busy = false;
    }
}

/// Возврат бюджета учитывает и раннюю ошибку, и успешный выход из handshake.
pub(super) struct PreauthLease {
    budget: Arc<Mutex<PreauthBudget>>,
    started: Instant,
}

impl PreauthLease {
    pub(super) fn acquire(budget: Arc<Mutex<PreauthBudget>>) -> Option<Self> {
        let started = Instant::now();
        if !budget.lock().try_begin(started) {
            return None;
        }
        Some(Self { budget, started })
    }
}

impl Drop for PreauthLease {
    fn drop(&mut self) {
        let now = Instant::now();
        self.budget
            .lock()
            .finish(now, now.saturating_duration_since(self.started));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expensive_scan_debt_survives_second_boundary() {
        let now = Instant::now();
        let mut budget = PreauthBudget::new(now);
        assert!(budget.try_begin(now));
        budget.finish(now + Duration::from_millis(250), Duration::from_millis(250));
        assert!(!budget.try_begin(now + Duration::from_secs(1)));
        assert!(budget.try_begin(now + Duration::from_secs(2)));
    }

    #[test]
    fn concurrent_scan_cannot_spend_unfinished_attempt_budget() {
        let now = Instant::now();
        let mut budget = PreauthBudget::new(now);
        assert!(budget.try_begin(now));
        assert!(!budget.try_begin(now + Duration::from_secs(10)));
        budget.finish(now + Duration::from_secs(10), Duration::from_millis(5));
        assert!(budget.try_begin(now + Duration::from_secs(10)));
    }

    #[test]
    fn many_fast_scans_exhaust_budget_even_below_packet_rate_limit() {
        let now = Instant::now();
        let mut budget = PreauthBudget::new(now);
        for index in 0..5 {
            assert!(budget.try_begin(now + Duration::from_millis(index * 25)));
            budget.finish(
                now + Duration::from_millis((index + 1) * 25),
                Duration::from_millis(25),
            );
        }
        assert!(!budget.try_begin(now + Duration::from_millis(125)));
    }
}
