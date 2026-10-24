//! Общий бюджет повторов до подтверждения PFS.
//!
//! Повтор сохраняет ephemeral key соединения, но заново шифруется с очередным
//! счетчиком и случайным InitialV2 nonce. Дедлайн не продлевается входным шумом.

use std::time::Duration;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(2);

pub struct HandshakeRetry {
    next_at: Duration,
    interval: Duration,
}

impl Default for HandshakeRetry {
    fn default() -> Self {
        use rand::Rng;
        Self::with_initial_delay(Duration::from_millis(
            rand::thread_rng().gen_range(250..=350),
        ))
    }
}

impl HandshakeRetry {
    pub fn with_initial_delay(delay: Duration) -> Self {
        let interval = delay.clamp(Duration::from_millis(250), Duration::from_millis(350));
        Self {
            next_at: interval,
            interval,
        }
    }

    pub fn next_at(&self) -> Duration {
        self.next_at.min(HANDSHAKE_TIMEOUT)
    }

    pub fn expired(&self, elapsed: Duration) -> bool {
        elapsed >= HANDSHAKE_TIMEOUT
    }

    /// Следующая попытка отсчитывается от отправки, без догоняющего burst.
    pub fn sent(&mut self, elapsed: Duration) {
        self.interval = self.interval.saturating_mul(2).min(MAX_RETRY_INTERVAL);
        self.next_at = elapsed.saturating_add(self.interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_budget_is_bounded_and_independent_of_keepalive() {
        for initial in [250, 300, 350] {
            let mut retry = HandshakeRetry::with_initial_delay(Duration::from_millis(initial));
            let mut count = 0;
            while !retry.expired(retry.next_at()) {
                let now = retry.next_at();
                assert!(now < HANDSHAKE_TIMEOUT);
                retry.sent(now);
                assert!(retry.next_at() - now <= MAX_RETRY_INTERVAL);
                count += 1;
            }
            assert!((6..=7).contains(&count));
            assert_eq!(retry.next_at(), HANDSHAKE_TIMEOUT);
        }
    }

    #[test]
    fn paused_sender_does_not_catch_up_with_a_burst() {
        let mut retry = HandshakeRetry::default();
        retry.sent(Duration::from_secs(5));
        assert!(retry.next_at() >= Duration::from_millis(5500));
        assert!(retry.expired(Duration::from_secs(10)));
    }
}
