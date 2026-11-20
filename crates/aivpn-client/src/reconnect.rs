//! Одна политика задержки для CLI и ограниченного пакетного работника.
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
/// Задержка после первой ошибки и после устойчивого соединения.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);
pub const HEALTHY_CONNECTION_THRESHOLD: Duration = Duration::from_secs(30);

pub async fn wait_reconnect_backoff(backoff: Duration, shutdown: &AtomicBool) {
    let deadline = tokio::time::Instant::now() + backoff;
    while !shutdown.load(Ordering::SeqCst) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + Duration::from_millis(100)),
        )
        .await;
    }
}

pub fn should_reset_backoff(uptime: Duration) -> bool {
    uptime >= HEALTHY_CONNECTION_THRESHOLD
}
