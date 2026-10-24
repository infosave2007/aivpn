//! Измерение задержки, потерь проб и полезной скорости внутри активной сессии.

use serde::{Deserialize, Serialize};
#[cfg(any(feature = "client-upload", test))]
use std::time::Duration;
use std::time::Instant;

pub const PING: &str = "/diagnostics/v1/ping";
pub const UP: &str = "/diagnostics/v1/up";
pub const DOWN: &str = "/diagnostics/v1/down";
pub const BLOCK_BYTES: usize = 768;
#[cfg(feature = "client-upload")]
const WINDOW: usize = 64;
#[cfg(feature = "client-upload")]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchResult {
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub throughput_up_kbps: f64,
    pub throughput_down_kbps: f64,
    pub packet_loss_pct: f64,
    pub quality_score: u8,
    pub quality_label: String,
    pub samples: usize,
}

pub fn is_diagnostic(path: &str) -> bool {
    matches!(path, PING | UP | DOWN)
}

/// Ответ ограничен одним блоком и отправляется только допущенному клиенту.
pub fn response(method: u8, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    match (method, path, body.len()) {
        (1, PING, 8) => (200, body.to_vec()),
        (1, UP, BLOCK_BYTES) => (200, blake3::hash(body).as_bytes().to_vec()),
        (1, DOWN, 8) => (200, download_block(body)),
        _ => (400, Vec::new()),
    }
}

fn download_block(seed: &[u8]) -> Vec<u8> {
    let mut body = vec![0; BLOCK_BYTES];
    blake3::Hasher::new()
        .update(seed)
        .finalize_xof()
        .fill(&mut body);
    body
}

/// Бюджет одной сессии: до 8 МиБ в секунду с небольшим начальным запасом.
#[derive(Debug)]
pub struct DiagnosticBudget {
    updated: Instant,
    tokens: f64,
}
impl Default for DiagnosticBudget {
    fn default() -> Self {
        Self {
            updated: Instant::now(),
            tokens: 256.0,
        }
    }
}
impl DiagnosticBudget {
    pub fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * 8192.0)
            .min(256.0);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[cfg(feature = "client-upload")]
pub async fn run(
    mgmt: crate::mgmt::MgmtClient,
    tx: tokio::sync::mpsc::Sender<crate::protocol::ControlPayload>,
    duration: Duration,
) -> crate::Result<BenchResult> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static RUNNING: AtomicBool = AtomicBool::new(false);
    if RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(crate::Error::Session(
            "A benchmark is already running".into(),
        ));
    }
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            RUNNING.store(false, Ordering::Release);
        }
    }
    let _guard = Guard;
    run_with(
        move |path, body| {
            let mgmt = mgmt.clone();
            let tx = tx.clone();
            async move { mgmt.mgmt_call(&tx, 1, path, body, REQUEST_TIMEOUT).await }
        },
        duration,
    )
    .await
}

#[cfg(feature = "client-upload")]
async fn run_with<F, Fut>(call: F, duration: Duration) -> crate::Result<BenchResult>
where
    F: Fn(&'static str, Vec<u8>) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = crate::Result<(u16, Vec<u8>)>> + Send + 'static,
{
    use rand::RngCore;
    use tokio::time::Instant;
    let duration = duration.clamp(Duration::from_secs(3), Duration::from_secs(30));
    let phase = duration / 3;
    let mut rtts = Vec::new();
    let mut sent = 0;
    let end = Instant::now() + phase;
    while Instant::now() < end {
        let seed = rand::random::<[u8; 8]>().to_vec();
        let start = Instant::now();
        sent += 1;
        match call(PING, seed.clone()).await {
            Ok((200, body)) if body == seed => rtts.push(start.elapsed().as_secs_f64() * 1000.0),
            Ok((status, _)) if status != 200 => {
                return Err(crate::Error::Session(format!(
                    "In-session diagnostics unavailable (status {status}); update the server"
                )))
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if rtts.is_empty() {
        return Err(crate::Error::Session(
            "No diagnostic replies from the active VPN session".into(),
        ));
    }
    let mut speeds = [0.0; 2];
    for (index, path) in [UP, DOWN].into_iter().enumerate() {
        let start = Instant::now();
        let end = start + phase;
        let mut jobs = tokio::task::JoinSet::new();
        let mut bytes: u64 = 0;
        let mut requests = 0u64;
        let mut failed = [0u64; 3];
        loop {
            while (requests == 0 || Instant::now() < end) && jobs.len() < WINDOW {
                let call = call.clone();
                let mut body = vec![0; if path == UP { BLOCK_BYTES } else { 8 }];
                rand::thread_rng().fill_bytes(&mut body);
                let expected = if path == UP {
                    blake3::hash(&body).as_bytes().to_vec()
                } else {
                    download_block(&body)
                };
                requests += 1;
                jobs.spawn(async move {
                    match call(path, body).await {
                        Ok((200, received)) if received == expected => (BLOCK_BYTES as u64, 0usize),
                        Ok((200, _)) => (0, 1),
                        Ok((_, _)) => (0, 2),
                        Err(_) => (0, 3),
                    }
                });
            }
            match jobs.join_next().await {
                Some(Ok((n, reason))) => {
                    bytes += n;
                    if reason > 0 {
                        failed[reason - 1] += 1;
                    }
                }
                Some(Err(_)) => {}
                None => break,
            }
        }
        tracing::debug!(path, requests, bytes, bad_body = failed[0], rejected = failed[1], call_failed = failed[2], elapsed = ?start.elapsed(), "Диагностика: передача тестовых блоков");
        if bytes == 0 {
            return Err(crate::Error::Session(format!(
                "No confirmed diagnostic blocks for {path} (requests={requests}, bad_body={}, rejected={}, call_failed={})",
                failed[0], failed[1], failed[2]
            )));
        }
        // Время включает доставку последнего подтверждения, а не только постановку в очередь.
        speeds[index] = bytes as f64 * 8.0 / start.elapsed().as_secs_f64().max(0.001) / 1000.0;
    }
    rtts.sort_by(f64::total_cmp);
    let percentile = |p: f64| {
        rtts[((rtts.len() as f64 * p).ceil() as usize)
            .saturating_sub(1)
            .min(rtts.len() - 1)]
    };
    let loss = (sent - rtts.len()) as f64 / sent as f64 * 100.0;
    let p50 = percentile(0.50);
    let latency_score: f64 = if p50 < 20.0 {
        100.0
    } else if p50 < 50.0 {
        90.0
    } else if p50 < 100.0 {
        75.0
    } else if p50 < 200.0 {
        55.0
    } else {
        30.0
    };
    let score = (latency_score - (loss * 2.0).min(60.0)).max(0.0) as u8;
    Ok(BenchResult {
        latency_p50_ms: p50,
        latency_p95_ms: percentile(0.95),
        latency_p99_ms: percentile(0.99),
        throughput_up_kbps: speeds[0],
        throughput_down_kbps: speeds[1],
        packet_loss_pct: loss,
        quality_score: score,
        quality_label: match score {
            80..=100 => "Excellent",
            60..=79 => "Good",
            40..=59 => "Fair",
            _ => "Poor",
        }
        .into(),
        samples: sent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_responses_and_budget() {
        assert_eq!(response(1, PING, &[3; 8]), (200, vec![3; 8]));
        assert_eq!(
            response(1, UP, &[7; BLOCK_BYTES]).1,
            blake3::hash(&[7; BLOCK_BYTES]).as_bytes()
        );
        assert_eq!(response(1, DOWN, &[0; 8]).1.len(), BLOCK_BYTES);
        assert_eq!(response(1, DOWN, &[0; 9]).0, 400);
        assert_eq!(response(0, PING, &[0; 8]).0, 400);
        let mut budget = DiagnosticBudget::default();
        let now = Instant::now();
        for _ in 0..256 {
            assert!(budget.take(now));
        }
        assert!(!budget.take(now));
        assert!(budget.take(now + Duration::from_secs(1)));
    }
    #[cfg(feature = "client-upload")]
    #[tokio::test(start_paused = true)]
    async fn a_failed_download_is_an_error_instead_of_an_excellent_connection() {
        let error = run_with(
            |path, body| async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if path == DOWN {
                    Err(crate::Error::Session("lost".into()))
                } else {
                    Ok(response(1, path, &body))
                }
            },
            Duration::from_secs(3),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(DOWN));
        assert!(error.to_string().contains("No confirmed diagnostic blocks"));
    }
    #[cfg(feature = "client-upload")]
    #[tokio::test(start_paused = true)]
    async fn measures_confirmed_bytes_with_loss_and_asymmetric_rates() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let sequence = Arc::new(AtomicUsize::new(0));
        let result = run_with(
            move |path, body| {
                let n = sequence.fetch_add(1, Ordering::Relaxed);
                async move {
                    let delay = if path == UP { 20 } else { 40 };
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    if path == PING && n % 3 == 0 {
                        return Err(crate::Error::Session("lost".into()));
                    }
                    Ok(response(1, path, &body))
                }
            },
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(result.packet_loss_pct > 0.0 && result.packet_loss_pct < 100.0);
        assert!(result.throughput_up_kbps > result.throughput_down_kbps * 1.5);
        assert!(result.latency_p50_ms >= 40.0);
    }
}
