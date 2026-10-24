//! Диагностика через активную сессию основного клиента.

pub use aivpn_common::diagnostics::BenchResult;
use std::{net::SocketAddrV4, time::Duration};

pub async fn run_bench(
    admin_addr: SocketAddrV4,
    duration: Duration,
) -> aivpn_common::Result<BenchResult> {
    run_bench_with_token(
        admin_addr,
        duration,
        crate::record_cmd::read_admin_token_at(admin_addr),
    )
    .await
}

pub async fn run_bench_with_token(
    admin_addr: SocketAddrV4,
    duration: Duration,
    token: Option<String>,
) -> aivpn_common::Result<BenchResult> {
    let token =
        token.ok_or_else(|| aivpn_common::Error::Session("No active client admin token".into()))?;
    let duration = duration.as_secs().clamp(3, 30);
    let line = format!("{token}:bench:{duration}");
    let reply = tokio::task::spawn_blocking(move || {
        aivpn_common::local_admin::request(admin_addr, &line, Duration::from_secs(duration + 8))
    })
    .await
    .map_err(|e| aivpn_common::Error::Session(e.to_string()))??;
    let value: serde_json::Value =
        serde_json::from_str(&reply).map_err(|e| aivpn_common::Error::Session(e.to_string()))?;
    if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
        return Err(aivpn_common::Error::Session(error.into()));
    }
    serde_json::from_value(value).map_err(|e| aivpn_common::Error::Session(e.to_string()))
}
