//! Auto-publish signed bootstrap descriptors to external distribution
//! channels (S3-compatible object storage, GitHub release, Telegram) so
//! brand-new clients — ones with no working `aivpn://` connection key yet —
//! can discover a server the same way the client's multi-channel
//! `bootstrap_loader.rs` already knows how to fetch from.
//!
//! Descriptors that are already-connected clients receive fresh copies
//! automatically over the session (see `Gateway::send_bootstrap_descriptors`);
//! this module covers the other half — getting them somewhere a client
//! *without* a session can find.
//!
//! The config struct types below are always compiled in (needed by
//! `GatewayConfig` regardless of build features); the actual network calls
//! are gated behind the `bootstrap-publish` Cargo feature, with a no-op
//! fallback when it's off so callers don't need to sprinkle `#[cfg(...)]`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapPublishConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub channels: Vec<PublishChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PublishChannel {
    /// Any S3-compatible object store (AWS S3, Cloudflare R2, MinIO, …),
    /// addressed path-style (`{endpoint}/{bucket}/{key}`) for maximum
    /// compatibility with self-hosted providers that don't do virtual-host
    /// DNS wildcards.
    S3 {
        /// e.g. "https://s3.us-east-1.amazonaws.com" or a MinIO/R2 endpoint.
        endpoint: String,
        region: String,
        bucket: String,
        /// Object key/path, e.g. "bootstrap.json".
        key: String,
        access_key: String,
        secret_key: String,
    },
    /// GitHub release asset. Reuses (and keeps overwriting) one fixed
    /// `tag_name`, since the client's `bootstrap_loader.rs` always fetches
    /// `GET /repos/{repo}/releases/latest`.
    Github {
        /// "owner/repo"
        repo: String,
        asset_name: String,
        tag_name: String,
        token: String,
    },
    Telegram {
        bot_token: String,
        /// Numeric chat ID or "@channelusername".
        chat_id: String,
    },
}

impl PublishChannel {
    #[cfg_attr(not(feature = "bootstrap-publish"), allow(dead_code))]
    fn label(&self) -> &'static str {
        match self {
            PublishChannel::S3 { .. } => "s3",
            PublishChannel::Github { .. } => "github",
            PublishChannel::Telegram { .. } => "telegram",
        }
    }
}

#[cfg(feature = "bootstrap-publish")]
mod publish_impl {
    use super::{BootstrapPublishConfig, PublishChannel};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use tracing::{error, info, warn};

    type HmacSha256 = Hmac<Sha256>;

    const RETRY_DELAYS: [std::time::Duration; 3] = [
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(120),
    ];

    /// Bounds on every outbound publish HTTP request. `publish_all` is
    /// awaited by the hourly descriptor-rotation task
    /// (`gateway/run_loop.rs`), so a hung endpoint (TCP connect blackhole,
    /// stalled TLS, a server that accepts but never answers) without a
    /// timeout would stop descriptor rotation until process restart — and
    /// block the channels queued behind it, breaking the "one failing
    /// channel never blocks the others" contract.
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// HTTP client with the bounds above applied. `build()` here is
    /// effectively infallible (no TLS/proxy config that could fail to
    /// parse), but fall back to a default client rather than panic the
    /// rotation task if it ever isn't.
    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|e| {
                warn!("reqwest client build failed ({e}); falling back to default client");
                reqwest::Client::new()
            })
    }

    async fn read_response(
        mut response: reqwest::Response,
        limit: usize,
    ) -> Result<Vec<u8>, String> {
        if response
            .content_length()
            .is_some_and(|size| size > limit as u64)
        {
            return Err("Ответ канала публикации превышает допустимый размер".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| error.without_url().to_string())?
        {
            if chunk.len() > limit.saturating_sub(body.len()) {
                return Err("Ответ канала публикации превышает допустимый размер".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    #[cfg(test)]
    mod response_tests {
        use super::*;

        #[tokio::test]
        async fn oversized_publish_reply_is_rejected_with_or_without_content_length() {
            for declared in [false, true] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let server = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                        .unwrap();
                    let mut request = [0; 4096];
                    let received = socket.read(&mut request).unwrap();
                    assert!(received > 0);
                    let length = if declared {
                        "Content-Length: 1025\r\n"
                    } else {
                        ""
                    };
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nConnection: close\r\n{length}\r\n"
                    )
                    .unwrap();
                    let _ = socket.write_all(&[b'x'; 1025]);
                });
                let reply = reqwest::Client::builder()
                    .no_proxy()
                    .build()
                    .unwrap()
                    .get(format!("http://{address}/"))
                    .send()
                    .await
                    .unwrap();
                let result = read_response(reply, 1024).await;
                server.join().unwrap();
                assert!(result.is_err(), "declared={declared}");
            }
        }
    }

    /// Publish `descriptors_json` (the same JSON-array shape produced by
    /// `--export-bootstrap-descriptor` and the management API export
    /// endpoint) to every enabled channel. Channels are independent — one
    /// failing never blocks the others. Each channel gets up to
    /// `RETRY_DELAYS.len() + 1` attempts before being logged as failed.
    pub async fn publish_all(descriptors_json: &str, config: &BootstrapPublishConfig) {
        if !config.enabled || config.channels.is_empty() {
            return;
        }
        for channel in &config.channels {
            let label = channel.label();
            let mut attempt = 0usize;
            loop {
                let result = publish_one(descriptors_json, channel).await;
                match result {
                    Ok(()) => {
                        info!("Bootstrap descriptor published to channel '{label}'");
                        break;
                    }
                    Err(e) if attempt < RETRY_DELAYS.len() => {
                        warn!(
                            "Bootstrap publish to '{label}' failed (attempt {}/{}): {e}; retrying in {:?}",
                            attempt + 1,
                            RETRY_DELAYS.len() + 1,
                            RETRY_DELAYS[attempt]
                        );
                        tokio::time::sleep(RETRY_DELAYS[attempt]).await;
                        attempt += 1;
                    }
                    Err(e) => {
                        error!(
                            "Bootstrap publish to '{label}' failed permanently after {} attempts: {e}",
                            attempt + 1
                        );
                        break;
                    }
                }
            }
        }
    }

    async fn publish_one(json: &str, channel: &PublishChannel) -> Result<(), String> {
        match channel {
            PublishChannel::S3 { .. } => publish_s3(json, channel).await,
            PublishChannel::Github { .. } => publish_github(json, channel).await,
            PublishChannel::Telegram { .. } => publish_telegram(json, channel).await,
        }
    }

    // ──────────────────── S3-compatible (AWS SigV4) ────────────────────

    fn hmac_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Minimal AWS Signature Version 4 for a single-shot `PUT` object
    /// request, addressed path-style so it works against self-hosted
    /// S3-compatible providers (MinIO, etc.) without virtual-host DNS.
    async fn publish_s3(json: &str, channel: &PublishChannel) -> Result<(), String> {
        let PublishChannel::S3 {
            endpoint,
            region,
            bucket,
            key,
            access_key,
            secret_key,
        } = channel
        else {
            unreachable!()
        };

        let endpoint_trimmed = endpoint.trim_end_matches('/');
        let host = endpoint_trimmed
            .strip_prefix("https://")
            .or_else(|| endpoint_trimmed.strip_prefix("http://"))
            .unwrap_or(endpoint_trimmed)
            .to_string();

        let payload = json.as_bytes();
        let payload_hash = sha256_hex(payload);

        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let canonical_uri = format!("/{bucket}/{key}");
        let canonical_headers =
            format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical_request = format!(
            "PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

        let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
        let string_to_sign =
            format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

        let k_date = hmac_bytes(
            format!("AWS4{secret_key}").as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_bytes(&k_date, region.as_bytes());
        let k_service = hmac_bytes(&k_region, b"s3");
        let k_signing = hmac_bytes(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_bytes(&k_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );

        let url = format!("{endpoint_trimmed}{canonical_uri}");
        let client = http_client();
        let resp = client
            .put(&url)
            .header("Host", host)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", amz_date)
            .header("Authorization", authorization)
            .header("Content-Type", "application/json")
            .body(payload.to_vec())
            .send()
            .await
            .map_err(|e| format!("S3 request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = String::from_utf8_lossy(&read_response(resp, 8192).await?).into_owned();
            return Err(format!("S3 PUT returned {status}: {body}"));
        }
        Ok(())
    }

    // ──────────────────── GitHub release asset ────────────────────

    async fn publish_github(json: &str, channel: &PublishChannel) -> Result<(), String> {
        let PublishChannel::Github {
            repo,
            asset_name,
            tag_name,
            token,
        } = channel
        else {
            unreachable!()
        };

        let client = http_client();
        let auth_header = format!("Bearer {token}");

        // Find (or create) the release for our fixed tag, since the client
        // always fetches /releases/latest and expects a stable tag to keep
        // pointing at the newest descriptors.
        let get_url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag_name}");
        let existing = client
            .get(&get_url)
            .header("Authorization", &auth_header)
            .header("User-Agent", "aivpn-server")
            .send()
            .await
            .map_err(|e| format!("GitHub GET release failed: {e}"))?;

        let (release_id, upload_url_template, existing_asset_id) = if existing.status().is_success()
        {
            let body: serde_json::Value =
                serde_json::from_slice(&read_response(existing, 4 * 1024 * 1024).await?)
                    .map_err(|e| format!("GitHub release JSON parse failed: {e}"))?;
            let id = body["id"]
                .as_u64()
                .ok_or("GitHub release response missing id")?;
            let upload_url = body["upload_url"]
                .as_str()
                .ok_or("GitHub release response missing upload_url")?
                .to_string();
            let asset_id = body["assets"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|a| a["name"].as_str() == Some(asset_name.as_str()))
                .and_then(|a| a["id"].as_u64());
            (id, upload_url, asset_id)
        } else {
            let create_url = format!("https://api.github.com/repos/{repo}/releases");
            let resp = client
                .post(&create_url)
                .header("Authorization", &auth_header)
                .header("User-Agent", "aivpn-server")
                .json(&serde_json::json!({
                    "tag_name": tag_name,
                    "name": tag_name,
                    "body": "AIVPN bootstrap descriptor distribution point — auto-updated.",
                    "draft": false,
                    "prerelease": false,
                }))
                .send()
                .await
                .map_err(|e| format!("GitHub create-release failed: {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = String::from_utf8_lossy(&read_response(resp, 8192).await?).into_owned();
                return Err(format!("GitHub create-release returned {status}: {body}"));
            }
            let body: serde_json::Value =
                serde_json::from_slice(&read_response(resp, 4 * 1024 * 1024).await?)
                    .map_err(|e| format!("GitHub create-release JSON parse failed: {e}"))?;
            let id = body["id"]
                .as_u64()
                .ok_or("GitHub create-release response missing id")?;
            let upload_url = body["upload_url"]
                .as_str()
                .ok_or("GitHub create-release response missing upload_url")?
                .to_string();
            (id, upload_url, None)
        };

        // Remove the previous asset with the same name — GitHub rejects a
        // duplicate-named asset upload rather than overwriting it.
        if let Some(asset_id) = existing_asset_id {
            let delete_url =
                format!("https://api.github.com/repos/{repo}/releases/assets/{asset_id}");
            let _ = client
                .delete(&delete_url)
                .header("Authorization", &auth_header)
                .header("User-Agent", "aivpn-server")
                .send()
                .await;
        }
        let _ = release_id; // kept for clarity/future use (e.g. logging)

        // upload_url is a URI template like ".../assets{?name,label}"
        let upload_url = upload_url_template
            .split('{')
            .next()
            .unwrap_or(&upload_url_template)
            .to_string();
        let resp = client
            .post(format!("{upload_url}?name={asset_name}"))
            .header("Authorization", &auth_header)
            .header("User-Agent", "aivpn-server")
            .header("Content-Type", "application/json")
            .body(json.to_string())
            .send()
            .await
            .map_err(|e| format!("GitHub asset upload failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = String::from_utf8_lossy(&read_response(resp, 8192).await?).into_owned();
            return Err(format!("GitHub asset upload returned {status}: {body}"));
        }
        Ok(())
    }

    // ──────────────────── Telegram ────────────────────

    fn telegram_request_error(error: reqwest::Error) -> String {
        let error = error.without_url();
        format!("Telegram request failed: {error}")
    }

    #[cfg(test)]
    mod tests {
        #[tokio::test]
        async fn telegram_request_error_does_not_expose_token() {
            let error = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(1))
                .build()
                .unwrap()
                .get("http://127.0.0.1:0/botFAKE_PRIVATE_TOKEN/sendDocument")
                .send()
                .await
                .unwrap_err();
            let text = super::telegram_request_error(error);
            assert!(!text.contains("FAKE_PRIVATE_TOKEN"), "request URL leaked");
        }
    }

    async fn publish_telegram(json: &str, channel: &PublishChannel) -> Result<(), String> {
        let PublishChannel::Telegram { bot_token, chat_id } = channel else {
            unreachable!()
        };

        let url = format!("https://api.telegram.org/bot{bot_token}/sendDocument");
        let part = reqwest::multipart::Part::bytes(json.as_bytes().to_vec())
            .file_name("bootstrap-descriptors.json")
            .mime_str("application/json")
            .map_err(|e| format!("Telegram multipart build failed: {e}"))?;
        let form = reqwest::multipart::Form::new()
            .text("chat_id", chat_id.clone())
            .part("document", part);

        let client = http_client();
        let resp = client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(telegram_request_error)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = String::from_utf8_lossy(&read_response(resp, 8192).await?).into_owned();
            return Err(format!("Telegram sendDocument returned {status}: {body}"));
        }
        Ok(())
    }
}

#[cfg(feature = "bootstrap-publish")]
pub use publish_impl::publish_all;

/// No-op fallback when the `bootstrap-publish` feature isn't compiled in —
/// so `Gateway::run()`'s periodic rotation task can call this unconditionally
/// without needing `#[cfg(...)]` at every call site.
#[cfg(not(feature = "bootstrap-publish"))]
pub async fn publish_all(_descriptors_json: &str, config: &BootstrapPublishConfig) {
    if config.enabled && !config.channels.is_empty() {
        tracing::warn!(
            "bootstrap_publish.enabled = true in config, but the server binary was built \
             without the 'bootstrap-publish' Cargo feature — auto-publish is a no-op. \
             Rebuild with --features bootstrap-publish to enable it."
        );
    }
}
