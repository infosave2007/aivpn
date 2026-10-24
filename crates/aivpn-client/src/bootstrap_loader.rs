//! Multi-channel Bootstrap Descriptor Loader
//!
//! Implements resilient bootstrap descriptor distribution across multiple channels
//! to prevent single-point-of-failure blocking by censors.

use rand::{prelude::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use aivpn_common::error::{Error, Result};
pub use aivpn_common::mask::{BootstrapChannel, BootstrapConfig, BootstrapDescriptor};

use crate::bootstrap_cache::{load_descriptors, store_verified_descriptor};

/// Result from a single channel load attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLoadResult {
    pub channel_name: String,
    pub channel_type: String,
    pub success: bool,
    pub descriptors_loaded: usize,
    pub error: Option<String>,
    pub latency_ms: u64,
}

/// Statistics from multi-channel loading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChannelLoadStats {
    pub total_channels: usize,
    pub successful_channels: usize,
    pub total_descriptors: usize,
    pub results: Vec<ChannelLoadResult>,
    pub elapsed_ms: u64,
}

/// Проверяет канонический URL тем же парсером, который использует HTTP-клиент.
pub(crate) fn validate_bootstrap_url(url: &str) -> Result<()> {
    let parsed =
        reqwest::Url::parse(url).map_err(|_| Error::Session("Invalid bootstrap URL".into()))?;
    if parsed.scheme() != "https" {
        return Err(Error::Session("Bootstrap URL requires HTTPS".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::Session(
            "Bootstrap URL credentials are not allowed".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::Session("Bootstrap URL has no host".into()))?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    let blocked = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !is_public_bootstrap_ip(ip),
        Err(_) => {
            matches!(host, "localhost" | "ip6-localhost" | "ip6-loopback")
                || host.ends_with(".localhost")
        }
    };
    if blocked {
        return Err(Error::Session(
            "Bootstrap URL requires a public address".into(),
        ));
    }
    Ok(())
}

fn is_public_bootstrap_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (18..=19).contains(&b))
                || (a == 192 && b == 0 && c == 0))
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public_bootstrap_ip(std::net::IpAddr::V4(v4));
            }
            let segments = ip.segments();
            // Принимаем глобальный unicast, исключая документационный диапазон.
            (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn public_bootstrap_addrs(
    addrs: impl Iterator<Item = std::net::SocketAddr>,
) -> std::io::Result<reqwest::dns::Addrs> {
    let addrs: Vec<_> = addrs.collect();
    if addrs.is_empty() || addrs.iter().any(|addr| !is_public_bootstrap_ip(addr.ip())) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Bootstrap DNS must resolve only to public addresses",
        ));
    }
    Ok(Box::new(addrs.into_iter()))
}

struct BootstrapResolver;

impl reqwest::dns::Resolve for BootstrapResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            // Проверяем именно адреса подключения, без повторного DNS-запроса.
            let addrs = tokio::net::lookup_host((name.as_str(), 0)).await?;
            Ok(public_bootstrap_addrs(addrs)?)
        })
    }
}

pub(crate) fn bootstrap_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .https_only(true)
        .user_agent("aivpn-client")
        // Системный прокси разрешает имена удаленно и обходит наш DNS-фильтр.
        .no_proxy()
        .dns_resolver(std::sync::Arc::new(BootstrapResolver))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("Too many bootstrap redirects")
            } else if validate_bootstrap_url(attempt.url().as_str()).is_err() {
                attempt.error("Bootstrap redirect requires a public HTTPS URL")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))
}

/// Hard cap on any bootstrap channel response body. Descriptor payloads are a
/// few KB; anything beyond this is either misconfiguration or an attempt to
/// exhaust memory via an attacker-influenced URL.
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Read a response body with a size cap — `response.text()` would buffer an
/// unbounded body in memory. Error strings are static so they can never leak
/// the request URL (which for Telegram embeds the bot token).
pub(crate) async fn read_body_capped(
    mut response: reqwest::Response,
) -> std::result::Result<String, &'static str> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BODY_BYTES as u64)
    {
        return Err("response body too large");
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "failed to read response body")?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
            return Err("response body too large");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "response body is not valid UTF-8")
}

/// Load descriptors from a CDN channel
async fn load_from_cdn(url: &str, signing_key: &[u8; 32]) -> Result<Vec<BootstrapDescriptor>> {
    validate_bootstrap_url(url)?;
    let client = bootstrap_http_client(Duration::from_secs(10))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("CDN request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Session(format!(
            "CDN returned status: {}",
            response.status()
        )));
    }

    let body = read_body_capped(response)
        .await
        .map_err(|e| Error::Session(format!("Failed to read CDN response: {}", e)))?;

    parse_descriptors_from_json(&body, Some(signing_key))
}

/// Describe a `reqwest::Error` without ever including its `Display` output,
/// which embeds the request URL — for Telegram Bot API calls, that URL
/// contains the bot token, and this text ends up in `ChannelLoadResult.error`,
/// which callers log.
fn describe_reqwest_error(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "request timed out"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_decode() {
        "failed to decode response body"
    } else {
        "network error"
    }
}

/// Load descriptors from a Telegram bot channel via the authenticated Bot
/// API: getUpdates -> find a message/channel_post carrying a document ->
/// getFile -> download. Mirrors the Android/iOS implementations — the
/// server's actual publish path (`bootstrap_publish.rs`'s `sendDocument`)
/// can only be retrieved this way; an unauthenticated `t.me/...?format=json`
/// scrape cannot see bot-posted documents at all.
async fn load_from_telegram(
    bot_token: &str,
    chat_id: Option<&str>,
    signing_key: &[u8; 32],
) -> Result<Vec<BootstrapDescriptor>> {
    let client = bootstrap_http_client(Duration::from_secs(15))?;

    let updates_url = format!(
        "https://api.telegram.org/bot{}/getUpdates?limit=50",
        bot_token
    );
    // Note: deliberately not formatting the reqwest::Error itself into these
    // messages — its Display output includes the request URL, which embeds
    // the bot token, and this error text flows into ChannelLoadResult.error
    // which gets logged.
    let response = client.get(&updates_url).send().await.map_err(|e| {
        Error::Session(format!(
            "Telegram getUpdates failed: {}",
            describe_reqwest_error(&e)
        ))
    })?;

    if !response.status().is_success() {
        return Err(Error::Session(format!(
            "Telegram getUpdates returned status: {}",
            response.status()
        )));
    }

    let body = read_body_capped(response).await.map_err(|e| {
        Error::Session(format!(
            "Failed to read Telegram getUpdates response: {}",
            e
        ))
    })?;

    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        Error::Session(format!(
            "Failed to parse Telegram getUpdates response: {}",
            e
        ))
    })?;

    let updates = json
        .get("result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| Error::Session("Telegram getUpdates response missing 'result'".into()))?;

    // Walk newest-first, same order the Android client scans in.
    for update in updates.iter().rev() {
        let message = update.get("message").or_else(|| update.get("channel_post"));
        let Some(message) = message else { continue };

        if let Some(want_chat) = chat_id {
            let chat = message.get("chat");
            let id_matches = chat
                .and_then(|c| c.get("id"))
                .map(|id| match id {
                    serde_json::Value::String(s) => s == want_chat,
                    other => other == want_chat,
                })
                .unwrap_or(false);
            let username_matches = chat
                .and_then(|c| c.get("username"))
                .and_then(|u| u.as_str())
                .map(|u| format!("@{u}") == want_chat)
                .unwrap_or(false);
            if !id_matches && !username_matches {
                continue;
            }
        }

        let Some(file_id) = message
            .get("document")
            .and_then(|d| d.get("file_id"))
            .and_then(|f| f.as_str())
        else {
            continue;
        };

        let get_file_url = format!(
            "https://api.telegram.org/bot{}/getFile?file_id={}",
            bot_token, file_id
        );
        let Ok(meta_resp) = client.get(&get_file_url).send().await else {
            continue;
        };
        let Ok(meta_body) = read_body_capped(meta_resp).await else {
            continue;
        };
        let Ok(meta_json) = serde_json::from_str::<serde_json::Value>(&meta_body) else {
            continue;
        };
        let Some(file_path) = meta_json
            .get("result")
            .and_then(|r| r.get("file_path"))
            .and_then(|p| p.as_str())
        else {
            continue;
        };

        let download_url = format!(
            "https://api.telegram.org/file/bot{}/{}",
            bot_token, file_path
        );
        let Ok(file_resp) = client.get(&download_url).send().await else {
            continue;
        };
        let Ok(file_body) = read_body_capped(file_resp).await else {
            continue;
        };

        if let Ok(descriptors) = parse_descriptors_from_json(&file_body, Some(signing_key)) {
            if !descriptors.is_empty() {
                return Ok(descriptors);
            }
        }
    }

    Err(Error::Session(
        "No verifiable bootstrap document found in recent Telegram updates \
         (getUpdates only sees messages since the bot's last poll)"
            .into(),
    ))
}

/// Load descriptors from a GitHub releases channel
async fn load_from_github(
    repo: &str,
    asset_name: &str,
    signing_key: &[u8; 32],
) -> Result<Vec<BootstrapDescriptor>> {
    // The GitHub API URL is constructed from the repo slug, not user input, so
    // it is always a safe HTTPS URL. The asset download URL from the release JSON
    // is user-influenced via the connection key and must be validated.
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo);

    let client = bootstrap_http_client(Duration::from_secs(10))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("GitHub request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Session(format!(
            "GitHub returned status: {}",
            response.status()
        )));
    }

    let body = read_body_capped(response)
        .await
        .map_err(|e| Error::Session(format!("Failed to read GitHub response: {}", e)))?;

    // Parse release JSON to find asset URL
    let release: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| Error::Session(format!("Failed to parse GitHub release: {}", e)))?;

    if let Some(assets) = release.get("assets").and_then(|a| a.as_array()) {
        for asset in assets {
            if let Some(name) = asset.get("name").and_then(|n| n.as_str()) {
                if name.contains(asset_name) || asset_name.contains(name) {
                    if let Some(download_url) =
                        asset.get("browser_download_url").and_then(|u| u.as_str())
                    {
                        // Validate the asset URL before fetching — the download
                        // URL comes from GitHub's API response and must be HTTPS.
                        if let Err(e) = validate_bootstrap_url(download_url) {
                            return Err(Error::Session(format!(
                                "GitHub asset URL rejected: {}",
                                e
                            )));
                        }
                        // Download the asset
                        let asset_response =
                            client.get(download_url).send().await.map_err(|e| {
                                Error::Session(format!("Failed to download asset: {}", e))
                            })?;

                        let asset_body = read_body_capped(asset_response)
                            .await
                            .map_err(|e| Error::Session(format!("Failed to read asset: {}", e)))?;

                        return parse_descriptors_from_json(&asset_body, Some(signing_key));
                    }
                }
            }
        }
    }

    Err(Error::Session(format!(
        "Asset '{}' not found in GitHub release",
        asset_name
    )))
}

/// Читает подписанные дескрипторы из текстовых частей писем через JMAP.
/// URL сессии и токен задаются переменными AIVPN_BOOTSTRAP_JMAP_URL и
/// AIVPN_BOOTSTRAP_JMAP_TOKEN. Письма не отправляются и не изменяются.
async fn load_from_email(
    address: &str,
    subject_pattern: &str,
    signing_key: &[u8; 32],
) -> Result<Vec<BootstrapDescriptor>> {
    use serde_json::json;
    const MAIL: &str = "urn:ietf:params:jmap:mail";
    let session_url = std::env::var("AIVPN_BOOTSTRAP_JMAP_URL")
        .map_err(|_| Error::Session("Email bootstrap requires AIVPN_BOOTSTRAP_JMAP_URL".into()))?;
    let token = std::env::var("AIVPN_BOOTSTRAP_JMAP_TOKEN").map_err(|_| {
        Error::Session("Email bootstrap requires AIVPN_BOOTSTRAP_JMAP_TOKEN".into())
    })?;
    if token.is_empty() || address.is_empty() || subject_pattern.is_empty() {
        return Err(Error::Session(
            "Email bootstrap requires token, sender and subject".into(),
        ));
    }
    validate_bootstrap_url(&session_url)?;
    let client = bootstrap_http_client(Duration::from_secs(10))?;
    let session = jmap_response(client.get(&session_url).bearer_auth(&token)).await?;
    let api_url = session["apiUrl"]
        .as_str()
        .ok_or_else(|| Error::Session("JMAP session has no API URL".into()))?;
    validate_bootstrap_url(api_url)?;
    let origin =
        reqwest::Url::parse(&session_url).map_err(|_| Error::Session("Invalid JMAP URL".into()))?;
    let api =
        reqwest::Url::parse(api_url).map_err(|_| Error::Session("Invalid JMAP API URL".into()))?;
    if origin.origin() != api.origin() {
        return Err(Error::Session(
            "JMAP API must share the configured session origin".into(),
        ));
    }
    let account = session["primaryAccounts"][MAIL]
        .as_str()
        .ok_or_else(|| Error::Session("JMAP session has no primary mail account".into()))?;
    let request = json!({
        "using": ["urn:ietf:params:jmap:core", MAIL],
        "methodCalls": [
            ["Email/query", {"accountId": account,
                "filter": {"from": address, "subject": subject_pattern},
                "sort": [{"property": "receivedAt", "isAscending": false}],
                "limit": 16}, "query"],
            ["Email/get", {"accountId": account,
                "#ids": {"resultOf": "query", "name": "Email/query", "path": "/ids"},
                "properties": ["from", "subject", "textBody", "bodyValues"],
                "fetchTextBodyValues": true, "maxBodyValueBytes": MAX_RESPONSE_BODY_BYTES}, "get"]
        ]
    });
    let response = jmap_response(client.post(api).bearer_auth(&token).json(&request)).await?;
    parse_jmap_descriptors(&response, address, subject_pattern, signing_key)
}

async fn jmap_response(request: reqwest::RequestBuilder) -> Result<serde_json::Value> {
    let response = request.send().await.map_err(|e| {
        Error::Session(format!(
            "JMAP request failed: {}",
            describe_reqwest_error(&e)
        ))
    })?;
    if !response.status().is_success() {
        return Err(Error::Session(format!(
            "JMAP returned status {}",
            response.status()
        )));
    }
    let body = read_body_capped(response)
        .await
        .map_err(|e| Error::Session(e.into()))?;
    serde_json::from_str(&body).map_err(|_| Error::Session("Invalid JMAP response".into()))
}

fn parse_jmap_descriptors(
    response: &serde_json::Value,
    address: &str,
    subject: &str,
    signing_key: &[u8; 32],
) -> Result<Vec<BootstrapDescriptor>> {
    let calls = response["methodResponses"]
        .as_array()
        .ok_or_else(|| Error::Session("JMAP response has no methods".into()))?;
    let messages = calls
        .iter()
        .find(|call| call[0] == "Email/get" && call[2] == "get")
        .and_then(|call| call[1]["list"].as_array())
        .ok_or_else(|| Error::Session("JMAP Email/get failed".into()))?;
    let mut descriptors = Vec::new();
    for message in messages.iter().take(16) {
        let sender_matches = message["from"].as_array().is_some_and(|senders| {
            senders.iter().any(|sender| {
                sender["email"]
                    .as_str()
                    .is_some_and(|email| email.eq_ignore_ascii_case(address))
            })
        });
        if !sender_matches
            || !message["subject"]
                .as_str()
                .is_some_and(|value| value.contains(subject))
        {
            continue;
        }
        if let Some(parts) = message["textBody"].as_array() {
            for part in parts {
                let Some(id) = part["partId"].as_str() else {
                    continue;
                };
                let body = &message["bodyValues"][id];
                if body["isTruncated"].as_bool() == Some(true)
                    || body["isEncodingProblem"].as_bool() == Some(true)
                {
                    continue;
                }
                if let Some(value) = body["value"].as_str() {
                    if value.len() <= MAX_RESPONSE_BODY_BYTES {
                        if let Ok(values) = parse_descriptors_from_json(value, Some(signing_key)) {
                            descriptors.extend(values);
                        }
                    }
                }
            }
        }
    }
    if descriptors.is_empty() {
        return Err(Error::Session(
            "Mailbox contains no valid signed bootstrap descriptors".into(),
        ));
    }
    descriptors.sort_by(|a, b| a.descriptor_id.cmp(&b.descriptor_id));
    descriptors.dedup_by(|a, b| a.descriptor_id == b.descriptor_id);
    Ok(descriptors)
}

/// Parse descriptors from JSON body
fn parse_descriptors_from_json(
    body: &str,
    signing_key: Option<&[u8; 32]>,
) -> Result<Vec<BootstrapDescriptor>> {
    // Try parsing as array first
    let descriptors: Vec<BootstrapDescriptor> = serde_json::from_str(body)
        .or_else(|_| {
            // Try parsing as single object
            let single: BootstrapDescriptor = serde_json::from_str(body)?;
            Ok(vec![single])
        })
        .map_err(|e: serde_json::Error| {
            Error::Session(format!("Failed to parse descriptors: {}", e))
        })?;

    // Verify each descriptor
    let mut valid_descriptors = Vec::new();
    for descriptor in descriptors {
        if store_verified_descriptor(descriptor.clone(), signing_key).is_ok() {
            valid_descriptors.push(descriptor);
        }
    }
    if valid_descriptors.is_empty() {
        return Err(Error::Session("No verified bootstrap descriptors".into()));
    }
    Ok(valid_descriptors)
}

/// Load descriptors from a single channel
async fn load_from_channel(
    channel: &BootstrapChannel,
    signing_key: Option<&[u8; 32]>,
) -> ChannelLoadResult {
    let start = std::time::Instant::now();

    let Some(signing_key) = signing_key else {
        return ChannelLoadResult {
            channel_name: channel.name().to_string(),
            channel_type: channel.channel_type().to_string(),
            success: false,
            descriptors_loaded: 0,
            error: Some("Network bootstrap requires a trusted signing key".into()),
            latency_ms: 0,
        };
    };
    let result = match channel {
        BootstrapChannel::CDN { url, provider: _ } => load_from_cdn(url, signing_key).await,
        BootstrapChannel::Telegram { bot_token, chat_id } => {
            load_from_telegram(bot_token, chat_id.as_deref(), signing_key).await
        }
        BootstrapChannel::GitHub { repo, asset_name } => {
            load_from_github(repo, asset_name, signing_key).await
        }
        BootstrapChannel::Email {
            address,
            subject_pattern,
        } => load_from_email(address, subject_pattern, signing_key).await,
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(descriptors) => ChannelLoadResult {
            channel_name: channel.name().to_string(),
            channel_type: channel.channel_type().to_string(),
            success: true,
            descriptors_loaded: descriptors.len(),
            error: None,
            latency_ms,
        },
        Err(e) => ChannelLoadResult {
            channel_name: channel.name().to_string(),
            channel_type: channel.channel_type().to_string(),
            success: false,
            descriptors_loaded: 0,
            error: Some(e.to_string()),
            latency_ms,
        },
    }
}

/// Load descriptors from all channels with random order
pub async fn load_multi_channel(config: &BootstrapConfig) -> MultiChannelLoadStats {
    let start = std::time::Instant::now();

    // Randomize channel order to prevent pattern detection
    let mut channels: Vec<_> = config.channels.iter().collect();
    let mut rng = rand::thread_rng();
    channels.shuffle(&mut rng);

    // Race all channels concurrently — sequential probing with 10–15 s timeouts
    // per channel could block startup for up to N×15 s when most channels are
    // unreachable. Channels are cloned so each task owns its data ('static bound).
    let tasks: Vec<_> = channels
        .iter()
        .map(|ch| {
            let ch = (*ch).clone();
            let signing_key = config.trusted_signing_key;
            tokio::spawn(async move { load_from_channel(&ch, signing_key.as_ref()).await })
        })
        .collect();

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        let r = task.await.unwrap_or_else(|e| ChannelLoadResult {
            channel_name: "unknown".into(),
            channel_type: "unknown".into(),
            success: false,
            descriptors_loaded: 0,
            error: Some(format!("task panicked: {e}")),
            latency_ms: 0,
        });
        results.push(r);
    }

    let mut total_descriptors = 0;
    for r in &results {
        total_descriptors += r.descriptors_loaded;
    }

    let successful_channels = results.iter().filter(|r| r.success).count();
    let elapsed_ms = start.elapsed().as_millis() as u64;

    MultiChannelLoadStats {
        total_channels: results.len(),
        successful_channels,
        total_descriptors,
        results,
        elapsed_ms,
    }
}

/// Check if we have valid descriptors in cache
pub fn has_valid_descriptors() -> bool {
    !load_descriptors().is_empty()
}

/// Get random delay for first refresh (1-60 seconds)
pub fn random_first_refresh_delay() -> Duration {
    let mut rng = rand::thread_rng();
    Duration::from_secs(rng.gen_range(1..=60))
}

/// Background descriptor refresher
pub struct BackgroundRefresher {
    config: BootstrapConfig,
}

impl BackgroundRefresher {
    pub fn new(config: BootstrapConfig) -> Self {
        Self { config }
    }

    /// Run the background refresher loop
    pub async fn run(&self) {
        // Random delay before first refresh
        if self.config.randomize_first_refresh {
            let delay = random_first_refresh_delay();
            tokio::time::sleep(delay).await;
        }

        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.refresh_interval.max(1)));

        let mut last_refresh = std::time::Instant::now()
            .checked_sub(Duration::from_secs(self.config.refresh_interval.max(1)))
            .unwrap_or_else(std::time::Instant::now);

        loop {
            interval.tick().await;

            // Always refresh when interval has elapsed, even if descriptors are valid.
            // This ensures descriptors are rotated before expiry (24h grace window
            // means has_valid_descriptors() stays true long after actual expiry).
            let elapsed = last_refresh.elapsed();
            if has_valid_descriptors()
                && elapsed < Duration::from_secs(self.config.refresh_interval.max(1))
            {
                continue;
            }

            last_refresh = std::time::Instant::now();

            // Load from multiple channels
            let stats = load_multi_channel(&self.config).await;

            tracing::info!(
                "Bootstrap refresh: {}/{} channels succeeded, {} descriptors loaded in {}ms",
                stats.successful_channels,
                stats.total_channels,
                stats.total_descriptors,
                stats.elapsed_ms
            );
        }
    }
}

/// Загружает публичный HTTPS-ресурс с проверкой каждого адреса и лимитом размера.
pub async fn fetch_public_bytes(url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    validate_bootstrap_url(url)?;
    let mut response = bootstrap_http_client(Duration::from_secs(15))?
        .get(url)
        .send()
        .await
        .map_err(|_| Error::Session("Public download failed".into()))?;
    if !response.status().is_success() {
        return Err(Error::Session("Public download HTTP error".into()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes as u64)
    {
        return Err(Error::Session("Public download exceeds byte limit".into()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::Session("Public download interrupted".into()))?
    {
        if chunk.len() > max_bytes.saturating_sub(body.len()) {
            return Err(Error::Session("Public download exceeds byte limit".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_bootstrap_checks_sender_subject_signature_and_complete_body() {
        use ed25519_dalek::Signer;
        use serde_json::json;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let mut descriptor = BootstrapDescriptor {
            descriptor_id: "mail-test".into(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            base_mask_ids: vec![],
            embedded_masks: vec![],
            candidate_count: 1,
            kdf_salt: [0; 32],
            signature: [0; 64],
        };
        descriptor.signature = key.sign(&descriptor.signing_bytes()).to_bytes();
        let response = json!({"methodResponses": [["Email/get", {"list": [{
            "from": [{"email": "bootstrap@example.com"}], "subject": "AIVPN descriptors",
            "textBody": [{"partId": "1"}], "bodyValues": {"1": {
                "value": serde_json::to_string(&descriptor).unwrap(),
                "isTruncated": false, "isEncodingProblem": false
            }}
        }]}, "get"]]});
        let public = key.verifying_key().to_bytes();
        assert_eq!(
            parse_jmap_descriptors(&response, "bootstrap@example.com", "AIVPN", &public)
                .unwrap()
                .len(),
            1
        );
        assert!(parse_jmap_descriptors(&response, "other@example.com", "AIVPN", &public).is_err());
        assert!(
            parse_jmap_descriptors(&response, "bootstrap@example.com", "other", &public).is_err()
        );
        let other = ed25519_dalek::SigningKey::from_bytes(&[24; 32])
            .verifying_key()
            .to_bytes();
        assert!(
            parse_jmap_descriptors(&response, "bootstrap@example.com", "AIVPN", &other).is_err()
        );
        let mut truncated = response;
        truncated["methodResponses"][0][1]["list"][0]["bodyValues"]["1"]["isTruncated"] =
            json!(true);
        assert!(
            parse_jmap_descriptors(&truncated, "bootstrap@example.com", "AIVPN", &public).is_err()
        );
    }

    #[test]
    fn bootstrap_dns_rejects_private_and_mixed_answers() {
        for answers in [
            vec![],
            vec!["127.0.0.1:443"],
            vec!["1.1.1.1:443", "10.0.0.1:443"],
            vec!["[::ffff:192.168.1.1]:443"],
        ] {
            assert!(
                public_bootstrap_addrs(answers.into_iter().map(|s| s.parse().unwrap())).is_err()
            );
        }
        assert!(public_bootstrap_addrs(
            ["1.1.1.1:443", "[2606:4700:4700::1111]:443"]
                .into_iter()
                .map(|s| s.parse().unwrap())
        )
        .is_ok());
    }

    #[tokio::test]
    async fn network_channels_require_a_trusted_signing_key() {
        let config = BootstrapConfig::default().with_cdn("https://example.com/", "test");
        let stats = load_multi_channel(&config).await;
        assert_eq!(stats.successful_channels, 0);
        assert_eq!(stats.total_descriptors, 0);
        assert!(stats.results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("trusted signing key"));
    }

    #[test]
    fn network_descriptors_reject_forged_signatures() {
        let descriptor = BootstrapDescriptor {
            descriptor_id: "forged".into(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            base_mask_ids: vec![],
            embedded_masks: vec![],
            candidate_count: 1,
            kdf_salt: [0; 32],
            signature: [0; 64],
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes();
        assert!(parse_descriptors_from_json(
            &serde_json::to_string(&descriptor).unwrap(),
            Some(&key)
        )
        .is_err());
    }

    #[test]
    fn bootstrap_url_rejects_non_public_canonical_addresses() {
        for url in [
            "https://127.1/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://LOCALHOST/",
            "https://localhost./",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[fc00::1]/",
            "https://[fe80::1]/",
            "https://0.0.0.0/",
            "https://100.64.0.1/",
            "https://224.0.0.1/",
            "https://user:password@example.com/",
        ] {
            assert!(validate_bootstrap_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn test_bootstrap_channel_names() {
        let cdn = BootstrapChannel::CDN {
            url: "https://cdn.example.com/descriptors".to_string(),
            provider: "Cloudflare".to_string(),
        };
        assert_eq!(cdn.name(), "Cloudflare");
        assert_eq!(cdn.channel_type(), "CDN");

        let telegram = BootstrapChannel::Telegram {
            bot_token: "123456:ABC-DEF".to_string(),
            chat_id: Some("@aivpn_bot".to_string()),
        };
        assert_eq!(telegram.name(), "@aivpn_bot");
        assert_eq!(telegram.channel_type(), "Telegram");
    }

    #[test]
    fn test_bootstrap_config_builder() {
        let config = BootstrapConfig::default()
            .with_cdn("https://cdn.example.com", "Cloudflare")
            .with_telegram("123456:ABC-DEF", Some("@aivpn_bot".to_string()))
            .with_github("infosave2007/aivpn", "bootstrap-");

        assert_eq!(config.channels.len(), 3);
        assert_eq!(config.channels[0].channel_type(), "CDN");
        assert_eq!(config.channels[1].channel_type(), "Telegram");
        assert_eq!(config.channels[2].channel_type(), "GitHub");
    }

    #[test]
    fn test_validate_bootstrap_url_accepts_https() {
        assert!(validate_bootstrap_url("https://cdn.example.com/descriptors.json").is_ok());
        assert!(validate_bootstrap_url("https://cdn.example.com:8443/path").is_ok());
        assert!(validate_bootstrap_url("https://example.org").is_ok());
        assert!(validate_bootstrap_url("https://192.0.1.10/").is_ok());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_http() {
        let err = validate_bootstrap_url("http://cdn.example.com/descriptors.json");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_custom_scheme() {
        assert!(validate_bootstrap_url("ftp://cdn.example.com/file").is_err());
        assert!(validate_bootstrap_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_localhost() {
        assert!(validate_bootstrap_url("https://localhost/descriptors").is_err());
        assert!(validate_bootstrap_url("https://127.0.0.1/descriptors").is_err());
        assert!(validate_bootstrap_url("https://127.0.0.5:8080/path").is_err());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_private_ranges() {
        assert!(validate_bootstrap_url("https://10.0.0.1/descriptors").is_err());
        assert!(validate_bootstrap_url("https://192.168.1.100/descriptors").is_err());
        assert!(validate_bootstrap_url("https://172.16.0.1/descriptors").is_err());
        assert!(validate_bootstrap_url("https://172.31.255.255/descriptors").is_err());
        // 172.32.x.x is outside the /12 block — must be accepted
        assert!(validate_bootstrap_url("https://172.32.0.1/descriptors").is_ok());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_link_local() {
        assert!(validate_bootstrap_url("https://169.254.1.1/descriptors").is_err());
    }

    #[test]
    fn test_parse_descriptors_from_json_single_object() {
        // Одиночный подписанный объект принимается так же, как массив.
        let _guard = crate::TEST_HOME_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = std::env::temp_dir().join("aivpn_parse_test");
        let _ = std::fs::create_dir_all(&temp);
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &temp);

        let desc_json = r#"{
            "descriptor_id": "parse_single_test",
            "version": 1,
            "created_at": 0,
            "expires_at": 9999999999,
            "base_mask_ids": [],
            "embedded_masks": [],
            "candidate_count": 1,
            "kdf_salt": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }"#;

        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let mut descriptor: BootstrapDescriptor = serde_json::from_str(desc_json).unwrap();
        descriptor.signature = key.sign(&descriptor.signing_bytes()).to_bytes();
        let signed_json = serde_json::to_string(&descriptor).unwrap();
        let result =
            parse_descriptors_from_json(&signed_json, Some(&key.verifying_key().to_bytes()));
        assert!(result.is_ok());
        let descs = result.unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].descriptor_id, "parse_single_test");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn test_parse_descriptors_from_json_invalid() {
        let result = parse_descriptors_from_json("not valid json at all !!!!", None);
        assert!(result.is_err());
    }
}
