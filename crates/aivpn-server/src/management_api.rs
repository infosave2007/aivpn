//! Management HTTP API over Unix socket.
//!
//! Enabled via `--features management-api`. Binds to a Unix domain socket
//! (default `/run/aivpn/api.sock`) and exposes a REST API for managing clients,
//! config, masks, backups, and server state.
//!
//! Unix-only: Unix domain sockets are not available on Windows.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt as _;
use tower::util::ServiceExt;

use crate::audit_log::{AuditActor, AuditLogger};
use crate::client_db::{ClientDatabase, ClientStats, UpdateClientParams};

// ── Config passed by main ────────────────────────────────────────────────────

/// Configuration bundle for `serve()`.
/// Avoids an ever-growing positional argument list.
pub struct ServeConfig {
    pub db: Option<Arc<ClientDatabase>>,
    pub socket_path: Option<String>,
    pub server_pub_key: Option<[u8; 32]>,
    pub server_addr: Option<String>,
    /// Ed25519 signing (verifying) public key, emitted as the `sk` field of
    /// API-issued connection keys — same value the CLI embeds, so
    /// panel-provisioned clients can verify signed server messages too.
    pub server_signing_pubkey: Option<[u8; 32]>,
    /// Path to the server.json config file (for live read/write).
    pub config_path: Option<PathBuf>,
    /// Path to clients.json (for backup export).
    pub clients_db_path: Option<PathBuf>,
    /// Directory containing mask JSON profiles.
    pub mask_dir: PathBuf,
    /// Path to the append-only audit log (for `GET /api/v1/audit-log`).
    pub audit_log_path: Option<PathBuf>,
    /// Live audit logger — API mutations are recorded with `AuditActor::Api`.
    pub audit_log: Option<AuditLogger>,
    /// Live bootstrap descriptors, shared with the gateway's rotation task.
    /// `None` if bootstrap descriptors weren't initialized (should not
    /// normally happen — `Gateway::new()` always builds them).
    pub bootstrap_descriptors:
        Option<Arc<parking_lot::RwLock<Vec<aivpn_common::mask::BootstrapDescriptor>>>>,
    /// Operator mask verifying key + verification mode, applied to masks
    /// uploaded via `POST /api/v1/masks` (mirrors mask_store's disk-load
    /// policy so the API can't be used to smuggle unverified profiles past
    /// `mask_verify_mode=enforce`).
    pub mask_operator_pubkey: Option<[u8; 32]>,
    pub mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    /// Live metrics collector, for enriching the `/api/v1/events` SSE
    /// `state` payload with sessions/bandwidth/latency/rotation data for the
    /// web panel's live dashboard graphs. Only present when the server
    /// binary was built with `--features metrics`; the field itself only
    /// exists in that build (see `#[cfg]` below) so a `metrics`-less build
    /// of `management-api` never needs to know about `MetricsCollector`.
    #[cfg(feature = "metrics")]
    pub metrics: Option<Arc<crate::metrics::MetricsCollector>>,
}

// ── Shared handler state ─────────────────────────────────────────────────────

#[derive(Clone)]
struct ApiState {
    db: Arc<ClientDatabase>,
    started_at: Instant,
    server_pub_key: Option<[u8; 32]>,
    server_addr: Option<String>,
    server_signing_pubkey: Option<[u8; 32]>,
    config_path: Option<PathBuf>,
    clients_db_path: Option<PathBuf>,
    mask_dir: PathBuf,
    audit_log_path: Option<PathBuf>,
    audit_log: Option<AuditLogger>,
    bootstrap_descriptors:
        Option<Arc<parking_lot::RwLock<Vec<aivpn_common::mask::BootstrapDescriptor>>>>,
    mask_operator_pubkey: Option<[u8; 32]>,
    mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<crate::metrics::MetricsCollector>>,
}

// ── Wire types ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ClientResponse {
    id: String,
    name: String,
    vpn_ip: String,
    enabled: bool,
    one_time: bool,
    device_bound: bool,
    created_at: DateTime<Utc>,
    stats: ClientStats,
    qos: Option<crate::qos::ClientQos>,
    expires_at: Option<DateTime<Utc>>,
}

impl From<crate::client_db::ClientConfig> for ClientResponse {
    fn from(c: crate::client_db::ClientConfig) -> Self {
        Self {
            device_bound: c.device_pubkey.is_some(),
            id: c.id,
            name: c.name,
            vpn_ip: c.vpn_ip.to_string(),
            enabled: c.enabled,
            one_time: c.one_time,
            created_at: c.created_at,
            stats: c.stats,
            qos: c.qos,
            expires_at: c.expires_at,
        }
    }
}

#[derive(Deserialize)]
struct AddClientRequest {
    name: String,
    #[serde(default)]
    one_time: bool,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct PatchClientRequest {
    name: Option<String>,
    enabled: Option<bool>,
    one_time: Option<bool>,
    /// Pass `null` in JSON to clear QoS; omit the field to leave it unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    qos: Option<Option<crate::qos::ClientQos>>,
    /// Pass `null` to clear expiry; omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    expires_at: Option<Option<DateTime<Utc>>>,
}

/// Deserialises a field that can be absent (don't touch), null (clear), or a value (set).
fn deserialize_opt_opt<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(de)?))
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    uptime_secs: u64,
    clients_total: usize,
    clients_enabled: usize,
    kernel_module: bool,
}

#[derive(Serialize)]
struct MaskInfo {
    id: String,
    file: String,
    size_bytes: u64,
    modified: Option<DateTime<Utc>>,
    /// True when the mask was auto-generated by mask_gen from a recording
    /// (read from the profile's `generated` flag). Lets the panel mark it "(авто)".
    generated: bool,
}

#[derive(Deserialize)]
struct SetActiveMaskRequest {
    client: String,
    mask: String,
}

#[derive(Serialize)]
struct KernelResponse {
    loaded: bool,
    device: &'static str,
}

#[derive(Deserialize, Default)]
struct AuditLogQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
}
fn default_audit_limit() -> usize {
    200
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn err(msg: impl ToString) -> Json<ErrorResponse> {
    Json(ErrorResponse {
        error: msg.to_string(),
    })
}

fn kernel_loaded() -> bool {
    std::path::Path::new("/dev/aivpn").exists()
}

/// Audit-log a mutating API action (no-op when no logger was wired up,
/// e.g. in unit tests).
fn audit(state: &ApiState, action: &str, target: &str, result: &str) {
    if let Some(ref log) = state.audit_log {
        log.log(AuditActor::Api, action, target, result);
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn get_status(State(state): State<ApiState>) -> impl IntoResponse {
    let clients = state.db.list_clients();
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        clients_total: clients.len(),
        clients_enabled: clients.iter().filter(|c| c.enabled).count(),
        kernel_module: kernel_loaded(),
    })
}

async fn list_clients(State(state): State<ApiState>) -> impl IntoResponse {
    let clients: Vec<ClientResponse> = state
        .db
        .list_clients()
        .into_iter()
        .map(Into::into)
        .collect();
    Json(clients)
}

async fn add_client(
    State(state): State<ApiState>,
    Json(body): Json<AddClientRequest>,
) -> impl IntoResponse {
    if body.name.is_empty() || body.name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name must be 1–64 characters"})),
        )
            .into_response();
    }
    let db = state.db.clone();
    let name = body.name.clone();
    let one_time = body.one_time;
    let expires_at = body.expires_at;
    let result = tokio::task::spawn_blocking(move || {
        let client = if one_time {
            db.add_client_one_time(&name)?
        } else {
            db.add_client(&name)?
        };
        if expires_at.is_some() {
            db.update_client(
                &client.id,
                UpdateClientParams {
                    expires_at: Some(expires_at),
                    ..Default::default()
                },
            )
        } else {
            Ok(client)
        }
    })
    .await;
    match result {
        Ok(Ok(c)) => {
            audit(&state, "ClientAdd", &format!("{} ({})", c.name, c.id), "ok");
            (StatusCode::CREATED, Json(ClientResponse::from(c))).into_response()
        }
        Ok(Err(e)) => {
            audit(&state, "ClientAdd", &body.name, &format!("failed: {}", e));
            (StatusCode::CONFLICT, err(e)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn get_client(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    match state.db.find_by_id(&id) {
        Some(c) => Json(ClientResponse::from(c)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            err(format!("Client '{}' not found", id)),
        )
            .into_response(),
    }
}

async fn patch_client(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<PatchClientRequest>,
) -> impl IntoResponse {
    if let Some(ref name) = body.name {
        if name.is_empty() || name.len() > 64 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "name must be 1–64 characters"})),
            )
                .into_response();
        }
    }
    let db = state.db.clone();
    let params = UpdateClientParams {
        name: body.name,
        enabled: body.enabled,
        one_time: body.one_time,
        qos: body.qos,
        expires_at: body.expires_at,
    };
    let id_for_log = id.clone();
    match tokio::task::spawn_blocking(move || db.update_client(&id, params)).await {
        Ok(Ok(c)) => {
            audit(&state, "ClientPatch", &id_for_log, "ok");
            Json(ClientResponse::from(c)).into_response()
        }
        Ok(Err(e)) => {
            audit(
                &state,
                "ClientPatch",
                &id_for_log,
                &format!("failed: {}", e),
            );
            let status = if e.to_string().contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            };
            (status, err(e)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn remove_client(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    let db = state.db.clone();
    let id_for_log = id.clone();
    match tokio::task::spawn_blocking(move || db.remove_client(&id)).await {
        Ok(Ok(())) => {
            audit(&state, "ClientRemove", &id_for_log, "ok");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => {
            audit(
                &state,
                "ClientRemove",
                &id_for_log,
                &format!("failed: {}", e),
            );
            (StatusCode::NOT_FOUND, err(e)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn reset_device(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    let db = state.db.clone();
    let id_for_log = id.clone();
    match tokio::task::spawn_blocking(move || db.reset_device_binding(&id)).await {
        Ok(Ok(())) => {
            audit(&state, "DeviceReset", &id_for_log, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Ok(Err(e)) => {
            audit(
                &state,
                "DeviceReset",
                &id_for_log,
                &format!("failed: {}", e),
            );
            (StatusCode::NOT_FOUND, err(e)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn reload(State(state): State<ApiState>) -> impl IntoResponse {
    let db = state.db.clone();
    match tokio::task::spawn_blocking(move || db.reload_if_changed()).await {
        Ok(changed) => Json(serde_json::json!({ "reloaded": changed })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn get_connection_key(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let (pub_key, server_addr) = match (&state.server_pub_key, &state.server_addr) {
        (Some(k), Some(a)) => (k, a.as_str()),
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                err("--server-ip or --key-file not configured; cannot build connection key"),
            )
                .into_response()
        }
    };
    let client = match state.db.find_by_id(&id) {
        Some(c) => c,
        None => {
            return (
                StatusCode::NOT_FOUND,
                err(format!("Client '{}' not found", id)),
            )
                .into_response()
        }
    };
    let client_net_cfg = match state.db.network_config().client_config(client.vpn_ip) {
        Ok(cfg) => cfg,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err(e)).into_response(),
    };
    use base64::Engine;
    let psk_b64 = base64::engine::general_purpose::STANDARD.encode(&client.psk);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_key);
    let mut json = serde_json::json!({
        "s": server_addr, "k": pub_b64, "p": psk_b64,
        "i": client_net_cfg.client_ip, "n": client_net_cfg,
    });
    // Parity with the CLI's `build_connection_key`: embed the server's
    // ed25519 signing pubkey (`sk`) and the operator mask-verifying pubkey
    // (`mop`) so panel-provisioned clients can verify signed server messages
    // and pushed masks out of the box, exactly like CLI-provisioned ones.
    if let Some(sk) = &state.server_signing_pubkey {
        json["sk"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(sk));
    }
    if let Some(mop) = &state.mask_operator_pubkey {
        json["mop"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(mop));
    }
    let json_str = match serde_json::to_string(&json) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("connection key serialization error: {}", e)),
            )
                .into_response()
        }
    };
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_str.as_bytes());
    Json(serde_json::json!({ "connection_key": format!("aivpn://{}", encoded) })).into_response()
}

// ── Config ───────────────────────────────────────────────────────────────────

async fn get_config(State(state): State<ApiState>) -> impl IntoResponse {
    let path = match &state.config_path {
        Some(p) => p.clone(),
        None => return (StatusCode::NOT_FOUND, err("config path not configured")).into_response(),
    };
    match tokio::task::spawn_blocking(move || std::fs::read_to_string(&path)).await {
        Ok(Ok(content)) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(v) => Json(v).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("config parse error: {}", e)),
            )
                .into_response(),
        },
        Ok(Err(e)) => (
            StatusCode::NOT_FOUND,
            err(format!("config not found: {}", e)),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn put_config(
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let path = match &state.config_path {
        Some(p) => p.clone(),
        None => return (StatusCode::NOT_FOUND, err("config path not configured")).into_response(),
    };
    // Structural validation: config must be a JSON object (not array, string, etc.)
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            err("invalid config: must be a JSON object"),
        )
            .into_response();
    }
    // Type-level validation: the body must deserialize into the SAME
    // `ServerFileConfig` the server parses at startup (deny_unknown_fields
    // catches typo'd keys). A key-name allowlist used to live here; it
    // drifted out of sync with the real schema and either 400'd valid
    // configs or accepted wrong-typed values that bricked the next server
    // start (`load_server_file_config` exits on parse failure).
    if let Err(e) = serde_json::from_value::<crate::server_config::ServerFileConfig>(body.clone()) {
        audit(
            &state,
            "ConfigPut",
            &path.display().to_string(),
            &format!("rejected: {}", e),
        );
        return (
            StatusCode::BAD_REQUEST,
            err(format!("invalid config: {}", e)),
        )
            .into_response();
    }
    let content = match serde_json::to_string_pretty(&body) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, err(format!("invalid JSON: {}", e))).into_response()
        }
    };
    let db = state.db.clone();
    let path_for_log = path.display().to_string();
    match tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &content)?;
        std::fs::rename(&tmp, &path)?;
        db.reload_if_changed();
        Ok(())
    })
    .await
    {
        Ok(Ok(())) => {
            audit(&state, "ConfigPut", &path_for_log, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Ok(Err(e)) => {
            audit(
                &state,
                "ConfigPut",
                &path_for_log,
                &format!("write failed: {}", e),
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("write failed: {}", e)),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

// ── Masks ────────────────────────────────────────────────────────────────────

async fn list_masks(State(state): State<ApiState>) -> impl IntoResponse {
    let mask_dir = state.mask_dir.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<MaskInfo>, std::io::Error> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&mask_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let meta = entry.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta.and_then(|m| m.modified().ok()).and_then(|t| {
                let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
                DateTime::from_timestamp(secs as i64, 0)
            });
            let file = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            // Cheaply read just the `generated` flag from the profile JSON so
            // the panel can mark auto-generated masks — avoids deserializing the
            // full MaskProfile.
            let generated = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v.get("generated").and_then(|g| g.as_bool()))
                .unwrap_or(false);
            entries.push(MaskInfo {
                id,
                file,
                size_bytes: size,
                modified,
                generated,
            });
        }
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    })
    .await;

    match result {
        Ok(Ok(masks)) => Json(masks).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            err(format!("mask dir read error: {}", e)),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

async fn upload_mask(
    State(state): State<ApiState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let name = match params.get("name") {
        Some(n) => n.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, err("query param 'name' required")).into_response()
        }
    };
    // Only allow safe filename characters to prevent path traversal
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            err("name must be 1–64 alphanumeric/dash/underscore chars"),
        )
            .into_response();
    }
    if body.len() > 5 * 1024 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            err("mask file exceeds 5 MB limit"),
        )
            .into_response();
    }
    // Must deserialize as an actual MaskProfile — plain `Value` validation
    // accepted any JSON with {"ok":true} and the file was then silently
    // skipped at load time (misleading operator feedback).
    let profile = match serde_json::from_slice::<aivpn_common::mask::MaskProfile>(&body) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                err(format!("not a valid mask profile: {}", e)),
            )
                .into_response()
        }
    };
    // Config-gated operator signature verification, mirroring mask_store's
    // disk-load policy: enforce → reject, warn → accept with a warning.
    let verdict = aivpn_common::mask::verify_mask_artifact(
        &profile,
        state.mask_operator_pubkey.as_ref(),
        state.mask_verify_mode,
    );
    if !verdict.accept {
        return (
            StatusCode::BAD_REQUEST,
            err(format!(
                "mask signature verification failed (mask_verify_mode=enforce): {:?}",
                verdict.detail
            )),
        )
            .into_response();
    }
    if verdict.is_failure() && state.mask_operator_pubkey.is_some() {
        tracing::warn!(
            "Uploaded mask '{}' failed operator signature verification ({:?}) — \
             accepted because mask_verify_mode=warn",
            name,
            verdict.detail
        );
    }
    let mask_path = state.mask_dir.join(format!("{}.json", name));
    match tokio::fs::write(&mask_path, &body).await {
        Ok(()) => {
            audit(&state, "MaskUpload", &name, "ok");
            Json(serde_json::json!({ "ok": true, "file": format!("{}.json", name) }))
                .into_response()
        }
        Err(e) => {
            audit(&state, "MaskUpload", &name, &format!("write error: {}", e));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("write error: {}", e)),
            )
                .into_response()
        }
    }
}

async fn delete_mask(State(state): State<ApiState>, Path(name): Path<String>) -> impl IntoResponse {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (StatusCode::BAD_REQUEST, err("invalid mask name")).into_response();
    }
    let mask_path = state.mask_dir.join(format!("{}.json", name));
    match tokio::fs::remove_file(&mask_path).await {
        Ok(()) => {
            audit(&state, "MaskDelete", &name, "ok");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            err(format!("mask '{}' not found", name)),
        )
            .into_response(),
        Err(e) => {
            audit(&state, "MaskDelete", &name, &format!("delete error: {}", e));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("delete error: {}", e)),
            )
                .into_response()
        }
    }
}

async fn set_active_mask(
    State(state): State<ApiState>,
    Json(body): Json<SetActiveMaskRequest>,
) -> impl IntoResponse {
    if body.client.is_empty() || body.mask.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            err("fields 'client' and 'mask' are required"),
        )
            .into_response();
    }
    if !body
        .mask
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (StatusCode::BAD_REQUEST, err("invalid mask name")).into_response();
    }

    // Resolve client → id
    let client = state
        .db
        .find_by_name(&body.client)
        .or_else(|| state.db.find_by_id(&body.client));
    let client_id = match client {
        Some(c) => c.id,
        None => {
            return (
                StatusCode::NOT_FOUND,
                err(format!("client '{}' not found", body.client)),
            )
                .into_response()
        }
    };

    // Validate mask exists on disk or is a built-in preset (mirrors --set-mask CLI logic)
    let mask_path = state.mask_dir.join(format!("{}.json", body.mask));
    let on_disk = mask_path.exists();
    let is_preset = aivpn_common::mask::preset_masks::by_id(&body.mask).is_some();
    if !on_disk && !is_preset {
        return (
            StatusCode::NOT_FOUND,
            err(format!(
                "mask '{}' not found in mask directory or built-in presets",
                body.mask
            )),
        )
            .into_response();
    }

    // Write override file: <mask_dir>/.overrides/<client-id>.mask
    let overrides_dir = state.mask_dir.join(".overrides");
    match tokio::fs::create_dir_all(&overrides_dir).await {
        Ok(()) => {}
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                err(format!("cannot create overrides dir: {}", e)),
            )
                .into_response()
        }
    }
    let override_path = overrides_dir.join(format!("{}.mask", client_id));
    match tokio::fs::write(&override_path, body.mask.as_bytes()).await {
        Ok(()) => {
            audit(
                &state,
                "MaskSetActive",
                &format!("{} → {}", client_id, body.mask),
                "ok",
            );
            Json(serde_json::json!({ "ok": true, "client": body.client, "mask": body.mask }))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            err(format!("write error: {}", e)),
        )
            .into_response(),
    }
}

// ── Backup ───────────────────────────────────────────────────────────────────

async fn export_backup(State(state): State<ApiState>) -> impl IntoResponse {
    use crate::backup::{export_server, ExportOptions};
    let mask_dir = state.mask_dir.clone();
    let clients_db_path = state.clients_db_path.clone();
    let config_path = state.config_path.clone();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        // server-sec HIGH5: a predictable /tmp path with default perms lets
        // any local user race to read (or pre-create/symlink) the backup —
        // which contains every client's plaintext PSK. Use an unpredictable
        // name and create it 0600 up front (before `export_server` ever
        // writes to it) rather than chmod-ing after the fact.
        let mut suffix = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let tmp = std::env::temp_dir().join(format!("aivpn-backup-{}.tar.gz", hex::encode(suffix)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
        }
        let opts = ExportOptions {
            include_clients: true,
            include_masks: true,
            include_config: true,
            config_path,
            mask_dir: Some(mask_dir),
            clients_db: clients_db_path,
        };
        export_server(&opts, &tmp)?;
        let data = std::fs::read(&tmp)?;
        let _ = std::fs::remove_file(&tmp);
        Ok(data)
    })
    .await;

    match result {
        Ok(Ok(data)) => (
            [
                (header::CONTENT_TYPE, "application/gzip"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"aivpn-backup.tar.gz\"",
                ),
            ],
            data,
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            err(format!("backup failed: {}", e)),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

/// Current signed bootstrap descriptors (previous/current/next epoch), same
/// JSON-array shape as `--export-bootstrap-descriptor` and what
/// already-connected clients receive — for an operator to publish manually,
/// or for future web-panel tooling. Admin-only in the web-panel proxy layer
/// (see `VIEWER_BLOCKED_PATHS`), matching the treatment already given to
/// `/config` and `/backup/*`.
async fn export_bootstrap(State(state): State<ApiState>) -> impl IntoResponse {
    match &state.bootstrap_descriptors {
        Some(lock) => Json(lock.read().clone()).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            err("bootstrap descriptors not available"),
        )
            .into_response(),
    }
}

async fn import_backup(State(state): State<ApiState>, body: Bytes) -> impl IntoResponse {
    use crate::backup::import_server;
    const MAX_BACKUP_SIZE: usize = 50 * 1024 * 1024; // 50 MB
    if body.len() > MAX_BACKUP_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "backup too large (max 50 MB)"})),
        )
            .into_response();
    }
    let target_dir = match state.config_path.as_ref().and_then(|p| p.parent()) {
        Some(d) => d.to_path_buf(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                err("config path not configured"),
            )
                .into_response()
        }
    };

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        // server-sec HIGH5: unpredictable name + created 0600 up front (the
        // uploaded archive contains plaintext PSKs until it is fully
        // validated and either imported or discarded) instead of a
        // predictable timestamp path with default perms.
        let mut suffix = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let tmp = std::env::temp_dir().join(format!("aivpn-import-{}.tar.gz", hex::encode(suffix)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
        }
        std::fs::write(&tmp, &body)?;
        let r = import_server(&tmp, &target_dir, false);
        let _ = std::fs::remove_file(&tmp);
        Ok(r?)
    })
    .await;

    match result {
        Ok(Ok(())) => {
            audit(&state, "BackupImport", "server backup", "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Ok(Err(e)) => {
            audit(
                &state,
                "BackupImport",
                "server backup",
                &format!("failed: {}", e),
            );
            (
                StatusCode::BAD_REQUEST,
                err(format!("import failed: {}", e)),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

// ── Audit log ────────────────────────────────────────────────────────────────

async fn get_audit_log(
    State(state): State<ApiState>,
    Query(q): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let log_path = match &state.audit_log_path {
        Some(p) => p.clone(),
        None => return (StatusCode::NOT_FOUND, err("audit log not configured")).into_response(),
    };
    let limit = q.limit.min(1000);
    let result = tokio::task::spawn_blocking(
        move || -> Result<Vec<crate::audit_log::AuditEntry>, std::io::Error> {
            use std::io::{Read as _, Seek, SeekFrom};
            // Bounded tail read: the log grows without rotation guarantees,
            // so never buffer the whole file — read at most enough bytes from
            // the end to cover `limit` entries (~1 KiB/entry is generous; the
            // typical entry is ~150 bytes), capped at 4 MiB.
            let mut file = std::fs::File::open(&log_path)?;
            let file_len = file.metadata()?.len();
            let max_bytes = (limit as u64)
                .saturating_mul(1024)
                .clamp(64 * 1024, 4 * 1024 * 1024);
            let start = file_len.saturating_sub(max_bytes);
            file.seek(SeekFrom::Start(start))?;
            let mut buf = Vec::with_capacity((file_len - start) as usize);
            file.read_to_end(&mut buf)?;
            let text = String::from_utf8_lossy(&buf);
            let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            // If we started mid-file, the first line is almost certainly a
            // truncated entry — drop it (it would fail to parse anyway).
            if start > 0 && !lines.is_empty() {
                lines.remove(0);
            }
            let entries: Vec<crate::audit_log::AuditEntry> = lines
                .iter()
                .rev()
                .take(limit)
                .rev()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            Ok(entries)
        },
    )
    .await;

    match result {
        Ok(Ok(entries)) => Json(entries).into_response(),
        Ok(Err(e)) => (StatusCode::NOT_FOUND, err(format!("audit log: {}", e))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, err("internal error")).into_response(),
    }
}

// ── Kernel module status ──────────────────────────────────────────────────────

async fn get_kernel() -> impl IntoResponse {
    Json(KernelResponse {
        loaded: kernel_loaded(),
        device: "/dev/aivpn",
    })
}

// ── SSE events (periodic state snapshots) ────────────────────────────────────

async fn sse_events(State(state): State<ApiState>) -> impl IntoResponse {
    let interval = tokio::time::interval(std::time::Duration::from_secs(5));
    let stream = IntervalStream::new(interval).map(move |_| {
        let clients = state.db.list_clients();
        #[allow(unused_mut)]
        let mut payload = serde_json::json!({
            "uptime_secs": state.started_at.elapsed().as_secs(),
            "clients_total": clients.len(),
            "clients_enabled": clients.iter().filter(|c| c.enabled).count(),
            // `last_connected` is never cleared, so this counts clients that
            // have EVER connected — named accordingly. The LIVE count is
            // `clients_connected`, derived from the metrics collector's
            // active-session gauge below (metrics builds only).
            "clients_ever_connected": clients.iter()
                .filter(|c| c.stats.last_connected.is_some()).count(),
            "kernel_module": kernel_loaded(),
            "ts": Utc::now().to_rfc3339(),
        });

        // Enrich with live Prometheus metrics for the web panel's live
        // dashboard graphs (active sessions, bandwidth, packet rates,
        // processing latency p50/p95, rotation/DPI counters). Only when
        // built with `--features metrics` AND a collector was wired up by
        // main.rs — otherwise the payload is unchanged from before this
        // feature existed. Counters are sent as raw cumulative totals; the
        // frontend derives per-second rates from consecutive SSE ticks.
        #[cfg(feature = "metrics")]
        if let Some(m) = &state.metrics {
            let (p50_ms, p95_ms) = m.packet_processing_percentiles_ms();
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "active_sessions".into(),
                    serde_json::json!(m.active_sessions()),
                );
                // Live connected count for the web panel's dashboard chart
                // (it reads `clients_connected` from this SSE payload). The
                // previous value counted ever-connected clients and never
                // went down; the active-session gauge is the real live count.
                obj.insert(
                    "clients_connected".into(),
                    serde_json::json!(m.active_sessions()),
                );
                obj.insert(
                    "bytes_received_total".into(),
                    serde_json::json!(m.bytes_received_total()),
                );
                obj.insert(
                    "bytes_sent_total".into(),
                    serde_json::json!(m.bytes_sent_total()),
                );
                obj.insert(
                    "packets_received_total".into(),
                    serde_json::json!(m.packets_received_total()),
                );
                obj.insert(
                    "packets_sent_total".into(),
                    serde_json::json!(m.packets_sent_total()),
                );
                obj.insert(
                    "mask_rotations_total".into(),
                    serde_json::json!(m.mask_rotations_total()),
                );
                obj.insert(
                    "key_rotations_total".into(),
                    serde_json::json!(m.key_rotations_total()),
                );
                obj.insert(
                    "neural_checks_total".into(),
                    serde_json::json!(m.neural_checks_total()),
                );
                obj.insert(
                    "neural_checks_failed_total".into(),
                    serde_json::json!(m.neural_checks_failed_total()),
                );
                obj.insert(
                    "dpi_attacks_detected_total".into(),
                    serde_json::json!(m.dpi_attacks_detected_total()),
                );
                obj.insert("packet_processing_p50_ms".into(), serde_json::json!(p50_ms));
                obj.insert("packet_processing_p95_ms".into(), serde_json::json!(p95_ms));

                // §2 crowdsourced mask feedback + §3 polymorphic masks —
                // same feature-gated, best-effort enrichment as the §1
                // fields above.
                obj.insert(
                    "mask_feedback_received_total".into(),
                    serde_json::json!(m.mask_feedback_received_total()),
                );
                obj.insert(
                    "regional_hints_sent_total".into(),
                    serde_json::json!(m.regional_hints_sent_total()),
                );
                obj.insert(
                    "feedback_buckets".into(),
                    serde_json::json!(m.feedback_buckets()),
                );
                obj.insert(
                    "feedback_regions".into(),
                    serde_json::json!(m.feedback_regions()),
                );
                obj.insert(
                    "mask_preference_requests_total".into(),
                    serde_json::json!(m.mask_preference_requests_total()),
                );
                obj.insert(
                    "polymorphic_variants_pushed_total".into(),
                    serde_json::json!(m.polymorphic_variants_pushed_total()),
                );
                obj.insert(
                    "polymorphic_sessions_active".into(),
                    serde_json::json!(m.polymorphic_sessions_active()),
                );
            }
        }

        Ok::<Event, std::convert::Infallible>(
            Event::default().event("state").data(payload.to_string()),
        )
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ── Router ───────────────────────────────────────────────────────────────────

fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/clients", get(list_clients).post(add_client))
        .route(
            "/api/v1/clients/:id",
            get(get_client).patch(patch_client).delete(remove_client),
        )
        .route(
            "/api/v1/clients/:id/connection-key",
            get(get_connection_key),
        )
        .route("/api/v1/clients/:id/reset-device", post(reset_device))
        .route("/api/v1/config", get(get_config).put(put_config))
        .route("/api/v1/masks", get(list_masks).post(upload_mask))
        .route("/api/v1/masks/:name", axum::routing::delete(delete_mask))
        .route("/api/v1/masks/active", post(set_active_mask))
        .route("/api/v1/backup/export", get(export_backup))
        .route("/api/v1/backup/import", post(import_backup))
        .route("/api/v1/bootstrap/export", get(export_bootstrap))
        .route("/api/v1/audit-log", get(get_audit_log))
        .route("/api/v1/kernel", get(get_kernel))
        .route("/api/v1/events", get(sse_events))
        .route("/api/v1/reload", post(reload))
        .with_state(state)
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn serve(cfg: ServeConfig) {
    let Some(db) = cfg.db else {
        tracing::info!("Management API: no client database configured, skipping");
        return;
    };
    let Some(path) = cfg.socket_path else {
        tracing::info!("Management API: no socket path configured, skipping");
        return;
    };

    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                "Management API: could not remove existing socket '{}': {}",
                path,
                e
            );
        }
    }

    if let Some(parent) = std::path::Path::new(&path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "Management API: cannot create socket directory '{}': {}",
                parent.display(),
                e
            );
            return;
        }
    }

    // The API has no in-band auth (a connection is full admin), so the socket
    // must never be even briefly connectable by other local users. Bind it
    // inside a fresh 0700 staging directory (the missing search bit blocks
    // everyone else), chmod it to 0600 while still shielded, then atomically
    // rename it to the final path. This avoids the previous umask() dance:
    // umask is process-wide, so flipping it here silently broke the mode of
    // any file or directory another thread created in the same window.
    // The staging name carries pid + an in-process sequence number so
    // concurrent serve() calls (e.g. the integration tests, which spawn one
    // API per test in the same process and directory) never share a dir.
    static STAGING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let staging_dir = std::path::Path::new(&path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!(
            ".aivpn-api-staging.{}.{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
    let _ = std::fs::remove_dir_all(&staging_dir);
    if let Err(e) = std::fs::create_dir(&staging_dir) {
        tracing::warn!(
            "Management API: cannot create staging dir '{}': {}",
            staging_dir.display(),
            e
        );
        return;
    }
    if let Err(e) = std::fs::set_permissions(
        &staging_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    ) {
        tracing::warn!("Management API: failed to restrict staging dir: {}", e);
        let _ = std::fs::remove_dir_all(&staging_dir);
        return;
    }
    let staged_sock = staging_dir.join("api.sock");
    let listener = match UnixListener::bind(&staged_sock) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Management API: failed to bind '{}': {}", path, e);
            let _ = std::fs::remove_dir_all(&staging_dir);
            return;
        }
    };
    if let Err(e) = std::fs::set_permissions(
        &staged_sock,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    ) {
        tracing::warn!("Management API: failed to set socket permissions: {}", e);
        let _ = std::fs::remove_dir_all(&staging_dir);
        return;
    }
    if let Err(e) = std::fs::rename(&staged_sock, &path) {
        tracing::warn!(
            "Management API: failed to move socket into place at '{}': {}",
            path,
            e
        );
        let _ = std::fs::remove_dir_all(&staging_dir);
        return;
    }
    let _ = std::fs::remove_dir_all(&staging_dir);

    tracing::info!("Management API listening on unix:{}", path);

    let state = ApiState {
        db,
        started_at: Instant::now(),
        server_pub_key: cfg.server_pub_key,
        server_addr: cfg.server_addr,
        server_signing_pubkey: cfg.server_signing_pubkey,
        config_path: cfg.config_path,
        clients_db_path: cfg.clients_db_path,
        mask_dir: cfg.mask_dir,
        audit_log_path: cfg.audit_log_path,
        audit_log: cfg.audit_log,
        bootstrap_descriptors: cfg.bootstrap_descriptors,
        mask_operator_pubkey: cfg.mask_operator_pubkey,
        mask_verify_mode: cfg.mask_verify_mode,
        #[cfg(feature = "metrics")]
        metrics: cfg.metrics,
    };
    let app = router(state);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Management API: accept error: {}", e);
                // Back off briefly: a persistent error (e.g. EMFILE) would
                // otherwise spin this loop at 100% CPU and starve the runtime.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let svc = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let hyper_svc = hyper::service::service_fn(move |req| svc.clone().oneshot(req));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper_svc)
                .await
            {
                tracing::debug!("Management API: connection error: {}", e);
            }
        });
    }
}

// PUT /api/v1/config validation is now type-level: the body must deserialize
// into `crate::server_config::ServerFileConfig` (see that module's tests for
// the shipped-example round-trip and unknown/typo-key rejection coverage).
