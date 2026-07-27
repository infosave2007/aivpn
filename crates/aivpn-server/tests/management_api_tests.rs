//! Integration tests for the Management HTTP API (Unix socket).
//!
//! Each test:
//!   1. Creates a real `ClientDatabase` in a temp directory.
//!   2. Spawns `management_api::serve()` on a unique temp Unix socket.
//!   3. Sends HTTP/1.1 requests over the Unix socket using hyper + tokio.
//!   4. Asserts on status codes and JSON response bodies.
//!
//! Guard: all tests are under `#[cfg(feature = "management-api")]` so they
//! are only compiled and executed when the feature is active.

#![cfg(feature = "management-api")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::UnixStream;
use tokio::time::sleep;

use aivpn_common::network_config::VpnNetworkConfig;
use aivpn_server::client_db::ClientDatabase;
use aivpn_server::management_api;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Global counter to give each test run a unique socket path even when
/// all 12 tests execute concurrently in the same process.
static SOCKET_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Default VPN network config suitable for tests (10.99.0.0/24).
fn test_network_config() -> VpnNetworkConfig {
    VpnNetworkConfig {
        server_vpn_ip: "10.99.0.1".parse().unwrap(),
        prefix_len: 24,
        mtu: 1400,
        keepalive_secs: None,
        ..Default::default()
    }
}

/// Create a temporary directory and a `ClientDatabase` inside it.
fn make_temp_db(test_name: &str) -> (tempfile::TempDir, Arc<ClientDatabase>) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("aivpn_api_test_{}_", test_name))
        .tempdir()
        .expect("tempdir");
    let db_path = dir.path().join("clients.json");
    let db = ClientDatabase::load(&db_path, test_network_config()).expect("load db");
    (dir, Arc::new(db))
}

/// Return a unique Unix socket path. Uniqueness is guaranteed by combining
/// the process PID with an atomic counter so concurrent tests never share a path.
fn unique_socket_path() -> String {
    let n = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("/tmp/aivpn_mgmt_test_{}_{}.sock", std::process::id(), n)
}

/// Spawn the management API server and wait until the socket file appears.
async fn spawn_server(db: Arc<ClientDatabase>, socket_path: String) {
    spawn_server_with_key(db, socket_path, None, None).await;
}

/// Spawn the management API server with optional server key and address.
async fn spawn_server_with_key(
    db: Arc<ClientDatabase>,
    socket_path: String,
    server_pub_key: Option<[u8; 32]>,
    server_addr: Option<String>,
) {
    let db_clone = db.clone();
    let path_clone = socket_path.clone();
    tokio::spawn(async move {
        management_api::serve(management_api::ServeConfig {
            db: Some(db_clone),
            socket_path: Some(path_clone),
            server_pub_key,
            server_addr,
            server_signing_pubkey: None,
            config_path: None,
            clients_db_path: None,
            mask_dir: std::env::temp_dir(),
            audit_log_path: None,
            audit_log: None,
            bootstrap_descriptors: None,
            mask_operator_pubkey: None,
            mask_verify_mode: aivpn_common::mask::MaskVerifyMode::default(),
            #[cfg(feature = "metrics")]
            metrics: None,
        })
        .await;
    });

    // Wait until the socket exists (up to 2 s)
    for _ in 0..40 {
        if std::path::Path::new(&socket_path).exists() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("Management API socket did not appear: {}", socket_path);
}

/// Open a persistent hyper HTTP/1.1 connection over a Unix socket.
async fn connect(socket_path: &str) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
    let stream = UnixStream::connect(socket_path)
        .await
        .expect("connect to unix socket");
    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("http1 handshake");
    tokio::spawn(conn);
    sender
}

/// Send a single request and return (status, body-as-Value).
async fn send(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    method: Method,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let body_bytes = body.map(|s| Bytes::from(s.to_owned())).unwrap_or_default();

    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .header("Content-Length", body_bytes.len().to_string())
        .body(Full::new(body_bytes))
        .expect("build request");

    let res = sender.send_request(req).await.expect("send request");
    let status = res.status();
    let bytes = res
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// GET /api/v1/status returns 200 with `version` and `uptime_secs` fields.
#[tokio::test]
async fn test_get_status_returns_200() {
    let (_dir, db) = make_temp_db("status");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (status, body) = send(&mut sender, Method::GET, "/api/v1/status", None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body["version"].is_string(),
        "version must be a string: {:?}",
        body
    );
    assert!(
        body["uptime_secs"].is_number(),
        "uptime_secs must be a number: {:?}",
        body
    );
}

/// GET /api/v1/clients on an empty database returns 200 and an empty array.
#[tokio::test]
async fn test_list_clients_empty() {
    let (_dir, db) = make_temp_db("list_empty");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (status, body) = send(&mut sender, Method::GET, "/api/v1/clients", None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.is_array(), "body must be an array: {:?}", body);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

/// POST /api/v1/clients creates a client and returns 201 with expected fields.
/// Verifies that `psk` is NOT present in the response.
#[tokio::test]
async fn test_add_client_returns_201_without_psk() {
    let (_dir, db) = make_temp_db("add_client");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let payload = r#"{"name": "alice"}"#;
    let (status, body) = send(&mut sender, Method::POST, "/api/v1/clients", Some(payload)).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "expected 201, got {:?}: {:?}",
        status,
        body
    );

    // Required fields present
    assert!(body["id"].is_string(), "id must be string: {:?}", body);
    assert!(body["name"].is_string(), "name must be string: {:?}", body);
    assert!(
        body["vpn_ip"].is_string(),
        "vpn_ip must be string: {:?}",
        body
    );
    assert!(
        body["enabled"].is_boolean(),
        "enabled must be bool: {:?}",
        body
    );
    assert!(
        body["created_at"].is_string(),
        "created_at must be string: {:?}",
        body
    );

    // PSK must NOT be in the response
    assert!(
        body.get("psk").is_none(),
        "PSK must not appear in API response: {:?}",
        body
    );

    // Name matches what we sent
    assert_eq!(body["name"], "alice");
    assert_eq!(body["enabled"], true);
}

/// POST /api/v1/clients with a duplicate name returns 409 Conflict.
#[tokio::test]
async fn test_add_client_duplicate_returns_409() {
    let (_dir, db) = make_temp_db("add_dup");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let payload = r#"{"name": "bob"}"#;

    // First creation — should succeed
    let mut sender = connect(&sock).await;
    let (s1, _) = send(&mut sender, Method::POST, "/api/v1/clients", Some(payload)).await;
    assert_eq!(s1, StatusCode::CREATED);

    // Second creation with same name — open a new connection
    let mut sender2 = connect(&sock).await;
    let (s2, body) = send(&mut sender2, Method::POST, "/api/v1/clients", Some(payload)).await;
    assert_eq!(
        s2,
        StatusCode::CONFLICT,
        "duplicate name must return 409: {:?}",
        body
    );
    assert!(
        body["error"].is_string(),
        "error field expected: {:?}",
        body
    );
}

/// GET /api/v1/clients/:id returns 200 with the correct client, without PSK.
#[tokio::test]
async fn test_get_client_by_id() {
    let (_dir, db) = make_temp_db("get_by_id");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    // Create a client
    let mut sender = connect(&sock).await;
    let (_, created) = send(
        &mut sender,
        Method::POST,
        "/api/v1/clients",
        Some(r#"{"name":"charlie"}"#),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    // Fetch by ID
    let mut sender2 = connect(&sock).await;
    let path = format!("/api/v1/clients/{}", id);
    let (status, body) = send(&mut sender2, Method::GET, &path, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], id.as_str());
    assert_eq!(body["name"], "charlie");
    assert!(body.get("psk").is_none(), "PSK must not appear: {:?}", body);
}

/// GET /api/v1/clients/:id for a non-existent ID returns 404.
#[tokio::test]
async fn test_get_client_not_found_returns_404() {
    let (_dir, db) = make_temp_db("get_404");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (status, body) = send(
        &mut sender,
        Method::GET,
        "/api/v1/clients/nonexistent",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["error"].is_string(),
        "error field expected: {:?}",
        body
    );
}

/// DELETE /api/v1/clients/:id removes the client and returns 204 No Content.
#[tokio::test]
async fn test_delete_client_returns_204() {
    let (_dir, db) = make_temp_db("delete_client");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    // Create client
    let mut sender = connect(&sock).await;
    let (_, created) = send(
        &mut sender,
        Method::POST,
        "/api/v1/clients",
        Some(r#"{"name":"dave"}"#),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    // Delete
    let mut sender2 = connect(&sock).await;
    let path = format!("/api/v1/clients/{}", id);
    let (status, _) = send(&mut sender2, Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "DELETE must return 204");

    // Verify it's gone
    let mut sender3 = connect(&sock).await;
    let (status2, _) = send(&mut sender3, Method::GET, &path, None).await;
    assert_eq!(
        status2,
        StatusCode::NOT_FOUND,
        "deleted client must return 404"
    );
}

/// DELETE /api/v1/clients/:id for a non-existent ID returns 404.
#[tokio::test]
async fn test_delete_nonexistent_client_returns_404() {
    let (_dir, db) = make_temp_db("delete_404");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (status, body) = send(
        &mut sender,
        Method::DELETE,
        "/api/v1/clients/no-such-id",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["error"].is_string(),
        "error field expected: {:?}",
        body
    );
}

/// POST /api/v1/reload returns 200 with `reloaded` boolean field.
#[tokio::test]
async fn test_reload_endpoint() {
    let (_dir, db) = make_temp_db("reload");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (status, body) = send(&mut sender, Method::POST, "/api/v1/reload", None).await;

    assert_eq!(status, StatusCode::OK, "reload must return 200: {:?}", body);
    assert!(
        body["reloaded"].is_boolean(),
        "`reloaded` must be a bool: {:?}",
        body
    );
}

/// GET /api/v1/clients returns all clients added so far.
#[tokio::test]
async fn test_list_clients_after_add() {
    let (_dir, db) = make_temp_db("list_after_add");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    // Add two clients
    for name in &["eve", "frank"] {
        let mut s = connect(&sock).await;
        let payload = format!(r#"{{"name":"{}"}}"#, name);
        let (status, _) = send(&mut s, Method::POST, "/api/v1/clients", Some(&payload)).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    // List
    let mut sender = connect(&sock).await;
    let (status, body) = send(&mut sender, Method::GET, "/api/v1/clients", None).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("body must be array");
    assert_eq!(
        arr.len(),
        2,
        "expected 2 clients, got {}: {:?}",
        arr.len(),
        body
    );

    // PSK must not appear in any item
    for item in arr {
        assert!(
            item.get("psk").is_none(),
            "PSK must not appear in list: {:?}",
            item
        );
        assert!(item["id"].is_string());
        assert!(item["name"].is_string());
        assert!(item["vpn_ip"].is_string());
    }
}

/// Stats fields are present in the client response.
#[tokio::test]
async fn test_client_response_has_stats() {
    let (_dir, db) = make_temp_db("stats_fields");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (_, created) = send(
        &mut sender,
        Method::POST,
        "/api/v1/clients",
        Some(r#"{"name":"grace"}"#),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let mut sender2 = connect(&sock).await;
    let path = format!("/api/v1/clients/{}", id);
    let (status, body) = send(&mut sender2, Method::GET, &path, None).await;

    assert_eq!(status, StatusCode::OK);
    let stats = &body["stats"];
    assert!(stats.is_object(), "stats must be an object: {:?}", body);
    assert!(stats["bytes_in"].is_number(), "bytes_in: {:?}", stats);
    assert!(stats["bytes_out"].is_number(), "bytes_out: {:?}", stats);
    assert!(
        stats["total_connections"].is_number(),
        "total_connections: {:?}",
        stats
    );
}

/// Confirm the PSK field is absent even when it is stored in the DB.
/// (Checks both single-client GET and list GET.)
#[tokio::test]
async fn test_psk_never_exposed() {
    let (_dir, db) = make_temp_db("psk_never");
    let sock = unique_socket_path();
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (_, created) = send(
        &mut sender,
        Method::POST,
        "/api/v1/clients",
        Some(r#"{"name":"henry"}"#),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    // Check PSK not in POST response
    assert!(
        created.get("psk").is_none(),
        "PSK in POST response: {:?}",
        created
    );

    // Check PSK not in GET single
    let mut s2 = connect(&sock).await;
    let path = format!("/api/v1/clients/{}", id);
    let (_, single) = send(&mut s2, Method::GET, &path, None).await;
    assert!(
        single.get("psk").is_none(),
        "PSK in GET single: {:?}",
        single
    );

    // Check PSK not in GET list
    let mut s3 = connect(&sock).await;
    let (_, list) = send(&mut s3, Method::GET, "/api/v1/clients", None).await;
    for item in list.as_array().unwrap() {
        assert!(item.get("psk").is_none(), "PSK in list item: {:?}", item);
    }
}

/// GET /api/v1/clients/:id/connection-key returns 503 when server is not
/// configured with --server-ip / --key-file.
#[tokio::test]
async fn test_connection_key_without_server_config_returns_503() {
    let (_dir, db) = make_temp_db("conn_key_503");
    let sock = unique_socket_path();
    // No server_pub_key, no server_addr
    spawn_server(db, sock.clone()).await;

    let mut sender = connect(&sock).await;
    let (_, created) = send(
        &mut sender,
        Method::POST,
        "/api/v1/clients",
        Some(r#"{"name":"ivan"}"#),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let mut s2 = connect(&sock).await;
    let path = format!("/api/v1/clients/{}/connection-key", id);
    let (status, body) = send(&mut s2, Method::GET, &path, None).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "expected 503: {:?}",
        body
    );
    assert!(
        body["error"].is_string(),
        "error field expected: {:?}",
        body
    );
}

/// GET /api/v1/clients/:id/connection-key returns 200 with a valid aivpn:// string
/// when the server is configured with a key and address.
#[tokio::test]
async fn test_connection_key_returns_aivpn_url() {
    let (_dir, db) = make_temp_db("conn_key_200");
    let sock = unique_socket_path();

    // Fake 32-byte server public key and a server address
    let pub_key = [0x42u8; 32];
    let server_addr = "1.2.3.4:4443".to_string();
    spawn_server_with_key(db, sock.clone(), Some(pub_key), Some(server_addr)).await;

    // Create client
    let mut sender = connect(&sock).await;
    let (_, created) = send(
        &mut sender,
        Method::POST,
        "/api/v1/clients",
        Some(r#"{"name":"judy"}"#),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    // Get connection key
    let mut s2 = connect(&sock).await;
    let path = format!("/api/v1/clients/{}/connection-key", id);
    let (status, body) = send(&mut s2, Method::GET, &path, None).await;

    assert_eq!(status, StatusCode::OK, "expected 200: {:?}", body);
    let key = body["connection_key"]
        .as_str()
        .expect("connection_key must be a string");
    assert!(
        key.starts_with("aivpn://"),
        "key must start with aivpn://: {}",
        key
    );

    // connection-key for non-existent client must return 404
    let mut s3 = connect(&sock).await;
    let (status404, _) = send(
        &mut s3,
        Method::GET,
        "/api/v1/clients/no-such-id/connection-key",
        None,
    )
    .await;
    assert_eq!(status404, StatusCode::NOT_FOUND);
}
