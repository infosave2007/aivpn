//! In-tunnel management dispatch (P1.2) — the curated `MgmtRequest`/
//! `MgmtResponse` router the gateway proxies over the masked tunnel, plus
//! its supporting wire types (`Tunnel*Request`), route classification
//! (`classify_route`/`Route`), and authorization (`authorize`).
//!
//! Split out of `mgmt_service` (ЭТАП 1 decomposition, pure move — see
//! `mgmt_service`'s module doc for the shared design context). `authorize`/
//! `classify_route`/`dispatch` are security-critical (the curated allowlist
//! + role gate that keeps `PUT /config`, `backup/import`, and role
//! assignment off the tunnel) — moved verbatim, logic unchanged.

use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::client_db::ClientRole;
use crate::mgmt_wire_common::deserialize_opt_opt;

use super::*;

// ── In-tunnel dispatch (P1.2) ───────────────────────────────────────────
//
// `dispatch` is the ONE router shared by the `MgmtRequest`/`MgmtResponse`
// control messages the gateway proxies over the masked tunnel (design
// doc §3.3–3.4). It intentionally supports a strict SUBSET of the axum
// `management_api.rs` routes — the "curated allowlist" — never the full
// REST surface: no `PUT /config`, no `backup/import`, no mask-signing-key
// management, and (critically) **no role assignment**, even for an Admin
// caller — see `TunnelPatchClientRequest` below, which has no `role`
// field at all, so a `role` key in the request JSON is silently ignored
// by serde rather than ever reaching `UpdateClientArgs`.
//
// `method` follows the wire convention documented on
// `ControlPayload::MgmtRequest`: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT.

const METHOD_GET: u8 = 0;
const METHOD_POST: u8 = 1;
const METHOD_PATCH: u8 = 2;
const METHOD_DELETE: u8 = 3;

/// Default `audit-log` tail length when the request path carries no
/// `?limit=` query — mirrors `management_api.rs`'s `default_audit_limit`.
const DEFAULT_AUDIT_LIMIT: usize = 200;
/// Same clamp `management_api.rs`'s `get_audit_log` applies to the query
/// param, so the tunnel path can't be used to force an unbounded read.
const MAX_AUDIT_LIMIT: usize = 1000;

/// One entry in the curated in-tunnel management allowlist (design §3.4).
/// `dispatch` and `authorize` both classify a `(method, path)` pair
/// through this SAME table (`classify_route`), so the two can never drift
/// out of sync — a route `dispatch` doesn't implement here is simply
/// unreachable via the tunnel, full stop, regardless of role.
enum Route {
    Status,
    ClientsList,
    ClientAdd,
    ClientGet(String),
    ClientPatch(String),
    ClientDelete(String),
    ClientConnectionKey(String),
    ClientResetDevice(String),
    /// P1.3: `POST /api/v1/clients/:id/revoke` — see [`revoke`]'s doc
    /// comment for why this is a distinct route from `ClientDelete` even
    /// though both tombstone via the same `ClientDatabase::remove_client`.
    ClientRevoke(String),
    AuditLog {
        limit: usize,
        verify: bool,
    },
    /// P1.5: `POST /api/v1/config/apply` — see the "Apply-with-rollback"
    /// section above.
    ConfigApply,
    /// P1.5: `POST /api/v1/config/confirm`.
    ConfigConfirm,
    /// Wave B1: `GET /api/v1/pool/nodes` — see the "Pool topology views"
    /// section above.
    PoolNodes,
    /// Wave B1: `GET /api/v1/pool/health`.
    PoolHealth,
    /// Wave B1: `GET /api/v1/pool/links`.
    PoolLinks,
    /// G-A3: `GET /api/v1/masks` — list available mask profiles so the
    /// native in-app "Server Settings" apply-with-rollback picker has the
    /// same data source as the web panel. Read-only listing of the mask
    /// directory (filenames + sizes + `generated` flag), no secrets — the
    /// REST handler is `management_api.rs::list_masks`; this arm mirrors its
    /// shape over the curated tunnel so Viewer+Admin can enumerate masks.
    MasksList,
}

/// Parse `?limit=N` out of a raw query string, clamped to
/// `[1, MAX_AUDIT_LIMIT]`. Any missing/unparsable value falls back to
/// `DEFAULT_AUDIT_LIMIT` — mirrors `management_api.rs`'s
/// `#[serde(default = "default_audit_limit")] limit: usize` + `.min(1000)`
/// handling for the same query param on the REST path.
fn parse_audit_limit(query: Option<&str>) -> usize {
    let raw = query
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("limit=")))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_AUDIT_LIMIT);
    raw.clamp(1, MAX_AUDIT_LIMIT)
}

/// Parse `?verify=1` (also accepts `verify=true`/`verify=yes`) out of a raw
/// query string — mirrors `management_api.rs`'s `AuditLogQuery::verify`
/// parsing for the same query param on the REST path. Any other/missing
/// value is `false` (the existing plain-array response shape).
fn parse_audit_verify(query: Option<&str>) -> bool {
    query
        .map(|q| {
            q.split('&').any(|kv| match kv.split_once('=') {
                Some(("verify", v)) => matches!(v, "1" | "true" | "yes"),
                _ => false,
            })
        })
        .unwrap_or(false)
}

/// Classify a raw `(method, path)` `MgmtRequest` into a curated `Route`,
/// or `None` if it falls outside the allowlist (§3.4) — including every
/// REST route `management_api.rs` exposes but the tunnel deliberately
/// never will (`PUT /config`, `backup/import`, mask-signing-key mgmt,
/// role assignment). `path` may carry a `?query`; only `audit-log`'s
/// `limit` is currently recognized.
fn classify_route(method: u8, path: &str) -> Option<Route> {
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let segments: Vec<&str> = path_only
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.len() < 3 || segments[0] != "api" || segments[1] != "v1" {
        return None;
    }
    let rest = &segments[2..];
    match (method, rest) {
        (METHOD_GET, ["status"]) => Some(Route::Status),
        (METHOD_GET, ["clients"]) => Some(Route::ClientsList),
        (METHOD_POST, ["clients"]) => Some(Route::ClientAdd),
        (METHOD_GET, ["clients", id]) => Some(Route::ClientGet((*id).to_string())),
        (METHOD_PATCH, ["clients", id]) => Some(Route::ClientPatch((*id).to_string())),
        (METHOD_DELETE, ["clients", id]) => Some(Route::ClientDelete((*id).to_string())),
        (METHOD_GET, ["clients", id, "connection-key"]) => {
            Some(Route::ClientConnectionKey((*id).to_string()))
        }
        (METHOD_POST, ["clients", id, "reset-device"]) => {
            Some(Route::ClientResetDevice((*id).to_string()))
        }
        (METHOD_POST, ["clients", id, "revoke"]) => Some(Route::ClientRevoke((*id).to_string())),
        (METHOD_GET, ["audit-log"]) => Some(Route::AuditLog {
            limit: parse_audit_limit(query),
            verify: parse_audit_verify(query),
        }),
        (METHOD_POST, ["config", "apply"]) => Some(Route::ConfigApply),
        (METHOD_POST, ["config", "confirm"]) => Some(Route::ConfigConfirm),
        (METHOD_GET, ["pool", "nodes"]) => Some(Route::PoolNodes),
        (METHOD_GET, ["pool", "health"]) => Some(Route::PoolHealth),
        (METHOD_GET, ["pool", "links"]) => Some(Route::PoolLinks),
        (METHOD_GET, ["masks"]) => Some(Route::MasksList),
        _ => None,
    }
}

/// Authorize a `MgmtRequest` before it's allowed to reach `dispatch`.
/// `role_u8` is the CALLER's server-assigned role (`ClientRole::as_u8`,
/// resolved server-side from the session's `client_id` — NEVER trust
/// anything the request itself claims): `0`=User, `1`=Viewer, `2`=Admin.
///
/// - User (0): denied everything — a `User`-role client has no
///   management access at all.
/// - Viewer (1): every curated route, but GET only (read-only monitoring
///   — status/clients/single-client/connection-key/audit-log).
/// - Admin (2): the full curated allowlist, both reads and mutations.
///
/// A path/method combination outside the curated allowlist (see
/// `classify_route`) is denied for EVERY role, including Admin — the
/// allowlist itself, not just the role check, is what keeps `PUT
/// /config`, `backup/import`, and role assignment off the tunnel.
pub fn authorize(role_u8: u8, method: u8, path: &str) -> bool {
    if classify_route(method, path).is_none() {
        return false;
    }
    match role_u8 {
        2 => true,
        1 => method == METHOD_GET,
        _ => false,
    }
}

/// If `(method, path)` classifies as the P1.3 admin "revoke" route, returns
/// the target client id — `None` for every other route. Used by the
/// gateway's in-tunnel `MgmtRequest` handling: after `dispatch` returns a
/// success status for this specific route, the gateway (which — unlike this
/// module — holds a live `SessionManager`/`PoolDialer`) performs the two
/// side effects `revoke()` itself cannot: an immediate forced session
/// disconnect and a priority pool beacon. See `revoke`'s doc comment for
/// the full split of responsibility.
pub fn revoke_target(method: u8, path: &str) -> Option<String> {
    match classify_route(method, path) {
        Some(Route::ClientRevoke(id)) => Some(id),
        _ => None,
    }
}

fn mgmt_error_status(e: &MgmtError) -> u16 {
    match e {
        MgmtError::NotFound => 404,
        MgmtError::Conflict(_) => 409,
        MgmtError::BadRequest(_) => 400,
        MgmtError::Forbidden => 403,
        MgmtError::Unavailable(_) => 503,
        MgmtError::Internal(_) => 500,
    }
}

/// Serialize `value` to JSON for a `MgmtResponse` body. A serialization
/// failure (should be unreachable for the `Serialize` types this module
/// returns) degrades to `500` with an empty body rather than panicking —
/// this runs on every server build, unauthenticated-adjacent input included
/// (an authorized-but-malicious peer controls `body`/`path`), so it must
/// never be a panic surface.
fn json_response<T: Serialize>(status: u16, value: &T) -> (u16, Vec<u8>) {
    match serde_json::to_vec(value) {
        Ok(bytes) => (status, bytes),
        Err(_) => (500, Vec::new()),
    }
}

fn err_response(e: MgmtError) -> (u16, Vec<u8>) {
    (mgmt_error_status(&e), Vec::new())
}

/// Wire body for `POST /api/v1/clients` over the tunnel. Deliberately has
/// NO `role` field — see the module-level allowlist doc comment — so a
/// `role` key present in the caller's JSON is silently dropped by serde
/// rather than reaching `AddClientArgs`.
#[derive(Deserialize)]
struct TunnelAddClientRequest {
    name: String,
    #[serde(default)]
    one_time: bool,
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    qos: Option<crate::qos::ClientQos>,
}

/// Wire body for `PATCH /api/v1/clients/:id` over the tunnel. Deliberately
/// has NO `role` field — see `TunnelAddClientRequest`'s doc comment; role
/// assignment is a web/CLI-only operation (`management_api.rs`'s
/// `PatchClientRequest`), never available through this path even to an
/// Admin-role caller.
#[derive(Deserialize)]
struct TunnelPatchClientRequest {
    name: Option<String>,
    enabled: Option<bool>,
    one_time: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    qos: Option<Option<crate::qos::ClientQos>>,
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    expires_at: Option<Option<DateTime<Utc>>>,
    /// Wave B2a: UNLIKE `role`, `exit_node` IS settable over the tunnel —
    /// see `UpdateClientArgs::exit_node`'s doc comment for why this is
    /// safe (a routing preference, not a privilege grant). Pass `null` to
    /// clear (fall back to the global default); omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    exit_node: Option<Option<String>>,
}

/// Wire body for `POST /api/v1/config/apply`. Which [`HeavySetting`] this
/// selects is determined by WHICH fields are present, not a `type` tag:
/// presence of the `exit_node` key (even as JSON `null`, to clear it)
/// selects [`HeavySetting::ExitNode`]; its absence selects the original
/// v1 [`HeavySetting::ActiveMask`] using `client`/`mask` (unchanged wire
/// shape, so existing callers are unaffected). Mirrors
/// `management_api.rs`'s `ApplyConfigRequest`, which the same convention.
#[derive(Deserialize)]
struct TunnelApplyRequest {
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    mask: Option<String>,
    /// Wave B2a: presence (even `null`) selects `HeavySetting::ExitNode`.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    exit_node: Option<Option<String>>,
}

/// Wire body for `POST /api/v1/config/confirm`.
#[derive(Deserialize)]
struct TunnelConfirmRequest {
    token: String,
}

/// Dispatch a decoded `MgmtRequest` (already authorized by `authorize`)
/// to the matching `mgmt_service` operation, returning the `(status,
/// body)` pair the gateway wraps into a `MgmtResponse`. Unknown/
/// unsupported `(method, path)` combinations return `404` with an empty
/// body — the same "route doesn't exist" signal `authorize` short-circuits
/// on before this is ever reached in the live gateway flow (see that
/// function's doc comment), but kept correct here too so this function is
/// safe and well-defined to call directly (as the unit tests below do).
pub fn dispatch(ctx: &MgmtCtx, method: u8, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let Some(route) = classify_route(method, path) else {
        return (404, Vec::new());
    };
    match route {
        Route::Status => json_response(200, &status(ctx)),
        Route::ClientsList => json_response(200, &list_clients(ctx)),
        Route::ClientAdd => {
            let req: TunnelAddClientRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            let args = AddClientArgs {
                name: req.name,
                one_time: req.one_time,
                expires_at: req.expires_at,
                role: ClientRole::User,
                qos: req.qos,
            };
            match add_client(ctx, args) {
                Ok(view) => json_response(201, &view),
                Err(e) => err_response(e),
            }
        }
        Route::ClientGet(id) => match ctx.db.find_by_id(&id) {
            Some(c) => json_response(200, &ClientView::from(c)),
            None => (404, Vec::new()),
        },
        Route::ClientPatch(id) => {
            let req: TunnelPatchClientRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            let args = UpdateClientArgs {
                name: req.name,
                enabled: req.enabled,
                one_time: req.one_time,
                qos: req.qos,
                expires_at: req.expires_at,
                // Never settable over the tunnel — see this route's doc
                // comment and `TunnelPatchClientRequest`.
                role: None,
                // Wave B2a: settable over the tunnel — see
                // `TunnelPatchClientRequest::exit_node`'s doc comment.
                exit_node: req.exit_node,
            };
            match update_client(ctx, &id, args) {
                Ok(view) => json_response(200, &view),
                Err(e) => err_response(e),
            }
        }
        Route::ClientDelete(id) => match remove_client(ctx, &id) {
            Ok(()) => (204, Vec::new()),
            Err(e) => err_response(e),
        },
        Route::ClientConnectionKey(id) => match connection_key(ctx, &id) {
            // Field name unified with the REST handler (management_api::get_connection_key)
            // so tunnel and socket clients parse the same key. Both use "connection_key".
            Ok(key) => json_response(200, &serde_json::json!({ "connection_key": key })),
            Err(e) => err_response(e),
        },
        Route::ClientResetDevice(id) => match reset_device(ctx, &id) {
            Ok(()) => (204, Vec::new()),
            Err(e) => err_response(e),
        },
        Route::ClientRevoke(id) => match revoke(ctx, &id) {
            Ok(()) => (204, Vec::new()),
            Err(e) => err_response(e),
        },
        Route::AuditLog { limit, verify } => {
            if verify {
                match audit_verify(ctx, limit) {
                    Ok(view) => json_response(200, &view),
                    Err(e) => err_response(e),
                }
            } else {
                match audit_tail(ctx, limit) {
                    Ok(entries) => json_response(200, &entries),
                    Err(e) => err_response(e),
                }
            }
        }
        Route::ConfigApply => {
            let req: TunnelApplyRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            let setting = if let Some(exit_node) = req.exit_node {
                HeavySetting::ExitNode { addr: exit_node }
            } else {
                HeavySetting::ActiveMask {
                    client: req.client.unwrap_or_default(),
                    mask: req.mask.unwrap_or_default(),
                }
            };
            match apply_heavy(ctx, setting, Instant::now()) {
                Ok(resp) => json_response(200, &resp),
                Err(e) => err_response(e),
            }
        }
        Route::ConfigConfirm => {
            let req: TunnelConfirmRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => return (400, Vec::new()),
            };
            match confirm_config(ctx, &req.token) {
                Ok(_) => (204, Vec::new()),
                Err(e) => err_response(e),
            }
        }
        // Wave B1: `ctx.pool` is `None` on a node with no pool sync
        // configured at all (or when a caller built `MgmtCtx` without
        // wiring it — should not happen for a real REST/tunnel caller, see
        // that field's doc comment) — degrade to the same `empty("none")`
        // shape a real "pool not configured" node would report, rather than
        // erroring. Always `200`.
        Route::PoolNodes => {
            let empty = PoolSnapshot::empty("none");
            let nodes = ctx.pool.as_ref().map(|p| &p.nodes).unwrap_or(&empty.nodes);
            json_response(200, nodes)
        }
        Route::PoolHealth => {
            let health = ctx
                .pool
                .as_ref()
                .map(|p| &p.health)
                .cloned()
                .unwrap_or_else(|| PoolHealth::empty("none"));
            json_response(200, &health)
        }
        Route::PoolLinks => {
            let empty = PoolSnapshot::empty("none");
            let links = ctx.pool.as_ref().map(|p| &p.links).unwrap_or(&empty.links);
            json_response(200, links)
        }
        Route::MasksList => json_response(200, &list_mask_files(ctx.mask_dir)),
    }
}

/// List the mask profiles in `mask_dir` for the tunnel `GET /api/v1/masks`
/// arm — mirrors the shape of `management_api.rs::list_masks`'s `MaskInfo`
/// (`id`/`file`/`size_bytes`/`modified`/`generated`) so the native and web
/// mask pickers consume identical JSON. Read-only; any unreadable directory
/// or entry degrades to an empty/partial list rather than erroring.
fn list_mask_files(mask_dir: &std::path::Path) -> Vec<serde_json::Value> {
    let mut entries = Vec::new();
    let Ok(dir) = std::fs::read_dir(mask_dir) else {
        return entries;
    };
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        // RFC3339 string to byte-match the REST handler's
        // `Option<DateTime<Utc>>` serialization (clients decode `modified`
        // as an optional string; a bare number would fail strict decoders).
        let modified = meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0))
            .map(|dt| dt.to_rfc3339());
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
        // the picker can mark auto-generated masks — mirrors the REST handler.
        let generated = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("generated").and_then(|g| g.as_bool()))
            .unwrap_or(false);
        entries.push(serde_json::json!({
            "id": id,
            "file": file,
            "size_bytes": size,
            "modified": modified,
            "generated": generated,
        }));
    }
    entries.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt_service::test_support::*;

    fn ctx_with_pool<'a>(
        db: &'a ClientDatabase,
        mask_dir: &'a Path,
        pool: Option<PoolSnapshot>,
    ) -> MgmtCtx<'a> {
        let mut c = ctx(db, mask_dir);
        c.pool = pool;
        c
    }

    #[test]
    fn authorize_viewer_get_ok_post_denied() {
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/clients"));
        assert!(!authorize(ROLE_VIEWER, METHOD_POST, "/api/v1/clients"));
    }
    #[test]
    fn authorize_user_denied_everything() {
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/status"));
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/clients"));
        assert!(!authorize(ROLE_USER, METHOD_POST, "/api/v1/clients"));
    }
    #[test]
    fn authorize_admin_post_ok() {
        assert!(authorize(ROLE_ADMIN, METHOD_POST, "/api/v1/clients"));
        assert!(authorize(ROLE_ADMIN, METHOD_PATCH, "/api/v1/clients/abc"));
        assert!(authorize(ROLE_ADMIN, METHOD_DELETE, "/api/v1/clients/abc"));
    }
    #[test]
    fn authorize_denies_routes_outside_the_curated_allowlist_for_every_role() {
        // Never-through-the-tunnel operations (design §3.4): full config
        // PUT, backup import, mask-signing-key management. None of these
        // are in `classify_route`'s table at all, so even Admin is denied.
        for role in [ROLE_USER, ROLE_VIEWER, ROLE_ADMIN] {
            assert!(!authorize(role, METHOD_POST, "/api/v1/backup/import"));
            assert!(!authorize(role, 4 /* PUT */, "/api/v1/config"));
            assert!(!authorize(role, METHOD_GET, "/api/v1/masks/signing-key"));
        }
    }
    #[test]
    fn dispatch_get_clients_as_admin_returns_200_and_json_array() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        add_client(
            &c,
            AddClientArgs {
                name: "frank".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/clients", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }
    #[test]
    fn dispatch_get_missing_client_by_id_is_404() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/clients/does-not-exist", &[]);
        assert_eq!(status, 404);
        assert!(body.is_empty());
    }
    #[test]
    fn dispatch_get_existing_client_by_id_returns_200() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "gina".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let (status, body) = dispatch(&c, METHOD_GET, &path, &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["id"], created.id);
        assert!(
            parsed.get("psk").is_none(),
            "PSK must never appear in a tunnel dispatch response"
        );
    }
    #[test]
    fn dispatch_unknown_path_is_404() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let (status, _) = dispatch(&c, METHOD_GET, "/api/v1/nope", &[]);
        assert_eq!(status, 404);
        let (status, _) = dispatch(&c, METHOD_POST, "/api/v1/backup/import", &[]);
        assert_eq!(status, 404);
    }
    #[test]
    fn dispatch_patch_client_ignores_role_field_in_body() {
        // Even though the JSON body claims `"role":"admin"`, the tunnel
        // PATCH path must never honor it — `TunnelPatchClientRequest` has
        // no `role` field at all, so serde silently drops the key and
        // `UpdateClientArgs.role` is always `None` on this path.
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "hank".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let body = br#"{"role":"admin","enabled":false}"#;
        let (status, resp_body) = dispatch(&c, METHOD_PATCH, &path, body);
        assert_eq!(status, 200);
        let updated: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(
            updated["role"], "user",
            "role must stay unchanged via the tunnel PATCH path, even when the body claims otherwise"
        );
        assert_eq!(
            updated["enabled"], false,
            "non-role fields must still apply"
        );
    }
    #[test]
    fn dispatch_post_clients_creates_and_returns_201() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let body = br#"{"name":"ivy","one_time":false}"#;
        let (status, resp_body) = dispatch(&c, METHOD_POST, "/api/v1/clients", body);
        assert_eq!(status, 201);
        let view: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(view["name"], "ivy");
        assert_eq!(list_clients(&c).len(), 1);
    }
    #[test]
    fn dispatch_delete_client_returns_204_and_removes_it() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "jack".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let (status, body) = dispatch(&c, METHOD_DELETE, &path, &[]);
        assert_eq!(status, 204);
        assert!(body.is_empty());
        assert!(list_clients(&c).is_empty());
    }
    #[test]
    fn dispatch_audit_log_status_matches_ctx_configuration() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        // `ctx()` leaves `audit_log_path` as `None` — the same "not
        // configured" state `MgmtError::NotFound` maps to `404` for.
        let (status, _) = dispatch(&c, METHOD_GET, "/api/v1/audit-log", &[]);
        assert_eq!(status, 404);
    }
    /// P1.2b regression: with a populated `MgmtCtx` (the `ctx()` fixture
    /// already sets `server_pub_key`/`server_addr`, the same "keys set"
    /// state `GatewayConfig::mgmt_server_addr` gives `dispatch_mgmt_request`
    /// once `main.rs` threads it through), the in-tunnel
    /// `GET .../connection-key` route must return `200` with a real
    /// `aivpn://` connection key — not the `503 Unavailable` it degraded to
    /// before `server_addr` was wired onto `GatewayConfig`.
    #[test]
    fn dispatch_connection_key_returns_200_with_aivpn_uri() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "erin".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}/connection-key", created.id);
        let (status, body) = dispatch(&c, METHOD_GET, &path, &[]);
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON body");
        let key = json["connection_key"]
            .as_str()
            .expect("response has string 'connection_key'");
        assert!(
            key.starts_with("aivpn://"),
            "connection key must start with aivpn:// scheme, got: {}",
            key
        );
    }
    /// P1.2b regression: with `audit_log_path` set to a real (even empty)
    /// file — the same populated state `GatewayConfig::audit_log_path`
    /// gives `dispatch_mgmt_request` once `main.rs` threads it through —
    /// the in-tunnel `GET /api/v1/audit-log` route must return `200` with a
    /// JSON array body, not the `404 NotFound` it degraded to before
    /// `audit_log_path` was wired onto `GatewayConfig`.
    #[test]
    fn dispatch_audit_log_returns_200_when_path_configured() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let audit_dir = tempfile::tempdir().unwrap();
        let audit_log_path = audit_dir.path().join("audit.jsonl");
        std::fs::write(&audit_log_path, b"").expect("create empty audit log file");

        let mut c = ctx(&db, &mask_dir);
        c.audit_log_path = Some(&audit_log_path);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/audit-log", &[]);
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON body");
        assert!(
            json.as_array().expect("body is a JSON array").is_empty(),
            "empty audit log file should decode to an empty entries array"
        );
    }
    #[test]
    fn authorize_revoke_route_is_admin_only() {
        let path = "/api/v1/clients/abc/revoke";
        assert!(
            !authorize(ROLE_USER, METHOD_POST, path),
            "User must be denied the revoke route"
        );
        assert!(
            !authorize(ROLE_VIEWER, METHOD_POST, path),
            "Viewer (read-only) must be denied the revoke route"
        );
        assert!(
            authorize(ROLE_ADMIN, METHOD_POST, path),
            "Admin must be allowed the revoke route"
        );
    }
    #[test]
    fn dispatch_revoke_returns_204_and_tombstones() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "mona".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}/revoke", created.id);
        let (status, body) = dispatch(&c, METHOD_POST, &path, &[]);
        assert_eq!(status, 204);
        assert!(body.is_empty());
        assert!(list_clients(&c).is_empty());
    }
    #[test]
    fn dispatch_revoke_missing_client_is_404() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let (status, _) = dispatch(&c, METHOD_POST, "/api/v1/clients/nope/revoke", &[]);
        assert_eq!(status, 404);
    }
    #[test]
    fn revoke_target_identifies_the_revoke_route_only() {
        assert_eq!(
            revoke_target(METHOD_POST, "/api/v1/clients/abc/revoke"),
            Some("abc".to_string())
        );
        assert_eq!(revoke_target(METHOD_DELETE, "/api/v1/clients/abc"), None);
        assert_eq!(revoke_target(METHOD_GET, "/api/v1/clients"), None);
        assert_eq!(
            revoke_target(METHOD_POST, "/api/v1/clients/abc/reset-device"),
            None
        );
    }
    #[test]
    fn authorize_config_apply_and_confirm_are_admin_only() {
        for path in ["/api/v1/config/apply", "/api/v1/config/confirm"] {
            assert!(
                !authorize(ROLE_USER, METHOD_POST, path),
                "User must be denied {}",
                path
            );
            assert!(
                !authorize(ROLE_VIEWER, METHOD_POST, path),
                "Viewer (read-only) must be denied {}",
                path
            );
            assert!(
                authorize(ROLE_ADMIN, METHOD_POST, path),
                "Admin must be allowed {}",
                path
            );
        }
    }
    #[test]
    fn dispatch_config_apply_then_confirm_round_trip() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        setup_mask_file(&mask_dir, "steam-udp");
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "quentin".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let apply_body =
            serde_json::to_vec(&serde_json::json!({"client": created.id, "mask": "steam-udp"}))
                .unwrap();
        let (status, body) = dispatch(&c, METHOD_POST, "/api/v1/config/apply", &apply_body);
        assert_eq!(status, 200);
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = resp["token"].as_str().unwrap().to_string();
        assert_eq!(resp["applied"], true);

        let confirm_body = serde_json::to_vec(&serde_json::json!({"token": token})).unwrap();
        let (status, body) = dispatch(&c, METHOD_POST, "/api/v1/config/confirm", &confirm_body);
        assert_eq!(status, 204);
        assert!(body.is_empty());
        assert!(pending.is_empty());
    }
    /// UNLIKE `role` (see `dispatch_patch_client_ignores_role_field_in_body`),
    /// `exit_node` MUST be settable over the tunnel PATCH path — it's a
    /// routing preference, not a privilege escalation.
    #[test]
    fn dispatch_patch_client_sets_exit_node_over_tunnel() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "sam".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let body = br#"{"exit_node":"exit.example.com:51820"}"#;
        let (status, resp_body) = dispatch(&c, METHOD_PATCH, &path, body);
        assert_eq!(status, 200);
        let updated: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(updated["exit_node"], "exit.example.com:51820");

        // null clears it back to "fall back to the global default".
        let clear_body = br#"{"exit_node":null}"#;
        let (status2, resp_body2) = dispatch(&c, METHOD_PATCH, &path, clear_body);
        assert_eq!(status2, 200);
        let updated2: serde_json::Value = serde_json::from_slice(&resp_body2).unwrap();
        assert!(updated2["exit_node"].is_null());
    }
    #[test]
    fn dispatch_patch_client_rejects_malformed_exit_node() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "tara".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let path = format!("/api/v1/clients/{}", created.id);
        let body = br#"{"exit_node":"not-a-valid-addr"}"#;
        let (status, _) = dispatch(&c, METHOD_PATCH, &path, body);
        assert_eq!(status, 400);
    }
    /// `POST /api/v1/config/apply` is the SAME curated route for every
    /// `HeavySetting` (v1 `ActiveMask` and Wave B2a `ExitNode` alike) — see
    /// `classify_route`/`authorize`, which never inspect the request body.
    /// `authorize_config_apply_and_confirm_are_admin_only` already proves
    /// Admin-only for this exact route; this test additionally exercises
    /// `dispatch` end-to-end with an `exit_node` body to confirm the
    /// ExitNode heavy op is actually reachable through it.
    #[test]
    fn dispatch_config_apply_exit_node_is_reachable_and_gated_admin_only() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(&config_path, br#"{}"#).unwrap();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        assert!(authorize(ROLE_ADMIN, METHOD_POST, "/api/v1/config/apply"));
        assert!(!authorize(ROLE_VIEWER, METHOD_POST, "/api/v1/config/apply"));
        assert!(!authorize(ROLE_USER, METHOD_POST, "/api/v1/config/apply"));

        let body = serde_json::to_vec(&serde_json::json!({"exit_node": "9.9.9.9:51820"})).unwrap();
        let (status, resp_body) = dispatch(&c, METHOD_POST, "/api/v1/config/apply", &body);
        assert_eq!(status, 200);
        let resp: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(resp["applied"], true);

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(written["pool"]["exit_node"], "9.9.9.9:51820");
    }
    /// `GET /api/v1/pool/nodes` with `ctx.pool == None` (no pool sync
    /// configured on this node) must degrade to `200` + an empty array —
    /// never a 404/500.
    #[test]
    fn dispatch_pool_nodes_returns_200_empty_when_ctx_pool_none() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx_with_pool(&db, &mask_dir, None);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/nodes", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, serde_json::json!([]));
    }
    /// `GET /api/v1/pool/health` with `ctx.pool == None` must degrade to
    /// `200` + `transport: "none"`, not an error.
    #[test]
    fn dispatch_pool_health_returns_200_transport_none_when_ctx_pool_none() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx_with_pool(&db, &mask_dir, None);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/health", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["transport"], "none");
        assert_eq!(parsed["total_nodes"], 0);
    }
    /// `GET /api/v1/pool/links` with `ctx.pool == None` must degrade to
    /// `200` + an empty array.
    #[test]
    fn dispatch_pool_links_returns_200_empty_when_ctx_pool_none() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx_with_pool(&db, &mask_dir, None);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/links", &[]);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, serde_json::json!([]));
    }
    /// With a real `Some(PoolSnapshot)` wired in, `dispatch` returns exactly
    /// that snapshot's field, sliced per-route — confirms the three routes
    /// actually read `ctx.pool` rather than always degrading.
    #[test]
    fn dispatch_pool_routes_return_populated_snapshot_when_ctx_pool_is_some() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let snapshot = build_pool_snapshot(PoolSnapshotInputs {
            peers: &["peer-z:443".to_string()],
            registry_nodes: &[("peer-z:443".to_string(), [3u8; 32])],
            revoked: &[],
            statuses: &[(
                "peer-z:443".to_string(),
                sample_status(true, true, Some(42), Some(42)),
            )],
            transport: "masked",
        });
        let c = ctx_with_pool(&db, &mask_dir, Some(snapshot));

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/nodes", &[]);
        assert_eq!(status, 200);
        let nodes: Vec<PoolNodeInfo> = serde_json::from_slice(&body).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "peer-z:443");
        assert!(nodes[0].verified);
        assert!(nodes[0].connected);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/health", &[]);
        assert_eq!(status, 200);
        let health: PoolHealth = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.transport, "masked");
        assert_eq!(health.connected_peers, 1);

        let (status, body) = dispatch(&c, METHOD_GET, "/api/v1/pool/links", &[]);
        assert_eq!(status, 200);
        let links: Vec<PoolLinkInfo> = serde_json::from_slice(&body).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].peer, "peer-z:443");
        assert!(links[0].converged);
    }
    /// Viewer (read-only) must be allowed on all three GET pool routes —
    /// they fall out of the existing "Viewer = GET only" rule automatically,
    /// this just confirms the allowlist entries actually classify.
    #[test]
    fn authorize_viewer_allowed_on_pool_get_routes() {
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/pool/nodes"));
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/pool/health"));
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/pool/links"));
    }
    /// Admin is allowed too (Admin = every curated route).
    #[test]
    fn authorize_admin_allowed_on_pool_get_routes() {
        assert!(authorize(ROLE_ADMIN, METHOD_GET, "/api/v1/pool/nodes"));
        assert!(authorize(ROLE_ADMIN, METHOD_GET, "/api/v1/pool/health"));
        assert!(authorize(ROLE_ADMIN, METHOD_GET, "/api/v1/pool/links"));
    }
    /// User (no management access) is denied on all three, same as every
    /// other curated route.
    #[test]
    fn authorize_user_denied_on_pool_get_routes() {
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/pool/nodes"));
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/pool/health"));
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/pool/links"));
    }
    /// Pool routes are GET-only over the tunnel (read-only by design) —
    /// even Admin gets no POST/PATCH/DELETE on `/api/v1/pool/*` since no
    /// such route exists in `classify_route`'s allowlist at all.
    #[test]
    fn authorize_pool_routes_reject_non_get_methods_for_every_role() {
        for role in [ROLE_USER, ROLE_VIEWER, ROLE_ADMIN] {
            assert!(!authorize(role, METHOD_POST, "/api/v1/pool/nodes"));
            assert!(!authorize(role, METHOD_PATCH, "/api/v1/pool/health"));
            assert!(!authorize(role, METHOD_DELETE, "/api/v1/pool/links"));
        }
    }
    /// G-A3: `GET /api/v1/masks` classifies and is a read-only route —
    /// Viewer+Admin may GET (falls out of "Viewer = GET only"), User denied,
    /// and no mutating method exists over the tunnel.
    #[test]
    fn authorize_masks_list_is_read_only_route() {
        assert!(matches!(
            classify_route(METHOD_GET, "/api/v1/masks"),
            Some(Route::MasksList)
        ));
        assert!(authorize(ROLE_VIEWER, METHOD_GET, "/api/v1/masks"));
        assert!(authorize(ROLE_ADMIN, METHOD_GET, "/api/v1/masks"));
        assert!(!authorize(ROLE_USER, METHOD_GET, "/api/v1/masks"));
        for role in [ROLE_USER, ROLE_VIEWER, ROLE_ADMIN] {
            assert!(!authorize(role, METHOD_POST, "/api/v1/masks"));
            assert!(!authorize(role, METHOD_DELETE, "/api/v1/masks"));
        }
    }
    /// `list_mask_files` lists `*.json` profiles with the REST `MaskInfo`
    /// shape (id/file/size_bytes/modified/generated), reads the `generated`
    /// flag, sorts by id, and ignores non-JSON entries.
    #[test]
    fn list_mask_files_shapes_and_filters_entries() {
        let dir = std::env::temp_dir().join(format!("aivpn-mask-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("zeta.json"), br#"{"generated":true}"#).unwrap();
        std::fs::write(dir.join("alpha.json"), br#"{"foo":1}"#).unwrap();
        std::fs::write(dir.join("notes.txt"), b"ignore me").unwrap();
        let masks = list_mask_files(&dir);
        assert_eq!(masks.len(), 2, "only *.json counted");
        assert_eq!(masks[0]["id"].as_str(), Some("alpha"), "sorted by id");
        assert_eq!(masks[0]["file"].as_str(), Some("alpha.json"));
        assert_eq!(masks[0]["generated"].as_bool(), Some(false));
        assert_eq!(masks[1]["id"].as_str(), Some("zeta"));
        assert_eq!(masks[1]["generated"].as_bool(), Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
