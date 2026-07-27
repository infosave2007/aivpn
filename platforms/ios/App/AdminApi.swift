import Foundation

// Swift wrapper around the in-tunnel management API (Phase A in-app admin).
//
// ARCHITECTURE NOTE — why role/mgmt go over provider IPC, not the C FFI:
// on iOS the tunnel session runs in the Network Extension PROCESS
// (AivpnTunnel target), which links its own copy of libaivpn_core.a. This
// app target links a SEPARATE copy (for bootstrap-descriptor verification,
// QR rendering, and the SSH installer), whose process-globals never see a
// session: calling `aivpn_get_role()` here always returns 0 and
// `aivpn_mgmt_request` always returns -1 ("no active tunnel session").
// So the session-bound surface is routed to the extension process via
// `VPNManager.mgmtRequest` / the get_traffic "role" field (see
// PacketTunnelProvider's "mgmt_request" handler), while the STATELESS
// `aivpn_qr_png` is still called in-process below (declared in
// App/AivpnCoreBridge.h, which #includes the whole aivpn_core.h).
//
// Wire schema below is transcribed from the SERVER side that answers these
// calls (crates/aivpn-server/src/mgmt_service.rs — `ClientView`,
// `TunnelAddClientRequest`, `TunnelPatchClientRequest`, `StatusView`,
// `AuditEntry`, `classify_route`/`dispatch`), not guessed. The
// connection-key response field is `"connection_key"` (unified across the
// tunnel dispatch and the REST handler).

// MARK: - Response models (mirror mgmt_service.rs's `Serialize` views)

/// Mirrors `crate::qos::ClientQos`.
struct AdminClientQos: Codable {
    let bandwidth_limit_up: UInt64?
    let bandwidth_limit_down: UInt64?
    let dscp_class: UInt8?
    let priority: UInt8?
}

/// Mirrors `client_db::ClientStats`.
struct AdminClientStats: Codable {
    let bytes_in: UInt64
    let bytes_out: UInt64
    let last_connected: String?
    let total_connections: UInt64
    let last_handshake: String?
}

/// Mirrors `mgmt_service::ClientView` (the PSK-stripped client shape).
/// `created_at`/`expires_at`/`stats.last_*` are RFC3339 strings (chrono's
/// default `Serialize` for `DateTime<Utc>`) — kept as raw `String` here
/// rather than decoded to `Date`, formatted for display with
/// `ISO8601DateFormatter` where needed, so a decode-strategy mismatch can
/// never make the whole client list fail to parse.
struct AdminClient: Identifiable, Codable, Equatable {
    let id: String
    let name: String
    let vpn_ip: String
    let enabled: Bool
    let one_time: Bool
    let device_bound: Bool
    let created_at: String
    let stats: AdminClientStats
    let qos: AdminClientQos?
    let expires_at: String?
    /// `ClientRole` is `#[serde(rename_all = "lowercase")]` server-side:
    /// "user" | "viewer" | "admin".
    let role: String
    /// Wave B2a: this client's per-client exit-node override (`host:port`),
    /// or `nil` to fall back to the server's global default
    /// (`pool.exit_node`). Mirrors `ClientView::exit_node`.
    let exit_node: String?

    static func == (lhs: AdminClient, rhs: AdminClient) -> Bool { lhs.id == rhs.id }
}

/// Mirrors `mgmt_service::StatusView`.
struct AdminStatus: Codable {
    let clients_total: Int
    let clients_enabled: Int
    let kernel_module: Bool
}

// MARK: - Pool topology models (Wave B1, mirror mgmt_service.rs's
// `PoolNodeInfo`/`PoolLinkInfo`/`PoolHealth`, returned by
// `GET /api/v1/pool/{nodes,health,links}`).

/// Mirrors `mgmt_service::PoolNodeInfo`. `node_id` is always populated
/// (falling back server-side to the address string when no crypto
/// identity is bound) so it's safe to use as `Identifiable`'s `id`.
struct AdminPoolNode: Identifiable, Codable {
    let node_id: String
    let address: String?
    let verified: Bool
    let revoked: Bool
    let connected: Bool
    let last_seen_unix: Int64?

    var id: String { node_id }
}

/// Mirrors `mgmt_service::PoolLinkInfo`.
struct AdminPoolLink: Identifiable, Codable {
    let peer: String
    let connected: Bool
    let converged: Bool
    let last_converged_unix: Int64?
    let partition_conflict: Bool
    let subnet_mismatch: Bool

    var id: String { peer }
}

/// Mirrors `mgmt_service::PoolHealth`. `transport` is `"masked"` |
/// `"legacy"` | `"none"` — see that field's doc comment server-side.
struct AdminPoolHealth: Codable {
    let transport: String
    let total_nodes: Int
    let connected_peers: Int
    let converged_peers: Int
    let diverged: Bool
    let partition_conflict: Bool
    let subnet_mismatch: Bool
}

/// Mirrors `audit_log::AuditEntry`. `AuditActor` IS `#[serde(rename_all =
/// "snake_case")]` (verified in crates/aivpn-server/src/audit_log.rs), so
/// `actor` serializes lowercase: "cli" | "api" | "system" — NOT the
/// capitalized Rust variant names.
struct AdminAuditEntry: Codable, Identifiable {
    let ts: String
    let actor: String
    let action: String
    let target: String
    let result: String
    let prev_hash: String
    let hash: String

    var id: String { hash.isEmpty ? "\(ts)-\(action)-\(target)" : hash }
}

/// Mirrors `mgmt_service::AuditVerifyView` (`GET .../audit-log?verify=1`'s
/// response shape — `{ entries, verified, broken_at }`). `broken_at` is the
/// tail-window index (0-based, oldest-first, matching `entries`) where
/// `audit_log::verify_chain` detected a hash-chain break, or `nil` when the
/// returned window verified clean; see that field's doc comment
/// server-side for the tail-window caveat (it verifies only the returned
/// window, not the whole on-disk log, when `limit` didn't cover it).
struct AdminAuditLogResult: Codable {
    let entries: [AdminAuditEntry]
    let verified: Bool
    let brokenAt: Int?

    enum CodingKeys: String, CodingKey {
        case entries
        case verified
        case brokenAt = "broken_at"
    }
}

/// Mirrors the tunnel dispatch's `GET .../connection-key` body:
/// `json_response(200, &serde_json::json!({ "connection_key": key }))`
/// (unified with the REST handler's field name).
private struct AdminConnectionKeyResponse: Codable {
    let key: String
    enum CodingKeys: String, CodingKey {
        case key = "connection_key"
    }
}

// MARK: - Apply-with-rollback config models (Wave 2 / G-A3, mirror
// mgmt_service.rs's `ApplyResponse` and management_api.rs's `MaskInfo`)

/// Mirrors `management_api.rs::MaskInfo` (the `GET /api/v1/masks` REST
/// response shape). `modified` is `Option<DateTime<Utc>>` server-side,
/// kept as a raw RFC3339 `String?` here for the same reason
/// `AdminClient`'s date fields are — a decode-strategy mismatch must never
/// fail the whole list.
struct AdminMaskInfo: Identifiable, Codable {
    let id: String
    let file: String
    let size_bytes: UInt64
    let modified: String?
    let generated: Bool
}

/// Mirrors `mgmt_service::ApplyResponse` (`POST /api/v1/config/apply`'s
/// response body). `token` must be handed to `AdminApi.confirmConfig`
/// within the server's rollback window (`pending_config::
/// PENDING_CONFIG_TIMEOUT` — 120s at time of writing) or the gateway's
/// sweep task silently reverts the write.
struct AdminApplyResponse: Codable {
    let token: String
    let applied: Bool
}

// MARK: - Errors

enum AdminApiError: LocalizedError, Equatable {
    /// `aivpn_mgmt_request` returned -1: no active tunnel session, the
    /// control channel is closed, or the call timed out (10s).
    case transport
    /// A non-2xx HTTP-style status came back from the server (e.g. 403
    /// role-not-authorized, 404 not found, 409 duplicate name).
    case http(status: UInt16)
    /// The response body wasn't the JSON shape expected.
    case decode

    var errorDescription: String? {
        switch self {
        case .transport:
            return "Not connected, or the request timed out"
        case .http(let status):
            return "Server returned status \(status)"
        case .decode:
            return "Failed to decode the server response"
        }
    }
}

/// Tri-state value for a PATCH field that supports being explicitly
/// cleared (serialized as JSON `null`) vs left untouched (key omitted
/// entirely) — mirrors `TunnelPatchClientRequest`'s `deserialize_opt_opt`
/// double-`Option` fields (`qos`, `expires_at`) on the server.
enum AdminPatchField<T> {
    case unchanged
    case clear
    case set(T)
}

// MARK: - AdminApi

/// Stateless namespace for the in-tunnel management API. Management calls
/// go over provider IPC to the tunnel extension (see the file header);
/// the stateless `aivpn_qr_png` FFI is still called in-process, hopping
/// off the caller's thread via `Task.detached` since it can block.
/// Callers (SwiftUI views) are responsible for hopping back to the main
/// actor before mutating `@State`/`@Published` UI state with the result.
enum AdminApi {
    /// Buffer convention for the in-process `aivpn_qr_png` call (see
    /// aivpn_core.h): the return value is either the number of bytes
    /// written (<= capacity passed in), or — when the response didn't fit
    /// — the needed length (> capacity passed in, buffer left untouched),
    /// or -1 on error/timeout.
    private static let initialBufferCapacity = 64 * 1024

    private struct RawResponse {
        let status: UInt16
        let body: Data
    }

    // MARK: Role

    /// Current server-assigned role (0=User, 1=Viewer, 2=Admin), cached
    /// from the last `Capabilities` control message this session — as
    /// polled from the TUNNEL EXTENSION process via get_traffic
    /// (`VPNManager.adminRole`), NOT this process's `aivpn_get_role()`,
    /// which reads a different copy of the core that never has a session
    /// and would always return 0 (see this file's header comment). Cheap;
    /// main-thread callers only (SwiftUI `body`/actions — every current
    /// call site), matching `VPNManager`'s own threading rules.
    static func role() -> UInt8 {
        VPNManager.shared.adminRole
    }

    // MARK: QR

    /// Renders `text` (an `aivpn://...` connection key) as a QR code PNG.
    /// Blocks internally — call from an async context.
    static func qrPngData(_ text: String) async -> Data? {
        await Task.detached(priority: .userInitiated) {
            qrPngDataBlocking(text)
        }.value
    }

    private static func qrPngDataBlocking(_ text: String) -> Data? {
        var cap = initialBufferCapacity
        // One retry with the server-reported needed length, per the
        // written-len-or-needed-len convention documented on
        // aivpn_qr_png in aivpn_core.h.
        for _ in 0..<2 {
            var outBuf = [UInt8](repeating: 0, count: cap)
            let written: Int = text.withCString { textPtr in
                outBuf.withUnsafeMutableBufferPointer { outBufPtr in
                    aivpn_qr_png(textPtr, outBufPtr.baseAddress, outBufPtr.count)
                }
            }
            if written < 0 { return nil }
            if written <= cap {
                return Data(outBuf.prefix(written))
            }
            cap = written
        }
        return nil
    }

    // MARK: Low-level mgmt request

    /// Routes the call to the TUNNEL EXTENSION process over provider IPC
    /// (see this file's header comment for why the in-process
    /// `aivpn_mgmt_request` FFI can never work from the app) and suspends
    /// until its reply arrives. The extension side enforces the FFI's own
    /// 10s timeout and its 64KB-then-needed-length buffer retry; a
    /// not-connected tunnel or an extension-reported transport failure
    /// resolves to `nil` (mapped to `.transport` by the callers below).
    private static func request(method: UInt8, path: String, body: Data = Data()) async -> RawResponse? {
        await withCheckedContinuation { continuation in
            // VPNManager's IPC surface is main-thread-only (it precondition-
            // checks the main queue); hop there before touching it.
            DispatchQueue.main.async {
                VPNManager.shared.mgmtRequest(method: method, path: path, body: body) { resp in
                    continuation.resume(returning: resp.map { RawResponse(status: $0.status, body: $0.body) })
                }
            }
        }
    }

    // MARK: JSON helpers

    private static func jsonBody(_ dict: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: dict)) ?? Data()
    }

    private static func getJSON<T: Decodable>(_ path: String) async -> Result<T, AdminApiError> {
        await sendJSON(method: 0, path: path, body: Data())
    }

    private static func sendJSON<T: Decodable>(method: UInt8, path: String, body: Data) async -> Result<T, AdminApiError> {
        guard let resp = await request(method: method, path: path, body: body) else {
            return .failure(.transport)
        }
        guard (200...299).contains(Int(resp.status)) else {
            return .failure(.http(status: resp.status))
        }
        guard let decoded = try? JSONDecoder().decode(T.self, from: resp.body) else {
            return .failure(.decode)
        }
        return .success(decoded)
    }

    private static func sendNoContent(method: UInt8, path: String, body: Data = Data()) async -> Result<Void, AdminApiError> {
        guard let resp = await request(method: method, path: path, body: body) else {
            return .failure(.transport)
        }
        guard (200...299).contains(Int(resp.status)) else {
            return .failure(.http(status: resp.status))
        }
        return .success(())
    }

    // MARK: Curated client-management calls (crates/aivpn-server/src/mgmt_service.rs)

    static func listClients() async -> Result<[AdminClient], AdminApiError> {
        await getJSON("/api/v1/clients")
    }

    static func getClient(id: String) async -> Result<AdminClient, AdminApiError> {
        await getJSON("/api/v1/clients/\(id.pathEncoded)")
    }

    /// `POST /api/v1/clients`. `expiresAt == nil` means no expiry (the key
    /// is simply omitted — `TunnelAddClientRequest.expires_at` is a plain
    /// `Option<DateTime<Utc>>`, implicitly `None` when the JSON key is
    /// absent). Role assignment is never accepted over this path — the
    /// server silently drops a `role` key even if sent (see
    /// `TunnelAddClientRequest`'s doc comment) — so it is not offered here.
    static func addClient(name: String, oneTime: Bool, expiresAt: Date?) async -> Result<AdminClient, AdminApiError> {
        var dict: [String: Any] = ["name": name, "one_time": oneTime]
        if let expiresAt {
            dict["expires_at"] = iso8601.string(from: expiresAt)
        }
        return await sendJSON(method: 1, path: "/api/v1/clients", body: jsonBody(dict))
    }

    /// `PATCH /api/v1/clients/:id`. Every parameter defaults to
    /// "unchanged" (key omitted) so callers only need to pass the fields
    /// they're actually editing. `expiresAt: .clear` sends an explicit
    /// JSON `null` to clear the expiry. `role` is never settable over the
    /// tunnel (server-side `TunnelPatchClientRequest` has no `role` field
    /// at all) — there is intentionally no parameter for it here.
    /// `exitNode: .clear` sends an explicit JSON `null` to fall back to
    /// the server's global default (`pool.exit_node`); UNLIKE `role`,
    /// `exit_node` IS settable over the tunnel (Wave B2a — see
    /// `TunnelPatchClientRequest::exit_node`'s doc comment server-side: a
    /// routing preference, not a privilege escalation).
    static func patchClient(
        id: String,
        name: String? = nil,
        enabled: Bool? = nil,
        oneTime: Bool? = nil,
        expiresAt: AdminPatchField<Date> = .unchanged,
        exitNode: AdminPatchField<String> = .unchanged
    ) async -> Result<AdminClient, AdminApiError> {
        var dict: [String: Any] = [:]
        if let name { dict["name"] = name }
        if let enabled { dict["enabled"] = enabled }
        if let oneTime { dict["one_time"] = oneTime }
        switch expiresAt {
        case .unchanged:
            break
        case .clear:
            dict["expires_at"] = NSNull()
        case .set(let date):
            dict["expires_at"] = iso8601.string(from: date)
        }
        switch exitNode {
        case .unchanged:
            break
        case .clear:
            dict["exit_node"] = NSNull()
        case .set(let addr):
            dict["exit_node"] = addr
        }
        return await sendJSON(method: 2, path: "/api/v1/clients/\(id.pathEncoded)", body: jsonBody(dict))
    }

    /// `DELETE /api/v1/clients/:id` — plain tombstone, 204 on success.
    /// Prefer `revokeClient(id:)` from the admin UI (distinct audit action
    /// + immediate session teardown side effects server-side); this is
    /// kept for completeness.
    static func deleteClient(id: String) async -> Result<Void, AdminApiError> {
        await sendNoContent(method: 3, path: "/api/v1/clients/\(id.pathEncoded)")
    }

    /// `POST /api/v1/clients/:id/revoke` — tombstones the client, records
    /// a `ClientRevoke` audit entry (distinct from a plain DELETE), and
    /// (server-side, in the gateway) forces any live session for this
    /// client to disconnect. 204 on success.
    static func revokeClient(id: String) async -> Result<Void, AdminApiError> {
        await sendNoContent(method: 1, path: "/api/v1/clients/\(id.pathEncoded)/revoke")
    }

    /// `POST /api/v1/clients/:id/reset-device` — clears the client's
    /// bound device key and re-enables one-time enrollment. 204 on
    /// success.
    static func resetDevice(id: String) async -> Result<Void, AdminApiError> {
        await sendNoContent(method: 1, path: "/api/v1/clients/\(id.pathEncoded)/reset-device")
    }

    /// `GET /api/v1/clients/:id/connection-key` → the freshly-issued
    /// `aivpn://...` connection key string.
    static func connectionKey(id: String) async -> Result<String, AdminApiError> {
        let result: Result<AdminConnectionKeyResponse, AdminApiError> =
            await getJSON("/api/v1/clients/\(id.pathEncoded)/connection-key")
        return result.map { $0.key }
    }

    static func status() async -> Result<AdminStatus, AdminApiError> {
        await getJSON("/api/v1/status")
    }

    // MARK: Pool topology (Wave B1 — `GET /api/v1/pool/{nodes,health,links}`)

    /// `GET /api/v1/pool/nodes` — always `200` with an empty array when
    /// pool sync isn't configured on this node (never an error condition,
    /// see `mgmt_service.rs`'s `Route::PoolNodes` doc comment).
    static func poolNodes() async -> Result<[AdminPoolNode], AdminApiError> {
        await getJSON("/api/v1/pool/nodes")
    }

    /// `GET /api/v1/pool/health` — degrades to `transport: "none"` (all
    /// counts zero) rather than erroring when pool sync isn't configured.
    static func poolHealth() async -> Result<AdminPoolHealth, AdminApiError> {
        await getJSON("/api/v1/pool/health")
    }

    /// `GET /api/v1/pool/links` — one entry per dialed peer this node has
    /// ever observed sync state for; always `200` with an empty array when
    /// there's no live `PoolDialer`.
    static func poolLinks() async -> Result<[AdminPoolLink], AdminApiError> {
        await getJSON("/api/v1/pool/links")
    }

    /// `GET /api/v1/audit-log?limit=N&verify=1` (server clamps `limit` to
    /// `[1, MAX_AUDIT_LIMIT]`, defaults if unparsable; `verify=1` switches
    /// the response shape from a plain array to `AuditVerifyView`, adding
    /// hash-chain verification of the returned window — see
    /// `AdminAuditLogResult`'s doc comment). Available to Viewer and Admin
    /// alike — `authorize()` allows every GET route to Viewer role.
    static func auditLog(limit: Int = 100) async -> Result<AdminAuditLogResult, AdminApiError> {
        await getJSON("/api/v1/audit-log?limit=\(limit)&verify=1")
    }

    // MARK: Apply-with-rollback config (Wave 2 / G-A3 — mgmt_service.rs's
    // "Apply-with-rollback for heavy config" section: `POST
    // /api/v1/config/{apply,confirm}`, dispatched over the SAME curated
    // tunnel allowlist as every other call here — `classify_route` maps
    // `(POST, ["config","apply"])`/`(POST, ["config","confirm"])` to
    // `Route::ConfigApply`/`Route::ConfigConfirm`, Admin-only.)

    /// `POST /api/v1/config/apply` selecting `HeavySetting::ActiveMask` —
    /// sets `client`'s per-client active-mask override to `mask` (writes
    /// `<mask_dir>/.overrides/<client-id>.mask`), LIVE, no reconnect
    /// needed. Mirrors `TunnelApplyRequest`'s "field presence, not a type
    /// tag" convention server-side: this omits the `exit_node` key
    /// entirely (never sends it, not even `null`) so the server resolves
    /// `HeavySetting::ActiveMask` from `client`/`mask` instead of
    /// `HeavySetting::ExitNode`. `client` MUST be a real, non-empty
    /// client id or name — `resolve_heavy_setting` 400s on an empty
    /// value (see that function's doc comment), there is no "server-wide"
    /// sentinel. Returns a token that must reach `confirmConfig` within
    /// the server's rollback window or the write auto-reverts.
    static func applyActiveMask(client: String, mask: String) async -> Result<AdminApplyResponse, AdminApiError> {
        let body = jsonBody(["client": client, "mask": mask])
        return await sendJSON(method: 1, path: "/api/v1/config/apply", body: body)
    }

    /// `POST /api/v1/config/apply` selecting `HeavySetting::ExitNode` —
    /// stages the server's GLOBAL default exit node (`pool.exit_node` in
    /// `server.json`), or clears it when `addr == nil`. Presence of the
    /// `exit_node` key (even as JSON `null`) is what selects this
    /// `HeavySetting` variant server-side — see `TunnelApplyRequest`'s doc
    /// comment. UNLIKE the per-client exit-node PATCH
    /// (`AdminApi.patchClient(exitNode:)`), this does NOT take effect
    /// live: `pool.exit_node` is only read at server startup, so the new
    /// value applies after the next server restart (see
    /// `HeavySetting::ExitNode`'s doc comment server-side). Returns a
    /// token that must reach `confirmConfig` within the server's rollback
    /// window or the write auto-reverts.
    static func applyGlobalExitNode(_ addr: String?) async -> Result<AdminApplyResponse, AdminApiError> {
        // `addr ?? NSNull()` does not type-check here (`String?` and
        // `NSNull` don't unify under `??`) — build the dict explicitly,
        // same pattern `patchClient`'s `exitNode: .clear` branch uses.
        var dict: [String: Any] = [:]
        if let addr {
            dict["exit_node"] = addr
        } else {
            dict["exit_node"] = NSNull()
        }
        return await sendJSON(method: 1, path: "/api/v1/config/apply", body: jsonBody(dict))
    }

    /// `POST /api/v1/config/confirm` — makes a pending `applyActiveMask`/
    /// `applyGlobalExitNode` write permanent instead of letting the
    /// gateway's sweep task auto-revert it once the rollback window
    /// elapses. 204 on success.
    static func confirmConfig(token: String) async -> Result<Void, AdminApiError> {
        await sendNoContent(method: 1, path: "/api/v1/config/confirm", body: jsonBody(["token": token]))
    }

    /// `GET /api/v1/masks` — lists mask profiles on disk (mirrors
    /// `management_api.rs::list_masks`/`MaskInfo`).
    ///
    /// KNOWN GAP (verified by reading `mgmt_service.rs`'s
    /// `classify_route`, not guessed): as of this writing, `classify_route`
    /// has NO `Masks*` arm — only `Status`/`Clients*`/`AuditLog`/
    /// `ConfigApply`/`ConfigConfirm`/`Pool*` are in the curated tunnel
    /// allowlist `aivpn_mgmt_request` can reach. So this call currently
    /// always returns `.failure(.http(status: 404))` over the tunnel,
    /// for every role including Admin — `/api/v1/masks` is reachable only
    /// from the REST/web-panel path (`management_api.rs`, a DIFFERENT
    /// trust boundary iOS has no access to), not from this FFI. Kept as a
    /// correctly-typed, forward-compatible wrapper (same shape the web
    /// panel's `masks.list()` uses) for the day `classify_route` gains a
    /// `Masks` arm; callers MUST treat a failure here as expected on
    /// today's server and fall back to another mask-id source — see
    /// `ServerSettingsView.swift`'s `serverSettingsLoadMaskChoices()`,
    /// which falls back to the live session's `VPNManager.maskCatalog`
    /// (the same `mask_id`/`generated` shape, sourced from the
    /// `ControlPayload::MaskCatalog` this session already received over
    /// the control channel) when this returns empty/failed.
    static func listMasks() async -> Result<[AdminMaskInfo], AdminApiError> {
        await getJSON("/api/v1/masks")
    }

    private static let iso8601 = ISO8601DateFormatter()
}

private extension String {
    /// Percent-encodes a client id for safe interpolation into a REST
    /// path segment. Ids are server-generated (opaque tokens/UUID-like),
    /// but this is cheap insurance against a stray `/` or `?` ever
    /// corrupting the curated route match server-side.
    var pathEncoded: String {
        addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? self
    }
}
