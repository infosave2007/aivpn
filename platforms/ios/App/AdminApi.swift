import Foundation

// Swift wrapper around the in-tunnel management-API FFI surface exposed by
// aivpn-ios-core (crates/aivpn-ios-core/include/aivpn_core.h):
//   uint8_t  aivpn_get_role(void)
//   intptr_t aivpn_mgmt_request(method, path, body, body_len, out_status, out_buf, out_cap)
//   intptr_t aivpn_qr_png(text, out_buf, out_cap)
//
// These are declared in the bridging header (App/AivpnCoreBridge.h, which
// #includes the whole aivpn_core.h), so they're callable directly from
// Swift with no extra glue.
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

    static func == (lhs: AdminClient, rhs: AdminClient) -> Bool { lhs.id == rhs.id }
}

/// Mirrors `mgmt_service::StatusView`.
struct AdminStatus: Codable {
    let clients_total: Int
    let clients_enabled: Int
    let kernel_module: Bool
}

/// Mirrors `audit_log::AuditEntry`. `actor` has no `#[serde(rename_all)]`
/// on `AuditActor`, so it serializes as the plain enum-variant string:
/// "Cli" | "Api" | "System".
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

/// Mirrors the tunnel dispatch's `GET .../connection-key` body:
/// `json_response(200, &serde_json::json!({ "connection_key": key }))`
/// (unified with the REST handler's field name).
private struct AdminConnectionKeyResponse: Codable {
    let key: String
    enum CodingKeys: String, CodingKey {
        case key = "connection_key"
    }
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

/// Stateless namespace wrapping the blocking FFI calls. Every public
/// function is `async` and hops off the caller's thread via
/// `Task.detached` before touching the FFI, because
/// `aivpn_mgmt_request`/`aivpn_qr_png` block the calling thread for up to
/// ~10s. Callers (SwiftUI views) are responsible for hopping back to the
/// main actor before mutating `@State`/`@Published` UI state with the
/// result.
enum AdminApi {
    /// Buffer convention shared by `aivpn_mgmt_request`/`aivpn_qr_png`
    /// (see aivpn_core.h): the return value is either the number of bytes
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
    /// from the last `Capabilities` control message this session. Cheap —
    /// reads a process-global atomic, no FFI blocking involved. Safe to
    /// call from any thread, including the main thread.
    static func role() -> UInt8 {
        aivpn_get_role()
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

    /// Blocking FFI call — always invoked from a detached task, never
    /// directly from a SwiftUI callback. Allocates a 64KB response buffer;
    /// if the server's response doesn't fit, retries exactly once with a
    /// buffer sized to the reported needed length (see aivpn_core.h's
    /// documented convention on `aivpn_mgmt_request`).
    private static func mgmtRequestBlocking(method: UInt8, path: String, body: Data) -> RawResponse? {
        var status: UInt16 = 0
        var cap = initialBufferCapacity
        var bodyBytes = [UInt8](body)

        for _ in 0..<2 {
            var outBuf = [UInt8](repeating: 0, count: cap)
            let written: Int = path.withCString { pathPtr in
                bodyBytes.withUnsafeMutableBufferPointer { bodyBufPtr in
                    outBuf.withUnsafeMutableBufferPointer { outBufPtr in
                        aivpn_mgmt_request(
                            method,
                            pathPtr,
                            bodyBufPtr.baseAddress,
                            bodyBufPtr.count,
                            &status,
                            outBufPtr.baseAddress,
                            outBufPtr.count
                        )
                    }
                }
            }

            if written < 0 {
                return nil
            }
            if written <= cap {
                return RawResponse(status: status, body: Data(outBuf.prefix(written)))
            }
            // Needed length reported (written > cap) — retry once with a
            // buffer of exactly that size.
            cap = written
        }
        return nil
    }

    private static func request(method: UInt8, path: String, body: Data = Data()) async -> RawResponse? {
        await Task.detached(priority: .userInitiated) {
            mgmtRequestBlocking(method: method, path: path, body: body)
        }.value
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
    static func patchClient(
        id: String,
        name: String? = nil,
        enabled: Bool? = nil,
        oneTime: Bool? = nil,
        expiresAt: AdminPatchField<Date> = .unchanged
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

    /// `GET /api/v1/audit-log?limit=N` (server clamps to
    /// `[1, MAX_AUDIT_LIMIT]`, defaults if unparsable).
    static func auditLog(limit: Int = 100) async -> Result<[AdminAuditEntry], AdminApiError> {
        await getJSON("/api/v1/audit-log?limit=\(limit)")
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
