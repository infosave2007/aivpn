import Foundation

/// Bridge to the running `aivpn-client` daemon's local admin socket — the
/// channel that carries in-tunnel client-management (P3 in-app admin) calls
/// on macOS.
///
/// ARCHITECTURE NOTE (why this isn't a C FFI wrapper like iOS/Android):
/// The iOS/Android apps embed `aivpn-ios-core`/`aivpn-android-core` directly
/// in-process and expose `aivpn_mgmt_request`/`aivpn_get_role`/
/// `aivpn_qr_png` as C functions (see
/// crates/aivpn-ios-core/include/aivpn_core.h). The macOS app does **not**
/// link that static library — it never has. Per VPNManager.swift, the
/// full VPN session runs as a *separate* `aivpn-client` process, either
/// spawned by the privileged helper (root, full-tunnel) or spawned directly
/// as the console user (SOCKS5 proxy mode). There is no in-process Rust
/// core to call a C function on here.
///
/// The desktop daemon (`aivpn-client`) exposes the exact same three
/// operations — mgmt/role/qr — over a local loopback UDP socket instead
/// (127.0.0.1:44301, token-authenticated), added for exactly this purpose:
/// see crates/aivpn-client/src/record_cmd.rs's `AdminCommand` enum and the
/// admin-socket task in crates/aivpn-client/src/client.rs::run(), and the
/// `aivpn-client mgmt`/`aivpn-client role` CLI subcommands in main.rs
/// (documented there as "the surface the Windows egui / Linux iced GUIs …
/// use"). This file speaks that same wire protocol directly from Swift,
/// rather than shelling out to the CLI subcommands per call — it avoids a
/// process spawn per request and lets us decode the reply straight into
/// `Data`/`Codable` without an intermediate temp file for the request body.
///
/// Wire protocol (mirrors `send_admin_request` in
/// crates/aivpn-client/src/main.rs and `AdminCommand`/`format_mgmt_reply`/
/// `parse_mgmt_reply` in record_cmd.rs exactly):
///   - Transport: one UDP datagram out, one UDP datagram back, 127.0.0.1:44301.
///   - `"{token}:role"`                              -> `"{0|1|2}"` (bare decimal, no wrapper)
///   - `"{token}:qr:{base64(text)}"`                  -> `"{base64(png)}"` (bare, no wrapper)
///   - `"{token}:mgmt:{method}:{path}:{base64(body)}"` -> `"{status}:{base64(body)}"`
///     `method`: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT (same encoding as
///     `ControlPayload::MgmtRequest`). `status == 0` is the daemon's local
///     "call failed" sentinel (control channel closed / no reply within its
///     own 10s `mgmt_call` timeout) — never a real server status; treat it
///     as a failure exactly like the `aivpn-client mgmt` CLI does (non-zero
///     exit).
///
/// KNOWN LIMITATION — admin token readability in full-tunnel mode:
/// the token lives at `/tmp/aivpn-{uid}/admin.token` (or
/// `$XDG_RUNTIME_DIR/aivpn/admin.token` when that env var is set), where
/// `{uid}` is the *daemon's own* uid, written mode 0600 by the daemon
/// itself (crates/aivpn-client/src/record_cmd.rs::ensure_admin_token). In
/// full-tunnel mode the daemon is spawned by the privileged helper as
/// **root**, so the token lands at `/tmp/aivpn-0/admin.token`, root-owned —
/// unreadable by this GUI process, which always runs as the console user.
/// `readAdminToken()` then simply returns nil (permission denied surfaces
/// as a failed file read, not a crash), and every operation below fails
/// closed with `nil`. In SOCKS5 proxy mode (aivpn-client runs directly as
/// the console user) the token is readable and everything works. AdminView
/// must treat a nil result as "unavailable in this mode", not as an error
/// worth alarming the user over — this mirrors a real, pre-existing
/// constraint of the desktop admin-socket design, not a bug introduced
/// here, and fixing it would mean changing `admin_token_path()` in
/// crates/aivpn-client (out of scope: platforms/macos/ only).
enum AdminApi {

    // MARK: - Config

    static let socketHost = "127.0.0.1"
    static let socketPort: UInt16 = 44301
    /// Matches the FFI doc's stated bound (`aivpn_mgmt_request`: "blocks …
    /// or the call times out (10s)") so behavior is consistent with the
    /// mobile cores even though the transport differs.
    static let timeoutSeconds: Double = 10.0

    // MARK: - Role

    /// Server-assigned role: 0 = User, 1 = Viewer, 2 = Admin.
    static let roleUser: UInt8 = 0
    static let roleViewer: UInt8 = 1
    static let roleAdmin: UInt8 = 2

    // MARK: - Token resolution

    /// Mirrors `admin_token_path()` in crates/aivpn-client/src/record_cmd.rs.
    /// Windows has its own `%LOCALAPPDATA%`-based branch there that does not
    /// apply on macOS, so only the Unix branch is reproduced here.
    private static func adminTokenPath() -> String {
        if let runtimeDir = ProcessInfo.processInfo.environment["XDG_RUNTIME_DIR"],
           !runtimeDir.isEmpty {
            return runtimeDir + "/aivpn/admin.token"
        }
        return "/tmp/aivpn-\(getuid())/admin.token"
    }

    /// Reads the admin-socket auth token this GUI process's own uid can see.
    /// Returns nil if the file doesn't exist or isn't readable by us (see
    /// the "KNOWN LIMITATION" note above) — never throws.
    static func readAdminToken() -> String? {
        guard let raw = try? String(contentsOfFile: adminTokenPath(), encoding: .utf8) else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Convenience for gating UI: true only when a token is currently
    /// readable, i.e. the admin channel has a chance of working at all.
    static func adminChannelAvailable() -> Bool {
        readAdminToken() != nil
    }

    // MARK: - Low-level datagram round trip

    /// Sends `line` as a single UDP datagram to 127.0.0.1:44301 and blocks
    /// (bounded by `timeoutSeconds`) for exactly one reply datagram.
    ///
    /// BLOCKING — this performs real socket I/O with `SO_RCVTIMEO`/
    /// `SO_SNDTIMEO` set to `timeoutSeconds`, so a call can legitimately
    /// take up to that long before returning. Callers (the public functions
    /// below) MUST be invoked off the main thread; see `AdminView` for the
    /// `DispatchQueue.global` wrapping used at the call sites.
    private static func sendAdminRequest(_ line: String) -> String? {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var timeout = timeval(tv_sec: Int(timeoutSeconds), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = socketPort.bigEndian
        addr.sin_addr.s_addr = inet_addr(socketHost)

        let lineBytes = Array(line.utf8)
        let sent = lineBytes.withUnsafeBufferPointer { buf -> Int in
            withUnsafePointer(to: &addr) { addrPtr -> Int in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    sendto(fd, buf.baseAddress, buf.count, 0, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == lineBytes.count else { return nil }

        var recvBuf = [UInt8](repeating: 0, count: 65536)
        var fromAddr = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let received = withUnsafeMutablePointer(to: &fromAddr) { fromPtr -> Int in
            fromPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                recvfrom(fd, &recvBuf, recvBuf.count, 0, sockPtr, &fromLen)
            }
        }
        guard received > 0 else { return nil }
        return String(bytes: recvBuf[0..<received], encoding: .utf8)
    }

    // MARK: - Public operations (blocking — call off the main thread)

    /// Issues an in-tunnel management API call against the running daemon
    /// and blocks until the correlated reply arrives or `timeoutSeconds`
    /// elapses.
    ///
    /// - Parameters:
    ///   - method: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT.
    ///   - path: curated REST-shaped path, e.g. "/api/v1/clients".
    ///   - body: optional JSON request payload (empty Data for none).
    /// - Returns: `(status, body)` on any reply from the daemon (including
    ///   a `status == 0` local-failure sentinel — callers must check for
    ///   that explicitly, it is NOT the same as nil), or nil when the token
    ///   can't be read, the daemon never replies, or the reply is
    ///   malformed (can't happen against a well-behaved daemon, but a
    ///   third-party sending garbage to the port is possible on a shared
    ///   host, so this is treated as "no answer").
    static func mgmtRequest(method: UInt8, path: String, body: Data = Data()) -> (status: UInt16, body: Data)? {
        guard let token = readAdminToken() else { return nil }
        let bodyB64 = body.base64EncodedString()
        let line = "\(token):mgmt:\(method):\(path):\(bodyB64)"
        guard let reply = sendAdminRequest(line) else { return nil }
        guard let sep = reply.firstIndex(of: ":") else { return nil }
        let statusStr = String(reply[reply.startIndex..<sep])
        let bodyB64Reply = String(reply[reply.index(after: sep)...])
        guard let status = UInt16(statusStr) else { return nil }
        // An empty body ("status:") is valid (e.g. 204 No Content replies to
        // DELETE/revoke/reset-device) — base64 decode of "" yields Data().
        guard let bodyData = Data(base64Encoded: bodyB64Reply) else { return nil }
        return (status, bodyData)
    }

    /// Cached server-assigned role (0=User, 1=Viewer, 2=Admin) from the
    /// running daemon's last `Capabilities` control message, or nil when
    /// unreachable/no token. Mirrors `AdminCommand::Role`'s reply: a bare
    /// decimal string, no wrapper (unlike `mgmtRequest`'s `"status:body"`).
    static func role() -> UInt8? {
        guard let token = readAdminToken() else { return nil }
        guard let reply = sendAdminRequest("\(token):role") else { return nil }
        return UInt8(reply.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Renders `text` (typically an `aivpn://…` connection key) as a QR
    /// code PNG via the daemon's `qr:` admin command — the same
    /// `qrcode`-crate-backed renderer every other platform's QR view uses,
    /// so the visual result matches exactly. Mirrors `AdminCommand::Qr`:
    /// reply is the *raw* base64(PNG) string, no status wrapper. Returns
    /// nil on any failure (no token, no reply, bad base64) — the daemon
    /// itself also sends no reply at all on a PNG-encoding error (see
    /// client.rs), which surfaces here as an ordinary timeout.
    static func qrPngData(_ text: String) -> Data? {
        guard let token = readAdminToken() else { return nil }
        guard let textB64 = text.data(using: .utf8)?.base64EncodedString() else { return nil }
        guard let reply = sendAdminRequest("\(token):qr:\(textB64)") else { return nil }
        return Data(base64Encoded: reply)
    }

    // MARK: - Pool topology (Wave B3-macOS)

    /// `GET /api/v1/pool/nodes` — thin wrapper over `mgmtRequest`, same raw
    /// `(status, body)` contract. Decoding into `[AdminPoolNodeView]` happens
    /// in `AdminStore` (see PoolView.swift), keeping this file transport-only
    /// per the module doc above.
    static func poolNodes() -> (status: UInt16, body: Data)? {
        mgmtRequest(method: 0 /* GET */, path: "/api/v1/pool/nodes")
    }

    /// `GET /api/v1/pool/health` — same shape as `poolNodes()`.
    static func poolHealth() -> (status: UInt16, body: Data)? {
        mgmtRequest(method: 0 /* GET */, path: "/api/v1/pool/health")
    }

    // MARK: - Audit log (G-A2)

    /// `GET /api/v1/audit-log?verify=1&limit={limit}` — thin wrapper over
    /// `mgmtRequest`, same raw `(status, body)` contract. Always requests
    /// hash-chain verification (`verify=1`): the view always wants the
    /// `verified`/`broken_at` badge, so the response always decodes as the
    /// server's `AuditVerifyView` shape (`{entries, verified, broken_at}`),
    /// never the bare `Vec<AuditEntry>` array `GET /api/v1/audit-log`
    /// (without `?verify=1`) returns — see
    /// `crates/aivpn-server/src/mgmt_service.rs::dispatch`'s `Route::AuditLog`
    /// arm. The `?query` rides inside `path` itself: the admin-socket wire
    /// protocol only splits on `:` (see the module doc above and
    /// `crates/aivpn-client/src/record_cmd.rs::parse_admin_line`'s
    /// `splitn(3, ':')`), so a `?`-bearing path round-trips unmodified —
    /// the server's own `classify_route` is what splits `path` from
    /// `query` on `?` (`mgmt_service.rs`). Available to Viewer (1) and
    /// Admin (2): `authorize()` server-side allows every curated GET route,
    /// including `audit-log`, at Viewer.
    static func auditLog(limit: Int = 200) -> (status: UInt16, body: Data)? {
        mgmtRequest(method: 0 /* GET */, path: "/api/v1/audit-log?verify=1&limit=\(limit)")
    }

    // MARK: - Server settings apply-with-rollback (G-A3)

    /// `GET /api/v1/masks` — thin wrapper over `mgmtRequest`, same raw
    /// `(status, body)` contract as `poolNodes()`/`auditLog()` above.
    ///
    /// KNOWN GAP, verified directly against
    /// `crates/aivpn-server/src/mgmt_service.rs`: unlike `clients`/`status`/
    /// `audit-log`/`config/apply`/`config/confirm`/`pool/*`, `["masks"]` has
    /// NO arm in that file's `classify_route()` match — the masks catalog
    /// is currently a REST-only route (`management_api.rs::list_masks`,
    /// mounted at the same `/api/v1/masks` path but only reachable over the
    /// web-panel's Unix-socket REST API, not the in-tunnel admin-socket
    /// `mgmt:` command this file speaks). Calling this today therefore
    /// always fails closed — `classify_route` returns `None`, so
    /// `authorize()` denies it before `dispatch()` is ever reached,
    /// regardless of caller role — surfacing here as a non-200 `status`
    /// (or, if the gateway declines to reply to an unauthorized request at
    /// all, as `mgmtRequest` returning `nil`, the same as any other
    /// unreachable-daemon case). This wrapper is written against the wire
    /// shape the server-side task (extending `classify_route`/`dispatch`
    /// with a `Route::Masks` arm reusing `management_api::MaskInfo`) is
    /// expected to land as a natural follow-up — once that lands, this
    /// starts working with no client-side change. Callers (`ServerSettingsStore.
    /// refreshMasks()`) MUST treat any non-200 as "catalog unavailable" and
    /// fall back to manual mask-id entry, never as a hard error — see that
    /// method's doc comment.
    static func listMasks() -> (status: UInt16, body: Data)? {
        mgmtRequest(method: 0 /* GET */, path: "/api/v1/masks")
    }

    /// `POST /api/v1/config/apply` — thin wrapper over `mgmtRequest`. Body
    /// is caller-built JSON: `{"client":"<id>","mask":"<id>"}` selects the
    /// per-client active-mask `HeavySetting` (live, no restart; `client`
    /// must be a real, non-empty client id/name — `resolve_heavy_setting`
    /// 400s on an empty value, there is no server-wide sentinel);
    /// `{"exit_node": "<host:port>"|null}` selects the global default exit-node
    /// `HeavySetting` (persisted to `server.json`'s `pool.exit_node`, takes
    /// effect on the server's NEXT RESTART only — see
    /// `HeavySetting::ExitNode`'s doc comment in mgmt_service.rs). A `200`
    /// reply decodes as `{"token":"...","applied":true}`
    /// (`mgmt_service::ApplyResponse`) — the caller must POST that `token`
    /// back to `confirmConfig(token:)` within `PENDING_CONFIG_TIMEOUT`
    /// (120s, `crates/aivpn-server/src/pending_config.rs`) or the server's
    /// own background sweep auto-rolls the change back.
    static func applyConfig(body: Data) -> (status: UInt16, body: Data)? {
        mgmtRequest(method: 1 /* POST */, path: "/api/v1/config/apply", body: body)
    }

    /// `POST /api/v1/config/confirm` — thin wrapper over `mgmtRequest`.
    /// Body is `{"token":"<token from applyConfig>"}`
    /// (`mgmt_service::TunnelConfirmRequest`). `204` on success (change is
    /// now permanent, nothing left to roll back); a non-2xx status
    /// (typically `404` — unknown or already-expired-and-swept token, see
    /// `PendingConfigManager::confirm`'s doc comment) means the token no
    /// longer names a live pending change — the caller should treat that
    /// the same as an expiry (the server has, or will shortly, roll back on
    /// its own sweep).
    static func confirmConfig(token: String) -> (status: UInt16, body: Data)? {
        let body = (try? JSONSerialization.data(withJSONObject: ["token": token])) ?? Data()
        return mgmtRequest(method: 1 /* POST */, path: "/api/v1/config/confirm", body: body)
    }
}
