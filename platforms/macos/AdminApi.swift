import Foundation

/// Управление работающим процессом aivpn-client через локальный IPC.
/// Запросы к серверу выполняются внутри VPN-сессии. В полном туннеле запрос
/// проходит через помощник, который проверяет подпись приложения и сессию.
/// В режиме SOCKS5 используется TCP IPC с токеном и префиксом длины u32 BE.
/// Ответы от прежней сессии отбрасываются до изменения состояния интерфейса.
enum AdminApi {
    private static let sessionLock = NSLock()
    private static var helperSession: String?
    private static var epoch: UInt64 = 0
    private static let bindingKey = "aivpn.admin.binding"

    static func updateHelperSession(_ session: String?) {
        sessionLock.lock()
        let changed = helperSession != session
        if changed { helperSession = session; epoch &+= 1 }
        sessionLock.unlock()
        if changed { NotificationCenter.default.post(name: .aivpnAdminSessionChanged, object: nil) }
    }

    static func invalidateSession() {
        sessionLock.lock()
        helperSession = nil
        epoch &+= 1
        sessionLock.unlock()
        NotificationCenter.default.post(name: .aivpnAdminSessionChanged, object: nil)
    }

    static func captureSession() -> [String: String] {
        sessionLock.lock()
        let session = helperSession ?? ""
        let generation = epoch
        sessionLock.unlock()
        return ["token": fileToken() ?? "", "helper": session, "epoch": String(generation)]
    }

    static func isCurrent(_ session: [String: String]) -> Bool { captureSession() == session }

    static func withSession<T>(_ session: [String: String], _ operation: () -> T) -> T {
        let dictionary = Thread.current.threadDictionary
        let previous = dictionary[bindingKey]
        dictionary[bindingKey] = session
        defer { dictionary[bindingKey] = previous }
        return operation()
    }

    private static func sendOperation(_ command: String) -> String? {
        let session = Thread.current.threadDictionary[bindingKey] as? [String: String] ?? captureSession()
        if let token = session["token"], !token.isEmpty { return sendAdminRequest("\(token):\(command)") }
        guard let helper = session["helper"], !helper.isEmpty,
              let response = LocalAdminIPC.request(["action": "admin", "key": helper, "service": command]),
              response["status"] as? String == "ok" else { return nil }
        return response["log"] as? String
    }

    static func benchmark() -> [String: Any]? {
        guard let reply = sendOperation("bench:9"), let data = reply.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    // MARK: - Config

    static let socketHost = "127.0.0.1"
    static let socketPort: UInt16 = 44301
    /// Matches the FFI doc's stated bound (`aivpn_mgmt_request`: "blocks …
    /// or the call times out (10s)") so behavior is consistent with the
    /// mobile cores even though the transport differs.
    static let timeoutSeconds: Double = 12.0

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
    private static func fileToken() -> String? {
        guard let raw = try? String(contentsOfFile: adminTokenPath(), encoding: .utf8) else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Convenience for gating UI: true only when a token is currently
    /// readable, i.e. the admin channel has a chance of working at all.
    static func adminChannelAvailable() -> Bool {
        fileToken() != nil || !captureSession()["helper", default: ""].isEmpty
    }

    // MARK: - Локальный TCP-запрос

    private static func sendAdminRequest(_ line: String) -> String? {
        LocalAdminIPC.clientRequest(line)
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
        let bodyB64 = body.base64EncodedString()
        let line = "mgmt:\(method):\(path):\(bodyB64)"
        guard let reply = sendOperation(line) else { return nil }
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
        guard let reply = sendOperation("role") else { return nil }
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
        guard let textB64 = text.data(using: .utf8)?.base64EncodedString() else { return nil }
        guard let reply = sendOperation("qr:\(textB64)") else { return nil }
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

    /// Каталог доступных масок через VPN. Требует роли Viewer или Admin.
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

extension Notification.Name {
    static let aivpnAdminSessionChanged = Notification.Name("AivpnAdminSessionChanged")
}
