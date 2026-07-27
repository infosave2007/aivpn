import SwiftUI
import UniformTypeIdentifiers

// MARK: - Wire types
//
// Mirrors the JSON shapes `crates/aivpn-server/src/mgmt_service.rs::dispatch()`
// returns for the curated in-tunnel management routes, reached here via
// `AdminApi.mgmtRequest` (see that file for the transport/wire-protocol
// layer this builds on).
//
// Dates are kept as raw RFC3339 strings rather than decoded straight to
// `Date`: chrono's `DateTime<Utc>` JSON output has variable-precision
// fractional seconds that Swift's built-in `.iso8601` `JSONDecoder` strategy
// cannot reliably parse. `AdminDate` below tries both with and without
// fractional seconds instead of trusting one fixed strategy.

/// Mirrors `mgmt_service::ClientView` — the PSK-stripped client shape
/// returned by `GET /api/v1/clients` (as an array) and
/// `GET /api/v1/clients/{id}` (a single object). `role` is the lowercase
/// string form (`#[serde(rename_all = "lowercase")]` on `ClientRole`):
/// "user" | "viewer" | "admin" — NOT the same encoding as
/// `AdminApi.role()`'s bare-decimal reply, which is a different endpoint.
struct AdminClientView: Codable, Identifiable, Equatable {
    let id: String
    let name: String
    let vpn_ip: String
    let enabled: Bool
    let one_time: Bool
    let device_bound: Bool
    let created_at: String
    let expires_at: String?
    let role: String
    /// Wave B2a/B3-macOS: this client's per-client exit-node override
    /// (`host:port`), or nil to fall back to the server's global default
    /// (`pool.exit_node`). Mirrors `mgmt_service::ClientView::exit_node`.
    let exit_node: String?
}

/// Mirrors `mgmt_service::StatusView` (`GET /api/v1/status`).
struct AdminStatusView: Codable {
    let clients_total: Int
    let clients_enabled: Int
    let kernel_module: Bool
}

/// Mirrors the `{"connection_key": "<aivpn://...>"}` object
/// `GET /api/v1/clients/{id}/connection-key` returns — verified directly
/// against `crates/aivpn-server/src/mgmt_service.rs`'s `Route::
/// ClientConnectionKey` dispatch arm and `management_api.rs::
/// get_connection_key` (both explicitly use `"connection_key"`, the same
/// key name on the REST and in-tunnel paths "so tunnel and socket clients
/// parse the same key" — see that arm's own comment). A prior version of
/// this struct used `"key"`, which matched the wire format at an earlier
/// point in server development but was unified to `"connection_key"`
/// before this ever shipped (see `df4401c fix(server): unify tunnel
/// connection-key response field to connection_key` and the matching
/// `7067bc5 fix(ios): parse connection_key response field`) — decoding
/// against the old name here silently failed on every real server
/// (JSONDecoder throws when a non-Optional key is absent), permanently
/// breaking the QR/connection-key sheet.
private struct AdminConnectionKeyResponse: Codable {
    let connection_key: String
}

/// Wire encoding used by `ControlPayload::MgmtRequest` / the admin-socket
/// `mgmt:` command, mirrored from `crates/aivpn-client/src/main.rs`'s
/// `MgmtMethod::as_u8`.
enum AdminMethod: UInt8 {
    case get = 0, post = 1, patch = 2, delete = 3, put = 4
}

enum AdminDate {
    /// Best-effort RFC3339 parse for `created_at`/`expires_at`. Tries
    /// fractional-seconds first (chrono's actual output), then falls back
    /// to the plain internet-date-time form.
    static func parse(_ s: String) -> Date? {
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = withFraction.date(from: s) { return d }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: s)
    }

    /// Formats a UI-picked `Date` as an RFC3339 string the server's
    /// `chrono::DateTime<Utc>` deserializer accepts for `expires_at`.
    static func format(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    /// Locale-formatted display string for `created_at`/`expires_at`. Falls
    /// back to the raw string if parsing fails, so a value the app can't
    /// parse is still visible rather than silently dropped.
    static func displayString(_ s: String) -> String {
        guard let date = parse(s) else { return s }
        let df = DateFormatter()
        df.dateStyle = .medium
        df.timeStyle = .short
        return df.string(from: date)
    }
}

// MARK: - Request body builders
//
// Built by hand with `JSONSerialization` rather than `Codable` structs +
// `JSONEncoder`: `PATCH /api/v1/clients/{id}` has three-state semantics on
// `expires_at` server-side (mirrors `TunnelPatchClientRequest`'s
// `deserialize_opt_opt` — key ABSENT = don't touch, `null` = clear, string =
// set), which `JSONEncoder`'s default `Optional` encoding can't express
// (`nil` always encodes to explicit `null`, never "omit the key").

private func adminAddClientBodyJSON(name: String, oneTime: Bool, expiresAt: Date?) -> Data {
    var dict: [String: Any] = ["name": name, "one_time": oneTime]
    if let expiresAt = expiresAt {
        dict["expires_at"] = AdminDate.format(expiresAt)
    }
    return (try? JSONSerialization.data(withJSONObject: dict)) ?? Data()
}

/// `name`/`enabled` nil = omit (don't touch). For `expires_at` and
/// `exit_node` (Wave B3-macOS): `clear*: true` sends an explicit JSON
/// `null` (server clears it, falling back to the global default for
/// `exit_node`); a non-nil value (with `clear*: false`) sends it; both
/// nil/false omits the key entirely (don't touch) — mirrors
/// `TunnelPatchClientRequest`'s `deserialize_opt_opt` tri-state on the
/// server (crates/aivpn-server/src/mgmt_service.rs).
private func adminPatchClientBodyJSON(name: String?, enabled: Bool?,
                                       expiresAt: Date?, clearExpiresAt: Bool,
                                       exitNode: String?, clearExitNode: Bool) -> Data {
    var dict: [String: Any] = [:]
    if let name = name { dict["name"] = name }
    if let enabled = enabled { dict["enabled"] = enabled }
    if clearExpiresAt {
        dict["expires_at"] = NSNull()
    } else if let expiresAt = expiresAt {
        dict["expires_at"] = AdminDate.format(expiresAt)
    }
    if clearExitNode {
        dict["exit_node"] = NSNull()
    } else if let exitNode = exitNode {
        dict["exit_node"] = exitNode
    }
    return (try? JSONSerialization.data(withJSONObject: dict)) ?? Data()
}

// MARK: - Store

/// Owns all client-management state for the Admin window and drives
/// `AdminApi` calls off the main thread — the same
/// `DispatchQueue.global`/`DispatchQueue.main` hop `VPNManager` already uses
/// for its own (root-daemon) IPC, since `AdminApi`'s socket round trip can
/// block for up to 10s.
final class AdminStore: ObservableObject {
    @Published var clients: [AdminClientView] = []
    @Published var status: AdminStatusView?
    @Published var isLoading = false
    /// True whenever the last list refresh couldn't reach the daemon at all
    /// (no readable admin token, or no reply) — as opposed to a real
    /// non-2xx status from a single action, which callers surface inline
    /// instead of blanking the whole window.
    @Published var channelUnavailable = false

    // MARK: Pool topology (Wave B3-macOS)

    @Published var poolNodes: [AdminPoolNodeView] = []
    @Published var poolHealth: AdminPoolHealthView?
    @Published var poolLoading = false
    /// Same "couldn't reach the daemon at all" meaning as `channelUnavailable`,
    /// tracked separately so switching to the Pool tab doesn't blank an
    /// already-loaded Clients tab (and vice versa).
    @Published var poolChannelUnavailable = false

    private func run<T>(_ work: @escaping () -> T, completion: @escaping (T) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = work()
            DispatchQueue.main.async { completion(result) }
        }
    }

    func refreshClients() {
        isLoading = true
        run({ AdminApi.mgmtRequest(method: AdminMethod.get.rawValue, path: "/api/v1/clients") }) { [weak self] result in
            guard let self = self else { return }
            self.isLoading = false
            guard let (status, body) = result, status == 200,
                  let decoded = try? JSONDecoder().decode([AdminClientView].self, from: body) else {
                self.channelUnavailable = (result == nil)
                return
            }
            self.channelUnavailable = false
            self.clients = decoded
        }
    }

    func refreshStatus() {
        run({ AdminApi.mgmtRequest(method: AdminMethod.get.rawValue, path: "/api/v1/status") }) { [weak self] result in
            guard let (status, body) = result, status == 200,
                  let decoded = try? JSONDecoder().decode(AdminStatusView.self, from: body) else { return }
            self?.status = decoded
        }
    }

    /// `exitNode` (Wave B3-macOS): server-side `POST /api/v1/clients`
    /// (`TunnelAddClientRequest` in mgmt_service.rs) has no `exit_node`
    /// field at all — it's silently dropped if sent in the create body, so
    /// it can only be applied as a follow-up `PATCH` once the new client's
    /// `id` is known from the create response. That follow-up runs here,
    /// transparently to the caller, only when `exitNode` is non-nil.
    func createClient(name: String, oneTime: Bool, expiresAt: Date?, exitNode: String?,
                       completion: @escaping (Bool, UInt16?) -> Void) {
        let body = adminAddClientBodyJSON(name: name, oneTime: oneTime, expiresAt: expiresAt)
        run({ AdminApi.mgmtRequest(method: AdminMethod.post.rawValue, path: "/api/v1/clients", body: body) }) { [weak self] result in
            guard let self = self else { return }
            guard let (status, body) = result, status == 201 else {
                completion(false, result?.status)
                return
            }
            guard let exitNode = exitNode,
                  let created = try? JSONDecoder().decode(AdminClientView.self, from: body) else {
                self.refreshClients()
                completion(true, status)
                return
            }
            self.updateClient(id: created.id, name: nil, enabled: nil,
                               expiresAt: nil, clearExpiresAt: false,
                               exitNode: exitNode, clearExitNode: false) { _, _ in
                // The client was already created successfully; a failure to
                // apply the exit-node follow-up is surfaced to the caller as
                // a partial success (still `true`) — refreshClients() below
                // will show whatever the server actually ended up with.
                self.refreshClients()
                completion(true, status)
            }
        }
    }

    func updateClient(id: String, name: String?, enabled: Bool?,
                       expiresAt: Date?, clearExpiresAt: Bool,
                       exitNode: String? = nil, clearExitNode: Bool = false,
                       completion: @escaping (Bool, UInt16?) -> Void) {
        let body = adminPatchClientBodyJSON(name: name, enabled: enabled,
                                             expiresAt: expiresAt, clearExpiresAt: clearExpiresAt,
                                             exitNode: exitNode, clearExitNode: clearExitNode)
        let path = "/api/v1/clients/\(id)"
        run({ AdminApi.mgmtRequest(method: AdminMethod.patch.rawValue, path: path, body: body) }) { [weak self] result in
            guard let (status, _) = result else {
                completion(false, nil)
                return
            }
            if status == 200 {
                self?.refreshClients()
                completion(true, status)
            } else {
                completion(false, status)
            }
        }
    }

    func revokeClient(id: String, completion: @escaping (Bool, UInt16?) -> Void) {
        let path = "/api/v1/clients/\(id)/revoke"
        run({ AdminApi.mgmtRequest(method: AdminMethod.post.rawValue, path: path) }) { [weak self] result in
            guard let (status, _) = result else {
                completion(false, nil)
                return
            }
            if status == 204 {
                self?.refreshClients()
                completion(true, status)
            } else {
                completion(false, status)
            }
        }
    }

    func resetDevice(id: String, completion: @escaping (Bool, UInt16?) -> Void) {
        let path = "/api/v1/clients/\(id)/reset-device"
        run({ AdminApi.mgmtRequest(method: AdminMethod.post.rawValue, path: path) }) { [weak self] result in
            guard let (status, _) = result else {
                completion(false, nil)
                return
            }
            if status == 204 {
                self?.refreshClients()
                completion(true, status)
            } else {
                completion(false, status)
            }
        }
    }

    func fetchConnectionKey(id: String, completion: @escaping (String?) -> Void) {
        let path = "/api/v1/clients/\(id)/connection-key"
        run({ AdminApi.mgmtRequest(method: AdminMethod.get.rawValue, path: path) }) { result in
            guard let (status, body) = result, status == 200,
                  let decoded = try? JSONDecoder().decode(AdminConnectionKeyResponse.self, from: body) else {
                completion(nil)
                return
            }
            completion(decoded.connection_key)
        }
    }

    func fetchQr(text: String, completion: @escaping (Data?) -> Void) {
        run({ AdminApi.qrPngData(text) }, completion: completion)
    }

    // MARK: Pool topology (Wave B3-macOS)

    func refreshPoolNodes() {
        poolLoading = true
        run({ AdminApi.poolNodes() }) { [weak self] result in
            guard let self = self else { return }
            self.poolLoading = false
            guard let (status, body) = result, status == 200,
                  let decoded = try? JSONDecoder().decode([AdminPoolNodeView].self, from: body) else {
                self.poolChannelUnavailable = (result == nil)
                return
            }
            self.poolChannelUnavailable = false
            self.poolNodes = decoded
        }
    }

    func refreshPoolHealth() {
        run({ AdminApi.poolHealth() }) { [weak self] result in
            guard let (status, body) = result, status == 200,
                  let decoded = try? JSONDecoder().decode(AdminPoolHealthView.self, from: body) else { return }
            self?.poolHealth = decoded
        }
    }

    /// Convenience for the tab-switch/refresh-button call sites in
    /// `AdminRootView` — both pool endpoints are cheap, read-only GETs, so
    /// there's no reason to make callers fire them individually.
    func refreshPool() {
        refreshPoolNodes()
        refreshPoolHealth()
    }
}

// MARK: - Window controller

/// Hosts `AdminRootView` in a standalone, resizable `NSWindow` rather than
/// growing the main popover: the popover has a fixed 360×440 content size
/// (`AivpnApp.swift`), which has no room for a client list + add-client
/// form + QR/save-panel flow. Reused as a singleton — `isReleasedWhenClosed
/// = false` means the standard red close button just orders the window out
/// (hides it); `show()` brings the same window/state back rather than
/// rebuilding it, the same way "Preferences…" windows behave in other
/// menu-bar (accessory-activation-policy) apps.
final class AdminWindowController: NSWindowController {
    static let shared = AdminWindowController()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 560),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(
            rootView: AdminRootView()
                .environmentObject(LocalizationManager.shared)
        )
        super.init(window: window)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        window?.title = LocalizationManager.shared.t("admin_panel_title")
        window?.center()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
        NotificationCenter.default.post(name: .adminWindowDidShow, object: nil)
    }
}

extension Notification.Name {
    /// Posted every time `AdminWindowController.show()` brings the window
    /// forward, so `AdminRootView` can refresh — the view itself is only
    /// created once (the window is reused, not rebuilt), so `.onAppear`
    /// alone would only ever fire on the very first open.
    static let adminWindowDidShow = Notification.Name("AdminWindowDidShow")
}

// MARK: - Root view

/// Which pane `AdminRootView`'s segmented control shows — client CRUD
/// (Phase A) or the read-only pool topology view (Wave B3-macOS).
/// `Hashable` is required both by `Picker`'s `selection:` binding and by
/// `.onChange(of:)` below.
enum AdminTab: Hashable {
    case clients, pool
}

struct AdminRootView: View {
    @EnvironmentObject var loc: LocalizationManager
    @StateObject private var store = AdminStore()
    @State private var showAddSheet = false
    @State private var selectedClient: AdminClientView?
    @State private var selectedTab: AdminTab = .clients

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(loc.t("admin_panel_title"))
                    .font(.title3)
                    .fontWeight(.semibold)
                Spacer()
                if selectedTab == .clients, let status = store.status {
                    Text("\(status.clients_enabled)/\(status.clients_total)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Button(action: { refreshActiveTab() }) {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.plain)
                .help(loc.t("admin_refresh"))

                if selectedTab == .clients {
                    Button(action: { showAddSheet = true }) {
                        Image(systemName: "plus")
                    }
                    .buttonStyle(.plain)
                    .help(loc.t("admin_add_client"))
                }
            }
            .padding(16)

            Picker("", selection: $selectedTab) {
                Text(loc.t("admin_tab_clients")).tag(AdminTab.clients)
                Text(loc.t("admin_tab_pool")).tag(AdminTab.pool)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 16)
            .padding(.bottom, 12)
            .onChange(of: selectedTab) { newValue in
                if newValue == .pool { store.refreshPool() }
            }

            Divider()

            if selectedTab == .clients {
                content
            } else {
                AdminPoolView(store: store)
            }
        }
        .frame(minWidth: 480, minHeight: 420)
        .onAppear {
            store.refreshClients()
            store.refreshStatus()
        }
        .onReceive(NotificationCenter.default.publisher(for: .adminWindowDidShow)) { _ in
            store.refreshClients()
            store.refreshStatus()
            if selectedTab == .pool { store.refreshPool() }
        }
        .sheet(isPresented: $showAddSheet) {
            AdminAddClientSheet(store: store, isPresented: $showAddSheet)
                .environmentObject(loc)
        }
        .sheet(item: $selectedClient) { client in
            AdminClientDetailSheet(store: store, client: client)
                .environmentObject(loc)
        }
    }

    private func refreshActiveTab() {
        switch selectedTab {
        case .clients:
            store.refreshClients()
            store.refreshStatus()
        case .pool:
            store.refreshPool()
        }
    }

    @ViewBuilder
    private var content: some View {
        if store.channelUnavailable {
            VStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.largeTitle)
                    .foregroundColor(.orange)
                Text(loc.t("admin_unavailable_title"))
                    .font(.headline)
                Text(loc.t("admin_unavailable_message"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 360)
            }
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if store.isLoading && store.clients.isEmpty {
            VStack {
                Spacer()
                ProgressView(loc.t("admin_loading"))
                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if store.clients.isEmpty {
            VStack {
                Spacer()
                Text(loc.t("admin_no_clients"))
                    .foregroundColor(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List(store.clients) { client in
                AdminClientRow(client: client)
                    .contentShape(Rectangle())
                    .onTapGesture { selectedClient = client }
            }
            .listStyle(.inset)
        }
    }
}

// MARK: - Row

struct AdminClientRow: View {
    let client: AdminClientView
    @EnvironmentObject var loc: LocalizationManager

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(client.enabled ? Color.green : Color.gray)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(client.name)
                        .font(.system(size: 13, weight: .medium))
                    if client.one_time {
                        Image(systemName: "1.circle")
                            .font(.system(size: 11))
                            .foregroundColor(.orange)
                            .help(loc.t("admin_one_time"))
                    }
                    if client.device_bound {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 9))
                            .foregroundColor(.secondary)
                            .help(loc.t("admin_device_bound"))
                    }
                }
                Text(client.vpn_ip)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                if let exitNode = client.exit_node {
                    HStack(spacing: 3) {
                        Image(systemName: "arrow.triangle.branch")
                            .font(.system(size: 8))
                        Text(exitNode)
                            .font(.system(size: 9, design: .monospaced))
                    }
                    .foregroundColor(.secondary)
                    .help(loc.t("admin_exit_node_current") + ": " + exitNode)
                }
            }

            Spacer()

            Text(roleLabel)
                .font(.system(size: 10))
                .foregroundColor(.secondary)

            Image(systemName: "chevron.right")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
    }

    private var roleLabel: String {
        switch client.role {
        case "admin": return loc.t("admin_role_admin")
        case "viewer": return loc.t("admin_role_viewer")
        default: return loc.t("admin_role_user")
        }
    }
}

// MARK: - Add client sheet

struct AdminAddClientSheet: View {
    @ObservedObject var store: AdminStore
    @Binding var isPresented: Bool
    @EnvironmentObject var loc: LocalizationManager

    @State private var name = ""
    @State private var oneTime = false
    @State private var expiresEnabled = false
    @State private var expiresAt = Date().addingTimeInterval(86400 * 30)
    /// Wave B3-macOS: `host:port`, empty = use the server's global default
    /// (`pool.exit_node`). Applied via a follow-up `PATCH` after creation —
    /// see `AdminStore.createClient`'s doc comment for why.
    @State private var exitNode = ""
    @State private var isCreating = false
    @State private var errorText: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(loc.t("admin_add_client"))
                .font(.headline)

            TextField(loc.t("admin_client_name"), text: $name)
                .textFieldStyle(.roundedBorder)

            Toggle(loc.t("admin_one_time"), isOn: $oneTime)
                .toggleStyle(.checkbox)

            Toggle(loc.t("admin_expires_enable"), isOn: $expiresEnabled)
                .toggleStyle(.checkbox)
            if expiresEnabled {
                DatePicker(loc.t("admin_expires_at"), selection: $expiresAt,
                           displayedComponents: [.date, .hourAndMinute])
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(loc.t("admin_exit_node"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                TextField(loc.t("admin_exit_node_placeholder"), text: $exitNode)
                    .textFieldStyle(.roundedBorder)
            }

            if let errorText = errorText {
                Text(errorText)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            HStack {
                Spacer()
                Button(loc.t("admin_cancel")) { isPresented = false }
                Button(isCreating ? loc.t("admin_creating") : loc.t("admin_create")) {
                    createTapped()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || isCreating)
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private func createTapped() {
        isCreating = true
        errorText = nil
        let trimmedExitNode = exitNode.trimmingCharacters(in: .whitespaces)
        store.createClient(name: name, oneTime: oneTime,
                            expiresAt: expiresEnabled ? expiresAt : nil,
                            exitNode: trimmedExitNode.isEmpty ? nil : trimmedExitNode) { success, status in
            isCreating = false
            if success {
                isPresented = false
            } else {
                errorText = loc.t("admin_error_generic") + (status.map { " (\($0))" } ?? "")
            }
        }
    }
}

// MARK: - Client detail sheet

struct AdminClientDetailSheet: View {
    @ObservedObject var store: AdminStore
    let client: AdminClientView
    @EnvironmentObject var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @State private var isEditing = false
    @State private var editName: String = ""
    @State private var editEnabled: Bool = true
    @State private var editExpiresEnabled: Bool = false
    @State private var editExpiresAt: Date = Date()
    /// Wave B3-macOS: `host:port`, empty = clear (fall back to the global
    /// default). Pre-filled from `client.exit_node` in `.onAppear` below.
    @State private var editExitNode: String = ""
    @State private var isSaving = false

    @State private var showRevokeConfirm = false
    @State private var showResetConfirm = false
    @State private var isBusy = false
    @State private var actionError: String?

    @State private var connectionKey: String?
    @State private var isLoadingKey = false
    @State private var qrImage: NSImage?
    @State private var isLoadingQr = false
    @State private var copiedFeedback = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header

                if isEditing {
                    editForm
                } else {
                    infoView
                }

                Divider()

                connectionKeySection

                Divider()

                actionsSection

                if let actionError = actionError {
                    Text(actionError)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            .padding(20)
        }
        .frame(width: 420, height: 520)
        .onAppear {
            editName = client.name
            editEnabled = client.enabled
            if let expires = client.expires_at, let date = AdminDate.parse(expires) {
                editExpiresEnabled = true
                editExpiresAt = date
            } else {
                editExpiresEnabled = false
                editExpiresAt = Date().addingTimeInterval(86400 * 30)
            }
            editExitNode = client.exit_node ?? ""
        }
        .confirmationDialog(loc.t("admin_revoke_confirm_title"), isPresented: $showRevokeConfirm) {
            Button(loc.t("admin_revoke"), role: .destructive) { revokeTapped() }
            Button(loc.t("admin_cancel"), role: .cancel) {}
        } message: {
            Text(loc.t("admin_revoke_confirm_message"))
        }
        .confirmationDialog(loc.t("admin_reset_device_confirm_title"), isPresented: $showResetConfirm) {
            Button(loc.t("admin_reset_device"), role: .destructive) { resetDeviceTapped() }
            Button(loc.t("admin_cancel"), role: .cancel) {}
        } message: {
            Text(loc.t("admin_reset_device_confirm_message"))
        }
    }

    // MARK: Subviews

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text(client.name).font(.title3).fontWeight(.semibold)
                Text(client.id)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            Button(loc.t("admin_close")) { dismiss() }
        }
    }

    private var infoView: some View {
        VStack(alignment: .leading, spacing: 6) {
            infoRow(icon: "network", text: "\(loc.t("admin_vpn_ip")): \(client.vpn_ip)")
            infoRow(icon: client.enabled ? "checkmark.circle.fill" : "xmark.circle",
                     text: client.enabled ? loc.t("admin_status_enabled") : loc.t("admin_status_disabled"),
                     color: client.enabled ? .green : .secondary)
            infoRow(icon: "person.badge.key", text: roleLabel)
            infoRow(icon: "calendar", text: "\(loc.t("admin_created_at")): \(AdminDate.displayString(client.created_at))")
            if let expires = client.expires_at {
                infoRow(icon: "hourglass", text: "\(loc.t("admin_expires_at")): \(AdminDate.displayString(expires))")
            }
            if client.device_bound {
                infoRow(icon: "lock.fill", text: loc.t("admin_device_bound"))
            }
            infoRow(icon: "arrow.triangle.branch",
                     text: "\(loc.t("admin_exit_node_current")): \(client.exit_node ?? loc.t("admin_exit_node_global"))")

            Button(loc.t("admin_edit")) { isEditing = true }
                .buttonStyle(.bordered)
                .padding(.top, 4)
        }
    }

    private func infoRow(icon: String, text: String, color: Color = .secondary) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 11))
                .foregroundColor(color)
                .frame(width: 14)
            Text(text)
                .font(.system(size: 12))
                .foregroundColor(color == .secondary ? .primary : color)
            Spacer()
        }
    }

    private var roleLabel: String {
        switch client.role {
        case "admin": return loc.t("admin_role_admin")
        case "viewer": return loc.t("admin_role_viewer")
        default: return loc.t("admin_role_user")
        }
    }

    private var editForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField(loc.t("admin_client_name"), text: $editName)
                .textFieldStyle(.roundedBorder)
            Toggle(loc.t("admin_status_enabled"), isOn: $editEnabled)
                .toggleStyle(.checkbox)
            Toggle(loc.t("admin_expires_enable"), isOn: $editExpiresEnabled)
                .toggleStyle(.checkbox)
            if editExpiresEnabled {
                DatePicker(loc.t("admin_expires_at"), selection: $editExpiresAt,
                           displayedComponents: [.date, .hourAndMinute])
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(loc.t("admin_exit_node"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                TextField(loc.t("admin_exit_node_placeholder"), text: $editExitNode)
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Spacer()
                Button(loc.t("admin_cancel")) { isEditing = false }
                Button(isSaving ? loc.t("admin_loading") : loc.t("admin_save")) { saveTapped() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || editName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private var connectionKeySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(loc.t("admin_connection_key")).font(.subheadline).fontWeight(.semibold)

            if let key = connectionKey {
                Text(key)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .truncationMode(.middle)

                if let qrImage = qrImage {
                    Image(nsImage: qrImage)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 160, height: 160)
                } else if isLoadingQr {
                    ProgressView(loc.t("admin_qr_loading"))
                } else {
                    Text(loc.t("admin_qr_failed"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                HStack {
                    Button(copiedFeedback ? loc.t("admin_copied") : loc.t("admin_copy_key")) {
                        copyKey(key)
                    }
                    Button(loc.t("admin_save_to_file")) {
                        saveKeyToFile(key)
                    }
                }
                .buttonStyle(.bordered)
                .font(.caption)
            } else if isLoadingKey {
                ProgressView(loc.t("admin_loading"))
            } else {
                Button(loc.t("admin_show_key")) {
                    loadConnectionKey()
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(loc.t("admin_reset_device")) { showResetConfirm = true }
                .buttonStyle(.bordered)
                .disabled(isBusy)

            Button(loc.t("admin_revoke")) { showRevokeConfirm = true }
                .buttonStyle(.bordered)
                .tint(.red)
                .disabled(isBusy)
        }
    }

    // MARK: Actions

    private func saveTapped() {
        isSaving = true
        actionError = nil
        let nameChanged = editName != client.name ? editName : nil
        let enabledChanged = editEnabled != client.enabled ? editEnabled : nil
        let hadExpires = client.expires_at != nil
        let clear = hadExpires && !editExpiresEnabled
        let sendExpires: Date? = editExpiresEnabled ? editExpiresAt : nil
        // Wave B3-macOS: same tri-state convention as expires_at above —
        // empty field clears an existing override (send explicit null);
        // empty field with no prior override omits the key (no-op); a
        // non-empty field always (re)sends the value.
        let trimmedExitNode = editExitNode.trimmingCharacters(in: .whitespaces)
        let hadExitNode = client.exit_node != nil
        let clearExitNode = hadExitNode && trimmedExitNode.isEmpty
        let sendExitNode: String? = trimmedExitNode.isEmpty ? nil : trimmedExitNode
        store.updateClient(id: client.id, name: nameChanged, enabled: enabledChanged,
                            expiresAt: sendExpires, clearExpiresAt: clear,
                            exitNode: sendExitNode, clearExitNode: clearExitNode) { success, status in
            isSaving = false
            if success {
                dismiss()
            } else {
                actionError = loc.t("admin_error_generic") + (status.map { " (\($0))" } ?? "")
            }
        }
    }

    private func revokeTapped() {
        isBusy = true
        actionError = nil
        store.revokeClient(id: client.id) { success, status in
            isBusy = false
            if success {
                dismiss()
            } else {
                actionError = loc.t("admin_error_generic") + (status.map { " (\($0))" } ?? "")
            }
        }
    }

    private func resetDeviceTapped() {
        isBusy = true
        actionError = nil
        store.resetDevice(id: client.id) { success, status in
            isBusy = false
            if !success {
                actionError = loc.t("admin_error_generic") + (status.map { " (\($0))" } ?? "")
            }
        }
    }

    private func loadConnectionKey() {
        isLoadingKey = true
        store.fetchConnectionKey(id: client.id) { key in
            isLoadingKey = false
            connectionKey = key
            guard let key = key else { return }
            isLoadingQr = true
            store.fetchQr(text: key) { data in
                isLoadingQr = false
                if let data = data, let image = NSImage(data: data) {
                    qrImage = image
                }
            }
        }
    }

    private func copyKey(_ key: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key, forType: .string)
        copiedFeedback = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            copiedFeedback = false
        }
    }

    private func saveKeyToFile(_ key: String) {
        let panel = NSSavePanel()
        panel.title = loc.t("admin_save_to_file")
        panel.nameFieldStringValue = "\(client.name)-connection-key.txt"
        panel.allowedContentTypes = [.plainText]
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            try? key.data(using: .utf8)?.write(to: url)
        }
    }
}
