import SwiftUI

// MARK: - Wire types (G-A3: server settings apply-with-rollback)
//
// Mirrors `crates/aivpn-server/src/mgmt_service.rs::ApplyResponse` and
// `crates/aivpn-server/src/management_api.rs::MaskInfo` exactly — field
// names match the server's `#[derive(Serialize)]` output verbatim
// (snake_case, no `#[serde(rename_all)]` override on either struct).
// Reached here via `AdminApi.applyConfig(body:)`/`confirmConfig(token:)`/
// `listMasks()` (thin wrappers around `AdminApi.mgmtRequest` — see that
// file, including the doc comment on `listMasks()` for a known gap: the
// masks catalog isn't in the tunnel's curated route allowlist yet), same
// layering as the pool-topology/audit-log wire types in
// PoolView.swift/AuditLogView.swift.

/// Mirrors `management_api::MaskInfo` — one entry of the array
/// `GET /api/v1/masks` returns. `modified` is `Option<DateTime<Utc>>`
/// server-side (chrono's serde impl emits an RFC3339 string or JSON
/// `null`), kept as a raw optional string here and formatted on demand via
/// `AdminDate` (AdminView.swift) — same convention as `AdminClientView.
/// created_at`/`expires_at`.
struct AdminMaskInfoView: Codable, Identifiable, Equatable {
    let id: String
    let file: String
    let size_bytes: UInt64
    let modified: String?
    let generated: Bool
}

/// Mirrors `mgmt_service::ApplyResponse` — the object both
/// `POST /api/v1/config/apply` branches (active-mask and global exit-node)
/// return on `200`.
struct AdminApplyResponseView: Codable {
    let token: String
    let applied: Bool
}

/// One in-flight apply-with-rollback change tracked client-side, mirroring
/// the server's `PendingConfig` (`pending_config.rs`): `token` must be
/// POSTed back to `AdminApi.confirmConfig(token:)` within
/// `timeoutSeconds` (mirrors `PENDING_CONFIG_TIMEOUT` = 120s server-side)
/// or the server's own background sweep task auto-rolls the change back
/// regardless of what this app does — this struct only drives the local
/// confirm-banner/countdown UI, it is never the source of truth for
/// whether the change is actually still pending server-side (a `confirm()`
/// call after the real server-side deadline correctly comes back as a
/// non-2xx "token not found", handled by `ServerSettingsStore`).
struct PendingApply {
    let token: String
    let appliedAt: Date

    static let timeoutSeconds: TimeInterval = 120
}

// MARK: - Request body builders
//
// Built by hand with `JSONSerialization`, same reasoning as AdminView.swift's
// `adminPatchClientBodyJSON`: `POST /api/v1/config/apply`'s exit-node branch
// is selected by KEY PRESENCE (even an explicit JSON `null`), which
// `JSONEncoder`'s `Optional` handling can't express directly — `NSNull()`
// gives precise control over that.

/// `{"client":"","mask":"<id>"}` — selects `HeavySetting::ActiveMask` on the
/// server (`client` empty is intentional here: this is the server's GLOBAL
/// active-mask control, not a per-client override — mirrors the same empty-
/// `client` convention the design note in mgmt_service.rs's `TunnelApplyRequest`
/// doc comment describes for this call shape).
private func adminApplyMaskBodyJSON(mask: String) -> Data {
    (try? JSONSerialization.data(withJSONObject: ["client": "", "mask": mask])) ?? Data()
}

/// `{"exit_node": "<host:port>"}` or `{"exit_node": null}` — the `exit_node`
/// key's mere PRESENCE (`addr` or explicit `NSNull()`) selects
/// `HeavySetting::ExitNode` server-side; omitting the key entirely would
/// instead select the active-mask branch (see `TunnelApplyRequest`'s doc
/// comment in mgmt_service.rs) — so this body builder, unlike
/// `adminApplyMaskBodyJSON`, is the ONLY way to reach the exit-node branch
/// and must always include the key.
private func adminApplyExitNodeBodyJSON(addr: String?) -> Data {
    let dict: [String: Any] = ["exit_node": addr ?? NSNull()]
    return (try? JSONSerialization.data(withJSONObject: dict)) ?? Data()
}

/// Same "no error body on the in-tunnel admin-socket path" constraint
/// `AdminView.swift`'s `adminErrorMessage(status:loc:)` documents (private
/// to that file, so re-implemented here rather than shared) — reuses the
/// SAME localized strings (`admin_error_*`) since the status-code meanings
/// are generic across every mgmt-socket call, not specific to client CRUD.
private func serverSettingsErrorMessage(status: UInt16?, loc: LocalizationManager) -> String {
    let statusSuffix = status.map { " (\($0))" } ?? ""
    switch status {
    case 400: return loc.t("admin_error_bad_request") + statusSuffix
    case 403: return loc.t("admin_error_forbidden") + statusSuffix
    case 404: return loc.t("admin_error_not_found") + statusSuffix
    case 409: return loc.t("admin_error_conflict") + statusSuffix
    case .some(let s) where s >= 500: return loc.t("admin_error_server") + statusSuffix
    default: return loc.t("admin_error_generic") + statusSuffix
    }
}

// MARK: - Store

/// Owns all state for the Server Settings window: role gating, the masks
/// catalog, the pool-nodes list (exit-node picker source), and the two
/// independent apply-with-rollback flows (active mask / global default
/// exit node). Kept as its own `ObservableObject` rather than extending
/// `AdminStore` (AdminView.swift) — this window is a separate admin-only
/// surface with its own lifecycle, and the two apply-with-rollback flows
/// below need their own `Timer`s, which would otherwise have to live
/// awkwardly alongside `AdminStore`'s unrelated client-CRUD state.
///
/// Threading follows the SAME `DispatchQueue.global`/`DispatchQueue.main`
/// hop as `AdminStore.run(_:completion:)` (AdminView.swift) — `AdminApi`'s
/// socket round trip can block for up to 10s, so it must never run on the
/// main thread.
final class ServerSettingsStore: ObservableObject {

    // MARK: Role (fails closed to "not Admin", same convention as
    // `AdminStore.canMutate` — see that property's doc comment).

    @Published var role: UInt8? = nil
    var isAdmin: Bool { role == AdminApi.roleAdmin }

    private func run<T>(_ work: @escaping () -> T, completion: @escaping (T) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = work()
            DispatchQueue.main.async { completion(result) }
        }
    }

    func refreshRole() {
        run({ AdminApi.role() }) { [weak self] role in
            self?.role = role
        }
    }

    // MARK: Masks catalog

    @Published var masks: [AdminMaskInfoView] = []
    @Published var masksLoading = false
    /// True whenever the last refresh couldn't decode a `200` +
    /// `[AdminMaskInfoView]` reply — currently ALWAYS true against a real
    /// server, since `GET /api/v1/masks` isn't in the tunnel's curated
    /// route allowlist yet (see `AdminApi.listMasks()`'s doc comment for
    /// the full explanation and the server-side follow-up this is written
    /// against). `ActiveMaskSection` below falls back to a free-text
    /// mask-id field whenever this is true, so the Apply flow itself still
    /// works even though the catalog dropdown can't populate.
    @Published var masksUnavailable = false

    func refreshMasks() {
        masksLoading = true
        run({ AdminApi.listMasks() }) { [weak self] result in
            guard let self = self else { return }
            self.masksLoading = false
            guard let (status, body) = result, status == 200,
                  let decoded = try? JSONDecoder().decode([AdminMaskInfoView].self, from: body) else {
                self.masksUnavailable = true
                self.masks = []
                return
            }
            self.masksUnavailable = false
            self.masks = decoded
        }
    }

    // MARK: Pool nodes (source for the global-exit-node picker)

    @Published var poolNodes: [AdminPoolNodeView] = []

    func refreshPoolNodes() {
        run({ AdminApi.poolNodes() }) { [weak self] result in
            guard let (status, body) = result, status == 200,
                  let decoded = try? JSONDecoder().decode([AdminPoolNodeView].self, from: body) else { return }
            self?.poolNodes = decoded
        }
    }

    // MARK: Active-mask apply-confirm flow

    @Published var maskPending: PendingApply?
    @Published var maskRemainingSeconds: Int = 0
    @Published var maskApplying = false
    @Published var maskConfirming = false
    /// Raw failed-attempt status (nil = no error currently shown). Kept as
    /// the raw `UInt16?` rather than a pre-localized string — the store has
    /// no `LocalizationManager` reference, so `ActiveMaskSection.body`
    /// localizes it on render via `serverSettingsErrorMessage(status:loc:)`.
    @Published var maskErrorStatus: UInt16? = nil
    /// Set true the instant the local countdown reaches zero without a
    /// confirm — mirrors the server auto-rolling the change back on its own
    /// sweep. Cleared on the next successful `applyMask(_:)`.
    @Published var maskReverted = false
    private var maskTimer: Timer?

    func applyMask(_ maskId: String) {
        maskApplying = true
        maskErrorStatus = nil
        maskReverted = false
        let body = adminApplyMaskBodyJSON(mask: maskId)
        run({ AdminApi.applyConfig(body: body) }) { [weak self] result in
            guard let self = self else { return }
            self.maskApplying = false
            guard let (status, respBody) = result, status == 200,
                  let decoded = try? JSONDecoder().decode(AdminApplyResponseView.self, from: respBody) else {
                self.maskErrorStatus = result?.status
                return
            }
            self.maskErrorStatus = nil
            self.beginMaskCountdown(token: decoded.token)
        }
    }

    func confirmMask() {
        guard let pending = maskPending else { return }
        maskConfirming = true
        maskErrorStatus = nil
        run({ AdminApi.confirmConfig(token: pending.token) }) { [weak self] result in
            guard let self = self else { return }
            self.maskConfirming = false
            guard let (status, _) = result, status == 204 else {
                self.maskErrorStatus = result?.status
                return
            }
            self.clearMaskCountdown()
        }
    }

    private func beginMaskCountdown(token: String) {
        maskTimer?.invalidate()
        let startedAt = Date()
        maskPending = PendingApply(token: token, appliedAt: startedAt)
        maskRemainingSeconds = Int(PendingApply.timeoutSeconds)
        let timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] timer in
            self?.tickMaskCountdown(startedAt: startedAt, timer: timer)
        }
        RunLoop.main.add(timer, forMode: .common)
        maskTimer = timer
    }

    private func tickMaskCountdown(startedAt: Date, timer: Timer) {
        let left = Int(PendingApply.timeoutSeconds - Date().timeIntervalSince(startedAt))
        if left <= 0 {
            maskRemainingSeconds = 0
            maskPending = nil
            maskReverted = true
            timer.invalidate()
            maskTimer = nil
        } else {
            maskRemainingSeconds = left
        }
    }

    private func clearMaskCountdown() {
        maskTimer?.invalidate()
        maskTimer = nil
        maskPending = nil
    }

    // MARK: Global default exit-node apply-confirm flow
    //
    // Mirrors the active-mask flow above field-for-field and method-for-
    // method (own `Timer`, own published state) rather than sharing one
    // generic implementation — the two `HeavySetting`s target different
    // files server-side (`.overrides/{client}.mask` vs `server.json`, see
    // `resolve_heavy_setting` in mgmt_service.rs) and so can have
    // INDEPENDENT pending changes in flight at the same time; keeping two
    // plain, symmetric blocks here (rather than one parameterized over
    // key paths) keeps that independence obvious and keeps this file
    // reviewable without a compiler on hand (see the G-A3 task's
    // compile-review gate).

    @Published var exitPending: PendingApply?
    @Published var exitRemainingSeconds: Int = 0
    @Published var exitApplying = false
    @Published var exitConfirming = false
    /// Same convention as `maskErrorStatus` above.
    @Published var exitErrorStatus: UInt16? = nil
    @Published var exitReverted = false
    private var exitTimer: Timer?

    func applyExitNode(_ addr: String?) {
        exitApplying = true
        exitErrorStatus = nil
        exitReverted = false
        let body = adminApplyExitNodeBodyJSON(addr: addr)
        run({ AdminApi.applyConfig(body: body) }) { [weak self] result in
            guard let self = self else { return }
            self.exitApplying = false
            guard let (status, respBody) = result, status == 200,
                  let decoded = try? JSONDecoder().decode(AdminApplyResponseView.self, from: respBody) else {
                self.exitErrorStatus = result?.status
                return
            }
            self.exitErrorStatus = nil
            self.beginExitCountdown(token: decoded.token)
        }
    }

    func confirmExitNode() {
        guard let pending = exitPending else { return }
        exitConfirming = true
        exitErrorStatus = nil
        run({ AdminApi.confirmConfig(token: pending.token) }) { [weak self] result in
            guard let self = self else { return }
            self.exitConfirming = false
            guard let (status, _) = result, status == 204 else {
                self.exitErrorStatus = result?.status
                return
            }
            self.clearExitCountdown()
        }
    }

    private func beginExitCountdown(token: String) {
        exitTimer?.invalidate()
        let startedAt = Date()
        exitPending = PendingApply(token: token, appliedAt: startedAt)
        exitRemainingSeconds = Int(PendingApply.timeoutSeconds)
        let timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] timer in
            self?.tickExitCountdown(startedAt: startedAt, timer: timer)
        }
        RunLoop.main.add(timer, forMode: .common)
        exitTimer = timer
    }

    private func tickExitCountdown(startedAt: Date, timer: Timer) {
        let left = Int(PendingApply.timeoutSeconds - Date().timeIntervalSince(startedAt))
        if left <= 0 {
            exitRemainingSeconds = 0
            exitPending = nil
            exitReverted = true
            timer.invalidate()
            exitTimer = nil
        } else {
            exitRemainingSeconds = left
        }
    }

    private func clearExitCountdown() {
        exitTimer?.invalidate()
        exitTimer = nil
        exitPending = nil
    }

    /// Both `Timer`s are `[weak self]`-captured (never retain this store),
    /// but a still-running repeating `Timer` otherwise keeps ITSELF alive
    /// on the run loop indefinitely — `invalidate()` here is what actually
    /// stops it once the window closes and this store is deallocated,
    /// same pattern as `VPNManager`'s poll timers.
    deinit {
        maskTimer?.invalidate()
        exitTimer?.invalidate()
    }
}

// MARK: - Window controller

/// Hosts `ServerSettingsRootView` in a standalone, resizable `NSWindow` —
/// same singleton/reuse pattern as `AdminWindowController` (AdminView.swift)
/// and `InstallServerWindowController` (InstallServerView.swift):
/// `isReleasedWhenClosed = false` so the standard red close button just
/// hides the window, `show()` brings the same window/state back.
final class ServerSettingsWindowController: NSWindowController {
    static let shared = ServerSettingsWindowController()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 560),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(
            rootView: ServerSettingsRootView()
                .environmentObject(LocalizationManager.shared)
        )
        super.init(window: window)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        window?.title = LocalizationManager.shared.t("server_settings_title")
        window?.center()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
        NotificationCenter.default.post(name: .serverSettingsWindowDidShow, object: nil)
    }
}

extension Notification.Name {
    /// Posted every time `ServerSettingsWindowController.show()` brings the
    /// window forward, so `ServerSettingsRootView` can refresh — the view
    /// itself is only created once (the window is reused, not rebuilt), so
    /// `.onAppear` alone would only ever fire on the very first open. Same
    /// convention as `.adminWindowDidShow` (AdminView.swift).
    static let serverSettingsWindowDidShow = Notification.Name("ServerSettingsWindowDidShow")
}

// MARK: - Root view

struct ServerSettingsRootView: View {
    @EnvironmentObject var loc: LocalizationManager
    @StateObject private var store = ServerSettingsStore()

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if store.role == nil {
                VStack {
                    Spacer()
                    ProgressView(loc.t("admin_loading"))
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if !store.isAdmin {
                // Defense in depth: the button that opens this window
                // (ContentView.swift) is already gated on Admin-only, and
                // the server's own `authorize()` would 403 every mutation
                // below regardless — this just keeps a non-Admin session
                // (Viewer, User, or a role that changed since the window
                // was last opened) from seeing controls that can never
                // succeed for them. Same convention as `AdminRootView`'s
                // Viewer-mode handling (AdminView.swift), but this whole
                // window is Admin-only rather than Admin-with-a-Viewer-
                // read-only-mode, per the G-A3 task.
                VStack(spacing: 8) {
                    Image(systemName: "lock.fill")
                        .font(.largeTitle)
                        .foregroundColor(.secondary)
                    Text(loc.t("server_settings_admin_only"))
                        .font(.headline)
                        .multilineTextAlignment(.center)
                }
                .padding(32)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        ActiveMaskSection(store: store)
                        Divider()
                        GlobalExitSection(store: store)
                    }
                    .padding(20)
                }
            }
        }
        .frame(minWidth: 420, minHeight: 480)
        .onAppear { refreshAll() }
        .onReceive(NotificationCenter.default.publisher(for: .serverSettingsWindowDidShow)) { _ in
            refreshAll()
        }
    }

    private func refreshAll() {
        store.refreshRole()
        store.refreshMasks()
        store.refreshPoolNodes()
    }

    private var header: some View {
        HStack {
            Text(loc.t("server_settings_title"))
                .font(.title3)
                .fontWeight(.semibold)
            Spacer()
            Button(action: { refreshAll() }) {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.plain)
            .help(loc.t("admin_refresh"))
        }
        .padding(16)
    }
}

// MARK: - Shared apply-confirm banner
//
// The ONE piece of UI genuinely shared between the two flows (§ task
// wording: "ОБЩИЙ apply-confirm flow") — both `ActiveMaskSection` and
// `GlobalExitSection` render this for their own `PendingApply`/countdown/
// confirm-handler, so the confirm-within-~120s banner looks and behaves
// identically for both actions without duplicating the SwiftUI layout.
private struct ApplyConfirmBanner: View {
    let remainingSeconds: Int
    let confirming: Bool
    let onConfirm: () -> Void
    @EnvironmentObject var loc: LocalizationManager

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "clock.badge.exclamationmark")
                    .foregroundColor(.orange)
                Text(String(format: loc.t("server_settings_confirm_countdown"), remainingSeconds))
                    .font(.caption)
                Spacer()
            }
            HStack {
                Spacer()
                Button(confirming ? loc.t("server_settings_confirming") : loc.t("server_settings_confirm")) {
                    onConfirm()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(confirming)
            }
        }
        .padding(10)
        .background(Color.orange.opacity(0.12))
        .cornerRadius(6)
    }
}

// MARK: - Active mask section

/// «Active mask»: `Picker` sourced from `GET /api/v1/masks` (falls back to
/// free-text entry while `store.masksUnavailable` — see that property's doc
/// comment) → Apply → `POST /api/v1/config/apply {"client":"","mask":id}` →
/// confirm-within-~120s banner (live change — no restart needed, unlike the
/// global exit node below).
private struct ActiveMaskSection: View {
    @ObservedObject var store: ServerSettingsStore
    @EnvironmentObject var loc: LocalizationManager

    @State private var selectedMaskId: String = ""
    @State private var manualMaskId: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(loc.t("server_settings_mask_section_title"))
                .font(.headline)

            if store.masksLoading {
                ProgressView()
            } else if store.masksUnavailable || store.masks.isEmpty {
                Text(loc.t("server_settings_mask_catalog_unavailable"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                TextField(loc.t("server_settings_mask_id_placeholder"), text: $manualMaskId)
                    .textFieldStyle(.roundedBorder)
            } else {
                Picker("", selection: $selectedMaskId) {
                    ForEach(store.masks) { mask in
                        Text(mask.generated
                             ? "\(mask.id) (\(loc.t("server_settings_mask_auto")))"
                             : mask.id)
                            .tag(mask.id)
                    }
                }
                .labelsHidden()
                .onAppear {
                    if selectedMaskId.isEmpty, let first = store.masks.first {
                        selectedMaskId = first.id
                    }
                }
            }

            if let pending = store.maskPending {
                ApplyConfirmBanner(remainingSeconds: store.maskRemainingSeconds,
                                    confirming: store.maskConfirming,
                                    onConfirm: { store.confirmMask() })
                    // `pending` is only used to decide WHICH view to show —
                    // `ApplyConfirmBanner` reads the live countdown straight
                    // from `store` so it updates every tick without this
                    // wrapper needing to re-derive anything from `pending`
                    // itself.
                    .id(pending.token)
            } else {
                HStack {
                    Spacer()
                    Button(store.maskApplying ? loc.t("server_settings_applying") : loc.t("server_settings_apply")) {
                        let id = effectiveMaskId
                        guard !id.isEmpty else { return }
                        store.applyMask(id)
                    }
                    .disabled(store.maskApplying || effectiveMaskId.isEmpty)
                }
            }

            if store.maskReverted {
                Text(loc.t("server_settings_reverted"))
                    .font(.caption)
                    .foregroundColor(.orange)
            }
            if let status = store.maskErrorStatus {
                Text(serverSettingsErrorMessage(status: status, loc: loc))
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
    }

    private var effectiveMaskId: String {
        if store.masksUnavailable || store.masks.isEmpty {
            return manualMaskId.trimmingCharacters(in: .whitespaces)
        }
        return selectedMaskId
    }
}

// MARK: - Global exit-node section

/// Which control `GlobalExitSection` shows — a private, distinctly-named
/// type from `AdminView.swift`'s own `ExitNodeChoice` (that one is `private`
/// to AdminView.swift and drives the PER-CLIENT exit-node picker there;
/// this drives the separate GLOBAL-DEFAULT picker here, over a different
/// wire call — `config/apply {"exit_node":...}` vs a client `PATCH`).
private enum ServerSettingsExitChoice: Hashable {
    case none
    case node(String)
    case custom
}

/// «Global default exit (pool)»: `Picker` sourced from `GET /api/v1/pool/nodes`
/// plus "(none)" and "custom host:port" entries → Apply →
/// `POST /api/v1/config/apply {"exit_node":addr|null}` →
/// confirm-within-~120s banner, captioned that this one only takes effect
/// after the server's NEXT RESTART (`HeavySetting::ExitNode`'s doc comment,
/// mgmt_service.rs — unlike the per-client exit-node override AdminView.swift's
/// `ExitNodePickerView` applies, which is live).
private struct GlobalExitSection: View {
    @ObservedObject var store: ServerSettingsStore
    @EnvironmentObject var loc: LocalizationManager

    @State private var choice: ServerSettingsExitChoice = .none
    @State private var customAddr: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(loc.t("server_settings_exit_section_title"))
                .font(.headline)
            Text(loc.t("server_settings_exit_restart_note"))
                .font(.caption)
                .foregroundColor(.secondary)

            Picker("", selection: $choice) {
                Text(loc.t("server_settings_exit_none")).tag(ServerSettingsExitChoice.none)
                ForEach(store.poolNodes.filter { $0.address != nil }) { node in
                    Text("\(node.node_id) (\(node.address!))").tag(ServerSettingsExitChoice.node(node.address!))
                }
                Text(loc.t("admin_exit_node_custom")).tag(ServerSettingsExitChoice.custom)
            }
            .labelsHidden()

            if choice == .custom {
                TextField(loc.t("admin_exit_node_placeholder"), text: $customAddr)
                    .textFieldStyle(.roundedBorder)
            }

            if let pending = store.exitPending {
                ApplyConfirmBanner(remainingSeconds: store.exitRemainingSeconds,
                                    confirming: store.exitConfirming,
                                    onConfirm: { store.confirmExitNode() })
                    .id(pending.token)
            } else {
                HStack {
                    Spacer()
                    Button(store.exitApplying ? loc.t("server_settings_applying") : loc.t("server_settings_apply")) {
                        store.applyExitNode(effectiveAddr)
                    }
                    .disabled(store.exitApplying || applyDisabled)
                }
            }

            if store.exitReverted {
                Text(loc.t("server_settings_reverted"))
                    .font(.caption)
                    .foregroundColor(.orange)
            }
            if let status = store.exitErrorStatus {
                Text(serverSettingsErrorMessage(status: status, loc: loc))
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
    }

    private var effectiveAddr: String? {
        switch choice {
        case .none: return nil
        case .node(let addr): return addr
        case .custom:
            let trimmed = customAddr.trimmingCharacters(in: .whitespaces)
            return trimmed.isEmpty ? nil : trimmed
        }
    }

    private var applyDisabled: Bool {
        if case .custom = choice {
            return customAddr.trimmingCharacters(in: .whitespaces).isEmpty
        }
        return false
    }
}
