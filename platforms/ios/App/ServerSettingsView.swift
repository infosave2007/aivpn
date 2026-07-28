import SwiftUI

// Admin-only "Server Settings" screen (Wave 2 / G-A3): apply-with-rollback
// UI for the two `HeavySetting` variants `mgmt_service.rs`'s
// `POST /api/v1/config/apply` exposes — a client's active-mask override
// (live) and the server's global default exit node (restart-required) —
// backed by AdminApi.swift's applyActiveMask/applyGlobalExitNode/
// confirmConfig wrappers around the SAME curated tunnel FFI every other
// admin call here uses. Presented as a sheet from AdminView, only ever
// offered a toolbar entry point there when `canMutate` (Admin, role 2) —
// unlike PoolView/AuditLogView there is nothing read-only for a Viewer to
// see here, every control mutates — so this view re-checks the same role
// gate defensively (mirrors AdminClientDetailView's `canMutate`, which is
// presented from a screen Viewer can also reach).
//
// Both sections share ONE apply-confirm-rollback flow
// (`ServerSettingsPendingApply` + `ServerSettingsConfirmBanner` below):
// Apply writes the change server-side immediately and returns a `token`;
// the server auto-reverts it unless `Confirm` is sent within the
// rollback window (`pending_config::PENDING_CONFIG_TIMEOUT`, 120s at
// time of writing — mirrored here only to size the local countdown
// banner; the server enforces the real deadline independently of this
// UI, so a stale/backgrounded countdown never leaves a change silently
// permanent).

/// Mirrors `pending_config::PENDING_CONFIG_TIMEOUT` server-side. Used only
/// to size the local countdown banner — if this ever drifts from the
/// server's actual constant, the worst case is a UI countdown that hits
/// zero a little early/late relative to the server's own sweep, not a
/// security issue (the server alone enforces the real deadline).
private let serverSettingsRollbackWindowSeconds: TimeInterval = 120

/// One in-flight apply-with-rollback change on this screen — mirrors the
/// server's `PendingConfig`. `descriptor` is an already-localized,
/// human-readable summary shown in the banner (e.g. "webrtc_vk_teams_v1
/// → my-phone", or the exit-node address).
private struct ServerSettingsPendingApply {
    let token: String
    let deadline: Date
    let descriptor: String
}

/// Shared countdown + Confirm banner, used identically by both sections
/// below. `onExpire` fires (once — guarded by `didFireExpire`) the moment
/// the LOCAL countdown reaches zero, so the caller can clear its pending
/// state and show a "reverted" message; the real rollback already
/// happened server-side by then regardless of whether this view is still
/// on screen. `Timer.publish(...).autoconnect()`'s subscription is torn
/// down by SwiftUI along with `onReceive` when this view disappears — no
/// manual `Timer.invalidate()` bookkeeping, no leak.
private struct ServerSettingsConfirmBanner: View {
    let pending: ServerSettingsPendingApply
    let loc: LocalizationManager
    let isConfirming: Bool
    let onConfirm: () -> Void
    let onExpire: () -> Void

    @State private var now: Date = Date()
    @State private var didFireExpire = false

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var remainingSeconds: Int {
        max(0, Int(pending.deadline.timeIntervalSince(now).rounded(.up)))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(pending.descriptor)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(2)
            HStack {
                Text("\(loc.t("server_settings_pending_prefix")) \(remainingSeconds)\(loc.t("server_settings_pending_suffix"))")
                    .font(.caption)
                    .foregroundColor(.orange)
                Spacer()
                if isConfirming {
                    ProgressView()
                } else {
                    Button(loc.t("server_settings_confirm"), action: onConfirm)
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                }
            }
        }
        .padding(.vertical, 4)
        .onReceive(ticker) { tick in
            now = tick
            if !didFireExpire && pending.deadline <= tick {
                didFireExpire = true
                onExpire()
            }
        }
    }
}

/// Mirrors the three things the global default exit-node field can
/// resolve to — `.none` clears `pool.exit_node` entirely (unlike
/// `AdminExitNodeChoice.globalDefault` in AdminView.swift, there is no
/// "defer to the global default" option HERE, because this picker IS the
/// global default).
private enum ServerSettingsExitChoice: Hashable {
    /// Initial selection. The curated tunnel allowlist exposes NO getter for
    /// the server's global `pool.exit_node` (verified in
    /// crates/aivpn-server/src/mgmt_service/tunnel_router.rs's
    /// `classify_route`: only status/clients*/audit-log/config apply+confirm/
    /// pool nodes+health+links/masks), so this screen cannot know the current
    /// value. Starting on `.none` would have made "Apply" send
    /// `{"exit_node": null}` — silently WIPING a configured global exit for an
    /// admin who came here to change the mask and tapped the wrong Apply. So
    /// the picker starts here and Apply is disabled until the operator picks
    /// something explicitly.
    case unknown
    case none
    case node(String)
    case custom
}

/// Best-effort mask-id source for the "Active mask" picker.
///
/// Tries the authoritative `GET /api/v1/masks` listing first
/// (`AdminApi.listMasks()`) — but as documented on that call, `classify_route`
/// (crates/aivpn-server/src/mgmt_service.rs) currently has NO tunnel route
/// for `/api/v1/masks`, so it always 404s over `aivpn_mgmt_request` today,
/// for every role including Admin. Verified by reading `classify_route`'s
/// match arms, not guessed — only `Status`/`Clients*`/`AuditLog`/
/// `ConfigApply`/`ConfigConfirm`/`Pool*` are in the curated tunnel
/// allowlist; `/api/v1/masks` is reachable only from the REST/web-panel
/// path, a different trust boundary iOS has no access to.
///
/// Falls back to this session's already-received `VPNManager.maskCatalog`
/// (`ControlPayload::MaskCatalog`, the same `mask_id`/`generated` shape,
/// pushed by the server at handshake for this client's OWN connection
/// masking) when the listing is empty or failed — the same set of masks
/// the server knows about, just sourced from data already on hand instead
/// of a call that cannot succeed yet. The "auto" resolution-mode sentinel
/// is filtered out (mirrors ContentView.swift's mask picker) since it is
/// not a concrete mask a `HeavySetting::ActiveMask` write can target.
private func serverSettingsLoadMaskChoices() async -> [AdminMaskInfo] {
    if case .success(let masks) = await AdminApi.listMasks(), !masks.isEmpty {
        return masks
    }
    return await MainActor.run {
        VPNManager.shared.maskCatalog
            .filter { $0.mask_id != "auto" }
            .map { AdminMaskInfo(id: $0.mask_id, file: "", size_bytes: 0, modified: nil, generated: $0.generated) }
    }
}

struct ServerSettingsView: View {
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    /// `true` only for the Admin role — see this file's header comment.
    private var isAdmin: Bool { AdminApi.role() == 2 }

    // MARK: Active-mask section state
    @State private var clients: [AdminClient] = []
    @State private var selectedClientId: String = ""
    @State private var maskChoices: [AdminMaskInfo] = []
    @State private var selectedMaskId: String = ""
    @State private var maskError: String?
    @State private var maskResultMessage: String?
    @State private var isApplyingMask = false
    @State private var isConfirmingMask = false
    @State private var maskPending: ServerSettingsPendingApply?

    // MARK: Global exit-node section state
    @State private var poolNodeAddresses: [String] = []
    @State private var exitChoice: ServerSettingsExitChoice = .unknown
    @State private var customExitAddr: String = ""
    @State private var exitError: String?
    @State private var exitResultMessage: String?
    @State private var isApplyingExit = false
    @State private var isConfirmingExit = false
    @State private var exitPending: ServerSettingsPendingApply?

    var body: some View {
        NavigationStack {
            Group {
                if !isAdmin {
                    VStack {
                        Text(loc.t("server_settings_admin_only"))
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    Form {
                        activeMaskSection
                        exitNodeSection
                    }
                }
            }
            .navigationTitle(loc.t("server_settings_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
        }
        .task { if isAdmin { await loadChoices() } }
    }

    // MARK: - Active mask

    @ViewBuilder
    private var activeMaskSection: some View {
        Section(
            header: Text(loc.t("server_settings_mask_section")),
            footer: Text(loc.t("server_settings_mask_hint"))
        ) {
            if clients.isEmpty {
                Text(loc.t("server_settings_no_clients"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                Picker(loc.t("server_settings_select_client"), selection: $selectedClientId) {
                    ForEach(clients) { client in
                        Text(client.name).tag(client.id)
                    }
                }
            }
            if maskChoices.isEmpty {
                Text(loc.t("server_settings_no_masks"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                Picker(loc.t("server_settings_select_mask"), selection: $selectedMaskId) {
                    ForEach(maskChoices) { mask in
                        Text(mask.generated ? "\(mask.id) \(loc.t("mask_generated_suffix"))" : mask.id)
                            .tag(mask.id)
                    }
                }
            }

            if let maskPending {
                ServerSettingsConfirmBanner(
                    pending: maskPending,
                    loc: loc,
                    isConfirming: isConfirmingMask,
                    onConfirm: { Task { await confirmMask() } },
                    onExpire: { maskExpired() }
                )
            } else {
                Button {
                    Task { await applyMask() }
                } label: {
                    if isApplyingMask {
                        ProgressView()
                    } else {
                        Text(loc.t("server_settings_apply"))
                    }
                }
                .disabled(isApplyingMask || selectedClientId.isEmpty || selectedMaskId.isEmpty)
            }

            if let maskError {
                Text(maskError).font(.caption2).foregroundColor(.red)
            }
            if let maskResultMessage {
                Text(maskResultMessage).font(.caption2).foregroundColor(.secondary)
            }
        }
    }

    @MainActor
    private func applyMask() async {
        isApplyingMask = true
        maskError = nil
        maskResultMessage = nil
        let clientId = selectedClientId
        let maskId = selectedMaskId
        let result = await AdminApi.applyActiveMask(client: clientId, mask: maskId)
        isApplyingMask = false
        switch result {
        case .success(let resp):
            let clientLabel = clients.first(where: { $0.id == clientId })?.name ?? clientId
            maskPending = ServerSettingsPendingApply(
                token: resp.token,
                deadline: Date().addingTimeInterval(serverSettingsRollbackWindowSeconds),
                descriptor: "\(maskId) → \(clientLabel)"
            )
        case .failure(let err):
            maskError = err.errorDescription
        }
    }

    @MainActor
    private func confirmMask() async {
        guard let pending = maskPending else { return }
        isConfirmingMask = true
        let result = await AdminApi.confirmConfig(token: pending.token)
        isConfirmingMask = false
        switch result {
        case .success:
            maskPending = nil
            maskResultMessage = loc.t("server_settings_confirmed")
        case .failure(let err):
            // Leave `maskPending` (and its countdown) in place — the
            // token is still valid until the deadline, so a transient
            // transport error just means "try Confirm again before it
            // expires", not "give up".
            maskError = err.errorDescription
        }
    }

    @MainActor
    private func maskExpired() {
        maskPending = nil
        maskResultMessage = loc.t("server_settings_reverted")
    }

    // MARK: - Global exit node

    @ViewBuilder
    private var exitNodeSection: some View {
        Section(
            header: Text(loc.t("server_settings_exit_section")),
            footer: Text(loc.t("server_settings_exit_hint"))
        ) {
            Picker(loc.t("admin_exit_node"), selection: $exitChoice) {
                Text(loc.t("server_settings_exit_unknown")).tag(ServerSettingsExitChoice.unknown)
                Text(loc.t("server_settings_exit_none")).tag(ServerSettingsExitChoice.none)
                ForEach(poolNodeAddresses, id: \.self) { addr in
                    Text(addr).tag(ServerSettingsExitChoice.node(addr))
                }
                Text(loc.t("admin_exit_node_custom")).tag(ServerSettingsExitChoice.custom)
            }
            if exitChoice == .custom {
                TextField(loc.t("admin_exit_node"), text: $customExitAddr)
                    .autocorrectionDisabled()
                    .autocapitalization(.none)
                    .keyboardType(.asciiCapable)
            }

            if let exitPending {
                ServerSettingsConfirmBanner(
                    pending: exitPending,
                    loc: loc,
                    isConfirming: isConfirmingExit,
                    onConfirm: { Task { await confirmExit() } },
                    onExpire: { exitExpired() }
                )
            } else {
                Button {
                    Task { await applyExit() }
                } label: {
                    if isApplyingExit {
                        ProgressView()
                    } else {
                        Text(loc.t("server_settings_apply"))
                    }
                }
                .disabled(isApplyingExit
                          || exitChoice == .unknown
                          || (exitChoice == .custom && customExitAddr.trimmingCharacters(in: .whitespaces).isEmpty))
            }

            if let exitError {
                Text(exitError).font(.caption2).foregroundColor(.red)
            }
            if let exitResultMessage {
                Text(exitResultMessage).font(.caption2).foregroundColor(.secondary)
            }
        }
    }

    private var effectiveExitAddr: String? {
        switch exitChoice {
        case .unknown, .none:
            return nil
        case .node(let addr):
            return addr
        case .custom:
            let trimmed = customExitAddr.trimmingCharacters(in: .whitespaces)
            return trimmed.isEmpty ? nil : trimmed
        }
    }

    @MainActor
    private func applyExit() async {
        // Belt and braces alongside the disabled Apply button: never send
        // `{"exit_node": null}` from the initial "current value unknown"
        // state — that would clear a global exit nobody asked to clear.
        guard exitChoice != .unknown else { return }
        isApplyingExit = true
        exitError = nil
        exitResultMessage = nil
        let addr = effectiveExitAddr
        let result = await AdminApi.applyGlobalExitNode(addr)
        isApplyingExit = false
        switch result {
        case .success(let resp):
            exitPending = ServerSettingsPendingApply(
                token: resp.token,
                deadline: Date().addingTimeInterval(serverSettingsRollbackWindowSeconds),
                descriptor: addr ?? loc.t("server_settings_exit_none")
            )
        case .failure(let err):
            exitError = err.errorDescription
        }
    }

    @MainActor
    private func confirmExit() async {
        guard let pending = exitPending else { return }
        isConfirmingExit = true
        let result = await AdminApi.confirmConfig(token: pending.token)
        isConfirmingExit = false
        switch result {
        case .success:
            exitPending = nil
            exitResultMessage = loc.t("server_settings_confirmed")
        case .failure(let err):
            exitError = err.errorDescription
        }
    }

    @MainActor
    private func exitExpired() {
        exitPending = nil
        exitResultMessage = loc.t("server_settings_reverted")
    }

    // MARK: - Loading

    @MainActor
    private func loadChoices() async {
        async let clientsResult = AdminApi.listClients()
        async let poolResult = AdminApi.poolNodes()
        async let masksResult = serverSettingsLoadMaskChoices()
        let (clientsOutcome, poolOutcome, masks) = await (clientsResult, poolResult, masksResult)

        switch clientsOutcome {
        case .success(let list):
            clients = list
            if selectedClientId.isEmpty, let first = list.first {
                selectedClientId = first.id
            }
        case .failure(let err):
            maskError = err.errorDescription
        }

        maskChoices = masks
        if selectedMaskId.isEmpty, let first = masks.first {
            selectedMaskId = first.id
        }

        if case .success(let nodes) = poolOutcome {
            let addrs = nodes.compactMap { $0.address?.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            poolNodeAddresses = Array(Set(addrs)).sorted()
        }
    }
}
