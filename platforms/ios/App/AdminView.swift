import SwiftUI
import UIKit

// In-app admin screen (P3.2-iOS): client list + add/edit/QR-share/revoke,
// backed by AdminApi.swift's wrapper around the in-tunnel management API
// (routed over provider IPC to the tunnel extension — see AdminApi.swift's
// architecture note — plus the in-process aivpn_qr_png). Presented
// from ContentView.swift as a sheet, gated on AdminApi.role() >= 1
// (Viewer or Admin) — there is no role-editing UI here: role assignment is
// not exposed over the tunnel (see AdminApi.patchClient's doc comment).
//
// G-A1 (Viewer read-only widening): the server authorizes every curated
// route's GET to Viewer role but rejects any mutation with 403 (see
// mgmt_service.rs's `authorize` doc comment) — this screen mirrors that on
// the client side via `canMutate` (`AdminApi.role() == 2`) so a Viewer
// never sees a control that would just bounce off a 403: the "add client"
// toolbar button, the swipe-to-revoke action, and the entire edit /
// reset-device / revoke sections of the detail sheet are hidden, not
// merely disabled, for Viewer. Connection-key display/QR/share is also
// Admin-only because it exposes a live PSK. Other read-only surfaces
// (client list, detail info, pool topology, audit log) stay available to
// both roles.

// MARK: - Small formatting helpers (file-scoped, mirror ContentView.swift's
// private helpers of the same shape but kept separate since those are
// `private` to that file).

private func adminFormatBytes(_ bytes: UInt64) -> String {
    let kb = Double(bytes) / 1024
    let mb = kb / 1024
    let gb = mb / 1024
    if gb >= 1 { return String(format: "%.2f GB", gb) }
    if mb >= 1 { return String(format: "%.2f MB", mb) }
    if kb >= 1 { return String(format: "%.1f KB", kb) }
    return "\(bytes) B"
}

/// Parses an RFC3339 timestamp as produced by chrono's `Serialize` for
/// `DateTime<Utc>` (fractional seconds, numeric `+00:00` offset — not
/// always plain "Z"), trying a fractional-seconds format first.
private func adminParseISO8601(_ s: String) -> Date? {
    let withFractional = ISO8601DateFormatter()
    withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = withFractional.date(from: s) { return d }
    return ISO8601DateFormatter().date(from: s)
}

private func adminDisplayDate(_ s: String) -> String {
    guard let date = adminParseISO8601(s) else { return s }
    let df = DateFormatter()
    df.dateStyle = .medium
    df.timeStyle = .short
    return df.string(from: date)
}

// MARK: - Exit-node picker (G-B1)
//
// Backs the free-text `exit_node` field (Wave B2a) with a `Picker` sourced
// from `GET /api/v1/pool/nodes` (`AdminApi.poolNodes()`), while preserving
// the original manual host:port entry as a "Custom…" option — neither
// `AdminAddClientView` nor `AdminClientDetailView` loses the ability to
// type an arbitrary address, they just gain a faster path for the common
// case of picking a known pool node.

/// Mirrors the three things the `exit_node` string field (`""` | a known
/// pool-node address | an arbitrary address) can resolve to for picker
/// display. `Hashable` is synthesized (Swift auto-derives it for enums
/// whose associated values are themselves `Hashable`, per SE-0185), which
/// is all `Picker`'s `selection:` binding needs for its tags below.
private enum AdminExitNodeChoice: Hashable {
    case globalDefault
    case node(String)
    case custom
}

/// Best-effort: pool sync being unconfigured on this node, or the call
/// failing outright, just yields an empty address list — the picker still
/// works fine via "(default)" and "custom" either way, mirroring
/// `AdminApi.poolNodes()`'s own "always 200 empty array when pool sync
/// isn't configured" contract (see that call's doc comment). Deduplicated
/// and sorted so re-appearances of the same peer (e.g. one entry with a
/// bound `node_id` and one address-only entry that both resolve to the
/// same `address`) don't produce duplicate Picker rows.
private func adminLoadPoolNodeAddresses() async -> [String] {
    guard case .success(let nodes) = await AdminApi.poolNodes() else { return [] }
    let addrs = nodes.compactMap { $0.address?.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty }
    return Array(Set(addrs)).sorted()
}

/// Shared row group (a `Picker` + a conditional manual `TextField`) for the
/// `exit_node` field, used identically by `AdminAddClientView`'s "add" form
/// and `AdminClientDetailView`'s "edit" form. `exitNode` is the SAME
/// `@State` the rest of each view's save logic already reads/trims/sends —
/// this never introduces a second source of truth for the field's value,
/// it only changes how that one binding gets edited: picking a pool node
/// writes its address straight into `exitNode`; picking "Custom…" leaves
/// whatever text is already there (clearing it only when it was a
/// just-deselected pool-node address, so a fresh custom entry starts
/// blank instead of pre-filled with the last-picked node); picking
/// "Global (default)" clears it, same as the old empty-TextField meant.
@ViewBuilder
private func adminExitNodePickerRows(
    exitNode: Binding<String>,
    poolNodeAddresses: [String],
    loc: LocalizationManager
) -> some View {
    let choice = Binding<AdminExitNodeChoice>(
        get: {
            let trimmed = exitNode.wrappedValue.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { return .globalDefault }
            if poolNodeAddresses.contains(trimmed) { return .node(trimmed) }
            return .custom
        },
        set: { newChoice in
            switch newChoice {
            case .globalDefault:
                exitNode.wrappedValue = ""
            case .node(let addr):
                exitNode.wrappedValue = addr
            case .custom:
                let trimmed = exitNode.wrappedValue.trimmingCharacters(in: .whitespaces)
                if poolNodeAddresses.contains(trimmed) {
                    exitNode.wrappedValue = ""
                }
            }
        }
    )
    Picker(loc.t("admin_exit_node"), selection: choice) {
        Text(loc.t("admin_exit_node_global")).tag(AdminExitNodeChoice.globalDefault)
        ForEach(poolNodeAddresses, id: \.self) { addr in
            Text(addr).tag(AdminExitNodeChoice.node(addr))
        }
        Text(loc.t("admin_exit_node_custom")).tag(AdminExitNodeChoice.custom)
    }
    if choice.wrappedValue == .custom {
        TextField(loc.t("admin_exit_node"), text: exitNode)
            .autocorrectionDisabled()
            .autocapitalization(.none)
            .keyboardType(.asciiCapable)
    }
}

// MARK: - Main admin screen

struct AdminView: View {
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @State private var clients: [AdminClient] = []
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var showAddClient = false
    @State private var detailClient: AdminClient?
    @State private var revokeTarget: AdminClient?
    @State private var showRevokeConfirm = false
    @State private var showPool = false
    @State private var showAuditLog = false
    @State private var showServerSettings = false

    /// `true` only for the Admin role (2) — Viewer (1) reaches this screen
    /// (see the header comment's G-A1 note) but every mutating control is
    /// gated on this. Cheap: `AdminApi.role()` reads the role VPNManager
    /// polled from the tunnel extension (main-thread; `body` always is).
    private var canMutate: Bool { AdminApi.role() == 2 }

    var body: some View {
        NavigationStack {
            Group {
                if isLoading && clients.isEmpty {
                    ProgressView(loc.t("admin_loading"))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if clients.isEmpty {
                    VStack(spacing: 12) {
                        Text(loc.t("admin_no_clients"))
                            .foregroundColor(.secondary)
                        if let errorMessage {
                            Text(errorMessage)
                                .font(.caption)
                                .foregroundColor(.red)
                                .multilineTextAlignment(.center)
                        }
                        if canMutate {
                            Button(loc.t("admin_add_client")) { showAddClient = true }
                                .buttonStyle(.bordered)
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List {
                        if let errorMessage {
                            Section {
                                Text(errorMessage)
                                    .font(.caption)
                                    .foregroundColor(.red)
                            }
                        }
                        Section {
                            ForEach(clients) { client in
                                Button {
                                    detailClient = client
                                } label: {
                                    AdminClientRow(client: client, loc: loc)
                                }
                                .buttonStyle(.plain)
                                .swipeActions(edge: .trailing) {
                                    if canMutate {
                                        Button(role: .destructive) {
                                            revokeTarget = client
                                            showRevokeConfirm = true
                                        } label: {
                                            Label(loc.t("admin_revoke"), systemImage: "xmark.shield")
                                        }
                                    }
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .refreshable { await loadClients() }
                }
            }
            .navigationTitle(loc.t("admin_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if canMutate {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button {
                            showAddClient = true
                        } label: {
                            Image(systemName: "plus.circle.fill")
                        }
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showAuditLog = true
                    } label: {
                        Image(systemName: "list.bullet.rectangle")
                    }
                    .accessibilityLabel(Text(loc.t("audit_title")))
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showPool = true
                    } label: {
                        Image(systemName: "network")
                    }
                    .accessibilityLabel(Text(loc.t("pool_title")))
                }
                // G-A3: apply-with-rollback server settings — Admin only,
                // same gate as the "add client" button above, since every
                // control on that screen mutates (see
                // ServerSettingsView.swift's header comment).
                if canMutate {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button {
                            showServerSettings = true
                        } label: {
                            Image(systemName: "gearshape")
                        }
                        .accessibilityLabel(Text(loc.t("server_settings_title")))
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
        }
        .task { await loadClients() }
        .sheet(isPresented: $showPool) {
            PoolView().environmentObject(loc)
        }
        .sheet(isPresented: $showAuditLog) {
            AuditLogView().environmentObject(loc)
        }
        .sheet(isPresented: $showServerSettings) {
            ServerSettingsView().environmentObject(loc)
        }
        .sheet(isPresented: $showAddClient) {
            AdminAddClientView { newClient, warning in
                showAddClient = false
                if let newClient {
                    clients.append(newClient)
                }
                if let warning {
                    errorMessage = warning
                }
            }
            .environmentObject(loc)
        }
        .sheet(item: $detailClient) { client in
            AdminClientDetailView(
                client: client,
                onUpdated: { updated in
                    if let idx = clients.firstIndex(where: { $0.id == updated.id }) {
                        clients[idx] = updated
                    }
                },
                onRevoked: { revokedId in
                    clients.removeAll { $0.id == revokedId }
                    detailClient = nil
                }
            )
            .environmentObject(loc)
        }
        .confirmationDialog(
            loc.t("admin_revoke_confirm_title"),
            isPresented: $showRevokeConfirm,
            titleVisibility: .visible
        ) {
            Button(loc.t("admin_revoke"), role: .destructive) {
                if let target = revokeTarget {
                    Task { await revoke(target) }
                }
                revokeTarget = nil
            }
            Button(loc.t("cancel"), role: .cancel) { revokeTarget = nil }
        } message: {
            Text(loc.t("admin_revoke_confirm_message"))
        }
    }

    @MainActor
    private func loadClients() async {
        isLoading = true
        let result = await AdminApi.listClients()
        isLoading = false
        switch result {
        case .success(let list):
            clients = list
            errorMessage = nil
        case .failure(let err):
            errorMessage = err.errorDescription
        }
    }

    @MainActor
    private func revoke(_ client: AdminClient) async {
        let result = await AdminApi.revokeClient(id: client.id)
        switch result {
        case .success:
            clients.removeAll { $0.id == client.id }
        case .failure(let err):
            errorMessage = err.errorDescription
        }
    }
}

// MARK: - Client row

private struct AdminClientRow: View {
    let client: AdminClient
    let loc: LocalizationManager

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(client.name)
                        .font(.body)
                        .foregroundColor(.primary)
                    if client.role != "user" {
                        Text(roleLabel)
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.accentColor.opacity(0.15))
                            .foregroundColor(.accentColor)
                            .cornerRadius(4)
                    }
                    if client.one_time {
                        Image(systemName: "1.circle")
                            .font(.caption2)
                            .foregroundColor(.orange)
                    }
                }
                Text(client.vpn_ip)
                    .font(.caption)
                    .foregroundColor(.secondary)
                if let exitNode = client.exit_node, !exitNode.isEmpty {
                    HStack(spacing: 3) {
                        Image(systemName: "arrow.triangle.branch")
                        Text(exitNode)
                    }
                    .font(.caption2)
                    .foregroundColor(.purple)
                }
            }
            Spacer()
            Circle()
                .fill(client.enabled ? Color.green : Color.red)
                .frame(width: 9, height: 9)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    private var roleLabel: String {
        switch client.role {
        case "admin": return loc.t("admin_role_admin")
        case "viewer": return loc.t("admin_role_viewer")
        default: return client.role
        }
    }
}

// MARK: - Add client sheet

private struct AdminAddClientView: View {
    @EnvironmentObject private var loc: LocalizationManager
    /// `(createdClient, nonFatalWarning)` — `warning` is set when the
    /// client itself was created successfully but the follow-up
    /// exit-node PATCH failed (see `save()`'s doc comment); the caller
    /// dismisses this sheet either way, so the warning is surfaced via
    /// the parent `AdminView`'s own error banner instead of here.
    let onComplete: (AdminClient?, String?) -> Void

    @State private var name: String = ""
    @State private var oneTime: Bool = false
    @State private var hasExpiry: Bool = false
    @State private var expiresAt: Date = Date().addingTimeInterval(86400 * 30)
    @State private var exitNode: String = ""
    @State private var poolNodeAddresses: [String] = []
    @State private var isSaving = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(loc.t("admin_client_name"), text: $name)
                        .autocorrectionDisabled()
                }
                Section {
                    Toggle(loc.t("admin_one_time"), isOn: $oneTime)
                    Toggle(loc.t("admin_has_expiry"), isOn: $hasExpiry.animation())
                    if hasExpiry {
                        DatePicker(
                            loc.t("admin_expires_at"),
                            selection: $expiresAt,
                            in: Date()...,
                            displayedComponents: [.date, .hourAndMinute]
                        )
                    }
                }
                Section(footer: Text(loc.t("admin_exit_node_hint"))) {
                    adminExitNodePickerRows(exitNode: $exitNode, poolNodeAddresses: poolNodeAddresses, loc: loc)
                }
                if let errorMessage {
                    Section {
                        Text(errorMessage)
                            .foregroundColor(.red)
                            .font(.caption)
                    }
                }
            }
            .navigationTitle(loc.t("admin_add_client"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(loc.t("cancel")) { onComplete(nil, nil) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isSaving {
                        ProgressView()
                    } else {
                        Button(loc.t("admin_save")) {
                            Task { await save() }
                        }
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            }
            .task { poolNodeAddresses = await adminLoadPoolNodeAddresses() }
        }
    }

    @MainActor
    private func save() async {
        isSaving = true
        errorMessage = nil
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        let trimmedExitNode = exitNode.trimmingCharacters(in: .whitespaces)
        let result = await AdminApi.addClient(
            name: trimmed,
            oneTime: oneTime,
            expiresAt: hasExpiry ? expiresAt : nil
        )
        switch result {
        case .success(let client):
            // `TunnelAddClientRequest` (the POST /api/v1/clients wire body)
            // has no `exit_node` field — see mgmt_service.rs's doc comment
            // on that type — so a per-client exit node can only be applied
            // as a follow-up PATCH after creation. If it fails, the client
            // itself was still created successfully; surface the PATCH
            // error but still hand the created client back so it shows up
            // in the list (the operator can retry setting it from the
            // detail/edit screen).
            if trimmedExitNode.isEmpty {
                isSaving = false
                onComplete(client, nil)
            } else {
                let patchResult = await AdminApi.patchClient(id: client.id, exitNode: .set(trimmedExitNode))
                isSaving = false
                switch patchResult {
                case .success(let updated):
                    onComplete(updated, nil)
                case .failure(let err):
                    onComplete(client, err.errorDescription)
                }
            }
        case .failure(let err):
            isSaving = false
            errorMessage = err.errorDescription
        }
    }
}

// MARK: - Client detail / edit sheet

private struct AdminClientDetailView: View {
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @State private var client: AdminClient
    let onUpdated: (AdminClient) -> Void
    let onRevoked: (String) -> Void

    init(client: AdminClient, onUpdated: @escaping (AdminClient) -> Void, onRevoked: @escaping (String) -> Void) {
        _client = State(initialValue: client)
        self.onUpdated = onUpdated
        self.onRevoked = onRevoked
    }

    @State private var editedName: String = ""
    @State private var editedEnabled: Bool = true
    @State private var editedOneTime: Bool = false
    @State private var editedHasExpiry: Bool = false
    @State private var editedExpiresAt: Date = Date().addingTimeInterval(86400 * 30)
    @State private var editedExitNode: String = ""
    @State private var poolNodeAddresses: [String] = []
    @State private var isSavingEdit = false

    @State private var connectionKey: String?
    @State private var qrImage: UIImage?
    @State private var isLoadingKey = false
    @State private var keyError: String?

    @State private var isResettingDevice = false
    @State private var resetMessage: String?

    @State private var showRevokeConfirm = false
    @State private var isRevoking = false
    @State private var actionError: String?

    /// `true` only for the Admin role — see `AdminView.canMutate`'s doc
    /// comment; this view is presented from both `AdminView`'s client list
    /// (Viewer+Admin) and its own edit/reset/revoke actions are 403'd
    /// server-side for Viewer, so they're hidden here too.
    private var canMutate: Bool { AdminApi.role() == 2 }

    var body: some View {
        NavigationStack {
            Form {
                if canMutate {
                    Section(header: Text(loc.t("admin_edit_section"))) {
                        TextField(loc.t("admin_client_name"), text: $editedName)
                            .autocorrectionDisabled()
                        Toggle(loc.t("admin_enabled"), isOn: $editedEnabled)
                        Toggle(loc.t("admin_one_time"), isOn: $editedOneTime)
                        Toggle(loc.t("admin_has_expiry"), isOn: $editedHasExpiry.animation())
                        if editedHasExpiry {
                            DatePicker(
                                loc.t("admin_expires_at"),
                                selection: $editedExpiresAt,
                                displayedComponents: [.date, .hourAndMinute]
                            )
                        }
                        adminExitNodePickerRows(exitNode: $editedExitNode, poolNodeAddresses: poolNodeAddresses, loc: loc)
                        Text(loc.t("admin_exit_node_hint"))
                            .font(.caption2)
                            .foregroundColor(.secondary)
                        Button {
                            Task { await saveEdits() }
                        } label: {
                            if isSavingEdit {
                                ProgressView()
                            } else {
                                Text(loc.t("admin_save"))
                            }
                        }
                        .disabled(isSavingEdit || editedName.trimmingCharacters(in: .whitespaces).isEmpty)
                        if let actionError {
                            Text(actionError).font(.caption).foregroundColor(.red)
                        }
                    }
                }

                Section(header: Text(loc.t("admin_info"))) {
                    LabeledContent(loc.t("admin_vpn_ip"), value: client.vpn_ip)
                    LabeledContent(loc.t("admin_role"), value: roleLabel)
                    LabeledContent(loc.t("admin_device_bound"), value: client.device_bound ? loc.t("admin_yes") : loc.t("admin_no"))
                    LabeledContent(loc.t("admin_created_at"), value: adminDisplayDate(client.created_at))
                    LabeledContent(loc.t("admin_traffic_in"), value: adminFormatBytes(client.stats.bytes_in))
                    LabeledContent(loc.t("admin_traffic_out"), value: adminFormatBytes(client.stats.bytes_out))
                    LabeledContent(loc.t("admin_exit_node"), value: exitNodeDisplayValue)
                }

                if canMutate {
                    Section(header: Text(loc.t("admin_connection_key"))) {
                        if let connectionKey {
                            Text(connectionKey)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(4)
                            if let qrImage {
                                Image(uiImage: qrImage)
                                    .interpolation(.none)
                                    .resizable()
                                    .aspectRatio(1, contentMode: .fit)
                                    .frame(maxWidth: 220)
                                    .frame(maxWidth: .infinity)
                            }
                            HStack {
                                Button {
                                    // A live, redeemable connection key. `.string`
                                    // would leave it on the general pasteboard
                                    // indefinitely — readable by every app the user
                                    // next foregrounds and mirrored to other devices
                                    // via Universal Clipboard. `.localOnly` keeps it
                                    // on this device and `.expirationDate` has the
                                    // system drop it after the paste window.
                                    UIPasteboard.general.setItems(
                                        [["public.utf8-plain-text": connectionKey]],
                                        options: [
                                            .localOnly: true,
                                            .expirationDate: Date().addingTimeInterval(120),
                                        ]
                                    )
                                } label: {
                                    Label(loc.t("admin_copy"), systemImage: "doc.on.doc")
                                }
                                Spacer()
                                ShareLink(item: connectionKey) {
                                    Label(loc.t("admin_share"), systemImage: "square.and.arrow.up")
                                }
                            }
                            .buttonStyle(.bordered)
                        } else if isLoadingKey {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            Button(loc.t("admin_show_connection_key")) {
                                Task { await loadConnectionKey() }
                            }
                        }
                        if let keyError {
                            Text(keyError).font(.caption).foregroundColor(.red)
                        }
                    }
                }

                if canMutate {
                    Section {
                        Button {
                            Task { await resetDevice() }
                        } label: {
                            if isResettingDevice {
                                ProgressView()
                            } else {
                                Label(loc.t("admin_reset_device"), systemImage: "arrow.counterclockwise")
                            }
                        }
                        .disabled(isResettingDevice)
                        if let resetMessage {
                            Text(resetMessage).font(.caption).foregroundColor(.secondary)
                        }
                    } footer: {
                        Text(loc.t("admin_reset_device_hint"))
                    }

                    Section {
                        Button(role: .destructive) {
                            showRevokeConfirm = true
                        } label: {
                            if isRevoking {
                                ProgressView()
                            } else {
                                Label(loc.t("admin_revoke"), systemImage: "xmark.shield")
                            }
                        }
                        .disabled(isRevoking)
                    }
                }
            }
            .navigationTitle(client.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
            .onAppear { resetEditedFields() }
            // Viewer (role 1) can open this sheet too (read-only info), but
            // the exit-node picker this feeds is inside the `if canMutate`
            // edit section above — skip the extra `/pool/nodes` round trip
            // for a role that will never see it.
            .task { if canMutate { poolNodeAddresses = await adminLoadPoolNodeAddresses() } }
            .confirmationDialog(
                loc.t("admin_revoke_confirm_title"),
                isPresented: $showRevokeConfirm,
                titleVisibility: .visible
            ) {
                Button(loc.t("admin_revoke"), role: .destructive) {
                    Task { await revoke() }
                }
                Button(loc.t("cancel"), role: .cancel) {}
            } message: {
                Text(loc.t("admin_revoke_confirm_message"))
            }
        }
    }

    private var roleLabel: String {
        switch client.role {
        case "admin": return loc.t("admin_role_admin")
        case "viewer": return loc.t("admin_role_viewer")
        default: return loc.t("admin_role_user")
        }
    }

    private var exitNodeDisplayValue: String {
        if let exitNode = client.exit_node, !exitNode.isEmpty {
            return exitNode
        }
        return loc.t("admin_exit_node_global")
    }

    private func resetEditedFields() {
        editedName = client.name
        editedEnabled = client.enabled
        editedOneTime = client.one_time
        if let expiresAtString = client.expires_at, let date = adminParseISO8601(expiresAtString) {
            editedHasExpiry = true
            editedExpiresAt = date
        } else {
            editedHasExpiry = false
            editedExpiresAt = Date().addingTimeInterval(86400 * 30)
        }
        editedExitNode = client.exit_node ?? ""
    }

    @MainActor
    private func saveEdits() async {
        isSavingEdit = true
        actionError = nil
        let trimmed = editedName.trimmingCharacters(in: .whitespaces)

        // Tri-state diff against the original: collapse to `.unchanged`
        // (key omitted entirely) when the edited value still matches what
        // the server last reported, so an edit screen opened and saved
        // without touching the expiry never sends a spurious
        // `expires_at: null` (or a re-set of the same instant) that would
        // land a pointless ClientPatch mutation + audit entry server-side.
        // The 1s tolerance absorbs the fractional seconds chrono serializes
        // but `iso8601.string(from:)` would drop on the way back.
        let originalExpiry = client.expires_at.flatMap { adminParseISO8601($0) }
        let expiryField: AdminPatchField<Date>
        if editedHasExpiry {
            if let orig = originalExpiry, abs(orig.timeIntervalSince(editedExpiresAt)) < 1 {
                expiryField = .unchanged
            } else {
                expiryField = .set(editedExpiresAt)
            }
        } else {
            expiryField = originalExpiry == nil ? .unchanged : .clear
        }

        // Same tri-state diff for the exit node, per the same rule.
        let trimmedExitNode = editedExitNode.trimmingCharacters(in: .whitespaces)
        let originalExitNode = client.exit_node ?? ""
        let exitNodeField: AdminPatchField<String>
        if trimmedExitNode == originalExitNode {
            exitNodeField = .unchanged
        } else if trimmedExitNode.isEmpty {
            exitNodeField = .clear
        } else {
            exitNodeField = .set(trimmedExitNode)
        }

        let result = await AdminApi.patchClient(
            id: client.id,
            name: trimmed == client.name ? nil : trimmed,
            enabled: editedEnabled == client.enabled ? nil : editedEnabled,
            oneTime: editedOneTime == client.one_time ? nil : editedOneTime,
            expiresAt: expiryField,
            exitNode: exitNodeField
        )
        isSavingEdit = false
        switch result {
        case .success(let updated):
            client = updated
            onUpdated(updated)
        case .failure(let err):
            actionError = err.errorDescription
        }
    }

    @MainActor
    private func loadConnectionKey() async {
        isLoadingKey = true
        keyError = nil
        let result = await AdminApi.connectionKey(id: client.id)
        switch result {
        case .success(let key):
            connectionKey = key
            isLoadingKey = false
            if let pngData = await AdminApi.qrPngData(key), let image = UIImage(data: pngData) {
                qrImage = image
            }
        case .failure(let err):
            isLoadingKey = false
            keyError = err.errorDescription
        }
    }

    @MainActor
    private func resetDevice() async {
        isResettingDevice = true
        resetMessage = nil
        let result = await AdminApi.resetDevice(id: client.id)
        isResettingDevice = false
        switch result {
        case .success:
            resetMessage = loc.t("admin_reset_device_done")
        case .failure(let err):
            resetMessage = err.errorDescription
        }
    }

    @MainActor
    private func revoke() async {
        isRevoking = true
        actionError = nil
        let result = await AdminApi.revokeClient(id: client.id)
        isRevoking = false
        switch result {
        case .success:
            onRevoked(client.id)
            dismiss()
        case .failure(let err):
            actionError = err.errorDescription
        }
    }
}
