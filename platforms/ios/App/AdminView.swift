import SwiftUI
import UIKit

// In-app admin screen (P3.2-iOS): client list + add/edit/QR-share/revoke,
// backed by AdminApi.swift's wrapper around the in-tunnel management API
// (aivpn_mgmt_request / aivpn_qr_png, see crates/aivpn-ios-core). Presented
// from ContentView.swift as a sheet, gated on AdminApi.role() == 2 (Admin) —
// there is no role-editing UI here: role assignment is not exposed over the
// tunnel (see AdminApi.patchClient's doc comment).

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
                        Button(loc.t("admin_add_client")) { showAddClient = true }
                            .buttonStyle(.bordered)
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
                    .listStyle(.insetGrouped)
                    .refreshable { await loadClients() }
                }
            }
            .navigationTitle(loc.t("admin_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        showAddClient = true
                    } label: {
                        Image(systemName: "plus.circle.fill")
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
        }
        .task { await loadClients() }
        .sheet(isPresented: $showAddClient) {
            AdminAddClientView { newClient in
                showAddClient = false
                if let newClient {
                    clients.append(newClient)
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
    let onComplete: (AdminClient?) -> Void

    @State private var name: String = ""
    @State private var oneTime: Bool = false
    @State private var hasExpiry: Bool = false
    @State private var expiresAt: Date = Date().addingTimeInterval(86400 * 30)
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
                    Button(loc.t("cancel")) { onComplete(nil) }
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
        }
    }

    @MainActor
    private func save() async {
        isSaving = true
        errorMessage = nil
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        let result = await AdminApi.addClient(
            name: trimmed,
            oneTime: oneTime,
            expiresAt: hasExpiry ? expiresAt : nil
        )
        isSaving = false
        switch result {
        case .success(let client):
            onComplete(client)
        case .failure(let err):
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

    var body: some View {
        NavigationStack {
            Form {
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

                Section(header: Text(loc.t("admin_info"))) {
                    LabeledContent(loc.t("admin_vpn_ip"), value: client.vpn_ip)
                    LabeledContent(loc.t("admin_role"), value: roleLabel)
                    LabeledContent(loc.t("admin_device_bound"), value: client.device_bound ? loc.t("admin_yes") : loc.t("admin_no"))
                    LabeledContent(loc.t("admin_created_at"), value: adminDisplayDate(client.created_at))
                    LabeledContent(loc.t("admin_traffic_in"), value: adminFormatBytes(client.stats.bytes_in))
                    LabeledContent(loc.t("admin_traffic_out"), value: adminFormatBytes(client.stats.bytes_out))
                }

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
                                UIPasteboard.general.string = connectionKey
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
            .navigationTitle(client.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
            .onAppear { resetEditedFields() }
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
    }

    @MainActor
    private func saveEdits() async {
        isSavingEdit = true
        actionError = nil
        let trimmed = editedName.trimmingCharacters(in: .whitespaces)
        let expiryField: AdminPatchField<Date> = editedHasExpiry ? .set(editedExpiresAt) : .clear
        let result = await AdminApi.patchClient(
            id: client.id,
            name: trimmed == client.name ? nil : trimmed,
            enabled: editedEnabled == client.enabled ? nil : editedEnabled,
            oneTime: editedOneTime == client.one_time ? nil : editedOneTime,
            expiresAt: expiryField
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
