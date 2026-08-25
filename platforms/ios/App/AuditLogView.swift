import SwiftUI

// In-app audit-log screen (G-A2): read-only view of the server's
// append-only audit log with hash-chain verification, backed by
// AdminApi.swift's `auditLog()` wrapper around
// `GET /api/v1/audit-log?limit=N&verify=1` (crates/aivpn-server/src/
// mgmt_service.rs's `audit_verify`/`AuditVerifyView`). Presented as a
// sheet from AdminView, which (G-A1) is gated on AdminApi.role() >= 1
// (Viewer or Admin) — there is nothing to mutate on this screen, so, like
// PoolView.swift, no separate role check is needed here: the underlying
// route is a plain GET, Viewer-authorized server-side.

private func auditParseISO8601(_ s: String) -> Date? {
    let withFractional = ISO8601DateFormatter()
    withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = withFractional.date(from: s) { return d }
    return ISO8601DateFormatter().date(from: s)
}

private func auditDisplayDate(_ s: String) -> String {
    guard let date = auditParseISO8601(s) else { return s }
    let df = DateFormatter()
    df.dateStyle = .medium
    df.timeStyle = .medium
    return df.string(from: date)
}

struct AuditLogView: View {
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @State private var entries: [AdminAuditEntry] = []
    @State private var verified: Bool = true
    @State private var brokenAt: Int?
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if isLoading && entries.isEmpty {
                    ProgressView(loc.t("admin_loading"))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if entries.isEmpty {
                    VStack(spacing: 12) {
                        Text(loc.t("audit_no_entries"))
                            .foregroundColor(.secondary)
                        if let errorMessage {
                            Text(errorMessage)
                                .font(.caption)
                                .foregroundColor(.red)
                                .multilineTextAlignment(.center)
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
                            HStack(spacing: 8) {
                                Image(systemName: verified ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                                    .foregroundColor(verified ? .green : .red)
                                Text(verified ? loc.t("audit_chain_verified") : loc.t("audit_chain_broken"))
                                    .font(.callout)
                                    .fontWeight(.medium)
                                    .foregroundColor(verified ? .primary : .red)
                                Spacer()
                            }
                            if !verified, let brokenAt {
                                Text("\(loc.t("audit_broken_at")) \(brokenAt)")
                                    .font(.caption2)
                                    .foregroundColor(.red)
                            }
                        }
                        // Newest first for a log-reading UI; `audit_tail`
                        // returns the window oldest-first (matching
                        // `broken_at`'s index convention above), so this
                        // reverses only for display.
                        Section {
                            ForEach(entries.reversed()) { entry in
                                AuditEntryRow(entry: entry, loc: loc)
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .refreshable { await load() }
                }
            }
            .navigationTitle(loc.t("audit_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
        }
        .task { await load() }
    }

    @MainActor
    private func load() async {
        isLoading = true
        let result = await AdminApi.auditLog()
        isLoading = false
        switch result {
        case .success(let value):
            entries = value.entries
            verified = value.verified
            brokenAt = value.brokenAt
            errorMessage = nil
        case .failure(let err):
            errorMessage = err.errorDescription
        }
    }
}

// MARK: - Entry row

private struct AuditEntryRow: View {
    let entry: AdminAuditEntry
    let loc: LocalizationManager

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(entry.action)
                    .font(.body)
                    .fontWeight(.medium)
                Spacer()
                Text(auditDisplayDate(entry.ts))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            if !entry.target.isEmpty {
                Text(entry.target)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            HStack(spacing: 10) {
                Text("\(loc.t("audit_actor")): \(actorLabel)")
                Text("\(loc.t("audit_result")): \(entry.result)")
                    .foregroundColor(entry.result == "ok" ? .secondary : .red)
            }
            .font(.caption2)
            .foregroundColor(.secondary)
        }
        .padding(.vertical, 3)
    }

    // `AuditActor` is `#[serde(rename_all = "snake_case")]` server-side
    // (audit_log.rs) — the wire value is lowercase ("cli"/"api"/"system"),
    // NOT the Rust variant name.
    private var actorLabel: String {
        switch entry.actor {
        case "cli": return loc.t("audit_actor_cli")
        case "api": return loc.t("audit_actor_api")
        case "system": return loc.t("audit_actor_system")
        default: return entry.actor
        }
    }
}
