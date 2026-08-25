import SwiftUI

// MARK: - Wire types (G-A2: audit log view)
//
// Mirrors `crates/aivpn-server/src/audit_log.rs::AuditEntry` and
// `crates/aivpn-server/src/mgmt_service.rs::AuditVerifyView` exactly — field
// names match the server's `#[derive(Serialize)]` output verbatim
// (snake_case, no `#[serde(rename_all)]` override on `AuditVerifyView`;
// `AuditEntry`'s own fields are already snake_case). Reached here via
// `AdminApi.auditLog()` (thin GET wrapper around `AdminApi.mgmtRequest` —
// see AdminApi.swift), decoded in `AdminStore.refreshAuditLog()`
// (AdminView.swift), same layering as the pool-topology wire types in
// PoolView.swift.

/// Mirrors `audit_log::AuditEntry` — one entry of `AdminAuditVerifyView.entries`.
/// `actor` is the lowercase string form (`#[serde(rename_all = "snake_case")]`
/// on `AuditActor`): "cli" | "api" | "system".
struct AdminAuditEntryView: Codable, Identifiable, Equatable {
    let ts: String
    let actor: String
    let action: String
    let target: String
    let result: String
    /// Hex hash of the previous entry in the chain (or the all-zero genesis
    /// sentinel for the first entry) — displayed only in the detail
    /// disclosure, mainly useful for manually cross-checking the chain.
    let prev_hash: String
    /// Hex SHA-256 over this entry's own fields. Used as `Identifiable.id`
    /// when non-empty (unique per entry); falls back to a composite of the
    /// other fields for pre-hash-chain log lines that deserialized `hash`
    /// to `""` (see `AuditEntry`'s server-side doc on that default).
    let hash: String

    var id: String { hash.isEmpty ? "\(ts)|\(actor)|\(action)|\(target)|\(result)" : hash }
}

/// Mirrors `mgmt_service::AuditVerifyView` — the object
/// `GET /api/v1/audit-log?verify=1` returns.
struct AdminAuditVerifyView: Codable {
    let entries: [AdminAuditEntryView]
    let verified: Bool
    /// Tail-window index (0-based, oldest-first, matching `entries`) where
    /// the hash chain broke, or nil when `verified` is true.
    let broken_at: Int?
}

// MARK: - Audit log view

/// Read-only audit-log pane shown by `AdminRootView`'s segmented control
/// (G-A2). Available to both Viewer and Admin — the server's `authorize()`
/// allows `audit-log` at Viewer (GET-only, same as every other curated
/// route), and this pane has no mutating controls at all, so it needs no
/// `store.canMutate` gating of its own.
///
/// Same pattern as `AdminPoolView`: takes the shared `AdminStore` (its
/// `@Published var audit*` properties live there since Swift extensions
/// can't add stored properties), refreshing is driven entirely by
/// `AdminRootView` (tab switch / refresh button / window-show
/// notification), and this view is a pure renderer of whatever `store`
/// currently holds.
struct AdminAuditLogView: View {
    @ObservedObject var store: AdminStore
    @EnvironmentObject var loc: LocalizationManager

    var body: some View {
        Group {
            if store.auditChannelUnavailable {
                unavailableView
            } else if store.auditLoading && store.auditEntries.isEmpty {
                VStack {
                    Spacer()
                    ProgressView(loc.t("admin_loading"))
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if store.auditNotConfigured {
                VStack(spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.largeTitle)
                        .foregroundColor(.secondary)
                    Text(loc.t("audit_not_configured_title"))
                        .font(.headline)
                    Text(loc.t("audit_not_configured_message"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: 360)
                }
                .padding(32)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if store.auditEntries.isEmpty {
                VStack {
                    Spacer()
                    Text(loc.t("audit_no_entries"))
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    verifyBanner
                    Divider()
                    List {
                        // Server returns oldest-first; show newest-first —
                        // the audit trail is read as a feed, most recent
                        // action on top, matching every other "activity
                        // log" UI convention.
                        ForEach(Array(store.auditEntries.reversed().enumerated()), id: \.element.id) { index, entry in
                            AdminAuditEntryRow(entry: entry, brokenHere: isBrokenAt(index))
                        }
                    }
                    .listStyle(.inset)
                }
            }
        }
    }

    /// `store.auditBrokenAt` is a 0-based, oldest-first tail-window index
    /// into the server's `entries` array; the list above is reversed
    /// (newest-first), so the matching displayed row is at
    /// `entries.count - 1 - brokenAt`.
    private func isBrokenAt(_ displayedIndex: Int) -> Bool {
        guard let brokenAt = store.auditBrokenAt else { return false }
        return displayedIndex == store.auditEntries.count - 1 - brokenAt
    }

    private var unavailableView: some View {
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
    }

    @ViewBuilder
    private var verifyBanner: some View {
        if let verified = store.auditVerified {
            HStack(spacing: 6) {
                Image(systemName: verified ? "checkmark.seal.fill" : "xmark.seal.fill")
                    .foregroundColor(verified ? .green : .red)
                Text(verified ? loc.t("audit_chain_verified") : loc.t("audit_chain_broken"))
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(verified ? .green : .red)
                Spacer()
                Text("\(store.auditEntries.count)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
    }
}

// MARK: - Entry row

struct AdminAuditEntryRow: View {
    let entry: AdminAuditEntryView
    /// True when this is the first entry (oldest-first tail-window) where
    /// the server-side hash-chain verification found a break — highlighted
    /// inline in addition to the summary banner above.
    let brokenHere: Bool
    @EnvironmentObject var loc: LocalizationManager

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(entry.action)
                    .font(.system(size: 12, weight: .medium))
                Text("(\(entry.actor))")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                Spacer()
                Text(resultLabel)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(isFailure ? .red : .green)
                if brokenHere {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 10))
                        .foregroundColor(.red)
                        .help(loc.t("audit_chain_broken_here"))
                }
            }
            Text(entry.target)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Text(AdminDate.displayString(entry.ts))
                .font(.system(size: 10))
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
    }

    private var isFailure: Bool {
        !entry.result.lowercased().hasPrefix("ok")
    }

    private var resultLabel: String {
        isFailure ? loc.t("audit_result_failed") : loc.t("audit_result_ok")
    }
}
