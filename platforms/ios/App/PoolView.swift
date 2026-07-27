import SwiftUI

// In-app pool topology screen (Wave B3-iOS): read-only view of pool nodes,
// aggregate health, and per-peer sync links, backed by AdminApi.swift's
// poolNodes()/poolHealth()/poolLinks() wrappers around
// `GET /api/v1/pool/{nodes,health,links}` (crates/aivpn-server/src/
// mgmt_service.rs). Presented as a sheet from AdminView, which (G-A1) is
// gated on AdminApi.role() >= 1 (Viewer or Admin) — there is no separate
// role check here because every control on this screen is a plain GET
// (`authorize()` allows those to Viewer server-side too) and there is
// nothing here to mutate.

private func poolFormatUnix(_ unix: Int64) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(unix))
    let df = DateFormatter()
    df.dateStyle = .medium
    df.timeStyle = .short
    return df.string(from: date)
}

struct PoolView: View {
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @State private var nodes: [AdminPoolNode] = []
    @State private var links: [AdminPoolLink] = []
    @State private var health: AdminPoolHealth?
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if isLoading && nodes.isEmpty && health == nil {
                    ProgressView(loc.t("admin_loading"))
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

                        if let health, health.partition_conflict || health.subnet_mismatch {
                            Section {
                                Label(loc.t("pool_conflict_warning"), systemImage: "exclamationmark.triangle.fill")
                                    .foregroundColor(.orange)
                                    .font(.callout)
                            }
                        }

                        if let health {
                            Section(header: Text(loc.t("pool_health_section"))) {
                                LabeledContent(loc.t("pool_transport"), value: transportLabel(health.transport))
                                LabeledContent(loc.t("pool_total_nodes"), value: "\(health.total_nodes)")
                                LabeledContent(loc.t("pool_connected_peers"), value: "\(health.connected_peers)")
                                LabeledContent(loc.t("pool_converged_peers"), value: "\(health.converged_peers)")
                                LabeledContent(loc.t("pool_diverged"), value: health.diverged ? loc.t("admin_yes") : loc.t("admin_no"))
                            }
                        }

                        Section(header: Text(loc.t("pool_nodes_section"))) {
                            if nodes.isEmpty {
                                Text(loc.t("pool_no_nodes"))
                                    .foregroundColor(.secondary)
                                    .font(.caption)
                            } else {
                                ForEach(nodes) { node in
                                    PoolNodeRow(node: node, loc: loc)
                                }
                            }
                        }

                        if !links.isEmpty {
                            Section(header: Text(loc.t("pool_links_section"))) {
                                ForEach(links) { link in
                                    PoolLinkRow(link: link, loc: loc)
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .refreshable { await loadAll() }
                }
            }
            .navigationTitle(loc.t("pool_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
        }
        .task { await loadAll() }
    }

    private func transportLabel(_ transport: String) -> String {
        switch transport {
        case "masked": return loc.t("pool_transport_masked")
        case "legacy": return loc.t("pool_transport_legacy")
        case "none": return loc.t("pool_transport_none")
        default: return transport
        }
    }

    /// Fires all three GETs concurrently — they're independent read-only
    /// calls, and the tunnel-IPC mgmt path (`AdminApi.request` →
    /// `VPNManager.mgmtRequest` → the extension's correlated
    /// `aivpn_mgmt_request` calls) handles concurrent in-flight requests.
    @MainActor
    private func loadAll() async {
        isLoading = true
        errorMessage = nil
        async let nodesResult = AdminApi.poolNodes()
        async let healthResult = AdminApi.poolHealth()
        async let linksResult = AdminApi.poolLinks()
        let (nodesOutcome, healthOutcome, linksOutcome) = await (nodesResult, healthResult, linksResult)
        isLoading = false

        switch nodesOutcome {
        case .success(let list):
            nodes = list
        case .failure(let err):
            errorMessage = err.errorDescription
        }
        switch healthOutcome {
        case .success(let value):
            health = value
        case .failure(let err):
            errorMessage = errorMessage ?? err.errorDescription
        }
        switch linksOutcome {
        case .success(let list):
            links = list
        case .failure(let err):
            errorMessage = errorMessage ?? err.errorDescription
        }
    }
}

// MARK: - Node row

private struct PoolNodeRow: View {
    let node: AdminPoolNode
    let loc: LocalizationManager

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(node.node_id)
                    .font(.body)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if node.revoked {
                    Text(loc.t("pool_revoked"))
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.red.opacity(0.15))
                        .foregroundColor(.red)
                        .cornerRadius(4)
                } else if node.verified {
                    Image(systemName: "checkmark.seal.fill")
                        .font(.caption2)
                        .foregroundColor(.blue)
                }
                Spacer()
                Circle()
                    .fill(node.connected ? Color.green : Color.gray)
                    .frame(width: 9, height: 9)
            }
            if let address = node.address {
                Text(address)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            if let lastSeen = node.last_seen_unix {
                Text("\(loc.t("pool_last_seen")): \(poolFormatUnix(lastSeen))")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Link row

private struct PoolLinkRow: View {
    let link: AdminPoolLink
    let loc: LocalizationManager

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(link.peer)
                    .font(.body)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Circle()
                    .fill(link.connected ? (link.converged ? Color.green : Color.orange) : Color.gray)
                    .frame(width: 9, height: 9)
            }
            if let lastConverged = link.last_converged_unix {
                Text("\(loc.t("pool_last_converged")): \(poolFormatUnix(lastConverged))")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            if link.partition_conflict || link.subnet_mismatch {
                Text(link.partition_conflict ? loc.t("pool_partition_conflict") : loc.t("pool_subnet_mismatch"))
                    .font(.caption2)
                    .foregroundColor(.orange)
            }
        }
        .padding(.vertical, 3)
    }
}
