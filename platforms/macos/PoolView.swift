import SwiftUI

// MARK: - Wire types (Wave B3-macOS: pool topology view)
//
// Mirrors `crates/aivpn-server/src/mgmt_service.rs::PoolNodeInfo`/
// `PoolHealth` exactly — field names match the server's `#[derive(Serialize)]`
// output verbatim (snake_case, no `#[serde(rename_all)]` override on either
// struct), so no `CodingKeys` are needed. Reached here via
// `AdminApi.poolNodes()`/`AdminApi.poolHealth()` (thin GET wrappers around
// `AdminApi.mgmtRequest` — see AdminApi.swift), decoded in
// `AdminStore.refreshPoolNodes()`/`refreshPoolHealth()` (AdminView.swift),
// same layering as the client-CRUD wire types at the top of that file.

/// Mirrors `mgmt_service::PoolNodeInfo` — one entry of the array
/// `GET /api/v1/pool/nodes` returns.
struct AdminPoolNodeView: Codable, Identifiable, Equatable {
    var id: String { node_id }
    let node_id: String
    /// `nil` for a node this registry knows about (bound crypto identity or
    /// a revoked entry) that isn't — or isn't yet — one of this node's
    /// configured dial-set peers.
    let address: String?
    /// `true` iff this node has a durable, TOFU/manually-pinned Ed25519
    /// binding in the node registry.
    let verified: Bool
    let revoked: Bool
    /// `true` iff a masked dialed session to this peer is up right now.
    let connected: Bool
    let last_seen_unix: Int?
}

/// Mirrors `mgmt_service::PoolHealth` — the object `GET /api/v1/pool/health`
/// returns.
struct AdminPoolHealthView: Codable, Equatable {
    /// `"masked"`, `"legacy"`, or `"none"` — see `PoolHealth::transport`'s
    /// doc comment server-side. Only `"masked"` ever has non-zero
    /// node/peer counts; `"legacy"`/`"none"` are degraded-but-valid 200s.
    let transport: String
    let total_nodes: Int
    let connected_peers: Int
    let converged_peers: Int
    /// Coarse "something is out of sync right now" dashboard flag.
    let diverged: Bool
    /// Coarse "at least one peer collides with our VPN-IP partition index"
    /// dashboard flag (Wave B-IP.2).
    let partition_conflict: Bool
    /// Coarse "at least one peer disagrees with our VPN subnet" dashboard
    /// flag (Wave B-IP.2).
    let subnet_mismatch: Bool
}

// MARK: - Pool view

/// Read-only pool topology pane shown by `AdminRootView`'s segmented
/// control (Wave B3-macOS). Takes the same `AdminStore` the Clients pane
/// uses — `@Published var poolNodes`/`poolHealth`/`poolLoading`/
/// `poolChannelUnavailable` live there (AdminView.swift) since Swift
/// extensions can't add stored `@Published` properties; only the refresh
/// methods and this view live in this file.
///
/// Refreshing is driven entirely by `AdminRootView` (tab switch / refresh
/// button / window-show notification) — this view is a pure renderer of
/// whatever `store` currently holds, exactly like `AdminRootView.content`
/// is for the Clients pane.
struct AdminPoolView: View {
    @ObservedObject var store: AdminStore
    @EnvironmentObject var loc: LocalizationManager

    var body: some View {
        Group {
            if store.poolChannelUnavailable {
                unavailableView
            } else if store.poolLoading && store.poolNodes.isEmpty && store.poolHealth == nil {
                VStack {
                    Spacer()
                    ProgressView(loc.t("admin_loading"))
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        healthSection
                        Divider()
                        nodesSection
                    }
                    .padding(16)
                }
            }
        }
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

    // MARK: Health summary

    @ViewBuilder
    private var healthSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(loc.t("admin_pool_health"))
                .font(.subheadline)
                .fontWeight(.semibold)

            if let health = store.poolHealth {
                VStack(alignment: .leading, spacing: 4) {
                    healthRow(loc.t("admin_pool_transport"), health.transport)
                    healthRow(loc.t("admin_pool_total_nodes"), "\(health.total_nodes)")
                    healthRow(loc.t("admin_pool_connected_peers"), "\(health.connected_peers)")
                    healthRow(loc.t("admin_pool_converged_peers"), "\(health.converged_peers)")
                }

                if health.partition_conflict {
                    warningRow(loc.t("admin_pool_partition_conflict_warning"))
                }
                if health.subnet_mismatch {
                    warningRow(loc.t("admin_pool_subnet_mismatch_warning"))
                }
                if health.diverged && !health.partition_conflict && !health.subnet_mismatch {
                    warningRow(loc.t("admin_pool_diverged_warning"))
                }
            } else {
                Text(loc.t("admin_loading"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }

    private func healthRow(_ label: String, _ value: String) -> some View {
        HStack(spacing: 6) {
            Text(label + ":")
                .font(.system(size: 12))
                .foregroundColor(.secondary)
            Text(value)
                .font(.system(size: 12, weight: .medium))
            Spacer()
        }
    }

    private func warningRow(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 11))
                .foregroundColor(.orange)
            Text(text)
                .font(.system(size: 11))
                .foregroundColor(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Nodes

    @ViewBuilder
    private var nodesSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(loc.t("admin_pool_title"))
                .font(.subheadline)
                .fontWeight(.semibold)

            if store.poolNodes.isEmpty {
                Text(loc.t("admin_pool_no_nodes"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                let nodes = store.poolNodes
                VStack(spacing: 0) {
                    ForEach(Array(nodes.enumerated()), id: \.element.id) { index, node in
                        AdminPoolNodeRow(node: node)
                        if index < nodes.count - 1 {
                            Divider()
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Node row

struct AdminPoolNodeRow: View {
    let node: AdminPoolNodeView
    @EnvironmentObject var loc: LocalizationManager

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(node.connected ? Color.green : Color.gray)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(node.node_id)
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .textSelection(.enabled)
                Text(node.address ?? loc.t("admin_pool_no_address"))
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                Text("\(loc.t("admin_pool_last_seen")): \(lastSeenText)")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                if node.revoked {
                    badge(loc.t("admin_pool_node_revoked"), color: .red)
                } else if node.verified {
                    badge(loc.t("admin_pool_node_verified"), color: .green)
                } else {
                    badge(loc.t("admin_pool_node_unverified"), color: .secondary)
                }
                Text(node.connected ? loc.t("admin_pool_node_connected") : loc.t("admin_pool_node_disconnected"))
                    .font(.system(size: 9))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 6)
    }

    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold))
            .foregroundColor(color)
    }

    private var lastSeenText: String {
        guard let unix = node.last_seen_unix else { return loc.t("admin_pool_never_seen") }
        let date = Date(timeIntervalSince1970: TimeInterval(unix))
        let df = DateFormatter()
        df.dateStyle = .medium
        df.timeStyle = .short
        return df.string(from: date)
    }
}
