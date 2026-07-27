import SwiftUI

// Manages excluded domains and CIDR routes stored in the App Group UserDefaults
// so the tunnel extension can read them without IPC.
//
// SECURITY NOTE (C-I-3): The domain and route lists are stored in App Group
// UserDefaults (group.com.aivpn.client) and are NOT cryptographically verified.
// Any process in the same App Group can modify these lists. Do not rely on this
// storage for security-sensitive routing decisions.
//
// DOMAIN EXCLUSION IS NOT ENFORCED ON iOS (client-parity #4). `excludedDomains`
// below is threaded all the way to PacketTunnelProvider.swift's
// providerConfiguration (VPNManager.connect() -> "excluded_domains") and
// stored in `settingsExcludedDomains`, but `buildSettings()` never applies it:
// NEDNSSettings has no `matchExcludedDomains` — confirmed by a real Xcode
// compile error when this was previously attempted, not a guess (see
// PacketTunnelProvider.swift's buildSettings doc comment). Implementing this
// properly would mean resolving each domain to its current IP(s) and adding
// those as route-level `excludedRoutes` (like Android's AivpnService does),
// which requires DNS resolution on the tunnel-setup path inside a
// resource-budgeted Network Extension — a much larger, ongoing-resolution
// feature this fix intentionally does not take on without the ability to
// build/test it on-device. `addDomain`/`removeDomain` below are consequently
// NOT wired to any SwiftUI control today (only the CIDR route section renders
// in `SplitTunnelView.body`) — do not add a UI entry point for them without
// first implementing the resolved-route enforcement above, or the control
// would silently do nothing again.
class SplitTunnelManager: ObservableObject {
    static let shared = SplitTunnelManager()

    @Published var excludedDomains: [String] = []
    @Published var excludedRoutes: [String] = []

    private let suiteName = "group.com.aivpn.client"
    private let domainsKey = "excluded_domains"
    private let routesKey  = "excluded_routes"

    private var defaults: UserDefaults {
        UserDefaults(suiteName: suiteName) ?? .standard
    }

    init() { load() }

    func load() {
        excludedDomains = defaults.stringArray(forKey: domainsKey) ?? []
        excludedRoutes  = defaults.stringArray(forKey: routesKey)  ?? []
    }

    // MARK: - Domain management

    func addDomain(_ domain: String) {
        let d = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !d.isEmpty, !excludedDomains.contains(d) else { return }
        excludedDomains.append(d)
        saveDomains()
    }

    func removeDomain(at offsets: IndexSet) {
        excludedDomains.remove(atOffsets: offsets)
        saveDomains()
    }

    private func saveDomains() {
        defaults.set(excludedDomains, forKey: domainsKey)
    }

    // MARK: - Route management (CIDR strings, e.g. "192.168.1.0/24")

    @discardableResult
    func addRoute(_ cidr: String) -> Bool {
        let r = cidr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !r.isEmpty, !excludedRoutes.contains(r), isValidCIDR(r) else { return false }
        excludedRoutes.append(r)
        saveRoutes()
        return true
    }

    private func isValidCIDR(_ cidr: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefix = Int(parts[1]), prefix >= 0 else { return false }
        let addr = String(parts[0])
        if addr.contains(":") {
            // IPv6 CIDRs are not supported — the tunnel only installs NEIPv4Route
            // entries, so any IPv6 exclude would be silently dropped. Reject here
            // so the user sees the "invalid_cidr" error instead of a silent no-op.
            return false
        }
        // IPv4 CIDR — valid prefix lengths are 0–32.
        guard prefix <= 32 else { return false }
        let octets = addr.split(separator: ".")
        guard octets.count == 4 else { return false }
        return octets.allSatisfy { Int($0).map { $0 >= 0 && $0 <= 255 } ?? false }
    }

    func removeRoute(at offsets: IndexSet) {
        excludedRoutes.remove(atOffsets: offsets)
        saveRoutes()
    }

    private func saveRoutes() {
        defaults.set(excludedRoutes, forKey: routesKey)
    }
}

struct SplitTunnelView: View {
    @ObservedObject private var mgr = SplitTunnelManager.shared
    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @State private var newRoute: String  = ""
    @State private var routeError: String?

    var body: some View {
        NavigationStack {
            List {
                // MARK: Excluded routes (CIDR)
                Section(header: Text(loc.t("split_tunnel_routes"))) {
                    if mgr.excludedRoutes.isEmpty {
                        Text(loc.t("split_tunnel_none"))
                            .foregroundColor(.secondary)
                            .font(.subheadline)
                    } else {
                        ForEach(mgr.excludedRoutes, id: \.self) { route in
                            Text(route)
                                .font(.system(.body, design: .monospaced))
                        }
                        .onDelete { mgr.removeRoute(at: $0) }
                    }
                    HStack {
                        TextField("192.168.1.0/24", text: $newRoute)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .keyboardType(.numbersAndPunctuation)
                            .onChange(of: newRoute) { _ in routeError = nil }
                        Button {
                            if mgr.addRoute(newRoute) {
                                newRoute = ""
                                routeError = nil
                            } else {
                                routeError = loc.t("invalid_cidr")
                            }
                        } label: {
                            Image(systemName: "plus.circle.fill")
                                .foregroundColor(.accentColor)
                        }
                        .disabled(newRoute.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                    if let err = routeError {
                        Text(err)
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                }

            }
            .navigationTitle(loc.t("split_tunnel_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc.t("done")) { dismiss() }
                }
            }
        }
    }
}
