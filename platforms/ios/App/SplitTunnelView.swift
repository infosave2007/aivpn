import SwiftUI

// Manages excluded domains and CIDR routes stored in the App Group UserDefaults
// so the tunnel extension can read them without IPC.
//
// SECURITY NOTE (C-I-3): The domain and route lists are stored in App Group
// UserDefaults (group.com.aivpn.client) and are NOT cryptographically verified.
// Any process in the same App Group can modify these lists. Do not rely on this
// storage for security-sensitive routing decisions.
//
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

    @discardableResult
    func addDomain(_ domain: String) -> Bool {
        let d = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard excludedDomains.count < 64, DomainExclusions.validDomain(d), !excludedDomains.contains(d) else { return false }
        excludedDomains.append(d)
        saveDomains()
        return true
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
        CIDRRoute(cidr) != nil
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
    @State private var newDomain = ""
    @State private var domainError = false

    var body: some View {
        NavigationStack {
            List {
                Section(header: Text(loc.t("split_domains"))) {
                    ForEach(mgr.excludedDomains, id: \.self) { Text($0) }
                        .onDelete { mgr.removeDomain(at: $0) }
                    HStack {
                        TextField("example.com", text: $newDomain)
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                            .onChange(of: newDomain) { _ in domainError = false }
                        Button {
                            if mgr.addDomain(newDomain) { newDomain = ""; domainError = false } else { domainError = true }
                        } label: { Image(systemName: "plus.circle.fill") }
                        .disabled(newDomain.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    if domainError { Text(loc.t("split_domain_invalid")).foregroundColor(.red).font(.caption) }
                    Text(loc.t("split_domain_note")).font(.caption).foregroundColor(.secondary)
                }
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
