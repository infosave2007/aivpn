import Foundation

/// Сохраненные списки не меняются при построении настроек текущего туннеля.
struct SplitTunnelConfiguration {
    let fullTunnel: Bool
    let excludedRoutes: [String]
    let excludedDomains: [String]

    init(_ configuration: [String: Any], defaults: UserDefaults? = nil) {
        let stored = defaults?.object(forKey: "split_enabled") as? Bool
        let enabled = stored ?? configuration["split_enabled"] as? Bool ?? true
        fullTunnel = !enabled || (configuration["fullTunnel"] as? Bool ?? true)
        func list(_ key: String) -> [String] {
            guard enabled else { return [] }
            if stored != nil { return defaults?.stringArray(forKey: key) ?? [] }
            return (configuration[key] as? String ?? "").split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        excludedRoutes = list("excluded_routes")
        excludedDomains = list("excluded_domains")
    }

    static func enabled(in defaults: UserDefaults, legacyFullTunnel: Bool?) -> Bool {
        if let enabled = defaults.object(forKey: "split_enabled") as? Bool { return enabled }
        return !(defaults.stringArray(forKey: "excluded_routes") ?? []).isEmpty ||
            !(defaults.stringArray(forKey: "excluded_domains") ?? []).isEmpty || legacyFullTunnel == false
    }
}
