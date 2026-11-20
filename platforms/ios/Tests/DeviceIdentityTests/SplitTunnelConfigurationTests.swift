import XCTest
@testable import DeviceIdentity

final class SplitTunnelConfigurationTests: XCTestCase {
    func testOffRetainsSavedListsAndEnablesFullTunnel() {
        var saved: [String: Any] = ["fullTunnel": false, "excluded_routes": "192.0.2.0/24, 2001:db8::/32", "excluded_domains": "example.net", "split_enabled": false]
        let disabled = SplitTunnelConfiguration(saved)
        XCTAssertTrue(disabled.fullTunnel)
        XCTAssertEqual(disabled.excludedRoutes, [])
        XCTAssertEqual(disabled.excludedDomains, [])
        saved["split_enabled"] = true
        let enabled = SplitTunnelConfiguration(saved)
        XCTAssertFalse(enabled.fullTunnel)
        XCTAssertEqual(enabled.excludedRoutes, ["192.0.2.0/24", "2001:db8::/32"])
        XCTAssertEqual(enabled.excludedDomains, ["example.net"])
    }

    func testOldProviderConfigurationKeepsItsBehavior() {
        let old = SplitTunnelConfiguration(["fullTunnel": false, "excluded_domains": "example.net"])
        XCTAssertFalse(old.fullTunnel)
        XCTAssertEqual(old.excludedDomains, ["example.net"])
    }

    func testSystemStartReadsTheCurrentSwitchInsteadOfAnOldProviderSnapshot() {
        let name = "aivpn-split-system-test-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let old: [String: Any] = ["split_enabled": true, "excluded_routes": "192.0.2.0/24"]
        defaults.set(false, forKey: "split_enabled")
        defaults.set(["203.0.113.0/24"], forKey: "excluded_routes")
        XCTAssertEqual(SplitTunnelConfiguration(old, defaults: defaults).excludedRoutes, [])
        defaults.set(true, forKey: "split_enabled")
        XCTAssertEqual(SplitTunnelConfiguration(old, defaults: defaults).excludedRoutes, ["203.0.113.0/24"])
    }

    func testDefaultsMigrationAndExplicitOffSurviveReload() {
        let name = "aivpn-split-test-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        XCTAssertFalse(SplitTunnelConfiguration.enabled(in: defaults, legacyFullTunnel: nil))
        XCTAssertTrue(SplitTunnelConfiguration.enabled(in: defaults, legacyFullTunnel: false))
        defaults.set(["example.net"], forKey: "excluded_domains")
        defaults.set(["192.0.2.0/24"], forKey: "excluded_routes")
        XCTAssertTrue(SplitTunnelConfiguration.enabled(in: defaults, legacyFullTunnel: true))
        defaults.set(false, forKey: "split_enabled")
        XCTAssertFalse(SplitTunnelConfiguration.enabled(in: UserDefaults(suiteName: name)!, legacyFullTunnel: false))
        XCTAssertEqual(defaults.stringArray(forKey: "excluded_domains"), ["example.net"])
        XCTAssertEqual(defaults.stringArray(forKey: "excluded_routes"), ["192.0.2.0/24"])
    }
}
