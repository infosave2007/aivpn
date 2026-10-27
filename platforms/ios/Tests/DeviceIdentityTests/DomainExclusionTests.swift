import XCTest
@testable import DeviceIdentity

final class DomainExclusionTests: XCTestCase {
    func testDomainValidationAndBothAddressFamilies() {
        XCTAssertTrue(DomainExclusions.validDomain("example.com"))
        for invalid in ["", ".example.com", "example..com", "https://example.com", "-bad.com", "bad-.com"] {
            XCTAssertFalse(DomainExclusions.validDomain(invalid))
        }
        let routes = DomainExclusions.routes(["EXAMPLE.COM", "example.com", "bad/url"], timeout: 1) { _ in
            ["192.0.2.1", "2001:db8::1", "invalid", "192.0.2.1"]
        }
        XCTAssertEqual(routes, ["192.0.2.1/32", "2001:db8::1/128"])
    }
    func testSlowResolverDoesNotBlockSetupOrAddLateResults() {
        let start = Date()
        let routes = DomainExclusions.routes(["slow.example"], timeout: 0.02) { _ in
            Thread.sleep(forTimeInterval: 0.2)
            return ["192.0.2.1"]
        }
        XCTAssertTrue(routes.isEmpty)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.15)
    }
}
