import XCTest
@testable import DeviceIdentity

final class TunnelRemoteAddressTests: XCTestCase {
    func testNumericEndpointsDoNotNeedDNS() {
        for host in ["203.0.113.7", "2001:db8::7"] {
            XCTAssertEqual(DomainExclusions.remoteAddress(host, resolver: { _ in [] }), host)
        }
    }

    func testHostnameBecomesNumericAddress() {
        let address = DomainExclusions.remoteAddress("vpn.example.com", resolver: { _ in
            ["not-an-address", "203.0.113.9"]
        })
        XCTAssertEqual(address, "203.0.113.9")
    }

    func testIPv6OnlyHostname() {
        XCTAssertEqual(DomainExclusions.remoteAddress("vpn.example.com", resolver: { _ in
            ["2001:db8::9"]
        }), "2001:db8::9")
    }

    func testLocalAndAbsoluteHostnamesKeepTheirResolverSemantics() {
        for host in ["vpn", "vpn.example.com."] {
            XCTAssertEqual(DomainExclusions.remoteAddress(host, resolver: { requested in
                XCTAssertEqual(requested, host)
                return ["203.0.113.9"]
            }), "203.0.113.9")
        }
    }

    func testFailedDNSDoesNotPassHostnameToNetworkExtension() {
        XCTAssertNil(DomainExclusions.remoteAddress("vpn.example.com", resolver: { _ in [] }))
        XCTAssertNil(DomainExclusions.remoteAddress("vpn.example.com:443", resolver: { _ in
            ["203.0.113.9"]
        }))
    }
}
