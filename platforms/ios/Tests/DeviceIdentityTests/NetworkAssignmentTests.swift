import Foundation
import XCTest
@testable import DeviceIdentity

final class NetworkAssignmentTests: XCTestCase {
    func testTunnelMtuFitsMaskCarriersWithoutViolatingIpv6Minimum() {
        XCTAssertEqual(NetworkAssignment.tunnelMtu(requested: nil, adaptiveLevel: 0, requiresIpv6: false), 1280)
        XCTAssertEqual(NetworkAssignment.tunnelMtu(requested: 1500, adaptiveLevel: 0, requiresIpv6: false), 1500)
        XCTAssertEqual(NetworkAssignment.tunnelMtu(requested: 1200, adaptiveLevel: 0, requiresIpv6: false), 1200)
        XCTAssertEqual(NetworkAssignment.tunnelMtu(requested: 1500, adaptiveLevel: 2, requiresIpv6: false), 1200)
        XCTAssertEqual(NetworkAssignment.tunnelMtu(requested: 1500, adaptiveLevel: 2, requiresIpv6: true), 1280)
    }

    func testServerPrefixAndIpv6AreDecodedTogether() throws {
        let data = Data(#"{"client_ip":"10.7.3.9","server_vpn_ip":"10.7.0.1","prefix_len":20,"mtu":1346,"ipv6_address":"fd10:cafe::a07:309","ipv6_prefix_len":64}"#.utf8)
        let assignment = try JSONDecoder().decode(NetworkAssignment.self, from: data)
        XCTAssertTrue(assignment.isValid)
        XCTAssertEqual(assignment.netmask, "255.255.240.0")
        XCTAssertEqual(assignment.networkAddress, "10.7.0.0")
        XCTAssertEqual(assignment.ipv6PrefixLen, 64)
    }

    func testInvalidNegotiatedSettingsAreRejected() {
        for assignment in [
            NetworkAssignment(clientIp: "10.0.0.2", serverVpnIp: "10.0.0.1", prefixLen: 24, mtu: 1346, ipv6Address: "not:ipv6", ipv6PrefixLen: 64),
            NetworkAssignment(clientIp: "10.0.0.2", serverVpnIp: "10.0.0.1", prefixLen: 0, mtu: 1346, ipv6Address: nil, ipv6PrefixLen: nil),
            NetworkAssignment(clientIp: "10.0.0.2", serverVpnIp: "10.0.0.1", prefixLen: 24, mtu: 1200, ipv6Address: "fd10::2", ipv6PrefixLen: 64),
            NetworkAssignment(clientIp: "10.0.0.999", serverVpnIp: "10.0.0.1", prefixLen: 24, mtu: 1346, ipv6Address: nil, ipv6PrefixLen: nil),
            NetworkAssignment(clientIp: "10.0.0.2", serverVpnIp: "10.0.0.1", prefixLen: 24, mtu: 1346, ipv6Address: "fd10::2", ipv6PrefixLen: nil)
        ] { XCTAssertFalse(assignment.isValid) }
    }
}

final class CIDRRouteTests: XCTestCase {
    func testBothFamiliesAndPrefixBoundaries() {
        XCTAssertEqual(CIDRRoute("192.168.1.0/24")?.ipv4Netmask, "255.255.255.0")
        XCTAssertEqual(CIDRRoute("0.0.0.0/0")?.ipv4Netmask, "0.0.0.0")
        XCTAssertEqual(CIDRRoute("192.0.2.1/32")?.ipv4Netmask, "255.255.255.255")
        XCTAssertEqual(CIDRRoute("2001:db8::/64")?.prefixLen, 64)
        XCTAssertTrue(CIDRRoute("::/0")?.isIPv6 ?? false)
        XCTAssertTrue(CIDRRoute("::1/128")?.isIPv6 ?? false)
        for input in ["1..2.3.4/24", "256.1.1.1/8", "::/129", "192.0.2.1/33", "::/-1", "::/64/", "invalid/64", "fe80::1%en0/64"] {
            XCTAssertNil(CIDRRoute(input), input)
        }
    }
}

final class VPNServerEndpointTests: XCTestCase {
    func testCompressedIPv6AndPortValidation() {
        XCTAssertEqual(VPNServerEndpoint("[2001:db8::1]:443")?.host, "2001:db8::1")
        XCTAssertEqual(VPNServerEndpoint("[::1]:8443")?.host, "::1")
        XCTAssertEqual(VPNServerEndpoint("host.example:8443")?.port, 8443)
        for invalid in ["2001:db8::1:443", "[::1]:0", "host:65536", ":443", "[broken]:443"] {
            XCTAssertNil(VPNServerEndpoint(invalid))
        }
    }
}
