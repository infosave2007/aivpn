import Foundation
import XCTest
@testable import DeviceIdentity

final class NetworkAssignmentTests: XCTestCase {
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
