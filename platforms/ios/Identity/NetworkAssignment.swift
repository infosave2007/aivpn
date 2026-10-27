import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

struct NetworkAssignment: Codable, Equatable {
    let clientIp: String
    let serverVpnIp: String
    let prefixLen: Int
    let mtu: Int
    let ipv6Address: String?
    let ipv6PrefixLen: Int?

    enum CodingKeys: String, CodingKey {
        case clientIp = "client_ip"
        case serverVpnIp = "server_vpn_ip"
        case prefixLen = "prefix_len"
        case mtu
        case ipv6Address = "ipv6_address"
        case ipv6PrefixLen = "ipv6_prefix_len"
    }

    var netmask: String {
        let mask = UInt32.max << (32 - prefixLen)
        return Self.address(mask)
    }

    var networkAddress: String {
        let parts = clientIp.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4 else { return clientIp }
        let value = parts.reduce(UInt32(0)) { ($0 << 8) | $1 }
        return Self.address(value & (UInt32.max << (32 - prefixLen)))
    }

    var isValid: Bool {
        let ipv4Valid: (String) -> Bool = { address in
            let parts = address.split(separator: ".", omittingEmptySubsequences: false)
            return parts.count == 4 && parts.allSatisfy { UInt8($0) != nil }
        }
        guard ipv4Valid(clientIp), ipv4Valid(serverVpnIp), (1...30).contains(prefixLen),
              (576...1500).contains(mtu) else { return false }
        if let address = ipv6Address, let prefix = ipv6PrefixLen {
            var binary = in6_addr()
            let parsed = address.withCString { inet_pton(AF_INET6, $0, &binary) }
            return parsed == 1 && address != "::" && address != "::1" &&
                !address.lowercased().hasPrefix("ff") && (1...96).contains(prefix) && mtu >= 1280
        }
        return ipv6Address == nil && ipv6PrefixLen == nil
    }

    private static func address(_ value: UInt32) -> String {
        "\((value >> 24) & 255).\((value >> 16) & 255).\((value >> 8) & 255).\(value & 255)"
    }
}
