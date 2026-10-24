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

    static func tunnelMtu(requested: Int?, adaptiveLevel: Int, requiresIpv6: Bool) -> Int {
        let desired = min(requested ?? 1280, adaptiveLevel >= 2 ? 1200 : 1500)
        return max(requiresIpv6 ? 1280 : 576, desired)
    }

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
            guard !address.contains("%"), !address.utf8.contains(0) else { return false }
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

/// Один проверенный маршрут исключения для IPv4 или IPv6.
struct CIDRRoute {
    let address: String
    let prefixLen: Int
    let isIPv6: Bool

    init?(_ value: String) {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0 else { return nil }
        let host = String(parts[0])
        guard !host.contains("%"), !host.utf8.contains(0) else { return nil }
        let ipv6 = host.contains(":")
        if ipv6 {
            var binary = in6_addr()
            guard prefix <= 128, host.withCString({ inet_pton(AF_INET6, $0, &binary) }) == 1 else { return nil }
        } else {
            var binary = in_addr()
            guard prefix <= 32, host.withCString({ inet_pton(AF_INET, $0, &binary) }) == 1 else { return nil }
        }
        address = host
        prefixLen = prefix
        isIPv6 = ipv6
    }

    var ipv4Netmask: String? {
        guard !isIPv6 else { return nil }
        let bits: UInt32 = prefixLen == 0 ? 0 : UInt32.max << (32 - prefixLen)
        return "\((bits >> 24) & 255).\((bits >> 16) & 255).\((bits >> 8) & 255).\(bits & 255)"
    }
}

/// Адрес сервера из ключа, с обязательными скобками для IPv6.
struct VPNServerEndpoint {
    let host: String
    let port: UInt16
    init?(_ address: String) {
        guard let colon = address.lastIndex(of: ":"),
              let port = UInt16(address[address.index(after: colon)...]), port > 0 else { return nil }
        let prefix = String(address[..<colon])
        let host: String
        if prefix.hasPrefix("["), prefix.hasSuffix("]") {
            host = String(prefix.dropFirst().dropLast())
            var binary = in6_addr()
            guard host.withCString({ inet_pton(AF_INET6, $0, &binary) }) == 1 else { return nil }
        } else {
            guard !prefix.isEmpty, !prefix.contains(":"), !prefix.contains("["), !prefix.contains("]") else { return nil }
            host = prefix
        }
        guard !host.contains(where: { $0.isWhitespace }), !host.contains("%"),
              !host.utf8.contains(0) else { return nil }
        self.host = host
        self.port = port
    }
}
