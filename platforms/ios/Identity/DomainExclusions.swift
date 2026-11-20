import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// DNS-исключения превращаются в маршруты только для текущих адресов домена.
enum DomainExclusions {
    private static let queue: OperationQueue = {
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 2
        queue.qualityOfService = .utility
        return queue
    }()
    private final class Addresses: @unchecked Sendable {
        let lock = NSLock()
        var values = Set<String>()
        func add(_ addresses: [String]) { lock.lock(); values.formUnion(addresses.prefix(64)); lock.unlock() }
        func read() -> [String] { lock.lock(); defer { lock.unlock() }; return Array(values).sorted() }
    }

    static func validDomain(_ value: String) -> Bool { validHostname(value, minimumLabels: 2) }

    private static func validHostname(_ value: String, minimumLabels: Int = 1) -> Bool {
        guard value.utf8.count <= 253 else { return false }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        return labels.count >= minimumLabels && labels.allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
                label.utf8.allSatisfy { (48...57).contains($0) || (97...122).contains($0) || $0 == 45 }
        }
    }

    static func routes(_ domains: [String], timeout: TimeInterval = 5,
                       resolver: @escaping @Sendable (String) -> [String] = { resolve($0) }) -> [String] {
        let names = Set(domains.map { $0.lowercased() }).sorted().prefix(64).filter { validDomain($0) }
        return addresses(names, timeout: timeout, resolver: resolver).compactMap { address in
            let cidr = "\(address)/\(address.contains(":") ? 128 : 32)"
            return CIDRRoute(cidr) == nil ? nil : cidr
        }
    }

    private static func addresses(_ names: [String], timeout: TimeInterval,
                                  resolver: @escaping @Sendable (String) -> [String]) -> [String] {
        let results = Addresses()
        let group = DispatchGroup()
        let deadline = DispatchTime.now() + max(0, timeout)
        for name in names {
            group.enter()
            queue.addOperation {
                defer { group.leave() }
                guard DispatchTime.now() < deadline else { return }
                let addresses = resolver(name)
                guard DispatchTime.now() < deadline else { return }
                results.add(addresses)
            }
        }
        _ = group.wait(timeout: deadline)
        return results.read()
    }

    /// NetworkExtension requires a numeric remote address, even when the
    /// transport's endpoint is a hostname. Keep DNS bounded like exclusions.
    static func remoteAddress(_ host: String, timeout: TimeInterval = 5,
                              resolver: @escaping @Sendable (String) -> [String] = { resolve($0) }) -> String? {
        let literal = CIDRRoute("\(host)/\(host.contains(":") ? 128 : 32)")
        if let literal = literal { return literal.address }
        let name = host.hasSuffix(".") ? String(host.dropLast()) : host
        guard validHostname(name) else { return nil }
        return addresses([host], timeout: timeout, resolver: resolver).compactMap { address in
            CIDRRoute("\(address)/\(address.contains(":") ? 128 : 32)")?.address
        }.first
    }

    private static func resolve(_ domain: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_DGRAM
        #else
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        #endif
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(domain, nil, &hints, &list) == 0, let first = list else { return [] }
        defer { freeaddrinfo(first) }
        var results = [String]()
        var current: UnsafeMutablePointer<addrinfo>? = first
        while let info = current, results.count < 64 {
            defer { current = info.pointee.ai_next }
            guard info.pointee.ai_family == AF_INET || info.pointee.ai_family == AF_INET6,
                  let address = info.pointee.ai_addr else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, info.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                results.append(String(cString: host))
            }
        }
        return results
    }
}
