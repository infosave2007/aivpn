import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Запрос к уже аутентифицирующему приложение системному помощнику.
enum LocalAdminIPC {
    static let maxFrame = 1024 * 1024

    static func clientRequest(_ line: String, port: UInt16 = 44301, timeout: Int = 38) -> String? {
        #if canImport(Darwin)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        #if canImport(Darwin)
        var enabled: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        #endif
        var limit = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        guard withUnsafePointer(to: &address, {
            connect(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
        }) == 0 else { return nil }
        let body = Data(line.utf8)
        guard !body.isEmpty, body.count <= maxFrame else { return nil }
        var length = UInt32(body.count).bigEndian
        var frame = withUnsafeBytes(of: &length) { Data($0) }
        frame.append(body)
        guard frame.withUnsafeBytes({ buffer -> Bool in
            var offset = 0
            while offset < buffer.count {
                #if canImport(Darwin)
                let count = send(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset, 0)
                #else
                let count = send(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset, Int32(MSG_NOSIGNAL))
                #endif
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }) else { return nil }
        func exact(_ size: Int) -> Data? {
            var result = Data(count: size)
            return result.withUnsafeMutableBytes { buffer -> Bool in
                var offset = 0
                while offset < size {
                    let count = recv(fd, buffer.baseAddress!.advanced(by: offset), size - offset, 0)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { return false }
                    offset += count
                }
                return true
            } ? result : nil
        }
        guard let header = exact(4) else { return nil }
        let size = header.reduce(0) { ($0 << 8) | Int($1) }
        guard size > 0, size <= maxFrame, let response = exact(size) else { return nil }
        return String(data: response, encoding: .utf8)
    }

    static func request(_ payload: [String: Any], path: String = "/var/run/aivpn/helper.sock",
                        timeout: Int = 40) -> [String: Any]? {
        #if canImport(Darwin)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        #if canImport(Darwin)
        var enabled: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        #endif
        var limit = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let name = Array(path.utf8)
        guard name.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            for (index, value) in name.enumerated() { buffer[index] = value }
        }
        let connected = withUnsafePointer(to: &address) {
            connect(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_un>.size))
        }
        guard connected == 0,
              let body = try? JSONSerialization.data(withJSONObject: payload), body.count <= 2 * maxFrame else { return nil }
        var length = UInt32(body.count).bigEndian
        var data = withUnsafeBytes(of: &length) { Data($0) }
        data.append(body)
        let written = data.withUnsafeBytes { buffer -> Bool in
            var offset = 0
            while offset < buffer.count {
                #if canImport(Darwin)
                let count = send(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset, 0)
                #else
                let count = send(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset, Int32(MSG_NOSIGNAL))
                #endif
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard written else { return nil }
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = recv(fd, &buffer, buffer.count, 0)
            if count < 0 && errno == EINTR { continue }
            if count == 0 { break }
            guard count > 0, response.count + count <= 2 * maxFrame else { return nil }
            response.append(contentsOf: buffer.prefix(count))
        }
        return (try? JSONSerialization.jsonObject(with: response)) as? [String: Any]
    }
}
