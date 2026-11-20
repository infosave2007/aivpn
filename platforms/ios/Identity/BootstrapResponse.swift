import Foundation

enum BootstrapResponse {
    static let maxBytes = 4 * 1024 * 1024

    static func read<S: AsyncSequence>(_ bytes: S, expectedLength: Int64) async throws -> Data where S.Element == UInt8 {
        guard expectedLength <= Int64(maxBytes) else {
            throw URLError(.dataLengthExceedsMaximum)
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < maxBytes else { throw URLError(.dataLengthExceedsMaximum) }
            if data.count % 8192 == 0 { try Task.checkCancellation() }
            data.append(byte)
        }
        return data
    }
}
