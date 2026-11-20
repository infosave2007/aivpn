import Foundation
import XCTest
@testable import DeviceIdentity

final class BootstrapResponseTests: XCTestCase {
    private struct Bytes: AsyncSequence, AsyncIteratorProtocol {
        typealias Element = UInt8
        var remaining: Int
        mutating func next() async throws -> UInt8? {
            guard remaining > 0 else { return nil }
            remaining -= 1
            return 65
        }
        func makeAsyncIterator() -> Bytes { self }
    }

    func testOversizedResponseWithoutContentLengthIsRejected() async {
        do {
            _ = try await BootstrapResponse.read(Bytes(remaining: BootstrapResponse.maxBytes + 1), expectedLength: -1)
            XCTFail("Большой ответ должен быть отклонен")
        } catch {}
    }

    func testDeclaredOversizedResponseIsRejectedBeforeReading() async {
        do {
            _ = try await BootstrapResponse.read(Bytes(remaining: 0), expectedLength: Int64(BootstrapResponse.maxBytes + 1))
            XCTFail("Недопустимый Content-Length должен быть отклонен")
        } catch {}
    }

    func testExactLimitIsAccepted() async throws {
        let data = try await BootstrapResponse.read(Bytes(remaining: BootstrapResponse.maxBytes), expectedLength: -1)
        XCTAssertEqual(data.count, BootstrapResponse.maxBytes)
        XCTAssertTrue(data.allSatisfy { $0 == 65 })
    }
}
