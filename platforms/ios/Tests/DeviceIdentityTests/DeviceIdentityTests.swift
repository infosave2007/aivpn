import Foundation
import XCTest
@testable import DeviceIdentity

final class DeviceIdentityTests: XCTestCase {
    enum Failure: Error { case denied }
    let valid = Data(repeating: 17, count: 32)

    func testExistingIdentityDoesNotCallGeneratorOrWriter() throws {
        let result = try loadDeviceIdentity(read: { self.valid }, generate: {
            XCTFail("Existing identity must not be regenerated")
            throw Failure.denied
        }, save: { _ in XCTFail("Existing identity must not be overwritten") })
        XCTAssertEqual(result, Array(valid))
    }

    func testReadFailureDoesNotReplaceIdentity() {
        XCTAssertThrowsError(try loadDeviceIdentity(read: { throw Failure.denied }, generate: {
            XCTFail("Read failure must not create a new identity")
            return self.valid
        }, save: { _ in XCTFail("Read failure must not write") }))
    }

    func testRandomFailureDoesNotWrite() {
        XCTAssertThrowsError(try loadDeviceIdentity(read: { nil }, generate: { throw Failure.denied },
            save: { _ in XCTFail("RNG failure must not write") }))
    }

    func testSaveFailureDoesNotReturnVolatileIdentity() {
        XCTAssertThrowsError(try loadDeviceIdentity(read: { nil }, generate: { self.valid },
            save: { _ in throw Failure.denied }))
    }

    func testInvalidStoredKeyIsNotReplaced() {
        for invalid in [Data(), Data(repeating: 0, count: 32), Data(repeating: 1, count: 31)] {
            XCTAssertThrowsError(try loadDeviceIdentity(read: { invalid }, generate: {
                XCTFail("Invalid stored key must not be overwritten")
                return self.valid
            }, save: { _ in XCTFail("Invalid stored key must not be overwritten") }))
        }
    }

    func testGeneratedZeroKeyIsRejectedBeforeSaving() {
        XCTAssertThrowsError(try loadDeviceIdentity(read: { nil }, generate: { Data(repeating: 0, count: 32) },
            save: { _ in XCTFail("Zero key must not be saved") }))
    }

    func testNewKeyIsPersistedBeforeReturning() throws {
        var stored: Data?
        let result = try loadDeviceIdentity(read: { nil }, generate: { self.valid }, save: { stored = $0 })
        XCTAssertEqual(stored, valid)
        XCTAssertEqual(result, Array(valid))
    }
}
