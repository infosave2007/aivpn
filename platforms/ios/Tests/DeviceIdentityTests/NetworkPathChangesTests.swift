import XCTest
@testable import DeviceIdentity

final class NetworkPathChangesTests: XCTestCase {
    func testStandbyChangesKeepTheCurrentSession() {
        var changes = NetworkPathChanges()
        XCTAssertFalse(changes.update(satisfied: true, interfaces: ["wifi#en0", "cellular#pdp0"]))
        XCTAssertFalse(changes.update(satisfied: true, interfaces: ["wifi#en0"]))
        XCTAssertFalse(changes.update(satisfied: true, interfaces: ["wifi#en0", "cellular#pdp1"]))
        XCTAssertTrue(changes.update(satisfied: true, interfaces: ["cellular#pdp1", "wifi#en0"]))
    }

    func testRestoredNetworkRestartsOnce() {
        var changes = NetworkPathChanges()
        XCTAssertFalse(changes.update(satisfied: true, interfaces: ["wifi#en0"]))
        XCTAssertFalse(changes.update(satisfied: false, interfaces: []))
        XCTAssertFalse(changes.update(satisfied: false, interfaces: []))
        XCTAssertTrue(changes.update(satisfied: true, interfaces: ["wifi#en0"]))
        XCTAssertFalse(changes.update(satisfied: true, interfaces: ["wifi#en0"]))
    }
}
