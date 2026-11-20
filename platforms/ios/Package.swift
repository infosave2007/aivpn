// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DeviceIdentityChecks",
    // BootstrapResponse reads an AsyncSequence of bytes (URLSession.bytes).
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [],
    targets: [
        .target(name: "DeviceIdentity", path: "Identity"),
        .testTarget(name: "DeviceIdentityTests", dependencies: ["DeviceIdentity"], path: "Tests/DeviceIdentityTests")
    ]
)
