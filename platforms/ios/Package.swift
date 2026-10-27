// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DeviceIdentityChecks",
    products: [],
    targets: [
        .target(name: "DeviceIdentity", path: "Identity"),
        .testTarget(name: "DeviceIdentityTests", dependencies: ["DeviceIdentity"], path: "Tests/DeviceIdentityTests")
    ]
)
