// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "sx",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SxCore", targets: ["SxCore"]),
        .executable(name: "sx", targets: ["sx"]),
    ],
    targets: [
        .target(name: "SxCore"),
        .executableTarget(name: "sx", dependencies: ["SxCore"]),
        .testTarget(name: "SxCoreTests", dependencies: ["SxCore"]),
    ]
)
