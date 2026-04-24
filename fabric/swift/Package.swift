// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Fabric",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "Fabric", targets: ["Fabric"]),
        .executable(name: "fabric", targets: ["FabricCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/spacesprotocol/libveritas-swift.git", exact: "0.2.0"),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1.git", exact: "0.17.0"),
    ],
    targets: [
        .target(
            name: "Fabric",
            dependencies: [
                .product(name: "Libveritas", package: "libveritas-swift"),
                .product(name: "secp256k1", package: "swift-secp256k1"),
            ],
            path: "Sources/Fabric"
        ),
        .executableTarget(
            name: "FabricCLI",
            dependencies: ["Fabric"],
            path: "Sources/FabricCLI"
        ),
    ]
)
