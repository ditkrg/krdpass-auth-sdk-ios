// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "KrdpassAuth",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "KrdpassAuth",
            targets: ["KrdpassAuth"]
        )
    ],
    targets: [
        .target(
            name: "KrdpassAuth",
            dependencies: [],
            path: "Sources/KrdpassAuth",
            // .copy, not .process: the privacy manifest must reach the bundle verbatim for
            // App Store privacy-report aggregation.
            resources: [.copy("PrivacyInfo.xcprivacy")]
        ),
        .testTarget(
            name: "KrdpassAuthTests",
            dependencies: ["KrdpassAuth"],
            path: "Tests/KrdpassAuthTests",
            // Vendored copy of the canonical redirect-validation vectors, decoded at test time
            // via Bundle.module rather than retyped into a literal.
            resources: [.process("Resources")]
        ),
    ]
)
