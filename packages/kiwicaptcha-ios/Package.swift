// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "KiwiCaptcha",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "KiwiCaptcha", targets: ["KiwiCaptcha"]),
        .executable(name: "kiwi-selftest", targets: ["KiwiSelfTest"]),
    ],
    targets: [
        // The vendored reference argon2 C implementation
        // (phc-winner-argon2 20190702, the Apache-2.0/CC0 dual-licensed
        // sources, src/ and include/ vendored unmodified). Threads stay
        // off: the protocol profile is p == 1, and the package links
        // without a thread-pool dependency on every Apple platform.
        .target(
            name: "CArgon2",
            cSettings: [.define("ARGON2_NO_THREADS")]
        ),
        .target(name: "KiwiCaptcha", dependencies: ["CArgon2"]),
        .executableTarget(
            name: "KiwiSelfTest",
            dependencies: ["KiwiCaptcha"]
        ),
        .testTarget(
            name: "KiwiCaptchaTests",
            dependencies: ["KiwiCaptcha"]
        ),
    ]
)
