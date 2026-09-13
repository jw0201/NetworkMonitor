// swift-tools-version: 6.0
import PackageDescription

let strict: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
]

let package = Package(
    name: "NetworkMonitor",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "nmtest", targets: ["nmtest"]),
    ],
    targets: [
        // C shim: hand-declared pktap structures plus the real pcap headers.
        // Apple's struct pcap_pkthdr carries a trailing char comment[256]
        // (sizeof == 280, not 24), so Swift must never redeclare it -- it comes
        // through this shim or not at all.
        .target(
            name: "CPktap",
            path: "Sources/CPktap",
            publicHeadersPath: "include",
            cSettings: [.unsafeFlags(["-fno-strict-aliasing"])],
            linkerSettings: [.linkedLibrary("pcap")]
        ),

        // Shared primitives with no I/O. ByteReader lives here and is the only
        // sanctioned way to read packet bytes anywhere in the project.
        .target(name: "NMCore", dependencies: [], swiftSettings: strict),

        // Tests are an executable, not a .testTarget: neither XCTest nor
        // swift-testing ships with the Command Line Tools, so `swift test`
        // cannot run here. Use `swift run nmtest`.
        .target(name: "NMTestKit", swiftSettings: strict),
        .executableTarget(
            name: "nmtest",
            dependencies: ["NMTestKit", "NMCore"],
            swiftSettings: strict
        ),
    ]
)
