// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "EchoMeshMac",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "EchoMeshMac",
            targets: ["EchoMeshMac"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EchoMeshCore",
            path: "Frameworks/EchoMeshCore.xcframework"
        ),
        .executableTarget(
            name: "EchoMeshMac",
            dependencies: [
                "EchoMeshCore"
            ],
            path: ".",
            exclude: [
                "Tests",
                "EchoMeshMac.entitlements",
                "Info.plist",
                "Frameworks",
                "EchoMeshMac.app",
                "run.sh"
            ],
            sources: [
                "App",
                "Bindings",
                "Services",
                "ViewModels",
                "Views"
            ]
        ),
        .testTarget(
            name: "EchoMeshMacTests",
            dependencies: [
                "EchoMeshMac"
            ],
            path: "Tests/EchoMeshMacTests"
        )
    ]
)
