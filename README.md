# EchoMesh macOS Client (`echomesh-mac`)

Native macOS client application for the **EchoMesh** mesh network. Built with **SwiftUI** and powered by a high-performance **Rust** engine via Mozilla UniFFI.

---

## Features

- **Native macOS Experience**: SwiftUI interface featuring Menu Bar integration, live status indicators, network latency (RTT ping), and configuration management.
- **DPI-Resistant Wire Format**: Fixed-size 1420-byte wire packets (`FRAME_SIZE`) with constant-size padding matching the [EchoMesh Relay](https://github.com/denxxy/echomesh-relay) specification.
- **End-to-End Cryptography**: Noise Protocol Framework (`Noise_NK_25519_ChaChaPoly_BLAKE2s`) with static 25519 relay authentication and ephemeral client keys.
- **Secure Key Storage**: System Keychain integration (`com.echomesh.mac.identity`) for private identity keys.
- **UniFFI Bridge**: Clean Swift-Rust boundary with typed error handling, asynchronous event polling, and memory safety.

---

## Repository Structure

```
echomesh-mac/
├── echomesh-core/           # Rust core library & UniFFI bindings
│   ├── src/                 # Protocol codec, Noise NK session, client engine
│   ├── tests/               # Integration tests
│   ├── bindings/            # UniFFI generated Swift & C headers
│   └── build_framework.sh   # Builds EchoMeshCore.xcframework
├── EchoMeshMac/             # Native macOS SwiftUI application
│   ├── App/                 # App entry point and lifecycle
│   ├── Bindings/            # Swift FFI bindings to Rust core
│   ├── Frameworks/          # EchoMeshCore.xcframework
│   ├── Services/            # Core bridge, Keychain, Network logging
│   ├── ViewModels/          # State management & ViewModels
│   ├── Views/               # SwiftUI Views (MenuBar, Chat, Settings)
│   ├── Tests/               # XCTest test suites
│   └── run.sh               # Build & launch helper script
├── build.sh                 # Unified build script (core + app)
└── README.md
```

---

## Getting Started

### Prerequisites

- macOS 14.0+ (Sonoma or later)
- Xcode 15.0+ or Xcode Command Line Tools
- Rust 1.80+ (only required if modifying the Rust core)

### Quick Run

To build and launch the application directly:

```bash
cd EchoMeshMac
./run.sh
```

### Building the Entire Stack

To recompile `echomesh-core`, rebuild the `.xcframework`, and compile the macOS app:

```bash
./build.sh
```

---

## Running Tests

### Rust Core Tests

```bash
cargo test --manifest-path echomesh-core/Cargo.toml
```

### macOS Application Tests

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test --package-path EchoMeshMac
```

---

## Related Projects

- [echomesh-relay](https://github.com/denxxy/echomesh-relay) — High-throughput, zero-knowledge, DPI-resistant relay proxy.
