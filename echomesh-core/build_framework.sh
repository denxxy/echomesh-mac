#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 1. Building echomesh-core release binaries ==="
cargo build --release

echo "=== 2. Generating UniFFI Swift bindings & C headers ==="
mkdir -p bindings
cargo run --bin uniffi-bindgen generate --library target/release/libechomesh_core.dylib --language swift --out-dir bindings

echo "=== 3. Organizing headers and modulemap ==="
mkdir -p bindings/headers
cp bindings/echomesh_coreFFI.h bindings/headers/
cp bindings/echomesh_coreFFI.modulemap bindings/headers/module.modulemap
cp bindings/echomesh_coreFFI.modulemap bindings/headers/echomesh_coreFFI.modulemap

DEST_APP_DIR="../EchoMeshMac"
mkdir -p "$DEST_APP_DIR/Frameworks"
mkdir -p "$DEST_APP_DIR/Bindings"

echo "=== 4. Creating EchoMeshCore.xcframework ==="
rm -rf "$DEST_APP_DIR/Frameworks/EchoMeshCore.xcframework"

DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -create-xcframework \
    -library target/release/libechomesh_core.a \
    -headers bindings/headers \
    -output "$DEST_APP_DIR/Frameworks/EchoMeshCore.xcframework"

echo "=== 5. Copying Swift bindings ==="
cp bindings/echomesh_core.swift "$DEST_APP_DIR/Bindings/EchoMeshCore.swift"

echo "=== Successfully built EchoMeshCore.xcframework and generated bindings ==="
