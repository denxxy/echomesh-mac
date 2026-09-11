#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 1. Building echomesh-core & generating EchoMeshCore.xcframework ==="
cd "$SCRIPT_DIR/echomesh-core"
./build_framework.sh

echo "=== 2. Building EchoMeshMac (release) ==="
cd "$SCRIPT_DIR/EchoMeshMac"
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
swift build -c release

echo "=== 3. Packaging EchoMeshMac.app ==="
mkdir -p EchoMeshMac.app/Contents/MacOS EchoMeshMac.app/Contents/Resources
cp .build/arm64-apple-macosx/release/EchoMeshMac EchoMeshMac.app/Contents/MacOS/
cp Info.plist EchoMeshMac.app/Contents/
codesign --force --deep --sign - --entitlements EchoMeshMac.entitlements EchoMeshMac.app 2>/dev/null || true

echo "=== Build completed successfully! ==="
echo "Artifact: $SCRIPT_DIR/EchoMeshMac/EchoMeshMac.app"
