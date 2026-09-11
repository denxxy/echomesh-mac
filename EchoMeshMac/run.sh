#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer

echo "=== Building EchoMeshMac ==="
swift build -c release

mkdir -p EchoMeshMac.app/Contents/MacOS EchoMeshMac.app/Contents/Resources
cp .build/arm64-apple-macosx/release/EchoMeshMac EchoMeshMac.app/Contents/MacOS/
cp Info.plist EchoMeshMac.app/Contents/
codesign --force --deep --sign - --entitlements EchoMeshMac.entitlements EchoMeshMac.app 2>/dev/null || true

echo "=== Launching EchoMeshMac.app ==="
open EchoMeshMac.app
echo "EchoMeshMac is running! Check your Menu Bar for the shield icon."
