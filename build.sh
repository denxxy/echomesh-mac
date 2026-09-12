#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 1. Building echomesh-core & generating EchoMeshCore.xcframework ==="
cd "$SCRIPT_DIR/echomesh-core"
./build_framework.sh

echo "=== 2. Building & Packaging EchoMeshMac.app ==="
cd "$SCRIPT_DIR/EchoMeshMac"
./build_app.sh

echo "=== Build completed successfully! ==="
echo "Artifact: $SCRIPT_DIR/EchoMeshMac/EchoMeshMac.app"
