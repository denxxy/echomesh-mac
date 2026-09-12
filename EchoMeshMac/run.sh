#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

./build_app.sh

echo "=== Launching EchoMeshMac.app ==="
open EchoMeshMac.app
echo "EchoMeshMac is running! Check your Menu Bar for the shield icon."
