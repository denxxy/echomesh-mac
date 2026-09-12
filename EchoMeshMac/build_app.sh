#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

APP_BUNDLE="EchoMeshMac.app"

# Clean any existing bundle prior to build so SPM does not report unhandled files
rm -rf "$APP_BUNDLE"

echo "=== Building EchoMeshMac (release) ==="
swift build -c release

echo "=== Packaging EchoMeshMac.app ==="
TMP_DIR="$(mktemp -d /tmp/echomesh_build.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

TMP_APP="$TMP_DIR/$APP_BUNDLE"
CONTENTS_DIR="$TMP_APP/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
FRAMEWORKS_DIR="$CONTENTS_DIR/Frameworks"

# 1. Structure
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$FRAMEWORKS_DIR"

# Copy binary
cp .build/arm64-apple-macosx/release/EchoMeshMac "$MACOS_DIR/EchoMeshMac"

# 2. Permissions
chmod +x "$MACOS_DIR/EchoMeshMac"

# 3. Info.plist & PkgInfo
cp Info.plist "$CONTENTS_DIR/Info.plist"
echo -n "APPL????" > "$CONTENTS_DIR/PkgInfo"

# Copy dynamic frameworks / dylibs if present
if [ -d "Frameworks" ]; then
    for item in Frameworks/*; do
        if [ -e "$item" ] && ([[ "$item" == *.dylib ]] || [[ "$item" == *.framework ]]); then
            cp -R "$item" "$FRAMEWORKS_DIR/"
        fi
    done
fi

# 5. rpath for UniFFI / Rust libraries
install_name_tool -add_rpath "@executable_path/../Frameworks" "$MACOS_DIR/EchoMeshMac" 2>/dev/null || true

# 4. Ad-hoc codesign in clean temp environment
xattr -cr "$TMP_APP" 2>/dev/null || true
codesign --force --deep --sign - "$TMP_APP"

# Copy signed bundle to target destination
rm -rf "$APP_BUNDLE"
ditto "$TMP_APP" "$APP_BUNDLE"

# Verification
echo "=== Verifying code signature ==="
codesign --verify --deep --verbose=2 "$APP_BUNDLE"

echo "=== Packaging complete: $SCRIPT_DIR/$APP_BUNDLE ==="
