#!/bin/bash
# NATIVE-16 (macOS): end-to-end build script for the NetLanvas .pkg
# installer -- Go helpers, PyInstaller binary, and pkgbuild packaging,
# all in one place. Run this ON A MAC, from a checkout of this repo's
# native-port branch, with Go and a Python 3.10+ venv (with
# requirements.txt + pyinstaller installed) already available.
#
# Written specifically to close the exact gap that caused NATIVE-7 to
# silently keep shipping for three Windows releases (v3.8.1-v3.8.3)
# after it was already fixed in source: there was no script forcing a
# fresh rebuild of the Go helper binaries before packaging, so a
# stale, pre-fix .exe kept getting reused. This script always
# cross^H^H^H natively compiles both Go helpers from whatever source
# is checked out RIGHT NOW -- never reuses a binary left over from a
# previous run.
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:?Usage: build_macos_pkg.sh <version, e.g. 3.8.7>}"
BUILD_DIR=~/netlanvas-build
PKGROOT=~/netlanvas-pkgroot
SCRIPTS_DIR=~/netlanvas-pkgscripts
OUT_DIR=~/netlanvas-pkgout

echo "=== Building Go helpers (fresh, from current source) ==="
( cd "$REPO_ROOT/tools/snmp_helper" && go build -o "$BUILD_DIR/tools/snmp_helper/netlanvas_snmp_helper" . )
( cd "$REPO_ROOT/tools/ping_sweep_helper" && go build -o "$BUILD_DIR/tools/ping_sweep_helper/netlanvas_ping_sweep" . )

echo "=== Syncing app source into build dir ==="
mkdir -p "$BUILD_DIR"
rsync -a --delete "$REPO_ROOT/src/" "$BUILD_DIR/src/"
[ "$REPO_ROOT/defaults.json" -ef "$BUILD_DIR/defaults.json" ] || cp -f "$REPO_ROOT/defaults.json" "$BUILD_DIR/defaults.json"

echo "=== Building netlanvas binary (PyInstaller) ==="
# PyInstaller resolves a spec's relative Analysis()/datas paths (e.g.
# 'src/main.py', 'defaults.json') against the SPEC FILE'S OWN
# directory, not the invocation cwd -- despite the spec's own comment
# claiming otherwise. Copy the spec into BUILD_DIR (where src/ and
# defaults.json actually live, just rsynced above) before running it,
# so it resolves against the fresh synced copy instead of silently
# failing to find packaging/macos/src/main.py. Confirmed live
# 2026-09-02: running pyinstaller on the repo-root copy of the spec
# fails with "script '.../packaging/macos/src/main.py' not found".
cp "$REPO_ROOT/packaging/macos/netlanvas_macos.spec" "$BUILD_DIR/netlanvas_macos.spec"
( cd "$BUILD_DIR" && venv/bin/pyinstaller netlanvas_macos.spec --noconfirm )

echo "=== Staging pkgroot ==="
rm -rf "$PKGROOT" "$OUT_DIR"
mkdir -p "$PKGROOT/Library/Application Support/NetLanvas/bin/ui"
mkdir -p "$PKGROOT/Library/Application Support/NetLanvas/bin/tools/ping_sweep_helper"
mkdir -p "$PKGROOT/Library/Application Support/NetLanvas/bin/tools/snmp_helper"
mkdir -p "$PKGROOT/Library/LaunchDaemons"
mkdir -p "$OUT_DIR"

cp "$BUILD_DIR/dist/netlanvas" "$PKGROOT/Library/Application Support/NetLanvas/bin/netlanvas"
cp -R "$BUILD_DIR/src/ui/." "$PKGROOT/Library/Application Support/NetLanvas/bin/ui/"
cp "$BUILD_DIR/tools/ping_sweep_helper/netlanvas_ping_sweep" "$PKGROOT/Library/Application Support/NetLanvas/bin/tools/ping_sweep_helper/netlanvas_ping_sweep"
cp "$BUILD_DIR/tools/snmp_helper/netlanvas_snmp_helper" "$PKGROOT/Library/Application Support/NetLanvas/bin/tools/snmp_helper/netlanvas_snmp_helper"
cp "$REPO_ROOT/packaging/macos/uninstall.sh" "$PKGROOT/Library/Application Support/NetLanvas/uninstall.sh"
chmod +x "$PKGROOT/Library/Application Support/NetLanvas/uninstall.sh"

sed "s/{{VERSION}}/v$VERSION/" "$REPO_ROOT/packaging/macos/com.netlanvas.daemon.plist" \
    > "$PKGROOT/Library/LaunchDaemons/com.netlanvas.daemon.plist"

mkdir -p "$SCRIPTS_DIR"
cp "$REPO_ROOT/packaging/macos/preinstall" "$SCRIPTS_DIR/preinstall"
cp "$REPO_ROOT/packaging/macos/postinstall" "$SCRIPTS_DIR/postinstall"
chmod +x "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"

echo "=== Building .pkg ==="
pkgbuild \
    --root "$PKGROOT" \
    --scripts "$SCRIPTS_DIR" \
    --identifier com.netlanvas.pkg \
    --version "$VERSION" \
    --install-location / \
    "$OUT_DIR/NetLanvas-Setup-$VERSION.pkg"

echo "=== Done: $OUT_DIR/NetLanvas-Setup-$VERSION.pkg ==="
