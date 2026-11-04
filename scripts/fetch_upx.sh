#!/usr/bin/env sh
# Download a standalone UPX binary into tools/ for `glassbox unpack`.
set -eu

VERSION="${UPX_VERSION:-5.3.0}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ASSET="upx-${VERSION}-amd64_linux.tar.xz" ;;
  aarch64|arm64) ASSET="upx-${VERSION}-arm64_linux.tar.xz" ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$ROOT/tools"

URL="https://github.com/upx/upx/releases/download/v${VERSION}/${ASSET}"
echo "downloading $URL"
curl -L --fail --max-time 180 -o "$TMP/upx.tar.xz" "$URL"
tar -xJf "$TMP/upx.tar.xz" -C "$TMP"
cp "$TMP"/upx-*/upx "$ROOT/tools/upx"
chmod +x "$ROOT/tools/upx"
"$ROOT/tools/upx" --version | head -1
