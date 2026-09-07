#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VER=${SPIRE_VERSION:-1.15.3}
ARCH=${SPIRE_ARCH:-linux-amd64-musl}
TGZ="spire-${VER}-${ARCH}.tar.gz"
URL="https://github.com/spiffe/spire/releases/download/v${VER}/${TGZ}"
DEST="$ROOT/third_party/spire"
RUNBIN=${SPIRE_BIN_DIR:-/tmp/spire-bin}
mkdir -p "$DEST/bin" "$RUNBIN" /tmp
cd /tmp
[ -f "$TGZ" ] || curl -fsSL -L -o "$TGZ" "$URL"
echo "sha256 $(sha256sum "$TGZ")"
rm -rf /tmp/spire-extract && mkdir -p /tmp/spire-extract
tar -xzf "$TGZ" -C /tmp/spire-extract
cp /tmp/spire-extract/spire-${VER}/bin/spire-agent "$RUNBIN/spire-agent"
cp /tmp/spire-extract/spire-${VER}/bin/spire-server "$RUNBIN/spire-server"
chmod +x "$RUNBIN/spire-agent" "$RUNBIN/spire-server"
"$RUNBIN/spire-agent" --version
"$RUNBIN/spire-server" --version
echo "installed $RUNBIN"
