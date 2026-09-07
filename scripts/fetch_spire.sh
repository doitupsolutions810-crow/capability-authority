#!/usr/bin/env bash
set -euo pipefail
VER=${SPIRE_VERSION:-1.15.3}
ARCH=${SPIRE_ARCH:-linux-amd64-musl}
TGZ="spire-${VER}-${ARCH}.tar.gz"
URL="https://github.com/spiffe/spire/releases/download/v${VER}/${TGZ}"
RUNBIN=${SPIRE_BIN_DIR:-/tmp/spire-bin}
mkdir -p "$RUNBIN" /tmp
cd /tmp
[ -f "$TGZ" ] || curl -fsSL -L -o "$TGZ" "$URL"
echo "sha256 $(sha256sum "$TGZ")"
rm -rf /tmp/spire-extract && mkdir /tmp/spire-extract
tar -xzf "$TGZ" -C /tmp/spire-extract
cp /tmp/spire-extract/spire-${VER}/bin/spire-agent /tmp/spire-extract/spire-${VER}/bin/spire-server "$RUNBIN/"
chmod +x "$RUNBIN/spire-agent" "$RUNBIN/spire-server"
"$RUNBIN/spire-agent" --version
"$RUNBIN/spire-server" --version
