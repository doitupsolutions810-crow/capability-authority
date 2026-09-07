#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
BIN=${SPIRE_BIN_DIR:-/tmp/spire-bin}
LAB=/tmp/spire-lab
SOCK="$LAB/sockets/agent.sock"
ADMIN="$LAB/server/private/api.sock"
mkdir -p "$LAB/server/private" "$LAB/agent" "$LAB/sockets"

if [ ! -x "$BIN/spire-server" ] || [ ! -x "$BIN/spire-agent" ]; then
  bash "$ROOT/scripts/fetch_spire.sh"
fi

bash "$ROOT/scripts/stop_spire.sh" >/dev/null 2>&1 || true
rm -f "$SOCK" "$ADMIN"

echo "starting spire-server 1.15.3"
"$BIN/spire-server" run -config "$ROOT/third_party/spire/conf/server/server.conf" \
  > "$LAB/server.log" 2>&1 &
echo $! > "$LAB/server.pid"

for i in $(seq 1 40); do
  if [ -S "$ADMIN" ] && "$BIN/spire-server" healthcheck -socketPath "$ADMIN" >/dev/null 2>&1; then
    echo "spire-server healthy"
    break
  fi
  sleep 0.25
done
"$BIN/spire-server" healthcheck -socketPath "$ADMIN"

TOKEN=$("$BIN/spire-server" token generate \
  -socketPath "$ADMIN" \
  -spiffeID spiffe://prod/node/plane | awk '/Token:/{print $2}')
if [ -z "${TOKEN:-}" ]; then
  echo "failed to mint join token" >&2
  tail -20 "$LAB/server.log" >&2
  exit 1
fi
echo "join token minted"

echo "starting spire-agent"
"$BIN/spire-agent" run \
  -config "$ROOT/third_party/spire/conf/agent/agent.conf" \
  -joinToken "$TOKEN" \
  > "$LAB/agent.log" 2>&1 &
echo $! > "$LAB/agent.pid"

for i in $(seq 1 50); do
  if [ -S "$SOCK" ]; then
    echo "workload API: $SOCK"
    break
  fi
  sleep 0.2
done

UID_NUM=$(id -u)
JOIN_PARENT=$("$BIN/spire-server" entry show -socketPath "$ADMIN" \
  | awk '/Parent ID/{print $4}' | grep 'spiffe://prod/spire/agent/join_token/' | head -1)
PARENT=${JOIN_PARENT:-spiffe://prod/node/plane}
"$BIN/spire-server" entry create \
  -socketPath "$ADMIN" \
  -spiffeID spiffe://prod/agent/dev \
  -parentID "$PARENT" \
  -selector "unix:uid:${UID_NUM}" || true

echo
echo "export SPIFFE_ENDPOINT_SOCKET=unix://$SOCK"
echo "export PLANE_TRUST_DOMAIN=prod"
"$BIN/spire-agent" healthcheck -socketPath "$SOCK" || true
