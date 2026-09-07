#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$ROOT/config/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$ROOT/config/tls/front_door.key" \
  -out "$ROOT/config/tls/front_door.crt" \
  -subj "/CN=localhost"
echo "wrote config/tls/front_door.{crt,key}"
