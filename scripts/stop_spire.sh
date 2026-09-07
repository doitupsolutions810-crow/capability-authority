#!/usr/bin/env bash
set -euo pipefail
LAB=/tmp/spire-lab
for f in "$LAB/agent.pid" "$LAB/server.pid"; do
  if [ -f "$f" ]; then
    kill "$(cat "$f")" 2>/dev/null || true
    rm -f "$f"
  fi
done
pkill -f 'spire-server run' 2>/dev/null || true
pkill -f 'spire-agent run' 2>/dev/null || true
echo "SPIRE lab stopped"
