#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYTHONPATH:-$(cd "$(dirname "$0")/.." && pwd)}"
exec python3 -m plane_service.server
