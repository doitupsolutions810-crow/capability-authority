#!/usr/bin/env bash
# Official py-spiffe library. PyPI package name is `spiffe`.
# Isolated target so Debian cryptography 41 is not overwritten.
set -euo pipefail
TARGET=${SPIFFE_PY_TARGET:-/opt/capability-authority/py-spiffe}
mkdir -p "$TARGET"
python3 -m pip install --target "$TARGET" --index-url https://pypi.org/simple --upgrade 'spiffe>=0.3.1'
python3 - "$TARGET" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from spiffe import WorkloadApiClient
print("py-spiffe ok:", WorkloadApiClient, "target=", sys.argv[1])
PY
echo "export PYTHONPATH=${TARGET}:\$PYTHONPATH"
echo "export SPIFFE_PY_TARGET=${TARGET}"
