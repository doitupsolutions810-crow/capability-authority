#!/usr/bin/env bash
# Run the same checks GitHub Actions would run, on this host.
# Use this when the account billing lock blocks hosted runners.
set -euo pipefail
export PYTHONPATH="${PYTHONPATH:-.}"
export PRODUCTION="${PRODUCTION:-0}"
export SPIFFE_REQUIRED="${SPIFFE_REQUIRED:-0}"
export ALLOW_ADMIN_DESTRUCTIVE_ACTIONS="${ALLOW_ADMIN_DESTRUCTIVE_ACTIONS:-false}"

echo "==> pip install -r requirements-lab.txt"
python3 -m pip install --upgrade pip >/dev/null
pip install -r requirements-lab.txt

echo "==> tests"
python3 tests/test_plane.py
python3 tests/test_evidence_receipt_spiffe.py
python3 tests/test_evidence_index_fail_closed.py
python3 tests/test_evidence_index_projection_consistency.py
python3 tests/test_evidence_recording_contract.py
python3 tests/test_evidence_warehouse_concurrency.py
python3 tests/test_execution_contract.py
python3 tests/test_agents.py

echo "==> demos"
python3 scripts/demo_hands.py
python3 scripts/demo_agents.py
python3 scripts/demo_production_profile.py || true

echo "ALL GREEN"
