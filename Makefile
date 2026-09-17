.PHONY: test plane ci

test:
	PYTHONPATH=. python3 tests/test_plane.py
	PYTHONPATH=. python3 tests/test_evidence_receipt_spiffe.py
	PYTHONPATH=. python3 tests/test_agents.py

ci:
	bash scripts/run_ci_local.sh

plane:
	PYTHONPATH=. python3 -m plane_service.server
