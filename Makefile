.PHONY: test plane ci

test:
	PYTHONPATH=. python3 tests/test_plane.py
	PYTHONPATH=. python3 tests/test_evidence_receipt_spiffe.py
	PYTHONPATH=. python3 tests/test_evidence_index_fail_closed.py
	PYTHONPATH=. python3 tests/test_evidence_index_projection_consistency.py
	PYTHONPATH=. python3 tests/test_evidence_recording_contract.py
	PYTHONPATH=. python3 tests/test_evidence_warehouse_concurrency.py
	PYTHONPATH=. python3 tests/test_execution_contract.py
	PYTHONPATH=. python3 tests/test_agents.py

ci:
	bash scripts/run_ci_local.sh

plane:
	PYTHONPATH=. python3 -m plane_service.server
