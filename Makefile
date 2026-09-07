PYTHON ?= python3
export PYTHONPATH := $(CURDIR)

.PHONY: test demos plane front-door health spire

test:
	$(PYTHON) tests/test_plane.py
	$(PYTHON) tests/test_evidence_receipt_spiffe.py
	$(PYTHON) tests/test_agents.py

plane:
	$(PYTHON) -m plane_service.server

spire:
	bash scripts/start_spire.sh

health:
	curl -sS http://127.0.0.1:8090/health | $(PYTHON) -m json.tool
