PYTHON ?= python3
export PYTHONPATH := $(CURDIR)
.PHONY: test demos plane health evidence
test:
	$(PYTHON) tests/test_plane.py
	$(PYTHON) tests/test_evidence_receipt_spiffe.py
plane:
	$(PYTHON) -m plane_service.server
health:
	curl -sS http://127.0.0.1:8090/health
evidence:
	curl -sS 'http://127.0.0.1:8090/v1/evidence?stats=1'
