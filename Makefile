PYTHON ?= python3
export PYTHONPATH := $(CURDIR)

.PHONY: test demos plane front-door health

test:
	$(PYTHON) tests/test_plane.py

demos:
	$(PYTHON) scripts/demo_hands.py
	$(PYTHON) scripts/demo_production_profile.py
	$(PYTHON) scripts/demo_issue_execute.py
	$(PYTHON) scripts/demo_remaining_rings.py

plane:
	$(PYTHON) -m plane_service.server

front-door:
	$(PYTHON) gateway/https_front_door.py

health:
	curl -sS http://127.0.0.1:8090/health | $(PYTHON) -m json.tool
