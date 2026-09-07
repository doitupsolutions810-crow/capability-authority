# Capability Authority

High-assurance **control plane for agentic systems**. Planners think. This plane is the only way they act.

Lab mode runs without SPIRE. Production mode **refuses to start** until SPIRE, a pinned measurement, and Postgres exist.

## Quick start (lab)

```bash
export PYTHONPATH=$PWD
pip install -r requirements-lab.txt
make test
python3 scripts/demo_hands.py
python3 scripts/demo_agents.py
python3 -m plane_service.server
```

Optional SPIRE + Workload API SVID:

```bash
bash scripts/fetch_spire.sh
bash scripts/start_spire.sh
export SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-lab/sockets/agent.sock
```

## Tests

GitHub Actions (`lab`) runs `test_plane`, `test_evidence_receipt_spiffe`, and `test_agents` on every push to `main`.

## Authority boundaries

| Actor | May |
|-------|-----|
| Agent / model | Frozen OpenAPI only |
| Hands router | Deny shell, kubectl-from-model, ambient keys, hold-bypass |
| Operator | `k8s_plan` + dual-approved admin actions |
| Executor | Only path that performs side effects |
| Production broker | Exit if preflight fails |
