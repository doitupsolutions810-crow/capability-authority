# capability-authority

High-assurance **capability + admin control plane** for agentic systems.

Agents get short-lived signed rights. Infrastructure changes go through dual
approval, immutable idempotency, and reconcile-before-retry. Every issued and
executed act leaves a verifiable receipt.

## Quick start

```bash
git clone https://github.com/doitupsolutions810-crow/capability-authority.git
cd capability-authority
pip install -r requirements-lab.txt
export PYTHONPATH=$PWD
make test
python3 -m plane_service.server          # :8090
```

## CI

Hosted Actions may be blocked by an account billing lock. Run the same checks
locally with no billing and no Docker:

```bash
bash scripts/run_ci_local.sh
```

See `docs/CI.md`.

## Hard rules

- No ambient shell or god tokens
- Timeout = unknown → reconcile before retry
- One immutable provider idempotency key per control-plane request id
- Forensic / legal hold / dispute always fail-closed
- Agents never mint admin power; UI never mints privilege
