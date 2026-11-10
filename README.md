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
python3 -m plane_service.server          # :8095
```

## CI

Hosted Actions may be blocked by an account billing lock. Run the same checks
locally with no billing and no Docker:

```bash
bash scripts/run_ci_local.sh
```

See `docs/CI.md`.

## Delegated workload capabilities

The `POST /v1/capabilities/delegate` endpoint supports short-lived, signed requester assertions, pinned requester keys, exact audience allowlists, parent-right attenuation, parent-lifetime bounds, one-use assertion IDs, idempotent correlation replay, and durable issuance evidence. See [docs/DELEGATED_CAPABILITY_ISSUANCE.md](docs/DELEGATED_CAPABILITY_ISSUANCE.md). It remains disabled until production trust roots and secret mounts are provisioned.

## Capability rights

Every right is the triple `type`, `resource`, and `method`. A right that omits `method` is rejected. There is no wildcard and no implied method: older clients that sent only `{"type":"read","resource":"demo"}` must send `"method":"GET"` (or another explicit method on the server allowlist). The same rule applies to execute's `required` object.

## Hard rules

- No ambient shell or god tokens
- Timeout = unknown → reconcile before retry
- One immutable provider idempotency key per control-plane request id
- Forensic / legal hold / dispute always fail-closed
- Agents never mint admin power; UI never mints privilege
