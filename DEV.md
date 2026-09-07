# Start development

Lab first. Production stays fail-closed.

```bash
cd capability-authority
pip install -r requirements-lab.txt
export PYTHONPATH=$PWD
make test
make demos
make plane          # http://127.0.0.1:8090/health
```

## This week

1. Keep Issue → Attenuate → Verify → Execute working with Ed25519.
2. Do not add ambient shell / kubectl / long-lived keys.
3. Production profile must fail without SPIRE + pinned measurement + durable outbox.
4. K8s adapter stays plan-first (`K8S_LIVE=0`).

## Frozen contract

- `POST /v1/capabilities/issue`
- `POST /v1/capabilities/attenuate`
- `POST /v1/capabilities/verify`
- `POST /v1/execute`
- `GET /health`
