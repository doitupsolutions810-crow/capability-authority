# Start development

Lab first. Production stays fail-closed.

```bash
export PYTHONPATH=$PWD
make test
make plane
curl -sS 'http://127.0.0.1:8090/v1/evidence?stats=1'
```

Frozen: Issue / Attenuate / Verify / Execute / health / evidence / identity.

SPIRE when an agent exists:

```bash
export SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock
export SPIFFE_REQUIRED=1
```

Without an agent, leave SPIFFE_REQUIRED unset.
