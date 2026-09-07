# Start development

```bash
export PYTHONPATH=$PWD
make test
make plane
bash scripts/fetch_spire.sh && bash scripts/start_spire.sh
export SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-lab/sockets/agent.sock
```

Frozen: Issue / Attenuate / Verify / Execute / health / evidence / identity / agents.
