# SPIRE agent integration

Official CNCF SPIRE v1.15.3 from https://github.com/spiffe/spire/releases

Tarball: `spire-1.15.3-linux-amd64-musl.tar.gz`
SHA-256: `ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7`

```bash
bash scripts/fetch_spire.sh
bash scripts/start_spire.sh
export SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-lab/sockets/agent.sock
export PLANE_TRUST_DOMAIN=prod
```

Lab uses join_token + insecure_bootstrap. Not production.
