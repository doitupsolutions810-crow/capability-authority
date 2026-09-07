# SPIRE agent integration

Official CNCF SPIRE **v1.15.3** (`spiffe/spire`), linux-amd64-musl.

Tarball SHA-256: `ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7`

```bash
bash scripts/fetch_spire.sh
bash scripts/start_spire.sh
export SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-lab/sockets/agent.sock
export PLANE_TRUST_DOMAIN=prod
python3 -m plane_service.server
```

Python client is the official `spiffe` package (py-spiffe project):

```bash
bash scripts/install_py_spiffe.sh
# or system site-packages:
# python3 -m pip install --index-url https://pypi.org/simple --target /usr/local/lib/python3.12/dist-packages 'spiffe>=0.3.1'
```

Lab uses join_token + insecure_bootstrap. Not production.
