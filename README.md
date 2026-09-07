# Capability Authority

High-assurance **control plane for agentic systems**. Planners think. This plane is the only way they act.

Lab mode runs without SPIRE. Production mode **refuses to start** until SPIRE, a pinned measurement, and Postgres exist.

## Quick start (lab)

```bash
export PYTHONPATH=$PWD
python3 scripts/demo_hands.py
python3 scripts/demo_production_profile.py
python3 scripts/demo_four_rings.py
python3 tools/evidence_export.py --out data/evidence_export.json
```

## Production profile

```bash
set -a && source config/production.env && set +a
python3 -c "from rings.production_profile import preflight; import json; print(json.dumps(preflight().as_dict(), indent=2))"
```

Until SPIRE + real PCR + `DATABASE_URL` are present, preflight is supposed to fail.

## Research we absorb

See [docs/GITHUB_RESEARCH.md](docs/GITHUB_RESEARCH.md): SPIRE, Cedar / cedar-for-agents, OpenFGA, Nitro/Nitrum, Microsoft TEE-Attestation-Verification, Confidential Containers.

## Boundaries

Agents use frozen OpenAPI only. Hands router denies shell, kubectl-from-model, ambient keys, and hold-bypass.
