# Source overlay

Public tree on GitHub starts with docs + rings + lab requirements.
Full workspace also includes plane_service, admin, evidence, scripts.

Lab tests (from a complete checkout of the workspace tree):

```bash
export PYTHONPATH=$PWD
python3 scripts/demo_hands.py
python3 scripts/demo_production_profile.py
```

This commit lands the rings package entry and lab pin file so clones have a place to grow.
