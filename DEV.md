# Development rules

- Frozen OpenAPI only: /v1/capabilities/issue|attenuate|verify, /v1/execute
- No ambient exec, no god tokens, no hold-bypass
- Production stays fail-closed (SPIRE + pinned measurement + DATABASE_URL)
- CI: hosted Actions may be billing-locked; use `bash scripts/run_ci_local.sh`
