# CI — hosted and local

## Hosted (GitHub Actions)

Workflow: `.github/workflows/lab.yml`. Triggers on push, PR, and manual dispatch.

If runs fail instantly with:

> The job was not started because your account is locked due to a billing issue

that is an account-level billing lock, not a test failure. Public repos get free
standard-runner minutes, but a stale authorization hold can still block the
account. Fix it at Settings → Billing & Licensing → Payment information
(re-add the card, or contact GitHub Support to clear the hold).

## Local (no billing, no Docker)

```bash
bash scripts/run_ci_local.sh
```

Same steps the workflow runs: install `requirements-lab.txt`, run the three test
modules, then the hands/agent demos. Production preflight is allowed to fail
here — that is expected in lab mode.

## Optional: nektos/act

If Docker is available, `act` runs the real workflow file locally:

```bash
act -P ubuntu-latest=-self-hosted
```

Prefer `run_ci_local.sh` when Docker is not present.
