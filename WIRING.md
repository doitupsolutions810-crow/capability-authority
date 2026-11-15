# Wiring notes (Harbor audit follow-through, 2026-11-15)

The existing `lab` workflow runs 3 of this repo's test files as scripts.
`ci/lab-full.yml` runs the **whole** `tests/` directory under pytest —
all 29 tests, including the GitHub App, policy-allowlist, SPIFFE-client and
evidence-receipt suites that CI currently never executes.

It is staged under `ci/` because the Muse GitHub App integration does not
hold GitHub's `workflows` permission and cannot write into
`.github/workflows/` (403 via both the contents and git-trees APIs). To
activate:

    git mv ci/lab-full.yml .github/workflows/lab-full.yml

One move, no edits needed. It uses the same env and deps as the existing
lab workflow, plus pytest. Verified locally before staging: 29 passed.
