# GitHub research map (Sep 2026)

This plane stays the hands. External projects are adapters or compilers.

## Identity
- https://github.com/spiffe/spire — production SVIDs (`SPIFFE_REQUIRED=1`)
- https://github.com/spiffe/helm-charts-hardened — next host install
- https://microsoft.github.io/identity-spiffe/ — sidecar above Issue, not a side door

## Policy
- https://github.com/cedar-policy/cedar — compile to capability templates
- https://github.com/cedar-policy/cedar-for-agents — agent tool allowlists (updated Sep 2026)
- https://github.com/openfga/openfga — delegation graphs only

Credential broker pattern (SPIFFE → Cedar → short creds): matches rings/vault_lease.py

## Confidential compute
- https://github.com/aws/aws-nitro-enclaves-samples
- https://github.com/matzapata/nitrum
- https://github.com/microsoft/TEE-Attestation-Verification
- https://github.com/confidential-containers/guest-components
- https://github.com/project-oak/oak
- https://github.com/TEE-Attestation
- https://github.com/Fraunhofer-AISEC/cmc

## Not merged
Agent shell/kubectl-from-model, long-lived cloud keys, hold-bypass.
