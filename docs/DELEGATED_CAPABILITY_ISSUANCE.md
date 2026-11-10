# Delegated workload capability issuance

The new `POST /v1/capabilities/delegate` route issues an attenuated child capability to a pre-approved workload audience. It does not enable caller override and does not trust a `caller` or `requester` field supplied in JSON.

## Trust model

1. AVRONE signs a short-lived `capability-authority.delegation-assertion/v1` object with its Ed25519 workload key.
2. The Authority verifies the assertion against the independently provisioned `PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE` and exact configured `PLANE_DELEGATION_REQUESTER_ID`.
3. The assertion's issuer and subject must both equal the pinned AVRONE identity, its audience must be the Authority SPIFFE identity, its lifetime is at most 60 seconds, and its `jti` is one-use.
4. The parent capability must have a valid Authority signature, issuer, bounds, and an audience exactly equal to the authenticated requester.
5. The requested child audience must be in both `PLANE_DELEGATION_ALLOWED_AUDIENCES` and the parent capability's signed `constraints.delegation_audiences` list. Child rights must be an exact subset of parent `(type, resource, method)` tuples. No wildcard or method substitution is accepted.
6. Child TTL is capped by the parent's remaining lifetime, the Authority's maximum TTL, and the configured maximum delegation depth. Parent constraints are inherited unchanged.
7. The signed child is committed to the durable issuance ledger (`PLANE_ISSUANCE_IDEMPOTENCY_PATH`) before the response is returned, then recorded in the evidence index. Idempotency binds the stable correlation ID to the request parameters, the assertion `jti`, and the digest of the full canonical signed requester assertion. A retry must reuse that exact signed assertion and those parameters, including after process restart, and then receives the byte-identical child. A fresh `jti`, an altered signed assertion, or any other parameter change (including method) under an already-used correlation is a conflict. Reusing one `jti` under a different correlation is rejected. Ledger entries expire with the child capability and remain tombstones, so expiry does not mint a replacement. A corrupt or unreadable ledger fails closed.

## Bootstrap parent capability

AVRONE cannot request its own parent capability by passing a JSON `caller`; that would reintroduce caller spoofing. An Authority operator provisions the narrow root parent capability out of band on the Authority host:

```bash
export PLANE_DELEGATION_REQUESTER_ID=spiffe://prod/agent/avrone
export PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE=/run/secrets/avrone-delegation-requester.pub
export PLANE_DELEGATION_ALLOWED_AUDIENCES=spiffe://prod/agent/swarm
export PLANE_AVRONE_PARENT_CAPABILITY_FILE=/var/lib/capability-authority/avrone-swarm-parent-capability.json
export PLANE_AVRONE_PARENT_CAPABILITY_CORRELATION_ID=avrone-swarm-root-2026-11-03
python scripts/issue_avrone_swarm_parent.py
```

The script issues only `Execute:swarm.jobs:POST`, binds the parent capability to AVRONE, embeds the exact delegated-audience scope in its constraints, persists the issuance evidence, and writes the capability/signature file atomically with mode `0600`. Re-running with the same correlation and exact request restores the same capability. A different request or different existing output file is refused. Mount the resulting file read-only into AVRONE as an independent secret/configuration artifact. Never commit it.

## Request

```json
{
  "requester_assertion": {
    "schema": "capability-authority.delegation-assertion/v1",
    "issuer": "spiffe://prod/agent/avrone",
    "subject": "spiffe://prod/agent/avrone",
    "audience": "spiffe://prod/broker",
    "jti": "unique-one-time-id",
    "issued_at": "2026-11-03T09:00:00.000Z",
    "expires_at": "2026-11-03T09:00:30.000Z",
    "signature": "BASE64_ED25519_SIGNATURE"
  },
  "parent_capability": {},
  "parent_signature": "BASE64_CA_SIGNATURE",
  "audience": "spiffe://prod/agent/swarm",
  "rights": [{"type":"Execute","resource":"swarm.jobs","method":"POST"}],
  "ttl_seconds": 120,
  "correlation_id": "stable-request-correlation-id"
}
```

The signature covers the RFC 8785 canonical JSON of every assertion field except `signature`. The endpoint path is `/v1/capabilities/delegate`.

## Production provisioning

Set the following in the protected production environment and mount the public key read-only from the independent secret store:

- `PLANE_DELEGATION_REQUESTER_ID=spiffe://prod/agent/avrone`
- `PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE=/run/secrets/avrone-delegation-requester.pub`
- `PLANE_DELEGATION_ALLOWED_AUDIENCES=spiffe://prod/agent/swarm`

The public key must be pinned out of band and correspond to the AVRONE signing key. Never accept a key supplied in the request. Do not enable `PLANE_ALLOW_CALLER_OVERRIDE`. If any trust root or allowlist is absent, the route fails closed.

## Remaining operational gate

The endpoint code and unit tests do not provision the production key, configure the secret mount, or prove an actual AVRONE-to-Authority signed assertion in the live deployment. Put `PLANE_ISSUANCE_IDEMPOTENCY_PATH` on durable storage local to the Authority; the ledger is the replay source Trinity uses after a lost delegation response. Keep the AVRONE→Swarm production route disabled until those are completed and verified.
