# Capability Rights Contract v1

A capability authorizes a request only when audience, expiry, type, resource, and method match exactly. Missing requested methods, missing granted methods, malformed expiry, and implicit method wildcards fail closed. Expiry is exclusive: now_ts >= expires_at is expired.

Attenuation must preserve or reduce exact (type, resource, method) tuples. Callers that omit method must be updated before rollout.

The same conformance vectors are stored in contracts/capability-rights-v1.json in both repositories.

Verification status: regression tests are authored but not yet executed in a functioning runtime. Require exact-head CI and call-site compatibility review before merge. This change is not deployed.
