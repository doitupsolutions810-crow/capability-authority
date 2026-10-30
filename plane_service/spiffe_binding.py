"""SPIRE-live binding for Issue audience."""
from __future__ import annotations

import os
from typing import Optional

from .spiffe_identity import WorkloadIdentity, fetch_workload_identity


class SpiffeBindingError(Exception):
    pass


def resolve_issue_identity(
    body_caller: Optional[str] = None,
    trust_domain_cfg: Optional[str] = None,
) -> WorkloadIdentity:
    ident = fetch_workload_identity(trust_domain_cfg=trust_domain_cfg)
    required = os.environ.get("SPIFFE_REQUIRED", "0") == "1" or os.environ.get(
        "PRODUCTION", "0"
    ) == "1" or os.environ.get("PLANE_PRODUCTION", "0") == "1"

    if ident.source == "workload-api":
        return ident

    if required and ident.source != "workload-api":
        raise SpiffeBindingError(
            "production requires a Workload API X509-SVID; "
            f"identity source was {ident.source!r} "
            f"(socket={os.environ.get('SPIFFE_ENDPOINT_SOCKET')})"
        )

    # Caller-provided identities are a development-only compatibility path.
    allow_override = (
        not required
        and os.environ.get("PLANE_ALLOW_CALLER_OVERRIDE", "0") == "1"
    )
    if body_caller and allow_override and ident.source in ("env", "fallback"):
        from .spiffe_identity import _parse_trust_domain

        return WorkloadIdentity(
            body_caller,
            trust_domain_cfg or _parse_trust_domain(body_caller),
            source="caller-override",
            socket_reachable=ident.socket_reachable,
        )
    return ident


def bind_issue_request(body: dict, authenticated_caller: Optional[str] = None) -> dict:
    required = (
        os.environ.get("SPIFFE_REQUIRED", "0") == "1"
        or os.environ.get("PRODUCTION", "0") == "1"
        or os.environ.get("PLANE_PRODUCTION", "0") == "1"
    )
    if required:
        # In production, caller identity comes only from the verified TLS peer
        # certificate. A JSON field or the broker's own SVID is not caller auth.
        if not authenticated_caller or not authenticated_caller.startswith("spiffe://"):
            raise SpiffeBindingError("production capability issuance requires an authenticated SPIFFE mTLS peer")
        from .spiffe_identity import _allowed_trust_domains, _parse_trust_domain

        trust_domain = _parse_trust_domain(authenticated_caller)
        if trust_domain not in _allowed_trust_domains():
            raise SpiffeBindingError("mTLS peer trust domain is not allowed")
        if not authenticated_caller.startswith(f"spiffe://{trust_domain}/agent/"):
            raise SpiffeBindingError("mTLS peer must be an agent workload identity")
        caller = authenticated_caller
        source = "mtls-peer"
    else:
        ident = resolve_issue_identity(
            body_caller=body.get("caller"),
            trust_domain_cfg=os.environ.get("PLANE_TRUST_DOMAIN"),
        )
        caller = ident.spiffe_id
        trust_domain = ident.trust_domain
        source = ident.source

    out = dict(body)
    out["caller"] = caller
    out["_identity_source"] = source
    out["_trust_domain"] = trust_domain
    return out
