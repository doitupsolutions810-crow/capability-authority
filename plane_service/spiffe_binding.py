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

    if required and ident.source == "fallback":
        raise SpiffeBindingError(
            "SPIFFE_REQUIRED=1 but Workload API SVID unavailable "
            f"(socket={os.environ.get('SPIFFE_ENDPOINT_SOCKET')})"
        )

    allow_override = os.environ.get("PLANE_ALLOW_CALLER_OVERRIDE", "0") == "1"
    if body_caller and allow_override and ident.source in ("env", "fallback"):
        from .spiffe_identity import _parse_trust_domain

        return WorkloadIdentity(
            body_caller,
            trust_domain_cfg or _parse_trust_domain(body_caller),
            source="caller-override",
            socket_reachable=ident.socket_reachable,
        )
    return ident


def bind_issue_request(body: dict) -> dict:
    ident = resolve_issue_identity(
        body_caller=body.get("caller"),
        trust_domain_cfg=os.environ.get("PLANE_TRUST_DOMAIN"),
    )
    out = dict(body)
    out["caller"] = ident.spiffe_id
    out["_identity_source"] = ident.source
    out["_trust_domain"] = ident.trust_domain
    return out
