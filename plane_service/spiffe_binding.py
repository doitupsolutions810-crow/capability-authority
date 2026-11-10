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
    """Bind issuance to the authenticated workload identity.

    A missing caller uses that identity. A supplied caller must match it.
    ``PLANE_ALLOW_CALLER_OVERRIDE=1`` is the only way to name a different
    caller, and only outside a live Workload API identity.
    """
    requested = body.get("caller") if isinstance(body, dict) else None
    if requested is not None and (not isinstance(requested, str) or not requested.strip()):
        raise SpiffeBindingError("caller must be a non-empty SPIFFE ID")
    ident = resolve_issue_identity(
        body_caller=requested if isinstance(requested, str) else None,
        trust_domain_cfg=os.environ.get("PLANE_TRUST_DOMAIN"),
    )
    if isinstance(requested, str) and requested != ident.spiffe_id:
        raise SpiffeBindingError(
            "requested caller does not match the authenticated workload identity"
        )
    out = dict(body)
    out["caller"] = ident.spiffe_id
    out["_identity_source"] = ident.source
    out["_trust_domain"] = ident.trust_domain
    return out
