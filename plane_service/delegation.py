"""Fail-closed delegated capability issuance primitives.

The requester assertion is signed by a separately pinned workload key. The
parent capability limits child rights and lifetime; a server-owned audience
allowlist prevents arbitrary subject selection.
"""
from __future__ import annotations

import base64
import math
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto_sign import canonical

ASSERTION_FIELDS = {
    "schema", "issuer", "subject", "audience", "jti",
    "issued_at", "expires_at", "signature",
}


class DelegationError(ValueError):
    pass


def _utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise DelegationError("assertion timestamps must be strings")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DelegationError("assertion timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise DelegationError("assertion timestamp must include UTC timezone")
    normalized = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if normalized != value:
        raise DelegationError("assertion timestamp must be canonical UTC")
    return parsed.astimezone(timezone.utc)


def verify_requester_assertion(
    assertion: dict,
    public_key_pem: bytes,
    *,
    expected_issuer: str,
    expected_audience: str,
    now: datetime | None = None,
    clock_skew_seconds: int = 30,
    max_lifetime_seconds: int = 60,
) -> str:
    if not isinstance(assertion, dict) or set(assertion) != ASSERTION_FIELDS:
        raise DelegationError("requester assertion schema mismatch")
    if assertion.get("schema") != "capability-authority.delegation-assertion/v1":
        raise DelegationError("unsupported requester assertion schema")
    if assertion.get("issuer") != expected_issuer or assertion.get("subject") != expected_issuer:
        raise DelegationError("requester assertion identity mismatch")
    if assertion.get("audience") != expected_audience:
        raise DelegationError("requester assertion audience mismatch")
    jti = assertion.get("jti")
    if not isinstance(jti, str) or not jti.strip() or len(jti) > 128:
        raise DelegationError("requester assertion jti is required")
    issued = _utc(assertion.get("issued_at"))
    expires = _utc(assertion.get("expires_at"))
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise DelegationError("verification clock must be timezone-aware")
    skew = clock_skew_seconds
    if issued.timestamp() > current.timestamp() + skew or expires.timestamp() <= current.timestamp() - skew:
        raise DelegationError("requester assertion is expired or premature")
    if expires <= issued or (expires - issued).total_seconds() > max_lifetime_seconds:
        raise DelegationError("requester assertion lifetime exceeds policy")
    signature = assertion.get("signature")
    if not isinstance(signature, str):
        raise DelegationError("requester assertion signature is required")
    try:
        raw = base64.b64decode(signature, validate=True)
        if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != signature:
            raise ValueError("non-canonical signature")
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise DelegationError("requester assertion key must be Ed25519")
        unsigned = {key: value for key, value in assertion.items() if key != "signature"}
        key.verify(raw, canonical(unsigned))
    except DelegationError:
        raise
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise DelegationError("requester assertion signature is invalid") from exc
    return jti


def validate_delegation(
    parent: dict,
    *,
    requester: str,
    audience: str,
    rights: list,
    ttl_seconds: int,
    allowed_audiences: set[str],
    now_ts: float,
    max_ttl_seconds: int = 300,
    max_delegation_depth: int = 3,
) -> int:
    if not isinstance(parent, dict):
        raise DelegationError("parent capability must be an object")
    if not isinstance(requester, str) or not requester.strip() or parent.get("audience") != requester:
        raise DelegationError("parent capability audience must match authenticated requester")
    if not isinstance(parent.get("id"), str) or not parent["id"].strip():
        raise DelegationError("parent capability id is required")
    depth = parent.get("delegation_depth", 0)
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0 or depth + 1 > max_delegation_depth:
        raise DelegationError("maximum delegation depth exceeded")
    parent_expiry = parent.get("expires_at")
    if isinstance(parent_expiry, bool) or not isinstance(parent_expiry, (int, float)) or not math.isfinite(parent_expiry):
        raise DelegationError("parent capability expiry is invalid")
    if parent_expiry <= now_ts:
        raise DelegationError("parent capability is expired")
    issued_at = parent.get("issued_at")
    if isinstance(issued_at, bool) or not isinstance(issued_at, (int, float)) or not math.isfinite(issued_at):
        raise DelegationError("parent capability issue time is invalid")
    if issued_at > now_ts + 30 or issued_at >= parent_expiry:
        raise DelegationError("parent capability issue time is invalid")
    if not isinstance(audience, str) or audience not in allowed_audiences:
        raise DelegationError("delegated audience is not allowlisted")
    constraints = parent.get("constraints")
    if not isinstance(constraints, dict):
        raise DelegationError("parent constraints must be an object")
    delegated_audiences = constraints.get("delegation_audiences")
    if not isinstance(delegated_audiences, list) or audience not in delegated_audiences:
        raise DelegationError("delegated audience is not authorized by parent constraints")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= max_ttl_seconds:
        raise DelegationError("delegated TTL must be an integer within policy")
    remaining = math.floor(parent_expiry - now_ts)
    if remaining < 1:
        raise DelegationError("parent capability is expired")
    parent_rights = parent.get("rights")
    if not isinstance(parent_rights, list):
        raise DelegationError("parent capability rights are invalid")
    allowed = set()
    for right in parent_rights:
        if not isinstance(right, dict):
            continue
        allowed.add((right.get("type"), right.get("resource"), right.get("method")))
    if not isinstance(rights, list) or not rights:
        raise DelegationError("delegated rights must be a non-empty list")
    seen = set()
    for right in rights:
        if not isinstance(right, dict) or set(right) != {"type", "resource", "method"}:
            raise DelegationError("each delegated right must contain exact type, resource, and method")
        key = (right.get("type"), right.get("resource"), right.get("method"))
        if not all(isinstance(part, str) and part.strip() for part in key):
            raise DelegationError("delegated right fields must be non-empty strings")
        if key in seen:
            raise DelegationError("duplicate delegated right")
        seen.add(key)
        if key not in allowed:
            raise DelegationError("delegated rights exceed parent capability")
    return min(ttl_seconds, max_ttl_seconds, remaining)
