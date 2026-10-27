"""Pure capability core — issue / attenuate / verify. Amplification forbidden."""
from __future__ import annotations
import math, time, uuid
from typing import Any, Optional

def now() -> float:
    return time.time()

def issue(caller, issuer, rights, constraints, ttl_seconds, trust_domain, broker_measurement, policy_version):
    issued_at = now()
    return {"id": str(uuid.uuid4()), "issuer": issuer, "audience": caller, "rights": rights, "constraints": constraints, "issued_at": issued_at, "expires_at": issued_at + ttl_seconds, "parent_id": None, "nonce": str(uuid.uuid4()), "trust_domain": trust_domain, "broker_measurement": broker_measurement, "policy_version": policy_version, "delegation_depth": 0}

def attenuate(cap, new_rights):
    if not isinstance(cap, dict):
        raise ValueError("parent capability must be an object")
    if not isinstance(new_rights, list):
        raise ValueError("child rights must be a list")
    parent_rights = cap.get("rights")
    if not isinstance(parent_rights, list):
        raise ValueError("parent rights must be a list")
    parent_id = cap.get("id")
    if not isinstance(parent_id, str) or not parent_id.strip():
        raise ValueError("parent capability id is required")

    old = set()
    fields = ("type", "resource", "method")
    for right in parent_rights:
        if not isinstance(right, dict):
            continue
        key = tuple(right.get(field) for field in fields)
        if all(isinstance(value, str) and value.strip() for value in key):
            old.add(key)

    for right in new_rights:
        if not isinstance(right, dict):
            raise ValueError("each child right must be an object")
        key = tuple(right.get(field) for field in fields)
        if not all(isinstance(value, str) and value.strip() for value in key):
            raise ValueError("each child right requires non-empty type, resource, and method")
        if key not in old:
            raise ValueError("amplification forbidden")

    depth = cap.get("delegation_depth", 0)
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
        raise ValueError("invalid parent delegation depth")
    out = dict(cap)
    out["id"] = str(uuid.uuid4())
    out["rights"] = new_rights
    out["issued_at"] = now()
    out["parent_id"] = parent_id
    out["nonce"] = str(uuid.uuid4())
    out["delegation_depth"] = depth + 1
    return out


def verify(cap, required, caller, now_ts=None):
    """Fail closed unless audience, expiry, type, resource, and method match exactly."""
    if not isinstance(cap, dict) or not isinstance(required, dict):
        return False
    if not isinstance(caller, str) or not caller:
        return False

    raw_now = now() if now_ts is None else now_ts
    if isinstance(raw_now, bool) or not isinstance(raw_now, (int, float)):
        return False
    ts = float(raw_now)
    if not math.isfinite(ts):
        return False

    raw_expiry = cap.get("expires_at")
    if isinstance(raw_expiry, bool) or not isinstance(raw_expiry, (int, float)):
        return False
    expires_at = float(raw_expiry)
    if not math.isfinite(expires_at) or ts >= expires_at:
        return False

    audience = cap.get("audience")
    if not isinstance(audience, str) or audience != caller:
        return False

    required_type = required.get("type")
    required_resource = required.get("resource")
    required_method = required.get("method")
    if not all(isinstance(value, str) and value.strip() for value in (required_type, required_resource, required_method)):
        return False

    rights = cap.get("rights")
    if not isinstance(rights, list):
        return False
    for right in rights:
        if not isinstance(right, dict):
            continue
        if (
            right.get("type") == required_type
            and right.get("resource") == required_resource
            and right.get("method") == required_method
        ):
            return True
    return False
