"""Pure capability core — issue / attenuate / verify. Amplification forbidden."""
from __future__ import annotations

import math
import time
import uuid
from typing import Any, Optional


def now() -> float:
    return time.time()


def issue(caller, issuer, rights, constraints, ttl_seconds, trust_domain, broker_measurement, policy_version):
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    issued_at = now()
    return {
        "id": str(uuid.uuid4()),
        "issuer": issuer,
        "audience": caller,
        "rights": rights,
        "constraints": constraints,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        "parent_id": None,
        "nonce": str(uuid.uuid4()),
        "trust_domain": trust_domain,
        "broker_measurement": broker_measurement,
        "policy_version": policy_version,
        "delegation_depth": 0,
    }


def attenuate(cap, new_rights):
    old = {(r.get("type"), r.get("resource"), r.get("method")) for r in cap.get("rights") or []}
    for right in new_rights:
        key = (right.get("type"), right.get("resource"), right.get("method"))
        if key not in old:
            raise ValueError("amplification forbidden")
    out = dict(cap)
    out["id"] = str(uuid.uuid4())
    out["rights"] = new_rights
    out["issued_at"] = now()
    out["parent_id"] = cap["id"]
    out["nonce"] = str(uuid.uuid4())
    out["delegation_depth"] = int(cap.get("delegation_depth") or 0) + 1
    return out


def verify(cap, required, caller, now_ts=None):
    """Verify audience, expiry, and the complete right tuple including method."""
    try:
        ts = now_ts if now_ts is not None else now()
        expires_at = float(cap.get("expires_at"))
        if not math.isfinite(ts) or not math.isfinite(expires_at) or ts >= expires_at:
            return False
        if cap.get("audience") not in (caller, "*"):
            return False
        required_type = required.get("type")
        required_resource = required.get("resource")
        required_method = required.get("method")
        for right in cap.get("rights") or []:
            if right.get("type") != required_type or right.get("resource") != required_resource:
                continue
            # Missing method is not a wildcard. Both sides must agree exactly.
            if right.get("method") != required_method:
                continue
            return True
        return False
    except (TypeError, ValueError, AttributeError):
        return False
