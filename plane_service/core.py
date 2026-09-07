"""Pure capability core — issue / attenuate / verify. Amplification forbidden."""
from __future__ import annotations
import time, uuid
from typing import Any, Optional

def now() -> float:
    return time.time()

def issue(caller, issuer, rights, constraints, ttl_seconds, trust_domain, broker_measurement, policy_version):
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
    for r in new_rights:
        if (r.get("type"), r.get("resource"), r.get("method")) not in old:
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
    ts = now_ts if now_ts is not None else now()
    if ts > float(cap.get("expires_at") or 0):
        return False
    if cap.get("audience") not in (caller, "*"):
        return False
    for r in cap.get("rights") or []:
        if r.get("type") == required.get("type") and r.get("resource") == required.get("resource"):
            return True
    return False
