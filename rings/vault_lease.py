from dataclasses import dataclass
import time

@dataclass
class Lease:
    capability_id: str
    audience: str
    scope: str
    expires_at: float
    token_ref: str
    signature: str = "lab"

class VaultStyleLease:
    def issue(self, capability, scope, ttl_seconds=60):
        cap_id = capability["id"]
        return Lease(cap_id, capability.get("audience") or "", scope, time.time()+ttl_seconds, f"lease:{cap_id[:8]}:{scope}")
    def redeem(self, lease, capability_id, now=None):
        ts = now if now is not None else time.time()
        if lease.capability_id != capability_id:
            return {"ok": False, "error": "lease not bound to this capability"}
        if ts > lease.expires_at:
            return {"ok": False, "error": "lease expired"}
        return {"ok": True, "token_ref": lease.token_ref, "scope": lease.scope}
