import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict, deque
from plane_service.bounds import check_bounds, load_acceptance
from plane_service.core import verify
from plane_service.crypto_sign import sign, verify_sig


class RateLimiter:
    def __init__(self):
        self.windows = defaultdict(deque)

    def allow(self, key, max_count, window_seconds):
        now = time.time()
        q = self.windows[key]
        cutoff = now - window_seconds
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= max_count:
            return False
        q.append(now)
        return True


class Executor:
    """Authorization verifier only; no action dispatcher is wired in this service."""

    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.crl = set()
        self.acceptance = load_acceptance()

    def execute(self, cap, signature, required, caller, *, message_id=None, correlation_id=None, payload_digest=None, previous_receipt_digest=None):
        if cap.get("id") in self.crl:
            return {"status": "error", "error": "revoked"}
        if not verify_sig(cap, signature):
            return {"status": "error", "error": "invalid signature"}
        err = check_bounds(cap, self.acceptance)
        if err:
            return {"status": "error", "error": err}
        if not verify(cap, required, caller):
            return {"status": "error", "error": "verify failed"}

        kind = required["type"]
        resource = required["resource"]
        method = required["method"]
        rl = (cap.get("constraints") or {}).get("rate_limit") or {}
        key = f"{cap.get('id')}:{kind}:{resource}:{method}"
        if not self.rate_limiter.allow(key, int(rl.get("count") or 5), int(rl.get("window_seconds") or 60)):
            return {"status": "error", "error": "rate limited"}

        # Authorization is proven; execution is not implemented. This signed
        # receipt deliberately records that no side effect was dispatched.
        payload_digest = payload_digest or ("sha256:" + hashlib.sha256(
            json.dumps(required, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest())
        receipt = {
            "message_id": message_id or uuid.uuid4().hex,
            "correlation_id": correlation_id or uuid.uuid4().hex,
            "capability_id": cap["id"],
            "issuer": cap.get("issuer"),
            "executor": "plane-authorization-gate-1",
            "action": f"{kind}:{resource}:{method}",
            "resource": resource,
            "method": method,
            "outcome": "authorized_not_executed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload_digest": payload_digest,
            "previous_receipt_digest": previous_receipt_digest,
        }
        receipt["signature"] = sign(receipt)
        return {
            "status": "authorized",
            "result": "not_executed",
            "execution_status": "NOT_IMPLEMENTED",
            "receipt": receipt,
        }
