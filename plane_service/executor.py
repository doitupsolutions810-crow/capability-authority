import time
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
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.crl = set()
        self.acceptance = load_acceptance()

    def execute(self, cap, signature, required, caller):
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

        # This receipt records the exact authorization tuple. It is not by
        # itself a cross-system history-chain receipt; a durable receipt
        # service must add correlation, payload digest, and chain ancestry.
        receipt = {
            "capability_id": cap["id"],
            "issuer": cap.get("issuer"),
            "audience": caller,
            "executor_id": "plane-executor-1",
            "action": f"{kind}:{resource}:{method}",
            "resource": resource,
            "method": method,
            "outcome": "ok",
            "timestamp": time.time(),
        }
        receipt["signature"] = sign(receipt)
        return {"status": "ok", "result": "executed", "receipt": receipt}
