import json
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


def _rate_limit_config(constraints):
    """Resolve defaults without treating explicit zero as missing.

    A zero count is a valid deny-all policy. A non-positive window is
    invalid and must fail closed rather than becoming the default window.
    """
    rl = (constraints or {}).get("rate_limit") or {}
    try:
        count = int(rl["count"]) if "count" in rl else 5
        window_seconds = int(rl["window_seconds"]) if "window_seconds" in rl else 60
    except (TypeError, ValueError):
        raise ValueError("rate limit count/window must be integers")
    if count < 0 or window_seconds <= 0:
        raise ValueError("rate limit count must be non-negative and window must be positive")
    return count, window_seconds


def _rate_limit_key(capability_id, action_identity):
    return json.dumps(
        [
            capability_id,
            action_identity.get("type"),
            action_identity.get("resource"),
            action_identity.get("method"),
        ],
        sort_keys=True,
        separators=(",", ":"),
    )


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

        action_identity = {
            "type": required.get("type"),
            "resource": required.get("resource"),
            "method": required.get("method"),
        }
        try:
            max_count, window_seconds = _rate_limit_config(cap.get("constraints"))
        except ValueError:
            return {"status": "error", "error": "invalid rate limit constraints"}

        # Rate-limit buckets must use the same full action identity as authorization.
        # Canonical JSON preserves field boundaries even when values contain colons.
        key = _rate_limit_key(cap.get("id"), action_identity)
        if not self.rate_limiter.allow(key, max_count, window_seconds):
            return {"status": "error", "error": "rate limited"}

        # Keep the legacy display label for compatibility, but sign the full tuple too.
        receipt = {
            "capability_id": cap["id"],
            "executor_id": "plane-executor-1",
            "action": f"{action_identity['type']}:{action_identity['resource']}",
            "action_identity": action_identity,
            "outcome": "ok",
            "timestamp": time.time(),
        }
        receipt["signature"] = sign(receipt)
        return {"status": "ok", "result": "executed", "receipt": receipt}
