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
        queue = self.windows[key]
        cutoff = now - window_seconds
        while queue and queue[0] <= cutoff:
            queue.popleft()
        if len(queue) >= max_count:
            return False
        queue.append(now)
        return True


def _rate_limit_config(constraints):
    """Resolve defaults while preserving an explicit deny-all count of zero."""
    rate_limit = (constraints or {}).get("rate_limit") or {}
    if not isinstance(rate_limit, dict):
        raise ValueError("rate_limit must be an object")
    try:
        count = int(rate_limit["count"]) if "count" in rate_limit else 5
        window_seconds = int(rate_limit["window_seconds"]) if "window_seconds" in rate_limit else 60
    except (TypeError, ValueError):
        raise ValueError("rate limit count/window must be integers")
    if count < 0 or window_seconds <= 0:
        raise ValueError("rate limit count must be non-negative and window must be positive")
    return count, window_seconds


def _rate_limit_key(capability_id, action_identity):
    # Canonical JSON preserves tuple boundaries even when identifiers contain colons.
    return json.dumps(
        [
            capability_id,
            action_identity.get("type"),
            action_identity.get("resource"),
            action_identity.get("method"),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


class Executor:
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.crl = set()
        self.acceptance = load_acceptance()

    def execute(
        self,
        cap,
        signature,
        required,
        caller,
        *,
        operation_id=None,
        request_digest=None,
    ):
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

        key = _rate_limit_key(cap.get("id"), action_identity)
        if not self.rate_limiter.allow(key, max_count, window_seconds):
            return {"status": "error", "error": "rate limited"}

        # Preserve the legacy display label, but also sign the exact typed action
        # tuple and (when invoked by the idempotency wrapper) the operation binding.
        receipt = {
            "capability_id": cap["id"],
            "executor_id": "plane-executor-1",
            "action": f"{action_identity['type']}:{action_identity['resource']}",
            "action_identity": action_identity,
            "outcome": "ok",
            "timestamp": time.time(),
        }
        if operation_id is not None:
            receipt["operation_id"] = operation_id
        if request_digest is not None:
            receipt["request_digest"] = request_digest
        receipt["signature"] = sign(receipt)
        return {"status": "ok", "result": "executed", "receipt": receipt}
