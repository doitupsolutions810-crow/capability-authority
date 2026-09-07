class PolicyError(Exception):
    pass

class PolicyEngine:
    def __init__(self, max_ttl=300, allowed_prefixes=None):
        self.max_ttl = max_ttl
        self.allowed_prefixes = allowed_prefixes or ["spiffe://prod/agent/", "spiffe://prod/broker/"]
    def authorize(self, caller, rights, constraints, ttl_seconds):
        if not any(caller.startswith(p) for p in self.allowed_prefixes):
            raise PolicyError("caller not allowed by trust domain prefixes")
        if ttl_seconds > self.max_ttl:
            raise PolicyError("TTL exceeds maximum")
