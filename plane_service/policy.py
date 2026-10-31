"""Server-owned capability policy.

The requester may request rights, but only exact method-scoped entries in
this allowlist can be issued. No methodless or wildcard rights are accepted.
"""
from __future__ import annotations

from typing import Iterable


class PolicyError(Exception):
    pass


DEFAULT_ALLOWED_RIGHTS = frozenset({
    ("read", "demo", "GET"),
    ("Execute", "tool.echo", "POST"),
    ("Execute", "tool.summarize", "POST"),
    ("Execute", "task.run_tests", "POST"),
    ("Execute", "task.build_artifact", "POST"),
    ("Execute", "task.analyze_repository", "POST"),
})


class PolicyEngine:
    def __init__(self, max_ttl=300, allowed_prefixes=None,
                 allowed_rights: Iterable[tuple[str, str, str]] | None = None):
        self.max_ttl = max_ttl
        self.allowed_prefixes = tuple(allowed_prefixes or (
            "spiffe://prod/agent/", "spiffe://prod/broker/"
        ))
        self.allowed_rights = frozenset(
            DEFAULT_ALLOWED_RIGHTS if allowed_rights is None else allowed_rights
        )

    def authorize(self, caller, rights, constraints, ttl_seconds):
        if not isinstance(caller, str) or not caller or not any(
            caller.startswith(prefix) for prefix in self.allowed_prefixes
        ):
            raise PolicyError("caller not allowed by trust domain prefixes")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
            raise PolicyError("TTL must be an integer")
        if ttl_seconds < 1 or ttl_seconds > self.max_ttl:
            raise PolicyError("TTL outside permitted range")
        if not isinstance(rights, list) or not rights:
            raise PolicyError("at least one capability right is required")
        if not isinstance(constraints, dict):
            raise PolicyError("constraints must be an object")

        for right in rights:
            if not isinstance(right, dict):
                raise PolicyError("each capability right must be an object")
            if set(right) != {"type", "resource", "method"}:
                raise PolicyError("capability right requires exactly type, resource, and method")
            kind, resource, method = right.get("type"), right.get("resource"), right.get("method")
            if not all(isinstance(v, str) and v.strip() for v in (kind, resource, method)):
                raise PolicyError("capability type, resource, and method must be non-empty strings")
            if (kind, resource, method) not in self.allowed_rights:
                raise PolicyError(f"right not allowlisted: {kind}:{resource}:{method}")
