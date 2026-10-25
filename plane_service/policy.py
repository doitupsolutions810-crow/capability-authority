"""Least-privilege policy checks for capability issuance."""
import json
import os


class PolicyError(Exception):
    pass


class PolicyEngine:
    # Small lab-only defaults. Production must provide an explicit policy.
    _LAB_ALLOWED_RIGHTS = frozenset({
        ("read", "demo", None),
        ("Execute", "tool.echo", None),
    })

    def __init__(self, max_ttl=300, allowed_prefixes=None, allowed_rights=None):
        self.max_ttl = max_ttl
        self.allowed_prefixes = (
            allowed_prefixes
            if allowed_prefixes is not None
            else ["spiffe://prod/agent/", "spiffe://prod/broker/"]
        )
        self.allowed_rights = self._resolve_allowed_rights(allowed_rights)

    @classmethod
    def _resolve_allowed_rights(cls, explicit):
        if explicit is not None:
            return cls._normalize_rights(explicit)

        raw = os.environ.get("PLANE_ALLOWED_RIGHTS")
        if raw is not None:
            try:
                parsed = json.loads(raw)
            except (TypeError, ValueError) as exc:
                raise PolicyError("PLANE_ALLOWED_RIGHTS must be valid JSON") from exc
            if not isinstance(parsed, list):
                raise PolicyError("PLANE_ALLOWED_RIGHTS must be a JSON array")
            return cls._normalize_rights(parsed)

        production = (
            os.environ.get("PRODUCTION", "0") == "1"
            or os.environ.get("PLANE_PRODUCTION", "0") == "1"
        )
        return frozenset() if production else cls._LAB_ALLOWED_RIGHTS

    @staticmethod
    def _normalize_rights(rights):
        normalized = set()
        if isinstance(rights, (set, frozenset, tuple)):
            for item in rights:
                if not isinstance(item, (tuple, list)) or len(item) != 3:
                    raise PolicyError("allowed rights entries must be (type, resource, method) tuples")
                right_type, resource, method = item
                if not isinstance(right_type, str) or not right_type or not isinstance(resource, str) or not resource:
                    raise PolicyError("allowed right type and resource must be non-empty strings")
                if method is not None and (not isinstance(method, str) or not method):
                    raise PolicyError("allowed right method must be a non-empty string or null")
                normalized.add((right_type, resource, method))
            return frozenset(normalized)

        if not isinstance(rights, list):
            raise PolicyError("allowed rights must be a list")
        for item in rights:
            if not isinstance(item, dict):
                raise PolicyError("allowed rights entries must be objects")
            right_type = item.get("type")
            resource = item.get("resource")
            method = item.get("method")
            if not isinstance(right_type, str) or not right_type or not isinstance(resource, str) or not resource:
                raise PolicyError("allowed right type and resource must be non-empty strings")
            if method is not None and (not isinstance(method, str) or not method):
                raise PolicyError("allowed right method must be a non-empty string or null")
            normalized.add((right_type, resource, method))
        return frozenset(normalized)

    def authorize(self, caller, rights, constraints, ttl_seconds):
        if not isinstance(caller, str) or not any(caller.startswith(p) for p in self.allowed_prefixes):
            raise PolicyError("caller not allowed by trust domain prefixes")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise PolicyError("TTL must be a positive integer")
        if ttl_seconds > self.max_ttl:
            raise PolicyError("TTL exceeds maximum")
        if not isinstance(constraints, dict):
            raise PolicyError("constraints must be an object")
        if not isinstance(rights, list) or not rights:
            raise PolicyError("at least one right is required")
        for right in rights:
            if not isinstance(right, dict):
                raise PolicyError("each right must be an object")
            right_type = right.get("type")
            resource = right.get("resource")
            method = right.get("method")
            if not isinstance(right_type, str) or not right_type or not isinstance(resource, str) or not resource:
                raise PolicyError("right type and resource must be non-empty strings")
            if method is not None and (not isinstance(method, str) or not method):
                raise PolicyError("right method must be a non-empty string or null")
            if (right_type, resource, method) not in self.allowed_rights:
                raise PolicyError(f"right not allowed by policy: {(right_type, resource, method)}")
