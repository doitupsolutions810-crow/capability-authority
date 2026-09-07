from pathlib import Path
from typing import Any

def load_acceptance(path="config/acceptance_policy.yaml"):
    return {
        "expected_trust_domain": "prod",
        "allowed_policy_versions": [1, 2, 3, 4, 5],
        "max_delegation_depth": 3,
    }

def check_bounds(cap, acceptance):
    if cap.get("trust_domain") != acceptance.get("expected_trust_domain", "prod"):
        return "trust domain mismatch"
    allowed = acceptance.get("allowed_policy_versions") or []
    if allowed and int(cap.get("policy_version") or -1) not in allowed:
        return "policy_version not allowed"
    if int(cap.get("delegation_depth") or 0) > int(acceptance.get("max_delegation_depth") or 3):
        return "delegation_depth exceeded"
    return None
