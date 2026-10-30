#!/usr/bin/env python3
import os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

def _fail(msg):
    print("FAIL", msg)
    raise SystemExit(1)

def test_no_amplification():
    from plane_service.core import issue, attenuate
    cap = issue("spiffe://prod/agent/dev", "spiffe://prod/broker", [{"type": "read", "resource": "demo"}], {}, 60, "prod", "dev:unattested", 1)
    try:
        attenuate(cap, [{"type": "Execute", "resource": "tool.echo"}])
    except ValueError:
        print("PASS no_amplification")
        return
    _fail("amplification was allowed")

def test_issue_sign_execute():
    from plane_service.core import issue, verify
    from plane_service.crypto_sign import sign, verify_sig
    from plane_service.executor import Executor
    from plane_service.policy import PolicyEngine
    caller = "spiffe://prod/agent/dev"
    rights = [{"type": "read", "resource": "demo"}]
    PolicyEngine().authorize(caller, rights, {}, 60)
    cap = issue(caller, "spiffe://prod/broker", rights, {}, 60, "prod", "dev:unattested", 1)
    sig = sign(cap)
    if not verify_sig(cap, sig) or not verify(cap, rights[0], caller):
        _fail("sig/verify")
    out = Executor().execute(cap, sig, rights[0], caller)
    if out.get("status") != "ok":
        _fail(str(out))
    print("PASS issue_sign_execute")

def test_policy_allowlist_and_bounds():
    from plane_service.policy import PolicyEngine, PolicyError
    policy = PolicyEngine()
    caller = "spiffe://prod/agent/avrone"
    policy.authorize(caller, [{"type": "Execute", "resource": "tool.echo"}], {}, 60)
    for rights in (
        [{"type": "Execute", "resource": "shell"}],
        [{"type": "Execute", "resource": "docker.sock"}],
        [{"type": "admin", "resource": "*"}],
        [{"type": "Execute", "resource": "tool.unknown"}],
    ):
        try:
            policy.authorize(caller, rights, {}, 60)
        except PolicyError:
            continue
        _fail(f"unapproved right granted: {rights}")
    for ttl in (0, -1, 301, True, "60"):
        try:
            policy.authorize(caller, [{"type": "read", "resource": "demo"}], {}, ttl)
        except PolicyError:
            continue
        _fail(f"invalid TTL accepted: {ttl}")
    print("PASS policy_allowlist_and_bounds")


def test_hands_deny():
    from rings.hands import route
    for h in ("shell", "kubectl", "cloud_key", "hold_bypass"):
        if route(h).get("status") != "denied":
            _fail(h)
    print("PASS hands_deny")

def test_prod_preflight_fail_closed():
    os.environ["PRODUCTION"] = "1"
    os.environ.pop("PLANE_SPIFFE_ID", None)
    os.environ.pop("SPIFFE_ENDPOINT_SOCKET", None)
    os.environ["PLANE_BROKER_MEASUREMENT"] = "dev:unattested"
    from rings.production_profile import preflight
    if preflight().ok:
        _fail("should fail closed")
    print("PASS prod_preflight_fail_closed")

def main():
    test_no_amplification()
    test_issue_sign_execute()
    test_policy_allowlist_and_bounds()
    test_hands_deny()
    test_prod_preflight_fail_closed()
    print("ALL PASS")

if __name__ == "__main__":
    main()
