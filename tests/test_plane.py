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
    cap = issue("spiffe://prod/agent/dev", "spiffe://prod/broker", [{"type": "read", "resource": "demo", "method": "GET"}], {}, 60, "prod", "dev:unattested", 1)
    try:
        attenuate(cap, [{"type": "Execute", "resource": "tool.echo", "method": "POST"}])
    except ValueError:
        print("PASS no_amplification")
        return
    _fail("amplification was allowed")


def test_method_scoped_verification():
    from plane_service.core import issue, verify
    caller = "spiffe://prod/agent/dev"
    rights = [{"type": "read", "resource": "demo", "method": "GET"}]
    cap = issue(caller, "spiffe://prod/broker", rights, {}, 60, "prod", "dev:unattested", 1)
    assert verify(cap, rights[0], caller)
    assert not verify(cap, {"type": "read", "resource": "demo", "method": "POST"}, caller)
    assert not verify(cap, {"type": "read", "resource": "demo"}, caller)
    assert not verify(cap, {"type": "write", "resource": "demo", "method": "GET"}, caller)
    assert not verify(cap, rights[0], "spiffe://prod/agent/other")
    assert not verify({**cap, "expires_at": 100}, rights[0], caller, now_ts=100)
    assert not verify({**cap, "expires_at": float("nan")}, rights[0], caller)
    print("PASS method_scoped_verification")


def test_issue_sign_execute():
    from plane_service.core import issue, verify
    from plane_service.crypto_sign import sign, verify_sig
    from plane_service.executor import Executor
    from plane_service.policy import PolicyEngine
    caller = "spiffe://prod/agent/dev"
    rights = [{"type": "read", "resource": "demo", "method": "GET"}]
    PolicyEngine().authorize(caller, rights, {}, 60)
    cap = issue(caller, "spiffe://prod/broker", rights, {}, 60, "prod", "dev:unattested", 1)
    sig = sign(cap)
    if not verify_sig(cap, sig) or not verify(cap, rights[0], caller):
        _fail("sig/verify")
    out = Executor().execute(cap, sig, rights[0], caller)
    if out.get("status") != "ok":
        _fail(str(out))
    denied = Executor().execute(cap, sig, {"type": "read", "resource": "demo", "method": "DELETE"}, caller)
    if denied.get("status") == "ok":
        _fail("wrong method executed")
    print("PASS issue_sign_execute")


def test_policy_allowlist_and_bounds():
    from plane_service.policy import PolicyEngine, PolicyError
    policy = PolicyEngine()
    caller = "spiffe://prod/agent/avrone"
    policy.authorize(caller, [{"type": "Execute", "resource": "tool.echo", "method": "POST"}], {}, 60)
    for rights in (
        [{"type": "Execute", "resource": "tool.echo", "method": "GET"}],
        [{"type": "Execute", "resource": "shell", "method": "POST"}],
        [{"type": "Execute", "resource": "docker.sock", "method": "POST"}],
        [{"type": "admin", "resource": "*", "method": "*"}],
        [{"type": "Execute", "resource": "tool.unknown", "method": "POST"}],
        [{"type": "read", "resource": "demo"}],
    ):
        try:
            policy.authorize(caller, rights, {}, 60)
        except PolicyError:
            continue
        _fail(f"unapproved right granted: {rights}")
    for ttl in (0, -1, 301, True, "60"):
        try:
            policy.authorize(caller, [{"type": "read", "resource": "demo", "method": "GET"}], {}, ttl)
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
    test_method_scoped_verification()
    test_issue_sign_execute()
    test_policy_allowlist_and_bounds()
    test_hands_deny()
    test_prod_preflight_fail_closed()
    print("ALL PASS")


if __name__ == "__main__":
    main()
