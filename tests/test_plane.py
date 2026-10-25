#!/usr/bin/env python3
import json, os, sys
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
    if verify(cap, {"type": "read", "resource": "demo", "method": "DELETE"}, caller):
        _fail("method mismatch was authorized")
    out = Executor().execute(cap, sig, rights[0], caller)
    if out.get("status") != "ok":
        _fail(str(out))
    print("PASS issue_sign_execute_and_method_binding")

def test_hands_deny():
    from rings.hands import route
    for h in ("shell", "kubectl", "cloud_key", "hold_bypass"):
        if route(h).get("status") != "denied":
            _fail(h)
    print("PASS hands_deny")

def test_prod_preflight_fail_closed():
    from unittest.mock import patch
    from rings.production_profile import preflight
    with patch.dict(os.environ, {
        "PRODUCTION": "1",
        "PLANE_BROKER_MEASUREMENT": "dev:unattested",
    }, clear=True):
        if preflight().ok:
            _fail("should fail closed without Workload API identity")
    print("PASS prod_preflight_fail_closed")

def test_prod_preflight_uses_resolved_spiffe_source():
    from unittest.mock import patch
    from plane_service.spiffe_identity import WorkloadIdentity
    from rings.production_profile import preflight

    with patch.dict(os.environ, {
        "PRODUCTION": "1",
        "PLANE_BROKER_MEASUREMENT": "sha256:verified",
    }, clear=True):
        with patch(
            "plane_service.spiffe_identity.fetch_workload_identity",
            return_value=WorkloadIdentity(
                "spiffe://prod/agent/test", "prod", "workload-api", True
            ),
        ):
            report = preflight()
            if not report.ok:
                _fail("valid workload-api identity rejected: " + str(report.as_dict()))
            print("PASS prod_preflight_accepts_workload_api_identity")

        with patch(
            "plane_service.spiffe_identity.fetch_workload_identity",
            return_value=WorkloadIdentity(
                "spiffe://prod/agent/test", "prod", "env", False
            ),
        ):
            report = preflight()
            if report.ok:
                _fail("environment identity incorrectly accepted as production SPIFFE")
            print("PASS prod_preflight_rejects_env_identity")

def test_policy_enforces_rights_allowlist():
    from unittest.mock import patch
    from plane_service.policy import PolicyEngine, PolicyError
    caller = "spiffe://prod/agent/test"
    with patch.dict(os.environ, {"PRODUCTION": "0"}, clear=True):
        policy = PolicyEngine()
        policy.authorize(caller, [{"type": "read", "resource": "demo"}], {}, 60)
        try:
            policy.authorize(caller, [{"type": "admin", "resource": "prod-secrets"}], {}, 60)
        except PolicyError:
            print("PASS policy_denies_unlisted_lab_right")
        else:
            _fail("unlisted right was authorized")

    with patch.dict(os.environ, {"PRODUCTION": "1"}, clear=True):
        policy = PolicyEngine()
        try:
            policy.authorize(caller, [{"type": "read", "resource": "demo"}], {}, 60)
        except PolicyError:
            print("PASS production_requires_explicit_rights_policy")
        else:
            _fail("production accepted demo defaults without explicit policy")

    allowed = json.dumps([{"type": "write", "resource": "orders", "method": "POST"}])
    with patch.dict(os.environ, {"PRODUCTION": "1", "PLANE_ALLOWED_RIGHTS": allowed}, clear=True):
        policy = PolicyEngine()
        policy.authorize(caller, [{"type": "write", "resource": "orders", "method": "POST"}], {}, 60)
        try:
            policy.authorize(caller, [{"type": "write", "resource": "orders", "method": "DELETE"}], {}, 60)
        except PolicyError:
            print("PASS policy_binds_allowlist_to_method")
        else:
            _fail("method outside allowlist was authorized")

def main():
    test_no_amplification()
    test_issue_sign_execute()
    test_hands_deny()
    test_prod_preflight_fail_closed()
    test_prod_preflight_uses_resolved_spiffe_source()
    test_policy_enforces_rights_allowlist()
    print("ALL PASS")

if __name__ == "__main__":
    main()
