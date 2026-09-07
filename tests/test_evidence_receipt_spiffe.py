#!/usr/bin/env python3
import json, os, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

def _fail(msg):
    print("FAIL", msg)
    raise SystemExit(1)

def test_evidence_index_and_query():
    from evidence.index import EvidenceIndex
    idx = EvidenceIndex(path=ROOT / "data" / "evidence_index_test.json")
    idx._docs = []
    idx.ingest({"message_type": "CapabilityIssued", "capability_id": "cap-test-1", "audience": "spiffe://prod/agent/dev"})
    if not idx.query(capability_id="cap-test-1"):
        _fail("empty")
    print("PASS evidence_index")

def test_receipt_verify_cli():
    from plane_service.core import issue
    from plane_service.crypto_sign import sign
    from plane_service.executor import Executor
    caller = "spiffe://prod/agent/dev"
    rights = [{"type": "read", "resource": "demo"}]
    cap = issue(caller, "spiffe://prod/broker", rights, {}, 60, "prod", "dev:unattested", 1)
    out = Executor().execute(cap, sign(cap), rights[0], caller)
    if out.get("status") != "ok":
        _fail(str(out))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"receipt": out["receipt"]}, f)
        path = f.name
    proc = subprocess.run([sys.executable, str(ROOT / "tools" / "receipt_verify.py"), "--file", path], capture_output=True, text=True)
    if proc.returncode != 0:
        _fail(proc.stdout + proc.stderr)
    if not json.loads(proc.stdout).get("ok"):
        _fail(proc.stdout)
    print("PASS receipt_verify_cli")

def test_spire_fail_closed_without_agent():
    os.environ["SPIFFE_REQUIRED"] = "1"
    for k in ("SPIFFE_ENDPOINT_SOCKET", "PLANE_SPIFFE_ID", "PRODUCTION", "PLANE_PRODUCTION"):
        os.environ.pop(k, None)
    from plane_service.spiffe_binding import SpiffeBindingError, bind_issue_request
    try:
        bind_issue_request({"caller": "spiffe://prod/agent/dev"})
    except SpiffeBindingError:
        print("PASS spire_fail_closed")
        os.environ.pop("SPIFFE_REQUIRED", None)
        return
    os.environ.pop("SPIFFE_REQUIRED", None)
    _fail("should fail closed")

def test_spire_lab_fallback_when_not_required():
    for k in ("SPIFFE_REQUIRED", "PRODUCTION", "PLANE_PRODUCTION", "SPIFFE_ENDPOINT_SOCKET", "PLANE_SPIFFE_ID"):
        os.environ.pop(k, None)
    from plane_service.spiffe_identity import fetch_workload_identity
    ident = fetch_workload_identity()
    if ident.source != "fallback":
        _fail(ident.source)
    print("PASS spire_lab_fallback")

def main():
    test_evidence_index_and_query()
    test_receipt_verify_cli()
    test_spire_fail_closed_without_agent()
    test_spire_lab_fallback_when_not_required()
    print("ALL PASS evidence/receipt/spiffe")

if __name__ == "__main__":
    main()
