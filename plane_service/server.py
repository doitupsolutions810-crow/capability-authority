#!/usr/bin/env python3
"""Broker + executor HTTP. Frozen OpenAPI paths only."""
from __future__ import annotations
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from plane_service.bounds import check_bounds, load_acceptance
from plane_service.core import attenuate, issue, verify
from plane_service.crypto_sign import public_key_b64, sign, verify_sig
from plane_service.executor import Executor
from plane_service.policy import PolicyEngine, PolicyError
from plane_service.spiffe_binding import SpiffeBindingError, bind_issue_request
from plane_service.spiffe_identity import identity_summary

TRUST_DOMAIN = os.environ.get("PLANE_TRUST_DOMAIN", "prod")
POLICY_VERSION = int(os.environ.get("PLANE_POLICY_VERSION", "1"))
BROKER_MEASUREMENT = os.environ.get("PLANE_BROKER_MEASUREMENT", "dev:unattested")
ISSUER = f"spiffe://{TRUST_DOMAIN}/broker"
policy = PolicyEngine()
executor = Executor()
acceptance = load_acceptance()

def handle_issue(body):
    try:
        body = bind_issue_request(body)
    except SpiffeBindingError as e:
        return {"status": "error", "error": str(e)}
    caller = body.get("caller") or f"spiffe://{TRUST_DOMAIN}/agent/dev"
    rights = body.get("rights") or []
    ttl = min(int(body.get("ttl_seconds") or 120), 300)
    constraints = dict(body.get("constraints") or {})
    try:
        policy.authorize(caller, rights, constraints, ttl)
    except PolicyError as e:
        return {"status": "error", "error": str(e)}
    cap = issue(caller, ISSUER, rights, constraints, ttl, TRUST_DOMAIN, BROKER_MEASUREMENT, POLICY_VERSION)
    return {"status": "ok", "capability": cap, "signature": sign(cap), "broker_public_key_b64": public_key_b64()}

def handle_attenuate(body):
    cap, sig = body.get("capability") or {}, body.get("signature") or ""
    if not verify_sig(cap, sig):
        return {"status": "error", "error": "invalid signature"}
    try:
        derived = attenuate(cap, body.get("new_rights") or [])
    except ValueError as e:
        return {"status": "error", "error": str(e)}
    return {"status": "ok", "capability": derived, "signature": sign(derived)}

def handle_verify(body):
    cap, sig = body.get("capability") or {}, body.get("signature") or ""
    required = body.get("required") or {}
    caller = body.get("caller") or cap.get("audience") or ""
    if not verify_sig(cap, sig):
        return {"status": "error", "valid": False, "error": "invalid signature"}
    err = check_bounds(cap, acceptance)
    if err:
        return {"status": "error", "valid": False, "error": err}
    ok = verify(cap, required, caller)
    return {"status": "ok" if ok else "error", "valid": ok}

def handle_execute(body):
    cap, sig = body.get("capability") or {}, body.get("signature") or ""
    required = body.get("required") or {}
    caller = body.get("caller") or cap.get("audience") or ""
    return executor.execute(cap, sig, required, caller)

ROUTES = {
    "/v1/capabilities/issue": handle_issue,
    "/v1/capabilities/attenuate": handle_attenuate,
    "/v1/capabilities/verify": handle_verify,
    "/v1/execute": handle_execute,
}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[plane]", self.command, self.path)
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n).decode() or "{}") if n else {}
        fn = ROUTES.get(urlparse(self.path).path)
        if not fn:
            return self._json(404, {"status": "error", "error": "unknown path"})
        try:
            self._json(200, fn(body))
        except Exception as e:
            self._json(500, {"status": "error", "error": str(e)})
    def do_GET(self):
        if urlparse(self.path).path == "/health":
            return self._json(200, {"status": "ok", "service": "broker+executor", "signing": "ed25519", "identity": identity_summary()})
        self._json(404, {"error": "not found"})
    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def main():
    host = os.environ.get("PLANE_HOST", "127.0.0.1")
    port = int(os.environ.get("PLANE_PORT", "8090"))
    print(f"Broker+Executor http://{host}:{port}")
    HTTPServer((host, port), Handler).serve_forever()

if __name__ == "__main__":
    main()
