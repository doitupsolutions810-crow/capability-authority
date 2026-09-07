#!/usr/bin/env python3
"""Broker + Executor HTTP service. Frozen OpenAPI paths."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from plane_service.bounds import check_bounds, load_acceptance
from plane_service.core import attenuate, issue, verify
from plane_service.crypto_sign import public_key_b64, sign, verify_sig
from plane_service.executor import Executor
from plane_service.policy import PolicyEngine, PolicyError
from plane_service.spiffe_binding import SpiffeBindingError, bind_issue_request
from plane_service.spiffe_identity import fetch_workload_identity

TRUST_DOMAIN = os.environ.get("PLANE_TRUST_DOMAIN", "prod")
POLICY_VERSION = int(os.environ.get("PLANE_POLICY_VERSION", "1"))
BROKER_MEASUREMENT = os.environ.get("PLANE_BROKER_MEASUREMENT", "dev:unattested")
ISSUER = f"spiffe://{TRUST_DOMAIN}/broker"

policy = PolicyEngine()
executor = Executor()
acceptance = load_acceptance()

try:
    from evidence.index import attach_to_attestpipe
    attach_to_attestpipe()
except Exception as e:
    print(f"[evidence-index] startup skip: {e}")

try:
    from rings.production_profile import is_production, preflight
    _pf = preflight()
    print(f"[preflight] production={_pf.production} ok={_pf.ok}")
    if is_production() and not _pf.ok:
        raise SystemExit("production preflight failed — refuse to start")
except SystemExit:
    raise
except Exception as e:
    print(f"[preflight] skip: {e}")


def _record_evidence(event: dict) -> None:
    try:
        from evidence.index import get_index
        get_index().ingest(event)
    except Exception as e:
        print(f"[evidence] ingest skipped: {e}")
    try:
        from attestpipe.bus import BUS
        BUS.publish(event)
    except Exception as e:
        print(f"[attestpipe] publish skipped: {e}")


def _bus_publish(msg) -> None:
    if isinstance(msg, dict):
        _record_evidence(msg)
        return
    try:
        from dataclasses import asdict
        _record_evidence(asdict(msg))
    except Exception:
        _record_evidence({"message_type": type(msg).__name__, "raw": str(msg)})


def handle_issue(body: dict) -> dict:
    try:
        body = bind_issue_request(body)
    except SpiffeBindingError as e:
        return {"status": "error", "error": str(e)}
    identity = fetch_workload_identity(trust_domain_cfg=TRUST_DOMAIN)
    caller = body.get("caller") or identity.spiffe_id
    rights = body.get("rights") or []
    ttl = min(int(body.get("ttl_seconds") or 120), 300)
    constraints = dict(body.get("constraints") or {})
    try:
        policy.authorize(caller, rights, constraints, ttl)
    except PolicyError as e:
        return {"status": "error", "error": str(e)}
    cap = issue(
        caller=caller,
        issuer=ISSUER,
        rights=rights,
        constraints=constraints,
        ttl_seconds=ttl,
        trust_domain=TRUST_DOMAIN,
        broker_measurement=BROKER_MEASUREMENT,
        policy_version=POLICY_VERSION,
    )
    sig = sign(cap)
    _record_evidence(
        {
            "message_type": "CapabilityIssued",
            "capability_id": cap["id"],
            "audience": cap.get("audience", ""),
            "issuer": cap.get("issuer", ""),
        }
    )
    return {
        "status": "ok",
        "capability": cap,
        "signature": sig,
        "platform": os.environ.get("PLANE_PLATFORM", "dev"),
        "broker_public_key_b64": public_key_b64(),
        "_identity_source": body.get("_identity_source"),
    }


def handle_attenuate(body: dict) -> dict:
    cap = body.get("capability") or {}
    sig = body.get("signature") or ""
    if not verify_sig(cap, sig):
        return {"status": "error", "error": "invalid signature"}
    try:
        derived = attenuate(cap, body.get("new_rights") or [])
    except ValueError as e:
        return {"status": "error", "error": str(e)}
    return {"status": "ok", "capability": derived, "signature": sign(derived)}


def handle_verify(body: dict) -> dict:
    cap = body.get("capability") or {}
    sig = body.get("signature") or ""
    required = body.get("required") or {}
    caller = body.get("caller") or cap.get("audience") or ""
    if not verify_sig(cap, sig):
        return {"status": "error", "valid": False, "error": "invalid signature"}
    err = check_bounds(cap, acceptance)
    if err:
        return {"status": "error", "valid": False, "error": err}
    ok = verify(cap, required, caller)
    return {"status": "ok" if ok else "error", "valid": ok}


def handle_execute(body: dict) -> dict:
    cap = body.get("capability") or {}
    sig = body.get("signature") or ""
    required = body.get("required") or {}
    caller = body.get("caller") or cap.get("audience") or ""
    result = executor.execute(cap, sig, required, caller)
    if result.get("status") == "ok":
        receipt = result.get("receipt") or {}
        _record_evidence(
            {
                "message_type": "ExecuteReceipt",
                "capability_id": cap.get("id", ""),
                "action": receipt.get("action", ""),
                "outcome": receipt.get("outcome", ""),
            }
        )
    return result


def handle_agent_mount(body: dict) -> dict:
    from agents.runtime import mount_agent
    return mount_agent(
        name=str(body.get("name") or "parent"),
        rights=body.get("rights"),
        ttl_seconds=int(body.get("ttl_seconds") or 120),
        constraints=body.get("constraints"),
        caller=body.get("caller"),
    )


def handle_agent_spawn(body: dict) -> dict:
    from agents.spawn import spawn_subagent
    parent = body.get("parent_agent_id") or body.get("agent_id")
    if not parent:
        return {"status": "denied", "error": "parent_agent_id required"}
    return spawn_subagent(
        parent_agent_id=str(parent),
        name=str(body.get("name") or "child"),
        rights=body.get("rights"),
    )


def handle_agent_list(_body: dict) -> dict:
    from agents.runtime import REGISTRY
    rows = [
        {
            "agent_id": h.agent_id,
            "spiffe_id": h.spiffe_id,
            "role": h.role,
            "parent_id": h.parent_id,
            "children": list(h.children),
            "capability_id": h.capability.get("id"),
        }
        for h in REGISTRY.list()
    ]
    return {"status": "ok", "count": len(rows), "agents": rows}


ROUTES = {
    "/v1/capabilities/issue": handle_issue,
    "/v1/capabilities/attenuate": handle_attenuate,
    "/v1/capabilities/verify": handle_verify,
    "/v1/execute": handle_execute,
    "/v1/agents/mount": handle_agent_mount,
    "/v1/agents/spawn": handle_agent_spawn,
    "/v1/agents/list": handle_agent_list,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[broker+executor] {self.command} {self.path} " + (fmt % args))

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode() or "{}")
            fn = ROUTES.get(path)
            if not fn:
                self._json(404, {"status": "error", "error": "unknown path"})
                return
            self._json(200, fn(body))
        except Exception as e:
            self._json(500, {"status": "error", "error": str(e)})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            ident = {}
            try:
                from plane_service.spiffe_identity import identity_summary
                ident = identity_summary()
            except Exception:
                pass
            self._json(
                200,
                {
                    "status": "ok",
                    "service": "broker+executor",
                    "trust_domain": TRUST_DOMAIN,
                    "policy_version": POLICY_VERSION,
                    "signing": "ed25519",
                    "broker_public_key_b64": public_key_b64(),
                    "identity": ident,
                },
            )
            return
        if path == "/v1/identity":
            from plane_service.spiffe_identity import identity_summary
            self._json(200, identity_summary())
            return
        if path in ("/v1/agents", "/v1/agents/list"):
            self._json(200, handle_agent_list({}))
            return
        if path == "/v1/evidence":
            from evidence.index import get_index
            q = parse_qs(parsed.query)
            idx = get_index()
            if q.get("stats"):
                self._json(200, idx.stats())
                return
            rows = idx.query(
                capability_id=(q.get("capability_id") or [None])[0],
                request_id=(q.get("request_id") or [None])[0],
                actor=(q.get("actor") or [None])[0],
                message_type=(q.get("message_type") or [None])[0],
                limit=int((q.get("limit") or ["20"])[0]),
            )
            self._json(200, {"count": len(rows), "results": rows})
            return
        self._json(404, {"status": "error", "error": "not found"})

    def _json(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    host = os.environ.get("PLANE_HOST", "127.0.0.1")
    port = int(os.environ.get("PLANE_PORT", "8090"))
    httpd = HTTPServer((host, port), Handler)
    print(f"Broker+Executor on http://{host}:{port} (ed25519)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
