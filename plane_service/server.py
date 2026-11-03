#!/usr/bin/env python3
"""Broker + Executor HTTP service. Frozen OpenAPI paths."""
from __future__ import annotations

import hashlib
import json
import uuid
import os
import sys
import time
import stat
import math
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from plane_service.bounds import check_bounds, load_acceptance
from plane_service.core import attenuate, issue, verify
from plane_service.crypto_sign import canonical, public_key_b64, sign, verify_sig
from plane_service.executor import Executor
from plane_service.policy import PolicyEngine, PolicyError
from plane_service.spiffe_binding import SpiffeBindingError, bind_issue_request
from plane_service.delegation import DelegationError, verify_requester_assertion, validate_delegation
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


class EvidencePersistenceError(RuntimeError):
    pass


def _record_evidence(event: dict) -> dict:
    """Publish through AttestPipe and confirm its durable index subscriber stored it.

    Evidence is a prerequisite for returning a successful capability/receipt.
    Missing subscribers, publish failures, or failed read-after-write checks
    therefore fail closed rather than logging and continuing.
    """
    if not isinstance(event, dict) or not isinstance(event.get("message_type"), str):
        raise EvidencePersistenceError("evidence event requires message_type")
    try:
        from evidence.index import get_index
        from attestpipe.bus import BUS
        BUS.publish(event)
        index = get_index()
        rows = index.query(
            capability_id=event.get("capability_id"),
            message_type=event["message_type"],
            correlation_id=event.get("correlation_id"),
            message_id=event.get("message_id"),
            limit=1,
        )
        if not rows:
            raise EvidencePersistenceError("evidence was not confirmed in the durable index")
        return {"durable": True, "replication": "published"}
    except EvidencePersistenceError:
        raise
    except Exception as exc:
        raise EvidencePersistenceError(f"evidence persistence failed: {exc}") from exc


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
    raw_ttl = body.get("ttl_seconds", 120)
    if isinstance(raw_ttl, bool) or not isinstance(raw_ttl, int):
        return {"status": "error", "error": "TTL must be an integer"}
    ttl = min(raw_ttl, 300)
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
    correlation_id = body.get("correlation_id") or uuid.uuid4().hex
    if not isinstance(correlation_id, str) or not correlation_id.strip() or len(correlation_id) > 128:
        return {"status": "error", "error": "correlation_id must be a non-empty string up to 128 characters"}
    issue_message_id = uuid.uuid4().hex
    _record_evidence(
        {
            "message_type": "CapabilityIssued",
            "message_id": issue_message_id,
            "correlation_id": correlation_id,
            "capability_id": cap["id"],
            "audience": cap.get("audience", ""),
            "issuer": cap.get("issuer", ""),
        }
    )
    return {
        "status": "ok",
        "message_id": issue_message_id,
        "correlation_id": correlation_id,
        "capability": cap,
        "signature": sig,
        "platform": os.environ.get("PLANE_PLATFORM", "dev"),
        "broker_public_key_b64": public_key_b64(),
        "_identity_source": body.get("_identity_source"),
    }


def handle_delegate(body: dict) -> dict:
    """Issue an attenuated child capability to an allowlisted workload audience."""
    if not isinstance(body, dict):
        return {"status": "error", "error": "delegation request must be an object"}
    requester = os.environ.get("PLANE_DELEGATION_REQUESTER_ID", "")
    key_file = os.environ.get("PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE", "")
    if not requester or not key_file:
        return {"status": "error", "error": "pinned delegation requester identity and public key are not configured"}
    try:
        key_fd = os.open(key_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            key_stat = os.fstat(key_fd)
            if not stat.S_ISREG(key_stat.st_mode) or key_stat.st_size > 16 * 1024:
                raise OSError("pinned requester public key must be a bounded regular file")
            with os.fdopen(key_fd, "rb") as key_stream:
                key_fd = -1
                requester_public_key = key_stream.read(16 * 1024 + 1)
            if len(requester_public_key) > 16 * 1024:
                raise OSError("pinned requester public key is oversized")
        finally:
            if key_fd >= 0:
                os.close(key_fd)
        assertion = body.get("requester_assertion")
        # Authenticate identity and signature before reconciliation, but defer
        # expiry enforcement until after exact prior-request lookup. This allows
        # only an idempotent read of an existing result after assertion expiry.
        jti = verify_requester_assertion(
            assertion, requester_public_key, expected_issuer=requester,
            expected_audience=ISSUER, allow_expired_for_replay=True,
        )
    except (OSError, DelegationError) as exc:
        return {"status": "error", "error": str(exc)}
    parent = body.get("parent_capability")
    parent_signature = body.get("parent_signature", "")
    if not verify_sig(parent, parent_signature):
        return {"status": "error", "error": "invalid parent capability signature"}
    if parent.get("issuer") != ISSUER:
        return {"status": "error", "error": "parent capability issuer mismatch"}
    if parent.get("audience") != requester:
        return {"status": "error", "error": "parent capability audience must match authenticated requester"}
    audience, rights = body.get("audience"), body.get("rights")
    requested_ttl = body.get("ttl_seconds", 120)
    correlation_id = body.get("correlation_id")
    if not isinstance(correlation_id, str) or not correlation_id.strip() or len(correlation_id) > 128:
        return {"status": "error", "error": "correlation_id is required (1..128 characters)"}
    allowed_audiences = {item.strip() for item in os.environ.get("PLANE_DELEGATION_ALLOWED_AUDIENCES", "").split(",") if item.strip()}
    if not allowed_audiences:
        return {"status": "error", "error": "delegation audience allowlist is not configured"}
    # Reconcile an already-issued correlation before checking parent expiry.
    # A caller retrying after a lost response must receive the exact same child.
    if not isinstance(audience, str) or audience not in allowed_audiences:
        return {"status": "error", "error": "delegated audience is not allowlisted"}
    parent_constraints = parent.get("constraints")
    parent_scope = parent_constraints.get("delegation_audiences") if isinstance(parent_constraints, dict) else None
    if not isinstance(parent_scope, list) or not all(isinstance(item, str) for item in parent_scope) or audience not in parent_scope:
        return {"status": "error", "error": "delegated audience is not authorized by parent constraints"}
    try:
        parent_digest = hashlib.sha256(canonical(parent)).hexdigest()
        request_digest = "sha256:" + hashlib.sha256(canonical({
            "parent_capability_digest": parent_digest, "audience": audience,
            "rights": rights, "ttl_seconds": requested_ttl, "requester": requester,
            # A correlation is idempotent only for the exact same signed requester
            # assertion identity. Otherwise a fresh JTI could receive the prior
            # child without being durably recorded under its own event_id.
            "requester_assertion_jti": jti,
            "requester_assertion_digest": "sha256:" + hashlib.sha256(canonical(assertion)).hexdigest(),
        })).hexdigest()
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        return {"status": "error", "error": "delegation request is not canonical finite JSON"}
    from evidence.index import get_index
    index = get_index()
    prior = index.query(message_type="CapabilityDelegated", correlation_id=correlation_id, limit=1)
    if prior:
        row = prior[0]
        if row.get("request_digest") != request_digest:
            return {"status": "error", "error": "delegation_correlation_replay_conflict"}
        if not isinstance(row.get("capability"), dict) or not isinstance(row.get("signature"), str):
            return {"status": "error", "error": "prior delegation evidence is incomplete"}
        prior_child = row["capability"]
        prior_expiry = prior_child.get("expires_at")
        if isinstance(prior_expiry, bool) or not isinstance(prior_expiry, (int, float)) or not math.isfinite(prior_expiry):
            return {"status": "error", "error": "prior delegated capability expiry is invalid"}
        if prior_expiry <= time.time():
            return {
                "status": "error", "error": "delegated_capability_expired",
                "message_id": row.get("message_id"), "correlation_id": correlation_id,
                "capability_id": prior_child.get("id"), "idempotent_replay": True,
            }
        return {"status": "ok", "message_id": row.get("message_id"), "correlation_id": correlation_id, "capability": prior_child, "signature": row["signature"], "idempotent_replay": True}
    # No prior result exists. An expired assertion must never authorize a
    # first issuance, even when its signature and identity remain authentic.
    try:
        verify_requester_assertion(
            assertion, requester_public_key, expected_issuer=requester,
            expected_audience=ISSUER,
        )
    except DelegationError as exc:
        return {"status": "error", "error": str(exc)}
    if check_bounds(parent, acceptance):
        return {"status": "error", "error": "parent capability bounds rejected"}
    try:
        ttl = validate_delegation(parent, requester=requester, audience=audience, rights=rights, ttl_seconds=requested_ttl, allowed_audiences=allowed_audiences, now_ts=time.time(), max_delegation_depth=int(acceptance.get("max_delegation_depth") or 3))
        parent_depth = parent.get("delegation_depth", 0)
        constraints = parent.get("constraints")
        if not isinstance(constraints, dict):
            raise DelegationError("parent constraints must be an object")
        policy.authorize(audience, rights, constraints, ttl)
    except (DelegationError, PolicyError, TypeError, ValueError) as exc:
        return {"status": "error", "error": str(exc)}
    reused = index.query(message_type="CapabilityDelegated", message_id=jti, limit=1)
    if reused:
        return {"status": "error", "error": "requester assertion replay detected"}
    child = issue(caller=audience, issuer=ISSUER, rights=rights, constraints=constraints, ttl_seconds=ttl, trust_domain=TRUST_DOMAIN, broker_measurement=BROKER_MEASUREMENT, policy_version=POLICY_VERSION)
    child["parent_id"] = parent["id"]
    child["delegation_depth"] = parent_depth + 1
    child_signature = sign(child)
    # The requester assertion JTI is the globally unique issuance identity.
    # Using only correlation_id here would allow the same signed assertion to
    # race under two correlations and mint two children before either query sees
    # the other's evidence. The warehouse's unique event_id index fences that.
    event_id = "delegation:" + hashlib.sha256(jti.encode("ascii")).hexdigest()
    event = {
        "event_id": event_id,
        "message_type": "CapabilityDelegated", "message_id": jti, "correlation_id": correlation_id,
        "request_digest": request_digest, "requester": requester, "audience": audience,
        "parent_capability_id": parent["id"], "capability_id": child["id"],
        "capability": child, "signature": child_signature,
        "delegation_depth": child["delegation_depth"], "expires_at": child["expires_at"],
    }
    try:
        _record_evidence(event)
    except Exception:
        # Resolve a concurrent writer only from durable evidence. A matching
        # correlation returns the exact winning child; a reused JTI under a
        # different correlation is rejected. Storage failures with no committed
        # evidence still propagate and never return an unrecorded capability.
        prior = index.query(message_type="CapabilityDelegated", correlation_id=correlation_id, limit=1)
        if prior:
            row = prior[0]
            if row.get("request_digest") != request_digest:
                return {"status": "error", "error": "delegation_correlation_replay_conflict"}
            if not isinstance(row.get("capability"), dict) or not isinstance(row.get("signature"), str):
                return {"status": "error", "error": "prior delegation evidence is incomplete"}
            prior_child = row["capability"]
            prior_expiry = prior_child.get("expires_at")
            if isinstance(prior_expiry, bool) or not isinstance(prior_expiry, (int, float)) or not math.isfinite(prior_expiry):
                return {"status": "error", "error": "prior delegated capability expiry is invalid"}
            if prior_expiry <= time.time():
                return {
                    "status": "error", "error": "delegated_capability_expired",
                    "message_id": row.get("message_id"), "correlation_id": correlation_id,
                    "capability_id": prior_child.get("id"), "idempotent_replay": True,
                }
            return {"status": "ok", "message_id": row.get("message_id"), "correlation_id": correlation_id,
                    "capability": prior_child, "signature": row["signature"], "idempotent_replay": True}
        reused = index.query(message_type="CapabilityDelegated", message_id=jti, limit=1)
        if reused:
            return {"status": "error", "error": "requester assertion replay detected"}
        raise
    return {"status": "ok", "message_id": jti, "correlation_id": correlation_id, "capability": child, "signature": child_signature, "idempotent_replay": False}


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
    action_input = body.get("input") or {}
    caller = body.get("caller") or cap.get("audience") or ""
    correlation_id = body.get("correlation_id")
    if not isinstance(correlation_id, str) or not correlation_id.strip() or len(correlation_id) > 128:
        return {"status": "error", "error": "correlation_id is required (1..128 characters)"}
    if not isinstance(action_input, dict):
        return {"status": "error", "error": "input must be an object"}

    if not verify_sig(cap, sig):
        return {"status": "error", "error": "invalid signature"}
    if check_bounds(cap, acceptance):
        return {"status": "error", "error": "capability bounds rejected"}
    if not verify(cap, required, caller):
        return {"status": "error", "error": "verify failed"}


    from evidence.index import get_index
    index = get_index()
    prior = index.query(
        message_type="AuthorizationReceipt",
        correlation_id=correlation_id,
        limit=1,
    )
    action = f"{required.get('type')}:{required.get('resource')}:{required.get('method')}"
    payload_bytes = canonical({"required": required, "input": action_input})
    payload_digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    if prior:
        prior_receipt = prior[0].get("receipt") or {}
        if (prior_receipt.get("action") != action or prior_receipt.get("capability_id") != cap.get("id") or prior_receipt.get("payload_digest") != payload_digest):
            return {"status": "error", "error": "correlation_id_replay_conflict"}
        executed = prior_receipt.get("outcome") == "succeeded"
        return {
            "status": "executed" if executed else "authorized",
            "result": prior[0].get("result") if executed else "not_executed",
            "execution_status": "SUCCEEDED" if executed else "NOT_IMPLEMENTED",
            "idempotent_replay": True,
            "receipt": prior_receipt,
        }

    message_id = uuid.uuid4().hex
    previous_receipt_digest = None
    prior_receipts = index.query(
        capability_id=cap.get("id"),
        message_type="AuthorizationReceipt",
        limit=1,
    )
    if prior_receipts:
        previous = prior_receipts[0].get("receipt") or {}
        if previous:
            previous_receipt_digest = "sha256:" + hashlib.sha256(canonical(previous)).hexdigest()

    result = executor.execute(
        cap, sig, required, caller,
        message_id=message_id,
        correlation_id=correlation_id,
        action_input=action_input,
        payload_digest=payload_digest,
        previous_receipt_digest=previous_receipt_digest,
    )
    if result.get("status") in ("authorized", "executed"):
        receipt = result.get("receipt") or {}
        _record_evidence(
            {
                "message_type": "AuthorizationReceipt",
                "message_id": receipt.get("message_id", message_id),
                "correlation_id": correlation_id,
                "capability_id": cap.get("id", ""),
                "action": receipt.get("action", ""),
                "outcome": receipt.get("outcome", ""),
                "result": result.get("result"),
                "receipt": receipt,
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
    "/v1/capabilities/delegate": handle_delegate,
    "/v1/capabilities/attenuate": handle_attenuate,
    "/v1/capabilities/verify": handle_verify,
    "/v1/execute": handle_execute,
    "/v1/agents/mount": handle_agent_mount,
    "/v1/agents/spawn": handle_agent_spawn,
    "/v1/agents/list": handle_agent_list,
}


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError("non-finite JSON constant is forbidden: " + value)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[broker+executor] {self.command} {self.path} " + (fmt % args))

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in ROUTES:
            self._json(404, {"status": "error", "error": "unknown path"})
            return
        if self.headers.get("Transfer-Encoding"):
            self._json(501, {"status": "error", "error": "transfer-encoded request bodies are unsupported"})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError, OverflowError):
            self._json(400, {"status": "error", "error": "invalid Content-Length"})
            return
        if n < 0:
            self._json(400, {"status": "error", "error": "invalid Content-Length"})
            return
        if n > 65536:
            self._json(413, {"status": "error", "error": "request body exceeds 64 KiB"})
            return
        raw = self.rfile.read(n) if n else b"{}"
        if len(raw) != n:
            self._json(400, {"status": "error", "error": "incomplete request body"})
            return
        try:
            body = json.loads(
                raw.decode("utf-8") or "{}",
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            self._json(400, {"status": "error", "error": "malformed, duplicate-key, or non-finite JSON request body"})
            return
        if not isinstance(body, dict):
            self._json(400, {"status": "error", "error": "request body must be a JSON object"})
            return
        try:
            self._json(200, ROUTES[path](body))
        except Exception:
            self._json(500, {"status": "error", "error": "internal server error"})

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
                correlation_id=(q.get("correlation_id") or [None])[0],
                message_id=(q.get("message_id") or [None])[0],
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
