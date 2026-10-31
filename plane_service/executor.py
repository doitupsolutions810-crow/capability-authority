from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, deque

from plane_service.bounds import check_bounds, load_acceptance
from plane_service.core import verify
from plane_service.crypto_sign import sign, verify_sig


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = ROOT / "data" / "dispatcher"
MAX_ARTIFACT_BYTES = 4096


class RateLimiter:
    def __init__(self):
        self.windows = defaultdict(deque)

    def allow(self, key, max_count, window_seconds):
        now = time.time()
        q = self.windows[key]
        cutoff = now - window_seconds
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= max_count:
            return False
        q.append(now)
        return True


class Executor:
    """Capability verifier plus one fixed-path, bounded artifact dispatcher."""

    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.crl = set()
        self.acceptance = load_acceptance()

    @staticmethod
    def _artifact_path(correlation_id: str) -> Path:
        if not isinstance(correlation_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", correlation_id):
            raise ValueError("correlation_id must contain only letters, digits, dot, underscore, or hyphen")
        return ARTIFACT_DIR / f"{correlation_id}.json"

    @staticmethod
    def _read_existing(path: Path, payload_digest: str):
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            receipt = envelope["receipt"]
            payload = envelope["payload"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RuntimeError("existing artifact is unreadable; refusing overwrite") from exc
        signature = receipt.get("signature")
        unsigned = dict(receipt)
        unsigned.pop("signature", None)
        if not verify_sig(unsigned, signature):
            raise RuntimeError("existing artifact receipt signature is invalid")
        if envelope.get("schema") != "avrone.execution-artifact/v1":
            raise RuntimeError("existing artifact schema is not supported")
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else b""
        actual_result_digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
        if receipt.get("result_digest") != actual_result_digest:
            raise RuntimeError("existing artifact payload digest does not match its receipt")
        if receipt.get("payload_digest") != payload_digest:
            raise RuntimeError("correlation_id already belongs to a different payload")
        return {
            "status": "executed",
            "result": {"artifact_path": str(path.relative_to(ROOT)), "sha256": receipt["result_digest"]},
            "execution_status": "SUCCEEDED",
            "idempotent_replay": True,
            "receipt": receipt,
        }

    def _dispatch_demo_artifact(self, *, cap, required, action_input, message_id,
                                correlation_id, payload_digest, previous_receipt_digest):
        if (required.get("type"), required.get("resource"), required.get("method")) != (
            "Execute", "artifact.write_demo", "POST"
        ):
            return None
        if not isinstance(action_input, dict) or set(action_input) != {"content"}:
            raise ValueError("artifact.write_demo input must contain exactly one field: content")
        content = action_input["content"]
        if not isinstance(content, str):
            raise ValueError("artifact content must be a string")
        data = content.encode("utf-8")
        if not data or len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact content must be 1..{MAX_ARTIFACT_BYTES} UTF-8 bytes")

        path = self._artifact_path(correlation_id)
        if path.exists():
            return self._read_existing(path, payload_digest)

        result_digest = "sha256:" + hashlib.sha256(data).hexdigest()
        receipt = {
            "message_id": message_id,
            "correlation_id": correlation_id,
            "capability_id": cap["id"],
            "issuer": cap.get("issuer"),
            "executor": "plane-allowlisted-dispatcher-1",
            "action": "Execute:artifact.write_demo:POST",
            "resource": "artifact.write_demo",
            "method": "POST",
            "outcome": "succeeded",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload_digest": payload_digest,
            "result_digest": result_digest,
            "result_reference": str(path.relative_to(ROOT)),
            "previous_receipt_digest": previous_receipt_digest,
        }
        receipt["signature"] = sign(receipt)
        envelope = {
            "schema": "avrone.execution-artifact/v1",
            "payload": content,
            "receipt": receipt,
        }
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(dir=ARTIFACT_DIR, prefix=".pending-", delete=False) as tmp:
                temp_name = tmp.name
                tmp.write(encoded)
                tmp.flush()
                os.fsync(tmp.fileno())
            # Hard-link creation is atomic and refuses to replace an existing
            # correlation artifact, providing filesystem-level replay safety.
            try:
                os.link(temp_name, path)
            except FileExistsError:
                return self._read_existing(path, payload_digest)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)

        return {
            "status": "executed",
            "result": {"artifact_path": str(path.relative_to(ROOT)), "sha256": result_digest},
            "execution_status": "SUCCEEDED",
            "idempotent_replay": False,
            "receipt": receipt,
        }

    def execute(self, cap, signature, required, caller, *, action_input=None,
                message_id=None, correlation_id=None, payload_digest=None,
                previous_receipt_digest=None):
        if cap.get("id") in self.crl:
            return {"status": "error", "error": "revoked"}
        if not verify_sig(cap, signature):
            return {"status": "error", "error": "invalid signature"}
        err = check_bounds(cap, self.acceptance)
        if err:
            return {"status": "error", "error": err}
        if not verify(cap, required, caller):
            return {"status": "error", "error": "verify failed"}

        kind = required["type"]
        resource = required["resource"]
        method = required["method"]
        rl = (cap.get("constraints") or {}).get("rate_limit") or {}
        key = f"{cap.get('id')}:{kind}:{resource}:{method}"
        if not self.rate_limiter.allow(key, int(rl.get("count") or 5), int(rl.get("window_seconds") or 60)):
            return {"status": "error", "error": "rate limited"}

        message_id = message_id or uuid.uuid4().hex
        correlation_id = correlation_id or uuid.uuid4().hex
        payload_digest = payload_digest or ("sha256:" + hashlib.sha256(
            json.dumps({"required": required, "input": action_input or {}},
                       sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest())

        if (kind, resource, method) == ("Execute", "artifact.write_demo", "POST"):
            result = self._dispatch_demo_artifact(
                cap=cap, required=required, action_input=action_input,
                message_id=message_id, correlation_id=correlation_id,
                payload_digest=payload_digest,
                previous_receipt_digest=previous_receipt_digest,
            )
            return result

        # Other allowlisted capabilities remain authorization-only until each
        # receives its own reviewed dispatcher and bounded input contract.
        receipt = {
            "message_id": message_id,
            "correlation_id": correlation_id,
            "capability_id": cap["id"],
            "issuer": cap.get("issuer"),
            "executor": "plane-authorization-gate-1",
            "action": f"{kind}:{resource}:{method}",
            "resource": resource,
            "method": method,
            "outcome": "authorized_not_executed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload_digest": payload_digest,
            "previous_receipt_digest": previous_receipt_digest,
        }
        receipt["signature"] = sign(receipt)
        return {
            "status": "authorized",
            "result": "not_executed",
            "execution_status": "NOT_IMPLEMENTED",
            "receipt": receipt,
        }
