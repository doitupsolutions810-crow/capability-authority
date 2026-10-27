"""Fail-closed idempotency contract for side-effecting execution requests.

Success is returned only after the ExecuteReceipt can be read back from the
verified evidence index. A retry with the same operation_id never re-runs an
in-progress/indeterminate operation. It can only replay a completed result or
reconcile a previously recorded receipt.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

_OPERATION_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")



def execution_http_status(result: dict[str, Any]) -> int:
    """Map operation uncertainty to an HTTP status without laundering success."""
    if result.get("status") == "indeterminate":
        return 202
    error = result.get("error")
    if error in {
        "operation_id_required",
        "operation_request_not_canonicalizable",
        "idempotency_key_mismatch",
    }:
        return 400
    if error == "operation_id_payload_conflict":
        return 409
    if error in {
        "operation_ledger_unavailable",
        "execution_intent_not_durable",
    }:
        return 503
    return 200


def _request_digest(body: dict[str, Any]) -> str:
    payload = {key: value for key, value in body.items() if key != "operation_id"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _indeterminate(operation_id: str, reason: str, *, audit_status: str = "unknown") -> dict[str, Any]:
    return {
        "status": "indeterminate",
        "audit_status": audit_status,
        "operation_id": operation_id,
        "error": reason,
        "retry_safe": False,
    }


def execute_with_idempotency(
    body: dict[str, Any],
    *,
    executor: Callable[[dict, str, dict, str], dict],
    record_evidence: Callable[[dict], Any],
    query_receipts: Callable[[str], list[dict[str, Any]]],
    query_intents: Callable[[str], list[dict[str, Any]]],
    ledger,
) -> dict[str, Any]:
    """Execute once per operation ID and require durable receipt read-back."""
    operation_id = body.get("operation_id") if isinstance(body, dict) else None
    if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
        return {
            "status": "error",
            "error": "operation_id_required",
            "message": "Provide a stable Idempotency-Key header or operation_id before execution.",
        }

    try:
        request_digest = _request_digest(body)
    except (TypeError, ValueError):
        return {"status": "error", "error": "operation_request_not_canonicalizable"}

    try:
        claim = ledger.claim(operation_id, request_digest)
    except Exception:
        return {
            "status": "error",
            "error": "operation_ledger_unavailable",
            "operation_id": operation_id,
            "retry_safe": False,
        }

    if claim.get("state") == "conflict":
        return {
            "status": "error",
            "error": "operation_id_payload_conflict",
            "operation_id": operation_id,
            "retry_safe": False,
        }
    if claim.get("state") == "completed" and isinstance(claim.get("result"), dict):
        # The operation row is a recovery index, not a substitute for the
        # durable evidence ledger. Revalidate the receipt on every replay.
        try:
            saved_receipts = query_receipts(operation_id)
        except Exception:
            return _indeterminate(operation_id, "completed_receipt_verification_unavailable")
        expected_event_id = f"execute-operation.{operation_id}.receipt"
        saved_result = claim["result"]
        receipt_is_durable = any(
            event.get("event_id") == expected_event_id
            and event.get("operation_id") == operation_id
            and event.get("request_id") == operation_id
            and event.get("request_digest") == request_digest
            and event.get("result") == saved_result
            for event in saved_receipts
        )
        if not receipt_is_durable:
            try:
                ledger.mark_indeterminate(operation_id, request_digest)
            except Exception:
                pass
            return _indeterminate(operation_id, "completed_receipt_missing_or_mismatched")
        return {**saved_result, "replayed": True}
    if claim.get("state") != "claimed":
        # A previous process may have persisted the receipt but crashed before
        # updating the operation row. Read back evidence before deciding.
        try:
            receipts = query_receipts(operation_id)
        except Exception:
            return _indeterminate(operation_id, "receipt_reconciliation_unavailable")
        expected_event_id = f"execute-operation.{operation_id}.receipt"
        for receipt_event in receipts:
            if receipt_event.get("request_digest") != request_digest:
                return {
                    "status": "error",
                    "error": "operation_id_payload_conflict",
                    "operation_id": operation_id,
                    "retry_safe": False,
                }
            if (
                receipt_event.get("event_id") != expected_event_id
                or receipt_event.get("operation_id") != operation_id
                or receipt_event.get("request_id") != operation_id
            ):
                continue
            saved_result = receipt_event.get("result")
            if isinstance(saved_result, dict):
                durable_result = {
                    **saved_result,
                    "operation_id": operation_id,
                    "audit_status": "durable",
                }
                try:
                    ledger.complete(operation_id, request_digest, durable_result)
                except Exception:
                    return _indeterminate(
                        operation_id,
                        "receipt_is_durable_but_operation_state_reconciliation_failed",
                        audit_status="durable",
                    )
                return {**durable_result, "replayed": True}
        return _indeterminate(operation_id, "prior_operation_outcome_unconfirmed")

    capability = body.get("capability") or {}
    signature = body.get("signature") or ""
    required = body.get("required") or {}
    caller = body.get("caller") or capability.get("audience") or ""
    capability_id = capability.get("id", "") if isinstance(capability, dict) else ""
    action = {
        "type": required.get("type") if isinstance(required, dict) else None,
        "resource": required.get("resource") if isinstance(required, dict) else None,
        "method": required.get("method") if isinstance(required, dict) else None,
    }

    intent = {
        "event_id": f"execute-operation.{operation_id}.intent",
        "request_id": operation_id,
        "operation_id": operation_id,
        "request_digest": request_digest,
        "message_type": "ExecuteIntent",
        "capability_id": capability_id,
        "caller": caller,
        "action": action,
    }
    try:
        record_evidence(intent)
        persisted_intents = query_intents(operation_id)
        intent_is_durable = any(
            event.get("event_id") == intent["event_id"]
            and event.get("message_type") == "ExecuteIntent"
            and event.get("request_digest") == request_digest
            for event in persisted_intents
        )
        if not intent_is_durable:
            raise RuntimeError("durable ExecuteIntent could not be read back")
    except Exception:
        # No external effect has been invoked yet. The operation may be retried
        # only after the intent path is available; the caller keeps the same ID.
        try:
            ledger.mark_not_started(operation_id, request_digest)
        except Exception:
            pass
        return {
            "status": "error",
            "error": "execution_intent_not_durable",
            "operation_id": operation_id,
            "retry_safe": True,
        }

    try:
        result = executor(capability, signature, required, caller)
        if not isinstance(result, dict):
            raise TypeError("executor returned a non-object result")
    except Exception:
        try:
            ledger.mark_indeterminate(operation_id, request_digest)
        except Exception:
            pass
        return _indeterminate(operation_id, "executor_outcome_unconfirmed")

    durable_result = {
        **result,
        "operation_id": operation_id,
        "audit_status": "durable",
    }
    receipt_event = {
        "event_id": f"execute-operation.{operation_id}.receipt",
        "request_id": operation_id,
        "operation_id": operation_id,
        "request_digest": request_digest,
        "message_type": "ExecuteReceipt",
        "capability_id": capability_id,
        "caller": caller,
        "action": action,
        "outcome": result.get("status", "unknown"),
        "result": durable_result,
    }

    try:
        record_evidence(receipt_event)
        receipts = query_receipts(operation_id)
        verified_receipt = any(
            event.get("event_id") == receipt_event["event_id"]
            and event.get("message_type") == "ExecuteReceipt"
            and event.get("operation_id") == operation_id
            and event.get("request_id") == operation_id
            and event.get("request_digest") == request_digest
            and event.get("result") == durable_result
            for event in receipts
        )
        if not verified_receipt:
            raise RuntimeError("durable ExecuteReceipt could not be read back")
    except Exception:
        try:
            ledger.mark_indeterminate(operation_id, request_digest)
        except Exception:
            pass
        return _indeterminate(operation_id, "execution_result_not_durably_attested")

    # If this update fails after receipt persistence, the next retry discovers
    # and replays the receipt rather than repeating the execution.
    try:
        ledger.complete(operation_id, request_digest, durable_result)
    except Exception:
        return _indeterminate(
            operation_id,
            "receipt_is_durable_but_operation_state_update_failed",
            audit_status="durable",
        )
    return durable_result
