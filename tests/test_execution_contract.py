import threading
import tempfile
import unittest
from pathlib import Path

from plane_service.execution_contract import execute_with_idempotency, execution_http_status
from plane_service.operation_ledger import OperationLedger


class ExecutionContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.ledger = OperationLedger(root / "evidence.db")
        self.events = {}
        self.event_lock = threading.Lock()
        self.executor_calls = 0
        self.executor_lock = threading.Lock()
        self.fail_record_event = None
        self.raise_after_record_event = None
        self.fail_intent_query = False
        self.fail_receipt_query = False
        self.executor_impl = self.executor

    def tearDown(self):
        self.tmp.cleanup()

    def body(self, operation_id="op-123"):
        return {
            "operation_id": operation_id,
            "capability": {"id": "cap-1", "audience": "spiffe://test/agent"},
            "signature": "unit-test-signature",
            "required": {"type": "resource", "resource": "test-object", "method": "POST"},
            "caller": "spiffe://test/agent",
        }

    def executor(self, capability, signature, required, caller):
        with self.executor_lock:
            self.executor_calls += 1
            number = self.executor_calls
        return {
            "status": "ok",
            "result": "executed",
            "receipt": {
                "capability_id": capability["id"],
                "action": f'{required["type"]}:{required["resource"]}:{required["method"]}',
                "outcome": "ok",
                "unit_sequence": number,
            },
        }

    def record(self, event):
        event_id = event["event_id"]
        if event_id == self.fail_record_event:
            raise OSError("injected evidence write failure")
        with self.event_lock:
            prior = self.events.get(event_id)
            if prior is not None and prior != event:
                raise ValueError("event identity reused with different payload")
            self.events[event_id] = dict(event)
        if event_id == self.raise_after_record_event:
            raise OSError("simulated acknowledgement loss after durable write")

    def query(self, operation_id, message_type, *, should_fail=False):
        if should_fail:
            raise OSError("injected read-back failure")
        with self.event_lock:
            return [
                dict(event) for event in self.events.values()
                if event.get("request_id") == operation_id
                and event.get("message_type") == message_type
            ]

    def run_contract(self, body=None, *, executor=None):
        body = body or self.body()
        return execute_with_idempotency(
            body,
            executor=executor or self.executor_impl,
            record_evidence=self.record,
            query_receipts=lambda operation_id: self.query(
                operation_id, "ExecuteReceipt", should_fail=self.fail_receipt_query
            ),
            query_intents=lambda operation_id: self.query(
                operation_id, "ExecuteIntent", should_fail=self.fail_intent_query
            ),
            ledger=self.ledger,
        )

    def test_missing_operation_identity_is_rejected_before_execution(self):
        candidate = self.body()
        candidate.pop("operation_id")
        result = self.run_contract(candidate)
        self.assertEqual(result["error"], "operation_id_required")
        self.assertEqual(self.executor_calls, 0)
        self.assertEqual(self.events, {})

    def test_completed_operation_replays_without_second_execution(self):
        first = self.run_contract()
        second = self.run_contract()
        self.assertEqual(first["status"], "ok")
        self.assertEqual(first["audit_status"], "durable")
        self.assertEqual(second["status"], "ok")
        self.assertTrue(second["replayed"])
        self.assertEqual(self.executor_calls, 1)
        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.ledger.claim("op-123", self._digest_for(self.body()))["state"], "completed")

    def test_reusing_operation_identity_for_different_payload_is_rejected(self):
        self.run_contract()
        altered = self.body()
        altered["required"]["method"] = "DELETE"
        result = self.run_contract(altered)
        self.assertEqual(result["error"], "operation_id_payload_conflict")
        self.assertFalse(result["retry_safe"])
        self.assertEqual(self.executor_calls, 1)

    def test_intent_must_be_read_back_before_executor_runs(self):
        self.fail_intent_query = True
        first = self.run_contract()
        self.assertEqual(first["error"], "execution_intent_not_durable")
        self.assertEqual(self.executor_calls, 0)
        # Intent may exist, but because execution has not started, the same ID can retry.
        self.fail_intent_query = False
        second = self.run_contract()
        self.assertEqual(second["status"], "ok")
        self.assertEqual(self.executor_calls, 1)

    def test_intent_write_failure_is_retryable_only_before_effect(self):
        self.fail_record_event = "execute-operation.op-123.intent"
        first = self.run_contract()
        self.assertEqual(first["error"], "execution_intent_not_durable")
        self.assertTrue(first["retry_safe"])
        self.assertEqual(self.executor_calls, 0)
        self.fail_record_event = None
        second = self.run_contract()
        self.assertEqual(second["status"], "ok")
        self.assertEqual(self.executor_calls, 1)

    def test_receipt_write_failure_yields_indeterminate_and_blocks_reexecution(self):
        self.fail_record_event = "execute-operation.op-123.receipt"
        first = self.run_contract()
        self.assertEqual(first["status"], "indeterminate")
        self.assertEqual(first["audit_status"], "unknown")
        self.assertFalse(first["retry_safe"])
        self.assertEqual(self.executor_calls, 1)
        self.fail_record_event = None
        second = self.run_contract()
        self.assertEqual(second["status"], "indeterminate")
        self.assertEqual(self.executor_calls, 1)

    def test_lost_ack_after_receipt_commit_reconciles_without_reexecution(self):
        self.raise_after_record_event = "execute-operation.op-123.receipt"
        first = self.run_contract()
        self.assertEqual(first["status"], "indeterminate")
        self.assertEqual(self.executor_calls, 1)
        self.raise_after_record_event = None
        second = self.run_contract()
        self.assertEqual(second["status"], "ok")
        self.assertTrue(second["replayed"])
        self.assertEqual(second["audit_status"], "durable")
        self.assertEqual(self.executor_calls, 1)

    def test_receipt_readback_failure_is_indeterminate_not_success(self):
        self.fail_receipt_query = True
        first = self.run_contract()
        self.assertEqual(first["status"], "indeterminate")
        self.assertEqual(self.executor_calls, 1)
        self.fail_receipt_query = False
        second = self.run_contract()
        self.assertEqual(second["status"], "ok")
        self.assertTrue(second["replayed"])
        self.assertEqual(self.executor_calls, 1)

    def test_durable_receipt_with_failed_operation_state_update_is_reconciled(self):
        original_complete = self.ledger.complete
        first_attempt = {"value": True}

        def fail_once(operation_id, request_digest, result):
            if first_attempt["value"]:
                first_attempt["value"] = False
                raise OSError("injected operation-row commit failure")
            return original_complete(operation_id, request_digest, result)

        self.ledger.complete = fail_once
        first = self.run_contract()
        self.assertEqual(first["status"], "indeterminate")
        self.assertEqual(first["audit_status"], "durable")
        self.assertEqual(self.executor_calls, 1)
        self.ledger.complete = original_complete
        second = self.run_contract()
        self.assertEqual(second["status"], "ok")
        self.assertTrue(second["replayed"])
        self.assertEqual(self.executor_calls, 1)

    def test_concurrent_duplicate_requests_execute_at_most_once(self):
        started = threading.Event()
        release = threading.Event()
        first_result = {}

        def blocking_executor(capability, signature, required, caller):
            with self.executor_lock:
                self.executor_calls += 1
            started.set()
            self.assert_release = release.wait(timeout=5)
            if not self.assert_release:
                raise TimeoutError("test executor was not released")
            return {
                "status": "ok",
                "result": "executed",
                "receipt": {"capability_id": capability["id"], "action": "resource:test-object:POST", "outcome": "ok"},
            }

        thread = threading.Thread(
            target=lambda: first_result.update(self.run_contract(executor=blocking_executor)),
            daemon=True,
        )
        thread.start()
        self.assertTrue(started.wait(timeout=2), "first operation did not reach executor")
        second = self.run_contract(executor=blocking_executor)
        self.assertEqual(second["status"], "indeterminate")
        self.assertFalse(second["retry_safe"])
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "first operation did not finish")
        self.assertEqual(first_result["status"], "ok")
        self.assertEqual(self.executor_calls, 1)

    def test_completed_ledger_row_cannot_replace_missing_durable_receipt(self):
        first = self.run_contract()
        self.assertEqual(first["status"], "ok")
        self.events.pop("execute-operation.op-123.receipt")
        replay = self.run_contract()
        self.assertEqual(replay["status"], "indeterminate")
        self.assertEqual(replay["error"], "completed_receipt_missing_or_mismatched")
        self.assertEqual(self.executor_calls, 1)


    def test_uncertain_operations_are_not_reported_as_http_success(self):
        self.assertEqual(execution_http_status({"status": "indeterminate"}), 202)
        self.assertEqual(execution_http_status({"status": "error", "error": "operation_id_payload_conflict"}), 409)
        self.assertEqual(execution_http_status({"status": "error", "error": "operation_id_required"}), 400)
        self.assertEqual(execution_http_status({"status": "error", "error": "operation_ledger_unavailable"}), 503)
        self.assertEqual(execution_http_status({"status": "error", "error": "execution_intent_not_durable"}), 503)
        self.assertEqual(execution_http_status({"status": "ok"}), 200)

    @staticmethod
    def _digest_for(body):
        import hashlib
        import json
        payload = {key: value for key, value in body.items() if key != "operation_id"}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


if __name__ == "__main__":
    unittest.main()
