import json
import tempfile
import unittest
from pathlib import Path

from evidence.index import EvidenceIndex


class EvidenceIndexIdempotencyTests(unittest.TestCase):
    def test_same_event_id_is_indexed_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            index = EvidenceIndex(path)
            event = {
                "event_id": "logical-event-001",
                "message_type": "ExecuteReceipt",
                "capability_id": "cap-1",
                "outcome": "ok",
            }

            first = index.ingest(event)
            second = index.ingest(dict(event))

            self.assertEqual(first, second)
            self.assertEqual(len(index.query(message_type="ExecuteReceipt")), 1)
            persisted = json.loads(path.read_text())
            self.assertEqual(len(persisted), 1)
            self.assertEqual(persisted[0]["event_id"], "logical-event-001")

    def test_same_event_id_with_changed_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = EvidenceIndex(Path(tmp) / "evidence.json")
            index.ingest({
                "event_id": "logical-event-001",
                "message_type": "ExecuteReceipt",
                "outcome": "ok",
            })

            with self.assertRaisesRegex(ValueError, "different evidence payload"):
                index.ingest({
                    "event_id": "logical-event-001",
                    "message_type": "ExecuteReceipt",
                    "outcome": "denied",
                })

    def test_distinct_event_ids_are_not_collapsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = EvidenceIndex(Path(tmp) / "evidence.json")
            index.ingest({"event_id": "event-a", "message_type": "ExecuteReceipt"})
            index.ingest({"event_id": "event-b", "message_type": "ExecuteReceipt"})

            self.assertEqual(len(index.query(message_type="ExecuteReceipt")), 2)



    def test_issue_does_not_release_capability_when_audit_is_unknown(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from plane_service import server

        cap = {"id": "cap-unknown", "audience": "caller", "issuer": "issuer"}
        with patch.object(server, "bind_issue_request", return_value={
            "caller": "caller", "rights": [], "constraints": {}, "ttl_seconds": 60
        }), patch.object(
            server, "fetch_workload_identity", return_value=SimpleNamespace(spiffe_id="caller")
        ), patch.object(server.policy, "authorize"), patch.object(
            server, "issue", return_value=cap
        ), patch.object(server, "sign", return_value="signed"), patch.object(
            server, "_record_evidence", return_value=False
        ):
            result = server.handle_issue({})

        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["audit_status"], "unknown")
        self.assertEqual(result["capability_id"], "cap-unknown")
        self.assertNotIn("capability", result)
        self.assertNotIn("signature", result)

    def test_execute_reports_indeterminate_when_audit_is_unknown(self):
        from unittest.mock import patch
        from plane_service import server

        with patch.object(server.executor, "execute", return_value={
            "status": "ok", "receipt": {"action": "read", "outcome": "executed"}
        }), patch.object(server, "_record_evidence", return_value=False):
            result = server.handle_execute({
                "capability": {"id": "cap-1"}, "signature": "sig",
                "required": {"type": "read"}, "caller": "caller"
            })

        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["audit_status"], "unknown")
        self.assertIn("error", result)

if __name__ == "__main__":
    unittest.main()
