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

    def test_distinct_event_ids_are_not_collapsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = EvidenceIndex(Path(tmp) / "evidence.json")
            index.ingest({"event_id": "event-a", "message_type": "ExecuteReceipt"})
            index.ingest({"event_id": "event-b", "message_type": "ExecuteReceipt"})

            self.assertEqual(len(index.query(message_type="ExecuteReceipt")), 2)


if __name__ == "__main__":
    unittest.main()
