import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence.index import EvidenceIndex


class EvidenceIndexFailClosedTests(unittest.TestCase):
    def test_corrupt_existing_index_refuses_to_reset_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            path.write_text('{"truncated":', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to reset history"):
                EvidenceIndex(path)

    def test_wrong_top_level_shape_refuses_to_reset_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid structure"):
                EvidenceIndex(path)

    def test_warehouse_failure_is_propagated_and_index_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            index = EvidenceIndex(path)
            with patch("evidence.warehouse.get_warehouse") as get_warehouse:
                get_warehouse.return_value.append.side_effect = OSError("warehouse unavailable")
                with self.assertRaisesRegex(OSError, "warehouse unavailable"):
                    index.ingest({"event_id": "evt-1", "message_type": "Probe"})
            self.assertEqual(index.stats()["total"], 0)
            self.assertFalse(path.exists())

    def test_successful_ingest_persists_complete_json_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            index = EvidenceIndex(path)
            with patch("evidence.warehouse.get_warehouse") as get_warehouse:
                get_warehouse.return_value.append.side_effect = lambda event: {
                    **event, "_digest": "a" * 64, "_idempotent_replay": False
                }
                saved = index.ingest({"event_id": "evt-1", "message_type": "Probe"})
            self.assertEqual(saved["_digest"], "a" * 64)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), [saved])
            self.assertEqual(index.stats()["total"], 1)
            self.assertFalse(list(Path(tmp).glob("*.tmp")))

    def test_retry_does_not_duplicate_projection_and_can_repair_missing_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            index = EvidenceIndex(path)
            committed = {}

            def append(event):
                event_id = event["event_id"]
                if event_id not in committed:
                    committed[event_id] = dict(event)
                    return {
                        **event, "_digest": "b" * 64, "_prev_digest": "0" * 64,
                        "_idempotent_replay": False,
                    }
                return {
                    **committed[event_id], "_digest": "b" * 64, "_prev_digest": "0" * 64,
                    "_idempotent_replay": True,
                }

            with patch("evidence.warehouse.get_warehouse") as get_warehouse:
                get_warehouse.return_value.append.side_effect = append
                first = index.ingest({"event_id": "evt-stable", "message_type": "Probe"})
                retry = index.ingest({"event_id": "evt-stable", "message_type": "Probe"})
            self.assertEqual(first["_digest"], retry["_digest"])
            self.assertEqual(index.stats()["total"], 1)

            # A fresh projection instance can reconstruct the committed event
            # when the ledger has it but the projection file is absent.
            repair_path = Path(tmp) / "repair.json"
            repair_index = EvidenceIndex(repair_path)
            with patch("evidence.warehouse.get_warehouse") as get_warehouse:
                get_warehouse.return_value.append.side_effect = append
                repaired = repair_index.ingest({"event_id": "evt-stable", "message_type": "Probe"})
            self.assertEqual(repaired["_digest"], "b" * 64)
            self.assertEqual(repair_index.stats()["total"], 1)
            self.assertEqual(json.loads(repair_path.read_text(encoding="utf-8"))[0]["event_id"], "evt-stable")


if __name__ == "__main__":
    unittest.main()
