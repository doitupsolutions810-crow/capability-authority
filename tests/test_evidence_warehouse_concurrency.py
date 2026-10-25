import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from evidence.warehouse import EvidenceWarehouse


class EvidenceWarehouseConcurrencyTests(unittest.TestCase):
    def test_concurrent_appends_preserve_one_valid_hash_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            warehouse = EvidenceWarehouse(Path(tmp) / "evidence.db")
            events = [
                {"event_id": f"evt-{i:03d}", "message_type": "Probe", "value": i}
                for i in range(64)
            ]

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(warehouse.append, events))

            self.assertEqual(len(results), len(events))
            verified = warehouse.verify_chain()
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(verified["length"], len(events))

    def test_retry_with_same_event_id_returns_original_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            warehouse = EvidenceWarehouse(Path(tmp) / "evidence.db")
            first = warehouse.append({
                "event_id": "evt-stable-1",
                "message_type": "Probe",
                "value": 7,
                "_indexed_at": 100.0,
            })
            retry = warehouse.append({
                "event_id": "evt-stable-1",
                "message_type": "Probe",
                "value": 7,
                "_indexed_at": 200.0,
            })

            self.assertEqual(retry["_digest"], first["_digest"])
            self.assertEqual(retry["_prev_digest"], first["_prev_digest"])
            self.assertEqual(retry["_indexed_at"], 100.0)
            verified = warehouse.verify_chain()
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(verified["length"], 1)

    def test_reusing_event_id_for_different_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            warehouse = EvidenceWarehouse(Path(tmp) / "evidence.db")
            warehouse.append({"event_id": "evt-stable-2", "value": "original"})
            with self.assertRaisesRegex(ValueError, "different payload"):
                warehouse.append({"event_id": "evt-stable-2", "value": "altered"})
            verified = warehouse.verify_chain()
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(verified["length"], 1)

    def test_concurrent_duplicate_event_id_is_committed_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            warehouse = EvidenceWarehouse(Path(tmp) / "evidence.db")
            event = {"event_id": "evt-race", "message_type": "Probe", "value": 9}
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: warehouse.append(event), range(32)))

            self.assertEqual(len({result["_digest"] for result in results}), 1)
            verified = warehouse.verify_chain()
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(verified["length"], 1)


if __name__ == "__main__":
    unittest.main()
