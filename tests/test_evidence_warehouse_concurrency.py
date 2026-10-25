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


if __name__ == "__main__":
    unittest.main()
