import json
import multiprocessing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence.index import EvidenceIndex
from evidence.warehouse import EvidenceWarehouse


def _ingest_worker(index_path, db_path, event, barrier):
    import evidence.warehouse as warehouse_module

    database_path = Path(db_path)
    warehouse_module.get_warehouse = lambda: EvidenceWarehouse(database_path)
    index = EvidenceIndex(Path(index_path))
    # Ensure both processes load the same initial projection before either writes.
    barrier.wait(timeout=20)
    index.ingest(event)


class EvidenceIndexProjectionConsistencyTests(unittest.TestCase):
    def test_query_repairs_a_stale_projection_from_the_verified_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path = root / "index.json"
            warehouse = EvidenceWarehouse(root / "evidence.db")
            expected_ids = {"evt-A", "evt-B"}
            for event_id in sorted(expected_ids):
                warehouse.append({"event_id": event_id, "message_type": "Probe"})
            index_path.write_text("[]", encoding="utf-8")

            index = EvidenceIndex(index_path)
            with patch("evidence.warehouse.get_warehouse", return_value=warehouse):
                queried = index.query(limit=10)

            self.assertEqual({event["event_id"] for event in queried}, expected_ids)
            persisted = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual({event["event_id"] for event in persisted}, expected_ids)

    def test_concurrent_processes_preserve_all_committed_ledger_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path = root / "index.json"
            db_path = root / "evidence.db"
            events = [
                {"event_id": "evt-A", "message_type": "Probe", "value": "A"},
                {"event_id": "evt-B", "message_type": "Probe", "value": "B"},
            ]

            warehouse = EvidenceWarehouse(db_path)
            context = multiprocessing.get_context("spawn")
            barrier = context.Barrier(len(events))
            processes = [
                context.Process(
                    target=_ingest_worker,
                    args=(str(index_path), str(db_path), event, barrier),
                )
                for event in events
            ]

            try:
                for process in processes:
                    process.start()
                for process in processes:
                    process.join(timeout=30)
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)
                        self.fail("evidence writer process did not finish")
                    self.assertEqual(process.exitcode, 0)

                verified = warehouse.verify_chain()
                self.assertTrue(verified["ok"], verified)
                self.assertEqual(verified["length"], len(events))

                persisted = json.loads(index_path.read_text(encoding="utf-8"))
                expected_ids = {event["event_id"] for event in events}
                self.assertEqual({event["event_id"] for event in persisted}, expected_ids)

                with patch("evidence.warehouse.get_warehouse", return_value=warehouse):
                    queried = EvidenceIndex(index_path).query(limit=10)
                self.assertEqual({event["event_id"] for event in queried}, expected_ids)
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)

    def test_query_fails_closed_when_the_authoritative_chain_is_corrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path = root / "index.json"
            db_path = root / "evidence.db"
            warehouse = EvidenceWarehouse(db_path)
            warehouse.append({"event_id": "evt-corrupt", "message_type": "Probe"})
            with sqlite3.connect(db_path) as connection:
                connection.execute("UPDATE evidence SET digest = ?", ("f" * 64,))

            index = EvidenceIndex(index_path)
            with patch("evidence.warehouse.get_warehouse", return_value=warehouse):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    index.query(limit=10)
            self.assertFalse(index_path.exists())


if __name__ == "__main__":
    unittest.main()
