import json
import sqlite3
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

    def test_delegation_correlation_is_unique_across_distinct_assertion_jtis(self):
        with tempfile.TemporaryDirectory() as tmp:
            warehouse = EvidenceWarehouse(Path(tmp) / "evidence.db")
            warehouse.append({
                "event_id": "delegation:jti-a",
                "message_type": "CapabilityDelegated",
                "message_id": "jti-a",
                "correlation_id": "stable-correlation",
                "request_digest": "same-request",
            })
            with self.assertRaisesRegex(ValueError, "correlation_id"):
                warehouse.append({
                    "event_id": "delegation:jti-b",
                    "message_type": "CapabilityDelegated",
                    "message_id": "jti-b",
                    "correlation_id": "stable-correlation",
                    "request_digest": "same-request",
                })
            verified = warehouse.verify_chain()
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(verified["length"], 1)

    def test_concurrent_delegation_correlation_is_committed_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            warehouse = EvidenceWarehouse(Path(tmp) / "evidence.db")
            events = [
                {
                    "event_id": f"delegation:jti-{i}",
                    "message_type": "CapabilityDelegated",
                    "message_id": f"jti-{i}",
                    "correlation_id": "one-correlation",
                    "request_digest": "same-request",
                }
                for i in range(2)
            ]

            def append_or_reject(event):
                try:
                    return ("committed", warehouse.append(event))
                except ValueError as exc:
                    return ("rejected", str(exc))

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(append_or_reject, events))

            self.assertEqual(sum(result[0] == "committed" for result in results), 1)
            self.assertEqual(sum(result[0] == "rejected" for result in results), 1)
            verified = warehouse.verify_chain()
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(verified["length"], 1)

    def test_legacy_ledger_migration_backfills_delegation_correlations(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "legacy.db"
            event = {
                "event_id": "delegation:legacy-jti",
                "message_type": "CapabilityDelegated",
                "message_id": "legacy-jti",
                "correlation_id": "legacy-correlation",
            }
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE evidence "
                    "(id INTEGER PRIMARY KEY, payload TEXT, prev_digest TEXT, digest TEXT UNIQUE, event_id TEXT)"
                )
                connection.execute(
                    "INSERT INTO evidence (payload, prev_digest, digest, event_id) VALUES (?,?,?,?)",
                    (json.dumps(event), "0" * 64, "legacy-digest", event["event_id"]),
                )

            warehouse = EvidenceWarehouse(db)
            with self.assertRaisesRegex(ValueError, "correlation_id"):
                warehouse.append({
                    "event_id": "delegation:new-jti",
                    "message_type": "CapabilityDelegated",
                    "message_id": "new-jti",
                    "correlation_id": "legacy-correlation",
                })

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
