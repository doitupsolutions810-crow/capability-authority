import json
from pathlib import Path
import unittest
from plane_service.core import attenuate, verify

ROOT = Path(__file__).resolve().parents[1]

class MethodBoundCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.cap = {"id":"cap-1","audience":"worker-a","expires_at":2000,"rights":[{"type":"file","resource":"report.txt","method":"read"}]}

    def test_exact_method_allowed(self):
        self.assertTrue(verify(self.cap, {"type":"file","resource":"report.txt","method":"read"}, "worker-a", 1000))

    def test_different_method_denied(self):
        self.assertFalse(verify(self.cap, {"type":"file","resource":"report.txt","method":"delete"}, "worker-a", 1000))

    def test_missing_requested_or_granted_method_denied(self):
        self.assertFalse(verify(self.cap, {"type":"file","resource":"report.txt"}, "worker-a", 1000))
        cap = {**self.cap, "rights":[{"type":"file","resource":"report.txt"}]}
        self.assertFalse(verify(cap, {"type":"file","resource":"report.txt","method":"read"}, "worker-a", 1000))

    def test_missing_type_or_resource_denied(self):
        self.assertFalse(verify(self.cap, {"resource":"report.txt","method":"read"}, "worker-a", 1000))
        self.assertFalse(verify(self.cap, {"type":"file","method":"read"}, "worker-a", 1000))

    def test_wrong_resource_audience_and_expiry_denied(self):
        self.assertFalse(verify(self.cap, {"type":"file","resource":"secrets.txt","method":"read"}, "worker-a", 1000))
        self.assertFalse(verify(self.cap, {"type":"file","resource":"report.txt","method":"read"}, "worker-b", 1000))
        self.assertFalse(verify(self.cap, {"type":"file","resource":"report.txt","method":"read"}, "worker-a", 2000))

    def test_malformed_and_nonfinite_expiry_denied(self):
        for expiry in ("bad", float("inf"), float("-inf"), float("nan")):
            self.assertFalse(verify({**self.cap,"expires_at":expiry}, {"type":"file","resource":"report.txt","method":"read"}, "worker-a", 1000))

    def test_malformed_right_entry_is_ignored(self):
        cap = {**self.cap, "rights":[None, "not-a-right", {"type":"file","resource":"report.txt","method":"read"}]}
        self.assertTrue(verify(cap, {"type":"file","resource":"report.txt","method":"read"}, "worker-a", 1000))

    def test_attenuation_cannot_escalate_method(self):
        with self.assertRaises(ValueError):
            attenuate(self.cap, [{"type":"file","resource":"report.txt","method":"delete"}])


    def test_wildcard_audience_is_denied(self):
        cap = {**self.cap, "audience": "*"}
        required = {"type": "file", "resource": "report.txt", "method": "read"}
        self.assertFalse(verify(cap, required, "worker-a", 1000))

    def test_invalid_top_level_inputs_and_clock_fail_closed(self):
        required = {"type": "file", "resource": "report.txt", "method": "read"}
        for malformed_cap in (None, [], "invalid"):
            self.assertFalse(verify(malformed_cap, required, "worker-a", 1000))
        for malformed_required in (None, [], "invalid"):
            self.assertFalse(verify(self.cap, malformed_required, "worker-a", 1000))
        for malformed_caller in ("", None):
            self.assertFalse(verify(self.cap, required, malformed_caller, 1000))
        for malformed_now in (float("nan"), float("inf"), "1000", True):
            self.assertFalse(verify(self.cap, required, "worker-a", malformed_now))

    def test_attenuation_rejects_malformed_child_rights(self):
        for malformed_rights in (None, "not-a-list", [None], [{"type": "file", "resource": "report.txt"}]):
            with self.subTest(rights=malformed_rights):
                with self.assertRaises(ValueError):
                    attenuate(self.cap, malformed_rights)

    def test_attenuation_accepts_exact_subset(self):
        child = attenuate(
            self.cap,
            [{"type": "file", "resource": "report.txt", "method": "read"}],
        )
        self.assertEqual(child["rights"], [{"type": "file", "resource": "report.txt", "method": "read"}])
        self.assertEqual(child["parent_id"], self.cap["id"])


    def test_frozen_contract_vectors(self):
        contract = json.loads((ROOT / "contracts/capability-rights-v1.json").read_text())
        self.assertEqual(contract["contract"], "capability-rights-v1")
        for vector in contract["vectors"]:
            with self.subTest(vector=vector["id"]):
                capability = {**self.cap, "rights": [vector["granted"]]}
                self.assertEqual(
                    verify(capability, vector["requested"], "worker-a", 1000),
                    vector["expected"],
                )

if __name__ == "__main__":
    unittest.main()
