import unittest
from plane_service.core import attenuate, verify

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

if __name__ == "__main__":
    unittest.main()
