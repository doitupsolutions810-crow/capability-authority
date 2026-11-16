import unittest
from unittest.mock import MagicMock, patch

from plane_service import server


class EvidenceRecordingContractTests(unittest.TestCase):
    def test_attached_bus_is_the_only_recording_path(self):
        with patch.object(server, "_EVIDENCE_BUS_ATTACHED", True), \
             patch("attestpipe.bus.BUS.publish") as publish, \
             patch("evidence.index.get_index") as get_index:
            server._record_evidence({"message_type": "Probe"})
        publish.assert_called_once()
        get_index.assert_not_called()

    def test_without_bus_subscription_index_is_recorded_directly(self):
        index = MagicMock()
        with patch.object(server, "_EVIDENCE_BUS_ATTACHED", False), \
             patch("evidence.index.get_index", return_value=index) as get_index, \
             patch("attestpipe.bus.BUS.publish") as publish:
            server._record_evidence({"message_type": "Probe"})
        get_index.assert_called_once()
        index.ingest.assert_called_once_with({"message_type": "Probe"})
        publish.assert_not_called()

    def test_bus_persistence_failure_is_not_silently_swallowed(self):
        with patch.object(server, "_EVIDENCE_BUS_ATTACHED", True), \
             patch("attestpipe.bus.BUS.publish", side_effect=OSError("index unavailable")):
            with self.assertRaisesRegex(OSError, "index unavailable"):
                server._record_evidence({"message_type": "Probe"})


if __name__ == "__main__":
    unittest.main()
