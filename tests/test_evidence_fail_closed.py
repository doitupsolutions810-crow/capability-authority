from __future__ import annotations

import pytest

import attestpipe.bus as bus_module
import evidence.index as index_module
from plane_service.server import EvidencePersistenceError, _record_evidence


class FakeIndex:
    def __init__(self):
        self.rows = []

    def ingest(self, event):
        self.rows.append(dict(event))
        return event

    def query(self, *, capability_id=None, message_type=None, limit=50, **_kwargs):
        rows = [
            row for row in self.rows
            if (capability_id is None or row.get("capability_id") == capability_id)
            and (message_type is None or row.get("message_type") == message_type)
        ]
        return rows[:limit]


class PublishingBus:
    def __init__(self, index, persist=True):
        self.index = index
        self.persist = persist

    def publish(self, event):
        if self.persist:
            self.index.ingest(event)
        return event


def test_evidence_publish_is_confirmed_in_durable_index(monkeypatch):
    index = FakeIndex()
    monkeypatch.setattr(index_module, "get_index", lambda: index)
    monkeypatch.setattr(bus_module, "BUS", PublishingBus(index))
    result = _record_evidence({
        "message_type": "CapabilityIssued",
        "capability_id": "cap-test",
    })
    assert result == {"durable": True, "replication": "published"}


def test_missing_durable_subscriber_fails_closed(monkeypatch):
    index = FakeIndex()
    monkeypatch.setattr(index_module, "get_index", lambda: index)
    monkeypatch.setattr(bus_module, "BUS", PublishingBus(index, persist=False))
    with pytest.raises(EvidencePersistenceError):
        _record_evidence({
            "message_type": "CapabilityIssued",
            "capability_id": "cap-not-persisted",
        })


def test_publish_exception_fails_closed(monkeypatch):
    index = FakeIndex()
    monkeypatch.setattr(index_module, "get_index", lambda: index)

    class BrokenBus:
        def publish(self, _event):
            raise OSError("disk unavailable")

    monkeypatch.setattr(bus_module, "BUS", BrokenBus())
    with pytest.raises(EvidencePersistenceError):
        _record_evidence({
            "message_type": "CapabilityIssued",
            "capability_id": "cap-disk-failure",
        })


def test_missing_event_type_fails_closed():
    with pytest.raises(EvidencePersistenceError):
        _record_evidence({"capability_id": "cap-no-type"})
