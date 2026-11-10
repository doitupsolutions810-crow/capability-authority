"""Issue stays fast as the evidence ledger grows.

Startup verifies the hash chain once. Later issues only hash the new suffix
and append it to the projection.
"""
from __future__ import annotations

import json
import sqlite3
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import attestpipe.bus as busmod
import evidence.index as idxmod
import evidence.warehouse as whmod
from evidence.index import EvidenceIndex
from evidence.warehouse import EvidenceWarehouse
from plane_service.issuance_idempotency import reset_issuance_store_for_tests
from plane_service.server import handle_issue

RIGHT = {"type": "read", "resource": "demo", "method": "GET"}


class _RecordingBus:
    def __init__(self, index):
        self.index = index

    def publish(self, event):
        return self.index.ingest(event)


@pytest.fixture
def issuing(monkeypatch, tmp_path):
    monkeypatch.setenv("PRODUCTION", "0")
    monkeypatch.setenv("PLANE_PRODUCTION", "0")
    monkeypatch.delenv("SPIFFE_REQUIRED", raising=False)
    monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
    monkeypatch.delenv("PLANE_SPIFFE_ID", raising=False)
    monkeypatch.delenv("SPIFFE_ID", raising=False)
    monkeypatch.delenv("PLANE_ALLOW_CALLER_OVERRIDE", raising=False)
    monkeypatch.setenv("PLANE_ISSUANCE_IDEMPOTENCY_PATH", str(tmp_path / "issuance.sqlite"))
    reset_issuance_store_for_tests()
    index = EvidenceIndex(tmp_path / "index.json")
    warehouse = EvidenceWarehouse(tmp_path / "evidence.db")
    monkeypatch.setattr(idxmod, "get_index", lambda: index)
    monkeypatch.setattr(whmod, "get_warehouse", lambda: warehouse)
    monkeypatch.setattr(busmod, "BUS", _RecordingBus(index))
    EvidenceWarehouse.full_ledger_verifications = 0
    return index, warehouse


def _issue(name: str):
    result = handle_issue({
        "correlation_id": name,
        "rights": [RIGHT],
        "ttl_seconds": 60,
    })
    assert result["status"] == "ok", result
    return result


def _median_batch(prefix: str, count: int) -> float:
    samples = []
    for slot in range(count):
        started = time.perf_counter()
        _issue(f"{prefix}-{slot}")
        samples.append(time.perf_counter() - started)
    return statistics.median(samples)


def test_issue_latency_stays_flat_as_the_ledger_grows(issuing):
    index, warehouse = issuing
    _issue("warm-up")
    assert EvidenceWarehouse.full_ledger_verifications == 1

    small = _median_batch("small", 8)
    for slot in range(120):
        _issue(f"fill-{slot}")
    assert EvidenceWarehouse.full_ledger_verifications == 1
    large = _median_batch("large", 8)

    chain = warehouse.verify_chain()
    assert chain["ok"] is True
    assert chain["length"] == 1 + 8 + 120 + 8
    projected = index.query(limit=1000)
    assert len(projected) == chain["length"]
    # A full rehash-and-rewrite grows with the ledger. The suffix path must not.
    assert large < max(small * 3, small + 0.02)
    assert large < 0.05, large


def test_two_hundred_fifty_six_concurrent_issues_finish_within_10_seconds(issuing):
    _index, warehouse = issuing
    for slot in range(24):
        _issue(f"prefill-{slot}")
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=256) as pool:
        results = list(pool.map(lambda slot: _issue(f"burst-{slot}"), range(256)))
    elapsed = time.perf_counter() - started
    assert elapsed < 10, elapsed
    assert len({result["capability"]["id"] for result in results}) == 256
    assert EvidenceWarehouse.full_ledger_verifications == 1
    chain = warehouse.verify_chain()
    assert chain["ok"] is True
    assert chain["length"] == 24 + 256


def test_incremental_suffix_keeps_the_hash_chain_and_appends(issuing):
    index, warehouse = issuing
    _issue("chain-0")
    before = index.path.stat().st_size
    rewrites = {"count": 0}
    original_rewrite = EvidenceIndex._write_atomic

    def counting_rewrite(self, docs):
        rewrites["count"] += 1
        return original_rewrite(self, docs)

    index._write_atomic = counting_rewrite.__get__(index, EvidenceIndex)
    _issue("chain-1")
    _issue("chain-2")
    assert rewrites["count"] == 0
    assert index.path.stat().st_size > before
    persisted = json.loads(index.path.read_text(encoding="utf-8"))
    assert [row["correlation_id"] for row in persisted] == ["chain-0", "chain-1", "chain-2"]
    assert warehouse.verify_chain()["ok"] is True

    # A row committed after the checkpoint must still be hash-checked.
    warehouse.append({
        "event_id": "suffix-unverified",
        "message_type": "CapabilityIssued",
        "correlation_id": "suffix",
    })
    with sqlite3.connect(warehouse.db_path) as connection:
        connection.execute(
            "UPDATE evidence SET digest = ? WHERE event_id = ?",
            ("ab" * 32, "suffix-unverified"),
        )
    with pytest.raises(ValueError, match="digest mismatch"):
        index.query(limit=10)
