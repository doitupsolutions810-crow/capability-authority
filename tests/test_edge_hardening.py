"""Bugs found while extending the edge-case pass, plus the checks that lock them."""
from __future__ import annotations

import json
import logging
import re
import threading

import httpx
import pytest

import attestpipe.bus as busmod
import evidence.index as idxmod
import evidence.warehouse as whmod
from evidence.index import EvidenceIndex
from evidence.warehouse import EvidenceWarehouse
from plane_service.anomalies import log_anomaly
from plane_service.core import issue
from plane_service.crypto_sign import sign
from plane_service.executor import Executor
from plane_service.issuance_idempotency import reset_issuance_store_for_tests
from plane_service.server import handle_issue, make_server

RIGHT = {"type": "read", "resource": "demo", "method": "GET"}
ISO_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class _RecordingBus:
    def __init__(self, index):
        self.index = index

    def publish(self, event):
        return self.index.ingest(event)


@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.setenv("PRODUCTION", "0")
    monkeypatch.setenv("PLANE_PRODUCTION", "0")
    monkeypatch.delenv("SPIFFE_REQUIRED", raising=False)
    monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
    monkeypatch.delenv("PLANE_SPIFFE_ID", raising=False)
    monkeypatch.delenv("SPIFFE_ID", raising=False)
    monkeypatch.setenv("PLANE_ISSUANCE_IDEMPOTENCY_PATH", str(tmp_path / "issuance.sqlite"))
    reset_issuance_store_for_tests()
    index = EvidenceIndex(tmp_path / "index.json")
    warehouse = EvidenceWarehouse(tmp_path / "evidence.db")
    monkeypatch.setattr(idxmod, "get_index", lambda: index)
    monkeypatch.setattr(whmod, "get_warehouse", lambda: warehouse)
    monkeypatch.setattr(busmod, "BUS", _RecordingBus(index))
    return index, warehouse


def test_capped_ttl_values_are_not_the_same_idempotency_key(lab):
    first = handle_issue({
        "correlation_id": "ttl-cap",
        "rights": [RIGHT],
        "ttl_seconds": 301,
    })
    assert first["status"] == "ok"
    assert first["capability"]["expires_at"] - first["capability"]["issued_at"] == 300
    other = handle_issue({
        "correlation_id": "ttl-cap",
        "rights": [RIGHT],
        "ttl_seconds": 300,
    })
    assert other["status"] == "error"
    assert other["error"] == "issue_correlation_replay_conflict"
    assert "capability" not in other
    replay = handle_issue({
        "correlation_id": "ttl-cap",
        "rights": [RIGHT],
        "ttl_seconds": 301,
    })
    assert replay["idempotent_replay"] is True
    assert replay["capability"]["id"] == first["capability"]["id"]
    assert replay["signature"] == first["signature"]


def test_non_object_constraints_are_rejected_without_a_traceback_escape(lab):
    for constraints in (["tenant"], "tenant", 1, 1.5):
        result = handle_issue({
            "correlation_id": f"constraints-{type(constraints).__name__}",
            "rights": [RIGHT],
            "ttl_seconds": 60,
            "constraints": constraints,
        })
        assert result["status"] == "error", constraints
        assert result["error"] == "constraints must be an object"
        assert "capability" not in result


def test_anomaly_log_keeps_iso_timestamp_and_traceback(caplog):
    caplog.set_level(logging.ERROR, logger="capability_authority.anomalies")
    try:
        raise RuntimeError("disk vanished")
    except RuntimeError as exc:
        log_anomaly("evidence append failed", exc)
    text = caplog.text
    assert "evidence append failed" in text
    assert ISO_STAMP.search(text)
    assert "Traceback (most recent call last)" in text
    assert "RuntimeError: disk vanished" in text


def test_evidence_limit_edge_values_are_400_and_logged(caplog):
    caplog.set_level(logging.ERROR, logger="capability_authority.anomalies")
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:" + str(server.server_address[1])
    try:
        for query in ("limit=nope", "limit=0", "limit=1001", "limit=-5"):
            response = httpx.get(base + "/v1/evidence?" + query, timeout=5)
            assert response.status_code == 400, (query, response.status_code, response.text)
            assert "limit" in response.json()["error"]
        ok = httpx.get(base + "/v1/evidence?limit=1", timeout=5)
        assert ok.status_code == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    assert ISO_STAMP.search(caplog.text)
    assert "Traceback (most recent call last)" in caplog.text
    assert "limit is not an integer" in caplog.text


def test_non_finite_execute_input_is_an_error_not_a_crash():
    cap = issue("spiffe://prod/agent/dev", "spiffe://prod/broker", [RIGHT], {}, 60, "prod", "dev:unattested", 1)
    result = Executor().execute(
        cap, sign(cap), RIGHT, cap["audience"],
        correlation_id="non-finite", action_input={"n": float("nan")},
    )
    assert result["status"] == "error"
    assert result["error"] == "execution request is not finite JSON"
    assert result.get("execution_status") != "NOT_IMPLEMENTED"


def test_projection_bracket_and_stale_checkpoint_repair(tmp_path):
    warehouse = EvidenceWarehouse(tmp_path / "evidence.db")
    index = EvidenceIndex(tmp_path / "index.json")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(whmod, "get_warehouse", lambda: warehouse)
        index.ingest({"event_id": "bracket", "message_type": "Probe", "note": "keep ] this"})
        index.ingest({"event_id": "after", "message_type": "Probe"})
        parsed = json.loads(index.path.read_text(encoding="utf-8"))
        assert [row["event_id"] for row in parsed] == ["bracket", "after"]
        assert parsed[0]["note"] == "keep ] this"
        index._tip = "cd" * 32
        index._synced = True
        found = index.query(limit=10)
        assert {row["event_id"] for row in found} == {"bracket", "after"}
        assert len(json.loads(index.path.read_text(encoding="utf-8"))) == 2
        assert warehouse.verify_chain()["ok"] is True


def test_execute_stays_not_implemented_for_unbound_actions(lab):
    issued = handle_issue({"rights": [RIGHT], "ttl_seconds": 60, "correlation_id": "not-impl"})
    assert issued["status"] == "ok"
    from plane_service.server import handle_execute
    result = handle_execute({
        "capability": issued["capability"],
        "signature": issued["signature"],
        "required": RIGHT,
        "caller": issued["capability"]["audience"],
        "correlation_id": "not-impl-exec",
    })
    assert result["status"] == "authorized"
    assert result["execution_status"] == "NOT_IMPLEMENTED"
    assert result["receipt"]["outcome"] == "authorized_not_executed"
