"""Edge cases for issue replay, execute identity, HTTP framing, and the evidence suffix."""
from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

import attestpipe.bus as busmod
import evidence.index as idxmod
import evidence.warehouse as whmod
from evidence.index import EvidenceIndex
from evidence.warehouse import EvidenceWarehouse
from plane_service.core import issue
from plane_service.crypto_sign import sign
from plane_service.executor import Executor
from plane_service.issuance_idempotency import reset_issuance_store_for_tests
from plane_service.server import handle_execute, handle_issue, make_server

RIGHT = {"type": "read", "resource": "demo", "method": "GET"}
OTHER = {"type": "Execute", "resource": "tool.echo", "method": "POST"}
CALLER = "spiffe://prod/agent/dev"


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
    monkeypatch.delenv("PLANE_ALLOW_CALLER_OVERRIDE", raising=False)
    monkeypatch.setenv("PLANE_ISSUANCE_IDEMPOTENCY_PATH", str(tmp_path / "issuance.sqlite"))
    reset_issuance_store_for_tests()
    index = EvidenceIndex(tmp_path / "index.json")
    warehouse = EvidenceWarehouse(tmp_path / "evidence.db")
    monkeypatch.setattr(idxmod, "get_index", lambda: index)
    monkeypatch.setattr(whmod, "get_warehouse", lambda: warehouse)
    monkeypatch.setattr(busmod, "BUS", _RecordingBus(index))
    return index, warehouse


def _body(**overrides):
    body = {
        "correlation_id": "edge-corr",
        "rights": [RIGHT],
        "ttl_seconds": 60,
        "constraints": {"tenant": "a", "zone": "b"},
    }
    body.update(overrides)
    return body


def test_issue_replay_ignores_constraint_key_order_and_rejects_real_changes(lab):
    first = handle_issue(_body())
    assert first["status"] == "ok"
    reordered = handle_issue(_body(constraints={"zone": "b", "tenant": "a"}))
    assert reordered["status"] == "ok"
    assert reordered["idempotent_replay"] is True
    assert reordered["signature"] == first["signature"]
    assert reordered["capability"]["id"] == first["capability"]["id"]

    swapped_rights = handle_issue(_body(rights=[OTHER, RIGHT]))
    assert swapped_rights["status"] == "error"
    assert swapped_rights["error"] == "issue_correlation_replay_conflict"
    assert "capability" not in swapped_rights

    capped_same = handle_issue(_body(correlation_id="edge-ttl", ttl_seconds=301))
    assert capped_same["status"] == "ok"
    assert capped_same["capability"]["expires_at"] - capped_same["capability"]["issued_at"] == 300
    again = handle_issue(_body(correlation_id="edge-ttl", ttl_seconds=301))
    assert again["capability"]["id"] == capped_same["capability"]["id"]
    different_request = handle_issue(_body(correlation_id="edge-ttl", ttl_seconds=300))
    assert different_request["status"] == "error"
    assert different_request["error"] == "issue_correlation_replay_conflict"


def test_issue_rejects_malformed_correlation_and_does_not_mint(lab, monkeypatch):
    calls = {"n": 0}
    real_issue = issue

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real_issue(*args, **kwargs)

    monkeypatch.setattr("plane_service.server.issue", counting)
    for bad in ("", "   ", "x" * 129, "bad\x00id", 12, True):
        result = handle_issue(_body(correlation_id=bad))
        assert result["status"] == "error", bad
        assert "correlation_id" in result["error"]
        assert "capability" not in result
    assert calls["n"] == 0


def test_expired_and_corrupt_issue_ledger_does_not_mint_a_replacement(lab, monkeypatch):
    import plane_service.server as server

    first = handle_issue(_body(correlation_id="edge-expire", ttl_seconds=60))
    assert first["status"] == "ok"
    expires_at = first["capability"]["expires_at"]
    monkeypatch.setattr(server.time, "time", lambda: expires_at + 1)
    expired = handle_issue(_body(correlation_id="edge-expire", ttl_seconds=60))
    assert expired["status"] == "error"
    assert expired["error"] == "issued_capability_expired"
    assert expired["capability_id"] == first["capability"]["id"]
    assert "capability" not in expired

    monkeypatch.setattr(server.time, "time", time.time)
    store_path = lab[0].path.parent / "issuance.sqlite"
    store_path.write_bytes(b"this is not a sqlite ledger")
    reset_issuance_store_for_tests()
    calls = {"n": 0}
    real_issue = issue

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real_issue(*args, **kwargs)

    monkeypatch.setattr(server, "issue", counting)
    corrupt = handle_issue(_body(correlation_id="edge-expire", ttl_seconds=60))
    assert corrupt["status"] == "error"
    assert corrupt["error"] == "issuance_idempotency_corrupt"
    assert calls["n"] == 0


def test_racing_issue_with_different_ttl_keeps_one_capability(lab):
    def once(ttl):
        return handle_issue(_body(correlation_id="edge-race", ttl_seconds=ttl))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(once, [60, 90] * 4))
    oks = [result for result in results if result["status"] == "ok"]
    conflicts = [result for result in results if result["status"] == "error"]
    assert oks and conflicts
    assert {result["error"] for result in conflicts} == {"issue_correlation_replay_conflict"}
    assert len({result["capability"]["id"] for result in oks}) == 1
    assert all("capability" not in result for result in conflicts)


def test_execute_replay_does_not_cross_capability_or_action(lab):
    first_cap = issue(CALLER, "spiffe://prod/broker", [RIGHT, OTHER], {}, 60, "prod", "dev:unattested", 1)
    second_cap = issue(CALLER, "spiffe://prod/broker", [RIGHT, OTHER], {}, 60, "prod", "dev:unattested", 1)
    first_sig = sign(first_cap)
    second_sig = sign(second_cap)
    executor = Executor()
    original = executor.execute(first_cap, first_sig, RIGHT, CALLER, correlation_id="same-corr")
    replay = executor.execute(first_cap, first_sig, RIGHT, CALLER, correlation_id="same-corr")
    other_cap = executor.execute(second_cap, second_sig, RIGHT, CALLER, correlation_id="same-corr")
    other_action = executor.execute(first_cap, first_sig, OTHER, CALLER, correlation_id="same-corr")
    assert replay["idempotent_replay"] is True
    assert replay["receipt"] == original["receipt"]
    assert other_cap["idempotent_replay"] is False
    assert other_cap["receipt"]["capability_id"] == second_cap["id"]
    assert other_cap["receipt"] != original["receipt"]
    assert other_action["receipt"]["action"] == "Execute:tool.echo:POST"
    assert other_action["receipt"] != original["receipt"]

    missing_method = handle_execute({
        "capability": first_cap,
        "signature": first_sig,
        "required": {"type": "read", "resource": "demo"},
        "caller": CALLER,
        "correlation_id": "methodless",
    })
    assert missing_method["status"] == "error"
    assert missing_method["error"] == "verify failed"
    blank = handle_execute({
        "capability": first_cap,
        "signature": first_sig,
        "required": RIGHT,
        "caller": CALLER,
        "correlation_id": "   ",
    })
    assert blank["status"] == "error"
    assert "correlation_id" in blank["error"]


def test_projection_append_survives_bracket_in_value_and_repairs_stale_checkpoint(tmp_path):
    warehouse = EvidenceWarehouse(tmp_path / "evidence.db")
    index = EvidenceIndex(tmp_path / "index.json")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(whmod, "get_warehouse", lambda: warehouse)
        index.ingest({"event_id": "bracket", "message_type": "Probe", "note": "keep ] this"})
        index.ingest({"event_id": "after", "message_type": "Probe", "note": "tail"})
        parsed = json.loads(index.path.read_text(encoding="utf-8"))
        assert [row["event_id"] for row in parsed] == ["bracket", "after"]
        assert parsed[0]["note"] == "keep ] this"
        assert warehouse.verify_chain()["ok"] is True

        index._tip = "ab" * 32
        index._synced = True
        repaired = index.query(limit=10)
        assert {row["event_id"] for row in repaired} == {"bracket", "after"}
        assert json.loads(index.path.read_text(encoding="utf-8"))
        assert len(json.loads(index.path.read_text(encoding="utf-8"))) == 2


def _raw_status(port: int, request: bytes) -> bytes:
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        sock.settimeout(2)
        sock.sendall(request)
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.split(b"\r\n", 1)[0]
    finally:
        sock.close()


def test_http_framing_edge_cases_stay_4xx():
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        non_finite = httpx.post(base + "/v1/capabilities/issue", content=b'{"ttl_seconds":NaN}', timeout=5)
        duplicate = httpx.post(base + "/v1/capabilities/issue", content=b'{"a":1,"a":2}', timeout=5)
        bom = httpx.post(base + "/v1/capabilities/issue", content=b"\xef\xbb\xbf{}", timeout=5)
        assert non_finite.status_code == 400
        assert duplicate.status_code == 400
        assert bom.status_code == 200
        assert bom.json()["status"] == "error"
        for header, status in (
            (b"Content-Length: nope\r\n", b"400"),
            (b"Content-Length: 1234567890123\r\n", b"400"),
            (b"Content-Length: -1\r\n", b"400"),
            (b"Transfer-Encoding: chunked\r\n", b"501"),
        ):
            raw = (
                b"POST /v1/capabilities/issue HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n" + header + b"\r\n"
            )
            assert status in _raw_status(port, raw), header
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
