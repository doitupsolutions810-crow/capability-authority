"""Regressions reported by the local live harness against plane_service."""
from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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
from plane_service.server import DEFAULT_PORT, Handler, handle_issue, make_server

RIGHT = {"type": "read", "resource": "demo", "method": "GET"}
CALLER = "spiffe://prod/agent/dev"


class _RecordingBus:
    def __init__(self, index):
        self.index = index

    def publish(self, event):
        return self.index.ingest(event)


@pytest.fixture(autouse=True)
def pin_lab_identity(monkeypatch):
    """Keep issuance tests on the dev workload identity regardless of earlier tests."""
    monkeypatch.setenv("PRODUCTION", "0")
    monkeypatch.setenv("PLANE_PRODUCTION", "0")
    monkeypatch.delenv("SPIFFE_REQUIRED", raising=False)
    monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
    monkeypatch.delenv("PLANE_SPIFFE_ID", raising=False)
    monkeypatch.delenv("SPIFFE_ID", raising=False)
    monkeypatch.delenv("PLANE_ALLOW_CALLER_OVERRIDE", raising=False)


@pytest.fixture
def authority_http(monkeypatch, tmp_path):
    index = EvidenceIndex(tmp_path / "index.json")
    warehouse = EvidenceWarehouse(tmp_path / "evidence.db")
    monkeypatch.setattr(idxmod, "get_index", lambda: index)
    monkeypatch.setattr(whmod, "get_warehouse", lambda: warehouse)
    monkeypatch.setattr(busmod, "BUS", _RecordingBus(index))
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _issued_capability():
    cap = issue(
        CALLER, "spiffe://prod/broker", [RIGHT],
        {"rate_limit": {"count": 1, "window_seconds": 60}},
        60, "prod", "dev:unattested", 1,
    )
    return cap, sign(cap)


def test_issue_rejects_caller_mismatch_instead_of_rebinding():
    mismatched = handle_issue({
        "caller": "spiffe://prod/agent/attacker",
        "rights": [RIGHT],
        "ttl_seconds": 60,
    })
    assert mismatched["status"] == "error"
    assert "does not match" in mismatched["error"]
    assert "capability" not in mismatched

    matched = handle_issue({"caller": CALLER, "rights": [RIGHT], "ttl_seconds": 60})
    assert matched["status"] == "ok"
    assert matched["capability"]["audience"] == CALLER

    omitted = handle_issue({"rights": [RIGHT], "ttl_seconds": 60})
    assert omitted["status"] == "ok"
    assert omitted["capability"]["audience"] == CALLER


def test_execute_replay_is_keyed_by_correlation_capability_and_action():
    cap, signature = _issued_capability()
    executor = Executor()
    first = executor.execute(cap, signature, RIGHT, CALLER, correlation_id="corr-execute-1")
    replay = executor.execute(cap, signature, RIGHT, CALLER, correlation_id="corr-execute-1")
    assert first["status"] == "authorized"
    assert first["execution_status"] == "NOT_IMPLEMENTED"
    assert first["idempotent_replay"] is False
    assert replay["idempotent_replay"] is True
    assert replay["receipt"] == first["receipt"]

    other = executor.execute(cap, signature, RIGHT, CALLER, correlation_id="corr-execute-2")
    assert other["status"] == "error"
    assert other["error"] == "rate limited"
    assert other.get("idempotent_replay") is not True

    conflict = executor.execute(
        cap, signature, RIGHT, CALLER,
        correlation_id="corr-execute-1", action_input={"changed": True},
    )
    assert conflict["status"] == "error"
    assert conflict["error"] == "execution_replay_conflict"

    fresh_cap, fresh_sig = _issued_capability()
    fresh = Executor()

    def once(_slot):
        return fresh.execute(fresh_cap, fresh_sig, RIGHT, CALLER, correlation_id="corr-execute-race")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(once, range(8)))
    assert all(result["status"] == "authorized" for result in results)
    assert sum(result.get("idempotent_replay") is False for result in results) == 1
    assert all(result["receipt"] == results[0]["receipt"] for result in results)


def test_malformed_and_non_object_json_return_4xx(authority_http):
    cases = {
        b"{bad": "malformed",
        b"[]": "JSON object",
        b"null": "JSON object",
        b"1": "JSON object",
        b'"text"': "JSON object",
        b"true": "JSON object",
    }
    for path in ("/v1/capabilities/issue", "/v1/execute"):
        for body, marker in cases.items():
            response = httpx.post(authority_http + path, content=body, timeout=5)
            assert response.status_code == 400, (path, body, response.status_code, response.text)
            assert marker in response.json()["error"]


def test_stalled_body_does_not_block_other_requests(monkeypatch):
    monkeypatch.setattr(Handler, "timeout", 2.0)
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    stalled = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        stalled.sendall(
            b"POST /v1/capabilities/issue HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 1000\r\n"
            b"\r\n"
        )
        started = time.monotonic()
        health = httpx.get(f"http://127.0.0.1:{port}/health", timeout=1)
        assert health.status_code == 200
        assert time.monotonic() - started < 1.0
        huge = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            huge.sendall(
                b"POST /v1/capabilities/issue HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Length: 999999999\r\n"
                b"\r\n"
            )
            huge.settimeout(2)
            reply = b""
            while b"\r\n\r\n" not in reply:
                chunk = huge.recv(4096)
                if not chunk:
                    break
                reply += chunk
            header, _, body = reply.partition(b"\r\n\r\n")
            length = 0
            for line in header.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1].strip())
            while len(body) < length:
                chunk = huge.recv(4096)
                if not chunk:
                    break
                body += chunk
            assert b"413" in header.split(b"\r\n", 1)[0]
            assert b"64 KiB" in body
        finally:
            huge.close()
    finally:
        stalled.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_concurrent_issue_requests_do_not_drop_connections(authority_http):
    body = {"rights": [RIGHT], "ttl_seconds": 60}

    def post(_slot):
        try:
            return httpx.post(authority_http + "/v1/capabilities/issue", json=body, timeout=30)
        except Exception as exc:
            return exc

    with ThreadPoolExecutor(max_workers=200) as pool:
        results = list(pool.map(post, range(200)))
    connection_errors = [result for result in results if isinstance(result, Exception)]
    assert connection_errors == []
    assert len(results) == 200
    assert all(result.status_code == 200 and result.json()["status"] == "ok" for result in results)


def test_issue_is_idempotent_by_correlation_id(monkeypatch, tmp_path):
    index = EvidenceIndex(tmp_path / "index.json")
    warehouse = EvidenceWarehouse(tmp_path / "evidence.db")
    monkeypatch.setattr(idxmod, "get_index", lambda: index)
    monkeypatch.setattr(whmod, "get_warehouse", lambda: warehouse)
    monkeypatch.setattr(busmod, "BUS", _RecordingBus(index))
    monkeypatch.setenv("PLANE_ISSUANCE_IDEMPOTENCY_PATH", str(tmp_path / "issuance.sqlite"))
    reset_issuance_store_for_tests()
    body = {"correlation_id": "issue-corr-1", "rights": [RIGHT], "ttl_seconds": 60}
    first = handle_issue(body)
    second = handle_issue(dict(body))
    assert first["status"] == "ok"
    assert second["status"] == "ok"
    assert second["idempotent_replay"] is True
    assert second["capability"] == first["capability"]
    assert second["signature"] == first["signature"]
    assert second["capability"]["id"] == first["capability"]["id"]

    changed = handle_issue({**body, "ttl_seconds": 30})
    assert changed["status"] == "error"
    assert changed["error"] == "issue_correlation_replay_conflict"
    assert "capability" not in changed

    def once(_slot):
        return handle_issue({
            "correlation_id": "issue-corr-race",
            "rights": [RIGHT],
            "ttl_seconds": 60,
        })

    with ThreadPoolExecutor(max_workers=64) as pool:
        results = list(pool.map(once, range(64)))
    assert all(result["status"] == "ok" for result in results)
    assert len({result["capability"]["id"] for result in results}) == 1
    assert len({result["signature"] for result in results}) == 1
    assert sum(result.get("idempotent_replay") is False for result in results) == 1


def test_methodless_rights_are_rejected():
    denied = handle_issue({
        "rights": [{"type": "read", "resource": "demo"}],
        "ttl_seconds": 60,
    })
    assert denied["status"] == "error"
    assert "method" in denied["error"]
    assert "capability" not in denied


def test_cryptography_is_declared_in_requirements():
    root = Path(__file__).resolve().parents[1]
    for name in ("requirements.txt", "requirements-lab.txt", "requirements-spiffe.txt"):
        text = (root / name).read_text(encoding="utf-8")
        assert any(line.split(">=", 1)[0].strip() == "cryptography" or line.startswith("cryptography")
                   for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))


def test_rfc8785_is_declared_in_requirements():
    root = Path(__file__).resolve().parents[1]
    for name in ("requirements.txt", "requirements-lab.txt", "requirements-spiffe.txt"):
        text = (root / name).read_text(encoding="utf-8")
        assert any(line.startswith("rfc8785") for line in text.splitlines())


def test_default_listen_port_does_not_clash_with_cyclekernal():
    assert DEFAULT_PORT != 8090
    assert DEFAULT_PORT == 8095
    gateway = Path(__file__).resolve().parents[1].joinpath("gateway/https_front_door.py").read_text(encoding="utf-8")
    assert "127.0.0.1:8095" in gateway
    assert "127.0.0.1:8090" not in gateway
