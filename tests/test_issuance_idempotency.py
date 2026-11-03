"""Persisted issuance idempotency: replay, conflict, expiry, and corruption."""
from __future__ import annotations

import base64
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plane_service import server
from plane_service.crypto_sign import canonical, sign, verify_sig
from plane_service.issuance_idempotency import (
    IssuanceIdempotencyConflict,
    IssuanceIdempotencyCorrupt,
    IssuanceIdempotencyExpired,
    IssuanceIdempotencyStore,
    get_issuance_store,
    reset_issuance_store_for_tests,
)

REQUESTER = "spiffe://prod/agent/avrone"
SWARM = "spiffe://prod/agent/swarm"
RIGHT = {"type": "Execute", "resource": "swarm.jobs", "method": "POST"}


def _fingerprint(method: str) -> str:
    import hashlib
    digest = hashlib.sha256(canonical({
        "operation": "delegate",
        "rights": [{"type": "Execute", "resource": "swarm.jobs", "method": method}],
    })).hexdigest()
    return "sha256:" + digest


def _capability(capability_id: str, expires_at: float, method: str = "POST") -> dict:
    return {
        "id": capability_id,
        "audience": SWARM,
        "rights": [{"type": "Execute", "resource": "swarm.jobs", "method": method}],
        "expires_at": expires_at,
    }


class MemoryIndex:
    def __init__(self):
        self.rows = []
        self.lock = threading.Lock()

    def query(self, **filters):
        limit = filters.pop("limit", None)
        with self.lock:
            matched = [
                dict(row) for row in self.rows
                if all(row.get(key) == value for key, value in filters.items() if value is not None)
            ]
        if isinstance(limit, int) and limit >= 0:
            return matched[:limit]
        return matched

    def append_event(self, event):
        with self.lock:
            event_id = event.get("event_id")
            existing = next((row for row in self.rows if row.get("event_id") == event_id), None)
            if existing is not None:
                if existing != event:
                    raise ValueError("event_id was already committed with a different payload")
                return {"durable": True, "idempotent_replay": True}
            self.rows.append(dict(event))
            return {"durable": True}


def test_concurrent_duplicates_persist_one_assertion(tmp_path):
    store = IssuanceIdempotencyStore(tmp_path / "issuance.sqlite")
    mints = {"n": 0}

    def mint():
        mints["n"] += 1
        return _capability("cap-concurrent", 10_000.0), "sig-concurrent"

    barrier = threading.Barrier(8)

    def attempt(_slot):
        barrier.wait()
        return store.commit_or_replay(
            correlation_id="corr-concurrent",
            fingerprint=_fingerprint("POST"),
            assertion_jti="jti-concurrent",
            now=1.0,
            mint=mint,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert mints["n"] == 1
    assert sum(created for _record, created in results) == 1
    canonical_forms = {record.capability_canonical for record, _created in results}
    assert canonical_forms == {canonical(_capability("cap-concurrent", 10_000.0))}
    assert {record.signature for record, _created in results} == {"sig-concurrent"}


def test_restart_between_issue_and_response_returns_identical_bytes(tmp_path):
    path = tmp_path / "issuance.sqlite"
    store = IssuanceIdempotencyStore(path)
    issued = {}

    def mint():
        capability = _capability("cap-restart", 10_000.0)
        return capability, "sig-restart"

    def lose_response(record):
        issued["canonical"] = record.capability_canonical
        issued["signature"] = record.signature
        raise RuntimeError("lost response after durable issue")

    store.after_commit = lose_response
    with pytest.raises(RuntimeError, match="lost response"):
        store.commit_or_replay(
            correlation_id="corr-restart",
            fingerprint=_fingerprint("POST"),
            assertion_jti="jti-restart",
            now=1.0,
            mint=mint,
        )
    reopened = IssuanceIdempotencyStore(path)

    def remint():
        raise AssertionError("restart reminted a second assertion")

    record, created = reopened.commit_or_replay(
        correlation_id="corr-restart",
        fingerprint=_fingerprint("POST"),
        assertion_jti="jti-restart",
        now=1.0,
        mint=remint,
    )
    assert created is False
    assert record.capability_canonical == issued["canonical"]
    assert record.signature == issued["signature"]
    assert record.capability_canonical == canonical(record.capability)


def test_reusing_a_key_with_a_different_method_is_rejected(tmp_path):
    store = IssuanceIdempotencyStore(tmp_path / "issuance.sqlite")
    store.commit_or_replay(
        correlation_id="corr-method",
        fingerprint=_fingerprint("POST"),
        assertion_jti="jti-method",
        now=1.0,
        mint=lambda: (_capability("cap-method", 10_000.0, "POST"), "sig-method"),
    )
    mints = {"n": 0}

    def remint():
        mints["n"] += 1
        return _capability("cap-other", 10_000.0, "GET"), "sig-other"

    with pytest.raises(IssuanceIdempotencyConflict):
        store.commit_or_replay(
            correlation_id="corr-method",
            fingerprint=_fingerprint("GET"),
            assertion_jti="jti-method-2",
            now=1.0,
            mint=remint,
        )
    assert mints["n"] == 0
    assert _fingerprint("POST") != _fingerprint("GET")
    stored = store.lookup("corr-method")
    assert stored is not None
    assert stored.signature == "sig-method"
    assert stored.capability["rights"][0]["method"] == "POST"


def test_expired_entries_do_not_mint_a_replacement(tmp_path):
    store = IssuanceIdempotencyStore(tmp_path / "issuance.sqlite")
    store.commit_or_replay(
        correlation_id="corr-expiry",
        fingerprint=_fingerprint("POST"),
        assertion_jti="jti-expiry",
        now=1.0,
        mint=lambda: (_capability("cap-expiry", 100.0), "sig-expiry"),
    )
    mints = {"n": 0}

    def remint():
        mints["n"] += 1
        return _capability("cap-replacement", 500.0), "sig-replacement"

    with pytest.raises(IssuanceIdempotencyExpired) as caught:
        store.commit_or_replay(
            correlation_id="corr-expiry",
            fingerprint=_fingerprint("POST"),
            assertion_jti="jti-expiry",
            now=100.0,
            mint=remint,
        )
    assert mints["n"] == 0
    assert caught.value.record.capability["id"] == "cap-expiry"
    assert caught.value.record.signature == "sig-expiry"
    tombstone = store.lookup("corr-expiry")
    assert tombstone is not None
    assert tombstone.capability["id"] == "cap-expiry"


def test_storage_corruption_fails_closed_without_issuing(tmp_path):
    path = tmp_path / "issuance.sqlite"
    store = IssuanceIdempotencyStore(path)
    store.commit_or_replay(
        correlation_id="corr-corrupt",
        fingerprint=_fingerprint("POST"),
        assertion_jti="jti-corrupt",
        now=1.0,
        mint=lambda: (_capability("cap-corrupt", 10_000.0), "sig-corrupt"),
    )
    with sqlite3.connect(path) as conn:
        original = conn.execute("SELECT capability_json FROM issuance_idempotency").fetchone()[0]
        flipped = original[:-1] + ("A" if original[-1] != "A" else "B")
        conn.execute("UPDATE issuance_idempotency SET capability_json = ?", (flipped,))
    mints = {"n": 0}

    def remint():
        mints["n"] += 1
        return _capability("cap-new", 10_000.0), "sig-new"

    reopened = IssuanceIdempotencyStore(path)
    with pytest.raises(IssuanceIdempotencyCorrupt):
        reopened.lookup("corr-corrupt")
    with pytest.raises(IssuanceIdempotencyCorrupt):
        reopened.commit_or_replay(
            correlation_id="corr-corrupt",
            fingerprint=_fingerprint("POST"),
            assertion_jti="jti-corrupt",
            now=1.0,
            mint=remint,
        )
    assert mints["n"] == 0

    garbage = tmp_path / "garbage.sqlite"
    garbage.write_bytes(b"this is not an issuance ledger")
    with pytest.raises(IssuanceIdempotencyCorrupt):
        IssuanceIdempotencyStore(garbage).lookup("corr-corrupt")
    truncated = tmp_path / "truncated.sqlite"
    truncated.write_bytes(path.read_bytes()[:24])
    with pytest.raises(IssuanceIdempotencyCorrupt):
        IssuanceIdempotencyStore(truncated).lookup("corr-corrupt")


@pytest.fixture
def issuance_env(monkeypatch, tmp_path):
    requester_key = Ed25519PrivateKey.generate()
    public_file = tmp_path / "avrone.pub"
    public_file.write_bytes(requester_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    path = tmp_path / "issuance.sqlite"
    monkeypatch.setenv("PLANE_DELEGATION_REQUESTER_ID", REQUESTER)
    monkeypatch.setenv("PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE", str(public_file))
    monkeypatch.setenv("PLANE_DELEGATION_ALLOWED_AUDIENCES", SWARM)
    monkeypatch.setenv("PLANE_ISSUANCE_IDEMPOTENCY_PATH", str(path))
    reset_issuance_store_for_tests()
    index = MemoryIndex()
    import evidence.index as evidence_index
    monkeypatch.setattr(evidence_index, "get_index", lambda: index)
    monkeypatch.setattr(server, "_record_evidence", index.append_event)
    monkeypatch.setattr(server, "verify_sig", lambda cap, signature: signature == "parent-signature")
    monkeypatch.setattr(server, "sign", lambda cap: "child-signature")
    return requester_key, index, path


def _request(requester_key, **overrides):
    now = datetime.now(timezone.utc)
    unsigned = {
        "schema": "capability-authority.delegation-assertion/v1",
        "issuer": REQUESTER,
        "subject": REQUESTER,
        "audience": server.ISSUER,
        "jti": "jti-handler-idem-001",
        "issued_at": (now - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=20)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    assertion = {**unsigned, "signature": base64.b64encode(requester_key.sign(canonical(unsigned))).decode("ascii")}
    parent = {
        "id": "parent-001", "issuer": server.ISSUER, "audience": REQUESTER,
        "rights": [RIGHT], "constraints": {"tenant": "test-tenant", "delegation_audiences": [SWARM]},
        "issued_at": now.timestamp() - 10, "expires_at": now.timestamp() + 90,
        "trust_domain": "prod", "policy_version": 1, "delegation_depth": 0,
    }
    body = {
        "requester_assertion": assertion, "parent_capability": parent,
        "parent_signature": "parent-signature", "audience": SWARM,
        "rights": [RIGHT], "ttl_seconds": 120, "correlation_id": "corr-handler-idem",
    }
    body.update(overrides)
    return body


def test_handler_rejects_correlation_reuse_with_a_different_method(issuance_env):
    requester_key, index, path = issuance_env
    request = _request(requester_key)
    first = server.handle_delegate(request)
    assert first["status"] == "ok"
    changed = _request(requester_key)
    changed["rights"] = [{"type": "Execute", "resource": "swarm.jobs", "method": "GET"}]
    changed["requester_assertion"] = request["requester_assertion"]
    conflict = server.handle_delegate(changed)
    assert conflict["status"] == "error"
    assert conflict["error"] == "delegation_correlation_replay_conflict"
    assert len(index.rows) == 1
    stored = IssuanceIdempotencyStore(path).lookup(request["correlation_id"])
    assert stored is not None
    assert stored.signature == first["signature"]
    assert stored.capability["rights"][0]["method"] == "POST"


def test_handler_corruption_does_not_issue_another_capability(issuance_env, monkeypatch):
    requester_key, index, path = issuance_env
    calls = {"n": 0}
    real_issue = server.issue

    def counting_issue(*args, **kwargs):
        calls["n"] += 1
        return real_issue(*args, **kwargs)

    monkeypatch.setattr(server, "issue", counting_issue)
    request = _request(requester_key)
    first = server.handle_delegate(request)
    assert first["status"] == "ok"
    assert calls["n"] == 1
    with sqlite3.connect(path) as conn:
        payload = conn.execute("SELECT capability_json FROM issuance_idempotency").fetchone()[0]
        conn.execute(
            "UPDATE issuance_idempotency SET capability_json = ?",
            (payload[:-1] + ("A" if payload[-1] != "A" else "B"),),
        )
    reset_issuance_store_for_tests()
    corrupted = server.handle_delegate(request)
    assert corrupted["status"] == "error"
    assert corrupted["error"] == "issuance_idempotency_corrupt"
    assert "capability" not in corrupted
    assert calls["n"] == 1
    assert len(index.rows) == 1

    garbage = path.parent / "not-a-ledger.sqlite"
    garbage.write_bytes(b"not a database")
    monkeypatch.setenv("PLANE_ISSUANCE_IDEMPOTENCY_PATH", str(garbage))
    reset_issuance_store_for_tests()
    fresh = _request(requester_key)
    fresh["correlation_id"] = "corr-garbage"
    fresh["requester_assertion"] = dict(request["requester_assertion"])
    refused = server.handle_delegate(fresh)
    assert refused["error"] == "issuance_idempotency_corrupt"
    assert calls["n"] == 1


def test_handler_restart_between_issue_and_response_replays_signed_assertion(monkeypatch, tmp_path):
    requester_key = Ed25519PrivateKey.generate()
    public_file = tmp_path / "avrone.pub"
    public_file.write_bytes(requester_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    path = tmp_path / "issuance.sqlite"
    monkeypatch.setenv("PLANE_DELEGATION_REQUESTER_ID", REQUESTER)
    monkeypatch.setenv("PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE", str(public_file))
    monkeypatch.setenv("PLANE_DELEGATION_ALLOWED_AUDIENCES", SWARM)
    monkeypatch.setenv("PLANE_ISSUANCE_IDEMPOTENCY_PATH", str(path))
    reset_issuance_store_for_tests()
    index = MemoryIndex()
    import evidence.index as evidence_index
    monkeypatch.setattr(evidence_index, "get_index", lambda: index)
    monkeypatch.setattr(server, "_record_evidence", index.append_event)

    now = datetime.now(timezone.utc)
    unsigned = {
        "schema": "capability-authority.delegation-assertion/v1",
        "issuer": REQUESTER,
        "subject": REQUESTER,
        "audience": server.ISSUER,
        "jti": "jti-restart-handler",
        "issued_at": (now - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=20)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    assertion = {**unsigned, "signature": base64.b64encode(requester_key.sign(canonical(unsigned))).decode("ascii")}
    parent = {
        "id": "parent-restart", "issuer": server.ISSUER, "audience": REQUESTER,
        "rights": [RIGHT], "constraints": {"tenant": "test-tenant", "delegation_audiences": [SWARM]},
        "issued_at": now.timestamp() - 10, "expires_at": now.timestamp() + 90,
        "trust_domain": "prod", "policy_version": 1, "delegation_depth": 0,
    }
    request = {
        "requester_assertion": assertion,
        "parent_capability": parent,
        "parent_signature": sign(parent),
        "audience": SWARM,
        "rights": [RIGHT],
        "ttl_seconds": 60,
        "correlation_id": "corr-restart-handler",
    }
    assert verify_sig(parent, request["parent_signature"])

    def lose_response(_record):
        raise RuntimeError("lost response after durable issue")

    get_issuance_store().after_commit = lose_response
    with pytest.raises(RuntimeError, match="lost response"):
        server.handle_delegate(request)
    assert index.rows == []
    saved = IssuanceIdempotencyStore(path).lookup(request["correlation_id"])
    assert saved is not None
    reset_issuance_store_for_tests()
    replayed = server.handle_delegate(request)
    assert replayed["status"] == "ok"
    assert replayed["idempotent_replay"] is True
    assert replayed["signature"] == saved.signature
    assert canonical(replayed["capability"]) == saved.capability_canonical
    assert verify_sig(replayed["capability"], replayed["signature"])
    assert len(index.rows) == 1
    assert index.rows[0]["signature"] == saved.signature
    assert canonical(index.rows[0]["capability"]) == saved.capability_canonical
