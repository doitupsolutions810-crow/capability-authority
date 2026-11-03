import base64
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plane_service import server
from plane_service import delegation
from plane_service.crypto_sign import canonical

REQUESTER = "spiffe://prod/agent/avrone"
SWARM = "spiffe://prod/agent/swarm"
RIGHT = {"type": "Execute", "resource": "swarm.jobs", "method": "POST"}


class MemoryIndex:
    def __init__(self):
        self.rows = []

    def query(self, **filters):
        return [
            row for row in self.rows
            if all(row.get(key) == value for key, value in filters.items() if value is not None)
        ]


@pytest.fixture
def delegation_env(monkeypatch, tmp_path):
    requester_key = Ed25519PrivateKey.generate()
    public_file = tmp_path / "avrone.pub"
    public_file.write_bytes(requester_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    monkeypatch.setenv("PLANE_DELEGATION_REQUESTER_ID", REQUESTER)
    monkeypatch.setenv("PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE", str(public_file))
    monkeypatch.setenv("PLANE_DELEGATION_ALLOWED_AUDIENCES", SWARM)
    index = MemoryIndex()
    import evidence.index as evidence_index
    monkeypatch.setattr(evidence_index, "get_index", lambda: index)
    monkeypatch.setattr(server, "_record_evidence", lambda event: index.rows.append(dict(event)) or {"durable": True})
    monkeypatch.setattr(server, "verify_sig", lambda cap, signature: signature == "parent-signature")
    monkeypatch.setattr(server, "sign", lambda cap: "child-signature")
    return requester_key, index


def make_request(requester_key, parent=None, **overrides):
    now = datetime.now(timezone.utc)
    unsigned = {
        "schema": "capability-authority.delegation-assertion/v1",
        "issuer": REQUESTER,
        "subject": REQUESTER,
        "audience": server.ISSUER,
        "jti": "jti-handler-test-001",
        "issued_at": (now - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=20)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    assertion = {**unsigned, "signature": base64.b64encode(requester_key.sign(canonical(unsigned))).decode("ascii")}
    parent = parent or {
        "id": "parent-001", "issuer": server.ISSUER, "audience": REQUESTER,
        "rights": [RIGHT], "constraints": {"tenant": "test-tenant", "delegation_audiences": [SWARM]},
        "issued_at": now.timestamp() - 10, "expires_at": now.timestamp() + 90,
        "trust_domain": "prod", "policy_version": 1, "delegation_depth": 0,
    }
    return {
        "requester_assertion": assertion, "parent_capability": parent,
        "parent_signature": "parent-signature", "audience": SWARM,
        "rights": [RIGHT], "ttl_seconds": 120, "correlation_id": "corr-handler-001",
        "caller": "spiffe://prod/agent/attacker", **overrides,
    }


def test_delegate_issues_attenuated_child_and_persists_before_return(delegation_env):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    parent_expiry = request["parent_capability"]["expires_at"]
    result = server.handle_delegate(request)
    assert result["status"] == "ok"
    child = result["capability"]
    assert child["audience"] == SWARM
    assert child["parent_id"] == "parent-001"
    assert child["rights"] == [RIGHT]
    assert child["constraints"] == {"tenant": "test-tenant", "delegation_audiences": [SWARM]}
    assert child["expires_at"] <= parent_expiry
    assert result["signature"] == "child-signature"
    assert len(index.rows) == 1
    assert index.rows[0]["message_type"] == "CapabilityDelegated"


def test_delegate_is_idempotent_for_same_correlation_and_request(delegation_env):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    first = server.handle_delegate(request)
    second = server.handle_delegate(request)
    assert first["capability"] == second["capability"]
    assert first["signature"] == second["signature"]
    assert second["idempotent_replay"] is True
    assert len(index.rows) == 1


def test_delegate_rejects_assertion_jti_replay_and_correlation_conflict(delegation_env):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    assert server.handle_delegate(request)["status"] == "ok"
    replay = server.handle_delegate({**request, "correlation_id": "corr-different"})
    assert "replay" in replay["error"]
    conflict = server.handle_delegate({**request, "ttl_seconds": 60})
    assert "correlation_replay_conflict" in conflict["error"]
    assert len(index.rows) == 1


@pytest.mark.parametrize("mutate,expected", [
    (lambda req: req.update(audience="spiffe://prod/agent/attacker"), "not allowlisted"),
    (lambda req: req.update(rights=[{"type": "Execute", "resource": "swarm.jobs", "method": "DELETE"}]), "exceed parent"),
    (lambda req: req["parent_capability"].update(audience="spiffe://prod/agent/attacker"), "audience"),
    (lambda req: req["parent_capability"].update(expires_at=1), "expired"),
])
def test_delegate_rejects_amplification_wrong_subject_and_expired_parent(delegation_env, mutate, expected):
    requester_key, _index = delegation_env
    request = make_request(requester_key)
    mutate(request)
    result = server.handle_delegate(request)
    assert result["status"] == "error"
    assert expected in result["error"]


def test_delegate_fails_closed_without_pinned_requester_key(monkeypatch, delegation_env):
    requester_key, _index = delegation_env
    monkeypatch.delenv("PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE")
    result = server.handle_delegate(make_request(requester_key))
    assert result["status"] == "error"
    assert "not configured" in result["error"]


def test_same_correlation_reconciles_after_parent_expiry(delegation_env, monkeypatch):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    first = server.handle_delegate(request)
    assert first["status"] == "ok"
    expiry = request["parent_capability"]["expires_at"]
    monkeypatch.setattr(server.time, "time", lambda: expiry + 1)
    second = server.handle_delegate(request)
    assert second["status"] == "error"
    assert second["error"] == "delegated_capability_expired"
    assert second["idempotent_replay"] is True
    assert second["capability_id"] == first["capability"]["id"]
    assert len(index.rows) == 1


def test_failed_durable_evidence_write_never_returns_capability(delegation_env, monkeypatch):
    requester_key, index = delegation_env
    def fail(_event):
        raise OSError("evidence volume unavailable")
    monkeypatch.setattr(server, "_record_evidence", fail)
    with pytest.raises(OSError, match="evidence volume unavailable"):
        server.handle_delegate(make_request(requester_key))
    assert index.rows == []


def test_parent_with_malformed_delegation_scope_is_rejected(delegation_env):
    requester_key, _index = delegation_env
    request = make_request(requester_key)
    request["parent_capability"]["constraints"]["delegation_audiences"] = "spiffe://prod/agent/swarm"
    result = server.handle_delegate(request)
    assert result["status"] == "error"
    assert "parent constraints" in result["error"]


def test_http_json_object_parser_rejects_duplicate_keys():
    with pytest.raises(ValueError, match="duplicate"):
        server._unique_json_object([("audience", SWARM), ("audience", "spiffe://prod/agent/attacker")])


def test_http_json_constant_parser_rejects_nan_and_infinity():
    for value in ("NaN", "Infinity", "-Infinity"):
        with pytest.raises(ValueError, match="non-finite"):
            server._reject_json_constant(value)


def test_delegation_evidence_has_stable_correlation_event_id(delegation_env):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    result = server.handle_delegate(request)
    assert result["status"] == "ok"
    expected = "delegation:" + hashlib.sha256(request["correlation_id"].encode("ascii")).hexdigest()
    assert index.rows[0]["event_id"] == expected


def test_same_correlation_with_fresh_assertion_jti_returns_original_child(delegation_env, monkeypatch):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    jtis = iter(["jti-first", "jti-first", "jti-retry"])
    monkeypatch.setattr(server, "verify_requester_assertion", lambda *a, **k: next(jtis))
    first = server.handle_delegate(request)
    second = server.handle_delegate(request)
    assert first["status"] == second["status"] == "ok"
    assert second["idempotent_replay"] is True
    assert second["capability"] == first["capability"]
    assert len(index.rows) == 1


def test_same_correlation_reconciles_after_requester_assertion_expiry(delegation_env, monkeypatch):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    original_now = server.time.time()
    first = server.handle_delegate(request)
    assert first["status"] == "ok"
    # Freeze both clocks: the assertion expires after 20 seconds while the
    # delegated child remains valid for the parent's remaining lifetime.
    real_datetime = delegation.datetime
    class ExpiredDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.fromtimestamp(original_now + 35, tz=tz)
    monkeypatch.setattr(delegation, "datetime", ExpiredDateTime)
    monkeypatch.setattr(server.time, "time", lambda: original_now + 35)
    second = server.handle_delegate(request)
    assert second["status"] == "ok"
    assert second["idempotent_replay"] is True
    assert second["capability"] == first["capability"]
    assert second["signature"] == first["signature"]
    assert len(index.rows) == 1


def test_expired_assertion_cannot_create_a_new_correlation(delegation_env, monkeypatch):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    original_now = server.time.time()
    real_datetime = delegation.datetime
    class ExpiredDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.fromtimestamp(original_now + 35, tz=tz)
    monkeypatch.setattr(delegation, "datetime", ExpiredDateTime)
    monkeypatch.setattr(server.time, "time", lambda: original_now + 35)
    result = server.handle_delegate(request)
    assert result["status"] == "error"
    assert result["error"] == "requester assertion is expired"
    assert index.rows == []


def test_expired_assertion_cannot_replay_same_correlation_with_changed_request(delegation_env, monkeypatch):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    original_now = server.time.time()
    first = server.handle_delegate(request)
    assert first["status"] == "ok"
    real_datetime = delegation.datetime
    class ExpiredDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.fromtimestamp(original_now + 35, tz=tz)
    monkeypatch.setattr(delegation, "datetime", ExpiredDateTime)
    monkeypatch.setattr(server.time, "time", lambda: original_now + 35)
    conflict = server.handle_delegate({**request, "ttl_seconds": 60})
    assert conflict["status"] == "error"
    assert conflict["error"] == "delegation_correlation_replay_conflict"
    assert len(index.rows) == 1


def test_expired_assertion_with_tampered_signature_cannot_retrieve_prior_result(delegation_env, monkeypatch):
    requester_key, index = delegation_env
    request = make_request(requester_key)
    original_now = server.time.time()
    first = server.handle_delegate(request)
    assert first["status"] == "ok"
    real_datetime = delegation.datetime
    class ExpiredDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.fromtimestamp(original_now + 35, tz=tz)
    monkeypatch.setattr(delegation, "datetime", ExpiredDateTime)
    monkeypatch.setattr(server.time, "time", lambda: original_now + 35)
    tampered = {**request, "requester_assertion": dict(request["requester_assertion"])}
    signature = tampered["requester_assertion"]["signature"]
    tampered["requester_assertion"]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    result = server.handle_delegate(tampered)
    assert result["status"] == "error"
    assert "signature" in result["error"]
    assert len(index.rows) == 1
