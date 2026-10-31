from __future__ import annotations

import pytest

from plane_service.policy import PolicyEngine, PolicyError


def test_allows_reviewed_minimal_rights():
    PolicyEngine().authorize(
        "spiffe://prod/agent/avrone",
        [{"type": "Execute", "resource": "tool.echo", "method": "POST"}],
        {},
        60,
    )


@pytest.mark.parametrize("rights", [
    [{"type": "Execute", "resource": "tool.echo", "method": "GET"}],
    [{"type": "Execute", "resource": "shell", "method": "POST"}],
    [{"type": "Execute", "resource": "docker.sock", "method": "POST"}],
    [{"type": "Execute", "resource": "tool.arbitrary", "method": "POST"}],
    [{"type": "admin", "resource": "*", "method": "*"}],
    [{"type": "read", "resource": "demo", "method": "GET", "unexpected": True}],
    [{"type": "read", "resource": "demo"}],
    [],
    "not-a-list",
])
def test_denies_unapproved_or_malformed_rights(rights):
    with pytest.raises(PolicyError):
        PolicyEngine().authorize(
            "spiffe://prod/agent/avrone", rights, {}, 60
        )


@pytest.mark.parametrize("ttl", [0, -1, 301, True, "60"])
def test_rejects_invalid_ttl(ttl):
    with pytest.raises(PolicyError):
        PolicyEngine().authorize(
            "spiffe://prod/agent/avrone",
            [{"type": "read", "resource": "demo", "method": "GET"}],
            {},
            ttl,
        )


def test_rejects_untrusted_identity():
    with pytest.raises(PolicyError):
        PolicyEngine().authorize(
            "spiffe://evil/agent/avrone",
            [{"type": "read", "resource": "demo", "method": "GET"}],
            {},
            60,
        )


def test_explicit_allowlist_can_be_narrowed():
    policy = PolicyEngine(allowed_rights={("read", "demo", "GET")})
    policy.authorize(
        "spiffe://prod/agent/avrone",
        [{"type": "read", "resource": "demo", "method": "GET"}],
        {},
        60,
    )
    with pytest.raises(PolicyError):
        policy.authorize(
            "spiffe://prod/agent/avrone",
            [{"type": "Execute", "resource": "tool.echo", "method": "POST"}],
            {},
            60,
        )
