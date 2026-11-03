import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plane_service.crypto_sign import canonical
from plane_service.delegation import DelegationError, validate_delegation, verify_requester_assertion

REQUESTER = "spiffe://prod/agent/avrone"
BROKER = "spiffe://prod/broker"
SWARM = "spiffe://prod/agent/swarm"
RIGHT = {"type": "Execute", "resource": "swarm.jobs", "method": "POST"}


@pytest.fixture
def keys():
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public_pem


def assertion_for(private, now=None, **overrides):
    now = now or datetime.now(timezone.utc)
    unsigned = {
        "schema": "capability-authority.delegation-assertion/v1",
        "issuer": REQUESTER,
        "subject": REQUESTER,
        "audience": BROKER,
        "jti": "assertion-unique-001",
        "issued_at": (now - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=20)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        **overrides,
    }
    signature = base64.b64encode(private.sign(canonical(unsigned))).decode("ascii")
    return {**unsigned, "signature": signature}


def parent_for(now_ts, **overrides):
    return {
        "id": "parent-cap-1",
        "issuer": BROKER,
        "audience": REQUESTER,
        "rights": [RIGHT, {"type": "read", "resource": "demo", "method": "GET"}],
        "constraints": {"tenant": "test-tenant", "delegation_audiences": [SWARM]},
        "issued_at": now_ts - 10,
        "expires_at": now_ts + 30,
        "delegation_depth": 0,
        **overrides,
    }


def test_valid_short_lived_signed_requester_assertion(keys):
    private, public = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(private, now)
    assert verify_requester_assertion(assertion, public, expected_issuer=REQUESTER, expected_audience=BROKER, now=now) == "assertion-unique-001"


@pytest.mark.parametrize("field,value", [
    ("issuer", "spiffe://prod/agent/attacker"),
    ("subject", "spiffe://prod/agent/attacker"),
    ("audience", "spiffe://prod/agent/other"),
    ("jti", ""),
])
def test_rejects_spoofed_requester_identity_and_assertion_audience(keys, field, value):
    private, public = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(private, now, **{field: value})
    with pytest.raises(DelegationError):
        verify_requester_assertion(assertion, public, expected_issuer=REQUESTER, expected_audience=BROKER, now=now)


def test_rejects_tampered_signature_and_unknown_fields(keys):
    private, public = keys
    assertion = assertion_for(private)
    assertion["signature"] = base64.b64encode(b"x" * 64).decode()
    with pytest.raises(DelegationError, match="signature"):
        verify_requester_assertion(assertion, public, expected_issuer=REQUESTER, expected_audience=BROKER)
    assertion = assertion_for(private)
    assertion["caller"] = "spiffe://prod/agent/attacker"
    with pytest.raises(DelegationError, match="schema"):
        verify_requester_assertion(assertion, public, expected_issuer=REQUESTER, expected_audience=BROKER)


def test_rejects_expired_premature_and_overlong_assertions(keys):
    private, public = keys
    now = datetime.now(timezone.utc)
    expired = assertion_for(private, now, issued_at=(now - timedelta(seconds=80)).isoformat(timespec="milliseconds").replace("+00:00", "Z"), expires_at=(now - timedelta(seconds=40)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    premature = assertion_for(private, now, issued_at=(now + timedelta(minutes=2)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    overlong = assertion_for(private, now, expires_at=(now + timedelta(minutes=2)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    for assertion in (expired, premature, overlong):
        with pytest.raises(DelegationError):
            verify_requester_assertion(assertion, public, expected_issuer=REQUESTER, expected_audience=BROKER, now=now)


def test_delegation_attenuates_rights_and_caps_ttl_to_parent_remaining_lifetime():
    now = datetime.now(timezone.utc).timestamp()
    ttl = validate_delegation(parent_for(now), requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=120, allowed_audiences={SWARM}, now_ts=now)
    assert ttl == 30


def test_rejects_arbitrary_target_audience_and_spoofed_parent_subject():
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError, match="not allowlisted"):
        validate_delegation(parent_for(now), requester=REQUESTER, audience="spiffe://prod/agent/attacker", rights=[RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)
    with pytest.raises(DelegationError, match="audience"):
        validate_delegation(parent_for(now, audience="spiffe://prod/agent/attacker"), requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)


def test_rejects_rights_amplification_and_method_substitution():
    now = datetime.now(timezone.utc).timestamp()
    parent = parent_for(now)
    for right in [
        {"type": "Execute", "resource": "swarm.jobs", "method": "DELETE"},
        {"type": "Execute", "resource": "admin.root", "method": "POST"},
        {"type": "Execute", "resource": "swarm.jobs", "method": "*"},
    ]:
        with pytest.raises(DelegationError, match="exceed parent"):
            validate_delegation(parent, requester=REQUESTER, audience=SWARM, rights=[right], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)


def test_rejects_expired_parent_and_invalid_ttl():
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError, match="expired"):
        validate_delegation(parent_for(now, expires_at=now - 1), requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)
    for ttl in (True, 0, -1, 301, "30"):
        with pytest.raises(DelegationError):
            validate_delegation(parent_for(now), requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=ttl, allowed_audiences={SWARM}, now_ts=now)


def test_rejects_duplicate_rights_and_missing_parent_id():
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError, match="duplicate"):
        validate_delegation(parent_for(now), requester=REQUESTER, audience=SWARM, rights=[RIGHT, RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)
    with pytest.raises(DelegationError, match="id"):
        validate_delegation(parent_for(now, id=""), requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)


def test_rejects_future_parent_issue_time_and_excessive_delegation_depth():
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError, match="issue time"):
        validate_delegation(parent_for(now, issued_at=now + 120), requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)
    with pytest.raises(DelegationError, match="depth"):
        validate_delegation(parent_for(now, delegation_depth=3), requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)


def test_rejects_audience_not_scoped_by_parent_even_if_globally_allowlisted():
    now = datetime.now(timezone.utc).timestamp()
    parent = parent_for(now, constraints={"tenant": "test-tenant", "delegation_audiences": []})
    with pytest.raises(DelegationError, match="parent constraints"):
        validate_delegation(parent, requester=REQUESTER, audience=SWARM, rights=[RIGHT], ttl_seconds=30, allowed_audiences={SWARM}, now_ts=now)


@pytest.mark.parametrize("bad_jti", ["", " ", "bad\njti", "tab\tjti", "nul\x00jti", "x" * 129, "☃"])
def test_rejects_unsafe_or_oversized_assertion_ids(keys, bad_jti):
    private, public = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(private, now, jti=bad_jti)
    with pytest.raises(DelegationError):
        verify_requester_assertion(
            assertion, public, expected_issuer=REQUESTER,
            expected_audience=BROKER, now=now,
        )


def test_assertion_expiry_is_strict_at_the_exact_boundary(keys):
    private, public = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(
        private, now,
        expires_at=now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )
    with pytest.raises(DelegationError, match="expired"):
        verify_requester_assertion(
            assertion, public, expected_issuer=REQUESTER,
            expected_audience=BROKER, now=now,
        )


@pytest.mark.parametrize("skew", [True, -1, 121, "30", 1.5])
def test_rejects_invalid_clock_skew_configuration(keys, skew):
    private, public = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(private, now)
    with pytest.raises(DelegationError, match="clock skew"):
        verify_requester_assertion(
            assertion, public, expected_issuer=REQUESTER,
            expected_audience=BROKER, now=now, clock_skew_seconds=skew,
        )


@pytest.mark.parametrize("lifetime", [True, 0, 61, -1, "60"])
def test_rejects_invalid_assertion_lifetime_configuration(keys, lifetime):
    private, public = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(private, now)
    with pytest.raises(DelegationError, match="maximum lifetime"):
        verify_requester_assertion(
            assertion, public, expected_issuer=REQUESTER,
            expected_audience=BROKER, now=now, max_lifetime_seconds=lifetime,
        )


@pytest.mark.parametrize("bad_now", [float("nan"), float("inf"), -float("inf"), True, "1000", None])
def test_rejects_invalid_delegation_clock(bad_now):
    now = 1000.0
    with pytest.raises(DelegationError, match="clock"):
        validate_delegation(
            parent_for(now), requester=REQUESTER, audience=SWARM,
            rights=[RIGHT], ttl_seconds=10, allowed_audiences={SWARM},
            now_ts=bad_now,
        )


@pytest.mark.parametrize("bad_depth", [True, -1, 1.5, "0", None])
def test_rejects_invalid_parent_delegation_depth(bad_depth):
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError, match="depth"):
        validate_delegation(
            parent_for(now, delegation_depth=bad_depth), requester=REQUESTER,
            audience=SWARM, rights=[RIGHT], ttl_seconds=10,
            allowed_audiences={SWARM}, now_ts=now,
        )


@pytest.mark.parametrize("bad_parent_right", [
    {"type": [], "resource": "swarm.jobs", "method": "POST"},
    {"type": "Execute", "resource": {}, "method": "POST"},
    {"type": "Execute", "resource": "swarm.jobs", "method": []},
])
def test_malformed_parent_rights_never_crash_or_grant(bad_parent_right):
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError, match="exceed parent"):
        validate_delegation(
            parent_for(now, rights=[bad_parent_right]), requester=REQUESTER,
            audience=SWARM, rights=[RIGHT], ttl_seconds=10,
            allowed_audiences={SWARM}, now_ts=now,
        )


@pytest.mark.parametrize("bad_now", [float("nan"), float("inf"), -float("inf"), True, "1"])
def test_rejects_invalid_parent_clock_values(bad_now):
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError):
        validate_delegation(
            parent_for(now), requester=REQUESTER, audience=SWARM,
            rights=[RIGHT], ttl_seconds=10, allowed_audiences={SWARM},
            now_ts=now, max_ttl_seconds=bad_now,
        )


@pytest.mark.parametrize("bad_allowlist", [None, set(), ["not-a-spiffe-id"], {1}, "spiffe://prod/agent/swarm"])
def test_rejects_malformed_audience_allowlists(bad_allowlist):
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError, match="allowlist"):
        validate_delegation(
            parent_for(now), requester=REQUESTER, audience=SWARM,
            rights=[RIGHT], ttl_seconds=10, allowed_audiences=bad_allowlist,
            now_ts=now,
        )


def test_rejects_malformed_delegated_audience_scope():
    now = datetime.now(timezone.utc).timestamp()
    for scope in ([SWARM, 1], "spiffe://prod/agent/swarm", [None]):
        with pytest.raises(DelegationError, match="parent constraints"):
            validate_delegation(
                parent_for(now, constraints={"delegation_audiences": scope}),
                requester=REQUESTER, audience=SWARM, rights=[RIGHT],
                ttl_seconds=10, allowed_audiences={SWARM}, now_ts=now,
            )


def test_rejects_naive_verification_clock(keys):
    private, public = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(private, now)
    with pytest.raises(DelegationError, match="timezone-aware"):
        verify_requester_assertion(
            assertion, public, expected_issuer=REQUESTER,
            expected_audience=BROKER, now=datetime.now(),
        )


def test_rejects_oversized_pinned_public_key(keys):
    private, _ = keys
    now = datetime.now(timezone.utc)
    assertion = assertion_for(private, now)
    with pytest.raises(DelegationError, match="oversized"):
        verify_requester_assertion(
            assertion, b"x" * (16 * 1024 + 1), expected_issuer=REQUESTER,
            expected_audience=BROKER, now=now,
        )


@pytest.mark.parametrize("bad_identity", [
    "spiffe://", "spiffe:///agent/swarm", "spiffe://prod",
    "spiffe://user@prod/agent/swarm", "spiffe://prod:8080/agent/swarm",
    "spiffe://prod/agent/swarm?debug=1", "spiffe://PROD/agent/swarm",
    "spiffe://prod/agent/swarm#fragment",
])
def test_rejects_malformed_spiiffe_identity_authorities(bad_identity):
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(DelegationError):
        validate_delegation(
            parent_for(now), requester=REQUESTER, audience=bad_identity,
            rights=[RIGHT], ttl_seconds=10, allowed_audiences={bad_identity},
            now_ts=now,
        )
