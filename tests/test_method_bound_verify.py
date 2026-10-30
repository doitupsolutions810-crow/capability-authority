from plane_service.core import verify


def _capability():
    return {
        "audience": "spiffe://prod/agent/avrone",
        "expires_at": 2_000_000_000,
        "rights": [
            {"type": "Execute", "resource": "task.run_tests", "method": "POST"}
        ],
    }


def test_verify_accepts_exact_method():
    assert verify(
        _capability(),
        {"type": "Execute", "resource": "task.run_tests", "method": "POST"},
        "spiffe://prod/agent/avrone",
        now_ts=1_900_000_000,
    )


def test_verify_rejects_different_method():
    assert not verify(
        _capability(),
        {"type": "Execute", "resource": "task.run_tests", "method": "DELETE"},
        "spiffe://prod/agent/avrone",
        now_ts=1_900_000_000,
    )


def test_verify_rejects_different_resource_even_with_same_method():
    assert not verify(
        _capability(),
        {"type": "Execute", "resource": "task.build_artifact", "method": "POST"},
        "spiffe://prod/agent/avrone",
        now_ts=1_900_000_000,
    )


def test_verify_preserves_resource_only_compatibility():
    assert verify(
        _capability(),
        {"type": "Execute", "resource": "task.run_tests"},
        "spiffe://prod/agent/avrone",
        now_ts=1_900_000_000,
    )


def test_verify_rejects_capability_at_exact_expiry():
    capability = _capability()
    capability["expires_at"] = 1_900_000_000
    assert not verify(
        capability,
        {"type": "Execute", "resource": "task.run_tests", "method": "POST"},
        "spiffe://prod/agent/avrone",
        now_ts=1_900_000_000,
    )
