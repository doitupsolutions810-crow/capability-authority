import pytest

from plane_service import spiffe_binding
from plane_service.spiffe_identity import WorkloadIdentity


def _identity(source):
    return WorkloadIdentity(
        "spiffe://prod/agent/test",
        "prod",
        source=source,
        socket_reachable=(source == "workload-api"),
    )


@pytest.mark.parametrize("source", ["env", "fallback", "socket", "caller-override"])
def test_production_rejects_non_workload_api_identity(monkeypatch, source):
    monkeypatch.setenv("PRODUCTION", "1")
    monkeypatch.setenv("PLANE_ALLOW_CALLER_OVERRIDE", "1")
    monkeypatch.setattr(
        spiffe_binding, "fetch_workload_identity", lambda **kwargs: _identity(source)
    )

    with pytest.raises(spiffe_binding.SpiffeBindingError, match="requires a Workload API"):
        spiffe_binding.resolve_issue_identity(
            body_caller="spiffe://prod/agent/attacker"
        )


def test_production_accepts_workload_api_identity_and_ignores_body_caller(monkeypatch):
    monkeypatch.setenv("SPIFFE_REQUIRED", "1")
    monkeypatch.setenv("PLANE_ALLOW_CALLER_OVERRIDE", "1")
    expected = _identity("workload-api")
    monkeypatch.setattr(
        spiffe_binding, "fetch_workload_identity", lambda **kwargs: expected
    )

    actual = spiffe_binding.resolve_issue_identity(
        body_caller="spiffe://prod/agent/attacker"
    )

    assert actual is expected
    assert actual.spiffe_id == "spiffe://prod/agent/test"


def test_development_caller_override_remains_opt_in(monkeypatch):
    monkeypatch.delenv("PRODUCTION", raising=False)
    monkeypatch.delenv("PLANE_PRODUCTION", raising=False)
    monkeypatch.delenv("SPIFFE_REQUIRED", raising=False)
    monkeypatch.setenv("PLANE_ALLOW_CALLER_OVERRIDE", "1")
    monkeypatch.setattr(
        spiffe_binding, "fetch_workload_identity", lambda **kwargs: _identity("env")
    )

    actual = spiffe_binding.resolve_issue_identity(
        body_caller="spiffe://prod/agent/dev-override"
    )

    assert actual.source == "caller-override"
    assert actual.spiffe_id == "spiffe://prod/agent/dev-override"
