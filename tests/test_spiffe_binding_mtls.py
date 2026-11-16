import pytest

from plane_service.spiffe_binding import SpiffeBindingError, bind_issue_request


def test_production_binds_caller_to_authenticated_mtls_peer(monkeypatch):
    monkeypatch.setenv("PRODUCTION", "1")
    monkeypatch.setenv("PLANE_TRUST_DOMAIN", "prod")
    monkeypatch.setenv("PLANE_ALLOWED_TRUST_DOMAINS", "prod")
    body = {"caller": "spiffe://prod/agent/forged", "rights": []}

    bound = bind_issue_request(
        body, authenticated_caller="spiffe://prod/agent/avrone-worker"
    )

    assert bound["caller"] == "spiffe://prod/agent/avrone-worker"
    assert bound["_identity_source"] == "mtls-peer"
    assert bound["_trust_domain"] == "prod"


@pytest.mark.parametrize(
    "peer",
    [None, "", "not-a-spiffe-id", "spiffe://evil/agent/worker", "spiffe://prod/broker/other"],
)
def test_production_rejects_missing_or_untrusted_mtls_peer(monkeypatch, peer):
    monkeypatch.setenv("PRODUCTION", "1")
    monkeypatch.setenv("PLANE_TRUST_DOMAIN", "prod")
    monkeypatch.setenv("PLANE_ALLOWED_TRUST_DOMAINS", "prod")

    with pytest.raises(SpiffeBindingError):
        bind_issue_request({"caller": "spiffe://prod/agent/forged"}, authenticated_caller=peer)


def test_development_keeps_existing_binding_path(monkeypatch):
    monkeypatch.delenv("PRODUCTION", raising=False)
    monkeypatch.delenv("PLANE_PRODUCTION", raising=False)
    monkeypatch.delenv("SPIFFE_REQUIRED", raising=False)
    monkeypatch.setenv("PLANE_SPIFFE_ID", "spiffe://prod/agent/dev")
    monkeypatch.delenv("PLANE_ALLOW_CALLER_OVERRIDE", raising=False)

    bound = bind_issue_request({"caller": "spiffe://prod/agent/forged"})

    assert bound["caller"] == "spiffe://prod/agent/dev"
    assert bound["_identity_source"] == "env"
