import os
import stat

import pytest

import plane_service.crypto_sign as crypto_sign


def test_production_refuses_to_generate_missing_signing_key(tmp_path, monkeypatch):
    key_path = tmp_path / "missing-production-key.pem"
    monkeypatch.setenv("PLANE_SIGNING_KEY", str(key_path))
    monkeypatch.setenv("PRODUCTION", "1")
    monkeypatch.delenv("PLANE_PRODUCTION", raising=False)
    monkeypatch.setattr(crypto_sign, "_KEY", None)
    monkeypatch.setattr(crypto_sign, "_PUB", None)
    with pytest.raises(RuntimeError, match="refusing to generate an ephemeral trust root"):
        crypto_sign.public_key_b64()
    assert not key_path.exists()


def test_development_key_generation_is_private_and_reusable(tmp_path, monkeypatch):
    key_path = tmp_path / "dev-key.pem"
    monkeypatch.setenv("PLANE_SIGNING_KEY", str(key_path))
    monkeypatch.setenv("PRODUCTION", "0")
    monkeypatch.setenv("PLANE_PRODUCTION", "0")
    monkeypatch.setattr(crypto_sign, "_KEY", None)
    monkeypatch.setattr(crypto_sign, "_PUB", None)
    first = crypto_sign.public_key_b64()
    assert key_path.exists()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    monkeypatch.setattr(crypto_sign, "_KEY", None)
    monkeypatch.setattr(crypto_sign, "_PUB", None)
    assert crypto_sign.public_key_b64() == first
