"""GitHub App installation-token helper. Production fails closed without App creds."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


class GitHubAppAuthError(RuntimeError):
    pass


def _b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint_app_jwt(app_id: str, pem: str) -> str:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise GitHubAppAuthError("cryptography required to mint GitHub App JWT") from exc

    now = int(time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}).encode())
    signing_input = f"{header}.{payload}".encode()
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(sig)}"


@dataclass(frozen=True)
class GitHubAppConfig:
    app_id: str
    installation_id: str
    private_key_pem: str
    allow_pat_fallback: bool = False


def load_config_from_env() -> GitHubAppConfig:
    app_id = os.environ.get("GITHUB_APP_ID", "").strip()
    inst = os.environ.get("GITHUB_APP_INSTALLATION_ID", "").strip()
    pem = os.environ.get("GITHUB_APP_PRIVATE_KEY", "").strip().replace("\\n", "\n")
    path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "").strip()
    if path and not pem:
        with open(path, encoding="utf-8") as fh:
            pem = fh.read()
    production = os.environ.get("PRODUCTION", "0") == "1"
    allow_pat = os.environ.get("GITHUB_ALLOW_PAT_FALLBACK", "0") == "1" and not production
    if not (app_id and inst and pem):
        if production or not allow_pat:
            raise GitHubAppAuthError(
                "FAIL_CLOSED: GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, and "
                "GITHUB_APP_PRIVATE_KEY[_PATH] required"
            )
        return GitHubAppConfig("", "", "", allow_pat_fallback=True)
    return GitHubAppConfig(app_id, inst, pem, allow_pat_fallback=False)


def installation_access_token(cfg: GitHubAppConfig | None = None) -> str:
    cfg = cfg or load_config_from_env()
    if cfg.allow_pat_fallback:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        if not token:
            raise GitHubAppAuthError("FAIL_CLOSED: no GitHub App creds and no GITHUB_TOKEN")
        return token
    jwt = mint_app_jwt(cfg.app_id, cfg.private_key_pem)
    url = f"https://api.github.com/app/installations/{cfg.installation_id}/access_tokens"
    req = urllib.request.Request(
        url,
        data=b"{}",
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "capability-authority-github-app",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise GitHubAppAuthError(f"installation token HTTP {exc.code}") from exc
    token = payload.get("token")
    if not token:
        raise GitHubAppAuthError("FAIL_CLOSED: installation token empty")
    return token
