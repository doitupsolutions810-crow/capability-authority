"""Ed25519 signing with fail-closed production key loading.

Production deployments must provision a stable private key out of band. Only
non-production runs may create a local development key automatically.
"""
import base64
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

_KEY = None
_PUB = None


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _is_production():
    return os.environ.get("PRODUCTION", "0") == "1" or os.environ.get("PLANE_PRODUCTION", "0") == "1"


def _read_key(path, production):
    if production:
        if path.is_symlink():
            raise RuntimeError("production signing key must not be a symlink")
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            raise RuntimeError("production signing key is not accessible") from exc
        if mode & 0o077:
            raise RuntimeError("production signing key permissions must be 0600 or stricter")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise RuntimeError("signing key could not be loaded") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("signing key must be Ed25519")
    return key


def _load():
    global _KEY, _PUB
    path = Path(os.environ.get("PLANE_SIGNING_KEY", "config/broker_ed25519.pem"))
    production = _is_production()

    if _KEY is not None:
        if production:
            if not path.is_file() or path.is_symlink():
                raise RuntimeError("production signing key must be a provisioned regular file")
            _read_key(path, production=True)
        return _KEY

    if path.exists() or path.is_symlink():
        _KEY = _read_key(path, production)
    else:
        if production:
            raise RuntimeError(
                "production signing key is missing; provision PLANE_SIGNING_KEY before startup"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # Another local process initialized the development key first.
            _KEY = _read_key(path, production=False)
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(pem)
                handle.flush()
                os.fsync(handle.fileno())
            _KEY = key

    _PUB = _KEY.public_key()
    return _KEY


def sign(cap):
    return base64.b64encode(_load().sign(canonical(cap))).decode()


def verify_sig(cap, sig_b64):
    _load()
    try:
        _PUB.verify(base64.b64decode(sig_b64), canonical(cap))
        return True
    except Exception:
        return False


def public_key_b64():
    _load()
    raw = _PUB.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()
