"""Ed25519 signing. Requires cryptography."""
import base64, os
import rfc8785
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

_KEY = None
_PUB = None

def canonical(obj):
    """RFC 8785 JSON Canonicalization Scheme shared with Node.js adapters."""
    return rfc8785.dumps(obj)

def _load():
    global _KEY, _PUB
    if _KEY is not None:
        return _KEY
    path = Path(os.environ.get("PLANE_SIGNING_KEY", "config/broker_ed25519.pem"))
    if path.exists():
        _KEY = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(_KEY, Ed25519PrivateKey):
            raise RuntimeError("configured signing key must be Ed25519")
    else:
        production = os.environ.get("PRODUCTION", "0") == "1" or os.environ.get("PLANE_PRODUCTION", "0") == "1"
        if production:
            raise RuntimeError("production signing key is missing; refusing to generate an ephemeral trust root")
        _KEY = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_KEY.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        path.chmod(0o600)
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
