#!/usr/bin/env python3
"""Focused regression tests for signing-key lifecycle safety."""
import importlib
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class SigningKeyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.saved_env = {key: os.environ.get(key) for key in ("PLANE_SIGNING_KEY", "PRODUCTION", "PLANE_PRODUCTION")}
        self.temp = tempfile.TemporaryDirectory()
        self.key_path = Path(self.temp.name) / "broker.pem"
        os.environ["PLANE_SIGNING_KEY"] = str(self.key_path)
        os.environ["PRODUCTION"] = "1"
        os.environ.pop("PLANE_PRODUCTION", None)
        import plane_service.crypto_sign as crypto_sign
        self.crypto_sign = importlib.reload(crypto_sign)

    def tearDown(self):
        for key, value in self.saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp.cleanup()
        self.crypto_sign._KEY = None
        self.crypto_sign._PUB = None

    def _write_key(self, mode=0o600):
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem)
        self.key_path.chmod(mode)

    def test_production_missing_key_fails_closed_without_generation(self):
        with self.assertRaisesRegex(RuntimeError, "missing"):
            self.crypto_sign._load()
        self.assertFalse(self.key_path.exists())

    def test_production_rejects_group_or_world_readable_key(self):
        self._write_key(0o644)
        with self.assertRaisesRegex(RuntimeError, "permissions"):
            self.crypto_sign._load()

    def test_production_accepts_preprovisioned_private_key(self):
        self._write_key(0o600)
        cap = {"resource": "demo", "type": "read"}
        signature = self.crypto_sign.sign(cap)
        self.assertTrue(self.crypto_sign.verify_sig(cap, signature))
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)

    def test_development_generation_uses_private_file_mode(self):
        os.environ["PRODUCTION"] = "0"
        self.crypto_sign._KEY = None
        self.crypto_sign._PUB = None
        self.crypto_sign._load()
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
