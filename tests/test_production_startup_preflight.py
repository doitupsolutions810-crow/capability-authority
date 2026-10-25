#!/usr/bin/env python3
"""Regression test that production server import validates signing identity."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProductionStartupPreflightTests(unittest.TestCase):
    def test_missing_production_key_prevents_server_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT)
            env["PRODUCTION"] = "1"
            env.pop("PLANE_PRODUCTION", None)
            env["PLANE_SIGNING_KEY"] = str(Path(tmp) / "missing.pem")
            proc = subprocess.run(
                [sys.executable, "-c", "import plane_service.server"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("production signing-key preflight failed", proc.stderr)
            self.assertFalse(Path(tmp, "missing.pem").exists())


if __name__ == "__main__":
    unittest.main()
