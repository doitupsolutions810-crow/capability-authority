"""Hash-chained evidence warehouse (SQLite)."""
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(prev, event):
    h = hashlib.sha256()
    h.update(prev.encode())
    h.update(_canonical(event))
    return h.hexdigest()


class EvidenceWarehouse:
    def __init__(self, db_path=None):
        root = Path(__file__).resolve().parents[1]
        self.db_path = Path(db_path or root / "data" / "evidence.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.db_path), timeout=30) as c:
            c.execute("PRAGMA busy_timeout = 30000")
            c.execute("CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, payload TEXT, prev_digest TEXT, digest TEXT UNIQUE)")

    def append(self, event):
        # Serialize the read-tip -> derive-digest -> insert sequence. Without an
        # early write lock, concurrent callers can read the same tip and append
        # sibling rows, breaking the single hash-chain invariant.
        with sqlite3.connect(str(self.db_path), timeout=30) as c:
            c.execute("PRAGMA busy_timeout = 30000")
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT digest FROM evidence ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else "0" * 64
            digest = _digest(prev, event)
            c.execute(
                "INSERT INTO evidence (payload, prev_digest, digest) VALUES (?,?,?)",
                (json.dumps(event, default=str), prev, digest),
            )
            c.commit()
        result = dict(event)
        result["_digest"] = digest
        result["_prev_digest"] = prev
        return result

    def verify_chain(self):
        with sqlite3.connect(str(self.db_path), timeout=30) as c:
            rows = c.execute("SELECT payload, prev_digest, digest FROM evidence ORDER BY id").fetchall()
        prev = "0" * 64
        for payload, prev_d, digest in rows:
            if prev_d != prev:
                return {"ok": False, "error": "prev mismatch"}
            expect = _digest(prev, json.loads(payload))
            if expect != digest:
                return {"ok": False, "error": "digest mismatch"}
            prev = digest
        return {"ok": True, "length": len(rows), "tip": prev}


def get_warehouse():
    return EvidenceWarehouse()
