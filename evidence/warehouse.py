"""Hash-chained evidence warehouse (SQLite)."""
import hashlib, json, sqlite3, time, os
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
        with sqlite3.connect(str(self.db_path)) as c:
            c.execute("CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, payload TEXT, prev_digest TEXT, digest TEXT UNIQUE)")
    def append(self, event):
        with sqlite3.connect(str(self.db_path)) as c:
            c.row_factory = sqlite3.Row
            row = c.execute("SELECT digest FROM evidence ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["digest"] if row else "0"*64
            digest = _digest(prev, event)
            c.execute("INSERT INTO evidence (payload, prev_digest, digest) VALUES (?,?,?)", (json.dumps(event, default=str), prev, digest))
            c.commit()
        event = dict(event)
        event["_digest"] = digest
        event["_prev_digest"] = prev
        return event
    def verify_chain(self):
        with sqlite3.connect(str(self.db_path)) as c:
            rows = c.execute("SELECT payload, prev_digest, digest FROM evidence ORDER BY id").fetchall()
        prev = "0"*64
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
