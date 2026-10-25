"""Hash-chained evidence warehouse (SQLite)."""
import hashlib
import json
import sqlite3
from pathlib import Path


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(prev, event):
    h = hashlib.sha256()
    h.update(prev.encode())
    h.update(_canonical(event))
    return h.hexdigest()


def _logical_event(event):
    """Remove projection/receipt metadata when comparing an idempotent retry."""
    return {
        key: value for key, value in event.items()
        if key not in {"_indexed_at", "_digest", "_prev_digest"}
    }


class EvidenceWarehouse:
    def __init__(self, db_path=None):
        root = Path(__file__).resolve().parents[1]
        self.db_path = Path(db_path or root / "data" / "evidence.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.db_path), timeout=30) as c:
            c.execute("PRAGMA busy_timeout = 30000")
            c.execute(
                "CREATE TABLE IF NOT EXISTS evidence "
                "(id INTEGER PRIMARY KEY, payload TEXT, prev_digest TEXT, digest TEXT UNIQUE)"
            )
            columns = {row[1] for row in c.execute("PRAGMA table_info(evidence)")}
            if "event_id" not in columns:
                c.execute("ALTER TABLE evidence ADD COLUMN event_id TEXT")

            # Backfill identities for pre-migration rows. Refuse ambiguous
            # history rather than silently weakening the uniqueness contract.
            rows = c.execute(
                "SELECT id, payload FROM evidence WHERE event_id IS NULL"
            ).fetchall()
            for row_id, payload in rows:
                event = json.loads(payload)
                event_id = event.get("event_id") if isinstance(event, dict) else None
                if isinstance(event_id, str) and event_id.strip():
                    c.execute(
                        "UPDATE evidence SET event_id = ? WHERE id = ?",
                        (event_id, row_id),
                    )
            duplicates = c.execute(
                "SELECT event_id, COUNT(*) FROM evidence "
                "WHERE event_id IS NOT NULL GROUP BY event_id HAVING COUNT(*) > 1"
            ).fetchall()
            if duplicates:
                raise RuntimeError(
                    "cannot enforce evidence event identity; duplicate historical event_id values exist"
                )
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS evidence_event_id_unique "
                "ON evidence(event_id) WHERE event_id IS NOT NULL"
            )

    def append(self, event):
        event = dict(event)
        event_id = event.get("event_id")
        if event_id is not None:
            if not isinstance(event_id, str) or not event_id.strip():
                raise ValueError("event_id must be a non-empty string when provided")

        # BEGIN IMMEDIATE serializes idempotency lookup and chain-tip updates
        # across independent SQLite connections/processes.
        with sqlite3.connect(str(self.db_path), timeout=30) as c:
            c.execute("PRAGMA busy_timeout = 30000")
            c.execute("BEGIN IMMEDIATE")

            if event_id is not None:
                existing = c.execute(
                    "SELECT payload, prev_digest, digest FROM evidence WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing:
                    existing_event = json.loads(existing[0])
                    if _canonical(_logical_event(existing_event)) != _canonical(_logical_event(event)):
                        raise ValueError(
                            f"event_id {event_id!r} was already committed with a different payload"
                        )
                    c.commit()
                    result = dict(existing_event)
                    result["_digest"] = existing[2]
                    result["_prev_digest"] = existing[1]
                    result["_idempotent_replay"] = True
                    return result

            row = c.execute(
                "SELECT digest FROM evidence ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else "0" * 64
            digest = _digest(prev, event)
            c.execute(
                "INSERT INTO evidence (payload, prev_digest, digest, event_id) VALUES (?,?,?,?)",
                (json.dumps(event, default=str), prev, digest, event_id),
            )
            c.commit()

        result = dict(event)
        result["_digest"] = digest
        result["_prev_digest"] = prev
        result["_idempotent_replay"] = False
        return result

    def verify_chain(self):
        with sqlite3.connect(str(self.db_path), timeout=30) as c:
            rows = c.execute(
                "SELECT payload, prev_digest, digest, event_id FROM evidence ORDER BY id"
            ).fetchall()
        prev = "0" * 64
        for payload, prev_d, digest, stored_event_id in rows:
            if prev_d != prev:
                return {"ok": False, "error": "prev mismatch"}
            event = json.loads(payload)
            if event.get("event_id") != stored_event_id:
                return {"ok": False, "error": "event identity mismatch"}
            expect = _digest(prev, event)
            if expect != digest:
                return {"ok": False, "error": "digest mismatch"}
            prev = digest
        return {"ok": True, "length": len(rows), "tip": prev}


def get_warehouse():
    return EvidenceWarehouse()
