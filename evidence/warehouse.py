"""Hash-chained evidence warehouse (SQLite)."""
import hashlib
import json
import sqlite3
from contextlib import closing
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


def _normalized_event_id(event):
    event_id = event.get("event_id") if isinstance(event, dict) else None
    return event_id if isinstance(event_id, str) and event_id.strip() else None


def _normalized_delegation_correlation_id(event):
    if not isinstance(event, dict) or event.get("message_type") != "CapabilityDelegated":
        return None
    correlation_id = event.get("correlation_id")
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        raise ValueError("CapabilityDelegated evidence requires a non-empty correlation_id")
    return correlation_id


class EvidenceWarehouse:
    # Genesis-to-tip scans. Issue traffic must not increment this after startup.
    full_ledger_verifications = 0

    def __init__(self, db_path=None):
        root = Path(__file__).resolve().parents[1]
        self.db_path = Path(db_path or root / "data" / "evidence.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(str(self.db_path), timeout=30)) as c:
            c.execute("PRAGMA busy_timeout = 30000")
            c.execute(
                "CREATE TABLE IF NOT EXISTS evidence "
                "(id INTEGER PRIMARY KEY, payload TEXT, prev_digest TEXT, digest TEXT UNIQUE)"
            )
            columns = {row[1] for row in c.execute("PRAGMA table_info(evidence)")}
            needs_identity_migration = "event_id" not in columns
            if needs_identity_migration:
                c.execute("ALTER TABLE evidence ADD COLUMN event_id TEXT")
                # Backfill only when introducing the column. Doing this on every
                # append would repeatedly scan all historical no-ID events.
                rows = c.execute(
                    "SELECT id, payload FROM evidence WHERE event_id IS NULL"
                ).fetchall()
                for row_id, payload in rows:
                    event = json.loads(payload)
                    event_id = _normalized_event_id(event)
                    if event_id is not None:
                        c.execute(
                            "UPDATE evidence SET event_id = ? WHERE id = ?",
                            (event_id, row_id),
                        )

            if "delegation_correlation_id" not in columns:
                c.execute("ALTER TABLE evidence ADD COLUMN delegation_correlation_id TEXT")
                # Backfill existing delegation records before adding the unique fence.
                rows = c.execute(
                    "SELECT id, payload FROM evidence WHERE delegation_correlation_id IS NULL"
                ).fetchall()
                for row_id, payload in rows:
                    event = json.loads(payload)
                    correlation_id = _normalized_delegation_correlation_id(event)
                    if correlation_id is not None:
                        c.execute(
                            "UPDATE evidence SET delegation_correlation_id = ? WHERE id = ?",
                            (correlation_id, row_id),
                        )

            delegation_index_exists = c.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                "AND name = 'evidence_delegation_correlation_unique'"
            ).fetchone()
            if not delegation_index_exists:
                duplicate_correlations = c.execute(
                    "SELECT delegation_correlation_id, COUNT(*) FROM evidence "
                    "WHERE delegation_correlation_id IS NOT NULL "
                    "GROUP BY delegation_correlation_id HAVING COUNT(*) > 1"
                ).fetchall()
                if duplicate_correlations:
                    raise RuntimeError(
                        "cannot enforce delegation correlation identity; duplicate historical correlation_id values exist"
                    )
                c.execute(
                    "CREATE UNIQUE INDEX evidence_delegation_correlation_unique "
                    "ON evidence(delegation_correlation_id) "
                    "WHERE delegation_correlation_id IS NOT NULL"
                )

            index_exists = c.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                "AND name = 'evidence_event_id_unique'"
            ).fetchone()
            if not index_exists:
                duplicates = c.execute(
                    "SELECT event_id, COUNT(*) FROM evidence "
                    "WHERE event_id IS NOT NULL GROUP BY event_id HAVING COUNT(*) > 1"
                ).fetchall()
                if duplicates:
                    raise RuntimeError(
                        "cannot enforce evidence event identity; duplicate historical event_id values exist"
                    )
                c.execute(
                    "CREATE UNIQUE INDEX evidence_event_id_unique "
                    "ON evidence(event_id) WHERE event_id IS NOT NULL"
                )
            c.commit()

    def append(self, event):
        event = dict(event)
        event_id = event.get("event_id")
        delegation_correlation_id = _normalized_delegation_correlation_id(event)
        if event_id is not None:
            if not isinstance(event_id, str) or not event_id.strip():
                raise ValueError("event_id must be a non-empty string when provided")

        # BEGIN IMMEDIATE serializes idempotency lookup and chain-tip updates
        # across independent SQLite connections/processes.
        with closing(sqlite3.connect(str(self.db_path), timeout=30)) as c:
            c.execute("PRAGMA busy_timeout = 30000")
            c.execute("BEGIN IMMEDIATE")

            if event_id is not None:
                existing = c.execute(
                    "SELECT payload, prev_digest, digest, delegation_correlation_id "
                    "FROM evidence WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing:
                    existing_event = json.loads(existing[0])
                    if _normalized_delegation_correlation_id(existing_event) != existing[3]:
                        raise ValueError("delegation correlation projection is inconsistent with evidence")
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

            if delegation_correlation_id is not None:
                existing_delegation = c.execute(
                    "SELECT event_id FROM evidence WHERE delegation_correlation_id = ?",
                    (delegation_correlation_id,),
                ).fetchone()
                if existing_delegation:
                    raise ValueError(
                        f"delegation correlation_id {delegation_correlation_id!r} was already committed"
                    )

            row = c.execute(
                "SELECT digest FROM evidence ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else "0" * 64
            digest = _digest(prev, event)
            c.execute(
                "INSERT INTO evidence "
                "(payload, prev_digest, digest, event_id, delegation_correlation_id) "
                "VALUES (?,?,?,?,?)",
                (json.dumps(event, default=str), prev, digest, event_id, delegation_correlation_id),
            )
            c.commit()

        result = dict(event)
        result["_digest"] = digest
        result["_prev_digest"] = prev
        result["_idempotent_replay"] = False
        return result

    def _project_linked_row(self, prev, payload, prev_d, digest, stored_event_id, stored_correlation_id):
        """Check one hash-chain link. ``prev`` is the digest the row must extend."""
        if prev_d != prev:
            raise ValueError("evidence warehouse chain is invalid: prev mismatch")
        event = json.loads(payload)
        if not isinstance(event, dict):
            raise ValueError("evidence warehouse chain is invalid: payload is not an object")
        if _normalized_event_id(event) != stored_event_id:
            raise ValueError("evidence warehouse chain is invalid: event identity mismatch")
        if _normalized_delegation_correlation_id(event) != stored_correlation_id:
            raise ValueError("evidence warehouse chain is invalid: delegation correlation identity mismatch")
        expected = _digest(prev, event)
        if expected != digest:
            raise ValueError("evidence warehouse chain is invalid: digest mismatch")
        projected = dict(event)
        projected["_digest"] = digest
        return projected, digest

    def read_verified_chain(self, after_id=0, expected_tip=None):
        """Verify the suffix after ``after_id``.

        ``after_id == 0`` walks every row from genesis and counts as a full
        verification. Later calls pass the last verified row id and its digest
        so only rows committed since that checkpoint are read and hashed.
        """
        if expected_tip is None:
            expected_tip = "0" * 64
        if isinstance(after_id, bool) or not isinstance(after_id, int) or after_id < 0:
            raise ValueError("evidence checkpoint row id is invalid")
        if not isinstance(expected_tip, str) or len(expected_tip) != 64:
            raise ValueError("evidence checkpoint tip is invalid")
        if after_id == 0:
            type(self).full_ledger_verifications += 1
        with closing(sqlite3.connect(str(self.db_path), timeout=30)) as c:
            c.execute("PRAGMA busy_timeout = 30000")
            c.execute("BEGIN")
            rows = c.execute(
                "SELECT id, payload, prev_digest, digest, event_id, delegation_correlation_id "
                "FROM evidence WHERE id > ? ORDER BY id",
                (after_id,),
            ).fetchall()

        prev = expected_tip
        events = []
        last_id = after_id
        for row_id, payload, prev_d, digest, stored_event_id, stored_correlation_id in rows:
            projected, prev = self._project_linked_row(
                prev, payload, prev_d, digest, stored_event_id, stored_correlation_id
            )
            events.append(projected)
            last_id = row_id
        return events, last_id, prev

    def read_verified_events(self):
        """Return the ordered ledger only after verifying identities and hashes."""
        events, _last_id, _tip = self.read_verified_chain()
        return events

    def verify_chain(self):
        with closing(sqlite3.connect(str(self.db_path), timeout=30)) as c:
            rows = c.execute(
                "SELECT payload, prev_digest, digest, event_id, delegation_correlation_id "
                "FROM evidence ORDER BY id"
            ).fetchall()
        prev = "0" * 64
        for payload, prev_d, digest, stored_event_id, stored_correlation_id in rows:
            if prev_d != prev:
                return {"ok": False, "error": "prev mismatch"}
            event = json.loads(payload)
            if _normalized_event_id(event) != stored_event_id:
                return {"ok": False, "error": "event identity mismatch"}
            try:
                correlation_id = _normalized_delegation_correlation_id(event)
            except ValueError:
                return {"ok": False, "error": "delegation correlation identity mismatch"}
            if correlation_id != stored_correlation_id:
                return {"ok": False, "error": "delegation correlation identity mismatch"}
            expect = _digest(prev, event)
            if expect != digest:
                return {"ok": False, "error": "digest mismatch"}
            prev = digest
        return {"ok": True, "length": len(rows), "tip": prev}


def get_warehouse():
    return EvidenceWarehouse()
