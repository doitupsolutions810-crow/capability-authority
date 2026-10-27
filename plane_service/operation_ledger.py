"""Durable idempotency state for side-effecting execution requests.

The operation row is written to the same SQLite database as the evidence
warehouse, but it is a separate transaction. An in-progress or indeterminate
operation is never automatically executed again. Reconciliation may promote it
to completed only after finding a matching durable ExecuteReceipt in the ledger.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from contextlib import closing
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "evidence.db"


class OperationLedger:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execute_operations (
                    operation_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    result_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            connection.commit()

    def _connect(self):
        connection = sqlite3.connect(str(self.db_path), timeout=30)
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @staticmethod
    def _row(row: tuple[Any, ...]) -> dict[str, Any]:
        operation_id, request_digest, state, result_json, created_at, updated_at = row
        try:
            result = json.loads(result_json) if result_json else None
        except (TypeError, ValueError):
            result = None
        return {
            "operation_id": operation_id,
            "request_digest": request_digest,
            "state": state,
            "result": result,
            "created_at": created_at,
            "updated_at": updated_at,
        }

    def claim(self, operation_id: str, request_digest: str) -> dict[str, Any]:
        """Atomically claim new work or return the existing operation state."""
        now = time.time()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT operation_id, request_digest, state, result_json, created_at, updated_at "
                "FROM execute_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO execute_operations "
                    "(operation_id, request_digest, state, result_json, created_at, updated_at) "
                    "VALUES (?, ?, 'in_progress', NULL, ?, ?)",
                    (operation_id, request_digest, now, now),
                )
                connection.commit()
                return {"operation_id": operation_id, "request_digest": request_digest, "state": "claimed", "result": None}
            existing = self._row(row)
            if existing["request_digest"] != request_digest:
                connection.commit()
                return {**existing, "state": "conflict", "result": None}
            if existing["state"] == "not_started":
                connection.execute(
                    "UPDATE execute_operations SET state='in_progress', updated_at=? WHERE operation_id=?",
                    (now, operation_id),
                )
                connection.commit()
                return {**existing, "state": "claimed", "result": None}
            connection.commit()
            return existing

    def mark_not_started(self, operation_id: str, request_digest: str) -> None:
        """Allow retry only when intent persistence failed before execution began."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE execute_operations SET state='not_started', updated_at=? "
                "WHERE operation_id=? AND request_digest=? AND state='in_progress'",
                (time.time(), operation_id, request_digest),
            )
            connection.commit()

    def mark_indeterminate(self, operation_id: str, request_digest: str) -> None:
        """Persist an uncertain outcome; it must not trigger automatic re-execution."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE execute_operations SET state='indeterminate', updated_at=? "
                "WHERE operation_id=? AND request_digest=? AND state!='completed'",
                (time.time(), operation_id, request_digest),
            )
            connection.commit()

    def complete(self, operation_id: str, request_digest: str, result: dict[str, Any]) -> None:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE execute_operations SET state='completed', result_json=?, updated_at=? "
                "WHERE operation_id=? AND request_digest=?",
                (encoded, time.time(), operation_id, request_digest),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise RuntimeError("operation completion did not match the claimed operation")
            connection.commit()
