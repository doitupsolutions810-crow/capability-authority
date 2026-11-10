"""Durable idempotency for capability issuance, keyed by correlation id.

A completed entry stores the canonical signed assertion. A later call with the
same correlation id and the same request fingerprint returns those exact bytes
after process restart. The same key with a different fingerprint is rejected.
Expired entries stay as tombstones so a retry cannot mint a second assertion.
A corrupt store fails closed and never falls through to a fresh signature.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from plane_service.crypto_sign import canonical

_HEADER = b"SQLite format 3\x00"
_MAX_CORRELATION = 128
_MAX_FINGERPRINT = 256
_MAX_JTI = 128
_MAX_SIGNATURE = 512
_MAX_CAPABILITY_BYTES = 65536


class IssuanceIdempotencyError(Exception):
    pass


class IssuanceIdempotencyCorrupt(IssuanceIdempotencyError):
    pass


class IssuanceIdempotencyConflict(IssuanceIdempotencyError):
    pass


class IssuanceIdempotencyReplay(IssuanceIdempotencyError):
    """The assertion jti is already bound to a different correlation id."""


class IssuanceIdempotencyExpired(IssuanceIdempotencyError):
    def __init__(self, record: "IssuedAssertion"):
        super().__init__("issuance idempotency entry is expired")
        self.record = record


@dataclass(frozen=True)
class IssuedAssertion:
    correlation_id: str
    assertion_jti: str
    fingerprint: str
    capability: dict
    capability_canonical: bytes
    signature: str
    expires_at: float


def _integrity(correlation_id: str, assertion_jti: str, fingerprint: str, capability_json: str, signature: str) -> str:
    digest = hashlib.sha256()
    for part in (correlation_id, assertion_jti, fingerprint, capability_json, signature):
        raw = part.encode("utf-8")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _finite_timestamp(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise IssuanceIdempotencyCorrupt("stored capability expiry is invalid")
    return float(value)


class IssuanceIdempotencyStore:
    """SQLite ledger of signed issuance results.

    ``after_commit`` runs only after a new row is durable and the write lock
    has been released. Tests use it to drop the response after the assertion
    is already recoverable.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.after_commit: Optional[Callable[[IssuedAssertion], None]] = None
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._prepare()

    def lookup(self, correlation_id: str) -> Optional[IssuedAssertion]:
        self._check_correlation(correlation_id)
        with self._lock:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT correlation_id, assertion_jti, fingerprint, capability_json, signature, integrity "
                    "FROM issuance_idempotency WHERE correlation_id = ?",
                    (correlation_id,),
                ).fetchone()
        if row is None:
            return None
        return self._record_from_row(row)

    def commit_or_replay(
        self,
        *,
        correlation_id: str,
        fingerprint: str,
        assertion_jti: str,
        now: float,
        mint: Callable[[], tuple],
    ) -> tuple[IssuedAssertion, bool]:
        """Return the stored assertion. ``mint`` runs at most once for a new key."""
        self._check_correlation(correlation_id)
        self._check_fingerprint(fingerprint)
        self._check_jti(assertion_jti)
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise IssuanceIdempotencyError("issuance clock must be a finite number")

        created_record: Optional[IssuedAssertion] = None
        with self._lock:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                open_txn = True
                try:
                    row = conn.execute(
                        "SELECT correlation_id, assertion_jti, fingerprint, capability_json, signature, integrity "
                        "FROM issuance_idempotency WHERE correlation_id = ?",
                        (correlation_id,),
                    ).fetchone()
                    if row is not None:
                        record = self._record_from_row(row)
                        conn.commit()
                        open_txn = False
                    else:
                        taken = conn.execute(
                            "SELECT correlation_id FROM issuance_idempotency WHERE assertion_jti = ?",
                            (assertion_jti,),
                        ).fetchone()
                        if taken is not None:
                            conn.commit()
                            open_txn = False
                            raise IssuanceIdempotencyReplay(
                                "requester assertion jti is already bound to another correlation id"
                            )
                        capability, signature = mint()
                        record = self._normalize(
                            correlation_id, assertion_jti, fingerprint, capability, signature
                        )
                        conn.execute(
                            "INSERT INTO issuance_idempotency "
                            "(correlation_id, assertion_jti, fingerprint, capability_json, signature, integrity) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                record.correlation_id,
                                record.assertion_jti,
                                record.fingerprint,
                                record.capability_canonical.decode("utf-8"),
                                record.signature,
                                _integrity(
                                    record.correlation_id,
                                    record.assertion_jti,
                                    record.fingerprint,
                                    record.capability_canonical.decode("utf-8"),
                                    record.signature,
                                ),
                            ),
                        )
                        conn.commit()
                        open_txn = False
                        created_record = record
                except sqlite3.IntegrityError as exc:
                    if open_txn:
                        conn.rollback()
                    raise IssuanceIdempotencyReplay(
                        "requester assertion jti is already bound to another correlation id"
                    ) from exc
                except Exception:
                    if open_txn:
                        conn.rollback()
                    raise
        if created_record is None:
            self._reject_unless_replayable(record, fingerprint=fingerprint, now=now)
            return record, False
        if self.after_commit is not None:
            self.after_commit(created_record)
        return created_record, True

    def _reject_unless_replayable(self, record: IssuedAssertion, *, fingerprint: str, now: float) -> None:
        if record.fingerprint != fingerprint:
            raise IssuanceIdempotencyConflict(
                "correlation id was already used for a different issuance request"
            )
        if record.expires_at <= now:
            raise IssuanceIdempotencyExpired(record)

    def _normalize(self, correlation_id: str, assertion_jti: str, fingerprint: str, capability, signature) -> IssuedAssertion:
        if not isinstance(capability, dict):
            raise IssuanceIdempotencyError("issued capability must be an object")
        if not isinstance(signature, str) or not signature.strip() or len(signature) > _MAX_SIGNATURE:
            raise IssuanceIdempotencyError("issued capability signature is missing or oversized")
        try:
            encoded = canonical(capability)
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
            raise IssuanceIdempotencyError("issued capability is not canonical finite JSON") from exc
        if not isinstance(encoded, bytes):
            encoded = str(encoded).encode("utf-8")
        if len(encoded) > _MAX_CAPABILITY_BYTES:
            raise IssuanceIdempotencyError("issued capability exceeds the idempotency size bound")
        try:
            parsed = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise IssuanceIdempotencyError("issued capability canonical bytes are not JSON") from exc
        if not isinstance(parsed, dict) or canonical(parsed) != encoded:
            raise IssuanceIdempotencyError("issued capability canonical form is unstable")
        expires_at = _finite_timestamp(parsed.get("expires_at"))
        return IssuedAssertion(
            correlation_id=correlation_id,
            assertion_jti=assertion_jti,
            fingerprint=fingerprint,
            capability=parsed,
            capability_canonical=encoded,
            signature=signature,
            expires_at=expires_at,
        )

    def _record_from_row(self, row) -> IssuedAssertion:
        try:
            correlation_id = row["correlation_id"]
            assertion_jti = row["assertion_jti"]
            fingerprint = row["fingerprint"]
            capability_json = row["capability_json"]
            signature = row["signature"]
            integrity = row["integrity"]
        except (KeyError, IndexError, TypeError) as exc:
            raise IssuanceIdempotencyCorrupt("idempotency row is incomplete") from exc
        if not all(isinstance(part, str) for part in (correlation_id, assertion_jti, fingerprint, capability_json, signature, integrity)):
            raise IssuanceIdempotencyCorrupt("idempotency row has a non-text field")
        expected = _integrity(correlation_id, assertion_jti, fingerprint, capability_json, signature)
        if not hmac.compare_digest(expected, integrity):
            raise IssuanceIdempotencyCorrupt("idempotency row integrity check failed")
        try:
            encoded = capability_json.encode("utf-8")
            parsed = json.loads(encoded)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise IssuanceIdempotencyCorrupt("stored capability JSON is unreadable") from exc
        if not isinstance(parsed, dict):
            raise IssuanceIdempotencyCorrupt("stored capability is not an object")
        try:
            if canonical(parsed) != encoded:
                raise IssuanceIdempotencyCorrupt("stored capability is not canonical")
        except IssuanceIdempotencyCorrupt:
            raise
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
            raise IssuanceIdempotencyCorrupt("stored capability is not canonical finite JSON") from exc
        expires_at = _finite_timestamp(parsed.get("expires_at"))
        return IssuedAssertion(
            correlation_id=correlation_id,
            assertion_jti=assertion_jti,
            fingerprint=fingerprint,
            capability=parsed,
            capability_canonical=encoded,
            signature=signature,
            expires_at=expires_at,
        )

    def _prepare(self) -> None:
        with closing(self._connect(initializing=True)) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS issuance_idempotency ("
                "correlation_id TEXT PRIMARY KEY, "
                "assertion_jti TEXT NOT NULL, "
                "fingerprint TEXT NOT NULL, "
                "capability_json TEXT NOT NULL, "
                "signature TEXT NOT NULL, "
                "integrity TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS issuance_idempotency_jti "
                "ON issuance_idempotency(assertion_jti)"
            )
            columns = {info[1] for info in conn.execute("PRAGMA table_info(issuance_idempotency)")}
            expected = {
                "correlation_id", "assertion_jti", "fingerprint",
                "capability_json", "signature", "integrity",
            }
            if columns != expected:
                raise IssuanceIdempotencyCorrupt("idempotency store schema is not the issuance contract")
            conn.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise IssuanceIdempotencyCorrupt("idempotency store permissions could not be restricted") from exc

    def _connect(self, *, initializing: bool = False) -> sqlite3.Connection:
        self._reject_corrupt_file()
        try:
            conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        except sqlite3.DatabaseError as exc:
            raise IssuanceIdempotencyCorrupt("idempotency store cannot be opened") from exc
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout = 30000")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA journal_mode = DELETE")
            if self.path.exists() and self.path.stat().st_size > 0:
                checked = conn.execute("PRAGMA quick_check").fetchone()
                if checked is None or checked[0] != "ok":
                    raise IssuanceIdempotencyCorrupt("idempotency store failed integrity check")
        except IssuanceIdempotencyCorrupt:
            conn.close()
            raise
        except sqlite3.DatabaseError as exc:
            conn.close()
            raise IssuanceIdempotencyCorrupt("idempotency store failed integrity check") from exc
        if not initializing:
            try:
                present = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'issuance_idempotency'"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                conn.close()
                raise IssuanceIdempotencyCorrupt("idempotency store catalog is unreadable") from exc
            if present is None:
                conn.close()
                raise IssuanceIdempotencyCorrupt("idempotency store is missing its table")
        return conn

    def _reject_corrupt_file(self) -> None:
        if not self.path.exists():
            return
        try:
            size = self.path.stat().st_size
        except OSError as exc:
            raise IssuanceIdempotencyCorrupt("idempotency store is unreadable") from exc
        if size == 0:
            raise IssuanceIdempotencyCorrupt("idempotency store is empty")
        try:
            with self.path.open("rb") as handle:
                header = handle.read(16)
        except OSError as exc:
            raise IssuanceIdempotencyCorrupt("idempotency store is unreadable") from exc
        if header != _HEADER:
            raise IssuanceIdempotencyCorrupt("idempotency store header is invalid")

    @staticmethod
    def _check_correlation(correlation_id: str) -> None:
        if not isinstance(correlation_id, str) or not correlation_id.strip() or len(correlation_id) > _MAX_CORRELATION:
            raise IssuanceIdempotencyError("correlation_id must be a non-empty string up to 128 characters")
        if "\x00" in correlation_id:
            raise IssuanceIdempotencyError("correlation_id must not contain NUL")

    @staticmethod
    def _check_fingerprint(fingerprint: str) -> None:
        if not isinstance(fingerprint, str) or not fingerprint.strip() or len(fingerprint) > _MAX_FINGERPRINT:
            raise IssuanceIdempotencyError("issuance fingerprint is invalid")

    @staticmethod
    def _check_jti(assertion_jti: str) -> None:
        if not isinstance(assertion_jti, str) or not assertion_jti.strip() or len(assertion_jti) > _MAX_JTI:
            raise IssuanceIdempotencyError("assertion jti is invalid")
        if "\x00" in assertion_jti:
            raise IssuanceIdempotencyError("assertion jti must not contain NUL")


_STORE: Optional[IssuanceIdempotencyStore] = None
_STORE_PATH: Optional[Path] = None
_GUARD = threading.Lock()


def configured_issuance_path() -> Path:
    override = os.environ.get("PLANE_ISSUANCE_IDEMPOTENCY_PATH", "")
    if override:
        return Path(override)
    root = Path(__file__).resolve().parents[1]
    return root / "data" / "issuance_idempotency.sqlite"


def get_issuance_store() -> IssuanceIdempotencyStore:
    global _STORE, _STORE_PATH
    path = configured_issuance_path()
    with _GUARD:
        if _STORE is None or _STORE_PATH != path:
            _STORE = IssuanceIdempotencyStore(path)
            _STORE_PATH = path
        return _STORE


def reset_issuance_store_for_tests() -> None:
    global _STORE, _STORE_PATH
    with _GUARD:
        _STORE = None
        _STORE_PATH = None
