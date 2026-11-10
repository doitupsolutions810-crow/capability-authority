import errno
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
INDEX_DB = Path(os.environ.get("EVIDENCE_INDEX_PATH", str(ROOT / "data" / "evidence_index.json")))


@contextmanager
def _interprocess_path_lock(path: Path):
    """Serialize projection refreshes across processes sharing this filesystem."""
    lock_path = path.with_name(f".{path.name}.lock")
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            retryable = {errno.EACCES, errno.EAGAIN, getattr(errno, "EDEADLK", errno.EACCES)}
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError as exc:
                    if exc.errno not in retryable:
                        raise
                    time.sleep(0.01)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
        yield
    finally:
        try:
            if locked:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


_GENESIS_TIP = "0" * 64


class EvidenceIndex:
    """Verified JSON projection over the authoritative hash-chained warehouse.

    The first refresh in a process verifies the ledger from genesis and
    rewrites the projection only when it differs. Later refreshes hash only
    rows committed after that checkpoint and append those objects to the
    projection. Writers sharing the path still serialize with the sidecar lock.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or INDEX_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._docs: List[dict] = self._read_projection()
        self._synced = False
        self._through_id = 0
        self._tip = _GENESIS_TIP

    def _read_projection(self) -> List[dict]:
        if not self.path.exists():
            return []
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"evidence index is unreadable; refusing to reset history: {self.path}") from exc
        if not isinstance(loaded, list) or any(not isinstance(item, dict) for item in loaded):
            raise ValueError(f"evidence index has invalid structure; refusing to reset history: {self.path}")
        return loaded

    def _write_atomic(self, docs: List[dict]) -> None:
        encoded = json.dumps(docs, indent=2, default=str).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(encoded)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self.path)
            dir_fd = os.open(str(self.path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass

    def _append_projection(self, new_docs: List[dict]) -> None:
        """Add verified events without rewriting the checkpointed prefix."""
        if not new_docs:
            return
        if not self.path.exists() or self.path.stat().st_size == 0:
            self._write_atomic(self._docs + new_docs)
            return
        pieces = [json.dumps(doc, indent=2, default=str).encode("utf-8") for doc in new_docs]
        with self.path.open("r+b") as handle:
            handle.seek(0, os.SEEK_END)
            end = handle.tell()
            window = min(end, 4096)
            handle.seek(end - window)
            tail = handle.read(window)
            relative = tail.rfind(b"]")
            if relative < 0:
                raise ValueError(
                    f"evidence index is unreadable; refusing to reset history: {self.path}"
                )
            absolute = end - window + relative
            before = tail[:relative].rstrip()
            empty = before.endswith(b"[") or before == b""
            payload = bytearray()
            for index, piece in enumerate(pieces):
                if not (empty and index == 0):
                    payload += b",\n"
                payload += piece
            payload += b"\n]"
            handle.seek(absolute)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            handle.truncate()

    def _refresh_from_warehouse(self, warehouse) -> List[dict]:
        if not self._synced:
            events, last_id, tip = warehouse.read_verified_chain()
            if self._docs != events:
                self._write_atomic(events)
            self._docs = events
            self._through_id = last_id
            self._tip = tip
            self._synced = True
            return self._docs
        new_events, last_id, tip = warehouse.read_verified_chain(self._through_id, self._tip)
        if not new_events:
            return self._docs
        self._append_projection(new_events)
        self._docs.extend(new_events)
        self._through_id = last_id
        self._tip = tip
        return self._docs

    def ingest(self, event):
        with self._lock:
            doc = dict(event)
            doc.setdefault("message_type", event.get("message_type") or event.get("type") or "unknown")
            doc["_indexed_at"] = time.time()

            from evidence.warehouse import get_warehouse
            warehouse = get_warehouse()
            chained = warehouse.append(doc)
            doc = dict(chained)
            doc.pop("_prev_digest", None)
            doc.pop("_idempotent_replay", None)
            doc["_digest"] = chained.get("_digest")

            # Append is committed first. Refresh under a shared path lock so
            # another process cannot replace the projection from a stale snapshot.
            with _interprocess_path_lock(self.path):
                docs = self._refresh_from_warehouse(warehouse)
            for saved in docs:
                if saved.get("_digest") == doc.get("_digest"):
                    return dict(saved)
            raise RuntimeError("committed evidence event missing from verified warehouse snapshot")

    def query(self, *, capability_id=None, request_id=None, actor=None, message_type=None, correlation_id=None, message_id=None, limit=50):
        from evidence.warehouse import get_warehouse

        with self._lock:
            with _interprocess_path_lock(self.path):
                docs = list(self._refresh_from_warehouse(get_warehouse()))
        out = []
        for d in reversed(docs):
            if capability_id and str(d.get("capability_id") or "") != capability_id:
                continue
            if request_id and str(d.get("request_id") or d.get("aggregate_id") or "") != request_id:
                continue
            if actor and actor not in str(d.get("audience") or d.get("actor_id") or d.get("caller") or ""):
                continue
            if message_type and str(d.get("message_type") or "") != message_type:
                continue
            if correlation_id and str(d.get("correlation_id") or "") != correlation_id:
                continue
            if message_id and str(d.get("message_id") or "") != message_id:
                continue
            out.append(d)
            if len(out) >= limit:
                break
        return out

    def stats(self):
        from evidence.warehouse import get_warehouse

        with self._lock:
            with _interprocess_path_lock(self.path):
                docs = self._refresh_from_warehouse(get_warehouse())
            by = {}
            for d in docs:
                t = str(d.get("message_type") or "unknown")
                by[t] = by.get(t, 0) + 1
            return {"total": len(docs), "by_message_type": by, "index_path": str(self.path)}


_INDEX = None


def get_index():
    global _INDEX
    if _INDEX is None:
        _INDEX = EvidenceIndex()
    return _INDEX


def attach_to_attestpipe():
    try:
        from attestpipe.bus import BUS
        idx = get_index()
        BUS.subscribe(lambda payload: idx.ingest(payload))
        print("[evidence-index] attached to AttestPipe")
        return True
    except Exception as e:
        print(f"[evidence-index] attach skip: {e}")
        return False
