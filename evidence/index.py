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


class EvidenceIndex:
    """Verified JSON projection over the authoritative hash-chained warehouse.

    Writers sharing the projection path serialize refreshes with a persistent
    sidecar lock file. Ingest, query, and stats rebuild the materialized view
    from a verified ledger snapshot, so stale process-local snapshots cannot
    silently hide committed records. The lock file must remain in place while
    service processes are running.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or INDEX_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._docs: List[dict] = self._read_projection()

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

    def _refresh_from_warehouse(self, warehouse) -> List[dict]:
        docs = warehouse.read_verified_events()
        try:
            projected = self._read_projection()
        except ValueError:
            # The verified ledger is authoritative; rebuild only the derived view.
            projected = None
        if projected != docs:
            self._write_atomic(docs)
        self._docs = docs
        return docs

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

    def query(self, *, capability_id=None, request_id=None, actor=None, message_type=None, limit=50):
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
