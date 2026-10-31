import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
INDEX_DB = Path(os.environ.get("EVIDENCE_INDEX_PATH", str(ROOT / "data" / "evidence_index.json")))


class EvidenceIndex:
    """JSON evidence projection backed by the hash-chained warehouse.

    Warehouse append failures are fatal to ingest: an event must not be
    represented as successfully indexed if the authoritative append failed.
    The JSON file is replaced atomically so readers see either the old or new
    complete document. This is not a cross-store transaction; an index write
    failure after a successful warehouse append must be reconciled.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or INDEX_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._docs: List[dict] = []
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise ValueError(f"evidence index is unreadable; refusing to reset history: {self.path}") from exc
            if not isinstance(loaded, list) or any(not isinstance(item, dict) for item in loaded):
                raise ValueError(f"evidence index has invalid structure; refusing to reset history: {self.path}")
            self._docs = loaded

    def _write_atomic(self, docs: List[dict]) -> None:
        encoded = json.dumps(docs, indent=2, default=str).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(encoded)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self.path)
            # Persist the directory entry where supported, so the rename is
            # durable across a crash on filesystems that honor directory fsync.
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

    def ingest(self, event):
        with self._lock:
            doc = dict(event)
            doc.setdefault("message_type", event.get("message_type") or event.get("type") or "unknown")
            doc["_indexed_at"] = time.time()

            # The warehouse is the hash-chained authority. Never hide a failed
            # append and continue as if the event were fully ingested.
            from evidence.warehouse import get_warehouse
            chained = get_warehouse().append(doc)
            doc["_digest"] = chained.get("_digest")

            next_docs = [*self._docs, doc]
            # Publish the new in-memory view only after the atomic file replace.
            self._write_atomic(next_docs)
            self._docs = next_docs
            return dict(doc)

    def query(self, *, capability_id=None, request_id=None, actor=None, message_type=None, limit=50):
        with self._lock:
            out = []
            for d in reversed(self._docs):
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
        with self._lock:
            by = {}
            for d in self._docs:
                t = str(d.get("message_type") or "unknown")
                by[t] = by.get(t, 0) + 1
            return {"total": len(self._docs), "by_message_type": by, "index_path": str(self.path)}


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
