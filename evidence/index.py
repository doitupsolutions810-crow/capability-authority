import json, os, time
from pathlib import Path
from typing import Any, List, Optional

ROOT = Path(__file__).resolve().parents[1]
INDEX_DB = Path(os.environ.get("EVIDENCE_INDEX_PATH", str(ROOT / "data" / "evidence_index.json")))

class EvidenceIndex:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or INDEX_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._docs: List[dict] = []
        if self.path.exists():
            try:
                self._docs = json.loads(self.path.read_text())
            except Exception:
                self._docs = []
    def ingest(self, event):
        doc = dict(event)
        doc.setdefault("message_type", event.get("message_type") or event.get("type") or "unknown")
        doc["_indexed_at"] = time.time()
        try:
            from evidence.warehouse import get_warehouse
            chained = get_warehouse().append(doc)
            doc["_digest"] = chained.get("_digest")
        except Exception:
            pass
        self._docs.append(doc)
        self.path.write_text(json.dumps(self._docs, indent=2, default=str))
        return doc
    def query(self, *, capability_id=None, request_id=None, actor=None, message_type=None, limit=50):
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
    except Exception as e:
        print(f"[evidence-index] attach skip: {e}")
