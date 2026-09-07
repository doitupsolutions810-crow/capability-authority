from dataclasses import dataclass
from typing import Optional
from pathlib import Path
import json, os

@dataclass
class DevSvid:
    spiffe_id: str
    trust_domain: str
    selector: str

class DevSpire:
    def __init__(self, mapping=None):
        self._map = mapping or {}
    def svid_for_selector(self, selector):
        return self._map.get(selector)

def load_dev_spire(path=None):
    root = Path(__file__).resolve().parents[1]
    p = Path(path or root / "identity" / "dev_svids.json")
    if not p.exists():
        return DevSpire({})
    raw = json.loads(p.read_text())
    return DevSpire({k: DevSvid(v["spiffe_id"], v.get("trust_domain", "prod"), k) for k, v in raw.items()})
