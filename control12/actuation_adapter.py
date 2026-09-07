from dataclasses import dataclass, field
from typing import Any
import json, urllib.request

@dataclass
class Intent:
    rights: list
    ttl_seconds: int = 60
    constraints: dict = field(default_factory=dict)
    caller: str = None

class PlaneClient:
    def __init__(self, base="http://127.0.0.1:8090"):
        self.base = base.rstrip("/")
    def _post(self, path, body):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    def actuate(self, intent: Intent):
        issued = self._post("/v1/capabilities/issue", {"caller": intent.caller, "rights": intent.rights, "ttl_seconds": intent.ttl_seconds, "constraints": intent.constraints})
        if issued.get("status") != "ok":
            return issued
        required = intent.rights[0] if intent.rights else {"type": "read", "resource": "demo"}
        return self._post("/v1/execute", {"capability": issued["capability"], "signature": issued["signature"], "required": required, "caller": issued["capability"].get("audience")})
