import hashlib
from dataclasses import dataclass
from typing import Any, Optional

@dataclass(frozen=True)
class IdempotencyKey:
    request_id: str
    action_type: str
    resource_id: str
    def stable_id(self):
        raw = f"{self.action_type}:{self.resource_id}:{self.request_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

class IdempotencyStore:
    def __init__(self):
        self._store = {}
    def get(self, key):
        return self._store.get(key)
    def put(self, key, result):
        self._store[key] = result
        return result
