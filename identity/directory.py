from dataclasses import dataclass
from typing import Optional
import os

@dataclass(frozen=True)
class Principal:
    spiffe_id: str
    trust_domain: str
    kind: str
    roles: tuple = ()

class IdentityDirectory:
    def __init__(self, principals=None):
        self._by_id = {p.spiffe_id: p for p in (principals or [])}

    def allowed(self, spiffe_id, kind=None):
        prefixes = ("spiffe://prod/agent/", "spiffe://prod/broker/", "spiffe://prod/operator/")
        return any(spiffe_id.startswith(p) for p in prefixes)
