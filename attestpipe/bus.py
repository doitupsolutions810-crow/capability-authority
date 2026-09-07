import json, os
from typing import Callable, List

class AttestPipeBus:
    def __init__(self):
        self._subs: List[Callable] = []
    def subscribe(self, fn):
        self._subs.append(fn)
    def publish(self, msg):
        if hasattr(msg, "to_json"):
            payload = json.loads(msg.to_json())
        elif isinstance(msg, dict):
            payload = msg
        else:
            payload = {"message_type": type(msg).__name__, "raw": str(msg)}
        for fn in self._subs:
            fn(payload)
        return payload

BUS = AttestPipeBus()
