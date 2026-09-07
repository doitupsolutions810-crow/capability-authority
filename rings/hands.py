"""Gated hands — no ambient shell/kubectl/keys/hold-bypass."""
from __future__ import annotations
from typing import Any, Optional
from rings.ingress import FORBIDDEN_DOORS, enter

HAND_ALIASES = {
    "shell": "ambient_shell",
    "kubectl": "kubectl_from_model",
    "cloud_key": "long_lived_cloud_token",
    "hold_bypass": "break_glass_override_hold",
    "break_glass": "break_glass_override_hold",
}

def route(hand: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    payload = payload or {}
    kind = HAND_ALIASES.get(hand, hand)
    if kind in FORBIDDEN_DOORS or kind in HAND_ALIASES.values():
        return {"status": "denied", "hand": kind, "error": f"forbidden hand: {kind}"}
    if kind == "probe":
        return {"status": "admitted", "hand": "probe", "note": "read-only"}
    return {"status": "denied", "error": f"unknown hand: {kind}"}
