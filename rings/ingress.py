"""Named doors only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional, Callable

@dataclass(frozen=True)
class Door:
    name: str
    kind: str
    target: str
    description: str

DOORS = {
    "watsonx": Door("watsonx", "planner", "/v1/capabilities/*", "frozen OpenAPI"),
    "control12": Door("control12", "planner", "actuation_adapter", "Intent only"),
    "admin_api": Door("admin_api", "operator", "/v1/admin", "dual approval"),
    "hands": Door("hands", "operator", "rings.hands.route", "gated hands"),
}

FORBIDDEN_DOORS = (
    "ambient_shell",
    "kubectl_from_model",
    "long_lived_cloud_token",
    "break_glass_override_hold",
    "execute_without_capability",
)

def enter(door_name: str, payload: dict[str, Any], handler: Optional[Callable] = None) -> dict[str, Any]:
    if door_name in FORBIDDEN_DOORS:
        return {"status": "denied", "error": f"forbidden door: {door_name}"}
    door = DOORS.get(door_name)
    if not door:
        return {"status": "denied", "error": f"unknown door: {door_name}"}
    return {"status": "admitted", "door": door.name, "kind": door.kind}
