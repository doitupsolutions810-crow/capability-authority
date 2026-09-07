import os, time, uuid
from plane_service.core import attenuate, verify
from plane_service.crypto_sign import sign, verify_sig
from rings.ingress import enter
from .runtime import REGISTRY, AgentHandle, _deny_forbidden_rights

MAX_DEPTH = int(os.environ.get("AGENT_MAX_SPAWN_DEPTH", "2"))

def spawn_subagent(parent_agent_id, name, rights=None):
    admitted = enter("subagent", {"parent": parent_agent_id, "name": name})
    if admitted.get("status") != "admitted":
        return admitted
    parent = REGISTRY.get(parent_agent_id)
    if parent is None:
        return {"status": "denied", "error": "parent agent not mounted"}
    if not verify_sig(parent.capability, parent.signature):
        return {"status": "denied", "error": "parent capability signature invalid"}
    depth = int(parent.capability.get("delegation_depth") or 0)
    if depth >= MAX_DEPTH:
        return {"status": "denied", "error": f"spawn depth {depth} >= max {MAX_DEPTH}"}
    child_rights = rights or list(parent.capability.get("rights") or [])
    bad = _deny_forbidden_rights(child_rights)
    if bad:
        return {"status": "denied", "error": bad}
    try:
        child_cap = attenuate(parent.capability, child_rights)
    except ValueError as e:
        return {"status": "denied", "error": str(e)}
    child_spiffe = f"{parent.spiffe_id}/{name}"
    child_cap["audience"] = child_spiffe
    child_sig = sign(child_cap)
    handle = AgentHandle(str(uuid.uuid4()), child_spiffe, parent.agent_id, "sub", child_cap, child_sig, time.time())
    REGISTRY.put(handle)
    parent.children.append(handle.agent_id)
    return {"status": "spawned", "agent_id": handle.agent_id, "parent_id": parent.agent_id, "spiffe_id": handle.spiffe_id, "delegation_depth": child_cap.get("delegation_depth"), "capability": child_cap, "signature": child_sig, "door": "subagent"}
