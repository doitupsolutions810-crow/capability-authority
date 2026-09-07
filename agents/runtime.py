import os, time, uuid
from dataclasses import dataclass, field
from plane_service.core import issue
from plane_service.crypto_sign import sign
from plane_service.policy import PolicyEngine, PolicyError
from plane_service.spiffe_binding import SpiffeBindingError, bind_issue_request
from plane_service.spiffe_identity import fetch_workload_identity
from rings.ingress import enter

FORBIDDEN_RIGHTS = {("Execute", "shell"), ("Execute", "kubectl"), ("Execute", "ambient_key")}

@dataclass
class AgentHandle:
    agent_id: str
    spiffe_id: str
    parent_id: str | None
    role: str
    capability: dict
    signature: str
    mounted_at: float
    children: list = field(default_factory=list)

class AgentRegistry:
    def __init__(self):
        self._by_id = {}
    def put(self, handle):
        self._by_id[handle.agent_id] = handle
        return handle
    def get(self, agent_id):
        return self._by_id.get(agent_id)
    def list(self):
        return list(self._by_id.values())

REGISTRY = AgentRegistry()

def _deny_forbidden_rights(rights):
    for r in rights:
        key = (r.get("type"), r.get("resource"))
        if key in FORBIDDEN_RIGHTS or str(r.get("resource") or "").startswith(("shell", "kubectl")):
            return f"forbidden right: {key}"
    return None

def mount_agent(name="parent", rights=None, ttl_seconds=120, constraints=None, caller=None):
    admitted = enter("agent", {"name": name})
    if admitted.get("status") != "admitted":
        return admitted
    rights = rights or [{"type": "read", "resource": "demo"}]
    bad = _deny_forbidden_rights(rights)
    if bad:
        return {"status": "denied", "error": bad}
    body = {"caller": caller, "rights": rights, "ttl_seconds": ttl_seconds, "constraints": dict(constraints or {})}
    try:
        body = bind_issue_request(body)
    except SpiffeBindingError as e:
        return {"status": "denied", "error": str(e)}
    ident = fetch_workload_identity()
    spiffe_id = body.get("caller") or ident.spiffe_id
    mounted_id = f"{spiffe_id.rstrip('/')}/{name}" if "/agent/" in spiffe_id else f"{spiffe_id}/agent/{name}"
    try:
        PolicyEngine().authorize(spiffe_id, rights, body["constraints"], ttl_seconds)
    except PolicyError as e:
        return {"status": "denied", "error": str(e)}
    td = os.environ.get("PLANE_TRUST_DOMAIN", "prod")
    cap = issue(mounted_id, f"spiffe://{td}/broker", rights, body["constraints"], ttl_seconds, td, os.environ.get("PLANE_BROKER_MEASUREMENT", "dev:unattested"), int(os.environ.get("PLANE_POLICY_VERSION", "1")))
    sig = sign(cap)
    handle = AgentHandle(str(uuid.uuid4()), mounted_id, None, "parent", cap, sig, time.time())
    REGISTRY.put(handle)
    return {"status": "mounted", "agent_id": handle.agent_id, "spiffe_id": handle.spiffe_id, "identity_source": ident.source, "capability": cap, "signature": sig, "door": "agent"}
