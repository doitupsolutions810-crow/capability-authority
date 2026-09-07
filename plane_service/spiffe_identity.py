import os
from dataclasses import dataclass

@dataclass
class WorkloadIdentity:
    spiffe_id: str
    trust_domain: str
    source: str
    socket_reachable: bool = False

def fetch_workload_identity(socket_path=None, trust_domain_cfg=None):
    env_id = os.environ.get("PLANE_SPIFFE_ID") or os.environ.get("SPIFFE_ID")
    td = trust_domain_cfg or os.environ.get("PLANE_TRUST_DOMAIN", "prod")
    if env_id:
        return WorkloadIdentity(env_id, td, "env")
    return WorkloadIdentity(f"spiffe://{td}/agent/dev", td, "fallback")

def identity_summary():
    i = fetch_workload_identity()
    return {"spiffe_id": i.spiffe_id, "trust_domain": i.trust_domain, "source": i.source, "socket_env": os.environ.get("SPIFFE_ENDPOINT_SOCKET")}
