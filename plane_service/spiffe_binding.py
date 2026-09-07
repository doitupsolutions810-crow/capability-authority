import os
from plane_service.spiffe_identity import WorkloadIdentity, fetch_workload_identity

class SpiffeBindingError(Exception):
    pass

def resolve_issue_identity(body_caller=None, trust_domain_cfg=None):
    ident = fetch_workload_identity(trust_domain_cfg=trust_domain_cfg)
    required = os.environ.get("SPIFFE_REQUIRED", "0") == "1" or os.environ.get("PRODUCTION", "0") == "1"
    if required and ident.source == "fallback":
        raise SpiffeBindingError("SPIFFE_REQUIRED=1 but Workload API SVID unavailable")
    return ident

def bind_issue_request(body):
    ident = resolve_issue_identity(body.get("caller"), os.environ.get("PLANE_TRUST_DOMAIN"))
    out = dict(body)
    out["caller"] = ident.spiffe_id
    out["_identity_source"] = ident.source
    return out
