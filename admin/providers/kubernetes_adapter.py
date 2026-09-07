"""K8s adapter: structured plan first. Live mutate only with explicit env."""
from admin.providers.base import Provider
from admin.providers.k8s_plan import isolation_plan
import os

class KubernetesProvider(Provider):
    name = "kubernetes"
    def isolate_or_mutate(self, provider_request_id, action, resource, params):
        ns = params.get("namespace") or "operations"
        dep = params.get("deployment") or "demo-app"
        mode = params.get("suspension_mode") or "network_isolation"
        plan = isolation_plan(provider_request_id, ns, dep, mode)
        live = os.environ.get("K8S_LIVE", "0") == "1"
        if not live:
            return {"status": "planned", "provider_request_id": provider_request_id, "plan": plan}
        if os.environ.get("ALLOW_ADMIN_DESTRUCTIVE_ACTIONS", "false").lower() != "true":
            return {"status": "denied", "error": "destructive gate off", "plan": plan}
        return {"status": "applied-lab", "provider_request_id": provider_request_id, "plan": plan, "note": "wire kubectl apply only in a real cluster"}
