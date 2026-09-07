from dataclasses import dataclass
import os

@dataclass
class WorkflowState:
    workflow_id: str
    status: str
    issue: dict = None
    execute: dict = None
    error: str = None

class IntentWorkflow:
    def run(self, workflow_id, intent):
        from plane_service.core import issue
        from plane_service.crypto_sign import sign
        from plane_service.executor import Executor
        from plane_service.policy import PolicyEngine
        from plane_service.spiffe_binding import bind_issue_request
        bound = bind_issue_request(intent)
        caller = bound["caller"]
        rights = intent.get("rights") or [{"type": "read", "resource": "demo"}]
        constraints = dict(intent.get("constraints") or {})
        ttl = int(intent.get("ttl_seconds") or 60)
        try:
            PolicyEngine().authorize(caller, rights, constraints, ttl)
        except Exception as e:
            return WorkflowState(workflow_id, "denied", error=str(e))
        cap = issue(caller, f"spiffe://{os.environ.get('PLANE_TRUST_DOMAIN','prod')}/broker", rights, constraints, ttl, os.environ.get("PLANE_TRUST_DOMAIN","prod"), os.environ.get("PLANE_BROKER_MEASUREMENT","dev:unattested"), int(os.environ.get("PLANE_POLICY_VERSION","1")))
        sig = sign(cap)
        result = Executor().execute(cap, sig, rights[0], caller)
        return WorkflowState(workflow_id, "completed" if result.get("status")=="ok" else "failed", issue={"capability": cap, "signature": sig}, execute=result, error=result.get("error"))
