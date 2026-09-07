from dataclasses import dataclass, field
from typing import List, Set

@dataclass
class ApprovalRequirement:
    action: str
    resource: str
    risk_class: str
    required_types: Set[str] = field(default_factory=set)
    forensic_hold: bool = False
    legal_hold: bool = False
    unresolved_dispute: bool = False

@dataclass
class GateDecision:
    allowed: bool
    reason: str
    failed: List[str] = field(default_factory=list)

def evaluate(req: ApprovalRequirement, approvals):
    if req.forensic_hold or req.legal_hold or req.unresolved_dispute:
        return GateDecision(False, "hold cannot be bypassed", ["hold"])
    if req.risk_class == "destructive":
        have = {a.get("approval_type") for a in approvals if a.get("status") == "approved"}
        missing = set(req.required_types) - have
        if missing:
            return GateDecision(False, "dual approval required", list(missing))
    return GateDecision(True, "ok")
