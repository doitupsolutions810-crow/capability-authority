import os
from dataclasses import dataclass, field

@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fatal: bool = True

@dataclass
class PreflightReport:
    production: bool
    checks: list = field(default_factory=list)
    @property
    def ok(self):
        return all(c.ok for c in self.checks if c.fatal)
    def as_dict(self):
        return {"production": self.production, "ok": self.ok, "checks": [c.__dict__ for c in self.checks]}

def is_production():
    return os.environ.get("PRODUCTION", "0") == "1" or os.environ.get("PLANE_PRODUCTION", "0") == "1"

def preflight():
    prod = is_production()
    report = PreflightReport(production=prod)
    sock = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    source = "env" if os.environ.get("PLANE_SPIFFE_ID") else "fallback"
    if prod and source != "workload-api":
        report.checks.append(Check("spire", False, f"source={source} socket={sock or 'unset'}"))
    else:
        report.checks.append(Check("spire", True, source, fatal=False))
    meas = os.environ.get("PLANE_BROKER_MEASUREMENT", "dev:unattested")
    if prod and meas.startswith("dev:"):
        report.checks.append(Check("measurement", False, meas))
    else:
        report.checks.append(Check("measurement", True, meas))
    if prod and os.environ.get("PLANE_ALLOW_CALLER_OVERRIDE", "0") == "1":
        report.checks.append(Check("caller_override", False, "must be 0"))
    else:
        report.checks.append(Check("caller_override", True, "ok"))
    return report
