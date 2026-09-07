from plane_service.crypto_sign import verify_sig
from rings.measurement_pin import MeasurementPolicy

def mesh_accept(cap, signature, expected_trust_domain="prod", max_delegation_depth=3, min_policy_version=1, measurement_policy=None):
    if not verify_sig(cap, signature):
        return {"ok": False, "error": "invalid signature"}
    if cap.get("trust_domain") != expected_trust_domain:
        return {"ok": False, "error": "trust_domain mismatch"}
    if int(cap.get("delegation_depth") or 0) > max_delegation_depth:
        return {"ok": False, "error": "delegation_depth exceeded"}
    mp = measurement_policy or MeasurementPolicy()
    ok, reason = mp.accept(str(cap.get("broker_measurement") or "dev:unattested"))
    if not ok:
        return {"ok": False, "error": reason}
    return {"ok": True, "reason": reason, "capability_id": cap.get("id")}
