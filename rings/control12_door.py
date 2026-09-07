from rings.ingress import enter
from control12.actuation_adapter import Intent, PlaneClient

def plan_and_actuate(intent, plane_base="http://127.0.0.1:8090"):
    admitted = enter("control12", intent if isinstance(intent, dict) else {})
    if admitted.get("status") != "admitted":
        return admitted
    if not isinstance(intent, dict):
        intent = {}
    obj = Intent(rights=intent.get("rights") or [{"type": "read", "resource": "demo"}], ttl_seconds=int(intent.get("ttl_seconds") or 60), constraints=dict(intent.get("constraints") or {}), caller=intent.get("caller"))
    try:
        return {"door": "control12", "result": PlaneClient(plane_base).actuate(obj)}
    except Exception as e:
        return {"door": "control12", "admitted": True, "offline": True, "note": str(e)}
