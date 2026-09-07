#!/usr/bin/env python3
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rings.production_profile import preflight, is_production
from rings.ingress import enter
from rings.hands import route
from admin.reconcile import classify, next_action
from admin.providers.factory import get_provider

def main():
    print("lab_preflight", preflight().as_dict())
    print("watsonx", enter("watsonx", {}))
    print("shell", route("shell"))
    rec = get_provider("kubernetes").isolate_or_mutate("prov:1", "tenant.suspend.network_isolation", "tenant:demo", {})
    print("k8s", rec["status"], rec.get("plan", {}).get("mode"))
    print("timeout", classify({"status": "timeout"}), next_action("unknown"))
    os.environ["PRODUCTION"] = "1"
    print("prod_ok", preflight().ok)

if __name__ == "__main__":
    main()
