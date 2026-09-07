#!/usr/bin/env python3
import os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def main():
    if not os.environ.get("SPIFFE_ENDPOINT_SOCKET"):
        print("SKIP no SPIFFE_ENDPOINT_SOCKET")
        return
    from plane_service.spiffe_identity import fetch_workload_identity
    ident = fetch_workload_identity()
    print(ident)
    if ident.source != "workload-api":
        raise SystemExit(f"FAIL expected workload-api, got {ident.source}")
    print("PASS workload-api")

if __name__ == "__main__":
    main()
