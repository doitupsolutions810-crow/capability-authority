#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from plane_service.crypto_sign import verify_sig

def main():
    if len(sys.argv) < 2:
        print("usage: cap_verify.py cap.json")
        return 2
    data = json.loads(Path(sys.argv[1]).read_text())
    cap = data.get("capability") or data
    sig = data.get("signature") or ""
    print(json.dumps({"ok": verify_sig(cap, sig)}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
