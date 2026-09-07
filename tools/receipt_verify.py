#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from plane_service.crypto_sign import verify_sig

def main():
    p = argparse.ArgumentParser(description="Verify a signed execute receipt")
    p.add_argument("--file")
    args = p.parse_args()
    raw = json.loads(Path(args.file).read_text()) if args.file else json.loads(sys.stdin.read())
    receipt = raw.get("receipt") or raw
    sig = receipt.get("signature")
    body = {k: v for k, v in receipt.items() if k != "signature"}
    if not sig:
        print(json.dumps({"ok": False, "error": "receipt.signature missing"}))
        return 2
    ok = verify_sig(body, sig)
    print(json.dumps({"ok": ok, "capability_id": body.get("capability_id"), "action": body.get("action"), "outcome": body.get("outcome")}))
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
