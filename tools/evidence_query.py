#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evidence.index import get_index

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--capability-id")
    p.add_argument("--request-id")
    p.add_argument("--actor")
    p.add_argument("--message-type")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--limit", type=int, default=20)
    args = p.parse_args()
    idx = get_index()
    if args.stats:
        print(json.dumps(idx.stats(), indent=2))
        return 0
    rows = idx.query(capability_id=args.capability_id, request_id=args.request_id, actor=args.actor, message_type=args.message_type, limit=args.limit)
    print(json.dumps({"count": len(rows), "results": rows}, indent=2, default=str))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
