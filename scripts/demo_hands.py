#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rings.hands import route
from rings.ingress import enter

def main():
    for h in ("shell", "kubectl", "cloud_key", "hold_bypass"):
        print(h, route(h))
    print("watsonx", enter("watsonx", {}))
    print("probe", route("probe"))

if __name__ == "__main__":
    main()
