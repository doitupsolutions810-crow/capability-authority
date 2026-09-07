#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from plane_service.core import issue, verify
from plane_service.crypto_sign import sign, verify_sig
from plane_service.executor import Executor
from plane_service.policy import PolicyEngine

def main():
    caller = "spiffe://prod/agent/dev"
    rights = [{"type": "read", "resource": "demo"}]
    PolicyEngine().authorize(caller, rights, {}, 60)
    cap = issue(caller, "spiffe://prod/broker", rights, {}, 60, "prod", "dev:unattested", 1)
    sig = sign(cap)
    print("sig_ok", verify_sig(cap, sig))
    print("verify", verify(cap, rights[0], caller))
    print("execute", Executor().execute(cap, sig, rights[0], caller)["status"])

if __name__ == "__main__":
    main()
