#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.runtime import mount_agent
from agents.spawn import spawn_subagent

def main():
    parent = mount_agent(name="planner", rights=[{"type": "read", "resource": "demo"}, {"type": "Execute", "resource": "tool.echo"}])
    print("MOUNT", parent.get("status"), parent.get("spiffe_id"))
    child = spawn_subagent(parent["agent_id"], "worker", [{"type": "read", "resource": "demo"}])
    print("SPAWN", child.get("status"), child.get("spiffe_id"), child.get("delegation_depth"))
    print("AMPLIFY", spawn_subagent(parent["agent_id"], "amp", [{"type": "Execute", "resource": "kubectl"}]).get("status"))

if __name__ == "__main__":
    main()
