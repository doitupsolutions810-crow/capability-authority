#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.runtime import REGISTRY, mount_agent
from agents.spawn import spawn_subagent

def main():
    parent = mount_agent(name="planner", rights=[
        {"type": "read", "resource": "demo", "method": "GET"},
        {"type": "Execute", "resource": "tool.echo", "method": "POST"}
    ])
    if parent.get("status") != "mounted":
        raise SystemExit(f"parent mount denied: {parent}")
    print("MOUNT", parent.get("status"), parent.get("spiffe_id"))
    child = spawn_subagent(parent_agent_id=parent["agent_id"], name="worker", rights=[
        {"type": "read", "resource": "demo", "method": "GET"}
    ])
    if child.get("status") != "spawned":
        raise SystemExit(f"child spawn denied: {child}")
    print("SPAWN", child.get("status"), child.get("spiffe_id"), child.get("delegation_depth"))
    denied = spawn_subagent(parent_agent_id=parent["agent_id"], name="amp", rights=[
        {"type": "Execute", "resource": "kubectl", "method": "POST"}
    ])
    print("AMPLIFY", denied.get("status"))
    print("REGISTRY", len(REGISTRY.list()), "agents")

if __name__ == "__main__":
    main()
