#!/usr/bin/env python3
from __future__ import annotations
import os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

def _fail(msg):
    print("FAIL", msg)
    raise SystemExit(1)

def test_mount_and_spawn():
    from agents.runtime import mount_agent
    from agents.spawn import spawn_subagent
    from plane_service.executor import Executor
    parent = mount_agent(name="planner", rights=[{"type": "read", "resource": "demo"}, {"type": "Execute", "resource": "tool.echo"}], ttl_seconds=60)
    if parent.get("status") != "mounted":
        _fail(str(parent))
    child = spawn_subagent(parent_agent_id=parent["agent_id"], name="worker", rights=[{"type": "read", "resource": "demo"}])
    if child.get("status") != "spawned":
        _fail(str(child))
    out = Executor().execute(child["capability"], child["signature"], {"type": "read", "resource": "demo"}, child["spiffe_id"])
    if out.get("status") != "ok":
        _fail(str(out))
    print("PASS mount_and_spawn")

def test_spawn_cannot_amplify():
    from agents.runtime import mount_agent
    from agents.spawn import spawn_subagent
    parent = mount_agent(name="narrow", rights=[{"type": "read", "resource": "demo"}])
    child = spawn_subagent(parent_agent_id=parent["agent_id"], name="evil", rights=[{"type": "Execute", "resource": "tool.echo"}])
    if child.get("status") != "denied":
        _fail(f"amplification allowed: {child}")
    print("PASS spawn_cannot_amplify")

def test_spawn_rejects_shell():
    from agents.runtime import mount_agent
    denied = mount_agent(name="bad", rights=[{"type": "Execute", "resource": "shell"}])
    if denied.get("status") != "denied":
        _fail(str(denied))
    print("PASS spawn_rejects_shell")

def main():
    test_mount_and_spawn()
    test_spawn_cannot_amplify()
    test_spawn_rejects_shell()
    print("ALL PASS agents")

if __name__ == "__main__":
    main()
