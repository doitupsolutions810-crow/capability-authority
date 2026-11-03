#!/usr/bin/env python3
"""Provision AVRONE's narrow parent capability out of band on the Authority host."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

from evidence.index import get_index
from plane_service.core import issue
from plane_service.crypto_sign import canonical, sign
from plane_service.policy import PolicyEngine
from plane_service.server import (
    BROKER_MEASUREMENT,
    ISSUER,
    POLICY_VERSION,
    TRUST_DOMAIN,
    _record_evidence,
)

RIGHTS = [{"type": "Execute", "resource": "swarm.jobs", "method": "POST"}]


def write_private_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            existing_bytes = path.read_bytes()
            existing = json.loads(existing_bytes.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError("existing parent-capability file is not valid JSON; refusing overwrite") from exc
        if not isinstance(existing, dict) or existing_bytes != data:
            raise RuntimeError("existing parent-capability file differs; refusing overwrite")
        return
    temp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    requester = os.environ.get("PLANE_DELEGATION_REQUESTER_ID", "")
    key_file = os.environ.get("PLANE_DELEGATION_REQUESTER_PUBLIC_KEY_FILE", "")
    audiences = sorted({
        item.strip() for item in os.environ.get("PLANE_DELEGATION_ALLOWED_AUDIENCES", "").split(",")
        if item.strip()
    })
    output = os.environ.get("PLANE_AVRONE_PARENT_CAPABILITY_FILE", "")
    correlation_id = os.environ.get("PLANE_AVRONE_PARENT_CAPABILITY_CORRELATION_ID", "")
    if not requester or not key_file or not Path(key_file).is_file():
        raise SystemExit("pinned requester identity/public key file must be configured before provisioning")
    if not audiences or not output or not correlation_id or len(correlation_id) > 128:
        raise SystemExit("audience allowlist, output file and stable correlation ID are required")
    if not requester.startswith("spiffe://prod/agent/"):
        raise SystemExit("requester must be an approved production agent SPIFFE ID")
    if not all(item.startswith("spiffe://prod/agent/") for item in audiences):
        raise SystemExit("all delegated audiences must be approved production agent SPIFFE IDs")
    try:
        ttl = int(os.environ.get("PLANE_AVRONE_PARENT_CAPABILITY_TTL_SECONDS", "300"))
    except ValueError as exc:
        raise SystemExit("parent capability TTL must be an integer") from exc
    if not 1 <= ttl <= 300:
        raise SystemExit("parent capability TTL must be within 1..300 seconds")
    tenant = os.environ.get("PLANE_AVRONE_PARENT_CAPABILITY_TENANT", "avrone-swarm")
    constraints = {"tenant": tenant, "delegation_audiences": audiences}
    PolicyEngine().authorize(requester, RIGHTS, constraints, ttl)
    request_digest = "sha256:" + hashlib.sha256(canonical({
        "requester": requester, "audiences": audiences, "rights": RIGHTS,
        "ttl_seconds": ttl, "constraints": constraints,
    })).hexdigest()
    index = get_index()
    prior = index.query(message_type="CapabilityRootProvisioned", correlation_id=correlation_id, limit=1)
    if prior:
        row = prior[0]
        if row.get("request_digest") != request_digest:
            raise SystemExit("root capability correlation ID was already used for a different request")
        capability, signature = row.get("capability"), row.get("signature")
        if not isinstance(capability, dict) or not isinstance(signature, str):
            raise SystemExit("prior root capability evidence is incomplete")
    else:
        capability = issue(
            caller=requester, issuer=ISSUER, rights=RIGHTS, constraints=constraints,
            ttl_seconds=ttl, trust_domain=TRUST_DOMAIN,
            broker_measurement=BROKER_MEASUREMENT, policy_version=POLICY_VERSION,
        )
        signature = sign(capability)
        _record_evidence({
            "message_type": "CapabilityRootProvisioned",
            "message_id": uuid.uuid4().hex,
            "correlation_id": correlation_id,
            "request_digest": request_digest,
            "requester": requester,
            "audiences": audiences,
            "capability_id": capability["id"],
            "capability": capability,
            "signature": signature,
        })
    destination = Path(output)
    write_private_atomic(destination, json.dumps(
        {"capability": capability, "signature": signature},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8"))
    print("Provisioned parent capability " + capability["id"] + " for " + requester)
    print("Audience scope: " + ", ".join(audiences))
    print("Credential file: " + str(destination) + " (mode 0600)")


if __name__ == "__main__":
    main()
