"""SPIFFE / SPIRE Workload API identity (Track 2 — Identity).

Priority:
  1) Workload API X509-SVID when SPIFFE_ENDPOINT_SOCKET is reachable
  2) PLANE_SPIFFE_ID / SPIFFE_ID env
  3) synthetic fallback spiffe://{trust_domain}/agent/dev

Install: bash scripts/install_py_spiffe.sh
The PyPI package name is `spiffe` (project: HewlettPackard/py-spiffe).
"""
from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass
from typing import Optional, Set

_SPIFFE_TARGET = os.environ.get("SPIFFE_PY_TARGET", "/opt/capability-authority/py-spiffe")
if _SPIFFE_TARGET and os.path.isdir(_SPIFFE_TARGET) and _SPIFFE_TARGET not in sys.path:
    sys.path.insert(0, _SPIFFE_TARGET)


@dataclass
class WorkloadIdentity:
    spiffe_id: str
    trust_domain: str
    source: str
    socket_reachable: bool = False


def _parse_trust_domain(spiffe_id: str) -> str:
    if not spiffe_id.startswith("spiffe://"):
        return os.environ.get("PLANE_TRUST_DOMAIN", "prod")
    rest = spiffe_id[len("spiffe://") :]
    return rest.split("/", 1)[0] or "prod"


def _socket_path(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    if raw.startswith("unix://"):
        return raw[len("unix://") :]
    return raw


def _probe_socket(path: str) -> bool:
    if not os.path.exists(path):
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(path)
        s.close()
        return True
    except Exception:
        return False


def _allowed_trust_domains() -> Set[str]:
    raw = os.environ.get("PLANE_ALLOWED_TRUST_DOMAINS", "")
    if not raw:
        td = os.environ.get("PLANE_TRUST_DOMAIN", "prod")
        return {td}
    return {x.strip() for x in raw.split(",") if x.strip()}


def _try_workload_api(sock_path: str) -> Optional[WorkloadIdentity]:
    reachable = _probe_socket(sock_path)
    try:
        from spiffe import WorkloadApiClient  # type: ignore

        endpoint = sock_path if sock_path.startswith("unix:") else f"unix://{sock_path}"
        with WorkloadApiClient(socket_path=endpoint, default_timeout=5.0) as client:
            svid = client.fetch_x509_svid()
            sid = str(svid.spiffe_id)
            td = _parse_trust_domain(sid)
            allowed = _allowed_trust_domains()
            if td not in allowed:
                print(f"[spiffe] trust domain {td} not in allowed {allowed}")
                return None
            return WorkloadIdentity(sid, td, "workload-api", socket_reachable=True)
    except ImportError:
        if reachable:
            print(
                f"[spiffe] socket reachable at {sock_path}; "
                "pip install spiffe for X509-SVID fetch"
            )
    except Exception as e:
        print(f"[spiffe] Workload API client error: {e}")
    if reachable:
        return None
    return None


def fetch_workload_identity(
    socket_path: Optional[str] = None,
    trust_domain_cfg: Optional[str] = None,
) -> WorkloadIdentity:
    sock = _socket_path(socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET"))
    env_id = os.environ.get("PLANE_SPIFFE_ID") or os.environ.get("SPIFFE_ID")

    if sock:
        ident = _try_workload_api(sock)
        if ident:
            return ident
        reachable = _probe_socket(sock)
        if env_id:
            td = trust_domain_cfg or _parse_trust_domain(env_id)
            return WorkloadIdentity(env_id, td, "env", socket_reachable=reachable)
        td = trust_domain_cfg or os.environ.get("PLANE_TRUST_DOMAIN", "prod")
        return WorkloadIdentity(
            f"spiffe://{td}/agent/dev",
            td,
            "socket",
            socket_reachable=reachable,
        )

    if env_id:
        td = trust_domain_cfg or _parse_trust_domain(env_id)
        return WorkloadIdentity(env_id, td, "env", socket_reachable=False)

    td = trust_domain_cfg or os.environ.get("PLANE_TRUST_DOMAIN", "prod")
    return WorkloadIdentity(f"spiffe://{td}/agent/dev", td, "fallback", socket_reachable=False)


def identity_summary() -> dict:
    ident = fetch_workload_identity()
    return {
        "spiffe_id": ident.spiffe_id,
        "trust_domain": ident.trust_domain,
        "source": ident.source,
        "socket_reachable": ident.socket_reachable,
        "socket_env": os.environ.get("SPIFFE_ENDPOINT_SOCKET"),
    }
