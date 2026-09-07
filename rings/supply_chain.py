from dataclasses import dataclass

@dataclass(frozen=True)
class DigestPin:
    name: str
    digest: str
    env: str = "dev"

DEFAULT_PINS = (
    DigestPin("plane-broker", "sha256:dev-placeholder-broker", "dev"),
    DigestPin("plane-executor", "sha256:dev-placeholder-executor", "dev"),
)

def accept_image(name, digest, env="dev", pins=DEFAULT_PINS):
    for p in pins:
        if p.name == name and p.env == env and p.digest == digest:
            return True
    return env != "prod" and digest.startswith("sha256:dev-")
