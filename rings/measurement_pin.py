import os
from pathlib import Path

class MeasurementPolicy:
    def __init__(self, raw=None):
        self.raw = raw or {"allowed": [{"measurement": "dev:unattested", "env": "dev"}]}
        self.production = os.environ.get("PRODUCTION", "0") == "1"

    def accept(self, measurement):
        if self.production and str(measurement).startswith("dev:"):
            return False, "unattested broker refused in production"
        if self.production and measurement == "sha256:REPLACE_NITRO_PCR0":
            return True, "pinned"
        if not self.production:
            return True, "lab"
        return False, "unattested broker refused in production"
