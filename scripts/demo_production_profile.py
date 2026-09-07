#!/usr/bin/env python3
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rings.measurement_pin import MeasurementPolicy
print("lab", MeasurementPolicy().accept("dev:unattested"))
os.environ["PRODUCTION"] = "1"
print("prod-dev", MeasurementPolicy().accept("dev:unattested"))
print("prod-pin", MeasurementPolicy().accept("sha256:REPLACE_NITRO_PCR0"))
