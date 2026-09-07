#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evidence.warehouse import EvidenceWarehouse
wh = EvidenceWarehouse()
print(json.dumps(wh.verify_chain()))
