#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-http://127.0.0.1:8095}
curl -sS "$BASE/health" | python3 -m json.tool
ISSUE=$(curl -sS -X POST "$BASE/v1/capabilities/issue" -H 'content-type: application/json' -d '{"caller":"spiffe://prod/agent/dev","rights":[{"type":"read","resource":"demo","method":"GET"}],"ttl_seconds":60,"correlation_id":"e2e-read-demo"}')
echo "$ISSUE" | python3 -m json.tool
python3 - <<PY
import json,os,urllib.request,sys
base=os.environ.get("BASE","$BASE")
issue=json.loads('''$ISSUE''')
body=json.dumps({"capability":issue["capability"],"signature":issue["signature"],"required":{"type":"read","resource":"demo","method":"GET"},"caller":"spiffe://prod/agent/dev","correlation_id":"e2e-read-demo"}).encode()
req=urllib.request.Request(base+"/v1/execute", data=body, headers={"content-type":"application/json"})
print(urllib.request.urlopen(req).read().decode())
PY
