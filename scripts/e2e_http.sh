#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-http://127.0.0.1:8090}
curl -sS "$BASE/health" | python3 -m json.tool
ISSUE=$(curl -sS -X POST "$BASE/v1/capabilities/issue" -H 'content-type: application/json' -d '{"caller":"spiffe://prod/agent/dev","rights":[{"type":"read","resource":"demo"}],"ttl_seconds":60}')
echo "$ISSUE" | python3 -m json.tool
python3 - <<PY
import json,os,urllib.request,sys
base=os.environ.get("BASE","$BASE")
issue=json.loads('''$ISSUE''')
body=json.dumps({"capability":issue["capability"],"signature":issue["signature"],"required":{"type":"read","resource":"demo"},"caller":"spiffe://prod/agent/dev"}).encode()
req=urllib.request.Request(base+"/v1/execute", data=body, headers={"content-type":"application/json"})
print(urllib.request.urlopen(req).read().decode())
PY
