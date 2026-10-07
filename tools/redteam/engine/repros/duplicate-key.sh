#!/bin/bash
# duplicate-key.sh — the repro harness for the "duplicate-key" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. The verdict is REFUTED when the wire
# refuses the attack (the expected behavior) and REPRODUCED when it
# accepts it (a finding).
set -u
. "$(cd "$(dirname "$0")" && pwd)/repro-common.sh"
BASE=$(repro_target)
OUT=$(KIWI_RT_BASE="$BASE" python3 - <<'PY'
import json, os, urllib.error, urllib.request
base = os.environ["KIWI_RT_BASE"]
raw = b"{\"scope\":\"login\",\"scope\":\"signup\"}"
req = urllib.request.Request(base + "/verify", data=raw, method="POST")
req.add_header("content-type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        status, body = resp.status, json.loads(resp.read())
except urllib.error.HTTPError as err:
    status, body = err.code, json.loads(err.read() or b"{}")
code = body.get("error", {}).get("code", "") if isinstance(body, dict) else ""
smuggled = 1 if status == 200 else 0
print(json.dumps({"code": code or str(status), "smuggled": smuggled}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"duplicate-key\", \"verdict\": \"REPRODUCED\" if doc[\"smuggled\"] else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
