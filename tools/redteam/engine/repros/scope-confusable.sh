#!/bin/bash
# scope-confusable.sh — the repro harness for the "scope-confusable" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. REFUTED means the wire refused the
# attack (the expected behavior); REPRODUCED means a finding.
set -u
. "$(cd "$(dirname "$0")" && pwd)/repro-common.sh"
BASE=$(repro_target)
OUT=$(KIWI_RT_BASE="$BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
doc = rt.solve(base, "login")
token = doc.get("token", "")
resp = rt.verify(base, token, scope="Login")
confused = 1 if resp.ok else 0
print(json.dumps({"code": resp.error_code or resp.code or "ok", "confused": confused}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"scope-confusable\", \"verdict\": \"REPRODUCED\" if doc[\"confused\"] else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
