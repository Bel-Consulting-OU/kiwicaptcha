#!/bin/bash
# record-tamper.sh — the repro harness for the "record-tamper" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. REFUTED means the wire refused the
# attack (the expected behavior); REPRODUCED means a finding.
set -u
. "/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone/tools/redteam/engine/repros/repro-common.sh"
BASE=$(repro_target)
OUT=$(KIWI_RT_BASE="$BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
doc = rt.solve(base, "login")
token = doc.get("token", "")
tampered = rt.mutate_token(token, len(token) // 2)
resp = rt.verify(base, tampered, scope="login")
accepted = 1 if resp.ok else 0
print(json.dumps({"code": resp.error_code or resp.code or "ok", "accepted": accepted}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"record-tamper\", \"verdict\": \"REPRODUCED\" if doc[\"accepted\"] else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
