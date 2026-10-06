#!/bin/bash
# forged-token.sh — the repro harness for the "forged-token" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. The verdict is REFUTED when the wire
# refuses the attack (the expected behavior) and REPRODUCED when it
# accepts it (a finding).
set -u
. "/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone/tools/redteam/engine/repros/repro-common.sh"
BASE=$(repro_target)
OUT=$(KIWI_RT_BASE="$BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
doc = rt.challenge(base, "login")
nonce = str(doc.body.get("nonce", ""))
forged = rt.forge_token(nonce)
resp = rt.verify(base, forged, scope="login")
accepted = 1 if resp.ok else 0
print(json.dumps({"code": resp.error_code or resp.code or ("accepted" if accepted else "refused"), "accepted": accepted}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"forged-token\", \"verdict\": \"REPRODUCED\" if doc[\"accepted\"] else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
