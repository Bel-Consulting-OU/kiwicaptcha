#!/bin/bash
# issuance-burst.sh — the repro harness for the "issuance-burst" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. REFUTED means the wire refused the
# attack (the expected behavior); REPRODUCED means a finding. No
# hardcoded verdict: the observed admission count decides.
set -u
. "/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone/tools/redteam/engine/repros/repro-common.sh"
BASE=$(repro_target)
if [ -z "$BASE" ]; then
    printf '{"harness":"issuance-burst","verdict":"INCONCLUSIVE","wire_code":"target_unavailable","accepted":0}\n'
    exit 0
fi
OUT=$(KIWI_RT_BASE="$BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
accepted = 0
for _ in range(50):
    doc = rt.challenge(base, "login")
    if doc.status == 200:
        accepted += 1
code = "burst_admitted" if accepted > 45 else "capped"
print(json.dumps({"code": code, "accepted": accepted}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
# A burst that admitted more than the cap is the attack succeeding.
verdict = 'REPRODUCED' if doc['accepted'] > 45 else 'REFUTED'
print(json.dumps({'harness': 'issuance-burst', 'verdict': verdict, 'wire_code': doc['code'], 'accepted': doc['accepted']}))
"
