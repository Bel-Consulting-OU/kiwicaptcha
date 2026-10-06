#!/bin/bash
# binding-relabel.sh — the repro harness for the "binding-relabel" candidate class.
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
wrong = rt.verify(base, token, scope="login", binding="attacker-binding")
retried = rt.verify(base, token, scope="login", binding="victim-binding")
relabeled = 1 if wrong.ok or retried.ok else 0
code = wrong.error_code or retried.error_code or "ok"
print(json.dumps({"code": code, "relabeled": relabeled}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"binding-relabel\", \"verdict\": \"REPRODUCED\" if doc[\"relabeled\"] else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
