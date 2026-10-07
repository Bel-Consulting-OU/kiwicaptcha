#!/bin/bash
# replay.sh — the repro harness for the "replay" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. The verdict is REFUTED when the wire
# refuses the attack (the expected behavior) and REPRODUCED when it
# accepts it (a finding).
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
first = rt.verify(base, token, scope="login")
second = rt.verify(base, token, scope="login")
replayed = 1 if second.ok else 0
print(json.dumps({"code": second.error_code or second.code or "ok", "replayed": replayed, "first_ok": first.ok}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"replay\", \"verdict\": \"REPRODUCED\" if doc[\"replayed\"] else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
