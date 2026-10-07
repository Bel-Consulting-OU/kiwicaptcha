#!/bin/bash
# privacy-canary.sh — the repro harness for the "privacy-canary" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. REFUTED means the wire refused the
# attack (the expected behavior); REPRODUCED means a finding.
set -u
. "$(cd "$(dirname "$0")" && pwd)/repro-common.sh"
BASE=$(repro_target)
CANARY="canary-$(head -c 6 /dev/urandom | xxd -p)"
OUT=$(KIWI_RT_BASE="$BASE" KIWI_RT_CANARY="$CANARY" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
canary = os.environ["KIWI_RT_CANARY"]
binding = canary + "-binding"
doc = rt.challenge(base, "login", binding=binding)
if doc.status != 200:
    print(json.dumps({"code": "issue_failed", "leaked": 1}))
    raise SystemExit
counter = rt.pow_solve(doc.body)
token = rt.mint_token(str(doc.body["nonce"]), counter)
rt.verify(base, token, scope="login", binding=binding)
import subprocess
url = os.environ.get("KIWI_RT_RISK_REDIS_URL", "")
dump = subprocess.run(["redis-cli", "-u", url, "--scan"], capture_output=True, text=True).stdout
leaked = 0
for key in dump.splitlines():
    value = subprocess.run(["redis-cli", "-u", url, "get", key], capture_output=True, text=True).stdout
    if canary in value:
        leaked = 1
        break
print(json.dumps({"code": "scanned", "leaked": leaked}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"privacy-canary\", \"verdict\": \"REPRODUCED\" if doc[\"leaked\"] else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
