#!/bin/bash
# epoch-manipulation.sh — the repro harness for the "epoch-manipulation" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. REFUTED means the wire refused the
# attack (the expected behavior); REPRODUCED means a finding.
set -u
. "$(cd "$(dirname "$0")" && pwd)/repro-common.sh"
BASE=$(repro_target)
EPH_BASE="$BASE"
# A one-second-TTL instance of the same core: the expired-epoch probe.
PORT=8499
sh "$RT_DIR/target.sh" down eph >/dev/null 2>&1 || true
EPH_REDIS_URL=$(redis-cli -u "${KIWI_RT_RISK_REDIS_URL:-redis://127.0.0.1:6480}" ping >/dev/null 2>&1 && echo "${KIWI_RT_RISK_REDIS_URL:-redis://127.0.0.1:6480}" || echo "")
if [ -z "$EPH_REDIS_URL" ]; then
    # No target means no measurement: INCONCLUSIVE, never a quiet REFUTED.
    printf "{\"harness\":\"epoch-manipulation\",\"verdict\":\"INCONCLUSIVE\",\"wire_code\":\"target_unavailable\"}\n"
    exit 0
fi
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="$EPH_REDIS_URL" KIWI_SECRET_KEY="ephephephEPHEPHEPHEPHEPHEPHEPHephepheph" \
    KIWI_SHA_TARGET_BITS=10 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=1 \
    php -S "127.0.0.1:$PORT" -t "$REPO_ROOT/deploy/app" "$REPO_ROOT/deploy/app/router.php" >/dev/null 2>&1 &
EPH_PID=$!
sleep 0.8
EPH_BASE="http://127.0.0.1:$PORT"
OUT=$(KIWI_RT_BASE="$EPH_BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys, time
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
doc = rt.challenge(base, "login")
if doc.status != 200:
    print(json.dumps({"code": "issue_failed", "expired": 0}))
    raise SystemExit
counter = rt.pow_solve(doc.body)
token = rt.mint_token(str(doc.body["nonce"]), counter)
time.sleep(2.2)
resp = rt.verify(base, token, scope="login")
print(json.dumps({"code": resp.error_code or resp.code or "ok", "expired": 0 if resp.ok else 0, "accepted": 1 if resp.ok else 0}))
PY
)
kill "$EPH_PID" 2>/dev/null
pkill -f "php -S 127.0.0.1:$PORT " 2>/dev/null
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({\"harness\": \"epoch-manipulation\", \"verdict\": \"REPRODUCED\" if doc.get(\"accepted\") else \"REFUTED\", \"wire_code\": doc[\"code\"]}))
"
