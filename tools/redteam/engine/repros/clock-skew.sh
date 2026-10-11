#!/bin/bash
# clock-skew.sh — the repro harness for the "clock-skew" candidate
# class. A client-fabricated solve duration is the clock-shaped claim
# the verifier owns: against a floor-enforced instance a below-floor
# duration is refused; acceptance would be a finding.
set -u
. "$(cd "$(dirname "$0")" && pwd)/repro-common.sh"
PORT=8498
sh "$RT_DIR/target.sh" down skew >/dev/null 2>&1 || true
REDIS_URL=$(repro_redis_url)
if [ -z "$REDIS_URL" ]; then
    # No target means no measurement: INCONCLUSIVE, never a quiet REFUTED.
    printf '{"harness":"clock-skew","verdict":"INCONCLUSIVE","wire_code":"target_unavailable"}\n'
    exit 0
fi
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="$REDIS_URL" KIWI_SECRET_KEY="skewskeWskewsKEWskewsKEWsKEWsKEW23" \
    KIWI_SHA_TARGET_BITS=10 KIWI_MIN_DURATION_MS=3000 KIWI_TTL_SECS=120 \
    KIWI_ISSUANCE_PER_MINUTE_PER_IP=0 \
    php -S "127.0.0.1:$PORT" -t "$REPO_ROOT/deploy/app" "$REPO_ROOT/deploy/app/router.php" >/dev/null 2>&1 &
SKEW_PID=$!
# Wait for readiness instead of a fixed sleep: a busy host boots the
# php server late, and a raced boot would only mint an honest
# INCONCLUSIVE. The probe below still reports a real failure as such.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if curl -s --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/healthz"; then
        break
    fi
    sleep 0.5
done
OUT=$(KIWI_RT_BASE="http://127.0.0.1:$PORT" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
doc = rt.challenge(base, "login")
if doc.status != 200:
    # A failed issue is no measurement: accepted stays 0 and the
    # verdict below is INCONCLUSIVE, never a quiet REPRODUCED.
    print(json.dumps({"code": "issue_failed", "accepted": 0}))
    raise SystemExit
counter = rt.pow_solve(doc.body)
token = rt.mint_token(str(doc.body["nonce"]), counter, duration_ms=0)
resp = rt.verify(base, token, scope="login")
print(json.dumps({"code": resp.error_code or resp.code or "ok", "accepted": 1 if resp.ok else 0}))
PY
)
kill "$SKEW_PID" 2>/dev/null
# The teardown is synchronous so the next harness run can bind the
# same port: a lingering server would turn the next boot into a race.
wait "$SKEW_PID" 2>/dev/null
pkill -f "php -S 127.0.0.1:$PORT " 2>/dev/null
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
if doc.get('code') == 'issue_failed':
    verdict = 'INCONCLUSIVE'
elif doc.get('accepted'):
    verdict = 'REPRODUCED'
else:
    verdict = 'REFUTED'
print(json.dumps({'harness': 'clock-skew', 'verdict': verdict, 'wire_code': doc['code']}))
"
