#!/bin/bash
# d3.1-commodity-nojs.sh — commodity no-JS bots (change.md D3.1).
#
# The spec asks for 10^5 forged, replayed and omitted tokens per hour.
# This harness states its downscale openly: KIWI_RT_D31_N drives the
# attempt budget (default 600 attempts, a 167x downscale of one hour's
# volume onto a laptop loopback).
#
# Attack classes, every one through the deployment's REAL verify
# endpoint: forged random tokens, structurally valid forgeries that
# never paid the proof of work, bit-flipped real tokens, replays of a
# legitimately solved token, omitted and empty tokens, cross-scope and
# binding re-labeling, oversized and malformed documents, wrong
# algorithm probes and scope confusables.
#
# Required result: zero accepted anywhere, the one-shot anti-oracle
# holds (a failed binding attempt burns the record), and the per-IP
# issuance cap holds exactly where the profile runs a Redis limiter
# (30 budget: 30 issues, the rest refused with 429).
#
# Human baseline: one honest solve plus one honest verification must
# succeed in the same run; a legitimate denial fails the release.
#
# Economic metric: cost per accepted abuse is unbounded (0 accepted);
# the run also reports what one honest solve costs on this cpu.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.1-commodity-nojs
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")
ATTEMPT_BUDGET=${KIWI_RT_D31_N:-$((600 * KIWI_RT_SCALE / 100))}

RESULT_FILE=$(mktemp "${TMPDIR:-/tmp}/kiwi-rt-d31.XXXXXX")
ERR_FILE="$RT_DIR/runs/env/d31-$RT_PROFILE.err"

KIWI_RT_REPO_ROOT="$REPO_ROOT" KIWI_RT_BASE="$BASE" KIWI_RT_N="$ATTEMPT_BUDGET" \
    python3 "$RT_DIR/campaigns/lib/d31.driver.py" >"$RESULT_FILE" 2>"$ERR_FILE"
DRIVER_RC=$?

fail_driver() {
    rt_report_fail "driver crashed; see runs/env/d31-$RT_PROFILE.err"
    rt_finish
}
[ "$DRIVER_RC" -le 1 ] || fail_driver

python3 - "$RESULT_FILE" <<'PYEOF'
import json, sys

doc = json.load(open(sys.argv[1]))
for row in doc["assertions"]:
    print("ASSERT: %s %s" % ("PASS" if row["ok"] else "FAIL", row["what"]))
print("SUMMARY: attempts=%d accepted=%d replay_burned=%d honest=%s"
      % (doc["attempts"], doc["accepted"], doc["replay_burned"], doc["honest_solve"]))
PYEOF

SUMMARY=$(python3 - "$RESULT_FILE" <<'PYPARSE'
import json, sys

doc = json.load(open(sys.argv[1]))
print("accepted=%d honest=%s attempts=%d replay_burned=%d"
      % (doc["accepted"], doc["honest_solve"], doc["attempts"], doc["replay_burned"]))
PYPARSE
)
ACCEPTED=$(printf '%s\n' "$SUMMARY" | sed -n 's/^accepted=\([0-9]*\).*$/\1/p')
HONEST=$(printf '%s\n' "$SUMMARY" | sed -n 's/^accepted=[0-9]* honest=\([A-Za-z]*\).*$/\1/p')

rt_assert_eq "$ACCEPTED" "0" "zero forged, replayed or omitted tokens accepted"
rt_assert_eq "$HONEST" "True" "human baseline: honest solve and verify accepted"

# The issuance cap leg: a dedicated deployment instance on the same
# Redis with the documented 30-per-minute budget; 40 burst posts must
# yield exactly 30 issues and 10 refusals with 429.
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
if [ -n "$REDIS_URL" ]; then
    CAP_PORT=$(( $(rt_state_get "$RT_PROFILE" PORT) + 20 ))
    CAP_SECRET='cap9d3b1f0aa71c4e2f90b35d671c2e5fa89c4d2e6f8071a3b5c9d7e1f2a4b6c8d0'
    env KC_REDIS_URL="$REDIS_URL" KIWI_SECRET_KEY="$CAP_SECRET" \
        KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 \
        KIWI_ISSUANCE_PER_MINUTE_PER_IP=30 \
        php -S "127.0.0.1:$CAP_PORT" -t "$REPO_ROOT/deploy/app" \
            "$REPO_ROOT/deploy/app/router.php" >/dev/null 2>&1 &
    CAP_PID=$!
    sleep 0.8
    # The limiter window persists on the dedicated redteam redis; the
    # profile's limiter keys are cleared first so the burst starts
    # from a zero counter.
    redis-cli -u "$REDIS_URL" --scan --pattern '{kiwi:rl}:*' 2>/dev/null |
        xargs -I{} redis-cli -u "$REDIS_URL" del '{}' >/dev/null 2>&1
    CAP_OUT=$(KIWI_RT_BASE="http://127.0.0.1:$CAP_PORT" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYCAP'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ.get("KIWI_RT_DIR", ".")))
base = os.environ["KIWI_RT_BASE"]
import rtclient as rt
issued = limited = 0
for i in range(40):
    resp = rt.challenge(base, "login")
    if resp.status == 200 and resp.body.get("nonce"):
        issued += 1
    elif resp.status == 429 and resp.error_code == "RATE_LIMITED":
        limited += 1
print(json.dumps({"issued": issued, "limited": limited}))
PYCAP
    )
    kill "$CAP_PID" 2>/dev/null
    CAP_PARSE=$(printf '%s' "$CAP_OUT" | python3 -c 'import json, sys; doc = json.load(sys.stdin); print(doc["issued"], doc["limited"])')
    CAP_ISSUED=${CAP_PARSE%% *}
    CAP_LIMITED=${CAP_PARSE##* }
    rt_assert_eq "$CAP_ISSUED" "30" "issuance cap admits exactly the budget"
    rt_assert_eq "$CAP_LIMITED" "10" "issuance cap refuses the burst remainder"
    rt_metric "issuance_cap=30 issued=$CAP_ISSUED limited=$CAP_LIMITED"
else
    rt_metric "issuance_cap=not-applicable (storage profile runs no Redis limiter)"
fi

rt_metric "attempts=$ATTEMPT_BUDGET downscaled_from=100000"
printf 'ECONOMIC: %s %s cost_per_accepted_abuse=unbounded accepted=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$ACCEPTED"

rt_finish
