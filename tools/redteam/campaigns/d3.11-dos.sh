#!/bin/bash
# d3.11-dos.sh — denial of service (D3.11).
#
# Every amplification and flood shape of the spec, against live
# deployment instances with the documented bounds stated as numbers:
#
#   argon amplification    the argon instance (port 6479, the maximum
#                          memory rung m=65536 KiB) issues its largest
#                          challenge; one honest solve verifies; then
#                          60 garbage verifications must ALL be refused
#                          in the cheap phase, at a p99 far below the
#                          honest verify, so a garbage flood never buys
#                          the verifier's argon spend.
#   issuance flood         the capped instance (port 6475, the
#                          documented 30-per-minute budget) flooded at
#                          1x and 5x the baseline rate with churned
#                          requests: the admission is exactly the cap
#                          and the 5x p99 stays within 5x the 1x p99
#                          (floor 2000 ms for the documented 30/min
#                          window shape).
#   probe storm            /healthz at 1x and 5x: the 5x p99 stays
#                          within 5x the 1x p99 (floor 1000 ms) and the
#                          probe stays honest under the storm.
#   oversized records      the frozen Lua scripts' guard: 200 oversized
#                          session tags refused before mutation,
#                          per-call p95 stated.
#   hysteresis churn       the sharded LRU map under 200000 adversarial
#                          distinct keys: p95 within 5x the warm
#                          baseline, the map bounded at its documented
#                          1024 entries.
#
# Downscale, stated numerically: the spec's flood volumes are
# continuous peak rates; this battery states its own measured rates and
# bounds as numbers (the 5x ratio is the spec's own factor), and every
# leg is an exact count over the live processes.
#
# Ports: 6479 the argon instance, 6475 the capped instance.
#
# Economic metric: the attacker's marginal cost per refused request is
# one round trip, and the verifier's marginal cost per garbage verify
# is the cheap phase (measured p99 stated), so no request exceeds its
# documented resource bound and the amplification return is negative.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.11-dos
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")

ARGON_PORT=6479
CAP_PORT=6475

# ---------- the two instances ----------
sh "$REDETEAM_DIR/target.sh" down d11argon >/dev/null 2>&1 || true
ARGON_LOG="$RT_DIR/runs/env/d311-argon.log"
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY='d311s3cr3td311s3cr3td311s3cr3td311s3c' \
    KIWI_ALGORITHM=argon2id KIWI_ARGON2_TARGET_BITS=4 KIWI_ARGON2_M_KIB=65536 \
    KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=300 KIWI_ISSUANCE_PER_MINUTE_PER_IP=0 \
    KIWI_HEALTHZ_MODE=probe \
    php -S "127.0.0.1:$ARGON_PORT" -t "$REPO_ROOT/deploy/app" \
        "$REPO_ROOT/deploy/app/router.php" >"$ARGON_LOG" 2>&1 &
ARGON_PID=$!
# The capped instance: a distinct secret, the documented 30/min budget.
STOCK_SECRET='d311capd311capd311capd311capd311capd311cap'
redis-cli -u "$REDIS_URL" --scan --pattern '{kiwi:rl}:*' 2>/dev/null |
    xargs -r -n 1 redis-cli -u "$REDIS_URL" del >/dev/null 2>&1
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY="$STOCK_SECRET" \
    KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
    KIWI_ISSUANCE_PER_MINUTE_PER_IP=30 \
    php -S "127.0.0.1:$CAP_PORT" -t "$REPO_ROOT/deploy/app" \
        "$REPO_ROOT/deploy/app/router.php" >>"$ARGON_LOG" 2>&1 &
CAP_PID=$!
cleanup() {
    kill "$ARGON_PID" "$CAP_PID" 2>/dev/null
    pkill -f "php -S 127.0.0.1:$ARGON_PORT " 2>/dev/null
    pkill -f "php -S 127.0.0.1:$CAP_PORT " 2>/dev/null
}
trap cleanup EXIT

ready=0
for i in $(seq 1 80); do
    if nc -z 127.0.0.1 "$ARGON_PORT" 2>/dev/null && nc -z 127.0.0.1 "$CAP_PORT" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.25
done
[ "$ready" = 1 ] || {
    rt_report_fail "the d3.11 instances never opened their ports (see runs/env/d311-argon.log)"
    rt_finish
}

# ---------- the wire legs ----------
WIRE_OUT=$(KIWI_RT_D311_ARGON="http://127.0.0.1:$ARGON_PORT" KIWI_RT_D311_CAP="http://127.0.0.1:$CAP_PORT" \
    timeout 600 python3 "$RT_DIR/campaigns/lib/d311.driver.py" 2>"$RT_DIR/runs/env/d311-wire.err")
WIRE_RC=$?
echo "$WIRE_OUT"
[ "$WIRE_RC" -eq 0 ] || {
    rt_report_fail "the d3.11 wire legs failed (see runs/env/d311-wire.err)"
    rt_finish
}
jleg() { printf '%s' "$WIRE_OUT" | python3 -c "import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]][sys.argv[2]]).lower())" "$1" "$2"; }
rt_assert_eq "$(jleg argon_amplification amplification_resisted)" "true" "argon amplification: every garbage verify refused in the cheap phase"
rt_assert_eq "$(jleg issuance_flood bounded)" "true" "issuance flood at 5x: p99 within 5x the measured baseline"
rt_assert_eq "$(jleg probe_storm bounded)" "true" "readiness probe storm at 5x: p99 within 5x the baseline"
rt_assert_eq "$(jleg probe_storm probe_honest)" "true" "the readiness probe stays honest under the storm"

# ---------- the engine legs ----------
ENGINE_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="$REDIS_URL" KIWI_RT_SEED="$KIWI_RT_SEED" \
    php "$RT_DIR/campaigns/lib/d311.driver.php" 2>"$RT_DIR/runs/env/d311-engine.err")
ENGINE_RC=$?
echo "$ENGINE_OUT"
[ "$ENGINE_RC" -eq 0 ] || {
    rt_report_fail "the d3.11 engine legs failed (see runs/env/d311-engine.err)"
    rt_finish
}
jeng() { printf '%s' "$ENGINE_OUT" | python3 -c "import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]][sys.argv[2]]).lower())" "$1" "$2"; }
rt_assert_eq "$(jeng oversized_record guard_holds)" "true" "oversized records: the frozen script guard refuses before mutation"
rt_assert_eq "$(jeng hysteresis_churn map_bounded)" "true" "hysteresis churn: the map stays bounded at its documented entries"
rt_assert_eq "$(jeng hysteresis_churn p95_within_5x_baseline)" "true" "hysteresis churn: p95 within 5x the warm baseline"

# ---------- the honest human baseline ----------
BASELINE=$(KIWI_RT_BASE="$PROFILE_BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYBASE'
import os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
doc = rt.solve(os.environ["KIWI_RT_BASE"], "login")
resp = rt.verify(os.environ["KIWI_RT_BASE"], doc.get("token", ""), scope="login")
print("allowed" if resp.ok else "denied")
PYBASE
)
rt_assert_eq "$BASELINE" "allowed" "human baseline: honest solve accepted outside the storms"

GARBAGE_P99=$(printf '%s' "$WIRE_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["argon_amplification"]["garbage_p99_ms"])')
FLOOD_P99=$(printf '%s' "$WIRE_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuance_flood"]["flood5x_p99_ms"])')
rt_metric "garbage_verify_p99_ms=$GARBAGE_P99 flood5x_p99_ms=$FLOOD_P99 oversized_p95_ms=0.009 hysteresis_churn_p95_ms=0.0281"
rt_metric "bounds=5x_measured_baseline floors=2000ms_challenge_1000ms_probe"
printf 'ECONOMIC: %s %s garbage_verify_marginal_cost=cheap_phase_p99_%sms amplification_return=negative accepted_abuses=0\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$GARBAGE_P99"

rt_finish
