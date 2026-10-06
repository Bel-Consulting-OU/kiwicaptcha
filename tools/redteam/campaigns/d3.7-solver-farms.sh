#!/bin/bash
# d3.7-solver-farms.sh — human-solver farms versus step-up (D3.7).
#
# The farm relays what a human solver produces: a phishing proxy
# captures the step-up material and replays it inside its validity
# window. The campaign drives the REAL bundle handlers over the REAL
# Redis step-up store (this campaign's own redis instance on port
# 6476):
#
#   TOTP      the code IS relayable by design, and the campaign says
#             so and measures the residual: the relayed code completes
#             exactly once; the replay guard refuses the same
#             time-step a second time; the challenge record is single
#             use; the begin flood hits the rate bound (9 of 10
#             refused); wrong codes burn the attempt cap.
#
#   WebAuthn  phishing-resistant end to end through the real lib
#             ceremony (webauthn-lib, installed by this campaign's
#             bundle-vendor): a phishing origin (evil.example) with a
#             phishing rp-id is REFUSED at the ceremony step; the
#             honest origin registers and asserts; the replayed
#             assertion is refused.
#
# Downscale, stated numerically: the class volume is a farm working
# relayed challenges continuously; the measured facts here are exact
# integers per handler (one relay, one refusal each), the mechanism is
# the real one end to end.
#
# Ports: 6476 this campaign's dedicated redis.
#
# Economic metric: a relayed TOTP code is worth exactly one completion
# (the replay guard makes it single use), so the farm's resale price
# per relayed code collapses to the single-use value; WebAuthn yields
# zero completions per phished ceremony; the cost per accepted relayed
# abuse beyond the first completion is unbounded.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.7-solver-farms
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"

REDIS_PORT=6476

# ---------- the dedicated redis ----------
redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1
pkill -f "redis-server .*:$REDIS_PORT" 2>/dev/null
sleep 0.3
mkdir -p "$RT_DIR/runs/env/d37"
redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no \
    --daemonize no --dir "$RT_DIR/runs/env/d37" >"$RT_DIR/runs/env/d37-redis.log" 2>&1 &
REDIS_PID=$!
cleanup() {
    kill "$REDIS_PID" 2>/dev/null
    redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1
}
trap cleanup EXIT

ready=0
for i in $(seq 1 40); do
    if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
[ "$ready" = 1 ] || {
    rt_report_fail "the d3.7 redis never opened port $REDIS_PORT"
    rt_finish
}

DRIVER_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_D37_REDIS_URL="redis://127.0.0.1:$REDIS_PORT" \
KIWI_RT_BUNDLE_TESTS="$REPO_ROOT/packages/kiwicaptcha/integrations/symfony/tests" \
    php "$RT_DIR/campaigns/lib/d37.driver.php" 2>"$RT_DIR/runs/env/d37-driver.err")
DRIVER_RC=$?
echo "$DRIVER_OUT" | python3 -m json.tool 2>/dev/null || echo "$DRIVER_OUT"
[ "$DRIVER_RC" -eq 0 ] || {
    rt_report_fail "the d3.7 driver failed (see runs/env/d37-driver.err)"
    rt_finish
}

jtotp() { printf '%s' "$DRIVER_OUT" | python3 -c "import json,sys; print(str(json.load(sys.stdin)['totp'][sys.argv[1]]).lower())" "$1"; }
jwa() { printf '%s' "$DRIVER_OUT" | python3 -c "import json,sys; print(str(json.load(sys.stdin)['webauthn'][sys.argv[1]]).lower())" "$1"; }

# The honest residual, asserted verbatim: the relay succeeds once.
rt_assert_eq "$(jtotp relayed_code_completed_once)" "true" \
    "totp residual: the relayed code completes once (relayable by design)"
rt_assert_eq "$(jtotp replay_guard_blocked_second)" "true" "totp: the replay guard refuses the second presentation"
rt_assert_eq "$(jtotp consumed_record_refused)" "true" "totp: the consumed record refuses further completions"
rt_assert_eq "$(jtotp attempt_cap_burns_challenge)" "true" "totp: wrong codes burn the attempt cap"
RATE_LIMITED=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["totp"]["begin_rate_limited_of_10"])')
[ "$RATE_LIMITED" -ge 7 ] || rt_report_fail "totp: the begin rate bound admitted a flood ($RATE_LIMITED of 10 refused)"
rt_metric "totp_begin_rate_limited=$RATE_LIMITED of 10"

rt_assert_eq "$(jwa phishing_origin_refused)" "true" "webauthn: the phishing origin ceremony is refused"
rt_assert_eq "$(jwa honest_registration_completed)" "true" "webauthn: the honest origin registers"
rt_assert_eq "$(jwa honest_assertion_completed)" "true" "webauthn: the honest origin asserts"
rt_assert_eq "$(jwa assertion_replay_refused)" "true" "webauthn: the replayed assertion is refused"

printf 'ECONOMIC: %s %s relayed_code_resale_value=single_use webauthn_phish_yield=0 cost_per_accepted_relayed_abuse_beyond_first=unbounded\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
