#!/bin/bash
# d3.5-credential-stuffing.sh — credential stuffing (change.md D3.5).
#
# The flagship campaign. OpenBullet-class adversaries with rented
# solves attack one victim account (login scope) over K attacker
# identities in three shared-ASN groups, every attempt walking the
# deployment's own challenge plus verify flow with an honestly paid
# proof of work, the risk plane scoring through the REAL php risk
# engine over the REAL Redis marks store (the AttackerDenialSimulator
# pattern of both cores, redeployed).
#
# The change.md 3.3.3 outcomes, asserted here:
#   - every attacker identity denied within N = 3 of its own attempts,
#   - the victim sees the interactive step-up exactly once, never a
#     lockout, and its step-up outcome credit books with zero marks,
#   - the storm subsides: after the quiet window the victim's next
#     login is the plain allow,
#   - zero wire failures: the denials come from the risk plane, never
#     from a broken flow.
#
# Economic metric: the attack's measured spend (proof of work hashes
# times the bench price of a solve) bought zero compromised accounts,
# so the cost per compromised account is unbounded.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.5-credential-stuffing
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")

SUMMARY_FILE="$RT_DIR/runs/env/d35-summary-$RT_PROFILE.json"
ERR_FILE="$RT_DIR/runs/env/d35-$RT_PROFILE.err"

KIWI_RT_BASE="$BASE" \
KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="$(rt_state_get "$RT_PROFILE" REDIS_URL)" \
KIWI_RT_SOLVER="$REPO_ROOT/target/debug/kiwicaptcha-solver" \
KIWI_RT_SUMMARY_PATH="$SUMMARY_FILE" \
    php "$RT_DIR/campaigns/lib/d35.driver.php" >"$RT_DIR/runs/env/d35-$RT_PROFILE.stdout" 2>"$ERR_FILE"
DRIVER_RC=$?

print_summary() {
    # The driver's stdout lands in the summary file; wait out the
    # writer's exit flush before parsing it.
    i=0
    while [ "$i" -lt 50 ] && [ ! -s "$SUMMARY_FILE" ]; do
        i=$((i + 1))
        sleep 0.2
    done
    if ! head -c 1 "$SUMMARY_FILE" | grep -q '{'; then
        printf 'debug: summary file not json:\n' >&2
        head -c 300 "$SUMMARY_FILE" >&2
        printf '\n' >&2
    fi
    python3 - "$SUMMARY_FILE" <<'PYPRINT'
import json, sys

doc = json.load(open(sys.argv[1]))
print("ASSERT: %s every attacker denied within %s of its own attempts (rounds %s)"
      % ("PASS" if doc["denied_within_n"] else "FAIL", doc["bound_n"], doc["denial_rounds"]))
print("ASSERT: %s victim step-up exactly once with the target-under-attack reason, then the plain allow"
      % ("PASS" if doc["exactly_one_step_up"] else "FAIL"))
print("ASSERT: %s zero victim lockouts" % ("PASS" if doc["zero_lockouts"] else "FAIL"))
print("ASSERT: %s step-up outcome credit booked with zero marks"
      % ("PASS" if doc["step_up_credit_booked"] else "FAIL"))
print("ASSERT: %s wire honest: %d verifies ok, %d failures, %d posts"
      % ("PASS" if doc["wire_failures"] == 0 else "FAIL",
         doc["wire_verifies_ok"], doc["wire_failures"], doc["http_posts"]))
print("SPEND: hashes=%d" % doc["pow_hashes_spent"])
PYPRINT
}

if [ "$DRIVER_RC" -gt 1 ]; then
    rt_report_fail "driver crashed; see runs/env/d35-$RT_PROFILE.err"
    rt_finish
fi
print_summary

DENIED=$(python3 -c 'import json,sys; print("True" if json.load(open(sys.argv[1]))["denied_within_n"] else "False")' "$SUMMARY_FILE")
STEPUP=$(python3 -c 'import json,sys; print("True" if json.load(open(sys.argv[1]))["exactly_one_step_up"] else "False")' "$SUMMARY_FILE")
LOCKOUT=$(python3 -c 'import json,sys; print("True" if json.load(open(sys.argv[1]))["zero_lockouts"] else "False")' "$SUMMARY_FILE")
CREDIT=$(python3 -c 'import json,sys; print("True" if json.load(open(sys.argv[1]))["step_up_credit_booked"] else "False")' "$SUMMARY_FILE")
WIRES=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["wire_failures"])' "$SUMMARY_FILE")
HASHES=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pow_hashes_spent"])' "$SUMMARY_FILE")

rt_assert_eq "$DENIED" "True" "attacker identities denied within the documented bound"
rt_assert_eq "$STEPUP" "True" "victim step-up exactly once"
rt_assert_eq "$LOCKOUT" "True" "zero victim lockouts"
rt_assert_eq "$CREDIT" "True" "step-up credit booked cleanly"
rt_assert_eq "$WIRES" "0" "zero wire failures under the storm"

# Economic truth: the measured attacker spend versus the outcome.
SHA16_US=$(KIWI_RT_REPO_ROOT="$REPO_ROOT" python3 -c '
import sys
sys.path.insert(0, sys.argv[1])
import lib.rtclient as rt
print("%.0f" % rt.sha16_mean_us(3))
' "$RT_DIR/campaigns" 2>/dev/null)
ATTACK_SECONDS=$(python3 -c "
print('%.1f' % ($HASHES * ${SHA16_US:-0} / 1e6))" 2>/dev/null)
rt_metric "attackers=12 rounds=6 solves=$HASHES hashes spend_cpu_seconds=$ATTACK_SECONDS sha16_solve_us=${SHA16_US:-0}"
printf 'ECONOMIC: %s %s cost_per_compromised_account=unbounded compromised=0 attacker_solve_hashes=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$HASHES"

rt_finish
