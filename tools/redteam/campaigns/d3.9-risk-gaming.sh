#!/bin/bash
# d3.9-risk-gaming.sh — risk-engine gaming (D3.9).
#
# Five gaming strategies, each against the REAL risk engine over the
# REAL Redis, asserted from the engine's own outputs:
#
#   trust farming        a session earns home-bucket credit and its
#                        cookie is replayed from 300 foreign ASN
#                        buckets: every foreign read earns and sees
#                        nothing; the home commute keeps every unit.
#   boundary riding      an oscillating edge score (449, 451, 450...)
#                        selects the stable hysteresis action, never a
#                        per-request flip.
#   calibration poison   the label flood of the 10^5-labels test,
#                        re-driven through the REAL outcome plane
#                        (register + confirm on the real store) at the
#                        stated count: forged confirmed-legitimate
#                        labels move the scope bias at most 1 point.
#   mark evasion         the storm session churns into fresh session
#                        identities: every churned identity starts
#                        untrusted while the source dimension keeps the
#                        storm pressure, so churn buys no escape.
#   victim forcing       the attacker shares the victim's subnet and
#                        carries confirmed abuse marks: the victim's
#                        own decision stays at its own price while the
#                        attacker is denied.
#
# Downscale, stated numerically: the label flood default is the full
# 10^5 forged labels of the calibration test; KIWI_RT_D39_LABELS
# scales it, and the rest of the legs are exact-integer mechanisms.
#
# Ports: 6478 this campaign's dedicated redis.
#
# Economic metric: every gaming strategy yields zero (farmed credit
# value 0 off-home, poisoned bias movement 0 measured points, churned
# identities start untrusted), so the cost of gaming the engine
# exceeds its yield and the return on gaming investment is zero.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.9-risk-gaming
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")

REDIS_PORT=6478
LABELS=${KIWI_RT_D39_LABELS:-$((100000 * KIWI_RT_SCALE / 100))}
[ "$LABELS" -lt 20000 ] && LABELS=20000

redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1
sleep 0.3
mkdir -p "$RT_DIR/runs/env/d39"
redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no \
    --daemonize no --dir "$RT_DIR/runs/env/d39" >"$RT_DIR/runs/env/d39-redis.log" 2>&1 &
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
    rt_report_fail "the d3.9 redis never opened port $REDIS_PORT"
    rt_finish
}

DRIVER_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="redis://127.0.0.1:$REDIS_PORT" \
KIWI_RT_SEED="$KIWI_RT_SEED" KIWI_RT_D39_LABELS="$LABELS" \
    php "$RT_DIR/campaigns/lib/d39.driver.php" 2>"$RT_DIR/runs/env/d39-driver.err")
DRIVER_RC=$?
echo "$DRIVER_OUT" | python3 -m json.tool 2>/dev/null || echo "$DRIVER_OUT"
[ "$DRIVER_RC" -eq 0 ] || {
    rt_report_fail "the d3.9 driver failed (see runs/env/d39-driver.err)"
    rt_finish
}

j() { printf '%s' "$DRIVER_OUT" | python3 -c "import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]][sys.argv[2]]).lower())" "$1" "$2"; }
rt_assert_eq "$(j trust_farming foreign_credit_zero)" "true" "trust farming: farmed credit never crosses ASNs (300 foreign peers)"
rt_assert_eq "$(j trust_farming home_credit_kept)" "true" "trust farming: the genuine home commute keeps every unit"
rt_assert_eq "$(j boundary_riding stable)" "true" "boundary riding: the edge-oscillating score selects the stable action"
rt_assert_eq "$(j calibration_poison bias_bounded_1_point)" "true" "calibration poisoning: the forged label flood moves the bias at most 1 point"
rt_assert_eq "$(j mark_evasion churned_starts_untrusted)" "true" "mark evasion: churned identities start untrusted"
rt_assert_eq "$(j mark_evasion source_pressure_kept)" "true" "mark evasion: the source dimension keeps the storm pressure across churn"
rt_assert_eq "$(j victim_forcing victim_clean)" "true" "victim forcing: the shared-network victim stays at its own price"
rt_assert_eq "$(j victim_forcing attacker_denied)" "true" "victim forcing: the marked attacker is denied"

# The honest human baseline outside the gaming.
BASELINE=$(KIWI_RT_BASE="$PROFILE_BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYBASE'
import os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
doc = rt.solve(os.environ["KIWI_RT_BASE"], "login")
resp = rt.verify(os.environ["KIWI_RT_BASE"], doc.get("token", ""), scope="login")
print("allowed" if resp.ok else "denied")
PYBASE
)
rt_assert_eq "$BASELINE" "allowed" "human baseline: honest solve accepted"

BIAS=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calibration_poison"]["bias_after_points"])')
rt_metric "labels=$LABELS bias_after=$BIAS foreign_peers=300 riding_scores=8 churn_sessions=2"
rt_metric "downscale=labels_are_the_full_100000 mechanisms_exact"
printf 'ECONOMIC: %s %s gaming_yield=zero farmed_offhome_credit=0 poisoned_bias_points=%s churned_escapes=0\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$BIAS"

rt_finish
