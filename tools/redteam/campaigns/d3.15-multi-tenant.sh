#!/bin/bash
# d3.15-multi-tenant.sh — multi-tenant isolation (D3.15).
#
# Two tenants share one Redis (this campaign's instance on port 6479)
# with every collision the spec names: colliding raw namespaces
# (suffix-identical pairs, the legacy sanitization fold, case
# variants), the SAME secret on both tenants, and the same scope
# names. The planes under test are the real stores: the risk plane's
# RedisRiskStateStore families (marks, decision ledger, bucket trust)
# under the digest namespace derivation, and the core's challenge
# record stores under distinct prefixes.
#
# Required results (asserted from real reads and real verifies):
#   - the digest namespace derivation is injective over the crafted
#     corpus (no two tenants' key families touch), and the legacy
#     derivation's fold is asserted as the documented hazard;
#   - zero cross-tenant reads: B reads A's mark, decision and trust
#     keys and finds nothing;
#   - the keyspace is segregated: A's and B's key sets never overlap;
#   - a crafted key named after A's layout but written in B's family
#     stays in B's family;
#   - zero cross-tenant replay with the SAME secret: A's token never
#     verifies through B's store, the same-tenant verify works, and
#     the one-shot consume holds on the owner.
#
# Downscale, stated numerically: two tenants, eight crafted namespace
# rows, three cross-read probes, one replay per direction: exact
# integers over the real stores.
#
# Ports: 6479 this campaign's dedicated redis.
#
# Economic metric: a cross-tenant attack yields zero accepted reads
# and zero accepted replays, so the value of a sibling tenant's
# namespace knowledge is zero and the cost per accepted cross-tenant
# abuse is unbounded.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.15-multi-tenant
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")

REDIS_PORT=6479
redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1
sleep 0.3
mkdir -p "$RT_DIR/runs/env/d315"
redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no \
    --daemonize no --dir "$RT_DIR/runs/env/d315" >"$RT_DIR/runs/env/d315-redis.log" 2>&1 &
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
    rt_report_fail "the d3.15 redis never opened port $REDIS_PORT"
    rt_finish
}

DRIVER_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="redis://127.0.0.1:$REDIS_PORT" KIWI_RT_SEED="$KIWI_RT_SEED" \
    php "$RT_DIR/campaigns/lib/d315.driver.php" 2>"$RT_DIR/runs/env/d315-driver.err")
DRIVER_RC=$?
echo "$DRIVER_OUT" | python3 -m json.tool 2>/dev/null || echo "$DRIVER_OUT"
[ "$DRIVER_RC" -eq 0 ] || {
    rt_report_fail "the d3.15 driver failed (see runs/env/d315-driver.err)"
    rt_finish
}

j() { printf '%s' "$DRIVER_OUT" | python3 -c "import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]]).lower())" "$1"; }
rt_assert_eq "$(j digest_injective)" "true" "namespaces: the digest derivation is injective over the crafted corpus"
rt_assert_eq "$(j legacy_fold_documented)" "true" "namespaces: the legacy fold is the documented hazard, asserted honestly"
rt_assert_eq "$(j zero_cross_reads)" "true" "isolation: zero cross-tenant reads (mark, decision, trust)"
rt_assert_eq "$(j keyspace_segregated)" "true" "isolation: the two tenants' key sets never overlap"
rt_assert_eq "$(j crafted_key_contained)" "true" "isolation: the crafted key stays inside its own tenant family"
rt_assert_eq "$(j cross_tenant_replay_refused)" "true" "replay: zero cross-tenant acceptance with the same secret"
rt_assert_eq "$(j same_tenant_verify_ok)" "true" "isolation honesty: the same-tenant verify still works"
rt_assert_eq "$(j one_shot_holds_on_owner)" "true" "isolation honesty: the one-shot consume holds on the owner"

# The honest human baseline outside the tenants.
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

rt_metric "tenants=2 namespace_corpus=8 cross_reads=3 replay_legs=3 shared_secret=yes"
printf 'ECONOMIC: %s %s cross_tenant_reads_accepted=0 cross_tenant_replays_accepted=0 cost_per_accepted_cross_tenant_abuse=unbounded\n' \
    "$RT_CAMPAIGN" "$REDIS_PORT"

rt_finish
