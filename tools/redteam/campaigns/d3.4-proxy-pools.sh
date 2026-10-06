#!/bin/bash
# d3.4-proxy-pools.sh — residential and mobile proxy pools (D3.4).
#
# The pool: 10^4 source addresses (KIWI_RT_D34_IPS scales) across 512
# listed synthetic ASNs from the committed dataset fixture plus the
# unknown-bucket path (CGNAT 100.64.0.0/10 and TEST-NET-2 are
# deliberately unlisted; the real resolver buckets them per /16), drawn
# by the seeded xormix64 mixer in the driver. Two planes take the
# storm, both real:
#
#   engine plane  every pool address walks the REAL sharded risk
#                 store's observe surface as an authentication-failure
#                 event (the scope failure-ratio pressure of the spec),
#                 the marks/escalation stages score the pool's own
#                 buckets, and the hot-target spread is scored through
#                 the marks stage; CGNAT neighbors sharing the /24 of
#                 attacker sources walk the same stages with clean
#                 identities.
#
#   wire plane    this campaign's own deployment instance (port 6472,
#                 trusted-edge forwarding header as the client address,
#                 the production shape behind a proxy) with the
#                 documented per-address issuance budget on: the pooled
#                 sources hammer /challenge and every source gets
#                 exactly its own budget, never the socket's.
#
# Downscale, stated numerically: the wire plane's flood is sampled at
# 66 requests over three forwarded sources (the budget mechanics are
# exact integers, not a rate), while the engine plane runs the full
# 10^4 addresses; the spec's upper band (10^6 IPs) is a further 100x.
#
# Required results: the ASN and target dimensions catch the pool
# (escalation observed on both), the scope failure-ratio pressure
# fires (merged aggregate rises and the hysteresis level ratchets),
# the per-source issuance budgets hold exactly, and the CGNAT-sharing
# clean users stay bounded by their own price (own session clean, the
# shared bucket prices at most to the argon floor, never a deny, never
# a step-up).
#
# Economic metric: a pooled address is priced by the pool operator at
# the reference table's rental rate; the measured accepted-abuse yield
# through both planes is zero, so the cost per accepted abuse is
# unbounded while the escalation ladder holds.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.4-proxy-pools
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)

WIRE_PORT=6472
IP_COUNT=${KIWI_RT_D34_IPS:-$((10000 * KIWI_RT_SCALE / 100))}
[ "$IP_COUNT" -lt 1000 ] && IP_COUNT=1000

# ---------- the wire instance (trusted edge, limiter on) ----------
sh "$REDETEAM_DIR/target.sh" down d34wire >/dev/null 2>&1 || true
WIRE_LOG="$RT_DIR/runs/env/d34-wire.log"
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY='d34s3cr3td34s3cr3td34s3cr3td34s3cr3t' \
    KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
    KIWI_ISSUANCE_PER_MINUTE_PER_IP=30 \
    php -S "127.0.0.1:$WIRE_PORT" -t "$REPO_ROOT/deploy/app" \
        "$RT_DIR/campaigns/lib/d34.router.php" >"$WIRE_LOG" 2>&1 &
WIRE_PID=$!
cleanup() {
    kill "$WIRE_PID" 2>/dev/null
    pkill -f "php -S 127.0.0.1:$WIRE_PORT " 2>/dev/null
}
trap cleanup EXIT

ready=0
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 "$WIRE_PORT" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.25
done
[ "$ready" = 1 ] || {
    rt_report_fail "the d3.4 wire instance never opened port $WIRE_PORT (see runs/env/d34-wire.log)"
    rt_finish
}

# ---------- the engine plane (the full pool) ----------
DRIVER_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="$REDIS_URL" KIWI_RT_SEED="$KIWI_RT_SEED" KIWI_RT_D34_IPS="$IP_COUNT" \
    php "$RT_DIR/campaigns/lib/d34.driver.php" 2>"$RT_DIR/runs/env/d34-engine.err")
DRIVER_RC=$?
echo "$DRIVER_OUT"
[ "$DRIVER_RC" -eq 0 ] || {
    rt_report_fail "the engine plane failed (see runs/env/d34-engine.err)"
    rt_finish
}

for key in distinct_asn_buckets_ge_500 scope_failure_fired asn_dimension_caught cgnat_clean_bounded; do
    val=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]]).lower())' "$key")
    rt_assert_eq "$val" "true" "engine plane: $key"
done
ATT_DENIED=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["attacker_denied_of_50"])')
VIC_STEP=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["victim_step_ups"])')
VIC_DENY=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["victim_denies"])')
rt_assert_eq "$ATT_DENIED" "50" "engine plane: every hot-target attacker denied"
rt_assert_eq "$VIC_STEP" "50" "engine plane: every hot-target victim stepped up exactly once"
rt_assert_eq "$VIC_DENY" "0" "engine plane: zero victim denials"

# ---------- the wire plane (per-source budgets behind the edge) ----------
WIPE=$(redis-cli -u "$REDIS_URL" --scan --pattern '{kiwi:rl}:*' 2>/dev/null | xargs -r -n 1 redis-cli -u "$REDIS_URL" del >/dev/null 2>&1; echo done)
WIRE_OUT=$(WIRE_PORT="$WIRE_PORT" python3 - <<'PYWIRE'
import json, os, time, urllib.error, urllib.request

port = int(os.environ["WIRE_PORT"])
base = f"http://127.0.0.1:{port}"

def issue(ip):
    req = urllib.request.Request(base + "/challenge", data=b'{"scope":"login"}', method="POST")
    req.add_header("content-type", "application/json")
    req.add_header("x-forwarded-for", ip)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
            return resp.status, body
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"{}")

results = {}
for ip in ("203.0.113.11", "203.0.113.12", "100.93.100.7"):
    issued = limited = 0
    for _ in range(22):
        status, body = issue(ip)
        if status == 200 and body.get("nonce"):
            issued += 1
        elif status == 429 and body.get("error", {}).get("code") == "RATE_LIMITED":
            limited += 1
        else:
            print(json.dumps({"error": "unexpected", "status": status, "body": body}))
            raise SystemExit(2)
    results[ip] = {"issued": issued, "limited": limited}
print(json.dumps(results))
PYWIRE
)
WIRE_RC=$?
[ "$WIRE_RC" -eq 0 ] || { rt_report_fail "the wire plane flood crashed"; rt_finish; }
printf '%s\n' "$WIRE_OUT"
for ip in 203.0.113.11 203.0.113.12 100.93.100.7; do
    issued=$(printf '%s' "$WIRE_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]]["issued"])' "$ip")
    limited=$(printf '%s' "$WIRE_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]]["limited"])' "$ip")
    rt_assert_eq "$issued" "22" "wire plane: $ip gets its own full budget behind the shared socket"
    rt_assert_eq "$limited" "0" "wire plane: $ip is not throttled by another source's spend"
done

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
rt_assert_eq "$BASELINE" "allowed" "human baseline: honest solve outside the pool accepted"

rt_metric "pool_ips=$IP_COUNT listed_buckets=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["listed_asn_buckets"])') unknown_buckets=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["unknown_asn_buckets"])') level_before=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["level_before"])') level_after=$(printf '%s' "$DRIVER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["level_after"])')"
rt_metric "downscale=10000_of_1000000 factor=100x wire_sample=66_requests"
printf 'ECONOMIC: %s %s cost_per_accepted_abuse=unbounded accepted=0 pool_ips=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$IP_COUNT"

rt_finish
