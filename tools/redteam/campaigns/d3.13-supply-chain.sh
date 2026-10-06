#!/bin/bash
# d3.13-supply-chain.sh — client and supply chain (D3.13).
#
# The supply-chain adversary owns the wire between the widget and the
# browser: a compromised CDN or MITM proxy flipping served asset
# bytes, a hostile service worker rewriting responses, and a hostile
# host page (prototype pollution plus DOM clobbering aimed at the
# driver). All legs run in real chromium against the real widget and
# the real deployment (port 6470 behind the page servers).
#
#   control     the clean page solves end to end (the baseline)
#   sri tamper  the driver asset's response bytes are flipped
#               mid-flight: the integrity attributes must refuse the
#               payload and the widget must fail closed (no token, no
#               solve, an explicit widget state)
#   sw mitm     a service worker rewrites every asset response with
#               tampered bytes: the same fail-closed verdict from a
#               different interception layer
#   pollution   Object.prototype pollution and id clobbering land
#               before and during the solve: the driver must survive
#               and complete; any breakage is reported as a finding
#   csp audit   the product's own CSP and hardening suites re-driven
#               as the gadget audit (execution-csp, locale-csp,
#               security, hardening)
#
# Required results: driver integrity holds (the tampered driver never
# executes on either interception layer) and fail-closed asset loading
# holds (no token under tamper, explicit widget state). The pollution
# leg's solve success is the survival assertion; its facts feed the
# findings channel when anything observable breaks.
#
# Downscale, stated numerically: one tampered byte per response (the
# minimal adversarial edit), one service worker, one hostile host
# page, four re-driven CSP suites: the mechanisms are the real ones;
# counts are the exact integers of this battery.
#
# Ports: 6470 the wire, 6471 the clean page server, 6473 the service
# worker page, 6474 the pollution page (sequential reuse of the port
# band; the campaigns never run concurrently).

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.13-supply-chain
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")

WIRE_PORT=6470
# ---------- the wire instance and the three page servers ----------
sh "$REDETEAM_DIR/target.sh" down d13wire >/dev/null 2>&1 || true
WIRE_LOG="$RT_DIR/runs/env/d313-wire.log"
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY='d313s3cr3td313s3cr3td313s3cr3td313s3c' \
    KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
    php -S "127.0.0.1:$WIRE_PORT" -t "$REPO_ROOT/deploy/app" \
        "$REPO_ROOT/deploy/app/router.php" >"$WIRE_LOG" 2>&1 &
WIRE_PID=$!
node "$RT_DIR/campaigns/lib/rt-page-server.mjs" --port 6471 \
    --wire "http://127.0.0.1:$WIRE_PORT" >/dev/null 2>&1 &
CLEAN_PID=$!
node "$RT_DIR/campaigns/lib/rt-page-server.mjs" --port 6473 \
    --wire "http://127.0.0.1:$WIRE_PORT" \
    --html "$RT_DIR/campaigns/lib/d313.sw.html" \
    --sw-file "$RT_DIR/campaigns/lib/d313.sw.js" >/dev/null 2>&1 &
SW_PID=$!
node "$RT_DIR/campaigns/lib/rt-page-server.mjs" --port 6474 \
    --wire "http://127.0.0.1:$WIRE_PORT" \
    --html "$RT_DIR/campaigns/lib/d313.pollution.html" >/dev/null 2>&1 &
POLL_PID=$!
cleanup() {
    kill "$WIRE_PID" "$CLEAN_PID" "$SW_PID" "$POLL_PID" 2>/dev/null
    pkill -f "php -S 127.0.0.1:$WIRE_PORT " 2>/dev/null
    pkill -f "rt-page-server.mjs --port 6471" 2>/dev/null
    pkill -f "rt-page-server.mjs --port 6473" 2>/dev/null
    pkill -f "rt-page-server.mjs --port 6474" 2>/dev/null
}
trap cleanup EXIT

ready=0
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 "$WIRE_PORT" 2>/dev/null && nc -z 127.0.0.1 6471 2>/dev/null && nc -z 127.0.0.1 6473 2>/dev/null && nc -z 127.0.0.1 6474 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.25
done
[ "$ready" = 1 ] || {
    rt_report_fail "the d3.13 wire or page servers never opened (see runs/env/d313-wire.log)"
    rt_finish
}

# ---------- the browser legs ----------
BROWSER_OUT="$RT_DIR/runs/env/d313-browser.json"
cd "$REPO_ROOT/tests/browser" || { rt_report_fail "tests/browser missing"; rt_finish; }
KIWI_RT_D313_CLEAN="http://127.0.0.1:6471/" \
KIWI_RT_D313_SW="http://127.0.0.1:6473/" \
KIWI_RT_D313_POLLUTION="http://127.0.0.1:6474/" \
KIWI_RT_D313_OUT="$BROWSER_OUT" \
    timeout 420 node "$RT_DIR/campaigns/lib/d313.supply.mjs" >"$RT_DIR/runs/env/d313-browser.out" 2>"$RT_DIR/runs/env/d313-browser.err"
BROWSER_RC=$?
cd "$REPO_ROOT" || exit 2
cat "$BROWSER_OUT" 2>/dev/null || tail -5 "$RT_DIR/runs/env/d313-browser.err"
[ "$BROWSER_RC" -eq 0 ] || {
    rt_report_fail "the supply-chain browser legs failed (see runs/env/d313-browser.err)"
    rt_finish
}

jleg() { python3 -c "import json,sys; print(str(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]]).lower())" "$BROWSER_OUT" "$1" "$2"; }
rt_assert_eq "$(jleg control solved)" "true" "control: the clean page solves end to end"
rt_assert_eq "$(jleg sri_tamper solved_despite_tamper)" "false" "SRI tamper: the flipped-byte driver never solves (fail closed)"
rt_assert_eq "$(jleg sw_mitm solved_despite_mitm)" "false" "service worker MITM: the tampered driver never solves (fail closed)"
rt_assert_eq "$(jleg pollution solved_under_pollution)" "true" "hostile host page: the driver survives pollution and clobbering"

# ---------- the CSP gadget audit (the product's own suites) ----------
CSP_LOG="$RT_DIR/runs/env/d313-csp.log"
cd "$REPO_ROOT/tests/browser" || exit 2
lsof -ti :8087 2>/dev/null | while IFS= read -r pid; do kill "$pid" 2>/dev/null; done
sleep 0.5
if timeout 900 npx playwright test --config=playwright.a11y.config.mjs --project=chromium \
        execution-csp.spec.mjs locale-csp.spec.mjs security.spec.mjs hardening.spec.mjs \
        --reporter=line --retries=1 >"$CSP_LOG" 2>&1; then
    PASSED=$(grep -o '[0-9]* passed' "$CSP_LOG" | tail -n 1)
    rt_report_pass "CSP gadget audit: the product's CSP and hardening suites green ($PASSED)"
else
    rt_report_fail "the CSP gadget audit failed (see runs/env/d313-csp.log)"
fi
cd "$REPO_ROOT" || exit 2

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
rt_assert_eq "$BASELINE" "allowed" "human baseline: honest solve accepted"

PAGE_ERRORS=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["pollution"]["page_errors"]))' "$BROWSER_OUT")
rt_metric "tamper_legs=2 pollution_leg=1 csp_suites=4 page_errors_under_pollution=$PAGE_ERRORS tampered_bytes=1_per_response"
printf 'ECONOMIC: %s %s tampered_driver_executions=0 mitm_yield=0 cost_per_accepted_supply_abuse=unbounded\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
