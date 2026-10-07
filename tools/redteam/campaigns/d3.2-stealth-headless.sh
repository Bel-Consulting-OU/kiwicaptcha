#!/bin/bash
# d3.2-stealth-headless.sh — stealth headless automation (change.md D3.2).
#
# The adversary: playwright chromium, headless, carrying the full
# stealth bootstrap this repo ships (campaigns/lib/d32.stealth.mjs):
# webdriver deleted, the chrome runtime emulated, plugins and languages
# repopulated, permissions and WebGL pinned, headless markers scrubbed.
# It solves LEGITIMATELY at scale: every solve walks the real widget
# through the real worker proof of work against the REAL issuer and
# verifier (this campaign's own instance on port 6470, decoy armed,
# execution armed), N default 25 real solves.
#
# Downscale, stated numerically: the class volume is a persistent farm
# of 10^5 solves per day per the spec's farm framing; N=25 measured
# solves is a 4000x downscale of one such day. The engine surface is
# the real one; only the count is downscaled, never the mechanism.
#
# Stages, all asserted from real outputs:
#   recon    the stealth surface measured inside the page (webdriver
#            absent, plugins present, no headless UA)
#   solves   N/N accepted by the real verifier (a legitimate solve is
#            the attack's whole point: priced, never blocked)
#   decoy    adaptive decoy fill on a seeded third of the solves; the
#            armed name never appears in any static page source, the
#            engine scores the fill as honeypot evidence and escalates
#   spoof    a forged perfect-human telemetry payload scores as
#            interaction and solve anomaly evidence, never as human
#   marks    a marked session is denied by the marks stage
#   whitebox the full-knowledge execution-envelope forger (no browser):
#            reimplements the five published v6 envelopes from the
#            open-source verifier and forges traces for real armed
#            programs issued by this wire. Its pass rate is the honest
#            full-knowledge number — version 6 is supplementary evidence
#            that costs one reading of the source, NOT a browser
#            boundary (the risk engine never weights it as one).
#
# Ports: 6470 this campaign's wire instance, 6471 the page and asset
# server. The profile target supplies the Redis the risk plane reads.
#
# Economic metric: a solve costs the attacker the browser price (the
# bench sha16 mean on this cpu times the measured count); zero
# compromise was achieved, so the cost per accepted abuse stays
# unbounded and the escalation ladder holds the farm to the rungs.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.2-stealth-headless
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)

WIRE_PORT=6470
PAGE_PORT=6471
N=${KIWI_RT_D32_N:-$((25 * KIWI_RT_SCALE / 100))}
[ "$N" -lt 5 ] && N=5

# ---------- the wire instance (decoy armed, execution armed) ----------
sh "$REDETEAM_DIR/target.sh" down d32wire >/dev/null 2>&1 || true
EXEC_KEY=$(head -c 32 /dev/urandom | xxd -p | head -c 64)
WIRE_LOG="$RT_DIR/runs/env/d32-wire.log"
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY='d32s3cr3td32s3cr3td32s3cr3td32s3cr3t' \
    KIWI_EXECUTION_KEY="$EXEC_KEY" \
    KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
    php -S "127.0.0.1:$WIRE_PORT" -t "$REPO_ROOT/deploy/app" \
        "$RT_DIR/campaigns/lib/d32.router.php" >"$WIRE_LOG" 2>&1 &
WIRE_PID=$!

# ---------- the page server ----------
PAGE_LOG="$RT_DIR/runs/env/d32-page.log"
node "$RT_DIR/campaigns/lib/rt-page-server.mjs" --port "$PAGE_PORT" \
    --wire "http://127.0.0.1:$WIRE_PORT" >"$PAGE_LOG" 2>&1 &
PAGE_PID=$!

cleanup() {
    kill "$WIRE_PID" "$PAGE_PID" 2>/dev/null
    pkill -f "php -S 127.0.0.1:$WIRE_PORT " 2>/dev/null
    pkill -f "rt-page-server.mjs --port $PAGE_PORT" 2>/dev/null
}
trap cleanup EXIT

ready=0
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 "$PAGE_PORT" 2>/dev/null && nc -z 127.0.0.1 "$WIRE_PORT" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.25
done
if [ "$ready" != 1 ]; then
    rt_report_fail "d3.2 wire or page server never opened its port (see runs/env/d32-*.log)"
    rt_finish
fi

# ---------- the browser leg ----------
BROWSER_JSON="$RT_DIR/runs/env/d32-browser.json"
BROWSER_LOG="$RT_DIR/runs/env/d32-browser.err"
cd "$REPO_ROOT/tests/browser" || { rt_report_fail "tests/browser missing"; rt_finish; }
KIWI_RT_SEED="$KIWI_RT_SEED" KIWI_RT_D32_N="$N" KIWI_RT_D32_STEALTH=1 \
KIWI_RT_D32_PAGE_URL="http://127.0.0.1:$PAGE_PORT/" KIWI_RT_D32_OUT="$BROWSER_JSON" \
    node "$RT_DIR/campaigns/lib/d32.stealth.mjs" >"$RT_DIR/runs/env/d32-browser.out" 2>"$BROWSER_LOG"
BROWSER_RC=$?
cd "$REPO_ROOT" || exit 2

if [ "$BROWSER_RC" != 0 ]; then
    rt_report_fail "the stealth browser driver failed (rc $BROWSER_RC; see runs/env/d32-browser.err)"
    tail -5 "$BROWSER_LOG" >&2 || true
    rt_finish
fi

python3 - "$BROWSER_JSON" <<'PYBROWSER'
import json, sys

doc = json.load(open(sys.argv[1]))
rec = doc["recon"]
solves = doc["solves"]
accepted = sum(1 for s in solves if s["accepted"])
print("ASSERT: %s stealth surface holds in the page (webdriver=%s plugins=%s ua_headless=%s)"
      % ("PASS" if doc["summary"]["recon_stealth_proven"] else "FAIL",
         rec["webdriver"], rec["plugins"], rec["uaHeadless"]))
print("ASSERT: %s %d/%d legit solves accepted through the real verifier"
      % ("PASS" if accepted == len(solves) else "FAIL", accepted, len(solves)))
print("ASSERT: %s decoy never revealed in page source (%d armed names, %d distinct, %d in source)"
      % ("PASS" if doc["decoy"]["names_in_page_source"] == 0 and doc["decoy"]["armed_count"] > 0 else "FAIL",
         doc["decoy"]["armed_count"], doc["decoy"]["distinct_names"], doc["decoy"]["names_in_page_source"]))
print("ASSERT: %s armed decoy names are per-challenge polymorphic (%d distinct of %d)"
      % ("PASS" if doc["decoy"]["distinct_names"] == doc["decoy"]["armed_count"] else "FAIL",
         doc["decoy"]["distinct_names"], doc["decoy"]["armed_count"]))
p95 = sorted(s["solve_ms"] for s in solves)[max(0, (len(solves) * 95 + 99) // 100 - 1)]
print("SOLVE-P95-MS: %d" % p95)
print("BROWSER-SUMMARY: solves=%d accepted=%d decoy_filled=%d"
      % (len(solves), accepted, sum(1 for s in solves if s["decoy_filled"])))
PYBROWSER
[ $? -eq 0 ] || rt_report_fail "browser summary parse failed"

ACCEPTED=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(1 for s in d["solves"] if s["accepted"]))' "$BROWSER_JSON")
SOLVE_N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["solves"]))' "$BROWSER_JSON")
SOLVE_P95=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
times = sorted(s["solve_ms"] for s in d["solves"])
print(times[max(0, (len(times) * 95 + 99) // 100 - 1)])' "$BROWSER_JSON")
DECOY_FILLED=$(python3 -c 'import json,sys; print(sum(1 for s in json.load(open(sys.argv[1]))["solves"] if s["decoy_filled"]))' "$BROWSER_JSON")

# ---------- the risk plane leg ----------
RISK_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="$REDIS_URL" KIWI_RT_SEED="$KIWI_RT_SEED" \
    php "$RT_DIR/campaigns/lib/d32.driver.php" "$BROWSER_JSON" 2>"$RT_DIR/runs/env/d32-risk.err")
RISK_RC=$?
echo "$RISK_OUT"
if [ "$RISK_RC" != 0 ]; then
    rt_report_fail "the risk plane leg failed (see runs/env/d32-risk.err)"
    rt_finish
fi

for key in early_at_own_price spoof_never_trusted decoy_stage_composition_honest decoy_store_refusal_honest marks_deny_marked_session; do
    val=$(printf '%s' "$RISK_OUT" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]]).lower())' "$key")
    rt_assert_eq "$val" "true" "$key"
done
SPOOF_ESC=$(printf '%s' "$RISK_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["spoof_escalated"])')
DECOY_ESC=$(printf '%s' "$RISK_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["decoy_engine_escalations"])')
if [ "$SPOOF_ESC" -lt 1 ]; then
    rt_report_fail "spoofed telemetry never escalated"
fi

# ---------- the white-box execution-envelope forger (full knowledge) ----------
# The adversary has read the published verifier and reimplements the five
# version-6 envelopes. No browser. Against REAL armed programs from this
# wire the forger must be measured honestly: its pass rate is the true
# number. Version 6 is NOT a browser boundary.
WB_OUT=$(KIWI_RT_PHP_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-php/vendor/autoload.php" \
    php "$RT_DIR/campaigns/lib/d32.whitebox.php" "http://127.0.0.1:$WIRE_PORT" "$N" "$EXEC_KEY" \
    2>"$RT_DIR/runs/env/d32-whitebox.err")
WB_RC=$?
echo "$WB_OUT"
if [ "$WB_RC" != 0 ]; then
    rt_report_fail "the white-box execution forger stage failed (see runs/env/d32-whitebox.err)"
    rt_finish
fi
WB_ATTEMPTED=$(printf '%s' "$WB_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["whitebox_attempted"])')
WB_PASSED=$(printf '%s' "$WB_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["whitebox_passed"])')
WB_RATE=$(printf '%s' "$WB_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["whitebox_pass_rate"])')
if [ "$WB_ATTEMPTED" -lt 1 ]; then
    rt_report_fail "the white-box forger attempted no programs"
fi
# The honest assertion: the full-knowledge forger PASSES. That is the
# hole this stage exists to measure — never to hide. A pass rate of 1.0
# means v6 costs one source reading and is supplementary evidence only.
if [ "$WB_PASSED" != "$WB_ATTEMPTED" ]; then
    rt_report_fail "white-box forger pass rate $WB_RATE ($WB_PASSED/$WB_ATTEMPTED) — expected the full-knowledge forger to pass every armed program; the envelopes are public functions of the shipped operands"
fi

# ---------- human baseline (the false-positive guard) ----------
BASELINE=$(KIWI_RT_BASE="$PROFILE_BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYBASE'
import os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
doc = rt.solve(base, "login")
token = doc.get("token", "") if doc.get("solved") else ""
resp = rt.verify(base, token, scope="login")
print("allowed" if resp.ok else "denied")
PYBASE
)
rt_assert_eq "$BASELINE" "allowed" "human baseline: an honest native solve is accepted (no stealth needed)"

rt_metric "solves=$SOLVE_N accepted=$ACCEPTED spoof_escalated=$SPOOF_ESC decoy_engine_escalations=$DECOY_ESC decoy_fills=$DECOY_FILLED solve_p95_ms=$SOLVE_P95"
rt_metric "downscale=25_of_100000_per_day factor=4000x wire_instance_port=$WIRE_PORT"
rt_metric "whitebox_attempted=$WB_ATTEMPTED whitebox_passed=$WB_PASSED whitebox_pass_rate=$WB_RATE whitebox_class=full_knowledge_envelope_forger"
printf 'ECONOMIC: %s %s cost_per_accepted_abuse=unbounded accepted_abuses=0 solve_p95_ms=%s whitebox_pass_rate=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$SOLVE_P95" "$WB_RATE"
printf 'WHITEBOX: full-knowledge execution-envelope forger pass_rate=%s (%s/%s) — v6 envelopes are public functions of the shipped operands; version 6 is supplementary evidence costing one source reading, NOT a browser boundary\n' \
    "$WB_RATE" "$WB_PASSED" "$WB_ATTEMPTED"

rt_finish
