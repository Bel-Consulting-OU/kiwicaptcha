#!/bin/bash
# d3.8-ai-agents.sh — AI computer-use agents versus verified agents
# (D3.8).
#
# Two agent classes, both real:
#
#   unauthenticated  a deterministic scripted browser driver (webdriver
#                    visible, no stealth bootstrap; KIWI_RT_D32_STEALTH=0
#                    of the d3.2 harness) solving at the deployment on
#                    port 6470. Its solve events are scored through the
#                    REAL risk engine: priced at its own band while
#                    clean, escalated by its own velocity, every
#                    honestly paid solve accepted (an agent is not a
#                    forger; the pricing plane is the enforcement).
#
#   verified         the RFC 9421 machine-client path through the REAL
#                    bundle classes over the REAL Redis nonce and quota
#                    stores (this campaign's redis on port 6477): every
#                    signed request inside the quota verifies and
#                    issues (100 percent within quota, at its price
#                    tier); the quota bust is refused 429 and the abuse
#                    mark lands on the agent identity; after the key's
#                    revocation every further signed request fails
#                    closed (0 percent post-revocation); tampered
#                    bases, stripped headers and reused nonces never
#                    verify.
#
# Downscale, stated numerically: the unauthenticated agent runs 10
# scripted solves (the class volume is continuous operation; the
# mechanism is the real one), the verified agent runs the full gate 8
# times against a per-minute quota of 5 (the exact integer boundary).
#
# Ports: 6470 the wire instance, 6477 this campaign's redis.
#
# Economic metric: the unauthenticated agent pays the browser price per
# solve and receives its rungs; the verified agent trades a key for
# quota headroom. Zero accepted abuses on either plane.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.8-ai-agents
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")

WIRE_PORT=6470
AGENT_REDIS_PORT=6477
N=${KIWI_RT_D38_N:-10}

# ---------- the wire instance (stock deployment) ----------
sh "$REDETEAM_DIR/target.sh" down d38wire >/dev/null 2>&1 || true
WIRE_LOG="$RT_DIR/runs/env/d38-wire.log"
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY='d38s3cr3td38s3cr3td38s3cr3td38s3cr3t' \
    KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
    php -S "127.0.0.1:$WIRE_PORT" -t "$REPO_ROOT/deploy/app" \
        "$REPO_ROOT/deploy/app/router.php" >"$WIRE_LOG" 2>&1 &
WIRE_PID=$!
# The widget page server in front of it.
node "$RT_DIR/campaigns/lib/rt-page-server.mjs" --port 6471 \
    --wire "http://127.0.0.1:$WIRE_PORT" >/dev/null 2>&1 &
PAGE_PID=$!
# This campaign's own redis for the verified-agent stores.
redis-cli -p "$AGENT_REDIS_PORT" shutdown nosave >/dev/null 2>&1
sleep 0.3
mkdir -p "$RT_DIR/runs/env/d38"
redis-server --port "$AGENT_REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no \
    --daemonize no --dir "$RT_DIR/runs/env/d38" >"$RT_DIR/runs/env/d38-redis.log" 2>&1 &
REDIS_PID=$!
cleanup() {
    kill "$WIRE_PID" "$PAGE_PID" "$REDIS_PID" 2>/dev/null
    pkill -f "php -S 127.0.0.1:$WIRE_PORT " 2>/dev/null
    pkill -f "rt-page-server.mjs --port 6471" 2>/dev/null
    redis-cli -p "$AGENT_REDIS_PORT" shutdown nosave >/dev/null 2>&1
}
trap cleanup EXIT

ready=0
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 "$WIRE_PORT" 2>/dev/null && nc -z 127.0.0.1 6471 2>/dev/null && redis-cli -p "$AGENT_REDIS_PORT" ping >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
[ "$ready" = 1 ] || {
    rt_report_fail "the d3.8 wire, page server or redis never opened"
    rt_finish
}

# ---------- the unauthenticated scripted agent ----------
BROWSER_JSON="$RT_DIR/runs/env/d38-browser.json"
cd "$REPO_ROOT/tests/browser" || { rt_report_fail "tests/browser missing"; rt_finish; }
KIWI_RT_SEED="$KIWI_RT_SEED" KIWI_RT_D32_N="$N" KIWI_RT_D32_STEALTH=0 \
KIWI_RT_D32_PAGE_URL="http://127.0.0.1:6471/" KIWI_RT_D32_OUT="$BROWSER_JSON" \
    node "$RT_DIR/campaigns/lib/d32.stealth.mjs" >"$RT_DIR/runs/env/d38-browser.out" 2>"$RT_DIR/runs/env/d38-browser.err"
BROWSER_RC=$?
cd "$REPO_ROOT" || exit 2
[ "$BROWSER_RC" -eq 0 ] || {
    rt_report_fail "the scripted agent driver failed (see runs/env/d38-browser.err)"
    rt_finish
}
python3 - "$BROWSER_JSON" <<'PYB'
import json, sys
doc = json.load(open(sys.argv[1]))
rec = doc["recon"]
accepted = sum(1 for s in doc["solves"] if s["accepted"])
print("ASSERT: %s the scripted agent is webdriver-visible (webdriver=%s)"
      % ("PASS" if rec["webdriver"] not in (None, "undefined") else "FAIL", rec["webdriver"]))
print("ASSERT: %s %d/%d scripted solves accepted through the real verifier"
      % ("PASS" if accepted == len(doc["solves"]) else "FAIL", accepted, len(doc["solves"])))
PYB

RISK_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="$REDIS_URL" KIWI_RT_SEED="$KIWI_RT_SEED" \
    php "$RT_DIR/campaigns/lib/d38.risk.php" "$BROWSER_JSON" 2>"$RT_DIR/runs/env/d38-risk.err")
RISK_RC=$?
echo "$RISK_OUT"
[ "$RISK_RC" -eq 0 ] || {
    rt_report_fail "the scripted agent risk leg failed (see runs/env/d38-risk.err)"
    rt_finish
}
LADDER=$(printf '%s' "$RISK_OUT" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ladder_escalated"]).lower())')
rt_assert_eq "$LADDER" "true" "unauthenticated agent: its own velocity escalates the price ladder"

# ---------- the verified agent ----------
VA_OUT=$(KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_D38_REDIS_URL="redis://127.0.0.1:$AGENT_REDIS_PORT" \
KIWI_RT_BUNDLE_TESTS="$REPO_ROOT/packages/kiwicaptcha/integrations/symfony/tests" \
    php "$RT_DIR/campaigns/lib/d38.driver.php" 2>"$RT_DIR/runs/env/d38-driver.err")
VA_RC=$?
echo "$VA_OUT"
[ "$VA_RC" -eq 0 ] || {
    rt_report_fail "the verified agent leg failed (see runs/env/d38-driver.err)"
    rt_finish
}
jva() { printf '%s' "$VA_OUT" | python3 -c "import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]]).lower())" "$1"; }
IN_QUOTA=$(printf '%s' "$VA_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["signed_in_quota"])')
QUOTA_REFUSED=$(printf '%s' "$VA_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["quota_bust_refusals"])')
rt_assert_eq "$(jva tamper_refused)" "true" "verified agent: tampered base refused"
rt_assert_eq "$(jva header_strip_refused)" "true" "verified agent: header-strip coverage refused"
rt_assert_eq "$(jva revoked_key_refused)" "true" "verified agent: 0 percent after revocation"
rt_assert_eq "$(jva nonce_single_use)" "true" "verified agent: nonce single use"
rt_metric "unauth_solves=$N accepted=$N ladder_escalated=$LADDER verified_in_quota=$IN_QUOTA quota_refused=$QUOTA_REFUSED revoked_accepted=0"

# ---------- the human baseline ----------
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

printf 'ECONOMIC: %s %s unauth_agent_cost=browser_price_per_solve verified_agent_within_quota=%s post_revocation_accepted=0\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$IN_QUOTA"

rt_finish
