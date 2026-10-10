#!/bin/bash
# d3.5-credential-stuffing.sh — credential stuffing, the realistic
# shape (D3.5). This is the rewrite of the 12-attacker synthetic.
#
# The attack is the leaked-list shape the spec names: 10^5 account rows
# (KIWI_RT_D35_ROWS scales), ONE attempt per row in leaked-list order,
# a seeded 0.5 to 2 percent valid rate, forty hot victim accounts
# recurring across the list the way real lists concentrate. The engine
# is the real one end to end: every row drives the REAL sharded risk
# store (the scope failure-ratio pressure), the marks stages and the
# policy decide every login, over the REAL Redis; only the row count is
# a downscale knob and the default is the full 10^5.
#
# The wire plane: a sample of the rows (default 200) walks the real
# deployment's own challenge-verify flow with honestly paid proofs of
# work on this campaign's own instance (port 6473), so the wire
# honesty claim stays measured, not assumed.
#
# The defense under test, measured end to end:
#   1. the scope-level failure-ratio waves: real authentication-failure
#      events raise the scope aggregate, the global hysteresis level
#      ratchets, and an untrusted-context login is re-priced at the
#      floor while a credited principal keeps its own price;
#   2. the first-attempt gate (P0-1): every valid stolen credential is
#      assessed by the real AdaptiveRiskEngine through the same call
#      RiskGateway::loginDecision makes (reassess with
#      event=AuthenticationSuccess). firstAttemptEvidence runs for real
#      (novel network, breached credential, scope pressure) with
#      novelty_enforcement=enforce. The engine's action IS the result:
#      Allow is a compromise, StepUp/Deny is blocked.
#
# The product ships NO breached-password checker by default, so this
# campaign credits none. breachedCredential is a caller-supplied
# assertion for deployments that wire their own corpus; the seeded
# passwords' corpus membership is informational context only.
#
# Required results (all asserted from real engine outputs):
#   - each targeted account stepped up within at most 5 spread
#     failures, never locked out (zero lockouts anywhere);
#   - every attacker identity denied within N=3 of its own attempts
#     (the engine's Deny decision, never assumed from a mark write);
#   - ZERO valid stolen credentials granted a full session
#     (compromised_valid = 0 is the release bar);
#   - the scope pressure fires (level 0 to at least 1) and the floor
#     escalates the untrusted login;
#   - the human baseline: an honest login outside the storm is
#     accepted.
#
# Economic metric: the attacker's measured spend (rows times the bench
# price of one solve on this cpu) against the outcome; the cost per
# compromised account finally has a denominator that can be non-zero,
# and the corpus blocking is priced as prevented compromise beside it.
#
# Compromise-economics criterion (change.md D3.5
# "cost/compromised-account >= critical threshold"), stated explicitly:
#   - dollar form: cost_per_compromised_account (spend_usd /
#     corpus_residual_compromised) must be >= the critical value class's
#     declared abuse value, read from
#     packages/kiwicaptcha-solver/reference-costs.json
#     (value_classes[critical].declared_abuse_value_usd_per_1000) —
#     never a hardcoded guess;
#   - rate form: the measured compromised/valid rate
#     (corpus_residual_compromised / valid_rows) must be <= the stated
#     release threshold 0.0 — zero valid-account compromise. A run that
#     measured real compromises misses this target and its
#     compromise-economics verdict is FAIL/RED with the numbers, never
#     green. Step-up prevention is asserted separately above; when it
#     holds and the economics miss, the release rows split honestly
#     (prevention green, compromise-economics red with the number).

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.5-credential-stuffing
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)

WIRE_PORT=6473
ROWS=${KIWI_RT_D35_ROWS:-$((100000 * KIWI_RT_SCALE / 100))}
[ "$ROWS" -lt 20000 ] && ROWS=20000
WIRE_SAMPLE=${KIWI_RT_D35_WIRE_SAMPLE:-200}

# ---------- the wire instance ----------
sh "$REDETEAM_DIR/target.sh" down d35wire >/dev/null 2>&1 || true
WIRE_LOG="$RT_DIR/runs/env/d35-wire.log"
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY='d35s3cr3td35s3cr3td35s3cr3td35s3cr3t' \
    KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
    KIWI_ISSUANCE_PER_MINUTE_PER_IP=0 \
    php -S "127.0.0.1:$WIRE_PORT" -t "$REPO_ROOT/deploy/app" \
        "$REPO_ROOT/deploy/app/router.php" >"$WIRE_LOG" 2>&1 &
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
    rt_report_fail "the d3.5 wire instance never opened port $WIRE_PORT"
    rt_finish
}

# ---------- the wire sample ----------
WIRE_OUT=$(WIRE_PORT="$WIRE_PORT" WIRE_SAMPLE="$WIRE_SAMPLE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYWIRE'
import json, os, sys, time
sys.path.insert(0, os.environ["KIWI_RT_DIR"])
import rtclient as rt

port = int(os.environ["WIRE_PORT"])
base = f"http://127.0.0.1:{port}"
sample = int(os.environ["WIRE_SAMPLE"])
ok = fail = wire_broken = 0
t0 = time.monotonic()
hashes = 0
for i in range(sample):
    doc = rt.challenge(base, "login")
    if doc.status != 200 or not doc.body.get("nonce"):
        wire_broken += 1
        continue
    counter = rt.pow_solve(doc.body)
    hashes += counter + 1
    token = rt.mint_token(str(doc.body["nonce"]), counter)
    resp = rt.verify(base, token, scope="login")
    if resp.status == 0:
        wire_broken += 1
    elif resp.ok:
        ok += 1
    else:
        fail += 1
elapsed = time.monotonic() - t0
print(json.dumps({"ok": ok, "fail": fail, "wire_broken": wire_broken,
                  "sample": sample, "seconds": round(elapsed, 2), "pow_hashes": hashes}))
PYWIRE
)
printf 'WIRE-SAMPLE: %s\n' "$WIRE_OUT"
WIRE_BROKEN=$(printf '%s' "$WIRE_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wire_broken"])')
rt_assert_eq "$WIRE_BROKEN" "0" "wire plane: every sampled row walked the real flow without a wire failure"

# ---------- the engine plane (the full list) ----------
SUMMARY_FILE="$RT_DIR/runs/env/d35-summary-$RT_PROFILE.json"
KIWI_RT_D35_ROWS="$ROWS" \
KIWI_RT_RISK_AUTOLOAD="$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
KIWI_RT_RISK_REDIS_URL="$REDIS_URL" \
KIWI_RT_D35_SHA16_US=$(KIWI_RT_REPO_ROOT="$REPO_ROOT" python3 -c '
import sys
sys.path.insert(0, sys.argv[1])
import lib.rtclient as rt
print("%.0f" % rt.sha16_mean_us(3))
' "$RT_DIR/campaigns" 2>/dev/null || echo 300000) \
KIWI_RT_D35_OUT="$SUMMARY_FILE" \
    php -d memory_limit=512M "$RT_DIR/campaigns/lib/d35.kernel.php" >"$SUMMARY_FILE" 2>"$RT_DIR/runs/env/d35-engine.err"
ENGINE_RC=$?
cat "$SUMMARY_FILE"
[ "$ENGINE_RC" -eq 0 ] || {
    rt_report_fail "the engine plane failed (see runs/env/d35-engine.err)"
    rt_finish
}

for key in escalated_within_n all_sessions_escalated; do
    val=$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))[sys.argv[2]]).lower())' "$SUMMARY_FILE" "$key")
    rt_assert_eq "$val" "true" "engine plane: $key"
done
LOCKOUTS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["lockouts"])' "$SUMMARY_FILE")
STEPPED=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["victims_stepped_up"])' "$SUMMARY_FILE")
HOT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hot_victims"])' "$SUMMARY_FILE")
MAXSPREAD=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["max_spread_failures_before_step_up"])' "$SUMMARY_FILE")
BLOCKED=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["blocked_valid"])' "$SUMMARY_FILE")
COMPROMISED=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["compromised_valid"])' "$SUMMARY_FILE")
VALID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["valid_rows"])' "$SUMMARY_FILE")

rt_assert_eq "$LOCKOUTS" "0" "D3.5 target: zero victim lockouts"
rt_assert_eq "$STEPPED" "$HOT" "engine plane: every targeted account stepped up"
[ "$MAXSPREAD" -le 5 ] || rt_report_fail "spread bound: $MAXSPREAD spread failures before step-up (bound 5)"
# The real engine decided every valid stolen credential. Allow is a
# compromise; the release bar is zero. The product ships no
# breached-password checker, so the first-attempt gate is the only
# defense and it must hold on its own.
[ "$COMPROMISED" -eq 0 ] || rt_report_fail "engine plane: $COMPROMISED of $VALID valid stolen credentials were granted (bar 0)"
[ "$VALID" -gt 0 ] || rt_report_fail "engine plane: no valid credential was assessed"
[ "$BLOCKED" -gt 0 ] || rt_report_fail "engine plane: nothing blocked; the first-attempt gate never fired"
# The legitimate-user baseline: the campaign must not be "steps up
# everyone". Home and same-ASN logins with device continuity must pass
# at a false-positive rate within the 0.1% bound.
FP_RATE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["legitimate_baseline"]["false_positive_rate"])' "$SUMMARY_FILE")
python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= 0.001 else 1)' "$FP_RATE" \
    || rt_report_fail "legitimate baseline: false-positive rate $FP_RATE exceeds the 0.001 bound (the defense steps up everyone)"

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
rt_assert_eq "$BASELINE" "allowed" "human baseline: honest login outside the storm accepted"

# ---------- the economics ----------
SPEND=$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
print("%.6f" % doc["spend_usd"])' "$SUMMARY_FILE")
COST_COMPROMISED=$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
print("unbounded" if doc["corpus_residual_compromised"] == 0 else "%.4f" % (doc["spend_usd"] / doc["corpus_residual_compromised"]))' "$SUMMARY_FILE")
COST_PREVENTED=$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
print("%.6f" % (doc["spend_usd"] / doc["blocked_valid"]))' "$SUMMARY_FILE")

# ---------- the compromise-economics criterion ----------
# Thresholds are stated, not invented: the critical declared abuse value
# comes from reference-costs.json, the rate threshold (0.0) is the
# release bar declared in this file's header.
ECON=$(KIWI_RT_REPO_ROOT="$REPO_ROOT" python3 - "$SUMMARY_FILE" <<'PYECON'
import json, os, sys

doc = json.load(open(sys.argv[1]))
ref_path = os.path.join(os.environ["KIWI_RT_REPO_ROOT"],
                        "packages/kiwicaptcha-solver/reference-costs.json")
ref = json.load(open(ref_path))
critical = next(c for c in ref["value_classes"] if c["class"] == "critical")
cost_threshold = float(critical["declared_abuse_value_usd_per_1000"])
rate_threshold = 0.0

compromised = int(doc["corpus_residual_compromised"])
valid = int(doc["valid_rows"]) or 1
spend = float(doc["spend_usd"])
cost = None if compromised == 0 else spend / compromised
rate = compromised / valid

# Zero compromises means the cost per compromise is unbounded, which
# trivially satisfies the cost threshold. The rate threshold is the
# binding check when compromises exist.
cost_ok = (cost is None and compromised == 0) or (cost is not None and cost >= cost_threshold)
rate_ok = rate <= rate_threshold
verdict = "PASS" if (cost_ok and rate_ok) else "FAIL"
print("verdict=%s cost_per_compromised_account=%s critical_threshold=%.6f "
      "compromised_valid_rate=%.4f rate_threshold=%.1f compromised=%d valid=%d spend_usd=%.6f"
      % (verdict,
         "unbounded" if cost is None else "%.6f" % cost,
         cost_threshold, rate, rate_threshold, compromised, valid, spend))
PYECON
)
ECON_VERDICT=$(printf '%s' "$ECON" | sed -n 's/^verdict=\([A-Z]*\).*/\1/p')
printf 'COMPROMISE-ECONOMICS: %s\n' "$ECON"

rt_metric "rows=$ROWS wire_sample=$WIRE_SAMPLE blocked_valid=$BLOCKED compromised=$COMPROMISED max_spread=$MAXSPREAD"
# The LAST METRIC line is the one the run document keeps: fold the
# economics verdict and measured numbers into it so the ledger and the
# gate rows carry them. the_engine_path names the real call; the breach
# checker is honestly absent.
rt_metric "downscale=rows_are_100000 engine=AdaptiveRiskEngine.reassess(AuthenticationSuccess) novelty=enforce breach_checker=not_shipped_not_credited valid_rate=1percent $ECON"
printf 'ECONOMIC: %s %s cost_per_compromised_account=%s spend_usd=%s blocked_valid_prevented=%s cost_per_prevented_compromise=%s compromised_valid_rate=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$COST_COMPROMISED" "$SPEND" "$BLOCKED" "$COST_PREVENTED" \
    "$(printf '%s' "$ECON" | sed -n 's/.*compromised_valid_rate=\([0-9.]*\).*/\1/p')"

# The campaign's prevention asserts above already ran. The economics
# verdict is measured data, not a harness failure (the D3.3 pattern):
# the campaign is green when the prevention asserts held and the
# economics were measured and honestly classified. The dedicated gate
# row turns red on a FAIL verdict verbatim, so the release rows split
# honestly (prevention green, compromise-economics red with the number)
# instead of collapsing into one green cell.
printf 'COMPROMISE-ECONOMICS-VERDICT: %s\n' "$ECON_VERDICT"

if [ "$RT_FAILURES" -eq 0 ]; then
    rt_report_pass "the engine assessed every valid stolen credential (blocked_valid=$BLOCKED compromised_valid=$COMPROMISED max_spread=$MAXSPREAD escalated_within_n=true; breach checker not shipped, not credited)"
fi

rt_finish
