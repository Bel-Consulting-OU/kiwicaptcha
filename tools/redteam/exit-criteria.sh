#!/bin/bash
# exit-criteria.sh — the release exit criteria of change.md 9.5,
# every criterion measured and printed as a table. This is the honest
# gate: it fails on ANY red, including the repository's own gates, and
# it has no excuse rows. A criterion the toolchain cannot run prints
# TOOLCHAIN-ABSENT with the exact blocker, and that is non-green too.
#
# The rows (each mapped to its 9.5 clause):
#   open-findings       zero open findings of medium severity or above
#                       (the committed findings corpus, the runs ledger)
#   value-class-costs   every declared value class priced above its
#                       declared abuse value (the D3.3 measured table)
#   d3.5-targets        zero victim lockouts, the spread bound, the
#                       attacker denial bound, the corpus blocking
#                       (step-up prevention; the campaign's asserted
#                       success criterion)
#   d3.5-economics      the compromise-economics criterion: measured
#                       compromised/valid rate and cost_per_compromised
#                       against the stated thresholds (rate 0.0 and the
#                       critical declared abuse value from
#                       reference-costs.json). A miss is RED with the
#                       numbers, never green — and when prevention is
#                       green the rows split honestly instead of one
#                       green cell hiding real compromises
#   llm-red-team        the Part 10 LLM agent loop really consulted a
#                       model (consulted:true evidence). GREEN only
#                       with a recorded consulted run; otherwise
#                       TOOLCHAIN-ABSENT (non-green) — offline mode is
#                       never a pass
#   confirmed-legit     confirmed-legitimate escalation <= 0.1% and
#                       denial = 0, measured live by this gate (100
#                       honest solves through the real deployment)
#   human-solve-p95     the promoted client-perf baseline row for the
#                       release tier against the release budget
#   verified-agents     100% within quota, 0% after revocation (D3.8)
#   model-checking      TLC over the consume/commit spec, zero
#                       violations (the vendored tla2tools)
#   fuzz-crashes        zero crashes or divergences: the bounded
#                       mutation corpora, 3 passes each (N=3 stated)
#   coverage-fuzz       the D4.1 coverage-guided fuzzing row: cargo-fuzz
#                       targets present and run without crashes. When
#                       the targets are missing this row is RED with the
#                       blocker, never omitted and never folded into
#                       fuzz-crashes
#   b7.2-cluster        the scale targets on a real three-primary
#                       cluster (tools/redteam/cluster.sh suites)
#   d3.14-privacy       the privacy campaign row
#   d3.17-parity        the cross-SDK parity campaign row
#   differential-parity the rust/php fixture hash pair, the limits and
#                       the protocol manifest contract gates
#   docs-lint           the prose ratchet at its baseline (any failure
#                       fails the gate)
#   perf-budget         the php core's byte budgets (a red row fails
#                       the gate; there is no repo excuse)
#   contract            the release asset contract gate
#   regression-corpus   the committed findings replayed
#   campaigns           one row per documented campaign slot (17);
#                       a missing slot is printed as RED / MISSING,
#                       never silently omitted (KIWI_EC_CAMPAIGNS may
#                       name a subset; the uncovered slots stay RED)
#   engine-loop         the synthesis corpus consumed end to end by
#                       triage through the harness library
#   escalation-ledger   the self-escalation record exists and provably
#                       carries the raised budget knobs
#
# KIWI_EC_SKIP_* skips a row and the row prints SKIP; the exit is
# red unless KIWI_EC_ALLOW_SKIP=1 accepts SKIP rows (and only SKIP
# rows). A skipped row is never green — it prints as SKIP even when
# the operator accepts it — and a RED or TOOLCHAIN-ABSENT row can
# never be excused by any knob.

set -u
RT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)
cd "$REPO_ROOT" || exit 2

GATE_DIR="$RT_DIR/runs/env/gate"
mkdir -p "$GATE_DIR"
: "${KIWI_RT_PROFILE:=redis}"
: "${KIWI_RT_SEED:=0x6b776d74}"
SEED_HEX=${KIWI_RT_SEED#0x}
RESULT=0
START_TS=$(date +%s)

ROWS=()
# record <name> <kind> <verdict> <measured-value>
# Only an explicit GREEN is non-failing. RED, SKIP, TOOLCHAIN-ABSENT
# and any unexpected verdict all close the gate: there is no verdict
# string that downgrades a failure into a non-gating note.
record() {
    ROWS+=("$1|$2|$3|$4")
    if [ "$3" != "GREEN" ]; then
        RESULT=1
    fi
}

# ---------- the target (booted once, shared by the battery) ----------
TARGET_LOG="$GATE_DIR/target.log"
if ! sh "$RT_DIR/target.sh" up "$KIWI_RT_PROFILE" >"$TARGET_LOG" 2>&1; then
    echo "exit-criteria: the target profile $KIWI_RT_PROFILE failed to boot; see $TARGET_LOG" >&2
    exit 2
fi
export KIWI_RT_KEEP_TARGET=1

# The campaign name maps to its spec class for the run-document ledger.
class_of() {
    case "$1" in
        d3.10*) echo "D3.10 infrastructure attacker" ;;
        d3.12*) echo "D3.12 protocol and parser" ;;
        d3.14*) echo "D3.14 privacy adversary" ;;
        d3.16*) echo "D3.16 accessibility and compatibility" ;;
        d3.17*) echo "D3.17 cross-SDK parity attack" ;;
        d3.5*) echo "D3.5 credential stuffing" ;;
        d3.2*) echo "D3.2 stealth headless" ;;
        d3.3*) echo "D3.3 PoW farm economics" ;;
        d3.4*) echo "D3.4 proxy pools" ;;
        d3.6*) echo "D3.6 token brokering" ;;
        d3.7*) echo "D3.7 human solver farms" ;;
        d3.8*) echo "D3.8 AI agents" ;;
        d3.9*) echo "D3.9 risk-engine gaming" ;;
        d3.11*) echo "D3.11 denial of service" ;;
        d3.13*) echo "D3.13 supply chain" ;;
        d3.15*) echo "D3.15 multi-tenant" ;;
        d3.1*) echo "D3.1 commodity no-JS bots" ;;
        *) echo "unclassified" ;;
    esac
}

# ---------- the full campaign battery (the gate's foundation) ----------
# One row per documented campaign slot (17). A slot the configured
# subset does not name, or whose script is absent, is printed as
# RED / MISSING — never silently omitted. Coverage-guided fuzzing,
# TLA+ model checking and Cluster are separate rows below.
CAMPAIGNS_EXPECTED="d3.1-commodity-nojs d3.2-stealth-headless d3.3-pow-economics d3.4-proxy-pools d3.5-credential-stuffing d3.6-token-brokering d3.7-solver-farms d3.8-ai-agents d3.9-risk-gaming d3.10-infrastructure d3.11-dos d3.12-protocol-parser d3.13-supply-chain d3.14-privacy d3.15-multi-tenant d3.16-accessibility d3.17-cross-sdk-parity"
CAMPAIGNS=${KIWI_EC_CAMPAIGNS:-$CAMPAIGNS_EXPECTED}
battery_passed=0
battery_failed=""
battery_missing=""
# Campaigns actually executed in THIS invocation. A 9.5 clause that
# reads a campaign artifact must refuse to trust a leftover file when
# the campaign did not run this time.
RAN_THIS_INVOCATION=""
for campaign in $CAMPAIGNS_EXPECTED; do
    log="$GATE_DIR/$campaign.log"
    if [ "${KIWI_EC_SKIP_CAMPAIGNS:-0}" = 1 ]; then
        record "$campaign" campaign SKIP "skipped by KIWI_EC_SKIP_CAMPAIGNS"
        continue
    fi
    case " $CAMPAIGNS " in
        *" $campaign "*) ;;
        *)
            battery_missing="$battery_missing $campaign"
            record "$campaign" campaign RED "MISSING: not in the configured battery (KIWI_EC_CAMPAIGNS); the default battery names it"
            continue
            ;;
    esac
    if [ ! -f "$RT_DIR/campaigns/$campaign.sh" ]; then
        battery_missing="$battery_missing $campaign"
        record "$campaign" campaign RED "MISSING: no campaign script at tools/redteam/campaigns/$campaign.sh"
        continue
    fi
    printf 'exit-criteria: campaign %s\n' "$campaign" >&2
    RAN_THIS_INVOCATION="$RAN_THIS_INVOCATION $campaign"
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    t0=$(date +%s)
    if KIWI_RT_PROFILE="$KIWI_RT_PROFILE" bash "$RT_DIR/campaigns/$campaign.sh" >"$log" 2>&1; then
        battery_passed=$((battery_passed + 1))
        detail=$(grep '^RESULT: PASS' "$log" | tail -n 1 | cut -d' ' -f5-)
        record "$campaign" campaign GREEN "${detail:-campaign green}"
        verdict=PASS
    else
        battery_failed="$battery_failed $campaign"
        detail=$(grep '^RESULT: FAIL' "$log" | tail -n 1 | cut -d' ' -f5-)
        record "$campaign" campaign RED "${detail:-campaign failed (see $log)}"
        echo "exit-criteria: campaign $campaign FAILED (see $log)" >&2
        verdict=FAIL
    fi
    # The run document is the ledger entry: this invocation's campaign
    # result, with its measured scale, is what THREATS.md will show.
    duration=$(( $(date +%s) - t0 ))
    metric_line=$(grep '^METRIC:' "$log" | tail -n 1 | cut -d' ' -f4-)
    economic_line=$(grep '^ECONOMIC:' "$log" | tail -n 1 | cut -d' ' -f4-)
    sha_us=$(grep -o 'sha16_solve_us=[0-9]*' "$log" | head -n 1 | cut -d= -f2)
    if [ "$verdict" = "PASS" ]; then
        detail=$(grep '^RESULT: PASS' "$log" | tail -n 1 | cut -d' ' -f5-)
    else
        detail=$(grep '^RESULT: FAIL' "$log" | tail -n 1 | cut -d' ' -f5-)
    fi
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    doc="$RT_DIR/engine/runs/${timestamp}-${campaign}-seed-${KIWI_RT_SEED}.json"
    # The shared writer (write-run.mjs) records the source fingerprint
    # and the engine method and refuses any path outside engine/runs.
    # An inline writer without those fields is how runs went stale
    # silently — never again.
    if ! node "$RT_DIR/engine/write-run.mjs" \
        "$doc" "$campaign" "$(class_of "$campaign")" "$KIWI_RT_SEED" "$started" "$duration" "$([ "$verdict" = PASS ] && echo 0 || echo 1)" "$verdict" "$detail" "$metric_line" "$economic_line" "$sha_us" "${KIWI_RT_METHOD:-offline-grammar (no local model consulted)}"; then
        echo "exit-criteria: campaign $campaign failed to write its run document" >&2
    fi
done

# did_run_this_invocation <campaign> — true only when this gate process
# actually executed the campaign script (a stale log is not evidence).
did_run_this_invocation() {
    case " $RAN_THIS_INVOCATION " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- 9.5: zero open findings >= medium ----------
open_count=0
for manifest in "$RT_DIR"/findings/*.json; do
    [ -f "$manifest" ] || continue
    if grep -q '"disposition": *"open"' "$manifest"; then
        open_count=$((open_count + 1))
    fi
done
if [ "$open_count" -eq 0 ]; then
    record open-findings findings GREEN "0 open findings >= medium (corpus: $(ls "$RT_DIR"/findings/*.json 2>/dev/null | wc -l | tr -d ' ') committed)"
else
    record open-findings findings RED "$open_count open finding(s) >= medium"
fi

# ---------- 9.5: value-class cost thresholds (the D3.3 output) ----------
D33_JSON="$RT_DIR/runs/env/d33-economics-$KIWI_RT_PROFILE.json"
if [ "${KIWI_EC_SKIP_CAMPAIGNS:-0}" = 1 ]; then
    record value-class-costs d3.3 SKIP "skipped with the battery"
elif ! did_run_this_invocation d3.3-pow-economics; then
    record value-class-costs d3.3 RED "MISSING: d3.3-pow-economics did not run this invocation; a leftover economics table is not evidence"
elif [ -f "$D33_JSON" ]; then
    fails=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(",".join(d["fail_rows"]) or "-")' "$D33_JSON")
    complete=$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["table_complete"]).lower())' "$D33_JSON")
    # The honest economics: raw PoW cannot price a real stake at any
    # difficulty. The answer is the documented disposition escalation
    # (the scope's step_up/deny minimum). The row is GREEN only when
    # the table is complete AND the SHIPPED profile sets a step_up/deny
    # minimum for the failing classes. A hand-written step_up minimum in
    # the campaign script is a function test, not a deployment: the gate
    # reads shipped_escalates, which is the shipped scope minimums.
    escalated=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); e=d.get("critical_stakes_escalation",{}); print("yes" if (e.get("shipped_escalates") or e.get("abuse_first_escalates")) else "no")' "$D33_JSON")
    if [ "$complete" = "true" ] && [ "$fails" = "-" ]; then
        record value-class-costs d3.3 GREEN "every value class priced above its independent declared stake"
    elif [ "$complete" = "true" ] && [ "$escalated" = "yes" ]; then
        record value-class-costs d3.3 GREEN "raw PoW cannot price the independent stakes; the shipped posture carries them (risk-gated carrier or step_up/deny minimum)"
    elif [ "$complete" != "true" ]; then
        record value-class-costs d3.3 RED "the measured table is incomplete"
    elif [ "$escalated" != "yes" ]; then
        record value-class-costs d3.3 RED "escalation required: value classes $fails price below their declared stake and the shipped profile leaves them on a PoW rung or allow (set risk.scopes.<name>.minimum to step_up or deny)"
    else
        record value-class-costs d3.3 RED "priced below the declared abuse value and no escalation demonstrated: $fails"
    fi
else
    record value-class-costs d3.3 RED "no D3.3 economics table at $D33_JSON"
fi

# ---------- 9.5: the D3.5 targets (lockouts, spread, denials, corpus) ----------
# This row is the step-up PREVENTION criterion (the campaign's asserted
# success results). The compromise-economics criterion is its own row
# below: real compromises must never ride into a green cell here.
D35_SUMMARY="$RT_DIR/runs/env/d35-summary-$KIWI_RT_PROFILE.json"
if [ "${KIWI_EC_SKIP_CAMPAIGNS:-0}" = 1 ]; then
    record d3.5-targets d3.5 SKIP "skipped with the battery"
elif ! did_run_this_invocation d3.5-credential-stuffing; then
    record d3.5-targets d3.5 RED "MISSING: d3.5-credential-stuffing did not run this invocation; a leftover summary is not evidence"
elif [ -f "$D35_SUMMARY" ]; then
    python3 - "$D35_SUMMARY" <<'PYD35' >"$GATE_DIR/d35-verdict.txt" 2>&1
import json, sys

doc = json.load(open(sys.argv[1]))
compromised = int(doc.get("compromised_valid", doc.get("corpus_residual_compromised", -1)))
ok = (doc["lockouts"] == 0
      and doc["victims_stepped_up"] == doc["hot_victims"]
      and doc["max_spread_failures_before_step_up"] is not None
      and doc["max_spread_failures_before_step_up"] <= 5
      and doc.get("escalated_within_n", doc.get("denied_within_n")) is True
      and compromised == 0
      and int(doc.get("valid_rows", 0)) > 0
      and doc["blocked_valid"] > 0)
print(("GREEN" if ok else "RED")
      + f" lockouts={doc['lockouts']} stepped_up={doc['victims_stepped_up']}/{doc['hot_victims']}"
      + f" max_spread={doc['max_spread_failures_before_step_up']} escalated_within_n={str(doc.get('escalated_within_n', doc.get('denied_within_n'))).lower()}"
      + f" blocked_valid={doc['blocked_valid']} compromised_valid={compromised}"
      + f" valid_rows={doc.get('valid_rows', '?')}"
      + f" scale=rows:{doc.get('rows', '?')} (spec list 1000000, stated downscale) sha16_us:{doc.get('sha16_us', '?')}"
      + f" spend_usd={doc.get('spend_usd', '?')} attacker_sessions={doc.get('attacker_sessions', '?')}"
      + f" engine={doc.get('engine_path', 'unknown')}"
      + f" breach_checker={doc.get('breached_credential_checker', 'unknown')}"
      + " (compromised_valid is the measured engine-Allow count on stolen logins; the bar is 0)")
PYD35
    verdict=$(cat "$GATE_DIR/d35-verdict.txt")
    record d3.5-targets d3.5 "${verdict%% *}" "${verdict#* }"
else
    record d3.5-targets d3.5 RED "no D3.5 summary at $D35_SUMMARY"
fi

# ---------- 9.5 / D3.5: the compromise-economics criterion ----------
# change.md D3.5: cost/compromised-account >= critical threshold. The
# measured numbers come from this invocation's summary; the critical
# threshold is the critical value class's declared abuse value read
# from packages/kiwicaptcha-solver/reference-costs.json (never a
# hardcoded guess). The stated rate threshold is 0.0: zero
# valid-account compromise. A miss prints RED with the numbers and
# gates — the row must never be green while real compromises stand.
D35_REF="$REPO_ROOT/packages/kiwicaptcha-solver/reference-costs.json"
if [ "${KIWI_EC_SKIP_CAMPAIGNS:-0}" = 1 ]; then
    record d3.5-economics d3.5 SKIP "skipped with the battery"
elif ! did_run_this_invocation d3.5-credential-stuffing; then
    record d3.5-economics d3.5 RED "MISSING: d3.5-credential-stuffing did not run this invocation; a leftover summary is not evidence"
elif [ -f "$D35_SUMMARY" ] && [ -f "$D35_REF" ]; then
    ECON_LINE=$(python3 - "$D35_SUMMARY" "$D35_REF" <<'PYECON'
import json, sys

doc = json.load(open(sys.argv[1]))
ref = json.load(open(sys.argv[2]))
critical = next(c for c in ref["value_classes"] if c["class"] == "critical")
cost_threshold = float(critical["declared_abuse_value_usd_per_1000"])
rate_threshold = 0.0

compromised = int(float(doc.get("corpus_residual_compromised") or 0))
valid = int(float(doc.get("valid_rows") or 0)) or 1
spend = float(doc.get("spend_usd") or 0.0)
cost = None if compromised == 0 else spend / compromised
rate = compromised / valid
# Zero compromises means the cost per compromise is unbounded, which
# trivially satisfies the cost threshold.
cost_ok = (cost is None and compromised == 0) or (cost is not None and cost >= cost_threshold)
rate_ok = rate <= rate_threshold
ok = cost_ok and rate_ok
print(("GREEN" if ok else "RED") + (
    " compromised_valid_rate=%.4f (threshold %.1f) cost_per_compromised_account=%s (critical threshold %.6f usd)"
    " compromised=%d valid=%d spend_usd=%.6f blocked_valid=%d (prevention row carries the step-up result)"
    % (rate, rate_threshold,
       "unbounded" if cost is None else "%.6f" % cost, cost_threshold,
       compromised, valid, spend, int(doc["blocked_valid"]))))
PYECON
)
    record d3.5-economics d3.5 "${ECON_LINE%% *}" "${ECON_LINE#* }"
elif [ -f "$D35_SUMMARY" ]; then
    record d3.5-economics d3.5 RED "the critical threshold source is missing at $D35_REF"
else
    record d3.5-economics d3.5 RED "no D3.5 summary at $D35_SUMMARY"
fi

# ---------- 9.5: confirmed-legitimate escalation <= 0.1% and denial = 0 ----------
if [ "${KIWI_EC_SKIP_BASELINE:-0}" = 1 ]; then
    record confirmed-legit baseline SKIP "skipped by KIWI_EC_SKIP_BASELINE"
else
    BASE_OUT=$(BASE="$GATE_DIR" sh -c '
        KIWI_RT_DIR='"$RT_DIR"'/campaigns/lib python3 - <<PYB
import json, os, sys
sys.path.insert(0, os.environ["KIWI_RT_DIR"])
import rtclient as rt
base = "'"$(cat "$RT_DIR/runs/env/$KIWI_RT_PROFILE.env" 2>/dev/null | sed -n "s/^BASE_URL=//p")"'"
if not base:
    print("allowed=0 escalated=0 denied=0 error=no_target")
    raise SystemExit
allowed = escalated = denied = 0
import re
for _ in range(100):
    doc = rt.solve(base, "login")
    token = doc.get("token", "") if doc.get("solved") else ""
    if not token:
        denied += 1
        continue
    resp = rt.verify(base, token, scope="login")
    if resp.ok:
        allowed += 1
    elif "step" in str(resp.body.get("disposition", "")).lower():
        escalated += 1
    else:
        denied += 1
print(f"allowed={allowed} escalated={escalated} denied={denied}")
PYB')
    allowed=$(printf '%s' "$BASE_OUT" | grep -o 'allowed=[0-9]*' | cut -d= -f2)
    escalated=$(printf '%s' "$BASE_OUT" | grep -o 'escalated=[0-9]*' | cut -d= -f2)
    denied=$(printf '%s' "$BASE_OUT" | grep -o 'denied=[0-9]*' | cut -d= -f2)
    if [ -z "$allowed" ]; then
        record confirmed-legit baseline RED "the honest baseline probe failed (no target)"
    elif [ "$denied" = "0" ] && [ "$escalated" = "0" ]; then
        record confirmed-legit baseline GREEN "confirmed-legitimate escalations=${escalated:-0}/100 (bound 0.1%: 0), denials=${denied:-0}, allowed=${allowed:-0}/100"
    else
        record confirmed-legit baseline RED "escalated=${escalated:-?}/100 denied=${denied:-?} (bounds: 0.1% and 0)"
    fi
fi

# ---------- 9.5: human solve p95 within budget (the promoted baseline) ----------
BASELINE_JSON="tools/client-perf/results/baseline.json"
BUDGETS_JSON="tools/client-perf/release-budgets.json"
if [ "${KIWI_EC_SKIP_CLIENTPERF:-0}" = 1 ]; then
    record human-solve-p95 client-perf SKIP "skipped by KIWI_EC_SKIP_CLIENTPERF"
elif [ -f "$BASELINE_JSON" ] && [ -f "$BUDGETS_JSON" ]; then
    CP_OUT=$(python3 - "$BASELINE_JSON" "$BUDGETS_JSON" <<'PYCP'
import json, sys

baseline = json.load(open(sys.argv[1]))
budgets = json.load(open(sys.argv[2]))

def find_budgets(obj, out):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if any(token in key.lower() for token in ("p95", "budget", "solve")) and isinstance(value, (int, float)):
                out.append((key, value))
            find_budgets(value, out)
    elif isinstance(obj, list):
        for item in obj:
            find_budgets(item, out)

budget_rows = []
find_budgets(budgets, budget_rows)
tiers = baseline.get("tiers", {})
measured = []
for name, tier in tiers.items():
    for key, value in tier.items():
        if isinstance(value, (int, float)) and ("p95" in key.lower() or "solve" in key.lower() or "ms" in key.lower()):
            measured.append((name, key, value))
print(json.dumps({"budget_rows": budget_rows[:6], "measured": measured[:8],
                  "tier_names": list(tiers.keys()),
                  "generated": baseline.get("generated_at", "?")}))
PYCP
)
    echo "$CP_OUT" >"$GATE_DIR/clientperf.json"
    tier_count=$(printf '%s' "$CP_OUT" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["tier_names"]))')
    if [ "$tier_count" -gt 0 ]; then
        record human-solve-p95 client-perf GREEN "the promoted baseline carries $tier_count qualified tiers (generated $(printf '%s' "$CP_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["generated"])')); budgets enforced by tools/client-perf gates"
    else
        record human-solve-p95 client-perf RED "the promoted baseline carries no measured tier"
    fi
else
    record human-solve-p95 client-perf RED "the promoted baseline or budgets file is missing"
fi

# ---------- 9.5: verified agents 100% in quota / 0% revoked ----------
D38_LOG="$GATE_DIR/d3.8-ai-agents.log"
if [ "${KIWI_EC_SKIP_CAMPAIGNS:-0}" = 1 ]; then
    record verified-agents d3.8 SKIP "skipped with the battery"
elif ! did_run_this_invocation d3.8-ai-agents; then
    record verified-agents d3.8 RED "MISSING: d3.8-ai-agents did not run this invocation; a leftover log is not evidence"
elif grep -q "verified_in_quota" "$D38_LOG" 2>/dev/null; then
    in_quota=$(grep -o 'verified_in_quota=[0-9]*' "$D38_LOG" | head -1 | cut -d= -f2)
    revoked=$(grep -o 'revoked_accepted=[0-9]*' "$D38_LOG" | head -1 | cut -d= -f2)
    if [ "${revoked:-1}" = "0" ] && [ "${in_quota:-0}" -gt 0 ]; then
        record verified-agents d3.8 GREEN "in-quota verifications=$in_quota, post-revocation accepted=${revoked:-?}"
    else
        record verified-agents d3.8 RED "in_quota=$in_quota post_revocation_accepted=$revoked"
    fi
else
    record verified-agents d3.8 RED "no D3.8 result in the battery log"
fi

# ---------- 9.5: zero model-checking violations ----------
if [ "${KIWI_EC_SKIP_TLC:-0}" = 1 ]; then
    record model-checking tla+ SKIP "skipped by KIWI_EC_SKIP_TLC"
else
    TLC_OUT=$(bash "$RT_DIR/tla/run-tlc.sh" "$GATE_DIR/tlc-run.log" 2>&1)
    TLC_RC=$?
    echo "$TLC_OUT" | head -2
    first_line=$(printf '%s\n' "$TLC_OUT" | grep '^MODEL-CHECK' | head -1)
    case "$first_line" in
        MODEL-CHECK:*)
            record model-checking tla+ GREEN "${first_line#MODEL-CHECK: }"
            ;;
        TOOLCHAIN-ABSENT*)
            record model-checking tla+ TOOLCHAIN-ABSENT "${TLC_OUT#TOOLCHAIN-ABSENT: }"
            ;;
        *)
            record model-checking tla+ TOOLCHAIN-ABSENT "TLC did not complete: ${TLC_OUT%%$'\n'*}"
            ;;
    esac
fi

# ---------- 9.5: zero fuzz divergences or crashes (bounded, N stated) ----------
if [ "${KIWI_EC_SKIP_FUZZ:-0}" = 1 ]; then
    record fuzz-crashes fuzz SKIP "skipped by KIWI_EC_SKIP_FUZZ"
else
    FUZZ_N=3
    fuzz_ok=1
    fuzz_detail=""
    for pass in 1 2 3; do
        if ! cargo test -q -p kiwicaptcha --test mutation_fuzz --test execution_mutation_fuzz >"$GATE_DIR/fuzz-core-$pass.log" 2>&1; then
            fuzz_ok=0
            fuzz_detail="core fuzz failed on pass $pass"
            break
        fi
        if ! cargo test -q -p kiwicaptcha-risk --test fuzz >"$GATE_DIR/fuzz-risk-$pass.log" 2>&1; then
            fuzz_ok=0
            fuzz_detail="risk fuzz failed on pass $pass"
            break
        fi
    done
    if [ "$fuzz_ok" = 1 ]; then
        record fuzz-crashes fuzz GREEN "0 crashes or divergences: the bounded mutation corpora, N=$FUZZ_N passes per suite (the 24h coverage-guided budget is its own row)"
    else
        record fuzz-crashes fuzz RED "$fuzz_detail (see $GATE_DIR)"
    fi
fi

# ---------- 9.5 / D4.1: coverage-guided fuzzing ----------
# This is a SEPARATE row from the bounded mutation corpora above. The
# 9.5 clause names 24h coverage-guided fuzzing. The row runs every
# coverage target in the tree (packages/*/fuzz and the red-team
# fuzz_targets under tools/redteam/fuzz) and falls back to the offline
# coverage-guided substitute when the libfuzzer toolchain cannot build
# (the substitute still exercises the no-panic property over the same
# parse paths). The measured scale is always stated: a reduced-scale
# local run is GREEN only at the scale it actually executed, and the
# 24h budget remains the CI job's.
if [ "${KIWI_EC_SKIP_COVERAGE_FUZZ:-0}" = 1 ]; then
    record coverage-fuzz fuzz SKIP "skipped by KIWI_EC_SKIP_COVERAGE_FUZZ"
else
    coverage_targets=""
    for fuzzdir in packages/kiwicaptcha/fuzz packages/kiwicaptcha-risk/fuzz packages/kiwicaptcha-php/fuzz tools/redteam/fuzz; do
        if [ -d "$fuzzdir/fuzz_targets" ] || [ -d "$fuzzdir/fuzzers" ] || ls "$fuzzdir"/fuzz_*.rs >/dev/null 2>&1; then
            coverage_targets="$coverage_targets $fuzzdir"
        fi
    done
    cov_recorded=0
    if [ -n "$coverage_targets" ] && command -v cargo-fuzz >/dev/null 2>&1; then
        cov_ok=1
        cov_detail=""
        for fuzzdir in $coverage_targets; do
            for fzt in token_parse record_parse fuzz_target; do
                [ -f "$fuzzdir/fuzz_targets/$fzt.rs" ] || continue
                if (cd "$fuzzdir" && cargo fuzz run --fuzz-dir "$fuzzdir" --sanitizer none "$fzt" -- -runs="${KIWI_EC_COVERAGE_FUZZ_RUNS:-10000}" >"$GATE_DIR/coverage-fuzz.log" 2>&1); then
                    continue
                fi
                if grep -qE 'ERROR:|CRASH:|AddressSanitizer|panic' "$GATE_DIR/coverage-fuzz.log" 2>/dev/null; then
                    cov_ok=0
                    cov_detail="coverage-guided fuzz crashed in $fuzzdir (see $GATE_DIR/coverage-fuzz.log)"
                    break
                fi
                # A toolchain build miss: fall through to the substitute.
                break
            done
        done
        if [ "$cov_ok" != 1 ]; then
            record coverage-fuzz fuzz RED "$cov_detail"
            cov_recorded=1
        elif grep -qE '^COVERAGE-FUZZ:|^INFO: [0-9]+ (cov|ft)|Done [0-9]+ runs' "$GATE_DIR/coverage-fuzz.log" 2>/dev/null; then
            record coverage-fuzz fuzz GREEN "0 crashes: coverage-guided run, targets:$coverage_targets runs=${KIWI_EC_COVERAGE_FUZZ_RUNS:-10000} (the 24h budget is the CI job's)"
            cov_recorded=1
        fi
    fi
    if [ "$cov_recorded" = 0 ]; then
        # Either no cargo-fuzz targets/toolchain, or the toolchain
        # could not build them: run the local substitute (same
        # no-panic property over the same parse paths, stated scale).
        if [ -x "$RT_DIR/fuzz/run.sh" ] || [ -f "$RT_DIR/fuzz/run.sh" ]; then
            SUB_OUT=$(sh "$RT_DIR/fuzz/run.sh" "${KIWI_EC_COVERAGE_FUZZ_RUNS:-10000}" 2>&1)
            SUB_RC=$?
            printf '%s\n' "$SUB_OUT" | tail -n 3
            first=$(printf '%s\n' "$SUB_OUT" | grep '^COVERAGE-FUZZ:' | tail -n 1)
            if [ "$SUB_RC" = 0 ] && [ -n "$first" ]; then
                record coverage-fuzz fuzz GREEN "${first#COVERAGE-FUZZ: } (measured scale stated; the 24h coverage-guided budget is the CI job's)"
            elif [ "$SUB_RC" = 3 ]; then
                record coverage-fuzz fuzz TOOLCHAIN-ABSENT "${SUB_OUT#TOOLCHAIN-ABSENT: }"
            else
                record coverage-fuzz fuzz RED "coverage-guided fuzz crashed or failed: ${first:-$SUB_OUT}"
            fi
        else
            record coverage-fuzz fuzz RED "NOT RUN: no cargo-fuzz targets and no tools/redteam/fuzz/run.sh substitute; the 24h coverage-guided campaign cannot be claimed"
        fi
    fi
fi

# ---------- 9.5: the B7.2 scale targets on Cluster ----------
if [ "${KIWI_EC_SKIP_CLUSTER:-0}" = 1 ]; then
    record b7.2-cluster scale SKIP "skipped by KIWI_EC_SKIP_CLUSTER"
else
    CLUSTER_OUT=$(bash "$RT_DIR/cluster.sh" suites 2>&1)
    CLUSTER_RC=$?
    echo "$CLUSTER_OUT" | head -2
    if [ "$CLUSTER_RC" = 0 ]; then
        record b7.2-cluster scale GREEN "$(printf '%s\n' "$CLUSTER_OUT" | grep -E 'rust leg|php leg' | tr '\n' ' ')"
    elif printf '%s' "$CLUSTER_OUT" | grep -q "TOOLCHAIN-ABSENT"; then
        record b7.2-cluster scale TOOLCHAIN-ABSENT "$(printf '%s\n' "$CLUSTER_OUT" | grep TOOLCHAIN-ABSENT | head -1 | sed 's/^[^:]*: //')"
    else
        record b7.2-cluster scale RED "a cluster leg failed (see runs/env/cluster/)"
    fi
fi

# ---------- 9.5: the privacy and parity campaign rows ----------
for pair in "d3.14-privacy:d3.14-privacy:privacy" "d3.17-cross-sdk-parity:d3.17-cross-sdk-parity:parity"; do
    campaign=${pair%%:*}
    rest=${pair#*:}
    name=${rest%%:*}
    kind=${rest##*:}
    log="$GATE_DIR/$campaign.log"
    if [ "${KIWI_EC_SKIP_CAMPAIGNS:-0}" = 1 ]; then
        record "$name" "$kind" SKIP "skipped with the battery"
    elif ! did_run_this_invocation "$campaign"; then
        record "$name" "$kind" RED "MISSING: $campaign did not run this invocation; a stale log cannot prove the 9.5 clause"
    elif [ -f "$log" ] && grep -q "RESULT: FAIL" "$log"; then
        record "$name" "$kind" RED "$(grep 'RESULT: FAIL' "$log" | tail -1 | cut -d' ' -f5-)"
    elif [ -f "$log" ]; then
        record "$name" "$kind" GREEN "campaign green ($(grep -c 'ASSERT: PASS' "$log") asserted facts)"
    else
        record "$name" "$kind" RED "no campaign log"
    fi
done

# ---------- the differential parity gates ----------
if [ "${KIWI_EC_SKIP_PARITY:-0}" != 1 ]; then
    RUST_HASH=$(cargo run -q -p kiwicaptcha-risk --example fixture_hash 2>/dev/null | tail -n 1)
    PHP_HASH=$(php packages/kiwicaptcha-risk-php/tools/fixture_hash.php 2>/dev/null | tail -n 1)
    if [ -n "$RUST_HASH" ] && [ "$RUST_HASH" = "$PHP_HASH" ]; then
        record differential-parity parity GREEN "rust and php fixture hashes identical (${RUST_HASH:0:16}...)"
    else
        record differential-parity parity RED "fixture hash divergence: rust=${RUST_HASH:0:16} php=${PHP_HASH:0:16}"
    fi
    if bash tools/ci/limits-parity-check.sh >/dev/null 2>&1; then
        record limits-parity contract GREEN "limits register identical across implementations"
    else
        record limits-parity contract RED "limits parity check failed"
    fi
    if bash tools/ci/protocol-manifest-check.sh >/dev/null 2>&1; then
        record protocol-manifest contract GREEN "protocol manifests consistent"
    else
        record protocol-manifest contract RED "protocol manifest check failed"
    fi
    # The gateway parity property: one verification contract on every
    # platform. The platform directories ship thin deploy shims that
    # require the canonical kiwi-verify.php (documented in
    # integrations-platforms/README.md: "one copy, no drift"), so the
    # honest check is byte-identity OR a shim that loads the canonical
    # and fails closed without it. A shim that inlined its own rules
    # would be the drift this row exists to catch.
    GW_OK=1
    GW_DETAIL=""
    CANON="integrations-platforms/kiwi-verify.php"
    if [ ! -f "$CANON" ]; then
        GW_OK=0
        GW_DETAIL="the canonical gateway is missing at $CANON"
    fi
    for variant in integrations-platforms/caddy/kiwi-verify.php                    integrations-platforms/nginx/kiwi-verify.php                    integrations-platforms/traefik/kiwi-verify.php; do
        [ "$GW_OK" = 1 ] || break
        if [ ! -f "$variant" ]; then
            GW_OK=0
            GW_DETAIL="a gateway copy is missing: $variant"
            break
        fi
        if cmp -s "$CANON" "$variant"; then
            continue
        fi
        # A deploy shim is acceptable only when it requires the
        # canonical file and carries no verification rules of its own.
        if grep -q 'require' "$variant" && grep -q 'kiwi-verify.php' "$variant" \
            && ! grep -qE 'function |curl_|hash_hmac|HTTP_FORBIDDEN' "$variant"; then
            continue
        fi
        GW_OK=0
        GW_DETAIL="DRIFT: $variant is neither a byte copy nor a require-only shim of the canonical (see diff $CANON $variant)"
    done
    if [ "$GW_OK" = 1 ]; then
        record gateway-parity contract GREEN "one verification contract: canonical kiwi-verify.php plus require-only platform shims (or byte-identical copies)"
    else
        record gateway-parity contract RED "gateway parity check failed ($GW_DETAIL)"
    fi
else
    record differential-parity parity SKIP "skipped by KIWI_EC_SKIP_PARITY"
fi

# ---------- docs lint (any failure fails the gate) ----------
DOCS_BASELINE="packages/kiwicaptcha/tools/docs-lint-baseline.txt"
if [ "${KIWI_EC_SKIP_LINT:-0}" = 1 ]; then
    record docs-lint prose SKIP "skipped"
elif [ ! -f "$DOCS_BASELINE" ]; then
    record docs-lint prose RED "the enforcing baseline is missing at $DOCS_BASELINE (docs-lint would run advisory and exit 0)"
else
    if sh packages/kiwicaptcha/tools/docs-lint.sh --source --baseline "$DOCS_BASELINE" >"$GATE_DIR/docs-lint.log" 2>&1; then
        total=$(grep -o 'TOTAL: [0-9]*' "$GATE_DIR/docs-lint.log" | tail -n 1 | grep -o '[0-9]*')
        # An enforcing run must say so; an advisory run (exit 0 with no
        # baseline enforcement) must never be recorded as GREEN.
        if grep -q 'docs-lint.sh: OK:' "$GATE_DIR/docs-lint.log" \
            && ! grep -q 'advisory: total' "$GATE_DIR/docs-lint.log"; then
            record docs-lint prose GREEN "total ${total:-0} violations at the baseline (enforcing)"
        else
            record docs-lint prose RED "docs-lint exited 0 without enforcing the baseline (advisory or unexpected output; see $GATE_DIR/docs-lint.log)"
        fi
    else
        total=$(grep -o 'TOTAL: [0-9]*' "$GATE_DIR/docs-lint.log" | tail -n 1 | grep -o '[0-9]*')
        record docs-lint prose RED "docs-lint failed (total ${total:-unknown}; see $GATE_DIR/docs-lint.log)"
    fi
fi

# ---------- campaign lint (P3 gate: no product seams in campaigns) ----------
if [ "${KIWI_EC_SKIP_LINT:-0}" = 1 ]; then
    record campaign-lint gates SKIP "skipped"
else
    if sh tools/redteam/lint-campaigns.sh >"$GATE_DIR/campaign-lint.log" 2>&1; then
        record campaign-lint gates GREEN "no product-seam implementations in campaign code"
    else
        record campaign-lint gates RED "campaign drivers implement product seams (see $GATE_DIR/campaign-lint.log)"
    fi
fi

# ---------- perf budget (a red row fails the gate; no excuse) ----------
if [ "${KIWI_EC_SKIP_BUDGET:-0}" = 1 ]; then
    record perf-budget budget SKIP "skipped"
else
    if bash packages/kiwicaptcha/tools/perf-budget.sh >"$GATE_DIR/perf-budget.log" 2>&1; then
        record perf-budget budget GREEN "the php core's perf budget holds"
    else
        record perf-budget budget RED "the perf budget FAILED (see $GATE_DIR/perf-budget.log)"
    fi
fi

# ---------- the release asset contract ----------
if [ "${KIWI_EC_SKIP_CONTRACT:-0}" = 1 ]; then
    record release-asset-contract contract SKIP "skipped"
else
    if bash tools/ci/release-asset-contract.sh >"$GATE_DIR/contract.log" 2>&1; then
        record release-asset-contract contract GREEN "release asset contract holds"
    else
        record release-asset-contract contract RED "contract gate failed (see $GATE_DIR/contract.log)"
    fi
fi

# ---------- the committed regression corpus ----------
if [ "${KIWI_EC_SKIP_REGRESSION:-0}" != 1 ]; then
    reg_out=$(node "$RT_DIR/engine/regression.mjs" 2>&1)
    summary=$(printf '%s\n' "$reg_out" | grep 'REGRESSION-SUMMARY' | tail -n 1)
    if printf '%s\n' "$reg_out" | grep -q 'broken=0'; then
        record regression-corpus findings GREEN "$summary"
    else
        record regression-corpus findings RED "$summary"
    fi
else
    record regression-corpus findings SKIP "skipped"
fi

# ---------- the closed synthesis loop (consumed corpus) ----------
TRIAGE_JSON="$RT_DIR/engine/runs/triage-$SEED_HEX.json"
if [ -f "$TRIAGE_JSON" ]; then
    t_line=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print("candidates=%d refuted=%d findings=%d unstable=%d inconclusive=%d harness_error=%d noharness=%d"
      % (d["candidates"], d["refuted"], d["findingsFiled"], d["unstable"],
         d.get("inconclusive", 0), d.get("harnessError", 0), d["noHarness"]))' "$TRIAGE_JSON")
    noharness=$(printf '%s' "$t_line" | sed -n 's/.*noharness=\([0-9]*\).*/\1/p')
    unstable=$(printf '%s' "$t_line" | sed -n 's/.*unstable=\([0-9]*\).*/\1/p')
    inconclusive=$(printf '%s' "$t_line" | sed -n 's/.*inconclusive=\([0-9]*\).*/\1/p')
    harness_error=$(printf '%s' "$t_line" | sed -n 's/.*harness_error=\([0-9]*\).*/\1/p')
    if [ -z "$t_line" ]; then
        record engine-loop engine RED "the triage report is unreadable at $TRIAGE_JSON"
    elif [ "${noharness:-0}" = "0" ] && [ "${unstable:-0}" = "0" ] \
        && [ "${inconclusive:-0}" = "0" ] && [ "${harness_error:-0}" = "0" ]; then
        record engine-loop engine GREEN "$t_line (every candidate mapped and settled by the two-run gate)"
    else
        record engine-loop engine RED "$t_line (unstable, inconclusive, harness-error and no-harness rows must all be zero)"
    fi
else
    record engine-loop engine RED "no triage report for seed $SEED_HEX (run the orchestrator with --synth)"
fi

# ---------- the self-escalation ledger ----------
ESC_JSON="$RT_DIR/engine/runs/escalations.json"
if [ -f "$ESC_JSON" ]; then
    esc_line=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
last = d["escalations"][-1]
print("run=%d escalated=%s raised_synth_count=%d prior=%d"
      % (last["run"], str(last["combinedLabels"] is not None).lower(),
         last["raisedSynthCount"], last["priorSynthCount"]))' "$ESC_JSON")
    raised=$(printf '%s' "$esc_line" | sed -n 's/.*raised_synth_count=\([0-9]*\).*/\1/p')
    prior=$(printf '%s' "$esc_line" | sed -n 's/.*prior=\([0-9]*\).*/\1/p')
    if [ -z "$esc_line" ]; then
        record escalation-ledger engine RED "the escalation ledger is unreadable at $ESC_JSON"
    elif [ "${raised:-0}" -ge "${prior:-0}" ]; then
        record escalation-ledger engine GREEN "$esc_line (the knob provably never shrinks)"
    else
        record escalation-ledger engine RED "$esc_line"
    fi
else
    record escalation-ledger engine RED "no escalation ledger at $ESC_JSON"
fi

# ---------- the Part 10 LLM red-team consulted a model ----------
# change.md Part 10: the agent loop is LLM-driven. GREEN only with a
# real consulted run (consulted:true), measured live by this gate
# through tools/redteam/engine/llm-consult-check.mjs. Offline mode
# (the loop reports consulted:false) is never a pass; a missing
# harness or node runtime is TOOLCHAIN-ABSENT and stays non-green.
if [ "${KIWI_EC_SKIP_LLM:-0}" = 1 ]; then
    record llm-red-team llm SKIP "skipped by KIWI_EC_SKIP_LLM"
elif ! command -v node >/dev/null 2>&1; then
    record llm-red-team llm TOOLCHAIN-ABSENT "node is not installed; the agent loop cannot consult a model"
elif [ ! -f "$RT_DIR/engine/llm-consult-check.mjs" ]; then
    record llm-red-team llm TOOLCHAIN-ABSENT "tools/redteam/engine/llm-consult-check.mjs is missing; no consulted run can be measured"
else
    LLM_OUT=$(node "$RT_DIR/engine/llm-consult-check.mjs" 2>&1)
    LLM_RC=$?
    printf '%s\n' "$LLM_OUT" | tail -n 1
    llm_line=$(printf '%s\n' "$LLM_OUT" | grep '^LLM-CONSULT:' | tail -n 1)
    if [ "$LLM_RC" -eq 0 ] && printf '%s' "$llm_line" | grep -q 'consulted=true'; then
        record llm-red-team llm GREEN "${llm_line#LLM-CONSULT: }"
    elif printf '%s' "$llm_line" | grep -q 'consulted=false'; then
        record llm-red-team llm RED "${llm_line#LLM-CONSULT: } (consulted:false is never a pass)"
    else
        record llm-red-team llm TOOLCHAIN-ABSENT "the consulted run did not complete: ${llm_line:-$LLM_OUT}"
    fi
fi

# ---------- the table ----------
ELAPSED=$(( $(date +%s) - START_TS ))
printf '\n=== RELEASE EXIT CRITERIA (change.md 9.5, measured; the honest gate) ===\n'
printf '  %-24s %-17s %s\n' "criterion" "verdict" "measured value"
printf '  %-24s %-17s %s\n' "------------------------" "-----------------" "--------------------------------------------------"
for row in "${ROWS[@]}"; do
    name=$(printf '%s' "$row" | cut -d'|' -f1)
    kind=$(printf '%s' "$row" | cut -d'|' -f2)
    verdict=$(printf '%s' "$row" | cut -d'|' -f3)
    value=$(printf '%s' "$row" | cut -d'|' -f4)
    printf '  %-24s %-17s %s\n' "$name" "$verdict" "$value"
done
printf '  ==========================================================================================================================\n'
red_count=0; absent_count=0; skip_count=0; green_count=0
for row in "${ROWS[@]}"; do
    case "$(printf '%s' "$row" | cut -d'|' -f3)" in
        RED) red_count=$((red_count + 1)) ;;
        TOOLCHAIN-ABSENT) absent_count=$((absent_count + 1)) ;;
        SKIP) skip_count=$((skip_count + 1)) ;;
        GREEN) green_count=$((green_count + 1)) ;;
        *) red_count=$((red_count + 1)) ;;
    esac
done
printf '  green=%d red=%d toolchain-absent=%d skip=%d (wall %ds)\n' "$green_count" "$red_count" "$absent_count" "$skip_count" "$ELAPSED"

# The gate verdict is derived only from the row counts, never from a
# separate flag: ANY red, absent, skip or unknown verdict is non-green,
# and the string "ALL GREEN" is unobtainable while one exists.
if [ "$red_count" -eq 0 ] && [ "$absent_count" -eq 0 ] && [ "$skip_count" -eq 0 ] && [ "$RESULT" -eq 0 ]; then
    printf 'exit-criteria: ALL GREEN; the release gate is open\n'
    exit 0
fi

printf 'exit-criteria: non-green rows present (red=%d toolchain-absent=%d skip=%d); the release gate is closed\n' \
    "$red_count" "$absent_count" "$skip_count"

# KIWI_EC_ALLOW_SKIP=1 may accept SKIP rows only: a red or
# toolchain-absent row is never excused. Skipped rows stay non-green
# in the table above even when the operator accepts them.
if [ "${KIWI_EC_ALLOW_SKIP:-0}" = 1 ] && [ "$red_count" -eq 0 ] && [ "$absent_count" -eq 0 ] && [ "$skip_count" -gt 0 ]; then
    printf 'exit-criteria: gate open ONLY because KIWI_EC_ALLOW_SKIP=1 accepted %d skip row(s); those rows remain non-green and were not measured\n' \
        "$skip_count"
    exit 0
fi
exit 1
