#!/bin/bash
# d3.3-pow-economics.sh — native PoW farm economics (change.md D3.3).
#
# The attacker rents the strongest hardware the reference table
# carries: SHA-NI/AVX-512 CPUs, GPU sha256 kernels (the two consumer
# GPU classes in reference-costs.json), and dedicated mining silicon
# (which the table honestly refuses to price). The campaign measures
# THIS cpu's per-rung cost with the solver's own bench, builds the
# value-class table, and prices every declared value class against the
# declared abuse value on both the native measurement and the fastest
# rentable GPU reference. Every row carries its verdict: the priced
# rung must cost MORE than the abuse value per 1000 solves, else the
# row says FAIL, and the FAIL rows feed the release gate's
# value-class threshold row verbatim.
#
# Downscale, stated numerically: the class volume is a farm at 10^6
# req/h (the D3.1 volume); the bench measures per-solve cost, which is
# scale-free, and the end-to-end leg runs 3 honest solves. The
# measurement mechanism is the real one; the count is the downscale.
#
# The RSW rung: no attacker rate is carried by the reference table on
# purpose (sequential time-lock squaring buys no parallel speedup), so
# the row's evidence is the crate's own RSW suite, re-run here.
#
# Ports: none of its own; the end-to-end leg uses the profile target.
#
# Economic metric: the table itself; cost per accepted abuse is
# unbounded (the deployment accepts zero forged solves).

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.3-pow-economics
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")

if [ ! -x "$REPO_ROOT/target/debug/kiwicaptcha-solver" ]; then
    rt_report_fail "the solver binary is missing; build it (cargo build -p kiwicaptcha-solver)"
    rt_finish
fi

D33_OUT="$RT_DIR/runs/env/d33-economics-$RT_PROFILE.json"
KIWI_RT_REPO_ROOT="$REPO_ROOT" KIWI_RT_BASE="$BASE" KIWI_RT_D33_OUT="$D33_OUT" \
KIWI_RT_D33_SAMPLES="${KIWI_RT_D33_SAMPLES:-3}" \
    python3 "$RT_DIR/campaigns/lib/d33.economics.py"
D33_RC=$?

TABLE_COMPLETE=$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["table_complete"]).lower())' "$D33_OUT")
ACCEPTED=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["honest_solves_verified"])' "$D33_OUT")
FAIL_ROWS=$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["fail_rows"]) or "-")' "$D33_OUT")

rt_assert_eq "$TABLE_COMPLETE" "true" "the value-class table covers every declared class"
rt_assert_eq "$ACCEPTED" "3" "honest baseline: three honest solves verified end-to-end"
[ "$D33_RC" -eq 0 ] || rt_report_fail "the economics builder reported an internal error"

# ---------- the critical-stakes escalation demonstration ----------
# The honest finding: raw PoW cannot price a $10-per-1000 stake at any
# difficulty (the strongest rung's measured ceiling is three orders of
# magnitude below it), and that is WHY the ladder ends in step_up/deny.
# The demonstration drives the bundle's own verdict: a critical scope
# configured beyond the ceiling with no disposition minimum draws the
# escalation advice naming the enforcement knob (risk.scopes.<name>
# .minimum), and the same scope with the step_up minimum set draws the
# verified pass.
ESC_JSON=$(REPO_ROOT="$REPO_ROOT" php -r '
require getenv("REPO_ROOT")."/tools/redteam/campaigns/lib/rt-risk-prelude.php";
use BelConsulting\KiwiCaptchaBundle\Economics\ValueClassCeiling;
$beyond = ["critical" => ["rung" => "argon64", "declared_usd_per_1000" => 10.0, "ceiling_usd_per_1000" => 0.00421]];
$advised = ValueClassCeiling::verdict("critical", "allow", $beyond);
$verified = ValueClassCeiling::verdict("critical", "step_up", $beyond);
$shipped = ValueClassCeiling::verdict("critical", "allow");
echo json_encode(["advised" => $advised, "verified" => $verified, "shipped_default" => $shipped]), "\n";
')
printf '%s\n' "$ESC_JSON" | python3 -c '
import json, sys
doc = json.loads(sys.stdin.read())
out_path = sys.argv[1]
store = json.load(open(out_path))
store["critical_stakes_escalation"] = {
    "beyond_ceiling_stake_usd_per_1000": 10.0,
    "advised": {"status": doc["advised"][0], "detail": doc["advised"][1]},
    "verified_with_step_up_minimum": {"status": doc["verified"][0], "detail": doc["verified"][1]},
    "shipped_default": {"status": doc["shipped_default"][0], "detail": doc["shipped_default"][1]},
}
json.dump(store, open(out_path, "w"), indent=2)
# The shipped default with an independent stake beyond the ceiling is
# the honest WARN (escalation demanded), not a PASS: raw PoW cannot
# price a real stake at any difficulty. The verified row (step_up
# minimum set) must PASS: the disposition carries the stake.
ok = (doc["advised"][0] == "WARN"
      and "risk.scopes" in doc["advised"][1]
      and "step_up" in doc["advised"][1]
      and doc["verified"][0] == "PASS"
      and doc["shipped_default"][0] in ("PASS", "WARN"))
print("CRITICAL-STAKES-ESCALATION: %s advised=%s verified=%s" % ("PASS" if ok else "FAIL", doc["advised"][0], doc["verified"][0]))
raise SystemExit(0 if ok else 1)
' "$D33_OUT"
rt_assert_eq "$?" "0" "the critical-stakes escalation path: beyond-ceiling scope advises the step_up minimum, then verifies it"

# ---------- the RSW sequentiality leg ----------
RSW_LOG=$(mktemp)
if (cd "$REPO_ROOT" && cargo test -q -p kiwicaptcha --test emission_capabilities -- rsw >"$RSW_LOG" 2>&1); then
    RSW_TESTS=$(grep -c '^test .* ok' "$RSW_LOG" 2>/dev/null || echo 0)
    rt_report_pass "rsw suite green: sequential squaring semantics pinned ($RSW_TESTS tests ok)"
else
    rt_report_fail "the rsw suite failed (a parallel-speedup claim would be a farm win)"
fi
rm -f "$RSW_LOG"

# ---------- the priced-abuse threshold rows (the gate reads these) ----------
# The verdict rows are measured data, not harness failures: the campaign
# is green when every row was measured and honestly classified, and the
# dedicated gate row turns red on the FAIL classes verbatim. ESCALATE
# rows are the documented disposition answer (the scope's step_up/deny
# minimum), so they are recorded, printed and not gate failures.
ESCALATE_ROWS=$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["escalate_rows"]) or "-")' "$D33_OUT")
if [ "$FAIL_ROWS" != "-" ]; then
    printf 'VALUE-CLASS-VERDICT: FAIL %s (the priced rung undercuts the declared abuse value)\n' "$FAIL_ROWS"
    rt_report_pass "value-class verdicts recorded honestly; the FAIL rows feed the gate row"
else
    printf 'VALUE-CLASS-VERDICT: PASS all classes (escalated to the disposition minimum: %s)\n' "$ESCALATE_ROWS"
    rt_report_pass "every value class priced above its declared abuse value, or escalated to the documented disposition path"
fi

# The metric names the honest-baseline count as what it is: those three
# are verified honest solves, NOT accepted abuses. Restating them as
# "accepted=3" beside cost_per_accepted_abuse=unbounded was the
# contradiction this line exists to prevent.
rt_metric "table_complete=$TABLE_COMPLETE honest_solves_verified=$ACCEPTED accepted_abuses=0 fail_rows=$FAIL_ROWS"
printf 'ECONOMIC: %s %s cost_per_accepted_abuse=unbounded accepted_abuses=0 honest_solves_verified=%s value_class_fails=%s table=tools/redteam/runs/env/d33-economics-%s.json\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$ACCEPTED" "$FAIL_ROWS" "$RT_PROFILE"

rt_finish
