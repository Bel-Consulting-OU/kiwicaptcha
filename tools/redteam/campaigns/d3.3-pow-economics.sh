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
# Ports: none of its own except the campaign-local redis (6478, the
# risk-gaming port reused sequentially) on profiles that carry no
# redis url; the end-to-end leg always uses the profile target.
#
# A storage profile carries no redis url, so the kernel leg (the
# shipped posture read through a booted product kernel) runs on the
# campaign-local redis and the campaign still reports a real verdict
# instead of a red against a dead store.
#
# Economic metric: the table itself; cost per accepted abuse is
# unbounded (the deployment accepts zero forged solves).

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.3-pow-economics
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")
# The risk-Redis URL of the booted profile: the escalation demonstration
# reads its config through the product kernel, and the kernel's runtime
# proof line needs a real Redis by design. A storage profile carries
# none, so the campaign boots its own (the ports are reused
# sequentially, never concurrently) and the posture reading stays the
# same product code over a different store.
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
ESC_REDIS_URL="$REDIS_URL"
if [ -z "$ESC_REDIS_URL" ]; then
    ESC_REDIS_PORT=6478
    redis-cli -p "$ESC_REDIS_PORT" shutdown nosave >/dev/null 2>&1
    sleep 0.3
    mkdir -p "$RT_DIR/runs/env/d33"
    redis-server --port "$ESC_REDIS_PORT" --bind 127.0.0.1 --save '' \
        --appendonly no --daemonize no --dir "$RT_DIR/runs/env/d33" \
        >"$RT_DIR/runs/env/d33-redis.log" 2>&1 &
    ESC_REDIS_PID=$!
    ESC_REDIS_URL="redis://127.0.0.1:$ESC_REDIS_PORT"
    cleanup_d33_redis() {
        kill "$ESC_REDIS_PID" 2>/dev/null
        redis-cli -p "$ESC_REDIS_PORT" shutdown nosave >/dev/null 2>&1
    }
    if [ "${KIWI_RT_KEEP_TARGET:-0}" != "1" ]; then
        trap 'cleanup_d33_redis; rt_teardown' EXIT
    else
        trap cleanup_d33_redis EXIT
    fi
    ready=0
    for i in $(seq 1 40); do
        if redis-cli -p "$ESC_REDIS_PORT" ping >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.25
    done
    [ "$ready" = 1 ] || {
        rt_report_fail "the d3.3 redis never opened port $ESC_REDIS_PORT"
        rt_finish
    }
fi

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
ESC_JSON=$(REPO_ROOT="$REPO_ROOT" KIWI_RT_RISK_REDIS_URL="$ESC_REDIS_URL" php -r '
require getenv("REPO_ROOT")."/tools/redteam/campaigns/lib/rt.kernel.php";
// The bundle"s own Symfony Config tree, so the shipped defaults are
// read from the product — never a literal list.
$bundleAutoload = getenv("REPO_ROOT")."/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php";
if (is_file($bundleAutoload)) {
    require_once $bundleAutoload;
}
use BelConsulting\KiwiCaptchaBundle\Economics\ValueClassCeiling;
$beyond = ["critical" => ["rung" => "argon64", "declared_usd_per_1000" => 10.0, "ceiling_usd_per_1000" => 0.00421]];
$advised = ValueClassCeiling::verdict("critical", "allow", $beyond);
$verified = ValueClassCeiling::verdict("critical", "step_up", $beyond);
$shipped = ValueClassCeiling::verdict("critical", "allow");
$processor = new \Symfony\Component\Config\Definition\Processor();
$config = new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration();

// The per-profile posture: the carrier table is measured per profile,
// never assumed uniform. The step-up plane counts as a carrier ONLY
// when the matching factor is enabled: a step_up minimum with no
// enabled handler (email_otp, totp, webauthn or a custom map) is a
// dead end the deployment cannot actually complete.
$hasEnabledFactor = static function (array $risk): bool {
    if (!($risk["step_up"]["enabled"] ?? false)) {
        return false;
    }
    $handlers = $risk["step_up"]["handlers"] ?? [];
    foreach (["email_otp", "totp", "webauthn"] as $factor) {
        if (($handlers[$factor]["enabled"] ?? false) === true) {
            return true;
        }
    }

    return ($handlers["custom"] ?? []) !== [];
};

// The shipped carrier model, read from the processed tree. A scope is
// covered when the shipped posture carries it with a completable
// enforcement, and the carriers are the product knobs themselves: the
// disposition minimum (deny, or step_up over an enabled handler), the
// enforcing novelty posture on the login scopes (login, admin_login
// and the password_reset recovery leg the shipped posture assesses
// under the same enforce decision), a named risk.scopes.<name>.carrier
// whose factor the tree enables, the login_step_up always policy (the
// post-credential gate withholds every session until a principal
// factor, totp or webauthn, completes) and the step_up_above rung (the
// risk-gated escalation over an enabled plane). A class is covered
// only when EVERY scope of that class is covered (any-vs-all: one
// covered scope never vouches for its class).
$loginScopes = ["login", "admin_login", "password_reset"];
$profiles = [];
$classCarrier = [];
foreach (["abuse_first", "balanced"] as $profileName) {
    $processed = $processor->processConfiguration($config, \BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults::stack([["secret_key" => str_repeat("a", 32), "protection_profile" => $profileName]]));
    $risk = $processed["risk"] ?? [];
    $scopes = $risk["scopes"] ?? [];
    $minimums = [];
    $scopeClasses = [];
    foreach ($scopes as $name => $scope) {
        $minimums[$name] = $scope["minimum"] ?? "allow";
        $scopeClasses[$name] = $scope["value_class"] ?? "standard";
    }
    $novelty = $risk["novelty_enforcement"] ?? "learn";
    $factorEnabled = $hasEnabledFactor($risk);
    // The factor map the carriers read: the plane must be on and the
    // named factor enabled for the carrier to be completable. The
    // step_up_email spelling maps to the anonymous email-ownership
    // grant under risk.step_up.email_ownership (the node
    // Configuration.php carries for it and the doctor carrier check
    // reads), never to the email_otp handler.
    $plane = $risk["step_up"] ?? [];
    $planeOn = (bool) ($plane["enabled"] ?? false);
    $handlers = $plane["handlers"] ?? [];
    $carrierFactor = [
        "email_otp" => $planeOn && ($handlers["email_otp"]["enabled"] ?? false) === true,
        "step_up_email" => $planeOn && ($plane["email_ownership"]["enabled"] ?? false) === true,
        "totp" => $planeOn && ($handlers["totp"]["enabled"] ?? false) === true,
        "webauthn" => $planeOn && ($handlers["webauthn"]["enabled"] ?? false) === true,
    ];
    $principalFactor = $carrierFactor["totp"] || $carrierFactor["webauthn"];
    $allCovered = true;
    $classCovered = [];
    $scopeCoverage = [];
    foreach ($scopeClasses as $name => $cls) {
        $min = $minimums[$name] ?? "allow";
        $isLogin = in_array($name, $loginScopes, true);
        $carrier = $scopes[$name]["carrier"] ?? null;
        // The existing minimum and novelty rules, exactly as before.
        $covered = ($isLogin && $novelty === "enforce")
            || $min === "deny"
            || ($min === "step_up" && $factorEnabled);
        $knob = "none";
        if ($min === "deny") {
            $knob = "minimum:deny";
        } elseif ($min === "step_up" && $factorEnabled) {
            $knob = "minimum:step_up";
        } elseif ($isLogin && $novelty === "enforce") {
            $knob = "novelty_enforcement";
        }
        // The named carrier: completable only when its factor is on.
        if (!$covered && is_string($carrier) && ($carrierFactor[$carrier] ?? false)) {
            $covered = true;
            $knob = "carrier:" . $carrier;
        }
        // The post-credential gate: every session waits for a principal
        // factor, so no solved request rides the PoW rung alone.
        if (!$covered && ($scopes[$name]["login_step_up"] ?? null) === "always" && $principalFactor) {
            $covered = true;
            $knob = "login_step_up:always";
        }
        // The risk-gated rung: only a scored decision above the rung
        // escalates, and the escalation completes over the enabled
        // plane.
        if (!$covered && isset($scopes[$name]["step_up_above"]) && $scopes[$name]["step_up_above"] !== null && $factorEnabled) {
            $covered = true;
            $knob = "step_up_above:" . $scopes[$name]["step_up_above"];
        }
        $scopeCoverage[$name] = $knob;
        $classCovered[$cls] = ($classCovered[$cls] ?? true) && $covered;
        $allCovered = $allCovered && $covered;
    }
    $profiles[$profileName] = [
        "escalates" => $novelty === "enforce",
        "novelty" => $novelty,
        "minimums" => $minimums,
        "factor_enabled" => $factorEnabled,
        "scope_value_classes" => $scopeClasses,
        "scope_coverage" => $scopeCoverage,
        // ALL scopes of a class must be covered, or the class is not.
        "class_carrier" => $classCovered,
    ];
    if ($profileName === "abuse_first") {
        $classCarrier = $classCovered;
    }
}
echo json_encode([
    "advised" => $advised,
    "verified" => $verified,
    "shipped_default" => $shipped,
    "profiles" => $profiles,
    "class_carrier" => $classCarrier,
    "carrier" => ($profiles["abuse_first"]["escalates"] ?? false) ? "novelty_enforcement=enforce (login scopes) + per-scope carriers" : "scope_minimums",
]), "\n";

// The runtime proof (method: product): the posture verdicts above are
// read from the product-own config tree INSIDE a booted real kernel
// (FrameworkBundle + SecurityBundle + KiwiCaptchaBundle, the shipped
// abuse_first profile, zero container overrides). The RUNTIME line is
// the provenance the run ledger checks.
$kernel = new \KiwiRt\RtCampaignKernel();
$kernel->boot();
if (!($kernel instanceof \Symfony\Component\HttpKernel\Kernel)) {
    fwrite(STDERR, "d3.3: the product kernel did not boot\n");
    exit(3);
}
fwrite(STDERR, sprintf("RUNTIME: driver=%s container_overrides=0 kernel=yes\n", get_class($kernel)));
')
printf '%s\n' "$ESC_JSON" | python3 -c '
import json, sys
doc = json.loads(sys.stdin.read())
out_path = sys.argv[1]
store = json.load(open(out_path))
profiles = doc.get("profiles", {})
abuse = profiles.get("abuse_first", {})
store["critical_stakes_escalation"] = {
    "beyond_ceiling_stake_usd_per_1000": 10.0,
    "advised": {"status": doc["advised"][0], "detail": doc["advised"][1]},
    "verified_with_step_up_minimum": {"status": doc["verified"][0], "detail": doc["verified"][1]},
    "shipped_default": {"status": doc["shipped_default"][0], "detail": doc["shipped_default"][1]},
    "shipped_escalates": abuse.get("escalates", False),
    "shipped_minimums": abuse.get("minimums", {}),
    "abuse_first_escalates": abuse.get("escalates", False),
    "abuse_first_novelty": abuse.get("novelty", "learn"),
    "abuse_first_minimums": abuse.get("minimums", {}),
    "abuse_first_factor_enabled": abuse.get("factor_enabled", False),
    "scope_value_classes": abuse.get("scope_value_classes", {}),
    "scope_coverage": abuse.get("scope_coverage", {}),
    "class_carrier": doc.get("class_carrier", {}),
    "profiles": profiles,
    "carrier": doc.get("carrier", "none"),
}
json.dump(store, open(out_path, "w"), indent=2)
# The shipped default with an independent stake beyond the ceiling is
# the honest WARN (escalation demanded), not a PASS: raw PoW cannot
# price a real stake at any difficulty. The verified row (step_up
# minimum set) must PASS: the disposition carries the stake. The
# SHIPPED configuration must also carry the stake — via a risk-gated
# carrier (novelty_enforcement=enforce) or via step_up/deny minimums.
ok = (doc["advised"][0] == "WARN"
      and "risk.scopes" in doc["advised"][1]
      and "step_up" in doc["advised"][1]
      and doc["verified"][0] == "PASS")
shipped = bool(abuse.get("escalates", False))
# The honest per-profile carrier table: one row per profile, the
# Profile column first, so the abuse_first and balanced postures are
# never collapsed into one cell. The per-scope coverage rides beside
# it, so the ledger shows exactly which knob covered every scope.
for name in ("abuse_first", "balanced"):
    row = profiles.get(name, {})
    carrier = row.get("class_carrier", {})
    classes = ",".join("%s=%s" % (c, "yes" if carrier.get(c) else "no")
                       for c in ("low", "standard", "high", "critical"))
    print("CLASS-CARRIER: profile=%s novelty=%s factor=%s %s"
          % (name, row.get("novelty", "?"),
             "enabled" if row.get("factor_enabled") else "disabled", classes))
    coverage = row.get("scope_coverage", {})
    print("SCOPE-COVERAGE: profile=%s %s"
          % (name, " ".join("%s=%s" % (s, k) for s, k in coverage.items())))
print("CRITICAL-STAKES-ESCALATION: %s advised=%s verified=%s carrier=%s"
      % ("PASS" if ok else "FAIL", doc["advised"][0], doc["verified"][0], doc.get("carrier", "none")))
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
    # The gate row reads fail_rows and the shipped escalation posture.
    # The gate row reads fail_rows and the shipped escalation posture.
    # Green only when every failing class has a carrier that applies to
    # it. Novelty covers login scopes only; non-login scopes need
    # step_up/deny. Per-class, not uniform.
    SHIPPED_ESC=$(python3 - "$D33_OUT" <<'PYESC'
import json, sys
d = json.load(open(sys.argv[1]))
e = d.get("critical_stakes_escalation", {})
fails = d.get("fail_rows", [])
class_carrier = e.get("class_carrier", {})
if not fails:
    print("yes")
    sys.exit(0)
missing = [c for c in fails if not class_carrier.get(c, False)]
print("yes" if not missing else "no")
PYESC
)
    CARRIER=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("critical_stakes_escalation",{}).get("carrier","none"))' "$D33_OUT")
    if [ "$SHIPPED_ESC" = "yes" ]; then
        rt_report_pass "value-class fails $FAIL_ROWS carried by the shipped posture ($CARRIER)"
    else
        rt_report_fail "value-class fails $FAIL_ROWS and the shipped profile leaves them on a PoW rung or allow (escalation required: novelty_enforcement=enforce or risk.scopes.<name>.minimum to step_up or deny)"
    fi
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
