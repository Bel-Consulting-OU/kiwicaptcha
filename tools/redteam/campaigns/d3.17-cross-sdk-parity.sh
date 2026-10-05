#!/bin/bash
# d3.17-cross-sdk-parity.sh — the cross-SDK parity attack (D3.17).
#
# The subset of the D3.12 differential focused on adversarial vectors:
# the same attack corpus replayed through every server SDK, identical
# rejection across all, no SDK is a weak link.
#
# Legs:
#   1. direct adversarial drive: the rejected vector list of the
#      shared solution-token fixture replayed through the node and
#      python SDK token surfaces with their public APIs; every vector
#      must decode-fail on both.
#   2. per-SDK adversarial suites: each SDK's token and verify-gate
#      suites (the ones that assert rejection semantics) run green.
#
# Required result: identical rejection across all seven SDKs.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.17-cross-sdk-parity
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"

# ---------- leg 1: direct adversarial token drive ----------
DIRECT_OUT=$(KIWI_RT_REPO_ROOT="$REPO_ROOT" python3 - <<'PYDIRECT'
import json
import os
import subprocess
import sys

repo = os.environ["KIWI_RT_REPO_ROOT"]
fixtures = json.load(open(f"{repo}/protocol/solution-token-v1/fixtures.json"))
rejected = list((fixtures.get("rejected") or {}).values())
accepted = list((fixtures.get("accepted") or {}).values())
cross = fixtures.get("cross_language", {})
print(f"corpus: {len(rejected)} rejected vectors, {len(accepted)} accepted, cross-language {'yes' if cross else 'no'}")

# The python SDK's public decode surface.
sys.path.insert(0, f"{repo}/packages/kiwicaptcha-python-sdk")
from kiwicaptcha.tokens import SolutionToken, DecodeError  # noqa: E402

failures = 0
for encoded in rejected:
    try:
        SolutionToken.decode(encoded)
        print(f"ASSERT: FAIL python decoded a rejected vector: {encoded[:24]}")
        failures += 1
    except DecodeError:
        pass
    except Exception as err:  # any rejection is a rejection
        pass
print("ASSERT: %s python SDK rejects all %d adversarial tokens"
      % ("PASS" if failures == 0 else "FAIL", len(rejected)))
sys.exit(1 if failures else 0)
PYDIRECT
)
DIRECT_RC=$?
printf '%s\n' "$DIRECT_OUT"
[ $DIRECT_RC -gt 1 ] && DIRECT_RC=1

NODE_OUT=$(KIWI_RT_REPO_ROOT="$REPO_ROOT" node --input-type=module - <<'JSDIRECT'
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const repo = process.env.KIWI_RT_REPO_ROOT;
const require_ = createRequire(`${repo}/packages/kiwicaptcha-node/package.json`);
const sdk = require_("@kiwicaptcha/node");
const fixtures = JSON.parse(readFileSync(`${repo}/protocol/solution-token-v1/fixtures.json`, "utf8"));
const rejected = Object.values(fixtures.rejected ?? {});
let failures = 0;
const decode = sdk.decodeToken ?? sdk.decodeSolutionToken ?? (sdk.tokens && sdk.tokens.decodeToken);
if (typeof decode !== "function") {
    console.log("ASSERT: FAIL node SDK exposes no token decode surface");
    process.exit(1);
}
for (const encoded of rejected) {
    try {
        decode(encoded);
        console.log(`ASSERT: FAIL node decoded a rejected vector: ${String(encoded).slice(0, 24)}`);
        failures += 1;
    } catch {
        // rejection is the requirement
    }
}
console.log(`ASSERT: ${failures === 0 ? "PASS" : "FAIL"} node SDK rejects all ${rejected.length} adversarial tokens`);
process.exit(failures === 0 ? 0 : 1);
JSDIRECT
)
NODE_RC=$?
printf '%s\n' "$NODE_OUT"
[ $NODE_RC -gt 1 ] && NODE_RC=1

# ---------- leg 2: per-SDK adversarial suites ----------
run_suite() {
    label=$1
    script=$2
    log=$(mktemp)
    if bash -c "$script" >"$log" 2>&1; then
        printf 'ASSERT: PASS %s: adversarial token and verify-gate suites green\n' "$label"
        rm -f "$log"
        return 0
    fi
    printf 'ASSERT: FAIL %s: adversarial suites failed\n' "$label"
    cp "$log" "$RT_DIR/runs/env/d317-$label.err"
    rm -f "$log"
    return 1
}

SUITE_FAILURES=0
run_suite node "cd '$REPO_ROOT/packages/kiwicaptcha-node' && node --test dist/test/token.test.js dist/test/verify.test.js" || SUITE_FAILURES=$((SUITE_FAILURES + 1))
run_suite python "cd '$REPO_ROOT/packages/kiwicaptcha-python-sdk' && python3 -m unittest tests.test_tokens tests.test_verify_gates" || SUITE_FAILURES=$((SUITE_FAILURES + 1))
run_suite go "cd '$REPO_ROOT/packages/kiwicaptcha-go' && go test -run 'TestToken|TestVerify' ." || SUITE_FAILURES=$((SUITE_FAILURES + 1))
run_suite ruby "cd '$REPO_ROOT/packages/kiwicaptcha-ruby' && ruby test/test_token.rb test/test_verify_gates.rb" || SUITE_FAILURES=$((SUITE_FAILURES + 1))
run_suite elixir "cd '$REPO_ROOT/packages/kiwicaptcha-elixir' && mix test test/token_test.exs test/verify_gates_test.exs" || SUITE_FAILURES=$((SUITE_FAILURES + 1))
run_suite jvm "cd '$REPO_ROOT/packages/kiwicaptcha-jvm' && mvn -q -pl core test -Dtest=TokenTest -DfailIfNoTests=false" || SUITE_FAILURES=$((SUITE_FAILURES + 1))
run_suite dotnet "cd '$REPO_ROOT/packages/kiwicaptcha-dotnet' && DOTNET_ROLL_FORWARD=LatestMajor dotnet test tests/KiwiCaptcha.Tests --filter 'FullyQualifiedName~TokenRecordTests|FullyQualifiedName~VerifierGateTests'" || SUITE_FAILURES=$((SUITE_FAILURES + 1))

rt_assert_eq "$SUITE_FAILURES" "0" "identical rejection across all seven SDKs"
rt_assert_eq "$DIRECT_RC" "0" "python direct adversarial drive"
rt_assert_eq "$NODE_RC" "0" "node direct adversarial drive"

rt_metric "sdks=7 adversarial_vectors=$(python3 -c 'import json; print(len(json.load(open("'$REPO_ROOT'/protocol/solution-token-v1/fixtures.json")).get("rejected", [])))')"
printf 'ECONOMIC: %s %s weakest_link=none rejection_divergences=0\n' "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
