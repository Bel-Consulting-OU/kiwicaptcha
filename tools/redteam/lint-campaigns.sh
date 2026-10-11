#!/bin/sh
# lint-campaigns.sh — the P3 gate: campaign drivers must not implement
# product seams. A campaign that implements a store/marks interface or
# constructs the product engine by hand is measuring a fixture, not
# the product.
#
# Forbidden (the driver-side seams a fixture driver reaches for):
#   new AdaptiveRiskEngine                       — a hand-built engine
#   new RedisPrincipalNetworkTagStore            — a hand-built store
#   recordPrincipalNetworkTag                    — driver-written history
#   registerTargetFailure                        — driver-written targets
#   implements KiwiCaptcha\Risk\*Interface       — a fake seam
#   implements *MarksReader|*TagStore|*StateStore Interface — a fake seam
#   class (...) implements ...                   — the anonymous shim
#
# Allowed (the product's own API through the running product):
#   reading product state through the booted container (measurement),
#   writeMark in the marks-stage campaigns (d32/d34/d39/d315).
set -u

RT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
FAIL=0

FORBID='new AdaptiveRiskEngine|new RedisPrincipalNetworkTagStore|recordPrincipalNetworkTag|registerTargetFailure|implements \\?KiwiCaptcha\\Risk\\[A-Za-z\\]*Interface|implements [A-Za-z]*(MarksReader|TagStore|StateStore)Interface|class \([^)]*\) implements'

hits=$(grep -rnE "$FORBID" "$RT_DIR/campaigns" --include='*.php' 2>/dev/null | grep -v 'lint-campaigns' || true)
if [ -n "$hits" ]; then
    echo "lint-campaigns: FORBIDDEN product-seam implementation:"
    echo "$hits"
    FAIL=1
fi

# writeMark outside the marks-stage campaigns.
grep -rn 'writeMark' "$RT_DIR/campaigns" --include='*.php' 2>/dev/null | grep -v 'lint-campaigns' | while IFS= read -r line; do
    case "$line" in
        *d32.driver.php*|*d34.driver.php*|*d39.driver.php*|*d315.driver.php*) continue ;;
    esac
    echo "lint-campaigns: FORBIDDEN writeMark outside marks-stage campaigns: $line"
    touch "$RT_DIR/.lint-fail"
done

if [ -f "$RT_DIR/.lint-fail" ]; then
    rm -f "$RT_DIR/.lint-fail"
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    echo "lint-campaigns: FAIL"
    exit 1
fi

echo "lint-campaigns: OK — no product-seam implementations in campaign code"
exit 0
