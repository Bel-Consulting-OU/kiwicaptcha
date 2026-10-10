#!/bin/sh
# lint-campaigns.sh — the P3 gate: campaign drivers must not implement
# product seams. A campaign that implements the store interface or
# writes marks outside the marks-stage campaigns is measuring a
# fixture, not the product.
#
# Forbidden:
#   implements PrincipalNetworkTagStoreInterface — a fake store
#   writeMark outside d32/d34/d39/d315          — faking deny points
#
# Allowed (the product's own API or campaign setup):
#   new AdaptiveRiskEngine, registerTargetFailure, recordPrincipalNetworkTag
#   writeMark in the marks-stage campaigns (d32/d34/d39/d315)
set -u

RT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
FAIL=0

hits=$(grep -rn 'implements PrincipalNetworkTagStoreInterface' "$RT_DIR/campaigns" --include='*.php' 2>/dev/null | grep -v 'lint-campaigns' || true)
if [ -n "$hits" ]; then
    echo "lint-campaigns: FORBIDDEN fake store implementation:"
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
