#!/usr/bin/env bash
# verify-gateway-parity.sh — the integration gateways' byte-parity gate.
#
# integrations-platforms/kiwi-verify.php exists in four copies (the
# root one plus the caddy, nginx and traefik platform variants); the
# copies are one script, not four, and a drift between them means one
# platform verifies with different rules than the others. This gate
# cmp-s every variant against the root copy and exits non-zero on the
# first differing byte, printing the diff command the fixer runs.
#
# Pure POSIX tooling: no network, no PHP, no composer — the lane runs
# anywhere a checkout exists.

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)

CANONICAL="$ROOT/integrations-platforms/kiwi-verify.php"
VARIANTS=(
    "$ROOT/integrations-platforms/caddy/kiwi-verify.php"
    "$ROOT/integrations-platforms/nginx/kiwi-verify.php"
    "$ROOT/integrations-platforms/traefik/kiwi-verify.php"
)

if [ ! -f "$CANONICAL" ]; then
    echo "verify-gateway-parity: the canonical gateway is missing: $CANONICAL" >&2
    exit 1
fi

RESULT=0
for variant in "${VARIANTS[@]}"; do
    if [ ! -f "$variant" ]; then
        echo "verify-gateway-parity: a gateway copy is missing: $variant" >&2
        RESULT=1
        continue
    fi
    if ! cmp -s "$CANONICAL" "$variant"; then
        echo "verify-gateway-parity: DRIFT between the canonical gateway and $variant" >&2
        echo "  inspect with: diff $CANONICAL $variant" >&2
        RESULT=1
    fi
done

if [ "$RESULT" -eq 0 ]; then
    echo "verify-gateway-parity: all gateway copies byte-identical to the canonical"
fi
exit $RESULT
