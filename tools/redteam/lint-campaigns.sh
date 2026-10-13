#!/bin/sh
# lint-campaigns.sh — the P3 gate: campaign drivers must not implement
# product seams. A campaign that implements a store/marks interface or
# constructs the product engine by hand is measuring a fixture, not
# the product.
#
# Forbidden (the driver-side seams a fixture driver reaches for, every
# spelling the audits caught):
#   new AdaptiveRiskEngine — a hand-built engine, in any of these
#     spellings: bare, fully qualified with a leading backslash
#     (new \KiwiCaptcha\Risk\AdaptiveRiskEngine), any interleaved
#     namespace, and any letter case
#   new RedisPrincipalNetworkTagStore — a hand-built store, same
#     spellings
#   recordPrincipalNetworkTag / ->recordprincipalnetworktag —
#     driver-written history, in any letter case
#   registerTargetFailure / ->registertargetfailure — driver-written
#     targets, in any letter case
#   implements KiwiCaptcha\Risk\*Interface — a fake seam
#   implements *MarksReader|*TagStore|*StateStore*Interface — a fake
#     seam, qualified or not
#   any implements clause (comma lists and continuation lines
#     included) naming a token that ends in Interface and is either
#     the product's own KiwiCaptcha namespace or an unqualified name
#     outside the harness allowlist below — a fake seam, including
#     the spellings a one-line grep misses
#   implements <alias> where the file itself declares
#     `use ...Interface as <alias>;` — the aliased interface import
#   new class implements ... (the paren-less anonymous shim) naming a
#     seam token — the anonymous shim; class(...)... implements too
#
# Allowed (the product's own API through the running product):
#   reading product state through the booted container (measurement),
#   writeMark in the marks-stage campaigns (d32/d34/d39/d315),
#   the harness-local interface implementations in rt.kernel.php and
#     d37.driver.php: Symfony's UserProviderInterface and
#     CompilerPassInterface doubles and the fully qualified
#     \Predis\* and \BelConsulting\KiwiCaptchaBundle\* interfaces,
#     which carry a non-product namespace (the unqualified allowlist
#     below is deliberately two names, not a blanket pass).
#
# Usage: lint-campaigns.sh [DIR] — scans DIR (default: campaigns/).
# The vendored third-party trees (any /vendor/ path) are not campaign
# driver code and are not scanned by the implements-clause pass.
set -u

RT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SCAN_DIR=${1:-$RT_DIR/campaigns}
FAIL=0

# Pass 1: the explicit line patterns (the originals, plus the fully
# qualified and paren-less-anonymous spellings).
FORBID='new AdaptiveRiskEngine|new RedisPrincipalNetworkTagStore|recordPrincipalNetworkTag|registerTargetFailure|implements \\?KiwiCaptcha\\Risk\\[A-Za-z\\]*Interface|implements [A-Za-z0-9_\\]*(MarksReader|TagStore|StateStore)Interface|class \([^)]*\) implements|new \\?[A-Za-z0-9_\\]*AdaptiveRiskEngine|new \\?[A-Za-z0-9_\\]*RedisPrincipalNetworkTagStore|new class[^;{]*implements[[:space:]]*(\\?KiwiCaptcha\\Risk\\|[A-Za-z0-9_]*(MarksReader|TagStore|StateStore)Interface)'

hits=$(grep -rnE "$FORBID" "$SCAN_DIR" --include='*.php' 2>/dev/null | grep -v 'lint-campaigns' || true)
if [ -n "$hits" ]; then
    echo "lint-campaigns: FORBIDDEN product-seam implementation:"
    echo "$hits"
    FAIL=1
fi

# Pass 2: the case-insensitive constructor and method-call shapes. A
# driver that renames the seam only by letter case (new
# adaptiveRiskEngine, ->RegisterTargetFailure) is the same fixture.
FORBID_ICASE='new +[a-z0-9_\\]*adaptiveriskengine|new +[a-z0-9_\\]*redisprincipalnetworktagstore|->[[:space:]]*recordprincipalnetworktag|->[[:space:]]*registertargetfailure'

hits=$(grep -rniE "$FORBID_ICASE" "$SCAN_DIR" --include='*.php' 2>/dev/null | grep -v 'lint-campaigns' || true)
if [ -n "$hits" ]; then
    echo "lint-campaigns: FORBIDDEN product-seam spelling (case-insensitive):"
    echo "$hits"
    FAIL=1
fi

# Pass 3: the implements-clause scanner. Line-based patterns miss the
# spellings a driver reaches for: comma lists (implements A, B), the
# seam token pushed to a continuation line, a paren-less anonymous
# class whose clause spans lines, and an interface imported under an
# alias (use ...Interface as X; + implements X). This pass extracts
# each clause (the implements keyword through the statement's brace or
# semicolon, at most three continuation lines), splits it into tokens,
# and flags:
#   - any token equal to one of the file's own `use ...Interface as`
#     aliases (the aliased import is implemented),
#   - any Interface-suffixed token in the product's KiwiCaptcha
#     namespace (BelConsulting\KiwiCaptchaBundle\* is the bundle, not
#     the product core, and stays legal),
#   - any UNQUALIFIED Interface-suffixed token outside the allowlist
#     (the harness's Symfony doubles), so a seam imported bare has no
#     spelling left.
IMPL_FILES=""
for f in $(find "$SCAN_DIR" -name '*.php' -type f 2>/dev/null | grep -v '/vendor/'); do
    IMPL_FILES="$IMPL_FILES $f"
done
if [ -n "$IMPL_FILES" ]; then
    # shellcheck disable=SC2086
    if ! awk '
        BEGIN { hits = 0 }
        function evaluate(c,   i, n, toks, j, t) {
            n = split(c, toks, /[[:space:],()]+/)
            for (i = 1; i <= n; i++) {
                t = toks[i]
                if (t == "") continue
                for (j = 1; j <= na; j++) {
                    if (t == aliasname[j]) {
                        printf "%s:%d: FORBIDDEN aliased interface import implemented: implements %s (the file declares use ...Interface as %s;)\n", FILENAME, cline, t, t
                        hits++
                    }
                }
                if (t !~ /Interface$/) continue
                if (t ~ /(^|\\)KiwiCaptcha\\/) {
                    printf "%s:%d: FORBIDDEN product-seam interface in implements clause: %s\n", FILENAME, cline, t
                    hits++
                } else if (t !~ /\\/ && t != "UserProviderInterface" && t != "CompilerPassInterface") {
                    printf "%s:%d: FORBIDDEN unqualified interface in implements clause: %s (not in the harness allowlist)\n", FILENAME, cline, t
                    hits++
                }
            }
        }
        FNR == 1 { na = 0; clause = ""; active = 0 }
        {
            if ($0 ~ /^[[:space:]]*use[[:space:]]+[A-Za-z0-9_\\]+Interface[[:space:]]+as[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;/) {
                t = $0
                sub(/^.*[[:space:]]as[[:space:]]/, "", t)
                sub(/[[:space:]]*;.*$/, "", t)
                aliasname[++na] = t
            }
            if (!active && $0 ~ /(^|[^A-Za-z0-9_$])implements([^A-Za-z0-9_$]|$)/) {
                clause = $0
                sub(/^.*implements/, "", clause)
                active = 1
                cline = FNR
            } else if (active) {
                clause = clause " " $0
            }
            if (active) {
                b = index(clause, "{")
                s = index(clause, ";")
                end = 0
                if (b > 0 && (s == 0 || b < s)) end = b
                else if (s > 0) end = s
                if (end > 0) {
                    evaluate(substr(clause, 1, end - 1))
                    clause = ""
                    active = 0
                } else if (FNR - cline >= 3) {
                    evaluate(clause)
                    clause = ""
                    active = 0
                }
            }
        }
        END { if (hits > 0) exit 1 }
    ' $IMPL_FILES; then
        FAIL=1
    fi
fi

# writeMark outside the marks-stage campaigns.
grep -rn 'writeMark' "$SCAN_DIR" --include='*.php' 2>/dev/null | grep -v 'lint-campaigns' | while IFS= read -r line; do
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
