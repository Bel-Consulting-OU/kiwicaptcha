#!/usr/bin/env bash
#
# tools/ci/protocol-manifest-check.sh - ExecutionChallengeV1 protocol
# manifest drift gate (KC-09/KC-16/KC-17 register coherence).
#
# The wire register of the ExecutionChallengeV1 dimension is defined by
# protocol/execution-v1.json (schema 'kiwicaptcha.execution-v1/1'), the
# single canonical table: the blob format version, the maximum
# execution version, the opcode name-to-number map (0..opcode_count-1)
# and the per-opcode trace-name list. Four implementations consume that
# register - the PHP core, the Rust core, the interpreter asset and the
# manifest - and every drift between any pair is a fleet-visible
# incoherence (a mixed-fleet decode fence, an opcode-shape mismatch or
# a digest divergence), so this lane fails on ANY pairwise difference.
#
# The PHP and Rust sides are read straight from their constant
# declarations, never from a handwritten list: a handwritten list could
# itself drift and would silently mask a source change. The interpreter
# asset declares no named opcode constants (its opcode dispatch is a
# numeric switch), so the interpreter check is deliberately limited to
# the two registers it does declare: OP_COUNT and the decode version
# gate string (the file's per-version maximum). The manifest itself is
# validated for internal coherence (sequential 0..N-1 opcode numbers,
# opcode_count == the map size == the trace-name list size) before any
# cross-language comparison runs.
#
# Pure POSIX tooling (bash, grep, sed, awk): no network, no composer,
# no cargo, no PHP required - the lane runs anywhere a checkout exists.
#
# Usage: bash tools/ci/protocol-manifest-check.sh
# Exit status: 0 when every register agrees, 1 on the first drift.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

MANIFEST="$ROOT/protocol/execution-v1.json"
PHP_SRC="$ROOT/packages/kiwicaptcha-php/src/ExecutionChallengeGenerator.php"
RUST_SRC="$ROOT/packages/kiwicaptcha/src/execution.rs"
JS_SRC="$ROOT/packages/kiwicaptcha/resources/execution-interpreter.js"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

for f in "$MANIFEST" "$PHP_SRC" "$RUST_SRC" "$JS_SRC"; do
    [ -f "$f" ] || fail "missing source file: $f"
done

# manifest_field <key>: the numeric value of a top-level manifest field.
manifest_field() {
    sed -n -E "s/^  \"$1\": ([0-9]+),?$/\1/p" "$MANIFEST" | head -n 1
}

FORMAT_VERSION=$(manifest_field format_version)
MAX_VERSION=$(manifest_field max_execution_version)
OPCODE_COUNT=$(manifest_field opcode_count)
[ -n "$FORMAT_VERSION" ] || fail "manifest carries no format_version"
[ -n "$MAX_VERSION" ] || fail "manifest carries no max_execution_version"
[ -n "$OPCODE_COUNT" ] || fail "manifest carries no opcode_count"

# manifest_opcodes: "NAME NUM" lines of the opcodes object, in file order.
# manifest_trace_names: the trace-name lines of the list.
MANIFEST_OPCODES=()
while IFS= read -r line; do
    [ -n "$line" ] && MANIFEST_OPCODES+=("$line")
done < <(sed -n -E 's/^    "([A-Z][A-Z0-9_]*)": ([0-9]+),?$/\1 \2/p' "$MANIFEST")
MANIFEST_TRACE_NAMES=()
while IFS= read -r line; do
    [ -n "$line" ] && MANIFEST_TRACE_NAMES+=("$line")
done < <(sed -n -E 's/^    "([a-z][a-z0-9]*)",?$/\1/p' "$MANIFEST")

# The manifest must be internally coherent before anything is compared
# against it: the opcode numbers are exactly 0..N-1 in order, and the
# map size, opcode_count and the trace-name list size all agree.
[ "${#MANIFEST_OPCODES[@]}" -eq "$OPCODE_COUNT" ] \
    || fail "manifest opcode map has ${#MANIFEST_OPCODES[@]} entries, opcode_count says $OPCODE_COUNT"
[ "${#MANIFEST_TRACE_NAMES[@]}" -eq "$OPCODE_COUNT" ] \
    || fail "manifest trace_names has ${#MANIFEST_TRACE_NAMES[@]} entries, opcode_count says $OPCODE_COUNT"
idx=0
for entry in "${MANIFEST_OPCODES[@]}"; do
    name=${entry%% *}
    num=${entry##* }
    [ "$num" = "$idx" ] \
        || fail "manifest opcode $name is numbered $num, expected $idx (sequential 0..N-1)"
    idx=$((idx + 1))
done
pass "manifest is internally coherent ($OPCODE_COUNT opcodes, format $FORMAT_VERSION, max execution version $MAX_VERSION)"

# normalized_trace_list <file> <sed-range>: the trace names of one
# source file as one space-joined string, read from the source's own
# array literal so the list can never drift from the declarations
# around it. Both quote styles are accepted (PHP single, the others
# double) and every other token is ignored.
normalized_trace_list() {
    local file=$1 pattern=$2
    sed -n -E "$pattern" "$file" \
        | grep -oE "['\"][a-z][a-z0-9]*['\"]" | tr -d "'\"" | paste -sd' ' -
}

PHP_TRACES=$(normalized_trace_list "$PHP_SRC" \
    "/private const TRACE_NAMES = \[/,/^    \];/p")
RUST_TRACES=$(normalized_trace_list "$RUST_SRC" \
    "/const TRACE_NAMES: \[&str; OP_COUNT as usize\] = \[/,/^];/p")
JS_TRACES=$(normalized_trace_list "$JS_SRC" "/var TRACE_NAMES = \[/,/\];/p")
MANIFEST_TRACES=$(normalized_trace_list "$MANIFEST" '/^  "trace_names": \[/,/^  \]/p')

# php_const <name>: the numeric value of a PHP OP_*/register constant.
php_const() {
    sed -n -E "s/^    public const $1 = ([0-9]+);$/\1/p" "$PHP_SRC" | head -n 1
}

# rust_const <name>: the numeric value of a Rust OP_*/register constant.
rust_const() {
    sed -n -E "s/^pub const $1: u8 = ([0-9]+);$/\1/p" "$RUST_SRC" | head -n 1
}

# Cross-language register comparison: the manifest is the canonical
# table, so the value read from each source must equal the manifest
# value exactly.
[ "$(php_const FORMAT_VERSION)" = "$FORMAT_VERSION" ] \
    || fail "PHP FORMAT_VERSION ($(php_const FORMAT_VERSION)) != manifest ($FORMAT_VERSION)"
[ "$(rust_const FORMAT_VERSION)" = "$FORMAT_VERSION" ] \
    || fail "Rust FORMAT_VERSION ($(rust_const FORMAT_VERSION)) != manifest ($FORMAT_VERSION)"
[ "$(php_const MAX_EXECUTION_VERSION)" = "$MAX_VERSION" ] \
    || fail "PHP MAX_EXECUTION_VERSION ($(php_const MAX_EXECUTION_VERSION)) != manifest ($MAX_VERSION)"
[ "$(rust_const MAX_EXECUTION_VERSION)" = "$MAX_VERSION" ] \
    || fail "Rust MAX_EXECUTION_VERSION ($(rust_const MAX_EXECUTION_VERSION)) != manifest ($MAX_VERSION)"
[ "$(php_const OP_COUNT)" = "$OPCODE_COUNT" ] \
    || fail "PHP OP_COUNT ($(php_const OP_COUNT)) != manifest ($OPCODE_COUNT)"
[ "$(rust_const OP_COUNT)" = "$OPCODE_COUNT" ] \
    || fail "Rust OP_COUNT ($(rust_const OP_COUNT)) != manifest ($OPCODE_COUNT)"
pass "format_version, max_execution_version and opcode_count agree across the manifest, PHP and Rust"

for entry in "${MANIFEST_OPCODES[@]}"; do
    name=${entry%% *}
    num=${entry##* }
    [ "$(php_const "OP_$name")" = "$num" ] \
        || fail "PHP OP_$name ($(php_const "OP_$name")) != manifest ($num)"
    [ "$(rust_const "OP_$name")" = "$num" ] \
        || fail "Rust OP_$name ($(rust_const "OP_$name")) != manifest ($num)"
done
pass "all $OPCODE_COUNT opcode numbers agree across the manifest, PHP and Rust"

[ "$PHP_TRACES" = "$MANIFEST_TRACES" ] \
    || fail "PHP TRACE_NAMES drift vs the manifest"
[ "$RUST_TRACES" = "$MANIFEST_TRACES" ] \
    || fail "Rust TRACE_NAMES drift vs the manifest"
[ "$JS_TRACES" = "$MANIFEST_TRACES" ] \
    || fail "interpreter TRACE_NAMES drift vs the manifest"
pass "trace-name lists agree across the manifest, PHP, Rust and the interpreter"

# The interpreter declares no per-opcode constants, so its register
# check is the two named declarations it does carry: OP_COUNT and the
# decode version gate string (`opVersion < 1 || opVersion > N`, the
# file's per-version maximum).
JS_COUNT=$(sed -n -E 's/^ var OP_COUNT = ([0-9]+);$/\1/p' "$JS_SRC" | head -n 1)
[ "$JS_COUNT" = "$OPCODE_COUNT" ] \
    || fail "interpreter OP_COUNT ($JS_COUNT) != manifest ($OPCODE_COUNT)"
JS_GATE=$(sed -n -E 's/.*opVersion < 1 \|\| opVersion > ([0-9]+)\) return null;.*/\1/p' "$JS_SRC" | head -n 1)
[ "$JS_GATE" = "$MAX_VERSION" ] \
    || fail "interpreter version gate allows version $JS_GATE, manifest max_execution_version is $MAX_VERSION"
pass "interpreter OP_COUNT and the decode version gate agree with the manifest"

echo "execution-v1 protocol manifest: all registers coherent"
