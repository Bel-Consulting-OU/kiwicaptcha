#!/usr/bin/env bash
#
# tools/ci/limits-parity-check.sh - the shared security/solver limits
# register gate.
#
# protocol/limits.json (schema 'kiwicaptcha.limits/1') is the single
# authoritative table of the policy ceilings and floors that PHP, Rust
# and the browser must enforce identically. This lane reads each
# implementation's own constant declarations (never a handwritten list,
# which could itself drift) and fails on ANY pairwise difference with
# the manifest, exactly like tools/ci/protocol-manifest-check.sh does
# for the ExecutionChallengeV1 opcode register.
#
# Why this exists: the solver-hash ceiling (5M vs 20M), the secret and
# execution-key floors (16 vs 32) and the browser challenge-contract
# bounds all live in more than one language. Without one machine-checked
# register, each language can stay internally consistent and green while
# the browser/server pair disagrees - a solve the widget mints that a
# server then refuses. See the register for the full field list.
#
# Pure POSIX tooling (bash, grep, sed, awk): no network, no composer,
# no cargo, no PHP required - the lane runs anywhere a checkout exists.
#
# Usage: bash tools/ci/limits-parity-check.sh
# Exit status: 0 when every register agrees, 1 on the first drift.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

MANIFEST="$ROOT/protocol/limits.json"

RUST_CHALLENGE="$ROOT/packages/kiwicaptcha/src/challenge.rs"
RUST_TOKEN="$ROOT/packages/kiwicaptcha/src/token.rs"
RUST_KEYS="$ROOT/packages/kiwicaptcha/src/keys.rs"
RUST_EXECUTION="$ROOT/packages/kiwicaptcha/src/execution.rs"
RUST_WASM="$ROOT/packages/kiwicaptcha-wasm/src/lib.rs"

PHP_CONFIG="$ROOT/packages/kiwicaptcha-php/src/Config.php"
PHP_TOKEN="$ROOT/packages/kiwicaptcha-php/src/SolutionToken.php"
PHP_VERIFIER="$ROOT/packages/kiwicaptcha-php/src/Verifier.php"
PHP_EXECUTION="$ROOT/packages/kiwicaptcha-php/src/ExecutionChallengeGenerator.php"

DRIVER="$ROOT/packages/kiwicaptcha-wasm/assets/widget-driver.js"
RISK="$ROOT/packages/kiwicaptcha-wasm/assets/widget-risk.js"
WORKER="$ROOT/packages/kiwicaptcha-wasm/assets/kiwi-worker.js"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

for f in "$MANIFEST" "$RUST_CHALLENGE" "$RUST_TOKEN" "$RUST_KEYS" "$RUST_EXECUTION" \
    "$RUST_WASM" "$PHP_CONFIG" "$PHP_TOKEN" "$PHP_VERIFIER" "$PHP_EXECUTION" \
    "$DRIVER" "$RISK" "$WORKER"; do
    [ -f "$f" ] || fail "missing source file: $f"
done

# manifest_field <key>: the numeric value of a top-level manifest field.
manifest_field() {
    sed -n -E "s/^  \"$1\": ([0-9]+),?$/\1/p" "$MANIFEST" | head -n 1
}

# manifest_string_field <key>: the string value of a top-level manifest field.
manifest_string_field() {
    sed -n -E "s/^  \"$1\": \"([^\"]+)\",?$/\1/p" "$MANIFEST" | head -n 1
}

FIELD_COUNT=$(grep -cE '^  "[a-z0-9_]+": ([0-9]+|"[^"]+"),?$' "$MANIFEST" || true)
[ "$FIELD_COUNT" -ge 17 ] || fail "the manifest carries only $FIELD_COUNT limit fields; every register row is required"

# rust_const <file> <name>: the numeric value of a `pub const NAME: T = N;`
# declaration (underscores stripped).
rust_const() {
    sed -n -E "s/^pub const $2: [A-Za-z0-9_]+ = ([0-9_]+);$/\1/p" "$1" | head -n 1 | tr -d '_'
}

# php_const <file> <name>: the numeric value of a `public|private const
# NAME = N;` declaration (underscores stripped).
php_const() {
    sed -n -E "s/^    (public|private) const $2 = ([0-9_]+);$/\2/p" "$1" | head -n 1 | tr -d '_'
}

# js_value <file> <sed-expr>: the first capture of one extraction
# expression, or the empty string when the pattern is absent. The
# patterns below read the browser's own declarations (named constants
# where they exist, the inline challenge-contract bounds otherwise), so
# a browser constant can never drift behind a green lane.
js_value() {
    sed -n -E "$2" "$1" | head -n 1 | tr -d '_'
}

# js_unique_value <file> <grep-pattern> <sed-expr>: every raw occurrence
# of a pattern (the worker asset embeds its own solver source as an
# escaped string, so each declaration appears more than once) must carry
# exactly one value; a split between copies fails closed.
js_unique_value() {
    local unique count
    unique=$(grep -oE "$2" "$1" 2>/dev/null | sed -n -E "$3" | tr -d '_' | sort -u || true)
    count=$(printf '%s' "$unique" | grep -c . || true)
    [ "$count" -ge 1 ] || fail "no occurrence of the pattern in $1"
    [ "$count" = "1" ] \
        || fail "$1 carries more than one value for one register row: $(printf '%s' "$unique" | tr '\n' ' ')"
    printf '%s' "$unique"
}

# assert_eq <label> <expected> <actual>
assert_eq() {
    local label=$1 expected=$2 actual=$3
    [ -n "$actual" ] || fail "$label: could not read the implementation value"
    [ "$actual" = "$expected" ] || fail "$label: implementation says $actual, protocol/limits.json says $expected"
}

# ── The register, read straight from the manifest ──────────────────────
SHA_MAX_TARGET_BITS=$(manifest_field sha_max_target_bits)
SOLVER_MAX_HASHES=$(manifest_field solver_max_hashes)
ARGON2_MAX_TARGET_BITS=$(manifest_field argon2_max_target_bits)
ARGON2_MAX_M_KIB=$(manifest_field argon2_max_m_kib)
ARGON2_MAX_T_ISSUANCE=$(manifest_field argon2_max_t_issuance)
ARGON2_MAX_T_VERIFICATION=$(manifest_field argon2_max_t_verification)
TTL_MAX_SECS=$(manifest_field ttl_max_secs)
RSW_T_MIN=$(manifest_field rsw_t_min)
RSW_T_MAX=$(manifest_field rsw_t_max)
TOKEN_MAX_DURATION_MS=$(manifest_field token_max_duration_ms)
MIN_MASTER_BYTES=$(manifest_field min_master_bytes)
MIN_EXECUTION_KEY_BYTES=$(manifest_field min_execution_key_bytes)
EXECUTION_MAX_VERSION=$(manifest_field execution_max_version)
EXECUTION_MAX_PROGRAM_BASE64=$(manifest_field execution_max_program_base64)
EXECUTION_MAX_OPS=$(manifest_field execution_max_ops)
WORKER_PROTOCOL_VERSION=$(manifest_field worker_protocol_version)
WORKER_PROTOCOL_ID=$(manifest_string_field worker_protocol_id)

for pair in \
    "sha_max_target_bits:$SHA_MAX_TARGET_BITS" \
    "solver_max_hashes:$SOLVER_MAX_HASHES" \
    "argon2_max_target_bits:$ARGON2_MAX_TARGET_BITS" \
    "argon2_max_m_kib:$ARGON2_MAX_M_KIB" \
    "argon2_max_t_issuance:$ARGON2_MAX_T_ISSUANCE" \
    "argon2_max_t_verification:$ARGON2_MAX_T_VERIFICATION" \
    "ttl_max_secs:$TTL_MAX_SECS" \
    "rsw_t_min:$RSW_T_MIN" \
    "rsw_t_max:$RSW_T_MAX" \
    "token_max_duration_ms:$TOKEN_MAX_DURATION_MS" \
    "min_master_bytes:$MIN_MASTER_BYTES" \
    "min_execution_key_bytes:$MIN_EXECUTION_KEY_BYTES" \
    "execution_max_version:$EXECUTION_MAX_VERSION" \
    "execution_max_program_base64:$EXECUTION_MAX_PROGRAM_BASE64" \
    "execution_max_ops:$EXECUTION_MAX_OPS" \
    "worker_protocol_version:$WORKER_PROTOCOL_VERSION"; do
    [ -n "${pair#*:}" ] || fail "manifest field ${pair%%:*} is missing"
done
pass "protocol/limits.json carries all $FIELD_COUNT register rows"

# ── SHA / solver ceilings ──────────────────────────────────────────────
assert_eq "Rust SOLVER_MAX_TARGET_BITS" "$SHA_MAX_TARGET_BITS" \
    "$(rust_const "$RUST_CHALLENGE" SOLVER_MAX_TARGET_BITS)"
assert_eq "PHP Config::MAX_SHA_TARGET_BITS" "$SHA_MAX_TARGET_BITS" \
    "$(php_const "$PHP_CONFIG" MAX_SHA_TARGET_BITS)"
assert_eq "browser SHA target-bit bound" "$SHA_MAX_TARGET_BITS" \
    "$(js_value "$DRIVER" 's/.*targetBits > \(alg === "argon2id" \? 10 : ([0-9]+)\).*/\1/p')"

assert_eq "Rust SOLVER_MAX_HASHES" "$SOLVER_MAX_HASHES" \
    "$(rust_const "$RUST_CHALLENGE" SOLVER_MAX_HASHES)"
assert_eq "PHP SolutionToken::MAX_SOLVER_COUNTER" "$SOLVER_MAX_HASHES" \
    "$(php_const "$PHP_TOKEN" MAX_SOLVER_COUNTER)"
assert_eq "widget-driver MAX_SHA_HASHES" "$SOLVER_MAX_HASHES" \
    "$(js_value "$DRIVER" 's/^  var MAX_SHA_HASHES = ([0-9]+);$/\1/p')"
assert_eq "widget-risk MAX_SHA_HASHES" "$SOLVER_MAX_HASHES" \
    "$(js_value "$RISK" 's/^  var MAX_SHA_HASHES = ([0-9]+);$/\1/p')"
assert_eq "worker solve maxHashes default" "$SOLVER_MAX_HASHES" \
    "$(js_unique_value "$WORKER" 'var maxHashes = \(m\.maxHashes \| 0\) > 0 \? \(m\.maxHashes \| 0\) : [0-9]+;' 's/.*: ([0-9]+);$/\1/p')"
pass "the SHA target-bit ceiling and the solver hash ceiling agree across PHP, Rust, the widget and the worker"

# ── Argon2id ceilings ──────────────────────────────────────────────────
assert_eq "Rust SOLVER_MAX_ARGON2_TARGET_BITS" "$ARGON2_MAX_TARGET_BITS" \
    "$(rust_const "$RUST_CHALLENGE" SOLVER_MAX_ARGON2_TARGET_BITS)"
assert_eq "PHP Config::MAX_ARGON2_TARGET_BITS" "$ARGON2_MAX_TARGET_BITS" \
    "$(php_const "$PHP_CONFIG" MAX_ARGON2_TARGET_BITS)"
assert_eq "browser Argon2id target-bit bound" "$ARGON2_MAX_TARGET_BITS" \
    "$(js_value "$DRIVER" 's/.*targetBits > \(alg === "argon2id" \? ([0-9]+) : 20\).*/\1/p')"

assert_eq "Rust SOLVER_MAX_ARGON2_M_KIB" "$ARGON2_MAX_M_KIB" \
    "$(rust_const "$RUST_CHALLENGE" SOLVER_MAX_ARGON2_M_KIB)"
assert_eq "PHP Verifier::MAX_ARGON_MEMORY_KIB" "$ARGON2_MAX_M_KIB" \
    "$(php_const "$PHP_VERIFIER" MAX_ARGON_MEMORY_KIB)"
assert_eq "browser mKib bound" "$ARGON2_MAX_M_KIB" \
    "$(js_value "$DRIVER" 's/.*mKib > ([0-9]+)\).*/\1/p')"

assert_eq "Rust MAX_ARGON_T (issuance)" "$ARGON2_MAX_T_ISSUANCE" \
    "$(rust_const "$RUST_CHALLENGE" MAX_ARGON_T)"
assert_eq "PHP Config::MAX_ARGON_T" "$ARGON2_MAX_T_ISSUANCE" \
    "$(php_const "$PHP_CONFIG" MAX_ARGON_T)"
assert_eq "browser Argon2id t bound" "$ARGON2_MAX_T_ISSUANCE" \
    "$(js_value "$DRIVER" 's/.*t < 3 \|\| t > ([0-9]+)\).*/\1/p')"

assert_eq "Rust MAX_ARGON_TIME (verification)" "$ARGON2_MAX_T_VERIFICATION" \
    "$(rust_const "$RUST_CHALLENGE" MAX_ARGON_TIME)"
assert_eq "PHP Verifier::MAX_ARGON_TIME" "$ARGON2_MAX_T_VERIFICATION" \
    "$(php_const "$PHP_VERIFIER" MAX_ARGON_TIME)"
pass "the Argon2id target-bit, memory and time ceilings agree across PHP, Rust and the widget"

# ── Lifetime, rsw and token duration ───────────────────────────────────
assert_eq "Rust MAX_TTL_SECS" "$TTL_MAX_SECS" \
    "$(rust_const "$RUST_CHALLENGE" MAX_TTL_SECS)"
assert_eq "PHP Config::MAX_TTL_SECS" "$TTL_MAX_SECS" \
    "$(php_const "$PHP_CONFIG" MAX_TTL_SECS)"
assert_eq "browser ttlSecs bound" "$TTL_MAX_SECS" \
    "$(js_value "$DRIVER" 's/.*data\.ttlSecs > ([0-9]+)\).*/\1/p')"

assert_eq "Rust MIN_RSW_T" "$RSW_T_MIN" "$(rust_const "$RUST_CHALLENGE" MIN_RSW_T)"
assert_eq "Rust MAX_RSW_T" "$RSW_T_MAX" "$(rust_const "$RUST_CHALLENGE" MAX_RSW_T)"
assert_eq "PHP Config::MIN_RSW_T" "$RSW_T_MIN" "$(php_const "$PHP_CONFIG" MIN_RSW_T)"
assert_eq "PHP Config::MAX_RSW_T" "$RSW_T_MAX" "$(php_const "$PHP_CONFIG" MAX_RSW_T)"
assert_eq "browser rsw T bound" "$RSW_T_MIN $RSW_T_MAX" \
    "$(js_value "$DRIVER" 's/.*rswT < ([0-9]+) \|\| rswT > ([0-9]+)\).*/\1 \2/p')"
assert_eq "worker rsw T bound" "$RSW_T_MIN $RSW_T_MAX" \
    "$(js_unique_value "$WORKER" 'm\.t < [0-9]+ \|\| m\.t > [0-9]+' 's/.*m\.t < ([0-9]+) \|\| m\.t > ([0-9]+).*/\1 \2/p')"

assert_eq "Rust token MAX_DURATION_MS" "$TOKEN_MAX_DURATION_MS" \
    "$(rust_const "$RUST_TOKEN" MAX_DURATION_MS)"
assert_eq "PHP SolutionToken::MAX_DURATION_MS" "$TOKEN_MAX_DURATION_MS" \
    "$(php_const "$PHP_TOKEN" MAX_DURATION_MS)"
pass "the TTL ceiling, the rsw T ladder and the token duration ceiling agree"

# ── Secret floors ──────────────────────────────────────────────────────
assert_eq "Rust MIN_MASTER_BYTES" "$MIN_MASTER_BYTES" \
    "$(rust_const "$RUST_KEYS" MIN_MASTER_BYTES)"
assert_eq "PHP Config::MIN_SECRET_BYTES" "$MIN_MASTER_BYTES" \
    "$(php_const "$PHP_CONFIG" MIN_SECRET_BYTES)"
assert_eq "Rust MIN_EXECUTION_KEY_BYTES" "$MIN_EXECUTION_KEY_BYTES" \
    "$(rust_const "$RUST_KEYS" MIN_EXECUTION_KEY_BYTES)"
assert_eq "PHP Config::MIN_EXECUTION_KEY_BYTES" "$MIN_EXECUTION_KEY_BYTES" \
    "$(php_const "$PHP_CONFIG" MIN_EXECUTION_KEY_BYTES)"
# The challenge.rs and execution.rs gates must route through the shared
# constants, never a repeated literal: a literal would not drift this
# register, but it is exactly how the 16-vs-32 split happened. Both
# files must carry at least one reference to their constant and no
# literal `len() < 16` gate at all.
[ "$(grep -c 'MIN_MASTER_BYTES' "$RUST_CHALLENGE" || true)" -ge 1 ] \
    || fail "$RUST_CHALLENGE does not route its secret-key gates through MIN_MASTER_BYTES"
[ "$(grep -c 'MIN_EXECUTION_KEY_BYTES' "$RUST_EXECUTION" || true)" -ge 1 ] \
    || fail "$RUST_EXECUTION does not route its execution-key gate through MIN_EXECUTION_KEY_BYTES"
[ "$(grep -c 'len() < 16' "$RUST_CHALLENGE" || true)" = "0" ] \
    || fail "$RUST_CHALLENGE still carries a literal 16-byte key gate"
[ "$(grep -c 'len() < 16' "$RUST_EXECUTION" || true)" = "0" ] \
    || fail "$RUST_EXECUTION still carries a literal 16-byte key gate"
for php_file in "$PHP_CONFIG" "$PHP_VERIFIER" "$PHP_EXECUTION" "$ROOT/packages/kiwicaptcha-php/src/DerivedKeys.php"; do
    [ "$(grep -cE 'strlen\([^)]*\) < 16' "$php_file" || true)" = "0" ] \
        || fail "$php_file still carries a literal 16-byte secret gate"
done
pass "the secret and execution-key floors are single shared constants on both sides"

# ── Execution register ─────────────────────────────────────────────────
assert_eq "Rust MAX_EXECUTION_VERSION" "$EXECUTION_MAX_VERSION" \
    "$(rust_const "$RUST_EXECUTION" MAX_EXECUTION_VERSION)"
assert_eq "PHP ExecutionChallengeGenerator::MAX_EXECUTION_VERSION" "$EXECUTION_MAX_VERSION" \
    "$(php_const "$PHP_EXECUTION" MAX_EXECUTION_VERSION)"
assert_eq "Rust MAX_PROGRAM_BASE64" "$EXECUTION_MAX_PROGRAM_BASE64" \
    "$(rust_const "$RUST_EXECUTION" MAX_PROGRAM_BASE64)"
assert_eq "PHP ExecutionChallengeGenerator::MAX_PROGRAM_BASE64" "$EXECUTION_MAX_PROGRAM_BASE64" \
    "$(php_const "$PHP_EXECUTION" MAX_PROGRAM_BASE64)"
assert_eq "browser execution_program bound" "$EXECUTION_MAX_PROGRAM_BASE64" \
    "$(js_value "$DRIVER" 's/.*data\.execution_program\.length > ([0-9]+)\).*/\1/p')"
assert_eq "Rust MAX_OPS" "$EXECUTION_MAX_OPS" \
    "$(rust_const "$RUST_EXECUTION" MAX_OPS)"
assert_eq "PHP ExecutionChallengeGenerator::MAX_OPS" "$EXECUTION_MAX_OPS" \
    "$(php_const "$PHP_EXECUTION" MAX_OPS)"
pass "the execution version, program-size and op-count ceilings agree across PHP, Rust and the widget"

# ── Worker protocol generation ─────────────────────────────────────────
assert_eq "Rust wasm SOLVER_PROTOCOL_VERSION" "$WORKER_PROTOCOL_VERSION" \
    "$(rust_const "$RUST_WASM" SOLVER_PROTOCOL_VERSION)"
assert_eq "worker KIWI_SOLVER_PROTOCOL_VERSION" "$WORKER_PROTOCOL_VERSION" \
    "$(js_unique_value "$WORKER" 'var KIWI_SOLVER_PROTOCOL_VERSION = [0-9]+;' 's/.*= ([0-9]+);$/\1/p')"
# The generation LABEL (a string) must be identical in the driver and
# the worker: the worker comment pins it as a MUST-equal pair.
DRIVER_PROTOCOL_ID=$(js_value "$DRIVER" 's/^  var KIWI_SOLVER_PROTOCOL_ID = "([^"]+)";$/\1/p')
WORKER_PROTOCOL_IDS=$(grep -oE 'var KIWI_SOLVER_PROTOCOL_ID = "[^"]+";' "$WORKER" 2>/dev/null | sed -n -E 's/.*"([^"]+)";$/\1/p' | sort -u || true)
assert_eq "widget-driver KIWI_SOLVER_PROTOCOL_ID" "$WORKER_PROTOCOL_ID" "$DRIVER_PROTOCOL_ID"
assert_eq "worker KIWI_SOLVER_PROTOCOL_ID" "$WORKER_PROTOCOL_ID" "$WORKER_PROTOCOL_IDS"
pass "the worker protocol generation agrees across the wasm source, the driver and the worker asset"

echo "limits register: all rows coherent across PHP, Rust, the widget and the worker"
