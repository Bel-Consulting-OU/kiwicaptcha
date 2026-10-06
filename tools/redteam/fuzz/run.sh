#!/bin/bash
# run.sh — the coverage-guided fuzz leg for the release gate.
#
# Prefers real cargo-fuzz over fuzz_targets/ when the toolchain can
# build them (libfuzzer-sys needs network on first build). When it
# cannot, runs the offline coverage-guided substitute binary (the
# same no-panic property over SolutionToken::decode and
# ChallengeRecord) and prints its measured scale. Exit 0: no crashes.
# Exit 3: the toolchain is absent AND the substitute cannot build.
#
# Usage: tools/redteam/fuzz/run.sh [runs]
set -u
FUZZ_DIR=$(cd "$(dirname "$0")" && pwd)
RUNS="${1:-${KIWI_EC_COVERAGE_FUZZ_RUNS:-10000}}"

# First choice: the real cargo-fuzz targets, if they can build here.
if command -v cargo-fuzz >/dev/null 2>&1 && [ -d "$FUZZ_DIR/fuzz_targets" ]; then
    for target in token_parse record_parse; do
        [ -f "$FUZZ_DIR/fuzz_targets/$target.rs" ] || continue
        if cargo fuzz run --fuzz-dir "$FUZZ_DIR" --sanitizer none "$target" -- -runs="$RUNS" >"$FUZZ_DIR/cargo-fuzz-$target.log" 2>&1; then
            echo "COVERAGE-FUZZ: cargo-fuzz $target runs=$RUNS (0 crashes)"
            continue
        fi
        # A crash is a real failure. A toolchain/build miss falls
        # through to the substitute — never a quiet green.
        if grep -qE 'ERROR:|CRASH:|AddressSanitizer|panic:|test panicked' "$FUZZ_DIR/cargo-fuzz-$target.log" 2>/dev/null; then
            echo "COVERAGE-FUZZ: cargo-fuzz $target found a crash (see $FUZZ_DIR/cargo-fuzz-$target.log)"
            exit 1
        fi
    done
    # If any target printed a success line we are done green.
    if grep -q '^COVERAGE-FUZZ: cargo-fuzz' "$FUZZ_DIR"/cargo-fuzz-*.log 2>/dev/null; then
        grep -h '^COVERAGE-FUZZ: cargo-fuzz' "$FUZZ_DIR"/cargo-fuzz-*.log | tail -n 1
        exit 0
    fi
fi

# The local substitute: same property, coverage feedback over parse
# outcomes, fully offline.
if ! (cd "$FUZZ_DIR" && cargo build --release --offline --bin coverage-fuzz >"$FUZZ_DIR/build.log" 2>&1); then
    echo "TOOLCHAIN-ABSENT: the coverage-fuzz substitute failed to build (see $FUZZ_DIR/build.log)"
    exit 3
fi
"$FUZZ_DIR/target/release/coverage-fuzz" --runs "$RUNS" --seed "${KIWI_RT_SEED:-0x6b776d74}"
exit $?
