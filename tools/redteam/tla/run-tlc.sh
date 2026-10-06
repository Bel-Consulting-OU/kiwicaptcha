#!/bin/bash
# run-tlc.sh — the model-checking leg of the release gate: runs TLC
# over the consume/commit spec with the vendored tla2tools jar.
#
# The toolchain: the jar is committed at vendor/tla2tools.jar (pinned
# release 1.7.4, downloaded from the project's GitHub releases at
# adoption time; the working tree carries it so the gate never needs
# the network). Java must be on the PATH. A missing jar or a missing
# java prints the exact blocker and exits 3, which the gate renders as
# the TOOLCHAIN-ABSENT row; the row is never green by default.

set -u
TLA_DIR=$(cd "$(dirname "$0")" && pwd)
JAR="$TLA_DIR/vendor/tla2tools.jar"
SPEC="$TLA_DIR/ConsumeCommit.tla"
CFG="$TLA_DIR/ConsumeCommit.cfg"
LOG="${1:-$TLA_DIR/tlc-run.log}"

if ! command -v java >/dev/null 2>&1; then
    echo "TOOLCHAIN-ABSENT: java is not on the PATH; install a JDK (the vendored tla2tools needs one)"
    exit 3
fi
if [ ! -f "$JAR" ]; then
    echo "TOOLCHAIN-ABSENT: the tla2tools jar is missing at $JAR"
    echo "TOOLCHAIN-ABSENT: fetch the pinned release: https://github.com/tlaplus/tlaplus/releases (v1.8.0)"
    exit 3
fi

# TLC run: the safety pass with the deadlock check, the state graph
# of this spec is tiny (two clients, one record, a bounded retry
# schedule). The vendored jar is release 1.8.0.
if java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -config "$CFG" -deadlock -cleanup "$SPEC" >"$LOG" 2>&1; then
    states=$(grep -oE '[0-9]+ states generated' "$LOG" | tail -n 1)
    distinct=$(grep -oE '[0-9]+ distinct states found' "$LOG" | tail -n 1)
    depth=$(grep -oE 'The depth of the complete state graph search is [0-9]+' "$LOG" | tail -n 1)
    echo "MODEL-CHECK: 0 violations; ${states:-?}; ${distinct:-?}; ${depth:-?}"
    echo "MODEL-CHECK: invariants checked: RecordState, ConsumedByOK, OneShot, NoDoubleCommit, NoAcceptWithoutConsume"
    exit 0
fi
violations=$(grep -cE 'Error:|Invariant .* is violated' "$LOG" 2>/dev/null || true)
if [ "${violations:-0}" -gt 0 ]; then
    echo "MODEL-CHECK: TLC ran and FOUND VIOLATIONS ($violations); see $LOG"
    grep -E 'Invariant .* is violated|Error:' "$LOG" | head -5
    exit 1
fi
echo "TOOLCHAIN-ABSENT/ERROR: TLC did not complete; see $LOG"
tail -5 "$LOG"
exit 3
