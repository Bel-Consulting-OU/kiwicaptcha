#!/usr/bin/env bash
# latency-compare-test.sh — deterministic unit fixtures with known
# answers for the balanced latency comparator (tools/ci/latency-compare.sh
# and tools/ci/latency-compare.awk). The comparator is a performance
# oracle, so it is itself tested: every fixture pins the exact verdict
# the gate must reach, including the nearest-rank p90 semantics, the
# incomplete-sample failure, and the non-blocking ambiguous contract.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
compare="$script_dir/latency-compare.sh"
awkbin="$(command -v gawk 2>/dev/null || command -v awk)"

tmpd="$(mktemp -d "${TMPDIR:-/tmp}/latency-compare-test.XXXXXX")"
trap 'rm -rf "$tmpd"' EXIT HUP INT TERM

pass=0
fail=0
ok() { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1" >&2; fail=$((fail + 1)); }

# mklog DIR SIDE MODE REPEAT ISSUE50 ISSUE90 ISSUE95 VERIFY50 VERIFY90 VERIFY95
mklog() {
  local dir=$1 side=$2 mode=$3 repeat=$4 i50=$5 i90=$6 i95=$7 v50=$8 v90=$9 v95=${10}
  mkdir -p "$dir/$side"
  printf 'perf-bench: SHA-256 array issuance p50 %s ms p95 %s ms p90 %s ms (n=100); verification p50 %s ms p95 %s ms p90 %s ms (n=50)\n' \
    "$i50" "$i95" "$i90" "$v50" "$v95" "$v90" >"$dir/$side/$mode-$repeat.log"
}

# filllogs DIR MODE BASE50 HEAD50 [BASE95 HEAD95]
filllogs() {
  local dir=$1 mode=$2 b=$3 h=$4 b95=${5:-10.500} h95=${6:-10.500}
  local b90 h90
  b90="$(awk -v v="$b" 'BEGIN { printf "%.3f", v + 0.200 }')"
  h90="$(awk -v v="$h" 'BEGIN { printf "%.3f", v + 0.200 }')"
  for repeat in 1 2 3 4 5 6; do
    mklog "$dir" base "$mode" "$repeat" "$b" "$b90" "$b95" 5.000 5.200 5.500
    mklog "$dir" head "$mode" "$repeat" "$h" "$h90" "$h95" 5.000 5.200 5.500
  done
}

# 1. Nearest-rank p90: with six observations the rank is 6 (ceil), not 5
#    (floor). A comparator that floors reads 0.5 instead of the 0.9
#    observation and misses the broad shift this fixture encodes.
{
  printf 'array\tbase\t1\t10.0\t10.1\t10.2\t5.0\t5.1\t5.2\n'
  printf 'array\tbase\t2\t10.0\t10.1\t10.2\t5.0\t5.1\t5.2\n'
  printf 'array\tbase\t3\t10.0\t10.1\t10.2\t5.0\t5.1\t5.2\n'
  printf 'array\tbase\t4\t10.0\t10.1\t10.2\t5.0\t5.1\t5.2\n'
  printf 'array\tbase\t5\t10.0\t10.1\t10.2\t5.0\t5.1\t5.2\n'
  printf 'array\tbase\t6\t10.0\t10.1\t10.2\t5.0\t5.1\t5.2\n'
  printf 'array\thead\t1\t10.1\t10.2\t10.3\t5.0\t5.1\t5.2\n'
  printf 'array\thead\t2\t10.2\t10.3\t10.4\t5.0\t5.1\t5.2\n'
  printf 'array\thead\t3\t10.3\t10.4\t10.5\t5.0\t5.1\t5.2\n'
  printf 'array\thead\t4\t10.4\t10.5\t10.6\t5.0\t5.1\t5.2\n'
  printf 'array\thead\t5\t10.5\t10.6\t10.7\t5.0\t5.1\t5.2\n'
  printf 'array\thead\t6\t10.9\t11.0\t11.1\t5.0\t5.1\t5.2\n'
} >"$tmpd/p90.tsv"
p90_line="$("$awkbin" -f "$script_dir/latency-compare.awk" -v metric='issue p50' -v col=4 -v p50c=4 -v p95c=6 \
  -v rel_max=9999 -v abs_max=0.5 -v spread_max=10 "$tmpd/p90.tsv")"
p90="$(printf '%s\n' "$p90_line" | cut -f9)"
p90_n="$(printf '%s\n' "$p90_line" | cut -f2)"
if [ "$p90_n" = "6" ] && [ "$p90" = "0.9000" ]; then
  ok "nearest-rank p90 reads rank 6 of 6 (0.9), not the floored rank 5 (0.5)"
else
  bad "nearest-rank p90: expected n=6 p90=0.9000, got n=$p90_n p90=$p90"
fi

# 2. A confident regression (side medians, paired median and paired p90
#    all clear the thresholds, every pair agrees, windows quiet) fails.
filllogs "$tmpd/regression" array 10.000 13.000
if out="$("$compare" "$tmpd/regression" 6 "array" 20 0.5 10 2>&1)"; then
  bad "confident regression must exit non-zero"
else
  case "$out" in
    *REGRESSION*) ok "confident regression exits 1 with the regression report" ;;
    *) bad "confident regression exited non-zero without a REGRESSION line: $out" ;;
  esac
fi

# 3. Identical sides pass and leave no ambiguous marker.
filllogs "$tmpd/pass" array 10.000 10.000
if out="$("$compare" "$tmpd/pass" 6 "array" 20 0.5 10 2>&1)"; then
  if [ ! -e "$tmpd/pass/ambiguous" ] && printf '%s' "$out" | grep -q 'PASS'; then
    ok "identical sides pass without an ambiguous marker"
  else
    bad "identical sides: unexpected output or marker: $out"
  fi
else
  bad "identical sides must pass"
fi

# 4. Over-threshold median with one contradicting pair is ambiguous:
#    non-blocking (exit 0) and marked for review, never the failure exit.
filllogs "$tmpd/ambiguous" array 10.000 12.000
mklog "$tmpd/ambiguous" head array 6 0.000 0.200 0.500 5.000 5.200 5.500
if out="$("$compare" "$tmpd/ambiguous" 6 "array" 20 0.5 10 2>&1)"; then
  if [ -e "$tmpd/ambiguous/ambiguous" ] && printf '%s' "$out" | grep -q 'AMBIGUOUS'; then
    ok "sign-contradicting over-threshold signal is ambiguous, non-blocking and marked"
  else
    bad "ambiguous case: expected marker plus AMBIGUOUS output: $out"
  fi
else
  bad "ambiguous signal must not use the failure exit"
fi

# 5. A noisy window (p95/p50 above the spread bound) demotes a
#    threshold crossing to ambiguous, non-blocking.
filllogs "$tmpd/noisy" array 10.000 13.000 10.500 200.000
if out="$("$compare" "$tmpd/noisy" 6 "array" 20 0.5 10 2>&1)"; then
  if [ -e "$tmpd/noisy/ambiguous" ] && printf '%s' "$out" | grep -q 'window noisy'; then
    ok "noisy window demotes the crossing to ambiguous"
  else
    bad "noisy case: expected a noisy-window ambiguous report: $out"
  fi
else
  bad "noisy window must be ambiguous, not a failure"
fi

# 6. A requested mode whose Redis measurement is missing fails: the mode
#    must never pass on an empty sample.
filllogs "$tmpd/noredis" array 10.000 10.000
mklog "$tmpd/noredis" head array 3 10.000 10.200 10.500 5.000 5.200 5.500
printf 'perf-bench NOTE: --redis requested but no Redis answers at redis://127.0.0.1:6399\n' \
  >"$tmpd/noredis/head/array-3.log"
if out="$("$compare" "$tmpd/noredis" 6 "array" 20 0.5 10 2>&1)"; then
  bad "a requested mode without measurements must fail"
else
  case "$out" in
    *"no Redis measurements"*) ok "requested mode with a missing Redis measurement fails loudly" ;;
    *) bad "Redis-unavailable failure message missing: $out" ;;
  esac
fi

# 7. A missing log for a requested mode fails before any comparison.
filllogs "$tmpd/missing" array 10.000 10.000
rm "$tmpd/missing/head/array-5.log"
if out="$("$compare" "$tmpd/missing" 6 "array" 20 0.5 10 2>&1)"; then
  bad "a missing log must fail"
else
  case "$out" in
    *"no log for head repeat 5"*) ok "missing log fails with the exact repeat named" ;;
    *) bad "missing-log failure message missing: $out" ;;
  esac
fi

echo ""
if [ "$fail" -gt 0 ]; then
  echo "latency-compare-test.sh: FAIL ($fail failed, $pass passed)" >&2
  exit 1
fi
echo "latency-compare-test.sh: ALL PASS ($pass fixtures)"
