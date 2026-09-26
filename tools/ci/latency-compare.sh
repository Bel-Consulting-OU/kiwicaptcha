#!/usr/bin/env bash
# latency-compare.sh — collect the balanced base/head perf-bench logs,
# prove every requested mode produced a complete paired sample, and run
# the comparator (tools/ci/latency-compare.awk).
#
# usage: latency-compare.sh EVIDENCE_DIR REPEATS "MODE ..." REL_MAX ABS_MAX SPREAD_MAX
#
# Contract: every requested mode must produce exactly REPEATS valid
# base measurements and REPEATS valid head measurements. A missing log,
# a Redis-unavailable log, an unparseable measurement, a non-numeric
# value, or a duplicate repeat fails loudly instead of silently
# comparing a smaller sample.
#
# Verdict semantics (explicit): only a confident regression exits 1.
# An over-threshold signal without paired-distribution agreement is
# AMBIGUOUS: it is printed loudly, flagged with an EVIDENCE_DIR/ambiguous
# marker for the caller and the uploaded evidence bundle, and does not
# block the run — re-run on the quiet runner before concluding.

set -euo pipefail

if [ "$#" -ne 6 ]; then
  echo "usage: latency-compare.sh EVIDENCE_DIR REPEATS \"MODE ...\" REL_MAX ABS_MAX SPREAD_MAX" >&2
  exit 2
fi

dir=$1
repeats=$2
modes=$3
rel_max=$4
abs_max=$5
spread_max=$6

awkbin="$(command -v gawk 2>/dev/null || command -v awk)"
script_dir="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$dir" ]; then
  echo "latency-compare: evidence dir not found: $dir" >&2
  exit 1
fi
if (( repeats < 2 || repeats % 2 != 0 )); then
  echo "latency-compare: REPEATS must be an even count >= 2 (got $repeats)" >&2
  exit 1
fi

failed=0
ambiguous=0

for mode in $modes; do
  tsv="$dir/$mode.tsv"
  : > "$tsv"
  for ((repeat = 1; repeat <= repeats; repeat++)); do
    for side in base head; do
      log="$dir/$side/$mode-$repeat.log"
      if [ ! -s "$log" ]; then
        echo "latency-compare: requested mode $mode has no log for $side repeat $repeat ($log)" >&2
        exit 1
      fi
      if grep -q 'no Redis answers' "$log"; then
        echo "latency-compare: requested mode $mode produced no Redis measurements for $side repeat $repeat; a requested mode must not pass without its measurements" >&2
        exit 1
      fi
      issue="$(sed -n 's/.*issuance p50 \([0-9.]*\) ms p95 \([0-9.]*\) ms p90 \([0-9.]*\) ms.*/\1 \2 \3/p' "$log")"
      verify="$(sed -n 's/.*verification p50 \([0-9.]*\) ms p95 \([0-9.]*\) ms p90 \([0-9.]*\) ms.*/\1 \2 \3/p' "$log")"
      if [ -z "$issue" ] || [ -z "$verify" ]; then
        echo "latency-compare: no perf-bench measurement line for $mode $side repeat $repeat:" >&2
        cat "$log" >&2
        exit 1
      fi
      read -r i50 i95 i90 <<<"$issue"
      read -r v50 v95 v90 <<<"$verify"
      for value in "$i50" "$i95" "$i90" "$v50" "$v95" "$v90"; do
        if [[ ! $value =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
          echo "latency-compare: non-numeric measurement '$value' for $mode $side repeat $repeat" >&2
          exit 1
        fi
      done
      # columns: 1=mode 2=side 3=repeat 4=i50 5=i90 6=i95 7=v50 8=v90 9=v95
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$side" "$repeat" "$i50" "$i90" "$i95" "$v50" "$v90" "$v95" >>"$tsv"
    done
  done

  bcount="$(awk -F '\t' '$2 == "base"' "$tsv" | wc -l | tr -d ' ')"
  hcount="$(awk -F '\t' '$2 == "head"' "$tsv" | wc -l | tr -d ' ')"
  if [ "$bcount" != "$repeats" ] || [ "$hcount" != "$repeats" ]; then
    echo "latency-compare: $mode produced $bcount base / $hcount head measurements, expected $repeats each" >&2
    exit 1
  fi
  echo "=== mode $mode ($repeats base + $repeats head measurements) ==="

  while IFS='|' read -r name col p50c p95c; do
    [ -n "$name" ] || continue
    line="$("$awkbin" -f "$script_dir/latency-compare.awk" \
      -v metric="$name" -v col="$col" -v p50c="$p50c" -v p95c="$p95c" \
      -v rel_max="$rel_max" -v abs_max="$abs_max" -v spread_max="$spread_max" "$tsv")"
    n="$(printf '%s\n' "$line" | cut -f2)"
    b_med="$(printf '%s\n' "$line" | cut -f3)"
    h_med="$(printf '%s\n' "$line" | cut -f4)"
    absd="$(printf '%s\n' "$line" | cut -f5)"
    rel="$(printf '%s\n' "$line" | cut -f6)"
    p_med="$(printf '%s\n' "$line" | cut -f7)"
    p_relmed="$(printf '%s\n' "$line" | cut -f8)"
    p_p90="$(printf '%s\n' "$line" | cut -f9)"
    contra="$(printf '%s\n' "$line" | cut -f10)"
    noisy="$(printf '%s\n' "$line" | cut -f11)"
    verdict="$(printf '%s\n' "$line" | cut -f12)"
    if [ "$n" != "$repeats" ]; then
      echo "latency-compare: $mode $name paired $n repeats, expected $repeats" >&2
      exit 1
    fi
    agreement="agree"
    [ "$contra" = "0" ] || agreement="disagree:$contra"
    report="$mode $name: base median ${b_med} ms, head median ${h_med} ms, delta ${absd} ms (${rel}%); paired n=${n} median delta ${p_med} ms / ${p_relmed}%, paired p90 delta ${p_p90} ms, agreement ${agreement}, window ${noisy}"
    case "$verdict" in
      regression)
        echo "REGRESSION: $report — over the ${rel_max}% / ${abs_max} ms thresholds with paired-distribution agreement" >&2
        failed=1
        ;;
      ambiguous)
        echo "SIGNAL BUT AMBIGUOUS: $report — over the thresholds without paired-distribution agreement; non-blocking, review the evidence" >&2
        ambiguous=1
        ;;
      pass)
        echo "$report"
        ;;
      *)
        echo "latency-compare: $mode $name comparator verdict '$verdict'" >&2
        exit 1
        ;;
    esac
  done <<'METRICS'
issue p50|4|4|6
issue p90|5|4|6
issue p95|6|4|6
verify p50|7|7|9
verify p90|8|7|9
verify p95|9|7|9
METRICS
done

if [ "$failed" -eq 1 ]; then
  echo "latency-compare: FAILED — confident regression(s) above" >&2
  exit 1
fi
if [ "$ambiguous" -eq 1 ]; then
  : >"$dir/ambiguous"
  echo "latency-compare: AMBIGUOUS — over-threshold signal(s) without paired-distribution agreement; recorded in $dir/ambiguous for review, not blocking (only confident regressions block)" >&2
  exit 0
fi
echo "latency-compare: PASS — no phase exceeds ${rel_max}% / ${abs_max} ms with paired-distribution agreement"
