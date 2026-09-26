# latency-compare.awk — one metric of the balanced base/head latency
# comparator. Input: the TSV the shell collector writes, one row per
# benchmark run: mode, side, repeat, i50, i90, i95, v50, v90, v95.
#
# Variables: metric (label), col (metric column), p50c/p95c (the same
# phase's p50/p95 columns for the spread check), rel_max (percent),
# abs_max (ms), spread_max (p95/p50 bound).
#
# Output: one tab-separated line:
#   metric n b_med h_med abs_delta rel_pct p_med p_relmed p90 contra noisy verdict
#
# One indexing convention throughout: values land at 1..n and every
# loop and nearest-rank lookup uses 1..n.
#
# verdict:
#   regression  side medians AND the paired median clear both
#               thresholds, the paired nearest-rank p90 delta clears the
#               absolute bound, every pair agrees with the median sign,
#               and no run is noisy
#   ambiguous   the same threshold crossing without that agreement:
#               over-threshold signal, not a confident regression
#   pass        no threshold crossing
#   insufficient fewer than two paired repeats (the shell rejects this
#               before the verdict can be trusted)

function sort_num(a, n,   i, j, key) {
  for (i = 2; i <= n; i++) {
    key = a[i]
    for (j = i - 1; j >= 1 && a[j] > key; j--) a[j + 1] = a[j]
    a[j + 1] = key
  }
}
function median_sorted(a, n) {
  if (n % 2) return a[(n + 1) / 2]
  return (a[n / 2] + a[n / 2 + 1]) / 2
}
function ceil_rank(x,   i) {
  i = int(x)
  if (i < x) i++
  return i
}
BEGIN { FS = "\t"; noisy = 0 }
{
  if ($2 == "base") { bb[$3] = $col + 0 }
  else if ($2 == "head") { hh[$3] = $col + 0 }
  else next
  p50 = $p50c + 0; p95 = $p95c + 0
  if (p50 > 0 && p95 / p50 > spread_max) noisy = 1
}
END {
  n = 0
  rn = 0
  for (r in hh) {
    if (!(r in bb)) continue
    n++
    deltas[n] = hh[r] - bb[r]
    if (bb[r] > 0) {
      rn++
      rels[rn] = deltas[n] / bb[r] * 100
    }
  }
  # The per-side median of the same metric across the repeats.
  bn = 0; hn = 0
  for (r in bb) bv[++bn] = bb[r]
  for (r in hh) hv[++hn] = hh[r]
  sort_num(bv, bn); sort_num(hv, hn)
  b_med = median_sorted(bv, bn)
  h_med = median_sorted(hv, hn)
  absd = h_med - b_med
  rel = (b_med > 0) ? absd / b_med * 100 : 0

  if (n < 1) {
    printf "%s\t0\t0\t0\t0\t0\t0\t0\t0\t0\t%s\tinsufficient\n", metric, (noisy ? "noisy" : "quiet")
    exit
  }
  sort_num(deltas, n)
  sort_num(rels, rn)
  med = median_sorted(deltas, n)
  relmed = rn ? median_sorted(rels, rn) : 0
  # Nearest-rank p90: the smallest rank whose cumulative share reaches
  # 90%, i.e. ceil(0.9 * n) clamped to 1..n. Flooring it would read the
  # wrong observation for small n (6 observations give rank 6, not 5).
  idx = ceil_rank(0.9 * n)
  if (idx < 1) idx = 1
  if (idx > n) idx = n
  p90 = deltas[idx]
  contra = 0
  for (i = 1; i <= n; i++) {
    if (deltas[i] != 0 && med != 0 && ((deltas[i] > 0) != (med > 0))) contra++
  }
  median_over = (rel >= rel_max && absd >= abs_max)
  paired_over = (relmed >= rel_max && med >= abs_max)
  broad = (p90 >= abs_max)
  verdict = "pass"
  if (n < 2) verdict = "insufficient"
  else if (median_over && paired_over && broad) {
    verdict = (contra == 0 && !noisy) ? "regression" : "ambiguous"
  }
  printf "%s\t%d\t%.4f\t%.4f\t%.4f\t%.1f\t%.4f\t%.1f\t%.4f\t%d\t%s\t%s\n", \
    metric, n, b_med, h_med, absd, rel, med, relmed, p90, contra, (noisy ? "noisy" : "quiet"), verdict
}
