#!/usr/bin/env bash
#
# run-proof.sh — the version-6 envelope fail-harness runner: the
# done-when proof that the browserless oracle and the jsdom/happy-dom
# emulators are rejected by the envelope walker at (far) above the
# 99.9 percent bar over the full 10^5-program corpus.
#
# Three legs over one deterministic synthetic corpus: the nonce is
# sha256 over the corpus index, the programs come from the real PHP
# generator at the real-platform rung.
#
#   oracle    the unchanged browserless forgery solver, the pure
#             state-machine oracle that forges every v1-v5 trace,
#             forges a trace per program; the PHP envelope walker
#             judges it.
#   jsdom     the unmodified interpreter asset runs inside a fresh
#             jsdom window per program; the produced traces are judged
#             by the same walker.
#   happy-dom the same attempt under happy-dom.
#
# Each leg shards across 5 workers for the oracle leg and 8 for the
# emulator legs; the
# per-attempt wall cost the emulator legs report is the Plane 8
# full-fidelity-emulator cost figure. Requirements: php + the php-core
# vendor dev autoload (packages/kiwicaptcha-php), node + the jsdom and
# happy-dom dev dependencies of tests/browser.
#
# Usage: bash run-proof.sh [per-shard N]   (default 20000; the proof
# figure in docs/performance-analysis.md is the 5x20000 + 8x12500 +
# 8x12500 run = 10^5 programs per leg)
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PER_SHARD=${1:-20000}

for s in 0 1 2 3 4; do
  php "$HERE/oracle-leg.php" $((s * PER_SHARD)) "$PER_SHARD" > "/tmp/v6-proof-oracle-$s.json"
done
cat /tmp/v6-proof-oracle-*.json | php -r '
$t = 0; $r = 0; $ms = 0;
while ($line = fgets(STDIN)) { $d = json_decode($line, true); $t += $d["attempted"]; $r += $d["rejected"]; $ms += $d["wallMs"]; }
echo json_encode(["leg" => "oracle", "attempted" => $t, "rejected" => $r, "rejectionRate" => round($r / $t, 6), "wallMs" => $ms]), "\n";
'
rm -f /tmp/v6-proof-oracle-*.json

EMULATOR_SHARD=$((PER_SHARD / 2))
for engine in jsdom happy-dom; do
  for s in 0 1 2 3 4 5 6 7; do
    (php "$HERE/corpus.php" $((s * EMULATOR_SHARD)) "$EMULATOR_SHARD" \
      | node "$HERE/emulator-leg.mjs" "$engine" 2>/dev/null \
      | php "$HERE/verify-leg.php" "$engine" > "/tmp/v6-proof-$engine-$s.json") &
  done
  wait
  cat /tmp/v6-proof-"$engine"-*.json | php -r '
    $t = 0; $r = 0; $p = 0; $c = 0; $ms = 0;
    while ($line = fgets(STDIN)) { $d = json_decode($line, true); $t += $d["attempted"]; $r += $d["rejected"]; $p += $d["produced"]; $c += $d["crashed"]; $ms += $d["msPerAttempt"] * $d["attempted"]; }
    echo json_encode(["leg" => $argv[1], "attempted" => $t, "produced" => $p, "crashed" => $c, "rejected" => $r, "rejectionRate" => round($r / $t, 6), "msPerAttempt" => round($ms / $t, 3)]), "\n";
  ' "$engine"
  rm -f /tmp/v6-proof-"$engine"-*.json
done
