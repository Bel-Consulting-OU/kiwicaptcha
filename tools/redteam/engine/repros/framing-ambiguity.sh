#!/bin/bash
# framing-ambiguity.sh — the repro harness for the "framing-ambiguity" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. The verdict is REFUTED when the wire
# refuses the attack (the expected behavior) and REPRODUCED when it
# accepts it (a finding). No hardcoded verdict: the HTTP status of the
# contradictory CL/TE request decides.
set -u
. "$(cd "$(dirname "$0")" && pwd)/repro-common.sh"
BASE=$(repro_target)
if [ -z "$BASE" ]; then
    printf '{"harness":"framing-ambiguity","verdict":"INCONCLUSIVE","wire_code":"target_unavailable"}\n'
    exit 0
fi
OUT=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -X POST \
  -H "content-type: application/json" -H "Transfer-Encoding: chunked" -H "Content-Length: 5" \
  --data-binary "0

" "$BASE/verify"; echo)
CODE=$OUT
# A 2xx means the edge accepted contradictory length framing (the
# smuggle landed) — a finding. A 4xx is the expected refusal. A 5xx or
# a transport-level 000 is inconclusive, never a quiet REFUTED.
case "$CODE" in
    2??) VERDICT=REPRODUCED ;;
    4??) VERDICT=REFUTED ;;
    *) VERDICT=INCONCLUSIVE ;;
esac
printf '{"harness":"framing-ambiguity","verdict":"%s","wire_code":"http_%s"}\n' "$VERDICT" "$CODE"
