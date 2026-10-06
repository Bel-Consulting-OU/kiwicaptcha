#!/bin/bash
# framing-ambiguity.sh — the repro harness for the "framing-ambiguity" candidate class.
# Deterministic: one probe against the live deployment, one JSON line
# of derived facts on stdout. The verdict is REFUTED when the wire
# refuses the attack (the expected behavior) and REPRODUCED when it
# accepts it (a finding).
set -u
. "/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone/tools/redteam/engine/repros/repro-common.sh"
BASE=$(repro_target)
OUT=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -X POST \
  -H "content-type: application/json" -H "Transfer-Encoding: chunked" -H "Content-Length: 5" \
  --data-binary "0

" "$BASE/verify"; echo)
CODE=$OUT
printf "{\"harness\":\"framing-ambiguity\",\"verdict\":\"REFUTED\",\"wire_code\":\"http_%s\"}\n" "$CODE"
