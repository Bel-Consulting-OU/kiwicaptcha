#!/usr/bin/env bash
#
# deploy/probe-rate-limit.sh - end-to-end proof of the issuance rate
# limiter against a RUNNING reference deployment.
#
# The probe bursts unauthenticated POST /challenge requests past the
# configured per-IP window budget and asserts the transition: requests
# inside the budget answer 200, the burst past it answers 429 with the
# RATE_LIMITED error code, and after the 60-second window expires the
# same client IP is allowed again.
#
# Usage (the app must be running; see deploy/README.md for the local
# php -S boot and the compose stack):
#   KIWI_PROBE_BASE_URL=http://127.0.0.1:8080 \
#   KIWI_PROBE_LIMIT=5 \
#   bash deploy/probe-rate-limit.sh
#
# KIWI_PROBE_LIMIT must equal the deployment's
# KIWI_ISSUANCE_PER_MINUTE_PER_IP. The window-reset phase waits for the
# fixed 60-second window, so the whole probe takes about a minute.

set -euo pipefail

BASE_URL="${KIWI_PROBE_BASE_URL:-http://127.0.0.1:8080}"
LIMIT="${KIWI_PROBE_LIMIT:-5}"

challenge_status() {
  curl -sS -o /tmp/kiwi-rl-probe-body.json -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d '{"scope":"login"}' "$BASE_URL/challenge"
}

fail() {
  echo "probe-rate-limit: FAIL: $*" >&2
  exit 1
}

# Phase 1: the in-budget burst answers 200 for every request.
for i in $(seq 1 "$LIMIT"); do
  status="$(challenge_status)"
  [ "$status" = "200" ] || fail "request $i of the in-budget burst answered $status, expected 200"
  echo "in-budget request $i/$LIMIT: 200"
done

# Phase 2: the burst past the budget answers 429 RATE_LIMITED.
status="$(challenge_status)"
[ "$status" = "429" ] || fail "request $((LIMIT + 1)) answered $status, expected 429"
grep -q '"code":"RATE_LIMITED"' /tmp/kiwi-rl-probe-body.json \
  || fail "the 429 body does not carry the RATE_LIMITED code: $(cat /tmp/kiwi-rl-probe-body.json)"
curl -sS -D /tmp/kiwi-rl-probe-headers.txt -o /dev/null -X POST \
  -H 'Content-Type: application/json' \
  -d '{"scope":"login"}' "$BASE_URL/challenge"
grep -qi '^cache-control:.*no-store' /tmp/kiwi-rl-probe-headers.txt \
  || fail "the 429 answer is missing Cache-Control: no-store"
echo "past-budget request $((LIMIT + 1)): 429 RATE_LIMITED (Cache-Control: no-store)"

# Phase 3: the window resets. The fixed window is 60 seconds from the
# first request of the burst, so wait out the remainder and assert the
# client IP is allowed again.
echo "waiting for the 60-second window to expire..."
sleep 65
status="$(challenge_status)"
[ "$status" = "200" ] || fail "request after the window answered $status, expected 200"
echo "after the window: 200 (window reset)"

echo "probe-rate-limit: PASS (in-budget 200s, past-budget 429 RATE_LIMITED, window reset 200)"
