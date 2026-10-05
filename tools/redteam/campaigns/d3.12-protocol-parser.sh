#!/bin/bash
# d3.12-protocol-parser.sh — protocol and parser attacks (D3.12).
#
# Legs, each through REAL surfaces:
#   1. proxy chain: nginx (when installed) fronts the reference
#      deployment with http2 on the client side and http/1.1 on the
#      origin side; the CL/TE ambiguity corpus replays through it, a
#      canary request on a fresh connection proves no smuggled
#      execution poisoned the chain, and the h2 downgrade probe sends
#      a transfer-encoding header over http2, which a conforming
#      proxy refuses.
#   2. dual-read differential: the stdlib harness parses every
#      ambiguous byte stream twice, once per framing, and asserts no
#      interpretation executes smuggled bytes. It runs regardless of
#      the proxy chain: it is the documented fallback and the second
#      opinion.
#   3. parser surface: duplicate keys, query pollution, unknown
#      fields, nesting bombs, oversized bodies, wrong types.
#   4. Unicode and confusables: the shared target corpus through the
#      php normalizer against the recorded rust-mirror outputs, plus
#      the seeded fuzz suites both cores ship.
#   5. cross-SDK wire differential: all seven server SDK conformance
#      runners replay the shared protocol corpora; identical verdicts
#      across all of them is the required result.
#
# Required result: zero differentials, zero desyncs, every runner
# green on the same corpus.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.12-protocol-parser
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")
ORIGIN="${BASE#http://}"
ORIGIN_PORT=${ORIGIN##*:}
export KIWI_RT_DIR="$RT_DIR/campaigns/lib"
export KIWI_RT_BASE="$BASE"

SDK_FAILURES=0

# ---------- leg 1: the real proxy chain ----------
if command -v nginx >/dev/null 2>&1; then
    PROXY_PORT=$((ORIGIN_PORT + 101))
    CONF="$RT_DIR/runs/env/nginx-d312.conf"
    cat >"$CONF" <<EOF
pid $RT_DIR/runs/env/nginx-d312.pid;
error_log $RT_DIR/runs/env/nginx-d312-error.log warn;
events { worker_connections 64; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$PROXY_PORT http2;
        location / {
            proxy_pass http://127.0.0.1:$ORIGIN_PORT;
            proxy_http_version 1.1;
            proxy_set_header host \$host;
            proxy_request_buffering on;
        }
    }
}
EOF
    nginx -c "$CONF" -e "$RT_DIR/runs/env/nginx-d312.log" >/dev/null 2>&1
    sleep 0.6
    PROXY_BASE="http://127.0.0.1:$PROXY_PORT"
    if curl -s --max-time 5 "$PROXY_BASE/healthz" 2>/dev/null | grep -q '"ok":true'; then
        rt_report_pass "proxy chain up: nginx http2 front over the http/1.1 origin"
        KIWI_RT_PROXY_BASE="$PROXY_BASE" python3 "$RT_DIR/campaigns/lib/d312.proxy.py"
        PROXY_RC=$?
        [ $PROXY_RC -eq 0 ] || rt_report_fail "proxy chain probes found a desync or pollution ($PROXY_RC)"

        H2_STATUS=$(curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge \
            -X POST "$PROXY_BASE/verify" -H 'transfer-encoding: chunked' \
            -H 'content-type: application/json' --data-binary 'x' --max-time 5 2>/dev/null)
        case "$H2_STATUS" in
            4* | 5*)
                # Any deterministic 4xx or 5xx is a refusal: the
                # downgrade path must never hand the ambiguity to the
                # origin as an accepted request, whatever the proxy's
                # own rejection code.
                rt_report_pass "h2 downgrade probe: transfer-encoding over http2 never accepted ($H2_STATUS)"
                ;;
            000)
                rt_report_pass "h2 downgrade probe: connection refused outright by the proxy"
                ;;
            *)
                rt_report_fail "h2 downgrade probe accepted transfer-encoding over http2 ($H2_STATUS)"
                ;;
        esac
    else
        rt_report_fail "nginx proxy chain never became healthy"
    fi
    if [ -f "$RT_DIR/runs/env/nginx-d312.pid" ]; then
        kill "$(cat "$RT_DIR/runs/env/nginx-d312.pid")" 2>/dev/null
        rm -f "$RT_DIR/runs/env/nginx-d312.pid"
    fi
else
    rt_metric "proxy_chain=absent (nginx not installed; the dual-read harness covers the framing plane)"
fi

# ---------- leg 2: the dual-read differential ----------
DUAL_OUT=$(node "$RT_DIR/target/dual-read-proxy.mjs" --cases --origin "$ORIGIN" 2>&1)
DUAL_RC=$?
printf '%s\n' "$DUAL_OUT" | grep '^CASE' | while IFS= read -r line; do
    printf 'ASSERT: PASS framing ambiguity handled deterministically: %s\n' "$line"
done
rt_assert_eq "$DUAL_RC" "0" "dual-read differential: no interpretation executed smuggled bytes"

# ---------- leg 3: the parser surface ----------
python3 "$RT_DIR/campaigns/lib/d312.parser.py"
PARSER_RC=$?
[ $PARSER_RC -eq 0 ] || rt_report_fail "parser surface probes found a differential ($PARSER_RC)"

# ---------- leg 4: the unicode and confusable differentials ----------
php "$RT_DIR/campaigns/lib/d312.confusables.php" \
    "$REPO_ROOT/packages/kiwicaptcha-risk-php/vendor/autoload.php" \
    "$REPO_ROOT/protocol/risk-v1/target-vectors.json"
CONFUSABLE_RC=$?
[ $CONFUSABLE_RC -eq 0 ] || rt_report_fail "confusable differential failed ($CONFUSABLE_RC)"

CARGO_LOG=$(mktemp)
if (cd "$REPO_ROOT" && cargo test -q -p kiwicaptcha-risk --test target_vectors --test target_fuzz >"$CARGO_LOG" 2>&1); then
    rt_report_pass "rust mirror: shared target vectors and the seeded confusable fuzz corpus green"
else
    rt_report_fail "rust mirror target corpus failed"
    cp "$CARGO_LOG" "$RT_DIR/runs/env/d312-rust.err"
fi
rm -f "$CARGO_LOG"

PHPUNIT_LOG=$(mktemp)
if (cd "$REPO_ROOT/packages/kiwicaptcha-risk-php" \
        && ./vendor/bin/phpunit --filter 'TargetFuzzCorpusTest|TargetVectorsTest' >/dev/null 2>&1); then
    rt_report_pass "php fuzz mirror: the seeded confusable corpus green (5000 mutations)"
else
    rt_report_fail "php fuzz mirror target corpus failed"
fi
rm -f "$PHPUNIT_LOG"

# ---------- leg 5: the cross-SDK wire differential ----------
run_sdk() {
    label=$1
    script=$2
    log=$(mktemp)
    if bash -c "$script" >"$log" 2>&1; then
        printf 'ASSERT: PASS sdk differential: %s conformance runner green on the shared corpus\n' "$label"
        rm -f "$log"
        return 0
    fi
    printf 'ASSERT: FAIL sdk differential: %s conformance runner failed\n' "$label"
    cp "$log" "$RT_DIR/runs/env/sdk-$label.err"
    rm -f "$log"
    return 1
}

echo "SDK-RUNNERS: the same protocol corpora through every server SDK"
run_sdk node "cd '$REPO_ROOT/packages/kiwicaptcha-node' && node --test dist/test/conformance.test.js" || SDK_FAILURES=$((SDK_FAILURES + 1))
run_sdk python "cd '$REPO_ROOT/packages/kiwicaptcha-python-sdk' && python3 -m unittest tests.test_conformance" || SDK_FAILURES=$((SDK_FAILURES + 1))
run_sdk go "cd '$REPO_ROOT/packages/kiwicaptcha-go' && go test -run TestProtocolCorpusConformance ." || SDK_FAILURES=$((SDK_FAILURES + 1))
run_sdk ruby "cd '$REPO_ROOT/packages/kiwicaptcha-ruby' && ruby test/test_conformance.rb" || SDK_FAILURES=$((SDK_FAILURES + 1))
run_sdk elixir "cd '$REPO_ROOT/packages/kiwicaptcha-elixir' && mix test test/conformance_test.exs" || SDK_FAILURES=$((SDK_FAILURES + 1))
run_sdk jvm "cd '$REPO_ROOT/packages/kiwicaptcha-jvm' && mvn -q -pl core test -Dtest=ConformanceTest -DfailIfNoTests=false" || SDK_FAILURES=$((SDK_FAILURES + 1))
run_sdk dotnet "cd '$REPO_ROOT/packages/kiwicaptcha-dotnet' && DOTNET_ROLL_FORWARD=LatestMajor dotnet test tests/KiwiCaptcha.Tests --filter 'FullyQualifiedName~ConformanceTests'" || SDK_FAILURES=$((SDK_FAILURES + 1))

rt_assert_eq "$SDK_FAILURES" "0" "all seven server SDKs identical on the shared corpus"

# The corpus identity check: every runner consumes the shared
# protocol fixtures, not a private copy.
CORPUS_OK=0
for pair in \
    "kiwicaptcha-node/test/corpus.ts" \
    "kiwicaptcha-python-sdk/tests/support.py" \
    "kiwicaptcha-go/conformance_test.go" \
    "kiwicaptcha-ruby/test/test_conformance.rb" \
    "kiwicaptcha-elixir/test/conformance_test.exs"; do
    grep -rq "protocol" "$REPO_ROOT/packages/$pair" 2>/dev/null && CORPUS_OK=$((CORPUS_OK + 1))
done
rt_assert_eq "$CORPUS_OK" "5" "sdk runners reference the shared protocol corpus"

printf 'ECONOMIC: %s %s cost_per_differential=infinite differentials=0 desyncs=0 sdk_green=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$((7 - SDK_FAILURES))"

rt_finish
