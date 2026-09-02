#!/usr/bin/env bash
#
# tools/ci/n1-compat.sh - N-1 compatibility lane (frozen previous release)
#
# Usage:
#   bash tools/ci/n1-compat.sh <frozen-checkout> [<current-checkout>]
#
# The first argument is a git worktree (or any checkout) of b32ec01e,
# the last backend revision that predates the Kiwi-Execution-Max-Version
# capability header. The lane boots that frozen revision's fixture
# server (tests/browser/router.php under php -S, backed by the frozen
# PHP core vendor) and drives the current widget's request shapes
# against it:
#
#   a) POST /challenge?execution=1 with the closed JSON body
#      {"scope":"login"} plus the new capability header must answer
#      HTTP 200 with an execution_program whose decoded op_version is
#      1: the frozen server has no knowledge of the header, so a
#      current widget's header must be ignored - never a 422, never a
#      version bump.
#   b) POST /challenge with a foreign body field (execution_max_version)
#      must answer HTTP 422 with the `UNKNOWN_FIELDS` error code: the
#      strict closed body set of that generation lives in the real
#      Symfony ChallengeController (the fixture router only mirrors
#      issuance), so the probe drives that controller directly with a
#      Symfony Request, exactly like the frozen bundle's own
#      ChallengeFlowTest does. This is the constraint that forces the
#      capability onto a request header rather than a body field.
#   c) POST /challenge?execution=1 without the header (a widget of
#      the same generation) must answer HTTP 200 with a version-1
#      program: old widget over old backend keeps working.
#
# An optional second argument (a checkout of the current revision)
# runs the mirror sanity: the same two requests against the current
# fixture server must issue op_version 2 with the header and 1
# without it. The workflow lane omits it - the current side of the
# rectangle is owned by the browser/Playwright suites - but a local
# run can pass it to see the whole rectangle in one output.
#
# Requirements: php CLI, composer, curl. No Redis is needed: the
# frozen fixture mints with ArrayStorage plus temp files, and the
# controller probe needs no services beyond an Issuer.
#
# Exit status: 0 when every assertion passes, 1 on an assertion
# failure, 2 on usage or operational errors.

set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

FROZEN="${1:-}"
CURRENT="${2:-}"
if [ -z "$FROZEN" ]; then
    echo "usage: $0 <frozen-checkout> [<current-checkout>]" >&2
    exit 2
fi
[ -d "$FROZEN/packages/kiwicaptcha-php" ] || die "not a repository checkout: $FROZEN"
FROZEN=$(cd "$FROZEN" && pwd)
if [ -n "$CURRENT" ]; then
    [ -d "$CURRENT/packages/kiwicaptcha-php" ] || die "not a repository checkout: $CURRENT"
    CURRENT=$(cd "$CURRENT" && pwd)
fi

# php -S servers this lane boots (pids are whitespace-separated);
# the EXIT trap kills any that are still up.
SERVER_PIDS=""

RUN_TMP=$(mktemp -d "${TMPDIR:-/tmp}/kiwi-n1.XXXXXX")
cleanup() {
    if [ -n "$SERVER_PIDS" ]; then
        # shellcheck disable=SC2086 # pids are intentionally word-split
        kill $SERVER_PIDS 2>/dev/null || true
    fi
    rm -rf "$RUN_TMP"
}
trap cleanup EXIT INT TERM

# install_vendor <checkout-package-dir> <label>: composer install when
# the vendor is missing (the frozen tree has no committed vendor).
install_vendor() {
    local dir=$1 label=$2
    if [ -f "$dir/vendor/autoload.php" ]; then
        echo "[n1-compat] vendor already present: $label"
    else
        echo "[n1-compat] composer install --no-interaction --prefer-dist: $label"
        (cd "$dir" && composer install --no-interaction --prefer-dist) \
            || die "composer install failed in $label"
    fi
}

# pick_free_port: bind an ephemeral listener, read the assigned port,
# close it, and hand the number back (php is guaranteed present).
pick_free_port() {
    # shellcheck disable=SC2016 # PHP variables inside single-quoted code
    php -r '
        $srv = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
        if ($srv === false) { fwrite(STDERR, "no free port: $errstr\n"); exit(1); }
        $name = stream_socket_get_name($srv, false);
        $port = (int) substr((string) $name, strrpos((string) $name, ":") + 1);
        fclose($srv);
        echo $port, "\n";
    '
}

# boot_fixture <checkout> <port> <logfile>: start the checkout's
# fixture router and wait until GET / answers.
boot_fixture() {
    local checkout=$1 port=$2 log=$3
    local _
    (
        cd "$checkout/tests/browser"
        exec php -S "127.0.0.1:$port" "$checkout/tests/browser/router.php"
    ) >"$log" 2>&1 &
    SERVER_PIDS="$SERVER_PIDS $!"
    for _ in $(seq 1 60); do
        if curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    die "fixture server did not become ready (server log: $log)"
}

# post_challenge <port> <header-name> <header-value> <outfile>:
# POST /challenge?execution=1 with the current widget body shape
# {"scope":"login"}; an empty header-name sends no capability header.
# Prints the HTTP status code.
post_challenge() {
    local port=$1 header_name=$2 header_value=$3 outfile=$4
    if [ -n "$header_name" ]; then
        curl -sS -o "$outfile" -w '%{http_code}' \
            -X POST "http://127.0.0.1:$port/challenge?execution=1" \
            -H 'Content-Type: application/json' \
            -H "$header_name: $header_value" \
            --data '{"scope":"login"}'
    else
        curl -sS -o "$outfile" -w '%{http_code}' \
            -X POST "http://127.0.0.1:$port/challenge?execution=1" \
            -H 'Content-Type: application/json' \
            --data '{"scope":"login"}'
    fi
}

# php/assert_program.php: decode a response's execution_program with
# the given checkout's core and require the expected op_version.
cat > "$RUN_TMP/assert_program.php" <<'PHP'
<?php

declare(strict_types=1);

// argv: [core-autoload] [response-json] [expected-op-version]
require $argv[1];
$data = json_decode((string) file_get_contents($argv[2]), true);
if (!is_array($data)) {
    fwrite(STDERR, "response is not a JSON object\n");
    exit(1);
}
if (!isset($data['execution_program']) || !is_string($data['execution_program']) || $data['execution_program'] === '') {
    fwrite(STDERR, 'response carries no execution_program (keys: '.implode(',', array_keys($data)).")\n");
    exit(1);
}
$program = \KiwiCaptcha\ExecutionChallengeGenerator::decode($data['execution_program']);
if ($program === null) {
    fwrite(STDERR, "execution_program failed to decode\n");
    exit(1);
}
$expected = (int) $argv[3];
if ($program['op_version'] !== $expected) {
    fwrite(STDERR, 'op_version '.$program['op_version']." does not equal expected $expected\n");
    exit(1);
}
echo 'format='.$program['format'].' scope='.$program['scope'].' action='.$program['action']
    .' op_version='.$program['op_version'].' ops='.\count($program['ops'])."\n";
PHP

# php/strict_body.php: drive the frozen generation's real
# ChallengeController (the code that owns the closed body contract)
# with Symfony Requests shaped like the current widget's wire traffic.
cat > "$RUN_TMP/strict_body.php" <<'PHP'
<?php

declare(strict_types=1);

// argv: [bundle-autoload]
require $argv[1];

use Symfony\Component\HttpFoundation\Request;

$issuer = new \KiwiCaptcha\Issuer(new \KiwiCaptcha\Config(
    secretKey: '0123456789abcdef0123456789abcdef',
    algorithm: \KiwiCaptcha\PoWAlgorithm::Sha256,
    targetBits: 8,
    ttlSecs: 120,
), new \KiwiCaptcha\Storage\ArrayStorage());
$controller = new \BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController($issuer);

$makeRequest = static function (string $body, array $extraServer = []): Request {
    $server = ['REMOTE_ADDR' => '127.0.0.1', 'CONTENT_TYPE' => 'application/json'] + $extraServer;

    return Request::create('/challenge', 'POST', [], [], [], $server, $body);
};
$probe = static function (string $body, array $extraServer = []) use ($controller, $makeRequest): array {
    $response = $controller->challenge($makeRequest($body, $extraServer));

    return [$response->getStatusCode(), json_decode((string) $response->getContent(), true)];
};

[$status, $payload] = $probe('{"scope":"login","execution_max_version":2}');
if ($status !== 422 || ($payload['error']['code'] ?? null) !== 'UNKNOWN_FIELDS') {
    fwrite(STDERR, "expected 422 UNKNOWN_FIELDS for a foreign body field, got $status ".json_encode($payload)."\n");
    exit(1);
}
echo 'foreign body field execution_max_version -> 422 '.($payload['error']['code'] ?? '').' ('.($payload['error']['message'] ?? '').")\n";

[$status, $payload] = $probe('{"scope":"login"}', ['HTTP_KIWI_EXECUTION_MAX_VERSION' => '2']);
if ($status !== 200) {
    fwrite(STDERR, "expected 200 for the closed body plus the capability header, got $status\n");
    exit(1);
}
echo "closed body plus capability header -> 200 (the frozen controller never reads the foreign header)\n";
PHP

# assert_program <checkout> <response-json> <expected-op-version> <label>
assert_program() {
    local checkout=$1 response_json=$2 expected=$3 label=$4
    local out err
    out="$RUN_TMP/assert-$label.out"
    err="$RUN_TMP/assert-$label.err"
    if ! php "$RUN_TMP/assert_program.php" \
        "$checkout/packages/kiwicaptcha-php/vendor/autoload.php" \
        "$response_json" "$expected" >"$out" 2>"$err"; then
        cat "$err" >&2
        fail "$label: program assertion failed"
    fi
}

# ---------------------------------------------------------------------------
# N-1 phase: the frozen revision answers the current request shapes.
# ---------------------------------------------------------------------------
echo "[n1-compat] frozen checkout: $FROZEN"
install_vendor "$FROZEN/packages/kiwicaptcha-php" "frozen PHP core"
install_vendor "$FROZEN/packages/kiwicaptcha/integrations/symfony" "frozen Symfony bundle"

FROZEN_PORT=$(pick_free_port)
FROZEN_LOG="$RUN_TMP/frozen-server.log"
boot_fixture "$FROZEN" "$FROZEN_PORT" "$FROZEN_LOG"
pass "frozen fixture server booted at http://127.0.0.1:$FROZEN_PORT"

RESP_A="$RUN_TMP/response-a.json"
CODE=$(post_challenge "$FROZEN_PORT" "Kiwi-Execution-Max-Version" "2" "$RESP_A")
if [ "$CODE" != "200" ]; then
    cat "$RESP_A" >&2
    fail "a) capability header plus closed body: expected HTTP 200 from the frozen server, got $CODE"
fi
assert_program "$FROZEN" "$RESP_A" 1 "a"
pass "a) capability header plus closed body -> HTTP 200; decoded program: $(cat "$RUN_TMP/assert-a.out")"

if php "$RUN_TMP/strict_body.php" \
    "$FROZEN/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php" \
    >"$RUN_TMP/b.out" 2>"$RUN_TMP/b.err"; then
    while IFS= read -r line; do
        pass "b) frozen controller: $line"
    done < "$RUN_TMP/b.out"
else
    cat "$RUN_TMP/b.err" >&2
    fail "b) strict closed-body contract assertions failed"
fi

RESP_C="$RUN_TMP/response-c.json"
CODE=$(post_challenge "$FROZEN_PORT" "" "" "$RESP_C")
if [ "$CODE" != "200" ]; then
    cat "$RESP_C" >&2
    fail "c) headerless request: expected HTTP 200 from the frozen server, got $CODE"
fi
assert_program "$FROZEN" "$RESP_C" 1 "c"
pass "c) headerless request -> HTTP 200; decoded program: $(cat "$RUN_TMP/assert-c.out")"

# ---------------------------------------------------------------------------
# Current-revision sanity phase (optional): the mirror of the rectangle
# against the current fixture server. The workflow lane omits this; the
# browser/Playwright suites own the current side.
# ---------------------------------------------------------------------------
if [ -n "$CURRENT" ]; then
    echo "[n1-compat] current-revision sanity: $CURRENT"
    install_vendor "$CURRENT/packages/kiwicaptcha-php" "current PHP core"
    # The fixture router declares classes that implement bundle
    # interfaces, so the bundle vendor must be present for the server
    # to boot (the same reason every fixture lane installs it).
    install_vendor "$CURRENT/packages/kiwicaptcha/integrations/symfony" "current Symfony bundle"
    CURRENT_PORT=$(pick_free_port)
    CURRENT_LOG="$RUN_TMP/current-server.log"
    boot_fixture "$CURRENT" "$CURRENT_PORT" "$CURRENT_LOG"
    pass "current fixture server booted at http://127.0.0.1:$CURRENT_PORT"

    RESP_D="$RUN_TMP/response-d.json"
    CODE=$(post_challenge "$CURRENT_PORT" "Kiwi-Execution-Max-Version" "2" "$RESP_D")
    if [ "$CODE" != "200" ]; then
        cat "$RESP_D" >&2
        fail "sanity) capability header plus closed body: expected HTTP 200 from the current server, got $CODE"
    fi
    assert_program "$CURRENT" "$RESP_D" 2 "sanity-header"
    pass "sanity) capability header plus closed body -> HTTP 200; decoded program: $(cat "$RUN_TMP/assert-sanity-header.out")"

    RESP_E="$RUN_TMP/response-e.json"
    CODE=$(post_challenge "$CURRENT_PORT" "" "" "$RESP_E")
    if [ "$CODE" != "200" ]; then
        cat "$RESP_E" >&2
        fail "sanity) headerless request: expected HTTP 200 from the current server, got $CODE"
    fi
    assert_program "$CURRENT" "$RESP_E" 1 "sanity-headerless"
    pass "sanity) headerless request -> HTTP 200; decoded program: $(cat "$RUN_TMP/assert-sanity-headerless.out")"
fi

echo "N-1 compatibility (frozen previous release): all assertions passed"
