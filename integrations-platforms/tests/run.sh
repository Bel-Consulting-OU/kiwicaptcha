#!/bin/sh
# The integrations-platforms test runner: everything the local
# toolchain allows. Usage: sh tests/run.sh (paths resolve from the
# script location, cwd is irrelevant).
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
cd "$ROOT"

failures=0
check() {
    if [ "$1" -eq 0 ]; then
        echo "ok: $2"
    else
        echo "FAIL: $2" >&2
        failures=$((failures + 1))
    fi
}

echo "== php -l over every PHP file =="
lint_status=0
for f in $(find "$ROOT" -name '*.php' -not -path '*/vendor/*'); do
    php -l "$f" >/dev/null 2>&1 || { echo "php -l failed: $f" >&2; lint_status=1; }
done
check "$lint_status" "php -l clean"

echo "== unit tests: endpoint logic =="
php "$HERE/unit-kiwi-verify.php" >/dev/null
check $? "unit-kiwi-verify"

echo "== endpoint copies are byte-identical =="
cmp -s "$ROOT/kiwi-verify.php" "$ROOT/nginx/kiwi-verify.php" \
  && cmp -s "$ROOT/kiwi-verify.php" "$ROOT/caddy/kiwi-verify.php" \
  && cmp -s "$ROOT/kiwi-verify.php" "$ROOT/traefik/kiwi-verify.php"
check $? "kiwi-verify.php copies identical"

echo "== nginx config lint =="
if command -v nginx >/dev/null 2>&1; then
    tmpdir=$(mktemp -d)
    nginx -t -c "$ROOT/nginx/kiwi-gate.conf.example" -p "$tmpdir" >/dev/null 2>&1
    check $? "nginx -t on kiwi-gate.conf.example"

    # The gitea-forgejo sign-up fragment, composed into the example
    # config (a fragment alone is not a complete nginx config).
    python3 - "$tmpdir" "$ROOT" <<'PYEOF' >/dev/null 2>&1
import sys
tmpd, root = sys.argv[1], sys.argv[2]
base = open(root + '/nginx/kiwi-gate.conf.example').read()
frag = open(root + '/gitea-forgejo/nginx-signup-gate.conf').read()
body = "\n".join(l for l in frag.splitlines() if not l.strip().startswith('#'))
body = body.replace("""location @kiwi_gate_fault {
    return 503;
}""", "")
indented = "\n".join(("        " + l) if l.strip() else l for l in body.splitlines())
anchor = "        # ---- piece 3: the deny and fault outcomes"
open(tmpd + '/composed.conf', 'w').write(base.replace(anchor, indented + "\n" + anchor))
PYEOF
    nginx -t -c "$tmpdir/composed.conf" -p "$tmpdir" >/dev/null 2>&1
    check $? "nginx -t on the composed gitea-forgejo fragment"
    rm -rf "$tmpdir"
else
    echo "skip: nginx not installed; documented in nginx/README.md"
fi

echo "== live matrix: php -S + curl =="
if ! command -v curl >/dev/null 2>&1; then
    echo "skip: curl not installed"
    if [ "$failures" -eq 0 ]; then echo "ALL GREEN (skips excluded)"; exit 0; fi
    echo "$failures FAILURE(S)" >&2
    exit 1
fi

stub_port=17371
stub_bearer_port=17372
gate_port=18788
gate_bearer_port=18789
gate_nobearer_port=18793
gate_dead_port=18790
gate_redirect_port=18791
gate_compat_port=18792

php -S 127.0.0.1:$stub_port "$HERE/stub-kiwi-router.php" >/dev/null 2>&1 &
pid_stub=$!
STUB_BEARER=s3cret-1 php -S 127.0.0.1:$stub_bearer_port "$HERE/stub-kiwi-router.php" >/dev/null 2>&1 &
pid_stub_bearer=$!

KIWI_VERIFY_URL=http://127.0.0.1:$stub_port/verify KIWI_TRUSTED_PROXIES=127.0.0.0/8 \
  php -S 127.0.0.1:$gate_port "$HERE/endpoint-router.php" >/dev/null 2>&1 &
pid_gate=$!
KIWI_VERIFY_URL=http://127.0.0.1:$stub_bearer_port/verify KIWI_BEARER=s3cret-1 \
  php -S 127.0.0.1:$gate_bearer_port "$HERE/endpoint-router.php" >/dev/null 2>&1 &
pid_gate_bearer=$!
KIWI_VERIFY_URL=http://127.0.0.1:$stub_bearer_port/verify \
  php -S 127.0.0.1:$gate_nobearer_port "$HERE/endpoint-router.php" >/dev/null 2>&1 &
pid_gate_nobearer=$!
KIWI_VERIFY_URL=http://127.0.0.1:1/verify \
  php -S 127.0.0.1:$gate_dead_port "$HERE/endpoint-router.php" >/dev/null 2>&1 &
pid_gate_dead=$!
KIWI_VERIFY_URL=http://127.0.0.1:$stub_port/verify KIWI_DENY=302 \
  KIWI_REDIRECT=http://127.0.0.1:$gate_port/need-captcha \
  php -S 127.0.0.1:$gate_redirect_port "$HERE/endpoint-router.php" >/dev/null 2>&1 &
pid_gate_redirect=$!
KIWI_VERIFY_URL=http://127.0.0.1:$stub_port/verify KIWI_VERIFY_MODE=compat KIWI_BEARER=compat-secret \
  php -S 127.0.0.1:$gate_compat_port "$HERE/endpoint-router.php" >/dev/null 2>&1 &
pid_gate_compat=$!

trap 'kill $pid_stub $pid_stub_bearer $pid_gate $pid_gate_bearer $pid_gate_nobearer $pid_gate_dead $pid_gate_redirect $pid_gate_compat 2>/dev/null' EXIT

sleep 1
gate=http://127.0.0.1:$gate_port/kiwi-verify.php

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Kiwi-Token: good' "$gate")
check "$([ "$code" = 204 ]; echo $?)" "valid header token passes (got $code)"

headers=$(curl -s -D - -o /dev/null -H 'X-Kiwi-Token: bogus' "$gate")
echo "$headers" | grep -q ' 403 ' && echo "$headers" | grep -qi '^X-Kiwi-Deny: 1'
check $? "invalid token denies 403 with the marker"

code=$(curl -s -o /dev/null -w '%{http_code}' "$gate")
check "$([ "$code" = 403 ]; echo $?)" "missing token denies 403 (got $code)"

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Kiwi-Token: stale' "$gate")
check "$([ "$code" = 403 ]; echo $?)" "stale token denies 403 (got $code)"

code=$(curl -s -o /dev/null -w '%{http_code}' -d 'g-recaptcha-response=good' "$gate")
check "$([ "$code" = 204 ]; echo $?)" "incumbent form field token passes (got $code)"

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"token":"good","scope":"login"}' "$gate")
check "$([ "$code" = 204 ]; echo $?)" "json body token passes (got $code)"

code=$(curl -s -o /dev/null -w '%{http_code}' -b 'kiwi_token=good' "$gate")
check "$([ "$code" = 204 ]; echo $?)" "cookie token passes (got $code)"

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Kiwi-Token: good' -H 'X-Forwarded-For: 203.0.113.9' "$gate")
check "$([ "$code" = 204 ]; echo $?)" "trusted proxy ip forwarded (got $code)"

bearer_gate=http://127.0.0.1:$gate_bearer_port/kiwi-verify.php
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Kiwi-Token: good' "$bearer_gate")
check "$([ "$code" = 204 ]; echo $?)" "bearer credential accepted end to end (got $code)"

nobearer_gate=http://127.0.0.1:$gate_nobearer_port/kiwi-verify.php
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Kiwi-Token: good' "$nobearer_gate")
check "$([ "$code" = 503 ]; echo $?)" "missing bearer fails closed with 503 (got $code)"

dead_gate=http://127.0.0.1:$gate_dead_port/kiwi-verify.php
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Kiwi-Token: good' "$dead_gate")
check "$([ "$code" = 503 ]; echo $?)" "unreachable kiwi fails closed with 503 (got $code)"

redirect_gate=http://127.0.0.1:$gate_redirect_port/kiwi-verify.php
out=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'X-Kiwi-Token: bogus' "$redirect_gate")
echo "$out" | grep -q '^302 '
check $? "deny redirect is a 302 ($out)"

compat_gate=http://127.0.0.1:$gate_compat_port/kiwi-verify.php
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Kiwi-Token: good' "$compat_gate")
check "$([ "$code" = 204 ]; echo $?)" "compat mode verifies against the provider surface (got $code)"

echo ""
if [ "$failures" -eq 0 ]; then
    echo "ALL GREEN"
    exit 0
fi
echo "$failures FAILURE(S)" >&2
exit 1
