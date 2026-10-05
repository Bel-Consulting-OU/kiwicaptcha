#!/bin/sh
# The master runner for integrations-platforms: every locally runnable
# test, one exit code. Skips document themselves when a toolchain is
# missing. Usage: sh tests/run-all.sh (cwd irrelevant).
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

fail=0
run() {
    name=$1
    shift
    if "$@" >/tmp/kiwi-runall-$$ 2>&1; then
        echo "ok:   $name"
    else
        echo "FAIL: $name (see below)" >&2
        cat /tmp/kiwi-runall-$$ >&2
        fail=1
    fi
    rm -f /tmp/kiwi-runall-$$
}

echo "== gateway bundle (nginx, caddy, traefik + the shared endpoint) =="
run "gateway: php -l + unit + live matrix + nginx -t" sh "$HERE/run.sh"

echo "== wordpress =="
run "wordpress: plugin tests" php "$ROOT/wordpress/tests/test-wordpress-plugin.php"

echo "== drupal =="
run "drupal: pure logic tests" php "$ROOT/drupal/tests/test-kiwicaptcha-pure.php"

echo "== joomla =="
run "joomla: plugin contract tests" php "$ROOT/joomla/tests/test-kiwicaptcha-plugin.php"

echo "== phpbb =="
run "phpbb: extension tests" php "$ROOT/phpbb/ext/kiwi/captcha/tests/test-client.php"

echo "== flarum =="
run "flarum: middleware tests" php "$ROOT/flarum/tests/test-middleware.php"

echo "== discourse =="
if command -v ruby >/dev/null 2>&1; then
    run "discourse: verifier tests" ruby "$ROOT/discourse/tests/verifier_test.rb"
else
    echo "skip: ruby not installed"
fi

echo "== authentik =="
if command -v python3 >/dev/null 2>&1; then
    run "authentik: verify module tests" python3 "$ROOT/authentik/tests/test_kiwi_verify.py"
else
    echo "skip: python3 not installed"
fi

echo "== zitadel =="
if command -v node >/dev/null 2>&1; then
    run "zitadel: action script tests" node "$ROOT/zitadel/tests/kiwi-signup-guard.test.mjs"
else
    echo "skip: node not installed"
fi

echo "== keycloak =="
if command -v java >/dev/null 2>&1 && command -v javac >/dev/null 2>&1; then
    classes=$(mktemp -d)
    if javac -d "$classes" \
        "$ROOT/keycloak/src/main/java/ee/bel/kiwi/keycloak/KiwiVerifyClient.java" \
        "$ROOT/keycloak/src/test/java/ee/bel/kiwi/keycloak/KiwiVerifyClientTest.java" >/dev/null 2>&1; then
        run "keycloak: verify client tests" java -cp "$classes" ee.bel.kiwi.keycloak.KiwiVerifyClientTest
    else
        echo "FAIL: keycloak test compile" >&2
        fail=1
    fi
    rm -rf "$classes"
else
    echo "skip: java/javac not installed"
fi

echo "== symfony bundle: the migrate command =="
symfony_root=$(CDPATH= cd -- "$ROOT/../packages/kiwicaptcha/integrations/symfony" && pwd)
if [ -x "$symfony_root/vendor/bin/phpunit" ]; then
    (cd "$symfony_root" && vendor/bin/phpunit tests/KiwiCaptchaMigrateCommandTest.php) >/tmp/kiwi-runall-$$ 2>&1
    if [ $? -eq 0 ]; then
        echo "ok:   migrate command tests"
    else
        echo "FAIL: migrate command tests" >&2
        cat /tmp/kiwi-runall-$$ >&2
        fail=1
    fi
    rm -f /tmp/kiwi-runall-$$
else
    echo "skip: bundle vendor missing (run composer install in the bundle)"
fi

echo ""
if [ "$fail" -eq 0 ]; then
    echo "ALL SUITES GREEN"
    exit 0
fi
echo "FAILURES ABOVE" >&2
exit 1
