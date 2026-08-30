#!/usr/bin/env bash
# perf-budget.sh — hard deterministic byte budgets for the widget assets
# and the challenge-response JSON.
#
# The three widget-driver copies (the canonical WASM asset, the core
# crate's embedded resources copy and the Symfony bundle's public copy)
# must each stay under the widget-driver cap. The measured baseline of
# every copy is 138,327 bytes (the committed bytes at f6c47cc plus the
# polymorphic-decoy rendering work, recorded 2026-08-30); the cap is
# 160,000 bytes, a 13.5% headroom, so a legitimate addition lands
# inside the cap and an accidental bloating regression trips it.
#
# The challenge-response JSON is measured by issuing real challenges
# through the PHP core (sha256 and argon2id, decoy armed) and encoding
# the wire shape of the bundle's /challenge response. The measured
# baseline is 957 bytes (the argon2id decoy-armed issuance, the largest
# variant, recorded 2026-08-30); the bound is 4096 bytes, a generous
# margin for future optional fields. The php-core vendor must be
# installed before this script runs (the CI job installs it).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

PHP_BIN="${PHP_BIN:-php}"
WIDGET_DRIVER_CAP=160000
CHALLENGE_JSON_CAP=4096

FAILED=0

for copy in packages/kiwicaptcha-wasm/assets/widget-driver.js \
            packages/kiwicaptcha/resources/widget-driver.js \
            packages/kiwicaptcha/integrations/symfony/Resources/public/widget-driver.js; do
  size=$(wc -c < "$copy")
  if [ "$size" -gt "$WIDGET_DRIVER_CAP" ]; then
    echo "perf budget FAILED: $copy is $size bytes (cap $WIDGET_DRIVER_CAP)" >&2
    FAILED=1
  else
    echo "widget-driver budget OK: $copy $size bytes (cap $WIDGET_DRIVER_CAP)"
  fi
done

challenge_size() {
  "$PHP_BIN" -r '
    require $argv[1]."/vendor/autoload.php";
    use KiwiCaptcha\Config;
    use KiwiCaptcha\Issuer;
    use KiwiCaptcha\PoWAlgorithm;
    use KiwiCaptcha\Storage\ArrayStorage;
    $algo = $argv[2] === "argon2id" ? PoWAlgorithm::Argon2id : PoWAlgorithm::Sha256;
    $config = new Config(
        secretKey: "0123456789abcdef0123456789abcdef",
        algorithm: $algo,
        ttlSecs: 120,
        mKib: $algo === PoWAlgorithm::Argon2id ? 64 : 0,
        t: $algo === PoWAlgorithm::Argon2id ? 3 : 1,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 4,
        minDurationMs: 0,
    );
    $challenge = (new Issuer($config, new ArrayStorage()))->issueWithDecoyField("login", "198.51.100.7");
    echo strlen(json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES));
  ' "packages/kiwicaptcha-php" "$1"
}

largest=0
for algo in sha256 argon2id; do
  size=$(challenge_size "$algo")
  echo "challenge-response budget ($algo): $size bytes (cap $CHALLENGE_JSON_CAP)"
  if [ "$size" -gt "$largest" ]; then
    largest=$size
  fi
done
if [ "$largest" -gt "$CHALLENGE_JSON_CAP" ]; then
  echo "perf budget FAILED: the challenge-response JSON is $largest bytes (cap $CHALLENGE_JSON_CAP)" >&2
  FAILED=1
fi

if [ "$FAILED" = "1" ]; then
  echo "perf-budget: byte budget exceeded — a regression or an intentional growth that needs a re-baselined cap" >&2
  exit 1
fi
echo "perf-budget: OK (all widget-driver copies and the challenge response within their caps)"
