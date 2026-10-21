<?php
// Fresh probe: per-request cost breakdown of issue / solve / verify.
// Each verify uses a freshly issued token (one-shot semantics).
$REPO = dirname(__DIR__, 2);
require $REPO . '/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\Verifier;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Config;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;

$SECRET = str_repeat('bench-key-0123456789abcdef', 2);
$config = new Config(secretKey: $SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, minDurationMs: 0);
$now = (int) (microtime(true) * 1000);

function freshStack(Config $config, string $secret): array {
    global $now;
    $storage = new ArrayStorage();
    $issuer = new Issuer($config, $storage, now: static fn (): int => $now);
    $verifier = new Verifier($storage, now: static fn (): int => $now, acceptLegacyV1: true);
    return [$issuer, $verifier, $storage];
}
function solve(\KiwiCaptcha\Challenge $ch): int {
    $salt = base64_decode($ch->salt, true);
    $c = 0;
    do { $h = hash('sha256', $ch->prefix.$c.$salt, true); $c++; }
    while (Verifier::leadingZeroBits($h) < $ch->targetBits);
    return $c - 1;
}

// Warm-up: derive lazy keys, JIT-compile the hot paths.
[$wi, $wv, $wstorage] = freshStack($config, $SECRET);
$ch = $wi->issue('login', '203.0.113.9');
$wv->verify(SolutionToken::create($ch->nonce, solve($ch), 5000, [])->encode(), $SECRET, 'login', '203.0.113.9');

$N = 300;
$ip = '203.0.113.9';
$issueUs = 0.0; $solveUs = 0.0; $verifyUs = 0.0; $verifyOk = 0;
for ($i = 0; $i < $N; $i++) {
    $t = hrtime(true);
    [$issuer, $verifier, $storage] = freshStack($config, $SECRET);
$ch = $issuer->issue('login', $ip);
    $issueUs += (hrtime(true) - $t) / 1000;
    $t = hrtime(true);
    $counter = solve($ch);
    $solveUs += (hrtime(true) - $t) / 1000;
    $t = hrtime(true);
    $tok = SolutionToken::create($ch->nonce, $counter, 5000, [])->encode();
    $out = $verifier->verify($tok, $SECRET, 'login', $ip, nowNs: (int) (microtime(true) * 1e9));
    $verifyUs += (hrtime(true) - $t) / 1000;
    if ($out->isOk()) $verifyOk++;
}
printf("N=%d\n", $N);
printf("issue:   %8.1f us/call\n", $issueUs / $N);
printf("solve:   %8.1f us/call (target 8 bits, variable)\n", $solveUs / $N);
printf("token+verify: %8.1f us/call  (verified %d/%d ok)\n", $verifyUs / $N, $verifyOk, $N);

// Fresh-stack cost (includes lazy DerivedKeys) vs warmed
$t = hrtime(true);
for ($i = 0; $i < 50; $i++) {
    [$fi, $fv] = freshStack($config, $SECRET);
    $c2 = $fi->issue('login', $ip);
    $fv->verify(SolutionToken::create($c2->nonce, solve($c2), 5000, [])->encode(), $SECRET, 'login', $ip);
}
printf("fresh stack issue+verify: %8.1f us/call (incl. per-request setup)\n", (hrtime(true) - $t) / 1000 / 50);
