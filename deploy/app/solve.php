<?php

declare(strict_types=1);

/**
 * The e2e solve helper of the reference deployment (CLI only, never a
 * served route: the router answers every HTTP request itself and the
 * php -S docroot never exposes this file).
 *
 * Replicates the canonical SHA-256 proof-of-work loop the browser
 * worker runs (packages/kiwicaptcha-wasm/assets/kiwi-worker.js): the
 * candidate hash is sha256(prefix bytes . ASCII decimal counter . salt
 * bytes), and a solution is the first counter whose hash carries at
 * least targetBits leading zero bits. The challenge document is the
 * exact JSON body POST /challenge returns; the printed token is the
 * exact body POST /verify accepts.
 *
 * Usage:
 *   php solve.php /path/to/challenge.json     (challenge file path)
 *   php solve.php < challenge.json            (challenge on stdin)
 *
 * Only sha256 challenges are solvable here. The helper carries no
 * credentials: the secret never reaches the solver, the challenge
 * document is public by design, and the token is built with the same
 * public core SolutionToken API the browser uses.
 */

require __DIR__.'/vendor/autoload.php';

use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;

/** The solver cap of the widget, mirrored from the core constant. */
const SOLVE_MAX_HASHES = 5_000_000;

function fail(string $message): never
{
    fwrite(STDERR, "solve: $message\n");
    exit(1);
}

$raw = null;
if (isset($argv[1]) && is_string($argv[1]) && $argv[1] !== '') {
    $raw = @file_get_contents($argv[1]);
    if ($raw === false) {
        fail('cannot read the challenge file '.$argv[1]);
    }
} else {
    $raw = stream_get_contents(STDIN);
    if ($raw === false || $raw === '') {
        fail('no challenge document on stdin');
    }
}
try {
    $challenge = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
} catch (\JsonException $e) {
    fail('challenge document is not valid JSON: '.$e->getMessage());
}
if (!is_array($challenge)) {
    fail('challenge document must be a JSON object');
}
foreach (['nonce', 'challenge', 'salt', 'prefix', 'targetBits'] as $field) {
    if (!isset($challenge[$field]) || !is_string($challenge[$field]) && !is_int($challenge[$field])) {
        fail("challenge document is missing the $field field");
    }
}
if (($challenge['algorithm'] ?? 'sha256') !== 'sha256') {
    fail('only the sha256 algorithm is solvable by this helper (got '.($challenge['algorithm'] ?? 'none').')');
}
$nonce = (string) $challenge['nonce'];
$prefix = (string) $challenge['prefix'];
$saltBytes = base64_decode((string) $challenge['salt'], true);
if ($saltBytes === false) {
    fail('challenge salt is not canonical base64');
}
$targetBits = (int) $challenge['targetBits'];
if ($targetBits < 1 || $targetBits > 20) {
    fail('challenge targetBits out of range');
}

$started = hrtime(true);
$counter = 0;
while ($counter < SOLVE_MAX_HASHES) {
    $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
    if (Verifier::leadingZeroBits($hash) >= $targetBits) {
        break;
    }
    ++$counter;
}
if ($counter >= SOLVE_MAX_HASHES) {
    fail('no solution found within the 5,000,000-hash solver cap');
}
$durationMs = (int) ((hrtime(true) - $started) / 1_000_000);

echo SolutionToken::create($nonce, $counter, $durationMs, [])->encode(), "\n";
