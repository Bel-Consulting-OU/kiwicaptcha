<?php

declare(strict_types=1);

/**
 * d32.whitebox.php — the D3.2 white-box execution forgery stage: the
 * full-knowledge adversary who has read the published verifier source
 * and reimplements the five version-6 acceptance envelopes. No browser,
 * no layout engine, no microtasks. Against REAL execution programs
 * issued by this campaign's wire instance (execution armed, real
 * execution_key), the forger emits a trace and the real
 * ExecutionChallengeGenerator::verifyExecutedTrace judges it.
 *
 * This is the honest measurement under the red-team program's
 * full-knowledge adversary rule. The naive oracle rejects 100 percent
 * only because it never implemented the envelopes; that figure is not a
 * full-knowledge number. Version 6 is supplementary evidence that costs
 * one reading of the source — the same class as v1-v5 — NOT a browser
 * boundary. The risk engine must never weight it as proof of a real
 * browser.
 *
 * Usage: php d32.whitebox.php <wire-base-url> <n> <exec-key>
 * Prints one JSON line:
 * {whitebox_attempted, whitebox_passed, whitebox_pass_rate, ...}
 */

// The white-box forger lives in the php-core test support namespace
// (KiwiCaptcha\Tests\Support), which the package's own vendor dev
// autoload exposes. Override with KIWI_RT_PHP_AUTOLOAD when needed.
$autoload = getenv('KIWI_RT_PHP_AUTOLOAD')
    ?: dirname(__DIR__, 4) . '/packages/kiwicaptcha-php/vendor/autoload.php';
require $autoload;

use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Tests\Support\WhiteBoxEnvelopeForger;

$base = rtrim((string) ($argv[1] ?? 'http://127.0.0.1:6470'), '/');
$n = max(1, (int) ($argv[2] ?? 25));
$execKey = (string) ($argv[3] ?? '');

if ($execKey === '') {
    fwrite(STDERR, "d32.whitebox: missing execution key\n");
    exit(2);
}

/**
 * Fetch one execution-armed challenge from the wire.
 *
 * @return array{program: string, nonce: string}|null
 */
function d32FetchChallenge(string $base): ?array
{
    $ch = curl_init($base . '/challenge');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['scope' => 'login']),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
    ]);
    $body = curl_exec($ch);
    unset($ch);
    if (!is_string($body)) {
        return null;
    }
    $doc = json_decode($body, true);
    if (!is_array($doc)) {
        return null;
    }
    // The challenge document carries the execution program and the
    // nonce the record is bound to.
    $program = (string) ($doc['execution_program'] ?? '');
    $nonce = (string) ($doc['nonce'] ?? '');
    if ($program === '' || $nonce === '') {
        return null;
    }

    return ['program' => $program, 'nonce' => $nonce];
}

$attempted = 0;
$passed = 0;
$missing = 0;
for ($i = 0; $i < $n; $i++) {
    $challenge = d32FetchChallenge($base);
    if ($challenge === null) {
        $missing++;
        // Fall back to a locally generated v6 program with the same
        // deployment key so the measurement never silently shrinks.
        $nonce = base64_encode(hash('sha256', 'd32-whitebox-fallback-' . $i, true));
        $program = ExecutionChallengeGenerator::generate($execKey, $nonce, 'login', 'login-action', 6);
    } else {
        $program = $challenge['program'];
        $nonce = $challenge['nonce'];
    }
    $decoded = ExecutionChallengeGenerator::decode($program);
    if ($decoded === null) {
        $missing++;
        continue;
    }
    $trace = WhiteBoxEnvelopeForger::forge($decoded);
    $attempted++;
    if (ExecutionChallengeGenerator::verifyExecutedTrace($program, $nonce, $trace) !== null) {
        $passed++;
    }
}

$passRate = $attempted > 0 ? round($passed / $attempted, 6) : 0.0;
echo json_encode([
    'whitebox_attempted' => $attempted,
    'whitebox_passed' => $passed,
    'whitebox_rejected' => $attempted - $passed,
    'whitebox_pass_rate' => $passRate,
    'whitebox_rejection_rate' => round(1.0 - $passRate, 6),
    'whitebox_wire_misses' => $missing,
    'whitebox_class' => 'full_knowledge_envelope_forger',
    'whitebox_verdict' => $passed === $attempted && $attempted > 0
        ? 'v6_envelope_is_not_a_browser_boundary'
        : 'partial',
]), "\n";
