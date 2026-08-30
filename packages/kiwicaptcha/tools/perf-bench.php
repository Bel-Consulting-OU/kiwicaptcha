<?php

declare(strict_types=1);

/**
 * Synthetic-load benchmark for issuance and verification latency.
 *
 * The workload is a fixed end-to-end transaction mix against a local
 * store (ArrayStorage, no network): 400 challenges are issued, solved
 * and verified with the SHA-256 proof of work at 8 target bits. The
 * first 40 iterations are warmup. Issuance and verification are timed
 * per iteration; the solve phase runs inside the workload but is not a
 * measured phase.
 *
 * The percentiles gate on generous relative ratchets: the run fails
 * only when p95 exceeds 3x its recorded baseline. The design is
 * noisy-runner-tolerant on purpose, because a shared CI runner can
 * stall a single iteration without any code regression. The byte and
 * count budgets live in perf-budget.sh, which gates deterministically;
 * this timing signal is loud but never a hard merge gate by itself.
 *
 * Baselines recorded 2026-08-30 on PHP 8.2 (local Mac): issuance p50
 * 0.008 ms p95 0.024 ms; verification p50 0.020 ms p95 0.060 ms. Run
 * with --update-baseline to print fresh values after a deliberate
 * change.
 */

$autoload = __DIR__.'/../../kiwicaptcha-php/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "perf-bench: kiwicaptcha-php vendor is missing at $autoload\n");
    exit(1);
}
require $autoload;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;

const UPDATE_BASELINE = '--update-baseline';
const WARMUP = 40;
const ITERATIONS = 400;
const RATCHET = 3.0;
const BASELINE_ISSUE_P50 = 0.008;
const BASELINE_ISSUE_P95 = 0.024;
const BASELINE_VERIFY_P50 = 0.020;
const BASELINE_VERIFY_P95 = 0.060;

function percentile(array $samples, float $q): float
{
    sort($samples, SORT_NUMERIC);
    $index = (int) ceil($q / 100.0 * count($samples)) - 1;

    return $samples[max(0, $index)];
}

$config = new Config(
    secretKey: '0123456789abcdef0123456789abcdef',
    algorithm: PoWAlgorithm::Sha256,
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 8,
    argon2TargetBits: 8,
    ttlSecs: 120,
    minDurationMs: 0,
);

$issueSamples = [];
$verifySamples = [];
for ($i = 0; $i < WARMUP + ITERATIONS; $i++) {
    $storage = new ArrayStorage();
    $issuer = new Issuer($config, $storage);

    $t0 = hrtime(true);
    $challenge = $issuer->issue('login', '198.51.100.7');
    $t1 = hrtime(true);

    $counter = 0;
    $saltBytes = base64_decode($challenge->salt, true);
    do {
        $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
        $counter++;
    } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
    --$counter;
    $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

    $t2 = hrtime(true);
    $outcome = (new Verifier($storage))->verify($token, $config->secretKey, 'login', '198.51.100.7');
    $t3 = hrtime(true);

    if (!$outcome->isOk()) {
        fwrite(STDERR, 'perf-bench: verification failed: '.$outcome->code()."\n");
        exit(1);
    }
    if ($i >= WARMUP) {
        $issueSamples[] = ($t1 - $t0) / 1e6;
        $verifySamples[] = ($t3 - $t2) / 1e6;
    }
}

$issueP50 = percentile($issueSamples, 50);
$issueP95 = percentile($issueSamples, 95);
$verifyP50 = percentile($verifySamples, 50);
$verifyP95 = percentile($verifySamples, 95);

printf("perf-bench: issuance p50 %.3f ms p95 %.3f ms (n=%d)\n", $issueP50, $issueP95, count($issueSamples));
printf("perf-bench: verification p50 %.3f ms p95 %.3f ms (n=%d)\n", $verifyP50, $verifyP95, count($verifySamples));

if (in_array(UPDATE_BASELINE, $argv, true)) {
    printf(
        "perf-bench: update the constants: ISSUE p50 %.3f p95 %.3f; VERIFY p50 %.3f p95 %.3f\n",
        $issueP50,
        $issueP95,
        $verifyP50,
        $verifyP95,
    );
    exit(0);
}

$failed = false;
if ($issueP95 > BASELINE_ISSUE_P95 * RATCHET) {
    fwrite(STDERR, sprintf("perf-bench FAILED: issuance p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $issueP95, BASELINE_ISSUE_P95 * RATCHET, BASELINE_ISSUE_P95));
    $failed = true;
}
if ($verifyP95 > BASELINE_VERIFY_P95 * RATCHET) {
    fwrite(STDERR, sprintf("perf-bench FAILED: verification p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $verifyP95, BASELINE_VERIFY_P95 * RATCHET, BASELINE_VERIFY_P95));
    $failed = true;
}

if ($failed) {
    exit(1);
}
echo "perf-bench: OK (both p95 values within the 3x noisy-runner-tolerant ratchet)\n";
