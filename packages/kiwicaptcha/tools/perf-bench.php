<?php

declare(strict_types=1);

/**
 * Synthetic-load benchmark for issuance and verification latency.
 *
 * Modes (all timing, all non-gating by design):
 *  - default (no flag): the SHA-256 workload against ArrayStorage, the
 *    original baseline mode. 400 challenges are issued, solved and
 *    verified at 8 target bits with 40 warmup iterations; issuance and
 *    verification are timed per iteration and the solve phase runs
 *    inside the workload without being a measured phase.
 *  - --redis: the same workload against the php-core RedisStorage on a
 *    real Redis. The mode activates only when a URL is available
 *    (KC_REDIS_URL, or --url, or the local default
 *    redis://127.0.0.1:6399) and the server answers ping. Without a
 *    reachable server it prints a loud note and exits 0, because the
 *    byte budgets in perf-budget.sh remain the gating gate and this
 *    timing signal is noisy-runner-tolerant by design. A per-run
 *    storage prefix keeps runs isolated; verification consumes each
 *    record, so no cleanup is needed.
 *  - --argon: Argon2id issuance + verification measured separately,
 *    through the admission gate (VerificationAdmissionGate) exactly as
 *    the verifier consumes it in production. The gate is an
 *    in-process token-set implementation inside this harness; the
 *    iteration count is small (20 + 5 warmup) because each verification
 *    derives a memory-hard hash (64 MiB, t=3, the argon64 production
 *    profile). The solve phase is memory-hard too: an Argon2id
 *    challenge is solved by Argon2id derivations, because the verifier
 *    re-derives the same hash. The harness therefore uses the 2-bit
 *    target (expected 4 derivations per solve) instead of the
 *    production 4-bit target to keep the non-measured solve phase
 *    bounded.
 *
 * Every mode gates on the same generous relative ratchet: the run
 * fails only when a p95 exceeds 3x its recorded baseline. The design is
 * noisy-runner-tolerant on purpose, because a shared CI runner can
 * stall a single iteration without any code regression. The byte and
 * count budgets live in perf-budget.sh, which gates deterministically;
 * this timing signal is loud but never a hard merge gate by itself.
 *
 * Baselines recorded 2026-08-30 on PHP 8.5 (local Mac):
 *  - SHA array: issuance p50 0.010 ms p95 0.026 ms; verification p50
 *    0.011 ms p95 0.037 ms.
 *  - Redis (local redis://127.0.0.1:6399): issuance p50 0.063 ms p95
 *    0.107 ms; verification p50 0.240 ms p95 0.408 ms.
 *  - Argon admission (64 MiB, t=3): issuance p50 0.032 ms p95 0.043 ms;
 *    verification p50 79.077 ms p95 83.331 ms.
 * Run with --update-baseline to print fresh values after a deliberate
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
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Verifier;

const UPDATE_BASELINE = '--update-baseline';
const WARMUP = 40;
const ITERATIONS = 400;
const ARGON_WARMUP = 5;
const ARGON_ITERATIONS = 20;
const RATCHET = 3.0;
const BASELINE_ISSUE_P50 = 0.010;
const BASELINE_ISSUE_P95 = 0.026;
const BASELINE_VERIFY_P50 = 0.011;
const BASELINE_VERIFY_P95 = 0.037;
const BASELINE_REDIS_ISSUE_P50 = 0.063;
const BASELINE_REDIS_ISSUE_P95 = 0.107;
const BASELINE_REDIS_VERIFY_P50 = 0.240;
const BASELINE_REDIS_VERIFY_P95 = 0.408;
const BASELINE_ARGON_ISSUE_P50 = 0.032;
const BASELINE_ARGON_ISSUE_P95 = 0.043;
const BASELINE_ARGON_VERIFY_P50 = 79.077;
const BASELINE_ARGON_VERIFY_P95 = 83.331;

/** The in-process admission gate of the harness: a token-set cap, the
 *  InProcessArgonGate contract without the bundle dependency. */
final class BenchAdmissionGate implements VerificationAdmissionGate
{
    /** @var array<string, true> */
    private array $leases = [];

    public function __construct(private readonly int $maxConcurrent = 8)
    {
    }

    public function acquire(): ?string
    {
        if ($this->maxConcurrent <= 0) {
            return 'disabled';
        }
        if (\count($this->leases) >= $this->maxConcurrent) {
            return null;
        }
        $token = bin2hex(random_bytes(16));
        $this->leases[$token] = true;

        return $token;
    }

    public function release(string $lease): void
    {
        unset($this->leases[$lease]);
    }
}

function percentile(array $samples, float $q): float
{
    sort($samples, SORT_NUMERIC);
    $index = (int) ceil($q / 100.0 * count($samples)) - 1;

    return $samples[max(0, $index)];
}

function shaConfig(): Config
{
    return new Config(
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
}

function argonConfig(): Config
{
    return new Config(
        secretKey: '0123456789abcdef0123456789abcdef',
        algorithm: PoWAlgorithm::Argon2id,
        mKib: 65536,
        t: 3,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 2,
        ttlSecs: 120,
        minDurationMs: 0,
    );
}

/** The memory-hard solve: derive Argon2id hashes until the target is met. */
function solveArgon($challenge): int
{
    $counter = 0;
    $saltBytes = base64_decode($challenge->salt, true);
    $memlimit = $challenge->mKib * 1024;
    do {
        $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, $challenge->t, $memlimit, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $counter++;
    } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

    return $counter - 1;
}

function solveCounter($challenge): int
{
    $counter = 0;
    $saltBytes = base64_decode($challenge->salt, true);
    do {
        $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
        $counter++;
    } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

    return $counter - 1;
}

function tokenFor($challenge, int $counter): string
{
    return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
}

/** @return array{p50: float, p95: float, n: int} */
function runWorkload(callable $issue, callable $solve, callable $verify, int $warmup, int $iterations): array
{
    $issueSamples = [];
    $verifySamples = [];
    for ($i = 0; $i < $warmup + $iterations; $i++) {
        $t0 = hrtime(true);
        $challenge = $issue();
        $t1 = hrtime(true);
        $token = tokenFor($challenge, $solve($challenge));
        $t2 = hrtime(true);
        $ok = $verify($token);
        $t3 = hrtime(true);
        if (!$ok) {
            fwrite(STDERR, "perf-bench: a verification failed in the workload\n");
            exit(1);
        }
        if ($i >= $warmup) {
            $issueSamples[] = ($t1 - $t0) / 1e6;
            $verifySamples[] = ($t3 - $t2) / 1e6;
        }
    }

    return [
        'issue' => ['p50' => percentile($issueSamples, 50), 'p95' => percentile($issueSamples, 95), 'n' => count($issueSamples)],
        'verify' => ['p50' => percentile($verifySamples, 50), 'p95' => percentile($verifySamples, 95), 'n' => count($verifySamples)],
    ];
}

function report(string $label, array $r, float $bIssueP50, float $bIssueP95, float $bVerifyP50, float $bVerifyP95): bool
{
    printf(
        "perf-bench: %s issuance p50 %.3f ms p95 %.3f ms (n=%d); verification p50 %.3f ms p95 %.3f ms (n=%d)\n",
        $label,
        $r['issue']['p50'],
        $r['issue']['p95'],
        $r['issue']['n'],
        $r['verify']['p50'],
        $r['verify']['p95'],
        $r['verify']['n'],
    );
    $failed = false;
    if ($r['issue']['p95'] > $bIssueP95 * RATCHET) {
        fwrite(STDERR, sprintf("perf-bench FAILED: %s issuance p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $label, $r['issue']['p95'], $bIssueP95 * RATCHET, $bIssueP95));
        $failed = true;
    }
    if ($r['verify']['p95'] > $bVerifyP95 * RATCHET) {
        fwrite(STDERR, sprintf("perf-bench FAILED: %s verification p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $label, $r['verify']['p95'], $bVerifyP95 * RATCHET, $bVerifyP95));
        $failed = true;
    }

    return !$failed;
}

$modeArray = !in_array('--redis', $argv, true) && !in_array('--argon', $argv, true) || in_array('--all', $argv, true);
$modeRedis = in_array('--redis', $argv, true) || in_array('--all', $argv, true);
$modeArgon = in_array('--argon', $argv, true) || in_array('--all', $argv, true);
$update = in_array(UPDATE_BASELINE, $argv, true);

$allOk = true;

if ($modeArray) {
    $storage = new ArrayStorage();
    $issuer = new Issuer(shaConfig(), $storage);
    $verifier = new Verifier($storage);
    $r = runWorkload(
        static fn () => $issuer->issue('login', '198.51.100.7'),
        solveCounter(...),
        static fn (string $token) => $verifier->verify($token, shaConfig()->secretKey, 'login', '198.51.100.7')->isOk(),
        WARMUP,
        ITERATIONS,
    );
    $allOk = report('SHA-256 array', $r, BASELINE_ISSUE_P50, BASELINE_ISSUE_P95, BASELINE_VERIFY_P50, BASELINE_VERIFY_P95) && $allOk;
}

if ($modeRedis) {
    $url = getenv('KC_REDIS_URL');
    if (!is_string($url) || $url === '') {
        $url = 'redis://127.0.0.1:6399';
    }
    if (!class_exists(\Predis\Client::class)) {
        fwrite(STDERR, "perf-bench: --redis requested but predis/predis is not installed; skipping the Redis mode\n");
        exit(1);
    }
    $redis = null;
    try {
        $redis = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
        $redis->ping();
    } catch (\Throwable $e) {
        fwrite(STDERR, sprintf("perf-bench NOTE: --redis requested but no Redis answers at %s (%s); the Redis mode is skipped — the timing signal is non-gating\n", $url, $e->getMessage()));
        $modeRedis = false;
    }
    if ($modeRedis) {
        $storage = new RedisStorage($redis, 'perf-bench-'.bin2hex(random_bytes(6)).'-');
        $issuer = new Issuer(shaConfig(), $storage);
        $verifier = new Verifier($storage);
        $r = runWorkload(
            static fn () => $issuer->issue('login', '198.51.100.7'),
            solveCounter(...),
            static fn (string $token) => $verifier->verify($token, shaConfig()->secretKey, 'login', '198.51.100.7')->isOk(),
            WARMUP,
            ITERATIONS,
        );
        $allOk = report('SHA-256 redis', $r, BASELINE_REDIS_ISSUE_P50, BASELINE_REDIS_ISSUE_P95, BASELINE_REDIS_VERIFY_P50, BASELINE_REDIS_VERIFY_P95) && $allOk;
    }
}

if ($modeArgon) {
    $storage = new ArrayStorage();
    $config = argonConfig();
    $issuer = new Issuer($config, $storage);
    $gate = new BenchAdmissionGate();
    $verifier = new Verifier($storage, $gate);
    $r = runWorkload(
        static fn () => $issuer->issue('login', '198.51.100.7'),
        solveArgon(...),
        static fn (string $token) => $verifier->verify($token, $config->secretKey, 'login', '198.51.100.7')->isOk(),
        ARGON_WARMUP,
        ARGON_ITERATIONS,
    );
    $allOk = report('Argon2id admission', $r, BASELINE_ARGON_ISSUE_P50, BASELINE_ARGON_ISSUE_P95, BASELINE_ARGON_VERIFY_P50, BASELINE_ARGON_VERIFY_P95) && $allOk;
}

if ($update) {
    exit(0);
}

if (!$allOk) {
    exit(1);
}
echo "perf-bench: OK (every measured p95 within its 3x noisy-runner-tolerant ratchet)\n";
