<?php

declare(strict_types=1);

/**
 * tools/ci/no-gmp-verify.php - the PHP core no-GMP surface proof.
 *
 * The CI lane "PHP core no-GMP" runs this script with ext-gmp absent
 * (setup-php installs json/openssl/sodium only and a preceding step
 * proves gmp is not loaded). The checks pin the GMP optionality
 * contract of the composer `suggest` entry:
 *
 *   1. the lane premise holds: ext-gmp is not loaded;
 *   2. the whole library surface autoloads and instantiates without
 *      gmp (a class-loading or declaration fatal would fail here);
 *   3. a sha256 challenge issues and verifies end to end;
 *   4. an argon2id challenge issues and verifies end to end
 *      (libsodium, never gmp);
 *   5. an execution-armed challenge issues and verifies end to end at
 *      the live grammar maximum (ExecutionChallengeGenerator::MAX_EXECUTION_VERSION),
 *      with the test-only browser-equivalent trace fixture producing
 *      the evidence exactly like the oracle suites;
 *   6. an RSW configuration refuses cleanly at construction with the
 *      documented missing-extension error - and only that error.
 *
 * Every check prints a PASS line; the script exits non-zero on the
 * first failure with the failure detail on STDERR. Run from anywhere;
 * the autoloader path is resolved relative to this file.
 */

require __DIR__.'/../../packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Rsw;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Support\ExecutionTraceFixture;
use KiwiCaptcha\Verifier;

const SECRET = '0123456789abcdef0123456789abcdef';
const EXECUTION_KEY = '0123456789abcdef0123456789abcdef';
const SCOPE = 'login';
const CLIENT_IP = '198.51.100.7';

$failures = 0;
function check(string $label, callable $fn): void
{
    global $failures;
    try {
        $fn();
        echo "no-GMP PASS: {$label}\n";
    } catch (\Throwable $e) {
        ++$failures;
        fwrite(STDERR, "no-GMP FAIL: {$label}: {$e->getMessage()}\n");
    }
}

function solveCounter(Config $config, \KiwiCaptcha\Challenge $challenge): int
{
    $saltBytes = base64_decode($challenge->salt, true);
    if ($saltBytes === false) {
        throw new \RuntimeException('the issued challenge must carry canonical base64 salt');
    }
    $counter = 0;
    do {
        $hash = $config->algorithm === PoWAlgorithm::Argon2id
            ? sodium_crypto_pwhash(
                32,
                $challenge->prefix.$counter,
                $saltBytes,
                $challenge->t,
                $challenge->mKib * 1024,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            )
            : hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
        ++$counter;
    } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

    return $counter - 1;
}

function issueVerify(Config $config, ?string $executionVersion = null): void
{
    $storage = new ArrayStorage();
    $issuer = new Issuer($config, $storage);
    $challenge = $executionVersion !== null
        ? $issuer->issueWithExecutionField(SCOPE, CLIENT_IP, true, executionAction: 'login-action', executionVersion: (int) $executionVersion)
        : $issuer->issue(SCOPE, CLIENT_IP);
    $counter = solveCounter($config, $challenge);

    $executionDigest = null;
    $executionTrace = null;
    if ($executionVersion !== null) {
        $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        if ($program === null) {
            throw new \RuntimeException('the issued execution program must parse');
        }
        $executionTrace = ExecutionTraceFixture::executedTraceForWithObservedHeight($program, 10);
        $executionDigest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $executionTrace);
        if ($executionDigest === null) {
            throw new \RuntimeException('the digest over the executed trace must compute');
        }
    }
    $token = SolutionToken::create(
        $challenge->nonce,
        $counter,
        5000,
        [],
        $executionDigest,
        $executionTrace !== null ? base64_encode($executionTrace) : null,
    )->encode();

    $outcome = (new Verifier($storage, now: static fn (): int => time()))
        ->verify($token, SECRET, SCOPE, CLIENT_IP);
    if (!$outcome->isOk()) {
        throw new \RuntimeException('the verifier rejected the solved challenge: '.$outcome->code());
    }
}

check('ext-gmp is not loaded (the lane premise)', static function (): void {
    if (\extension_loaded('gmp')) {
        throw new \RuntimeException('ext-gmp is loaded: the no-GMP lane premise is broken');
    }
});

check('the whole library surface autoloads without gmp', static function (): void {
    $classes = array_map(
        static fn (string $file): string => 'KiwiCaptcha\\'.basename($file, '.php'),
        glob(__DIR__.'/../../packages/kiwicaptcha-php/src/*.php') ?: [],
    );
    foreach ($classes as $class) {
        if (!class_exists($class) && !interface_exists($class) && !enum_exists($class)) {
            throw new \RuntimeException("{$class} must autoload");
        }
    }
});

check('sha256 issue + verify', static function (): void {
    issueVerify(new Config(
        secretKey: SECRET,
        targetBits: 8,
        ttlSecs: 120,
        minDurationMs: 0,
    ));
});

check('argon2id issue + verify', static function (): void {
    issueVerify(new Config(
        secretKey: SECRET,
        algorithm: PoWAlgorithm::Argon2id,
        mKib: 8,
        t: 3,
        p: 1,
        argon2TargetBits: 1,
        ttlSecs: 120,
        minDurationMs: 0,
    ));
});

check('execution issue + verify at the live grammar maximum', static function (): void {
    issueVerify(new Config(
        secretKey: SECRET,
        targetBits: 8,
        ttlSecs: 120,
        minDurationMs: 0,
        executionKey: EXECUTION_KEY,
    ), (string) ExecutionChallengeGenerator::MAX_EXECUTION_VERSION);
});

check('an rsw configuration refuses cleanly with the documented error', static function (): void {
    try {
        new Config(
            secretKey: SECRET,
            algorithm: PoWAlgorithm::Rsw,
            rswModulusN: base64_encode(str_repeat("\xff", 256)),
            rswLambda: base64_encode("\x02\x00"),
            rswT: 75_000,
        );
        throw new \RuntimeException('the rsw configuration must refuse without gmp');
    } catch (\InvalidArgumentException $e) {
        $expected = 'the rsw algorithm requires the gmp extension for its modular arithmetic';
        if ($e->getMessage() !== $expected) {
            throw new \RuntimeException(sprintf(
                'the missing-extension error must be the documented one, got: %s',
                $e->getMessage(),
            ));
        }
    }
    // The direct construction path fails identically (same guard).
    try {
        new Rsw('AAAA', 'AAAA');
        throw new \RuntimeException('direct Rsw construction must refuse without gmp');
    } catch (\InvalidArgumentException $e) {
        if ($e->getMessage() !== 'the rsw algorithm requires the gmp extension for its modular arithmetic') {
            throw new \RuntimeException('the direct Rsw guard must throw the documented error');
        }
    }
});

if ($failures !== 0) {
    fwrite(STDERR, "no-GMP verify FAILED: {$failures} check(s) failed\n");
    exit(1);
}
echo "no-GMP verify OK: the core needs gmp only for the optional rsw algorithm\n";
