<?php

declare(strict_types=1);

/**
 * Reference-deployment configuration bootstrap.
 *
 * EVERY setting of the deploy surface comes from the environment; no
 * file under deploy/ carries a fixed secret, a test credential or a
 * baked-in trapdoor value. The audit contract:
 *
 *   $secret       = requiredSecret('KIWI_SECRET_KEY', 32);
 *   $redisUrl     = requiredEnv('KC_REDIS_URL');
 *   $executionKey = optionalSecret('KIWI_EXECUTION_KEY', 32);
 *   $rswN         = optionalEnv('KIWI_RSW_MODULUS_N');
 *   $rswLambda    = optionalSecret('KIWI_RSW_LAMBDA');
 *
 * and exactly one of the rsw pair set throws
 * RuntimeException('KIWI_RSW_MODULUS_N and KIWI_RSW_LAMBDA must be
 * configured together'). The remaining knobs that shape the request
 * surface (algorithm profile selection, difficulty, lifetime) are
 * optional and carry documented defaults mirroring the Symfony bundle
 * configuration defaults.
 *
 * php -S re-includes the router once per request, so the configuration
 * is deliberately cheap to rebuild per request; nothing here caches
 * process-lifetime state.
 */

use KiwiCaptcha\Config;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;

/**
 * @throws RuntimeException when the variable is unset or empty
 */
function requiredEnv(string $name): string
{
    $value = getenv($name);
    if ($value === false || $value === '') {
        throw new RuntimeException(sprintf('required environment variable %s is not set', $name));
    }

    return $value;
}

/**
 * An optional environment variable; an unset or empty value is null.
 */
function optionalEnv(string $name): ?string
{
    $value = getenv($name);
    if ($value === false || $value === '') {
        return null;
    }

    return $value;
}

/**
 * @throws RuntimeException when the variable is unset or shorter than
 *                           $minBytes bytes
 */
function requiredSecret(string $name, int $minBytes): string
{
    $value = requiredEnv($name);
    if (strlen($value) < $minBytes) {
        throw new RuntimeException(sprintf(
            'environment variable %s must be at least %d bytes (got %d)',
            $name,
            $minBytes,
            strlen($value),
        ));
    }

    return $value;
}

/**
 * An optional secret; an unset or empty value is null, anything shorter
 * than $minBytes bytes throws.
 *
 * @throws RuntimeException when the variable is set but shorter than
 *                           $minBytes bytes
 */
function optionalSecret(string $name, int $minBytes = 1): ?string
{
    $value = optionalEnv($name);
    if ($value === null) {
        return null;
    }
    if (strlen($value) < $minBytes) {
        throw new RuntimeException(sprintf(
            'environment variable %s must be at least %d bytes when set (got %d)',
            $name,
            $minBytes,
            strlen($value),
        ));
    }

    return $value;
}

/**
 * An optional integer environment variable within [$min, $max]; an
 * unset or empty value is $default.
 *
 * @throws RuntimeException when the value is not a canonical decimal
 *                           integer within the bounds
 */
function optionalInt(string $name, int $default, int $min, int $max): int
{
    $value = optionalEnv($name);
    if ($value === null) {
        return $default;
    }
    if (preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) !== 1) {
        throw new RuntimeException(sprintf(
            'environment variable %s must be an integer (got "%s")',
            $name,
            $value,
        ));
    }
    $int = (int) $value;
    if ($int < $min || $int > $max) {
        throw new RuntimeException(sprintf(
            'environment variable %s must be within %d..%d (got %d)',
            $name,
            $min,
            $max,
            $int,
        ));
    }

    return $int;
}

/**
 * The configured deployment: the validated environment surface the
 * request endpoints share.
 *
 * @return array{
 *     secret: string,
 *     redisUrl: string,
 *     executionKey: string|null,
 *     rswModulusN: string|null,
 *     rswLambda: string|null,
 *     algorithm: PoWAlgorithm,
 *     shaTargetBits: int,
 *     argon2TargetBits: int,
 *     argonMKib: int,
 *     ttlSecs: int,
 *     minDurationMs: int|null,
 *     rswT: int,
 *     config: Config
 * }
 *
 * @throws RuntimeException on any invalid or missing configuration
 */
function kiwiDeployment(): array
{
    $secret = requiredSecret('KIWI_SECRET_KEY', 32);
    $redisUrl = requiredEnv('KC_REDIS_URL');
    $executionKey = optionalSecret('KIWI_EXECUTION_KEY', 32);
    $rswModulusN = optionalEnv('KIWI_RSW_MODULUS_N');
    $rswLambda = optionalSecret('KIWI_RSW_LAMBDA');
    if (($rswModulusN === null) !== ($rswLambda === null)) {
        throw new RuntimeException('KIWI_RSW_MODULUS_N and KIWI_RSW_LAMBDA must be configured together');
    }

    // Algorithm profile selection (server-owned, mirroring the bundle
    // configuration defaults). The rsw algorithm additionally requires
    // the trapdoor pair above.
    $algorithm = match (optionalEnv('KIWI_ALGORITHM') ?? 'sha256') {
        'sha256' => PoWAlgorithm::Sha256,
        'argon2id' => PoWAlgorithm::Argon2id,
        'rsw' => PoWAlgorithm::Rsw,
        default => throw new RuntimeException(
            'environment variable KIWI_ALGORITHM must be one of sha256, argon2id, rsw'
        ),
    };
    if ($algorithm === PoWAlgorithm::Rsw && ($rswModulusN === null || $rswLambda === null)) {
        throw new RuntimeException(
            'KIWI_RSW_MODULUS_N and KIWI_RSW_LAMBDA must be configured together when KIWI_ALGORITHM is rsw'
        );
    }

    // Optional difficulty/lifetime knobs with the bundle-mirroring
    // defaults; the core Config validates every bound anyway.
    $shaTargetBits = optionalInt('KIWI_SHA_TARGET_BITS', 18, 1, Config::MAX_SHA_TARGET_BITS);
    $argon2TargetBits = optionalInt('KIWI_ARGON2_TARGET_BITS', 8, 1, Config::MAX_ARGON2_TARGET_BITS);
    $ttlSecs = optionalInt('KIWI_TTL_SECS', 120, 1, Config::MAX_TTL_SECS);
    $rswT = optionalInt('KIWI_RSW_T', 75_000, Config::MIN_RSW_T, Config::MAX_RSW_T);
    // The memory-hard profile memory envelope (KiB); 65536 KiB is the
    // documented argon64 rung of the browser-solvable ladder.
    $argonMKib = optionalInt('KIWI_ARGON2_M_KIB', 65536, 8, 65536);
    // KIWI_MIN_DURATION_MS: unset = the core derives the floor from the
    // difficulty (the bundle default); 0 disables the server-measured
    // solve-timing floor.
    $minDurationMs = optionalEnv('KIWI_MIN_DURATION_MS');
    if ($minDurationMs !== null) {
        if (preg_match('/^(?:0|[1-9][0-9]*)$/D', $minDurationMs) !== 1) {
            throw new RuntimeException(sprintf(
                'environment variable KIWI_MIN_DURATION_MS must be an integer (got "%s")',
                $minDurationMs,
            ));
        }
        $minDurationMs = (int) $minDurationMs;
        if ($minDurationMs < 0 || $minDurationMs >= $ttlSecs * 1000) {
            throw new RuntimeException(
                'environment variable KIWI_MIN_DURATION_MS must be >= 0 and below KIWI_TTL_SECS * 1000'
            );
        }
    }

    $deployment = [
        'secret' => $secret,
        'redisUrl' => $redisUrl,
        'executionKey' => $executionKey,
        'rswModulusN' => $rswModulusN,
        'rswLambda' => $rswLambda,
        'algorithm' => $algorithm,
        'shaTargetBits' => $shaTargetBits,
        'argon2TargetBits' => $argon2TargetBits,
        'argonMKib' => $argonMKib,
        'ttlSecs' => $ttlSecs,
        'minDurationMs' => $minDurationMs,
        'rswT' => $rswT,
    ];
    $deployment['config'] = kiwiConfig($deployment, $algorithm);

    return $deployment;
}

/**
 * Build the Config of a deployment profile: the configured algorithm
 * plus the shared difficulty/lifetime knobs of $deployment. Issuance
 * is server-owned: kiwiDeployment() builds exactly one config from the
 * environment, and the request endpoints always issue under it — a
 * client `algorithm` advertisement is compatibility metadata only and
 * never rebuilds the config.
 *
 * @param array<string, mixed> $deployment a kiwiDeployment() result
 */
function kiwiConfig(array $deployment, PoWAlgorithm $algorithm): Config
{
    return new Config(
        secretKey: (string) $deployment['secret'],
        algorithm: $algorithm,
        mKib: $algorithm === PoWAlgorithm::Argon2id ? (int) $deployment['argonMKib'] : 0,
        // The intentional protocol profile of the core: t >= 3, p == 1.
        t: 3,
        p: 1,
        targetBits: (int) $deployment['shaTargetBits'],
        argon2TargetBits: (int) $deployment['argon2TargetBits'],
        ttlSecs: (int) $deployment['ttlSecs'],
        minDurationMs: $deployment['minDurationMs'] !== null ? (int) $deployment['minDurationMs'] : null,
        executionKey: $deployment['executionKey'] !== null ? (string) $deployment['executionKey'] : null,
        rswModulusN: $deployment['rswModulusN'] !== null ? (string) $deployment['rswModulusN'] : null,
        rswLambda: $deployment['rswLambda'] !== null ? (string) $deployment['rswLambda'] : null,
        rswT: (int) $deployment['rswT'],
    );
}

/**
 * The real challenge-record store of the core, exactly the backend the
 * Symfony bundle wires from its redis_dsn setting: a Predis client on
 * the configured URL behind KiwiCaptcha\Storage\RedisStorage. The
 * reference deployment never falls back to temp-file persistence.
 *
 * The client fails fast (2 s connect/read timeouts) so a down store is
 * surfaced by the healthz probe instead of hanging the request.
 */
function kiwiStorage(string $redisUrl): RedisStorage
{
    $client = new \Predis\Client($redisUrl, [
        'timeout' => 2.0,
        'read_write_timeout' => 2.0,
    ]);

    return new RedisStorage($client);
}
