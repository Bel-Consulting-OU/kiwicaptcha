<?php

declare(strict_types=1);

/**
 * The request entry point of the reference deployment
 * (php -S 0.0.0.0:8080 -t /srv/kiwicaptcha/app /srv/kiwicaptcha/app/router.php).
 *
 * The surface mirrors the JSON wire contract the browser fixture
 * server and the Symfony bundle controller speak, backed by the REAL
 * core storage (RedisStorage on KC_REDIS_URL — never temp files) and
 * the REAL core issuer/verifier configured from the environment only:
 *
 *   GET  /healthz -> 200 {"ok":true} only after a real store round
 *                    trip (write, read, delete-if-pending); 503 with
 *                    {"ok":false,"code":"storage_probe_failed"} otherwise.
 *   POST /challenge -> 200 with the canonical challenge document
 *                    (nonce, challenge, salt, algorithm, mKib, t, p,
 *                    targetBits, ttlSecs, minDurationMs, prefix, plus
 *                    execution_program when the execution key is
 *                    configured and rsw_modulus for rsw challenges).
 *   POST /verify   -> 200 {"ok":true,"code":""} for a fresh valid
 *                    redemption; {"ok":false,"code":"<error>"} for
 *                    every failure. A replayed token answers
 *                    code "already_consumed": the consumed marker in
 *                    the core storage rejects it.
 *
 * Every other request is a 404 and every non-POST call to the POST
 * endpoints is a 405 with the Allow header, so php -S never serves a
 * static file and no app file is ever reachable by URL.
 */

require __DIR__.'/vendor/autoload.php';
require __DIR__.'/bootstrap.php';
require __DIR__.'/health.php';

use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;

/** The bounded shape of the request-body fields of both POST surfaces. */
const KIWI_IDENTIFIER_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';
/** Hard ceiling for a request body: the language is tiny. */
const KIWI_MAX_BODY_BYTES = 8192;

/**
 * Emit a JSON document with the given status and framing headers.
 *
 * @param array<string, mixed> $payload
 */
function kiwiJson(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store, private, max-age=0');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
}

/**
 * The canonical failure document: {"error":{"code":...,"message":...}}.
 */
function kiwiError(string $code, string $message, int $status): void
{
    kiwiJson(['error' => ['code' => $code, 'message' => $message]], $status);
}

/**
 * The strict request-body read of a POST surface: at most
 * KIWI_MAX_BODY_BYTES bytes, decoded as a flat JSON object whose keys
 * are all listed in $accepted.
 *
 * @param list<string> $accepted the closed set of accepted field names
 *
 * @return array<string, mixed>|null the decoded payload
 */
function kiwiReadBody(array $accepted): ?array
{
    $raw = file_get_contents('php://input');
    if ($raw === false) {
        $raw = '';
    }
    if (strlen($raw) > KIWI_MAX_BODY_BYTES) {
        kiwiError('BODY_TOO_LARGE', 'The request body must not exceed '.KIWI_MAX_BODY_BYTES.' bytes.', 413);

        return null;
    }
    if (trim($raw) === '') {
        return [];
    }
    try {
        $decoded = json_decode($raw, false, 32, JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
        kiwiError('INVALID_JSON', 'The request body must be a JSON object.', 422);

        return null;
    }
    if (!$decoded instanceof stdClass) {
        kiwiError('INVALID_JSON', 'The request body must be a JSON object.', 422);

        return null;
    }
    $payload = (array) $decoded;
    $unknown = array_values(array_diff(array_keys($payload), $accepted));
    if ($unknown !== []) {
        kiwiError('UNKNOWN_FIELDS', 'The request carries unknown fields: '.implode(', ', $unknown).'.', 422);

        return null;
    }

    return $payload;
}

/**
 * The bounded client IP of the request. php -S is single-hop by
 * construction, so the socket peer is the only identity input; no
 * forwarding header is ever trusted.
 */
function kiwiClientIp(): string
{
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
}

/**
 * POST /challenge: issue a challenge through the real core issuer.
 *
 * Server-owned semantics mirroring the bundle controller: the issued
 * algorithm always comes from the server. The deployment profile is
 * selected by KIWI_ALGORITHM; a client request for rsw is honored only
 * when the trapdoor pair is configured; the execution dimension is
 * armed on every issuance exactly when KIWI_EXECUTION_KEY is set.
 */
function kiwiChallenge(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        header('Allow: POST');
        kiwiError('METHOD_NOT_ALLOWED', 'The challenge endpoint accepts POST requests only.', 405);

        return;
    }
    $payload = kiwiReadBody(['scope', 'algorithm', 'request_binding']);
    if ($payload === null) {
        return;
    }
    foreach (['scope', 'algorithm', 'request_binding'] as $field) {
        if (array_key_exists($field, $payload) && $payload[$field] !== null && !is_string($payload[$field])) {
            kiwiError('INVALID_JSON', 'The challenge request fields must be strings.', 422);

            return;
        }
    }
    $scope = isset($payload['scope']) && $payload['scope'] !== '' ? (string) $payload['scope'] : 'default';
    $requestBinding = isset($payload['request_binding']) && $payload['request_binding'] !== ''
        ? (string) $payload['request_binding']
        : null;
    if (preg_match(KIWI_IDENTIFIER_PATTERN, $scope) !== 1) {
        kiwiError('INVALID_SCOPE', 'The scope must be 1-128 characters of [A-Za-z0-9._:-].', 422);

        return;
    }
    if ($requestBinding !== null && preg_match(KIWI_IDENTIFIER_PATTERN, $requestBinding) !== 1) {
        kiwiError('INVALID_REQUEST_BINDING', 'The request_binding must be 1-128 characters of [A-Za-z0-9._:-].', 422);

        return;
    }

    $deployment = kiwiDeployment();

    // The requested algorithm is a hint the server owns: sha256 and
    // argon2id are always available capabilities; rsw only when the
    // trapdoor pair is configured.
    $config = $deployment['config'];
    if (isset($payload['algorithm']) && $payload['algorithm'] !== '') {
        $algorithm = match ((string) $payload['algorithm']) {
            'sha256' => PoWAlgorithm::Sha256,
            'argon2id' => PoWAlgorithm::Argon2id,
            'rsw' => PoWAlgorithm::Rsw,
            default => null,
        };
        if ($algorithm === null) {
            kiwiError('INVALID_ALGORITHM', 'The algorithm must be one of sha256, argon2id, rsw.', 422);

            return;
        }
        if ($algorithm === PoWAlgorithm::Rsw && $deployment['rswModulusN'] === null) {
            kiwiError(
                'RSW_NOT_CONFIGURED',
                'The rsw algorithm is not configured: set KIWI_RSW_MODULUS_N and KIWI_RSW_LAMBDA together.',
                422,
            );

            return;
        }
        $config = kiwiConfig($deployment, $algorithm);
    }

    $storage = kiwiStorage($deployment['redisUrl']);
    $issuer = new Issuer($config, $storage);
    try {
        // The execution dimension is armed exactly when the deployment
        // configured the execution key (the mirror of the bundle gate:
        // the key is the arming condition).
        $challenge = $config->executionKey !== null
            ? $issuer->issueWithExecutionField($scope, kiwiClientIp(), true, $requestBinding)
            : $issuer->issue($scope, kiwiClientIp(), $requestBinding);
    } catch (\Throwable $e) {
        error_log(sprintf('kiwicaptcha deploy: challenge issuance failed: %s', $e->getMessage()));
        kiwiError('SERVICE_UNAVAILABLE', 'Challenge issuance is temporarily unavailable. Try again later.', 503);

        return;
    }
    kiwiJson($challenge->toArray());
}

/**
 * POST /verify: redeem a solution token through the real core verifier.
 *
 * The answer document is the fixture contract: 200 with
 * {"ok":bool,"code":string} where a fresh valid redemption carries
 * ok true and an empty code, and every failure carries the canonical
 * core error code. A second POST with the same token is refused as
 * "already_consumed": the atomic consume transition of the core
 * storage already guarantees single use, this surface only reports it.
 */
function kiwiVerify(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        header('Allow: POST');
        kiwiError('METHOD_NOT_ALLOWED', 'The verify endpoint accepts POST requests only.', 405);

        return;
    }
    $payload = kiwiReadBody(['token', 'scope']);
    if ($payload === null) {
        return;
    }
    $token = isset($payload['token']) && is_string($payload['token']) ? $payload['token'] : '';
    $scope = isset($payload['scope']) && is_string($payload['scope']) && $payload['scope'] !== ''
        ? $payload['scope']
        : 'default';
    $deployment = kiwiDeployment();

    // The transaction binding of the stored record, resolved exactly
    // like the browser fixture does before redemption: a challenge
    // minted bound to a transaction redeems only against that binding.
    $binding = null;
    try {
        $nonce = $token !== '' ? SolutionToken::decode($token)->nonce : null;
    } catch (\Throwable) {
        $nonce = null;
    }
    if ($nonce !== null) {
        try {
            $storage = kiwiStorage($deployment['redisUrl']);
            $record = $storage->find($nonce);
            $binding = $record?->requestBinding;
        } catch (\Throwable) {
            // A storage outage during the binding lookup is surfaced by
            // the verifier below (its reads carry the same failure
            // semantics), never by a partial 500.
            $binding = null;
        }
    }

    try {
        $verifier = new Verifier(
            kiwiStorage($deployment['redisUrl']),
            rswModulusN: $deployment['rswModulusN'],
            rswLambda: $deployment['rswLambda'],
        );
        $outcome = $verifier->verify(
            $token,
            $deployment['secret'],
            $scope,
            kiwiClientIp(),
            expectedRequestBinding: $binding,
        );
    } catch (\Throwable $e) {
        error_log(sprintf('kiwicaptcha deploy: verification failed: %s', $e->getMessage()));
        kiwiJson(['ok' => false, 'code' => 'storage_unavailable']);

        return;
    }
    kiwiJson(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);
}

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
try {
    if ($_SERVER['REQUEST_METHOD'] === 'GET' && $path === '/healthz') {
        kiwiHealthz();

        return true;
    }
    if ($path === '/challenge') {
        kiwiChallenge();

        return true;
    }
    if ($path === '/verify') {
        kiwiVerify();

        return true;
    }

    kiwiError('NOT_FOUND', 'not found', 404);
} catch (\LogicException $e) {
    // A configuration error (missing/undersized secret, the half-set
    // rsw pair, an out-of-range knob, an invalid trapdoor value) is
    // operator-facing and answers a structured document; the exception
    // message names variables and bounds only, never secret values.
    error_log(sprintf('kiwicaptcha deploy: configuration error: %s', $e->getMessage()));
    kiwiError('CONFIGURATION_ERROR', $e->getMessage(), 500);
} catch (\Throwable $e) {
    error_log(sprintf('kiwicaptcha deploy: internal error: %s', $e->getMessage()));
    kiwiError('INTERNAL_ERROR', 'The request could not be completed.', 500);
}

return true;
