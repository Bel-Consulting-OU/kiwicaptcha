<?php

declare(strict_types=1);

/**
 * The request entry point of the reference deployment
 * (php -S 0.0.0.0:8080 -t /srv/kiwicaptcha/app /srv/kiwicaptcha/app/router.php).
 *
 * The surface mirrors the JSON wire contract the browser fixture
 * server and the Symfony bundle controller speak, backed by the real
 * core storage (RedisStorage on KC_REDIS_URL — never temp files) and
 * the real core issuer/verifier configured from the environment only:
 *
 *   GET  /healthz -> 200 {"ok":true} only after a real store round
 *                    trip (write, read, delete-if-pending); 503 with
 *                    {"ok":false,"code":"storage_probe_failed"} and NO
 *                    backend detail otherwise (the detail goes to the
 *                    server log only).
 *   POST /challenge -> 200 with the canonical challenge document
 *                    (nonce, challenge, salt, algorithm, mKib, t, p,
 *                    targetBits, ttlSecs, minDurationMs, prefix, plus
 *                    execution_program when the execution key is
 *                    configured and rsw_modulus for rsw challenges).
 *                    The issued algorithm always comes from the
 *                    server-selected KIWI_ALGORITHM profile: the
 *                    request `algorithm` field is compatibility
 *                    metadata only (validated, never honored).
 *                    Issuance is rate limited per client IP on the
 *                    store Redis (KIWI_ISSUANCE_PER_MINUTE_PER_IP,
 *                    default 30 challenges per 60-second window, 0
 *                    disables); an over-limit request answers 429 with
 *                    code RATE_LIMITED.
 *   POST /verify   -> 200 {"ok":true,"code":""} for a fresh valid
 *                    redemption; {"ok":false,"code":"<error>"} for
 *                    every failure. The presented `request_binding` is
 *                    the independent expected transaction binding: it
 *                    is handed to the core verifier, which retires the
 *                    pending record on a hard cheap-phase verdict — a
 *                    binding mismatch included (the one-shot
 *                    anti-oracle semantics) — so the same token can
 *                    never be re-tried against a corrected binding (it
 *                    answers code "record_not_found"). A replayed token
 *                    answers code "already_consumed": the consumed
 *                    marker in the core storage rejects it.
 *                    `remoteip` is accepted for the shared gateway and
 *                    siteverify client shape and is never honored: the
 *                    connection's peer address governs IP binding, so a
 *                    proxied caller can never claim a foreign address.
 *
 * The POST surfaces enforce a strict framing contract before any body
 * byte is read: no query parameters, a canonical bounded
 * Content-Length, identity Content-Encoding only, application/json
 * only (an absent Content-Type is accepted), a capped streaming body
 * read, no duplicate JSON keys and a bounded JSON nesting depth. Those
 * rules live in framing.php and are shared with every other router of
 * this wire contract, so one set of bytes has one interpretation
 * wherever this surface is served.
 *
 * Every other request is a 404 and every non-POST call to the POST
 * endpoints is a 405 with the Allow header, so php -S never serves a
 * static file and no app file is ever reachable by URL.
 */

require __DIR__.'/vendor/autoload.php';
require __DIR__.'/bootstrap.php';
require __DIR__.'/health.php';
// The strict framing surface every router of this wire contract
// shares (see framing.php): one implementation of the rules,
// so the deployment and the red-team storage matrix accept and
// refuse exactly the same bytes.
require __DIR__.'/framing.php';

use KiwiCaptcha\Issuer;
use KiwiCaptcha\Verifier;


const KIWI_RATE_LIMIT_ALLOWED = 'allowed';
const KIWI_RATE_LIMIT_LIMITED = 'limited';
const KIWI_RATE_LIMIT_INDETERMINATE = 'indeterminate';

/**
 * The privacy-preserving limiter pseudonym: an HMAC under a
 * PURPOSE-SEPARATED rate-limit key derived from the deployment master
 * secret (never the challenge-signing key directly), over a labelled
 * canonical IP plus a coarse epoch. Neither the raw textual IP nor its
 * packed bytes ever appears in the Redis key, matching the bundle's
 * IssuanceRateLimiter derivation. The epoch rotates hourly and the
 * limiter checks the current and previous epochs together, so a
 * boundary can not double the budget.
 */
function kiwiRateLimitPseudonym(string $masterSecret, string $ip, int $epoch): string
{
    $rateKey = hash_hmac('sha256', 'kiwi-deploy-rate-limit-v1', $masterSecret, true);

    return hash_hmac('sha256', 'kiwi:rl:issuance:v1|'.$epoch.'|'.$ip, $rateKey);
}

/**
 * The per-client-IP fixed-window issuance limiter, on the same Redis
 * the storage uses: an INCR per challenge request under the pseudonym
 * key {kiwi:rl}:issuance:v1:<pseudonym> (the raw IP never appears; see
 * kiwiRateLimitPseudonym), and the 60-second window is armed exactly
 * when the counter is new (INCR result 1 -> EXPIRE 60). The union of
 * the current and previous epoch counters keeps the budget meaningful
 * across the hourly pseudonym rotation. A limiter budget of 0 disables
 * the limiter.
 *
 * Failure policy: a Redis error leaves the decision INDETERMINATE and
 * /challenge answers a retryable 503. An explicitly configured abuse
 * limit must not silently become unlimited issuance when the limiter
 * alone cannot run (an ACL or script error can break EVAL while the
 * storage command families still work, so the storage's own failure
 * mode is not a substitute). KIWI_RATE_LIMIT_FAIL_OPEN=1 is the
 * deliberately named demo-only opt-in that logs and allows instead;
 * the default is fail-closed.
 *
 * @return string one of KIWI_RATE_LIMIT_ALLOWED / LIMITED / INDETERMINATE
 */
function kiwiIssuanceAllowed(string $redisUrl, string $ip, int $perMinute, string $masterSecret): string
{
    if ($perMinute < 1) {
        return KIWI_RATE_LIMIT_ALLOWED;
    }
    $epoch = intdiv(time(), 3600);
    $currentKey = '{kiwi:rl}:issuance:v1:'.kiwiRateLimitPseudonym($masterSecret, $ip, $epoch);
    $previousKey = '{kiwi:rl}:issuance:v1:'.kiwiRateLimitPseudonym($masterSecret, $ip, $epoch - 1);
    // One script both increments and arms the window: a split INCR and
    // EXPIRE can leave a counter without an expiry when the process or
    // connection dies between them, and every later request would feed
    // a never-resetting counter that throttles the address forever.
    // The script arms the sixty-second window exactly when the counter
    // is minted, atomically, and sums the previous epoch's counter so
    // the hourly pseudonym rotation cannot reset the budget. Both keys
    // share the {kiwi:rl} hash tag, so the two-key script is Cluster
    // safe.
    $window = <<<'LUA'
local n = redis.call('INCR', KEYS[1])
if n == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
local previous = tonumber(redis.call('GET', KEYS[2])) or 0
return n + previous
LUA;
    try {
        $client = kiwiRedisClient($redisUrl);
        $count = (int) $client->eval($window, 2, $currentKey, $previousKey, 60);
    } catch (\Throwable $e) {
        error_log(sprintf('kiwicaptcha deploy: issuance limiter unavailable: %s', $e->getMessage()));
        if (getenv('KIWI_RATE_LIMIT_FAIL_OPEN') === '1') {
            error_log('kiwicaptcha deploy: KIWI_RATE_LIMIT_FAIL_OPEN=1 — allowing issuance despite the unavailable limiter (demo opt-in)');

            return KIWI_RATE_LIMIT_ALLOWED;
        }

        return KIWI_RATE_LIMIT_INDETERMINATE;
    }

    return $count <= $perMinute ? KIWI_RATE_LIMIT_ALLOWED : KIWI_RATE_LIMIT_LIMITED;
}

/**
 * POST /challenge: issue a challenge through the real core issuer.
 *
 * Server-owned semantics mirroring the bundle controller: the issued
 * algorithm always comes from the deployment profile selected by
 * KIWI_ALGORITHM. The request `algorithm` field is compatibility
 * metadata only (the existing widget sends the profile it expects):
 * a present non-empty value must name one of the known profiles or the
 * request is refused with 422 INVALID_ALGORITHM, and it never rebuilds
 * the issuance configuration. The execution dimension is armed on
 * every issuance exactly when KIWI_EXECUTION_KEY is set.
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
    // Absent or null means the documented default; an explicitly
    // empty string is a malformed identifier and is refused below,
    // never silently promoted to the default scope.
    $scope = array_key_exists('scope', $payload) && $payload['scope'] !== null ? (string) $payload['scope'] : 'default';
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

    // The algorithm field never selects the issuance profile: it is
    // validated compatibility metadata only (the widget advertises the
    // profile it expects), and $config stays the deployment's own
    // config for every request.
    $config = $deployment['config'];
    if (isset($payload['algorithm']) && $payload['algorithm'] !== ''
        && !in_array($payload['algorithm'], KIWI_ALGORITHM_PROFILES, true)) {
        kiwiError('INVALID_ALGORITHM', 'The algorithm must be one of sha256, argon2id, rsw.', 422);

        return;
    }

    // The unauthenticated issuance surface is rate limited per client
    // IP before any issuance work runs: the socket peer is the only
    // identity input (the deployment trusts no forwarding header), so
    // a burst burns only its own window.
    $limit = kiwiIssuanceAllowed($deployment['redisUrl'], kiwiClientIp(), (int) $deployment['issuancePerMinute'], $deployment['secret']);
    if ($limit === KIWI_RATE_LIMIT_LIMITED) {
        kiwiError('RATE_LIMITED', 'Too many challenge requests from this address. Try again later.', 429);

        return;
    }
    if ($limit === KIWI_RATE_LIMIT_INDETERMINATE) {
        kiwiError('RATE_LIMIT_UNAVAILABLE', 'The issuance rate limiter is unavailable. Try again shortly.', 503);

        return;
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
 *
 * The expected transaction binding is INDEPENDENT: it is parsed from
 * the request `request_binding` field, never read back from the
 * stored record (a challenge minted bound to a transaction redeems
 * only against the binding the verifier is told to expect), and it is
 * enforced by the core verifier alone — this surface performs no
 * record lookup of its own. A mismatching binding is a hard
 * cheap-phase verdict of the core, and the core's one-shot model
 * retires the pending record on it: the challenge dies with the failed
 * attempt, so a mislabeled redemption cannot be re-tried against a
 * corrected binding (the same token then answers "record_not_found"),
 * and an attacker gets exactly one guess per issued challenge instead
 * of a free binding oracle. Single-use consumption, already_consumed
 * and record-not-found all stay in the verifier below.
 */
function kiwiVerify(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        header('Allow: POST');
        kiwiError('METHOD_NOT_ALLOWED', 'The verify endpoint accepts POST requests only.', 405);

        return;
    }
    $payload = kiwiReadBody(['token', 'scope', 'request_binding', 'remoteip']);
    if ($payload === null) {
        return;
    }
    $token = isset($payload['token']) && is_string($payload['token']) ? $payload['token'] : '';
    $scope = isset($payload['scope']) && is_string($payload['scope']) && $payload['scope'] !== ''
        ? $payload['scope']
        : 'default';

    // The independent expected binding: absent/null/empty = the record
    // must be explicitly unbound; a non-empty string must match the
    // record's signed request_binding exactly.
    $expectedRequestBinding = null;
    if (array_key_exists('request_binding', $payload) && $payload['request_binding'] !== null) {
        if (!is_string($payload['request_binding'])) {
            kiwiError('INVALID_JSON', 'The verify request fields must be strings.', 422);

            return;
        }
        if ($payload['request_binding'] !== ''
            && preg_match(KIWI_IDENTIFIER_PATTERN, $payload['request_binding']) !== 1) {
            kiwiError('INVALID_REQUEST_BINDING', 'The request_binding must be 1-128 characters of [A-Za-z0-9._:-].', 422);

            return;
        }
        $expectedRequestBinding = $payload['request_binding'] !== ''
            ? $payload['request_binding']
            : null;
    }

    $deployment = kiwiDeployment();
    try {
        $storage = kiwiStorage($deployment['redisUrl']);

        // The route is exactly the core verifier: the expected binding
        // is enforced inside verify() (never through a manual record
        // lookup here), so the core's one-shot cheap-phase retirement
        // decides every mismatch verdict and no adapter-level pre-read
        // ever turns a mismatch into a free retry oracle.
        $verifier = new Verifier(
            $storage,
            rswModulusN: $deployment['rswModulusN'],
            rswLambda: $deployment['rswLambda'],
        );
        $outcome = $verifier->verify(
            $token,
            $deployment['secret'],
            $scope,
            kiwiClientIp(),
            expectedRequestBinding: $expectedRequestBinding,
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
} catch (\RuntimeException $e) {
    // A configuration error (missing/undersized secret, the half-set
    // rsw pair, an out-of-range knob, an invalid trapdoor value) is
    // operator-facing and answers a structured document; the bootstrap
    // signals every configuration failure with RuntimeException, and
    // the exception message names variables and bounds only, never
    // secret values.
    error_log(sprintf('kiwicaptcha deploy: configuration error: %s', $e->getMessage()));
    kiwiError('CONFIGURATION_ERROR', $e->getMessage(), 500);
} catch (\LogicException $e) {
    error_log(sprintf('kiwicaptcha deploy: configuration error: %s', $e->getMessage()));
    kiwiError('CONFIGURATION_ERROR', $e->getMessage(), 500);
} catch (\Throwable $e) {
    error_log(sprintf('kiwicaptcha deploy: internal error: %s', $e->getMessage()));
    kiwiError('INTERNAL_ERROR', 'The request could not be completed.', 500);
}

return true;
