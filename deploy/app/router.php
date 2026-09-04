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
 *
 * The POST surfaces enforce a strict framing contract before any body
 * byte is read: no query parameters, a canonical bounded
 * Content-Length, identity Content-Encoding only, application/json
 * only (an absent Content-Type is accepted), a capped streaming body
 * read, no duplicate JSON keys and a bounded JSON nesting depth.
 *
 * Every other request is a 404 and every non-POST call to the POST
 * endpoints is a 405 with the Allow header, so php -S never serves a
 * static file and no app file is ever reachable by URL.
 */

require __DIR__.'/vendor/autoload.php';
require __DIR__.'/bootstrap.php';
require __DIR__.'/health.php';

use KiwiCaptcha\Issuer;
use KiwiCaptcha\Verifier;

/** The bounded shape of the request-body fields of both POST surfaces. */
const KIWI_IDENTIFIER_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';
/** Hard ceiling for a request body: the language is tiny. */
const KIWI_MAX_BODY_BYTES = 8192;
/**
 * The JSON nesting ceiling of the strict decoder, the same depth the
 * Symfony bundle passes to json_decode (32).
 */
const KIWI_MAX_JSON_DEPTH = 32;
/** The closed set of client-advertised algorithm profiles (server-owned). */
const KIWI_ALGORITHM_PROFILES = ['sha256', 'argon2id', 'rsw'];

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
 * The strict framed body read of a POST surface, in rejection order:
 *
 *  1. query parameters are refused (400 QUERY_NOT_ALLOWED),
 *  2. a declared Content-Length must be one canonical decimal integer
 *     (400 INVALID_CONTENT_LENGTH) not exceeding the ceiling (413
 *     BODY_TOO_LARGE),
 *  3. a Content-Encoding other than identity is refused before the
 *     body is read (415 UNSUPPORTED_CONTENT_ENCODING),
 *  4. a present Content-Type must be application/json (415
 *     INVALID_CONTENT_TYPE; an absent header is accepted, mirroring
 *     the Symfony controller, since the body still has to parse as a
 *     strict JSON object),
 *  5. the body is consumed from a bounded stream, so at most
 *     KIWI_MAX_BODY_BYTES + 1 bytes are ever materialized and a
 *     multi-MB chunked request is rejected at the cap (413),
 *  6. duplicate JSON keys are rejected on the raw document (400
 *     DUPLICATE_JSON_KEY),
 *  7. the strict decode enforces the JSON nesting ceiling (400
 *     JSON_NESTING_TOO_DEEP) and the object shape (422 INVALID_JSON).
 *
 * The accepted fields are decoded as a flat JSON object whose keys are
 * all listed in $accepted.
 *
 * @param list<string> $accepted the closed set of accepted field names
 *
 * @return array<string, mixed>|null the decoded payload
 */
function kiwiReadBody(array $accepted): ?array
{
    $query = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_QUERY);
    if (is_string($query) && $query !== '') {
        kiwiError('QUERY_NOT_ALLOWED', 'The request must not carry query parameters.', 400);

        return null;
    }

    $declaredLength = null;
    if (isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] !== '') {
        $declaredLength = (string) $_SERVER['CONTENT_LENGTH'];
    } elseif (isset($_SERVER['HTTP_CONTENT_LENGTH']) && $_SERVER['HTTP_CONTENT_LENGTH'] !== '') {
        $declaredLength = (string) $_SERVER['HTTP_CONTENT_LENGTH'];
    }
    if ($declaredLength !== null) {
        if (preg_match('/^(?:0|[1-9][0-9]*)$/D', $declaredLength) !== 1) {
            kiwiError('INVALID_CONTENT_LENGTH', 'The Content-Length header must be one canonical decimal integer.', 400);

            return null;
        }
        if ((int) $declaredLength > KIWI_MAX_BODY_BYTES) {
            kiwiError('BODY_TOO_LARGE', 'The request body must not exceed '.KIWI_MAX_BODY_BYTES.' bytes.', 413);

            return null;
        }
    }

    $contentEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;
    if (is_string($contentEncoding) && strtolower(trim($contentEncoding)) !== 'identity') {
        kiwiError('UNSUPPORTED_CONTENT_ENCODING', 'The request Content-Encoding must be identity (the widget POSTs plain JSON).', 415);

        return null;
    }

    $contentType = $_SERVER['CONTENT_TYPE'] ?? ($_SERVER['HTTP_CONTENT_TYPE'] ?? null);
    if (is_string($contentType) && trim($contentType) !== '') {
        $mediaType = strtolower(trim(explode(';', $contentType, 2)[0]));
        if ($mediaType !== 'application/json') {
            kiwiError('INVALID_CONTENT_TYPE', 'The request Content-Type must be application/json.', 415);

            return null;
        }
    }

    $stream = @fopen('php://input', 'rb');
    if ($stream === false) {
        kiwiError('INVALID_BODY', 'The request body could not be read.', 400);

        return null;
    }
    $raw = stream_get_contents($stream, KIWI_MAX_BODY_BYTES + 1);
    fclose($stream);
    if ($raw === false) {
        kiwiError('INVALID_BODY', 'The request body could not be read.', 400);

        return null;
    }
    if (strlen($raw) > KIWI_MAX_BODY_BYTES) {
        kiwiError('BODY_TOO_LARGE', 'The request body must not exceed '.KIWI_MAX_BODY_BYTES.' bytes.', 413);

        return null;
    }
    if (trim($raw) === '') {
        return [];
    }

    // Duplicate JSON keys: json_decode silently keeps the last
    // occurrence of a repeated object key, and intermediaries could
    // disagree on the effective value ({"scope":"login","scope":"signup"}
    // is a parser-ambiguity probe). The raw document is scanned before
    // the decode; the walker recursion is bounded well below any stack
    // risk, and a document it cannot walk is decided by the strict
    // decode below (never treated as clean by this surface, whose
    // accepted documents are flat objects of scalar fields).
    try {
        $duplicateKey = kiwiScanForDuplicateJsonKey($raw);
    } catch (KiwiJsonWalkAbort) {
        $duplicateKey = null;
    }
    if (is_string($duplicateKey)) {
        kiwiError('DUPLICATE_JSON_KEY', 'The request body carries a duplicate JSON key: '.$duplicateKey.'.', 400);

        return null;
    }

    try {
        $decoded = json_decode($raw, false, KIWI_MAX_JSON_DEPTH, JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
        // A depth breach is its own deterministic answer (the same
        // ceiling the Symfony surface passes to json_decode); every
        // other parse failure is the canonical invalid-JSON document.
        if (kiwiIsJsonDepthError($e)) {
            kiwiError('JSON_NESTING_TOO_DEEP', 'The request body must not nest deeper than '.KIWI_MAX_JSON_DEPTH.' levels.', 400);
        } else {
            kiwiError('INVALID_JSON', 'The request body must be a JSON object.', 422);
        }

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
 * Whether a strict-decode JsonException is the JSON depth breach.
 *
 * The JsonException thrown by a JSON_THROW_ON_ERROR decode failure
 * carries the parser's own error code, and only the depth breach ever
 * carries JSON_ERROR_DEPTH (1): every other parse failure (state
 * mismatch, control character, syntax, UTF-8/UTF-16, recursion,
 * unsupported values) reports a different code. json_last_error() is
 * unreliable after the throwing decode (it can report a stale decode),
 * so the exception code is the sole deterministic marker.
 */
function kiwiIsJsonDepthError(\JsonException $e): bool
{
    return $e->getCode() === JSON_ERROR_DEPTH;
}

/**
 * The raw-bytes duplicate-key walker of the request surface: a
 * recursive scan of the document that reports the first object key
 * seen more than once at the same level, mirroring the bundle's
 * JsonDuplicateKeyScanner shape. Duplicate detection compares decoded
 * (semantic) keys, so {"a":1,"\u0061":2} is one key spelled twice.
 * Keys inside any nesting depth are scanned, because an intermediary
 * could disagree about any of them.
 *
 * The recursion is bounded: beyond KIWI_MAX_JSON_DEPTH + 8 nesting
 * levels the walk gives up with {@see KiwiJsonWalkAbort} and the
 * strict decoder (whose ceiling is lower) decides the document, so a
 * depth bomb can never exhaust the stack and can never be reported
 * clean. A malformed document is equally handed to the strict decoder.
 *
 * @throws KiwiJsonWalkAbort when the document cannot be walked
 */
function kiwiScanForDuplicateJsonKey(string $json): ?string
{
    $offset = 0;
    try {
        kiwiScanJsonValue($json, $offset, 0);

        return null;
    } catch (KiwiDuplicateJsonKeyException $e) {
        return $e->key;
    }
}

/**
 * Consume one JSON value starting at $offset, reporting a duplicated
 * object key through {@see KiwiDuplicateJsonKeyException}.
 *
 * @param int $offset position in the raw JSON string (by reference)
 *
 * @throws KiwiDuplicateJsonKeyException on the first duplicated key
 * @throws KiwiJsonWalkAbort on a document the walk cannot establish as clean
 */
function kiwiScanJsonValue(string $json, int &$offset, int $depth): void
{
    if ($depth > KIWI_MAX_JSON_DEPTH + 8) {
        throw new KiwiJsonWalkAbort('json walk depth cap exceeded');
    }
    $length = strlen($json);
    kiwiSkipJsonWhitespace($json, $offset);
    if ($offset >= $length) {
        throw new KiwiJsonWalkAbort('unexpected end of document');
    }
    $ch = $json[$offset];

    if ($ch === '{') {
        $offset++;
        kiwiSkipJsonWhitespace($json, $offset);
        if ($offset < $length && $json[$offset] === '}') {
            $offset++;

            return;
        }
        $keys = [];
        while (true) {
            kiwiSkipJsonWhitespace($json, $offset);
            $key = kiwiScanJsonString($json, $offset);
            if ($key === null) {
                throw new KiwiJsonWalkAbort('object key is not a string');
            }
            if (isset($keys[$key])) {
                throw new KiwiDuplicateJsonKeyException($key);
            }
            $keys[$key] = true;
            kiwiSkipJsonWhitespace($json, $offset);
            if ($offset >= $length || $json[$offset] !== ':') {
                throw new KiwiJsonWalkAbort('missing object colon');
            }
            $offset++;
            kiwiScanJsonValue($json, $offset, $depth + 1);
            kiwiSkipJsonWhitespace($json, $offset);
            if ($offset >= $length) {
                throw new KiwiJsonWalkAbort('unexpected end of object');
            }
            $ch = $json[$offset];
            $offset++;
            if ($ch === '}') {
                return;
            }
            if ($ch !== ',') {
                throw new KiwiJsonWalkAbort('missing object comma');
            }
        }
    }

    if ($ch === '[') {
        $offset++;
        kiwiSkipJsonWhitespace($json, $offset);
        if ($offset < $length && $json[$offset] === ']') {
            $offset++;

            return;
        }
        while (true) {
            kiwiScanJsonValue($json, $offset, $depth + 1);
            kiwiSkipJsonWhitespace($json, $offset);
            if ($offset >= $length) {
                throw new KiwiJsonWalkAbort('unexpected end of array');
            }
            $ch = $json[$offset];
            $offset++;
            if ($ch === ']') {
                return;
            }
            if ($ch !== ',') {
                throw new KiwiJsonWalkAbort('missing array comma');
            }
        }
    }

    if ($ch === '"') {
        kiwiScanJsonString($json, $offset);

        return;
    }

    // number / true / false / null: skip a bare token.
    while ($offset < $length) {
        $ch = $json[$offset];
        if ($ch === ',' || $ch === '}' || $ch === ']' || $ch === ' ' || $ch === "\t" || $ch === "\n" || $ch === "\r") {
            break;
        }
        $offset++;
    }
}

/**
 * Consume one JSON string starting at $offset (which must point at the
 * opening quote) and return its decoded content, escape sequences
 * resolved to the actual characters, so duplicate detection compares
 * semantic keys. null when the string cannot be walked (the strict
 * json_decode below decides such a document).
 *
 * @param int $offset position in the raw JSON string (by reference)
 */
function kiwiScanJsonString(string $json, int &$offset): ?string
{
    $length = strlen($json);
    if ($offset >= $length || $json[$offset] !== '"') {
        return null;
    }
    $end = $offset + 1;
    while ($end < $length) {
        $ch = $json[$end];
        if ($ch === '\\') {
            $end += 2;

            continue;
        }
        if ($ch === '"') {
            break;
        }
        $end++;
    }
    if ($end >= $length) {
        return null;
    }
    $raw = substr($json, $offset, $end - $offset + 1);
    try {
        $decoded = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
        // A malformed escape, an unpaired surrogate or invalid UTF-8
        // inside the string: the strict document decode decides it.
        throw new KiwiJsonWalkAbort('undecodable string content');
    }
    if (!is_string($decoded)) {
        return null;
    }
    $offset = $end + 1;

    return $decoded;
}

function kiwiSkipJsonWhitespace(string $json, int &$offset): void
{
    $length = strlen($json);
    while ($offset < $length) {
        $ch = $json[$offset];
        if ($ch !== ' ' && $ch !== "\t" && $ch !== "\n" && $ch !== "\r") {
            break;
        }
        $offset++;
    }
}

/** The walker's depth/malformed abort: the strict decoder decides. */
final class KiwiJsonWalkAbort extends \RuntimeException
{
}

/** The first duplicated object key of the scanned document. */
final class KiwiDuplicateJsonKeyException extends \RuntimeException
{
    public function __construct(public readonly string $key)
    {
        parent::__construct('duplicate JSON object key: '.$key);
    }
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
    $payload = kiwiReadBody(['token', 'scope', 'request_binding']);
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
