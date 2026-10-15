<?php

declare(strict_types=1);

/**
 * The strict request-framing surface of the reference deployment,
 * shared by every router that serves its wire contract.
 *
 * This file is the one implementation of the POST framing rules: the
 * rejection order (query parameters, the canonical bounded
 * Content-Length, identity Content-Encoding only, application/json
 * only, the capped streaming body read, duplicate JSON keys and the
 * bounded nesting depth), the flat-object field gate, the bounded
 * client IP of the single-hop socket peer, and the JSON document
 * walker the duplicate-key scan runs on.
 *
 * It lives apart from router.php because a second deployment serves
 * the same contract over a different storage adapter (the red-team
 * storage matrix: tools/redteam/target/router-storage.php over
 * SqliteStorage and FilesystemStorage). Two copies of these rules
 * would be two parser surfaces to keep in step, and the D3.12 parser
 * leg exists precisely to prove there is only one interpretation of
 * any byte stream. The endpoint semantics stay in each router; the
 * bytes they accept are decided here.
 *
 * Nothing in this file reads configuration or touches a store.
 */

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
