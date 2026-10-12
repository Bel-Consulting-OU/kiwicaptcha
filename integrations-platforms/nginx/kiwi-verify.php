<?php

/**
 * kiwi-verify.php: the shared companion endpoint for the gateway
 * integrations. The nginx auth_request subrequest, the Caddy
 * forward_auth request and the Traefik forwardAuth request all land
 * here. The endpoint extracts the captcha token from the incoming
 * request, verifies it server-to-server against the kiwi deployment
 * (the verifier sidecar's POST /verify by default, or a provider
 * shaped siteverify endpoint), and answers with the shared gate
 * contract:
 *
 *   204 No Content   the token verified, the gateway lets the request pass
 *   403 Forbidden    missing, invalid or already consumed token
 *   302 Found        deny with a redirect (KIWI_DENY=302 plus KIWI_REDIRECT)
 *   503 Unavailable  the kiwi deployment did not answer; the gate fails closed
 *
 * Configuration rides environment variables (a reverse-proxy or FPM
 * fastcgi_param lands in $_SERVER and works the same way):
 *
 *   KIWI_VERIFY_URL   default http://127.0.0.1:7371/verify (the sidecar)
 *   KIWI_BEARER       optional bearer credential for the kiwi endpoint
 *   KIWI_SCOPE        the challenge scope, default "login"
 *   KIWI_VERIFY_MODE  "json" (sidecar /verify, default) or "compat"
 *                     (a siteverify endpoint: response/secret/remoteip
 *                     form encoding, the bearer rides the secret field)
 *   KIWI_TRUSTED_PROXIES  comma-separated trusted-proxy CIDRs (IPv4 or
 *                     IPv6). The default empty list trusts nobody:
 *                     X-Forwarded-For and X-Real-IP are ignored and
 *                     the socket peer is the client ip. With a trusted
 *                     peer, the forwarded chain is walked right to
 *                     left through the trusted hops and X-Real-IP is
 *                     honored when no chain exists.
 *   KIWI_DENY         "403" (default) or "302" with KIWI_REDIRECT
 *   KIWI_REDIRECT     the deny redirect target
 *   KIWI_TIMEOUT      upstream timeout in seconds, default 5
 *
 * Token sources, in order: the X-Kiwi-Token header, any incumbent
 * form field (kiwi__token, g-recaptcha-response, h-captcha-response,
 * cf-turnstile-response, frc-captcha-solution, altcha) on a form POST,
 * a JSON body under a NAMESPACED key (kiwi_token or captcha_response —
 * never the bare "token" key, which is the application's own wire field
 * and would forward app secrets into the verify call), and the
 * kiwi_token cookie. Note the nginx auth_request subrequest carries
 * headers and cookies only; the body sources exist for Traefik
 * forwardAuth, which forwards them.
 */

declare(strict_types=1);

const KIWI_VERIFY_TOKEN_FIELDS = [
    'kiwi__token',
    'g-recaptcha-response',
    'h-captcha-response',
    'cf-turnstile-response',
    'frc-captcha-solution',
    'altcha',
];

/**
 * The namespaced JSON body keys. The bare "token" key is deliberately
 * absent: an application POSTing its own {"token": ...} API credential
 * must never have that value consumed (and forwarded) as a captcha
 * token.
 */
const KIWI_VERIFY_JSON_TOKEN_FIELDS = [
    'kiwi_token',
    'captcha_response',
];

/** Hard ceiling for a request body the endpoint will ever materialize. */
const KIWI_MAX_BODY_BYTES = 65536;

/** Hard ceiling for one extracted token candidate. */
const KIWI_MAX_TOKEN_BYTES = 65536;

/** The scope grammar of the shared wire contract (the deploy app's identifier pattern). */
const KIWI_SCOPE_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

/**
 * The config character floor: a configuration value that reaches an
 * HTTP header or the upstream request line must never carry a control
 * character (CRLF in the bearer or the redirect target would split
 * headers on the upstream request or the deny response).
 */
function kiwi_verify_has_control(string $value): bool
{
    return preg_match('/[\x00-\x1F\x7F]/', $value) === 1;
}

/**
 * The strict JSON media-type check of the body parser. The media type
 * must be exactly application/json (case-insensitive, parameters such
 * as "; charset=utf-8" allowed): substrings like application/jsonp or
 * application/json-seq never qualify, so a content-type confusion can
 * not smuggle a body into the JSON token source.
 */
function kiwi_verify_is_json_content_type(array $server): bool
{
    $contentType = $server['CONTENT_TYPE'] ?? null;
    if (!is_string($contentType)) {
        return false;
    }
    $media = strtolower(trim(explode(';', $contentType, 2)[0]));

    return $media === 'application/json';
}

/**
 * The effective configuration. $_SERVER wins over the process
 * environment so an nginx fastcgi_param or an FPM pool env directive
 * configures the endpoint without touching the process env. These are
 * deployment knobs, never request data: in every standard SAPI a
 * request header lands under an HTTP_ prefixed key and can not reach
 * these names. The values still get validated at read time (scheme,
 * control characters, scope grammar, timeout bounds) so even a
 * mis-injected knob can not turn into an SSRF target, a response
 * split or an upstream header injection; a broken knob sets
 * `config_error` and the gate then fails closed on every request.
 */
function kiwi_verify_config(): array
{
    $env = static function (string $name, string $default = '') {
        $fromServer = $_SERVER[$name] ?? null;
        if (is_string($fromServer) && $fromServer !== '') {
            return $fromServer;
        }
        $fromEnv = getenv($name);

        return is_string($fromEnv) && $fromEnv !== '' ? $fromEnv : $default;
    };

    $verifyUrl = $env('KIWI_VERIFY_URL', 'http://127.0.0.1:7371/verify');
    $bearer = $env('KIWI_BEARER', '');
    $scope = $env('KIWI_SCOPE', 'login');
    $redirect = $env('KIWI_REDIRECT', '');
    // The timeout parses as a float and is bounded below: the empty
    // value already fell back to the default inside $env, and a
    // falsy-but-set "0" must fail the audit rather than silently
    // re-arming the default.
    $timeout = (float) $env('KIWI_TIMEOUT', '5');

    return [
        'verify_url' => $verifyUrl,
        'bearer' => $bearer,
        'scope' => $scope,
        'mode' => $env('KIWI_VERIFY_MODE', 'json') === 'compat' ? 'compat' : 'json',
        'trusted_proxies' => kiwi_verify_parse_cidrs($env('KIWI_TRUSTED_PROXIES', '')),
        'deny_redirect' => $env('KIWI_DENY', '403') === '302' && $redirect !== '',
        'redirect' => $redirect,
        'timeout' => $timeout,
        'config_error' => kiwi_verify_validate_config($verifyUrl, $bearer, $scope, $redirect, $timeout),
    ];
}

/**
 * The configuration audit: null when every knob is safe to use, a
 * human-readable reason otherwise. The verify URL must be an http(s)
 * URL without control characters or whitespace (a file:// or php://
 * target would turn the verify call into a local-file oracle, a
 * scheme the SSRF contract refuses at the config boundary), and the
 * bearer, scope and redirect must never carry a control character
 * (each reaches an HTTP header or the upstream request).
 */
function kiwi_verify_validate_config(string $verifyUrl, string $bearer, string $scope, string $redirect, float $timeout): ?string
{
    foreach (['KIWI_VERIFY_URL' => $verifyUrl, 'KIWI_BEARER' => $bearer, 'KIWI_SCOPE' => $scope, 'KIWI_REDIRECT' => $redirect] as $name => $value) {
        if (kiwi_verify_has_control($value)) {
            return $name.' must not carry control characters';
        }
    }
    if (preg_match('#^https?://[^\s]+$#i', $verifyUrl) !== 1) {
        return 'KIWI_VERIFY_URL must be one absolute http(s) URL without whitespace';
    }
    if (preg_match(KIWI_SCOPE_PATTERN, $scope) !== 1) {
        return 'KIWI_SCOPE must be 1-128 characters of [A-Za-z0-9._:-]';
    }
    if ($timeout <= 0.0 || $timeout > 120.0) {
        return 'KIWI_TIMEOUT must be within (0, 120] seconds';
    }

    return null;
}

/**
 * The trusted CIDR list: comma-separated, empty entries dropped, one
 * entry that fails to parse can never widen the boundary.
 *
 * @return list<string>
 */
function kiwi_verify_parse_cidrs(string $csv): array
{
    $cidrs = [];
    foreach (explode(',', $csv) as $candidate) {
        $candidate = trim($candidate);
        if ($candidate !== '') {
            $cidrs[] = $candidate;
        }
    }

    return $cidrs;
}

/**
 * The bounded request-body read of the POST path. At most
 * KIWI_MAX_BODY_BYTES + 1 bytes are ever materialized (a multi-MB or
 * gzip-bomb body never balloons memory), and an oversized body
 * contributes no token source at all — the header and cookie sources
 * still decide the request, and a body-only token then denies.
 */
function kiwi_verify_read_body(): ?string
{
    $stream = @fopen('php://input', 'rb');
    if ($stream === false) {
        return null;
    }
    $raw = stream_get_contents($stream, KIWI_MAX_BODY_BYTES + 1);
    fclose($stream);
    if ($raw === false || strlen($raw) > KIWI_MAX_BODY_BYTES) {
        return null;
    }

    return $raw;
}

/**
 * The first present token from the CLOSED source list, or null. Only
 * the documented carriers are ever consulted: the X-Kiwi-Token header,
 * the documented form fields on a form POST, the namespaced JSON body
 * keys under an exact application/json media type (never the bare
 * "token" key, which is the application's own wire field and would
 * forward app secrets into the verify call), and the kiwi_token
 * cookie. Query strings, paths and every other header or field are
 * not token sources. A candidate beyond the token ceiling is skipped
 * (never forwarded upstream).
 */
function kiwi_verify_extract_token(array $server, array $post, array $cookie, ?string $rawBody = null): ?string
{
    $candidates = [];
    $header = $server['HTTP_X_KIWI_TOKEN'] ?? null;
    if (is_string($header) && trim($header) !== '') {
        $candidates[] = trim($header);
    }
    foreach (KIWI_VERIFY_TOKEN_FIELDS as $field) {
        $value = $post[$field] ?? null;
        if (is_string($value) && trim($value) !== '') {
            $candidates[] = trim($value);
        }
    }
    if ($rawBody !== null && trim($rawBody) !== ''
        && kiwi_verify_is_json_content_type($server)) {
        $parsed = json_decode($rawBody, true);
        foreach (KIWI_VERIFY_JSON_TOKEN_FIELDS as $field) {
            $value = is_array($parsed) ? ($parsed[$field] ?? null) : null;
            if (is_string($value) && trim($value) !== '') {
                $candidates[] = trim($value);
                break;
            }
        }
    }
    $cookieToken = $cookie['kiwi_token'] ?? null;
    if (is_string($cookieToken) && trim($cookieToken) !== '') {
        $candidates[] = trim($cookieToken);
    }

    foreach ($candidates as $candidate) {
        if ($candidate !== '' && strlen($candidate) <= KIWI_MAX_TOKEN_BYTES) {
            return $candidate;
        }
    }

    return null;
}

/**
 * The client ip bound into the verify call. The socket peer wins
 * unless the peer sits inside KIWI_TRUSTED_PROXIES; the default empty
 * list trusts nobody, so a forged X-Forwarded-For can never move the
 * binding. With a trusted peer the forwarded chain is walked right to
 * left through the trusted hops (the Symfony ClientIpResolver
 * trusted-chain walk), and X-Real-IP is honored only when the peer is
 * trusted and no chain exists. A missing or unparsable socket peer
 * resolves to '' (fail closed): the caller refuses the request rather
 * than inventing an address, and a peer string that is not a genuine
 * IP (control characters, unicode, an obfuscated token) is never
 * forwarded upstream as a client identity.
 */
function kiwi_verify_client_ip(array $server, array $trustedCidrs): string
{
    $peer = (string) ($server['REMOTE_ADDR'] ?? '');
    $peerCanonical = kiwi_verify_canonical_ip($peer);
    if ($peerCanonical === null) {
        // Fail closed: a missing or malformed socket peer is not a
        // loopback client. The caller refuses the request rather than
        // trusting 127.0.0.1.
        return '';
    }
    if ($trustedCidrs === []) {
        return $peerCanonical;
    }
    $peerTrusted = kiwi_verify_in_trusted($peerCanonical, $trustedCidrs);
    $forwarded = $server['HTTP_X_FORWARDED_FOR'] ?? null;
    if (!is_string($forwarded) || trim($forwarded) === '') {
        if (!$peerTrusted) {
            return $peerCanonical;
        }
        $realIp = $server['HTTP_X_REAL_IP'] ?? null;
        if (!is_string($realIp)) {
            return $peerCanonical;
        }
        $realIp = trim($realIp);
        if ($realIp === '' || kiwi_verify_has_control($realIp)) {
            return $peerCanonical;
        }
        $canonical = kiwi_verify_canonical_ip($realIp);

        return $canonical ?? $peerCanonical;
    }
    if (kiwi_verify_has_control($forwarded) || !$peerTrusted) {
        return $peerCanonical;
    }
    $hops = array_reverse(array_map('trim', explode(',', $forwarded)));
    foreach ($hops as $hop) {
        $canonical = kiwi_verify_canonical_ip($hop);
        if ($canonical === null) {
            // An unparsable hop terminates the trust chain: who lies
            // beyond it cannot be established, so the peer falls back.
            return $peerCanonical;
        }
        if (!kiwi_verify_in_trusted($canonical, $trustedCidrs)) {
            return $canonical;
        }
    }

    return $peerCanonical;
}

/**
 * The canonical IP text of one forwarded node, or null when it is not
 * a genuine address. Handles bare IPv4, IPv4 with a port, bracketed
 * IPv6 with an optional port; rejects unknown, obfuscated tokens and
 * malformed ports; normalizes IPv4-mapped IPv6 to its IPv4 form. The
 * same strict grammar the Symfony bundle's resolver applies.
 */
function kiwi_verify_canonical_ip(string $identifier): ?string
{
    $value = trim($identifier);
    if ($value === '' || $value === 'unknown' || str_starts_with($value, '_')) {
        return null;
    }
    $candidate = $value;
    if (str_starts_with($candidate, '[')) {
        $closing = strpos($candidate, ']');
        if ($closing === false) {
            return null;
        }
        $suffix = substr($candidate, $closing + 1);
        if ($suffix !== '' && !kiwi_verify_port_suffix($suffix)) {
            return null;
        }
        $candidate = substr($candidate, 1, $closing - 1);
    } elseif (substr_count($candidate, ':') === 1) {
        $parts = explode(':', $candidate);
        if (count($parts) === 2
            && filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && kiwi_verify_port_suffix(':'.$parts[1])) {
            $candidate = $parts[0];
        }
    }
    if (str_contains($candidate, ':') && substr_count($candidate, ':') < 2) {
        $parts = explode(':', $candidate);
        $last = array_pop($parts);
        if (filter_var($last, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $candidate = implode(':', $parts);
        }
    }
    if (filter_var($candidate, FILTER_VALIDATE_IP) === false) {
        return null;
    }
    $packed = @inet_pton($candidate);
    if ($packed === false) {
        return null;
    }
    if (strlen($packed) === 16 && substr($packed, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
        // IPv4-mapped IPv6 normalizes to its IPv4 form.
        return (string) inet_ntop(substr($packed, 12));
    }

    return (string) inet_ntop($packed);
}

/**
 * Exactly ":" plus a decimal port in the 1..65535 range.
 */
function kiwi_verify_port_suffix(string $suffix): bool
{
    if (!str_starts_with($suffix, ':')) {
        return false;
    }
    $digits = substr($suffix, 1);

    return ctype_digit($digits) && strlen($digits) <= 5
        && (int) $digits >= 1 && (int) $digits <= 65535;
}

/**
 * Whether one canonical IP text sits inside any trusted CIDR. Host
 * bits set in a CIDR are masked away, and an IPv4-mapped IPv6 address
 * matches in its IPv4 form (canonicalization already removed the
 * mapped spellings, so families always compare exactly).
 */
function kiwi_verify_in_trusted(string $ip, array $cidrs): bool
{
    $packed = @inet_pton($ip);
    if ($packed === false) {
        return false;
    }
    foreach ($cidrs as $cidr) {
        $cidr = trim((string) $cidr);
        if ($cidr === '') {
            continue;
        }
        if (!str_contains($cidr, '/')) {
            $network = kiwi_verify_canonical_ip($cidr);
            if ($network !== null && $network === $ip) {
                return true;
            }
            continue;
        }
        [$networkText, $prefixText] = explode('/', $cidr, 2);
        if (!ctype_digit($prefixText)) {
            continue;
        }
        $network = @inet_pton((string) kiwi_verify_canonical_ip($networkText));
        if ($network === false || $network === null || strlen($network) !== strlen($packed)) {
            continue;
        }
        $bits = strlen($packed) * 8;
        $prefix = (int) $prefixText;
        if ($prefix < 0 || $prefix > $bits) {
            continue;
        }
        $fullBytes = intdiv($prefix, 8);
        $remainder = $prefix % 8;
        if (substr($network, 0, $fullBytes) !== substr($packed, 0, $fullBytes)) {
            continue;
        }
        if ($remainder > 0 && $fullBytes < strlen($packed)) {
            $mask = chr((0xFF << (8 - $remainder)) & 0xFF);
            if ((substr($network, $fullBytes, 1) & $mask) !== (substr($packed, $fullBytes, 1) & $mask)) {
                continue;
            }
        }

        return true;
    }

    return false;
}

/**
 * The server-to-server verify call. Returns
 * array{http: int, success: bool, error_codes: list<string>}.
 * A transport failure is http 0; any kiwi answer that is not a
 * readable provider JSON counts as success false.
 */
function kiwi_verify_call(string $verifyUrl, string $token, string $scope, string $ip, array $cfg): array
{
    if ($cfg['mode'] === 'compat') {
        $body = http_build_query([
            'secret' => $cfg['bearer'],
            'response' => $token,
            'remoteip' => $ip,
        ]);
        $contentType = 'application/x-www-form-urlencoded';
    } else {
        $body = json_encode(['token' => $token, 'scope' => $scope, 'remoteip' => $ip], JSON_UNESCAPED_SLASHES);
        $contentType = 'application/json';
    }
    $headers = ['Content-Type: '.$contentType];
    if ($cfg['mode'] === 'json' && $cfg['bearer'] !== '') {
        $headers[] = 'Authorization: Bearer '.$cfg['bearer'];
    }
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers),
            'content' => $body,
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => $cfg['timeout'],
        ],
    ]);
    $response = @file_get_contents($verifyUrl, false, $context);
    if ($response === false && empty($http_response_header)) {
        return ['http' => 0, 'success' => false, 'error_codes' => ['transport']];
    }
    $status = 0;
    foreach (($http_response_header ?? []) as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
            // The last status line wins: an informational 1xx or an
            // intermediate hop must never mask the final answer status.
            $status = (int) $m[1];
        }
    }
    $success = false;
    $errorCodes = [];
    $parsed = json_decode((string) $response, true);
    if (is_array($parsed)) {
        // json mode fronts two answer shapes: the sidecar's provider
        // shape (success) and the core deployment's ok shape.
        $success = ($parsed['success'] ?? false) === true || ($parsed['ok'] ?? false) === true;
        $codes = $parsed['error-codes'] ?? [];
        if (is_array($codes)) {
            $errorCodes = array_values(array_filter($codes, 'is_string'));
        }
    }

    return ['http' => $status, 'success' => $success, 'error_codes' => $errorCodes];
}

/**
 * The pure gate decision: the endpoint status for a token candidate
 * and an upstream answer. Missing token denies. A transport failure,
 * a 5xx or a 401/404 kiwi answer is a gate fault and answers 503 (fail
 * closed, and the client is not at fault). A pass requires the
 * upstream to say success on a 2xx status: a redirect (3xx) or any
 * other non-2xx answer carrying a success-shaped body never opens the
 * gate (status/body mismatches fail closed). Everything else denies
 * with 403 unless the upstream said success.
 *
 * @return array{0: int, 1: array<string, string>} status plus headers
 */
function kiwi_verify_decide(?string $token, array $upstream, array $cfg): array
{
    if ($token === null) {
        return kiwi_verify_deny($cfg);
    }
    if ($upstream['http'] === 0 || $upstream['http'] >= 500 || $upstream['http'] === 401 || $upstream['http'] === 404) {
        return [503, ['X-Kiwi-Gate-Fault' => '1']];
    }
    if ($upstream['success'] === true && $upstream['http'] >= 200 && $upstream['http'] <= 299) {
        return [204, []];
    }

    return kiwi_verify_deny($cfg);
}

/**
 * The deny response shape: 403 with the deny marker by default, or a
 * 302 to the configured redirect target (the gateway then forwards the
 * browser; for nginx use error_page, see nginx/README.md). A redirect
 * target that carries a control character is never emitted (no
 * response splitting), and the request then denies with 403.
 */
function kiwi_verify_deny(array $cfg): array
{
    $redirect = (string) ($cfg['redirect'] ?? '');
    if (($cfg['deny_redirect'] ?? false) === true
        && $redirect !== ''
        && !kiwi_verify_has_control($redirect)) {
        return [302, ['Location' => $redirect, 'X-Kiwi-Deny' => '1']];
    }

    return [403, ['X-Kiwi-Deny' => '1', 'Content-Type' => 'application/json']];
}

if (!defined('KIWI_VERIFY_LIBRARY')) {
    $cfg = kiwi_verify_config();
    $method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $requestPath = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
    if ($method === 'GET' && $requestPath === '/healthz') {
        // Exact path match (a suffix like /admin/healthz is not this
        // endpoint) and the scope is JSON-encoded (a configured scope
        // can never break out of the document).
        $healthy = $cfg['config_error'] === null;
        http_response_code($healthy ? 200 : 503);
        header('Content-Type: application/json');
        echo json_encode([
            'status' => $healthy ? 'ok' : 'error',
            'scope' => $cfg['scope'],
        ], JSON_UNESCAPED_SLASHES)."\n";
        exit;
    }
    if ($cfg['config_error'] !== null) {
        // Fail closed: a gate whose own configuration is unsafe (a
        // non-http(s) verify target, a CRLF-bearing knob, an out of
        // grammar scope) never answers a pass.
        error_log('kiwicaptcha gateway: configuration error: '.$cfg['config_error']);
        http_response_code(503);
        header('X-Kiwi-Gate-Fault: 1');
        exit;
    }
    $rawBody = $method === 'POST' ? kiwi_verify_read_body() : null;
    $token = kiwi_verify_extract_token($_SERVER, $_POST, $_COOKIE, $rawBody);
    $clientIp = kiwi_verify_client_ip($_SERVER, $cfg['trusted_proxies']);
    if ($token === null || $clientIp === '') {
        // A missing or malformed socket peer fails closed: never
        // invent 127.0.0.1.
        [$status, $headers] = kiwi_verify_deny($cfg);
    } else {
        $upstream = kiwi_verify_call(
            $cfg['verify_url'],
            $token,
            $cfg['scope'],
            $clientIp,
            $cfg,
        );
        [$status, $headers] = kiwi_verify_decide($token, $upstream, $cfg);
    }
    http_response_code($status);
    foreach ($headers as $name => $value) {
        header($name.': '.$value);
    }
    if ($status === 403 && ($headers['Content-Type'] ?? '') === 'application/json') {
        echo "{\"success\":false,\"error-codes\":[\"invalid-input-response\"]}\n";
    }
    exit;
}
