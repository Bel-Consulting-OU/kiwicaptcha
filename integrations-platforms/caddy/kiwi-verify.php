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
 * a JSON body {"token": ...}, and the kiwi_token cookie. Note the
 * nginx auth_request subrequest carries headers and cookies only; the
 * body sources exist for Traefik forwardAuth, which forwards them.
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
 * The effective configuration. $_SERVER wins over the process
 * environment so an nginx fastcgi_param or an FPM pool env directive
 * configures the endpoint without touching the process env.
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

    return [
        'verify_url' => $env('KIWI_VERIFY_URL', 'http://127.0.0.1:7371/verify'),
        'bearer' => $env('KIWI_BEARER', ''),
        'scope' => $env('KIWI_SCOPE', 'login'),
        'mode' => $env('KIWI_VERIFY_MODE', 'json') === 'compat' ? 'compat' : 'json',
        'trusted_proxies' => kiwi_verify_parse_cidrs($env('KIWI_TRUSTED_PROXIES', '')),
        'deny_redirect' => $env('KIWI_DENY', '403') === '302' && $env('KIWI_REDIRECT', '') !== '',
        'redirect' => $env('KIWI_REDIRECT', ''),
        'timeout' => (float) ($env('KIWI_TIMEOUT', '5') ?: '5'),
    ];
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
 * The first present token from the shared source list, or null.
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
        && is_string($server['CONTENT_TYPE'] ?? null)
        && str_contains((string) $server['CONTENT_TYPE'], 'application/json')) {
        $parsed = json_decode($rawBody, true);
        $value = is_array($parsed) ? ($parsed['token'] ?? null) : null;
        if (is_string($value) && trim($value) !== '') {
            $candidates[] = trim($value);
        }
    }
    $cookieToken = $cookie['kiwi_token'] ?? null;
    if (is_string($cookieToken) && trim($cookieToken) !== '') {
        $candidates[] = trim($cookieToken);
    }

    foreach ($candidates as $candidate) {
        if ($candidate !== '') {
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
 * trusted and no chain exists.
 */
function kiwi_verify_client_ip(array $server, array $trustedCidrs): string
{
    $peer = (string) ($server['REMOTE_ADDR'] ?? '127.0.0.1');
    if ($trustedCidrs === []) {
        return $peer;
    }
    $peerCanonical = kiwi_verify_canonical_ip($peer);
    $peerTrusted = $peerCanonical !== null && kiwi_verify_in_trusted($peerCanonical, $trustedCidrs);
    $forwarded = $server['HTTP_X_FORWARDED_FOR'] ?? null;
    if (!is_string($forwarded) || trim($forwarded) === '') {
        if (!$peerTrusted) {
            return $peer;
        }
        $realIp = $server['HTTP_X_REAL_IP'] ?? null;
        if (!is_string($realIp)) {
            return $peer;
        }
        $realIp = trim($realIp);
        if ($realIp === '' || preg_match('/[\x00-\x1F\x7F]/', $realIp) === 1) {
            return $peer;
        }
        $canonical = kiwi_verify_canonical_ip($realIp);

        return $canonical ?? $peer;
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $forwarded) === 1 || !$peerTrusted) {
        return $peer;
    }
    $hops = array_reverse(array_map('trim', explode(',', $forwarded)));
    foreach ($hops as $hop) {
        $canonical = kiwi_verify_canonical_ip($hop);
        if ($canonical === null) {
            // An unparsable hop terminates the trust chain: who lies
            // beyond it cannot be established, so the peer falls back.
            return $peer;
        }
        if (!kiwi_verify_in_trusted($canonical, $trustedCidrs)) {
            return $canonical;
        }
    }

    return $peer;
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
            $status = (int) $m[1];
            break;
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
 * closed, and the client is not at fault). Everything else denies with
 * 403 unless the upstream said success.
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
    if ($upstream['success'] === true) {
        return [204, []];
    }

    return kiwi_verify_deny($cfg);
}

/**
 * The deny response shape: 403 with the deny marker by default, or a
 * 302 to the configured redirect target (the gateway then forwards the
 * browser; for nginx use error_page, see nginx/README.md).
 */
function kiwi_verify_deny(array $cfg): array
{
    if ($cfg['deny_redirect']) {
        return [302, ['Location' => $cfg['redirect'], 'X-Kiwi-Deny' => '1']];
    }

    return [403, ['X-Kiwi-Deny' => '1', 'Content-Type' => 'application/json']];
}

if (!defined('KIWI_VERIFY_LIBRARY')) {
    $cfg = kiwi_verify_config();
    $method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if ($method === 'GET' && str_ends_with((string) ($_SERVER['REQUEST_URI'] ?? ''), '/healthz')) {
        http_response_code(200);
        header('Content-Type: application/json');
        echo "{\"status\":\"ok\",\"scope\":\"{$cfg['scope']}\"}\n";
        exit;
    }
    $rawBody = $method === 'POST' ? (string) file_get_contents('php://input') : null;
    $jsonPost = [];
    if ($rawBody !== null && str_contains((string) ($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json')) {
        $decoded = json_decode($rawBody, true);
        if (is_array($decoded)) {
            $jsonPost = $decoded;
        }
    }
    $token = kiwi_verify_extract_token($_SERVER, $_POST + $jsonPost, $_COOKIE, $rawBody);
    if ($token === null) {
        [$status, $headers] = kiwi_verify_deny($cfg);
    } else {
        $upstream = kiwi_verify_call(
            $cfg['verify_url'],
            $token,
            $cfg['scope'],
            kiwi_verify_client_ip($_SERVER, $cfg['trusted_proxies']),
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
