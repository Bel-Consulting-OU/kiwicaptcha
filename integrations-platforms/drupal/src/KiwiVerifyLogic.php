<?php

declare(strict_types=1);

namespace Drupal\kiwicaptcha;

/**
 * The framework-free kiwi verify logic: token extraction, the wire
 * body, the decision table. No Drupal classes and no I/O: the HTTP
 * transport is an injected callable, so the whole file unit-tests
 * with plain php.
 */
final class KiwiVerifyLogic
{
    /**
     * The shim response field names, native first, in extraction order.
     */
    public const TOKEN_FIELDS = [
        'kiwi__token',
        'g-recaptcha-response',
        'h-captcha-response',
        'cf-turnstile-response',
        'frc-captcha-solution',
        'altcha',
    ];

    /**
     * The namespaced JSON body keys. The bare "token" key is
     * deliberately absent: an application POSTing its own {"token":…}
     * API credential must never have that value consumed (and
     * forwarded) as a captcha token.
     */
    public const JSON_TOKEN_FIELDS = [
        'kiwi_token',
        'captcha_response',
    ];

    /**
     * The first present token: header, form values, JSON body, cookie.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $values
     * @param array<string, mixed> $cookie
     */
    public static function extractToken(array $server, array $values, array $cookie, ?string $rawBody = null): ?string
    {
        $header = $server['HTTP_X_KIWI_TOKEN'] ?? null;
        if (is_string($header) && trim($header) !== '') {
            return trim($header);
        }
        foreach (self::TOKEN_FIELDS as $field) {
            $value = $values[$field] ?? null;
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        if (is_string($rawBody) && trim($rawBody) !== ''
            && is_string($server['CONTENT_TYPE'] ?? null)
            && strpos((string) $server['CONTENT_TYPE'], 'application/json') !== false) {
            $parsed = json_decode($rawBody, true);
            foreach (self::JSON_TOKEN_FIELDS as $field) {
                $value = is_array($parsed) ? ($parsed[$field] ?? null) : null;
                if (is_string($value) && trim($value) !== '') {
                    return trim($value);
                }
            }
        }
        $cookieToken = $cookie['kiwi_token'] ?? null;
        if (is_string($cookieToken) && trim($cookieToken) !== '') {
            return trim($cookieToken);
        }

        return null;
    }

    /**
     * The client ip bound into the verify call, resolved through the
     * shared trusted-proxy walk: the socket peer wins unless the peer
     * sits inside the trusted_proxies CIDR list (the default empty
     * list trusts nobody, so a forged X-Forwarded-For never moves the
     * binding). The chain is walked right to left through the trusted
     * hops and X-Real-IP is honored when no chain exists.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $settings
     */
    public static function clientIp(array $server, array $settings = []): string
    {
        $cidrs = [];
        foreach (explode(',', (string) ($settings['trusted_proxies'] ?? '')) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate !== '') {
                $cidrs[] = $candidate;
            }
        }
        $peerCanonical = self::canonicalIp((string) ($server['REMOTE_ADDR'] ?? ''));
        if ($peerCanonical === null) {
            // Fail closed: a missing or unparsable socket peer is not a
            // loopback client. The caller refuses the request rather
            // than inventing 127.0.0.1 or forwarding a fabricated
            // identity.
            return '';
        }
        if ($cidrs === []) {
            return $peerCanonical;
        }
        $peerTrusted = self::inTrusted($peerCanonical, $cidrs);
        $forwarded = isset($server['HTTP_X_FORWARDED_FOR']) && is_string($server['HTTP_X_FORWARDED_FOR'])
            ? trim($server['HTTP_X_FORWARDED_FOR'])
            : '';
        if ($forwarded === '') {
            if (!$peerTrusted) {
                return $peerCanonical;
            }
            $realIp = isset($server['HTTP_X_REAL_IP']) && is_string($server['HTTP_X_REAL_IP'])
                ? trim($server['HTTP_X_REAL_IP'])
                : '';
            if ($realIp === '' || preg_match('/[\x00-\x1F\x7F]/', $realIp) === 1) {
                return $peerCanonical;
            }
            $canonical = self::canonicalIp($realIp);

            return $canonical ?? $peerCanonical;
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $forwarded) === 1 || !$peerTrusted) {
            return $peerCanonical;
        }
        foreach (array_reverse(array_map('trim', explode(',', $forwarded))) as $hop) {
            $canonical = self::canonicalIp($hop);
            if ($canonical === null) {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back.
                return $peerCanonical;
            }
            if (!self::inTrusted($canonical, $cidrs)) {
                return $canonical;
            }
        }

        return $peerCanonical;
    }

    /**
     * The canonical IP text of one forwarded node, or null when it is
     * not a genuine address: bare IPv4, IPv4 with a port, bracketed
     * IPv6 with an optional port; unknown, obfuscated tokens and
     * malformed ports refuse; IPv4-mapped IPv6 normalizes to IPv4.
     */
    private static function canonicalIp(string $identifier): ?string
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
            if ($suffix !== '' && !self::portSuffix($suffix)) {
                return null;
            }
            $candidate = substr($candidate, 1, $closing - 1);
        } elseif (substr_count($candidate, ':') === 1) {
            $parts = explode(':', $candidate);
            if (count($parts) === 2
                && filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                && self::portSuffix(':'.$parts[1])) {
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
            return (string) inet_ntop(substr($packed, 12));
        }

        return (string) inet_ntop($packed);
    }

    /**
     * Exactly ":" plus a decimal port in the 1..65535 range.
     */
    private static function portSuffix(string $suffix): bool
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
     * bits set in a CIDR are masked away, and an IPv4-mapped IPv6
     * address matches in its IPv4 form.
     *
     * @param list<string> $cidrs
     */
    private static function inTrusted(string $ip, array $cidrs): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        foreach ($cidrs as $cidr) {
            $cidr = trim($cidr);
            if ($cidr === '') {
                continue;
            }
            if (!str_contains($cidr, '/')) {
                $network = self::canonicalIp($cidr);
                if ($network !== null && $network === $ip) {
                    return true;
                }
                continue;
            }
            [$networkText, $prefixText] = explode('/', $cidr, 2);
            if (!ctype_digit($prefixText)) {
                continue;
            }
            $networkCanonical = self::canonicalIp($networkText);
            if ($networkCanonical === null) {
                continue;
            }
            $network = @inet_pton($networkCanonical);
            if ($network === false || strlen($network) !== strlen($packed)) {
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
     * The request for the transport callable: mode json speaks the
     * sidecar, mode compat speaks siteverify.
     *
     * @param array<string, mixed> $settings
     *
     * @return array{url: string, headers: array<string, string>, body: string}
     */
    public static function buildRequest(array $settings, string $token, string $scope, array $server): array
    {
        $ip = self::clientIp($server, $settings);
        if (($settings['mode'] ?? 'json') === 'compat') {
            $body = http_build_query([
                'secret' => (string) ($settings['bearer'] ?? ''),
                'response' => $token,
                'remoteip' => $ip,
            ]);
            $contentType = 'application/x-www-form-urlencoded';
        } else {
            $body = json_encode(['token' => $token, 'scope' => $scope, 'remoteip' => $ip], JSON_UNESCAPED_SLASHES);
            $contentType = 'application/json';
        }
        $headers = ['Content-Type' => $contentType];
        if (($settings['mode'] ?? 'json') !== 'compat' && (string) ($settings['bearer'] ?? '') !== '') {
            $headers['Authorization'] = 'Bearer '.(string) $settings['bearer'];
        }

        return [
            'url' => (string) ($settings['verify_url'] ?? 'http://127.0.0.1:7371/verify'),
            'headers' => $headers,
            'body' => $body,
        ];
    }

    /**
     * The decision table over a transport answer
     * array{status: int, body: string}.
     *
     * @param array<string, mixed> $settings
     *
     * @return array{ok: bool, code: string}
     */
    public static function decide(array $settings, string $token, string $scope, array $server, callable $transport): array
    {
        $request = self::buildRequest($settings, $token, $scope, $server);
        try {
            $answer = $transport($request);
        } catch (\Throwable $e) {
            return ['ok' => false, 'code' => 'verify_unavailable'];
        }
        $status = (int) ($answer['status'] ?? 0);
        if ($status === 0 || $status >= 500 || $status === 401 || $status === 404) {
            return ['ok' => false, 'code' => 'verify_unavailable'];
        }
        $body = json_decode((string) ($answer['body'] ?? ''), true);
        if (!is_array($body)) {
            return ['ok' => false, 'code' => 'verify_unreadable'];
        }
        // A pass requires the upstream to say success on a 2xx status:
        // a redirect (3xx) or any other non-2xx carrying a
        // success-shaped body is a status/body mismatch and fails
        // closed.
        if ($status >= 200 && $status <= 299 && ($body['success'] ?? false) === true) {
            return ['ok' => true, 'code' => 'verified'];
        }

        return ['ok' => false, 'code' => 'challenge_failed'];
    }

    /**
     * The scope for a form id, read from the settings array shape the
     * module stores: enabled_<scope> and scope_<scope> keys.
     *
     * @param array<string, mixed> $settings
     */
    public static function scopeForForm(string $formId, array $settings): ?string
    {
        $map = [
            'user_login_form' => 'login',
            'user_login_block' => 'login',
            'user_register_form' => 'signup',
            'comment_form' => 'comment',
        ];
        $scope = $map[$formId] ?? (str_starts_with($formId, 'contact_message') ? 'contact' : null);
        if ($scope === null || empty($settings['enabled_'.$scope])) {
            return null;
        }
        $configured = $settings['scope_'.$scope] ?? $scope;

        return is_string($configured) && preg_match('/^[A-Za-z0-9_:-]{1,64}$/', $configured) === 1
            ? $configured
            : $scope;
    }
}
