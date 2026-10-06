<?php

/*
 * This file is part of kiwi/flarum-captcha.
 *
 * The framework-free kiwi verify client: token extraction, the wire
 * request, the decision table. The only type it knows is Guzzle's
 * client interface, which Flarum ships.
 */

namespace Kiwi\FlarumCaptcha\Api;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

class KiwiVerifier
{
    public const TOKEN_FIELDS = [
        'kiwi__token',
        'g-recaptcha-response',
        'h-captcha-response',
        'cf-turnstile-response',
        'frc-captcha-solution',
        'altcha',
    ];

    private ClientInterface $client;

    public function __construct(ClientInterface $client)
    {
        $this->client = $client;
    }

    /**
     * Verify one token for one scope.
     *
     * @param array<string, mixed> $settings
     * @param array<string, mixed> $server
     *
     * @return array{ok: bool, code: string}
     */
    public function verify(array $settings, string $token, string $scope, array $server = []): array
    {
        $request = self::buildRequest($settings, $token, $scope, $server);
        try {
            $response = $this->client->request('POST', $request['url'], [
                'headers' => $request['headers'],
                'body' => $request['body'],
                'timeout' => 5,
                'http_errors' => false,
            ]);
        } catch (GuzzleException $e) {
            return ['ok' => false, 'code' => 'verify_unavailable'];
        }

        return self::decide((int) $response->getStatusCode(), (string) $response->getBody());
    }

    /**
     * The wire request for the sidecar json contract.
     *
     * @param array<string, mixed> $settings
     * @param array<string, mixed> $server
     *
     * @return array{url: string, headers: array<string, string>, body: string}
     */
    public static function buildRequest(array $settings, string $token, string $scope, array $server): array
    {
        $ip = self::clientIp($server, (string) ($settings['trusted_proxies'] ?? ''));
        $headers = ['Content-Type' => 'application/json'];
        if ((string) ($settings['bearer'] ?? '') !== '') {
            $headers['Authorization'] = 'Bearer '.(string) $settings['bearer'];
        }

        return [
            'url' => (string) ($settings['verify_url'] ?? 'http://127.0.0.1:7371/verify'),
            'headers' => $headers,
            'body' => json_encode(['token' => $token, 'scope' => $scope, 'remoteip' => $ip], JSON_UNESCAPED_SLASHES),
        ];
    }

    /**
     * The decision table: status plus provider-shaped body.
     *
     * @return array{ok: bool, code: string}
     */
    public static function decide(int $status, string $body): array
    {
        if ($status === 0 || $status >= 500 || $status === 401 || $status === 404) {
            return ['ok' => false, 'code' => 'verify_unavailable'];
        }
        $parsed = json_decode($body, true);
        if (!is_array($parsed)) {
            return ['ok' => false, 'code' => 'verify_unreadable'];
        }
        if (($parsed['success'] ?? false) === true) {
            return ['ok' => true, 'code' => 'verified'];
        }

        return ['ok' => false, 'code' => 'challenge_failed'];
    }

    /**
     * The first present token: header, form fields, cookie.
     *
     * @param array<string, mixed> $params
     * @param array<string, mixed> $cookies
     */
    public static function extractToken(string $headerToken, array $params, array $cookies): ?string
    {
        if (trim($headerToken) !== '') {
            return trim($headerToken);
        }
        foreach (self::TOKEN_FIELDS as $field) {
            $value = $params[$field] ?? null;
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        $cookie = $cookies['kiwi_token'] ?? null;
        if (is_string($cookie) && trim($cookie) !== '') {
            return trim($cookie);
        }

        return null;
    }

    /**
     * The client ip bound into the verify call, resolved through the
     * shared trusted-proxy walk: the socket peer wins unless the peer
     * sits inside the trusted proxy CIDR list (the default empty list
     * trusts nobody, so a forged X-Forwarded-For never moves the
     * binding). The chain is walked right to left through the trusted
     * hops and X-Real-IP is honored when no chain exists.
     *
     * @param array<string, mixed> $server
     */
    public static function clientIp(array $server, string $trustedProxies = ''): string
    {
        $cidrs = [];
        foreach (explode(',', $trustedProxies) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate !== '') {
                $cidrs[] = $candidate;
            }
        }
        $peer = (string) ($server['REMOTE_ADDR'] ?? '127.0.0.1');
        if ($cidrs === []) {
            return $peer;
        }
        $peerCanonical = self::canonicalIp($peer);
        $peerTrusted = $peerCanonical !== null && self::inTrusted($peerCanonical, $cidrs);
        $forwarded = isset($server['HTTP_X_FORWARDED_FOR']) && is_string($server['HTTP_X_FORWARDED_FOR'])
            ? trim($server['HTTP_X_FORWARDED_FOR'])
            : '';
        if ($forwarded === '') {
            if (!$peerTrusted) {
                return $peer;
            }
            $realIp = isset($server['HTTP_X_REAL_IP']) && is_string($server['HTTP_X_REAL_IP'])
                ? trim($server['HTTP_X_REAL_IP'])
                : '';
            if ($realIp === '' || preg_match('/[\x00-\x1F\x7F]/', $realIp) === 1) {
                return $peer;
            }
            $canonical = self::canonicalIp($realIp);

            return $canonical ?? $peer;
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $forwarded) === 1 || !$peerTrusted) {
            return $peer;
        }
        foreach (array_reverse(array_map('trim', explode(',', $forwarded))) as $hop) {
            $canonical = self::canonicalIp($hop);
            if ($canonical === null) {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back.
                return $peer;
            }
            if (!self::inTrusted($canonical, $cidrs)) {
                return $canonical;
            }
        }

        return $peer;
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
}
