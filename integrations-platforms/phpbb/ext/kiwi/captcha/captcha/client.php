<?php
/**
 * The kiwi verify client for the phpBB extension. The transport is
 * phpBB's http_client service (Guzzle), injected; the request
 * building and the decision table are pure static methods, so they
 * unit-test with plain php.
 *
 * @package kiwi\captcha\captcha
 */

namespace kiwi\captcha\captcha;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

class client
{
    /** @var ClientInterface */
    protected $http_client;

    public function __construct(ClientInterface $http_client)
    {
        $this->http_client = $http_client;
    }

    /**
     * Verify one token for one scope with the board's configured
     * settings (the kiwi_* config keys).
     *
     * @param array<string, mixed> $settings the resolved settings
     * @param string               $token    the challenge token
     * @param string               $scope    the challenge scope
     * @param array<string, mixed> $server   the server superglobal
     *
     * @return array{ok: bool, code: string}
     */
    public function verify(array $settings, string $token, string $scope, array $server = []): array
    {
        $request = client::build_request($settings, $token, $scope, $server);
        try {
            $response = $this->http_client->request('POST', $request['url'], [
                'headers' => $request['headers'],
                'body' => $request['body'],
                'timeout' => 5,
                'http_errors' => false,
            ]);
        } catch (GuzzleException $e) {
            return ['ok' => false, 'code' => 'verify_unavailable'];
        }

        return client::decide(
            (int) $response->getStatusCode(),
            (string) $response->getBody()
        );
    }

    /**
     * The wire request: mode json speaks the sidecar, mode compat
     * speaks siteverify.
     *
     * @param array<string, mixed> $settings
     * @param array<string, mixed> $server
     *
     * @return array{url: string, headers: array<string, string>, body: string}
     */
    public static function build_request(array $settings, string $token, string $scope, array $server): array
    {
        $ip = client::client_ip($server, (string) ($settings['trusted_proxies'] ?? ''));
        if (($settings['mode'] ?? 'json') === 'compat') {
            $body = http_build_query([
                'secret' => (string) ($settings['bearer'] ?? ''),
                'response' => $token,
                'remoteip' => $ip,
            ]);
            $content_type = 'application/x-www-form-urlencoded';
        } else {
            $body = json_encode(['token' => $token, 'scope' => $scope, 'remoteip' => $ip], JSON_UNESCAPED_SLASHES);
            $content_type = 'application/json';
        }
        $headers = ['Content-Type' => $content_type];
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
     * The decision table: status plus provider-shaped body. A
     * transport failure, 5xx or 401/404 is a gate fault; the rest
     * answer the challenge verdict.
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
     * The client ip bound into the verify call, resolved through the
     * shared trusted-proxy walk: the socket peer wins unless the peer
     * sits inside the trusted proxy CIDR list (the default empty list
     * trusts nobody, so a forged X-Forwarded-For never moves the
     * binding). The chain is walked right to left through the trusted
     * hops and X-Real-IP is honored when no chain exists.
     *
     * @param array<string, mixed> $server
     */
    public static function client_ip(array $server, string $trusted_proxies = ''): string
    {
        $cidrs = [];
        foreach (explode(',', $trusted_proxies) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate !== '') {
                $cidrs[] = $candidate;
            }
        }
        $peer = (string) ($server['REMOTE_ADDR'] ?? '127.0.0.1');
        if ($cidrs === []) {
            return $peer;
        }
        $peer_canonical = self::canonical_ip($peer);
        $peer_trusted = $peer_canonical !== null && self::in_trusted($peer_canonical, $cidrs);
        $forwarded = isset($server['HTTP_X_FORWARDED_FOR']) && is_string($server['HTTP_X_FORWARDED_FOR'])
            ? trim($server['HTTP_X_FORWARDED_FOR'])
            : '';
        if ($forwarded === '') {
            if (!$peer_trusted) {
                return $peer;
            }
            $real_ip = isset($server['HTTP_X_REAL_IP']) && is_string($server['HTTP_X_REAL_IP'])
                ? trim($server['HTTP_X_REAL_IP'])
                : '';
            if ($real_ip === '' || preg_match('/[\x00-\x1F\x7F]/', $real_ip) === 1) {
                return $peer;
            }
            $canonical = self::canonical_ip($real_ip);

            return $canonical ?? $peer;
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $forwarded) === 1 || !$peer_trusted) {
            return $peer;
        }
        foreach (array_reverse(array_map('trim', explode(',', $forwarded))) as $hop) {
            $canonical = self::canonical_ip($hop);
            if ($canonical === null) {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back.
                return $peer;
            }
            if (!self::in_trusted($canonical, $cidrs)) {
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
    private static function canonical_ip(string $identifier): ?string
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
            if ($suffix !== '' && !self::port_suffix($suffix)) {
                return null;
            }
            $candidate = substr($candidate, 1, $closing - 1);
        } elseif (substr_count($candidate, ':') === 1) {
            $parts = explode(':', $candidate);
            if (count($parts) === 2
                && filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                && self::port_suffix(':'.$parts[1])) {
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
    private static function port_suffix(string $suffix): bool
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
    private static function in_trusted(string $ip, array $cidrs): bool
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
                $network = self::canonical_ip($cidr);
                if ($network !== null && $network === $ip) {
                    return true;
                }
                continue;
            }
            [$network_text, $prefix_text] = explode('/', $cidr, 2);
            if (!ctype_digit($prefix_text)) {
                continue;
            }
            $network_canonical = self::canonical_ip($network_text);
            if ($network_canonical === null) {
                continue;
            }
            $network = @inet_pton($network_canonical);
            if ($network === false || strlen($network) !== strlen($packed)) {
                continue;
            }
            $bits = strlen($packed) * 8;
            $prefix = (int) $prefix_text;
            if ($prefix < 0 || $prefix > $bits) {
                continue;
            }
            $full_bytes = intdiv($prefix, 8);
            $remainder = $prefix % 8;
            if (substr($network, 0, $full_bytes) !== substr($packed, 0, $full_bytes)) {
                continue;
            }
            if ($remainder > 0 && $full_bytes < strlen($packed)) {
                $mask = chr((0xFF << (8 - $remainder)) & 0xFF);
                if ((substr($network, $full_bytes, 1) & $mask) !== (substr($packed, $full_bytes, 1) & $mask)) {
                    continue;
                }
            }

            return true;
        }

        return false;
    }
}
