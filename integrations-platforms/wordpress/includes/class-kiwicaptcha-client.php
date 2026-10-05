<?php
/**
 * The kiwi verify client: token extraction, the server-to-server call
 * through wp_remote_post, and the decision table. The evaluate() entry
 * is pure, so the whole gate is unit-testable outside WordPress.
 *
 * @package kiwicaptcha
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The verification client. Static methods; the options store is the
 * state.
 */
final class KiwiCaptcha_Client
{
    /**
     * The incumbent response field names the shims maintain, plus the
     * native field, in extraction order.
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
     * The pure gate decision. Returns the outcome array
     * {ok: bool, code: string, status: int}: ok gates the request,
     * code names the reason, status is the HTTP shape of the same
     * answer (200 pass, 403 deny, 503 fault).
     *
     * @param array<string, mixed> $settings the merged options
     * @param string               $scope    the challenge scope
     * @param array<string, mixed> $server   $_SERVER
     * @param array<string, mixed> $post     $_POST plus parsed JSON
     */
    public static function evaluate(array $settings, string $scope, array $server, array $post, ?string $rawBody = null): array
    {
        $token = self::extractToken($server, $post, $_COOKIE ?? [], $rawBody);
        if ($token === null) {
            return ['ok' => false, 'code' => 'missing_token', 'status' => 403];
        }
        $result = self::verify($settings, $token, $scope, $server);
        if (is_wp_error($result)) {
            return ['ok' => false, 'code' => 'verify_unavailable', 'status' => 503];
        }
        $status = (int) wp_remote_retrieve_response_code($result);
        if ($status === 0 || $status >= 500 || $status === 401 || $status === 404) {
            return ['ok' => false, 'code' => 'verify_unavailable', 'status' => 503];
        }
        $body = json_decode((string) wp_remote_retrieve_body($result), true);
        if (!is_array($body)) {
            return ['ok' => false, 'code' => 'verify_unreadable', 'status' => 503];
        }
        if (($body['success'] ?? false) === true) {
            return ['ok' => true, 'code' => 'verified', 'status' => 200];
        }

        return ['ok' => false, 'code' => 'challenge_failed', 'status' => 403];
    }

    /**
     * The first present token: header, then form fields (native and
     * incumbent), then a JSON body, then the kiwi_token cookie.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     */
    public static function extractToken(array $server, array $post, array $cookie, ?string $rawBody = null): ?string
    {
        $header = $server['HTTP_X_KIWI_TOKEN'] ?? null;
        if (is_string($header) && trim($header) !== '') {
            return trim($header);
        }
        foreach (self::TOKEN_FIELDS as $field) {
            $value = $post[$field] ?? null;
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        if (is_string($rawBody) && trim($rawBody) !== ''
            && is_string($server['CONTENT_TYPE'] ?? null)
            && strpos((string) $server['CONTENT_TYPE'], 'application/json') !== false) {
            $parsed = json_decode($rawBody, true);
            $value = is_array($parsed) ? ($parsed['token'] ?? null) : null;
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        $cookieToken = $cookie['kiwi_token'] ?? null;
        if (is_string($cookieToken) && trim($cookieToken) !== '') {
            return trim($cookieToken);
        }

        return null;
    }

    /**
     * The wp_remote_post call. json mode speaks the sidecar contract
     * (token/scope/remoteip with the bearer header); compat mode
     * speaks the siteverify contract (response/secret/remoteip form
     * encoding).
     *
     * @return array|WP_Error the raw HTTP result
     */
    public static function verify(array $settings, string $token, string $scope, array $server = [])
    {
        $ip = self::clientIp($server, !empty($settings['trust_proxy']));
        if (($settings['mode'] ?? 'json') === 'compat') {
            $body = http_build_query([
                'secret' => (string) ($settings['bearer'] ?? ''),
                'response' => $token,
                'remoteip' => $ip,
            ]);
            $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
        } else {
            $body = wp_json_encode(['token' => $token, 'scope' => $scope, 'remoteip' => $ip]);
            $headers = ['Content-Type' => 'application/json'];
            if ((string) ($settings['bearer'] ?? '') !== '') {
                $headers['Authorization'] = 'Bearer '.(string) $settings['bearer'];
            }
        }

        return wp_remote_post((string) $settings['verify_url'], [
            'timeout' => 5,
            'redirection' => 0,
            'body' => $body,
            'headers' => $headers,
        ]);
    }

    /**
     * The client ip bound into the verify call.
     *
     * @param array<string, mixed> $server
     */
    public static function clientIp(array $server, bool $trustProxy): string
    {
        if ($trustProxy) {
            $forwarded = $server['HTTP_X_FORWARDED_FOR'] ?? null;
            if (is_string($forwarded) && $forwarded !== '') {
                $first = trim(explode(',', $forwarded)[0]);
                if ($first !== '') {
                    return $first;
                }
            }
        }

        return (string) ($server['REMOTE_ADDR'] ?? '127.0.0.1');
    }
}
