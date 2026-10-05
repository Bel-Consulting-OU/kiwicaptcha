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
        $ip = self::clientIp($server, (bool) ($settings['trust_proxy'] ?? false));
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
        if (($body['success'] ?? false) === true) {
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
