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
        $ip = self::clientIp($server, (bool) ($settings['trust_proxy'] ?? false));
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
