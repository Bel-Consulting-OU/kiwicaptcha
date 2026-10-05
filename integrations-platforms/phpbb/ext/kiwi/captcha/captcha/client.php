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
        $ip = client::client_ip($server, !empty($settings['trust_proxy']));
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
     * The client ip bound into the verify call.
     *
     * @param array<string, mixed> $server
     */
    public static function client_ip(array $server, bool $trust_proxy): string
    {
        if ($trust_proxy) {
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
