<?php
/**
 * @package     KiwiCaptcha
 * @subpackage  plg_captcha_kiwicaptcha
 *
 * The framework-free kiwi verify client: token extraction, wire
 * bodies, decision table. No Joomla classes, so it unit-tests with
 * plain php.
 */

namespace Joomla\Plugin\Captcha\Kiwicaptcha;

defined('_JEXEC') or die;

final class KiwiClient
{
    /**
     * Test hook: when set, defaultTransport delegates here instead of
     * touching the network. Null in production.
     *
     * @var callable|null
     */
    public static $testTransport;

    /**
     * The shim response field names, native first.
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
     * The first present token: header, form values, explicit answer,
     * JSON body, cookie.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     */
    public static function extractToken(array $server, array $post, array $cookie, ?string $code = null): ?string
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
        if (is_string($code) && trim($code) !== '') {
            return trim($code);
        }
        if (is_string($server['CONTENT_TYPE'] ?? null) && strpos((string) $server['CONTENT_TYPE'], 'application/json') !== false) {
            $raw = file_get_contents('php://input');
            $parsed = is_string($raw) ? json_decode($raw, true) : null;
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
     * Scope names are short kiwi identifiers.
     */
    public static function sanitizeScope(string $scope): string
    {
        if (preg_match('/^[A-Za-z0-9_:-]{1,64}$/', $scope) === 1) {
            return $scope;
        }

        return 'login';
    }

    /**
     * The verify call through Joomla's HttpFactory transport is the
     * service layer's business; this client takes a transport callable
     * array{status, body} (url, headers, body) => answer.
     *
     * @param array<string, mixed>  $params    the plugin params
     * @param string                $token     the challenge token
     * @param string                $scope     the challenge scope
     * @param array<string, mixed>  $server    the server superglobal
     * @param callable|null         $transport injected in tests
     *
     * @return array{ok: bool, code: string}
     */
    public static function verify(array $params, string $token, string $scope, array $server = [], ?callable $transport = null): array
    {
        $request = self::buildRequest($params, $token, $scope, $server);
        if ($transport === null) {
            $transport = [self::class, 'defaultTransport'];
        }
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
     * The wire request for the transport callable.
     *
     * @param array<string, mixed> $params
     * @param array<string, mixed> $server
     *
     * @return array{url: string, headers: array<string, string>, body: string}
     */
    public static function buildRequest(array $params, string $token, string $scope, array $server): array
    {
        $ip = self::clientIp($server, (bool) ($params['trust_proxy'] ?? false));
        if (($params['mode'] ?? 'json') === 'compat') {
            $body = http_build_query([
                'secret' => (string) ($params['bearer'] ?? ''),
                'response' => $token,
                'remoteip' => $ip,
            ]);
            $contentType = 'application/x-www-form-urlencoded';
        } else {
            $body = json_encode(['token' => $token, 'scope' => $scope, 'remoteip' => $ip], JSON_UNESCAPED_SLASHES);
            $contentType = 'application/json';
        }
        $headers = ['Content-Type' => $contentType];
        if (($params['mode'] ?? 'json') !== 'compat' && (string) ($params['bearer'] ?? '') !== '') {
            $headers['Authorization'] = 'Bearer '.(string) $params['bearer'];
        }

        return [
            'url' => (string) ($params['verify_url'] ?? 'http://127.0.0.1:7371/verify'),
            'headers' => $headers,
            'body' => $body,
        ];
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
     * The production transport: a blocking file_get_contents POST,
     * dependency free. Returns array{status, body}; status 0 on
     * transport failure.
     *
     * @param array{url: string, headers: array<string, string>, body: string} $request
     *
     * @return array{status: int, body: string}
     */
    public static function defaultTransport(array $request): array
    {
        if (self::$testTransport !== null) {
            return (self::$testTransport)($request);
        }
        $headerLines = [];
        foreach ($request['headers'] as $name => $value) {
            $headerLines[] = $name.': '.$value;
        }
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headerLines),
                'content' => $request['body'],
                'ignore_errors' => true,
                'follow_location' => 0,
                'timeout' => 5,
            ],
        ]);
        $response = @file_get_contents($request['url'], false, $context);
        $status = 0;
        foreach (($http_response_header ?? []) as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
                break;
            }
        }
        if ($response === false && $status === 0) {
            return ['status' => 0, 'body' => ''];
        }

        return ['status' => $status, 'body' => (string) $response];
    }
}
