<?php

/*
 * This file is part of kiwi/flarum-captcha.
 *
 * The api middleware: every registration request (POST /register)
 * must carry a kiwi proof-of-work token, verified server-to-server
 * against the deployment before Flarum's RegisterController runs.
 * The middleware is a PSR-15 handler, exactly what the
 * Flarum\Extend\Middleware extender adds to the api frontend. Flarum
 * resolves the constructor dependencies from the container.
 */

namespace Kiwi\FlarumCaptcha\Api\Middleware;

use Flarum\Settings\SettingsRepositoryInterface;
use GuzzleHttp\ClientInterface;
use Kiwi\FlarumCaptcha\Api\KiwiVerifier;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class VerifySignupMiddleware implements MiddlewareInterface
{
    public const VERIFY_URL_SETTING = 'kiwi-verify-url';

    public const BEARER_SETTING = 'kiwi-bearer';

    public const SCOPE_SETTING = 'kiwi-signup-scope';

    public const TRUST_PROXY_SETTING = 'kiwi-trust-proxy';

    public const ENABLED_SETTING = 'kiwi-enabled';

    private SettingsRepositoryInterface $settings;

    private ClientInterface $client;

    public function __construct(SettingsRepositoryInterface $settings, ClientInterface $client)
    {
        $this->settings = $settings;
        $this->client = $client;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (empty($this->settings->get(self::ENABLED_SETTING))
            || $request->getMethod() !== 'POST'
            || $request->getUri()->getPath() !== '/register') {
            return $handler->handle($request);
        }

        $serverParams = $request->getServerParams();
        $server = [
            'REMOTE_ADDR' => $serverParams['REMOTE_ADDR'] ?? '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => $serverParams['HTTP_X_FORWARDED_FOR'] ?? null,
        ];
        $params = (array) ($request->getParsedBody() ?: []);
        $token = KiwiVerifier::extractToken(
            $request->getHeaderLine('X-Kiwi-Token'),
            $params,
            $request->getCookieParams()
        );
        if ($token === null) {
            return new JsonResponse([
                'errors' => [['detail' => 'The security check did not run. Solve the challenge and try again.', 'code' => 'kiwi_captcha_missing']],
            ], 403);
        }

        $verifier = new KiwiVerifier($this->client);
        $result = $verifier->verify(
            [
                'verify_url' => (string) $this->settings->get(self::VERIFY_URL_SETTING),
                'bearer' => (string) $this->settings->get(self::BEARER_SETTING),
                'mode' => 'json',
                'trust_proxy' => !empty($this->settings->get(self::TRUST_PROXY_SETTING)),
            ],
            $token,
            (string) ($this->settings->get(self::SCOPE_SETTING) ?: 'signup'),
            $server
        );
        if ($result['ok']) {
            return $handler->handle($request);
        }

        $unavailable = in_array($result['code'], ['verify_unavailable', 'verify_unreadable'], true);

        return new JsonResponse([
            'errors' => [['detail' => $unavailable
                ? 'The security service is unavailable. Try again shortly.'
                : 'The security check did not pass. Solve the challenge and try again.',
            'code' => 'kiwi_captcha_'.$result['code']]],
        ], $unavailable ? 503 : 403);
    }
}
