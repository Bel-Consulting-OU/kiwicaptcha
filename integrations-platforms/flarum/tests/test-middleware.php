<?php

declare(strict_types=1);

/**
 * The plain-php test of the flarum extension: the framework-free
 * verifier plus the middleware against stubbed PSR-7/15 and Flarum
 * surfaces. Run: php tests/test-middleware.php
 */

$failures = 0;
$checks = 0;
function check(string $name, bool $condition): void
{
    global $failures, $checks;
    ++$checks;
    if (!$condition) {
        ++$failures;
        fwrite(STDERR, "FAIL: {$name}\n");
    }
}

// Declare the two framework types the middleware references, then
// load the real classes.
if (!interface_exists('Flarum\\Settings\\SettingsRepositoryInterface')) {
    // phpcs:ignore
    eval('namespace Flarum\Settings; interface SettingsRepositoryInterface {
        public function all(): array;
        public function get($key, $default = null);
        public function set($key, $value);
        public function delete($key);
    }');
}
if (!interface_exists('GuzzleHttp\\ClientInterface')) {
    // phpcs:ignore
    eval('namespace GuzzleHttp; interface ClientInterface { public function request(string $m, string $u, array $o = []); }
    class Exception extends \Exception {}
    interface GuzzleException {}');
}
if (!interface_exists('Psr\\Http\\Message\\ResponseInterface')) {
    // phpcs:ignore
    eval('namespace Psr\Http\Message; interface ResponseInterface {}
    interface StreamInterface {} interface UriInterface {} interface UploadedFileInterface {}
    interface ServerRequestFactoryInterface {} interface ResponseFactoryInterface {}');
}
if (!interface_exists('Psr\\Http\\Message\\ServerRequestInterface')) {
    // phpcs:ignore
    eval('namespace Psr\Http\Message; interface RequestInterface {} interface ServerRequestInterface extends RequestInterface {}');
}
if (!interface_exists('Psr\\Http\\Server\\RequestHandlerInterface')) {
    // phpcs:ignore
    eval('namespace Psr\Http\Server; interface RequestHandlerInterface {
        public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface;
    }');
}
if (!interface_exists('Psr\\Http\\Server\\MiddlewareInterface')) {
    // phpcs:ignore
    eval('namespace Psr\Http\Server; interface MiddlewareInterface {
        public function process(\Psr\Http\Message\ServerRequestInterface $request, \Psr\Http\Server\RequestHandlerInterface $handler): \Psr\Http\Message\ResponseInterface;
    }');
}
if (!class_exists('Laminas\\Diactoros\\Response\\JsonResponse')) {
    // phpcs:ignore
    eval('namespace Laminas\Diactoros\Response; class JsonResponse implements \Psr\Http\Message\ResponseInterface { private $payload; private $status;
        public function __construct($payload, int $status = 200, array $headers = []) { $this->payload = $payload; $this->status = $status; }
        public function getStatusCode(): int { return $this->status; }
        public function getPayload() { return $this->payload; }
    }');
}

require dirname(__DIR__).'/src/Api/KiwiVerifier.php';
require dirname(__DIR__).'/src/Api/Middleware/VerifySignupMiddleware.php';

use GuzzleHttp\ClientInterface;
use Kiwi\FlarumCaptcha\Api\KiwiVerifier;
use Kiwi\FlarumCaptcha\Api\Middleware\VerifySignupMiddleware;

// The pure verifier.
$request = KiwiVerifier::buildRequest(['verify_url' => 'http://127.0.0.1:7371/verify', 'bearer' => 'b'], 't', 'signup', ['REMOTE_ADDR' => '192.0.2.3']);
$body = json_decode($request['body'], true);
check('request shape', ($body['token'] ?? '') === 't' && ($body['scope'] ?? '') === 'signup' && ($body['remoteip'] ?? '') === '192.0.2.3');
check('bearer header', ($request['headers']['Authorization'] ?? '') === 'Bearer b');
check('decision success', KiwiVerifier::decide(200, '{"success":true}') === ['ok' => true, 'code' => 'verified']);
check('decision failure', KiwiVerifier::decide(200, '{"success":false}')['code'] === 'challenge_failed');
check('decision fault', KiwiVerifier::decide(502, '')['code'] === 'verify_unavailable');
check('302 with success body fails closed', KiwiVerifier::decide(302, '{"success":true}')['code'] === 'challenge_failed');
check('403 with success body fails closed', KiwiVerifier::decide(403, '{"success":true}')['code'] === 'challenge_failed');
check('429 with success body fails closed', KiwiVerifier::decide(429, '{"success":true}')['code'] === 'challenge_failed');
check('199 with success body fails closed', KiwiVerifier::decide(199, '{"success":true}')['code'] === 'challenge_failed');
check('204 with success body passes', KiwiVerifier::decide(204, '{"success":true}') === ['ok' => true, 'code' => 'verified']);
check('header token', KiwiVerifier::extractToken(' hdr ', [], []) === 'hdr');
check('form token', KiwiVerifier::extractToken('', ['cf-turnstile-response' => 'cf'], []) === 'cf');
check('cookie token', KiwiVerifier::extractToken('', [], ['kiwi_token' => 'ck']) === 'ck');
check('missing token', KiwiVerifier::extractToken('', [], []) === null);
check('untrusted peer ignores xff', KiwiVerifier::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.2, 10.0.0.9']) === '10.0.0.1');
check('trusted lb takes next left', KiwiVerifier::clientIp(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.2, 10.0.0.9'], '10.0.0.0/24') === '203.0.113.2');
check('client-supplied leftmost entry is ignored', KiwiVerifier::clientIp(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.2, 10.0.0.9'], '10.0.0.0/24') === '203.0.113.2');
check('garbage hop fails closed', KiwiVerifier::clientIp(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.2, garbage!!, 10.0.0.9'], '10.0.0.0/24') === '10.0.0.9');

// The middleware over stubs.
class TestSettings implements \Flarum\Settings\SettingsRepositoryInterface
{
    public function __construct(private array $data = [])
    {
    }
    public function all(): array
    {
        return $this->data;
    }
    public function get($key, $default = null)
    {
        return $this->data[$key] ?? $default;
    }
    public function set($key, $value): void
    {
    }
    public function delete($key): void
    {
    }
}

class TestClient implements ClientInterface
{
    public function __construct(private int $status, private string $body)
    {
    }
    public function request(string $method, string $url, array $options = [])
    {
        return new class($this->status, $this->body) {
            public function __construct(private int $status, private string $body)
            {
            }
            public function getStatusCode(): int
            {
                return $this->status;
            }
            public function getBody(): string
            {
                return $this->body;
            }
        };
    }
}

class TestRequest implements \Psr\Http\Message\ServerRequestInterface
{
    public function __construct(private string $method, private string $path, private array $headers = [], private array $parsed = [], private array $cookies = [], private array $server = [])
    {
    }
    public function getMethod(): string
    {
        return $this->method;
    }
    public function getUri()
    {
        return new class($this->path) {
            public function __construct(private string $path)
            {
            }
            public function getPath(): string
            {
                return $this->path;
            }
        };
    }
    public function getHeaderLine(string $name): string
    {
        return (string) ($this->headers[$name] ?? '');
    }
    public function getParsedBody()
    {
        return $this->parsed;
    }
    public function getCookieParams(): array
    {
        return $this->cookies;
    }
    public function getServerParams(): array
    {
        return $this->server;
    }
}

class TestHandler implements \Psr\Http\Server\RequestHandlerInterface
{
    public bool $handled = false;
    public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
    {
        $this->handled = true;

        return new class implements \Psr\Http\Message\ResponseInterface {
        };
    }
}

$settings = new TestSettings([
    'kiwi-enabled' => true,
    'kiwi-verify-url' => 'http://127.0.0.1:7371/verify',
    'kiwi-signup-scope' => 'signup',
]);
$okClient = new TestClient(200, '{"success":true}');

$middleware = new VerifySignupMiddleware($settings, $okClient);
$handler = new TestHandler();
check('non-register posts pass through', is_object($middleware->process(new TestRequest('POST', '/discuss'), $handler)) && $handler->handled);
$handler = new TestHandler();
check('register without token is 403', $middleware->process(new TestRequest('POST', '/register'), $handler)->getStatusCode() === 403 && !$handler->handled);
$handler = new TestHandler();
check('register with token passes', is_object($middleware->process(new TestRequest('POST', '/register', ['X-Kiwi-Token' => 'good']), $handler)) && $handler->handled);
$handler = new TestHandler();
$response = $middleware->process(new TestRequest('POST', '/register', [], ['kiwi__token' => 'form-token']), $handler);
check('form token also passes', $handler->handled === true);

$failing = new VerifySignupMiddleware($settings, new TestClient(200, '{"success":false}'));
$handler = new TestHandler();
$response = $failing->process(new TestRequest('POST', '/register', ['X-Kiwi-Token' => 'stale']), $handler);
check('failed challenge is 403', $response->getStatusCode() === 403);
$down = new VerifySignupMiddleware(new TestSettings(['kiwi-enabled' => true, 'kiwi-verify-url' => 'http://127.0.0.1:7371/verify']), new TestClient(503, ''));
$handler = new TestHandler();
$response = $down->process(new TestRequest('POST', '/register', ['X-Kiwi-Token' => 'good']), $handler);
check('deployment 5xx is 503', $response->getStatusCode() === 503 && !$handler->handled);
$disabled = new VerifySignupMiddleware(new TestSettings(['kiwi-enabled' => false]), $okClient);
$handler = new TestHandler();
check('disabled middleware passes everything through', is_object($disabled->process(new TestRequest('POST', '/register'), $handler)) && $handler->handled);

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
