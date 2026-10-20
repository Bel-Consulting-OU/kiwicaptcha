<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\MethodOverrideFramingSubscriber;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * The method-override framing contract on the bundle's POST endpoints.
 *
 * Symfony derives the effective method from `X-HTTP-Method-Override`
 * (and the optional `_method` form field) before routing and before a
 * controller runs. An ambiguous override must answer 400 with the
 * duplicate-header code instead of becoming a routing 405. The early
 * subscriber owns that ordering; the controllers keep the same rule for
 * direct invocation.
 */
final class MethodOverrideFramingTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const PEER = '198.51.100.7';

    /** @return iterable<string, array{0: list<string>|string}> */
    public static function ambiguousHeaderProvider(): iterable
    {
        yield 'two different values' => [['DELETE', 'POST']];
        yield 'two equal values' => [['POST', 'POST']];
        yield 'first value is a framework-refused verb' => [['GET', 'POST']];
        yield 'joined value' => ['DELETE, POST'];
        yield 'folded value' => ["DELETE\r\n POST"];
    }

    private function controller(): ChallengeController
    {
        return new ChallengeController(new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
        ), new ArrayStorage()));
    }

    private function subscriber(string $prefix = '/kiwi-captcha'): MethodOverrideFramingSubscriber
    {
        return new MethodOverrideFramingSubscriber($prefix);
    }

    private function challengeRequest(
        array|string|null $override = null,
        string $path = '/kiwi-captcha/challenge',
        string $body = '{"scope":"login"}',
        array $parameters = [],
        array $server = [],
    ): Request {
        $request = JsonRequest::create(
            $path,
            'POST',
            $parameters,
            [],
            [],
            $server + ['REMOTE_ADDR' => self::PEER],
            $body,
        );
        if ($override !== null) {
            $request->headers->set('X-HTTP-Method-Override', $override);
        }

        return $request;
    }

    private function dispatch(
        MethodOverrideFramingSubscriber $subscriber,
        Request $request,
        int $requestType = HttpKernelInterface::MAIN_REQUEST,
    ): ?Response {
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, $requestType);
        $subscriber->onKernelRequest($event);

        return $event->getResponse();
    }

    private function errorCode(Response $response): ?string
    {
        $decoded = json_decode((string) $response->getContent(), true);

        return \is_array($decoded) ? ($decoded['error']['code'] ?? null) : null;
    }

    #[DataProvider('ambiguousHeaderProvider')]
    public function testSubscriberRejectsAmbiguousHeader(array|string $override): void
    {
        $request = $this->challengeRequest($override);
        $response = $this->dispatch($this->subscriber(), $request);

        self::assertNotNull($response);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($response));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertStringContainsString('private', (string) $response->headers->get('Cache-Control'));
    }

    /** @return iterable<string, array{0: list<string>|string}> */
    public static function allowedValueOrderingProvider(): iterable
    {
        yield 'DELETE then POST' => [['DELETE', 'POST']];
        yield 'PUT then POST' => [['PUT', 'POST']];
        yield 'PATCH then POST' => [['PATCH', 'POST']];
    }

    /**
     * The first value of a multi-value header is what Symfony's header
     * bag returns. These values are accepted overrides on every supported
     * Symfony line, so the framework would present `DELETE`, `PUT` or
     * `PATCH` to routing without the early gate. This is the ordering the
     * subscriber corrects on the installed framework.
     */
    #[DataProvider('allowedValueOrderingProvider')]
    public function testSubscriberAnswersBeforeTheFrameworkPresentsTheFirstValue(array $override): void
    {
        $request = $this->challengeRequest($override);
        self::assertSame($override[0], $request->getMethod(), 'the framework presents the first header value');

        $response = $this->dispatch($this->subscriber(), $request);

        self::assertNotNull($response);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($response));
    }

    public function testDirectControllerRejectsTheSameAmbiguity(): void
    {
        foreach ([['DELETE', 'POST'], ['POST', 'POST'], ['GET', 'POST'], 'DELETE, POST', "DELETE\r\n POST"] as $override) {
            $response = $this->controller()->challenge($this->challengeRequest($override));
            self::assertSame(400, $response->getStatusCode(), is_array($override) ? implode(',', $override) : $override);
            self::assertSame('DUPLICATE_HEADER', $this->errorCode($response));
        }

        $cancel = $this->controller()->cancel($this->challengeRequest(
            ['DELETE', 'POST'],
            '/kiwi-captcha/challenge/cancel',
            '{"nonce":"abc"}',
        ));
        self::assertSame(400, $cancel->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($cancel));
    }

    public function testQueryMethodOverrideIsRefusedBeforeRouting(): void
    {
        // A query-string _method is honored by Request::getMethod() the
        // moment anything asks, so the canonical query-framing refusal —
        // not the framework's 405 — has to answer first.
        // POST parameters land in the request bag; the override the
        // framework honors lives in the query string itself.
        $request = $this->challengeRequest(path: '/kiwi-captcha/challenge?_method=DELETE');
        self::assertNotNull($this->dispatch($this->subscriber(), $request), 'the subscriber must answer a query override');
        $response = $this->dispatch($this->subscriber(), $request);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('METHOD_OVERRIDE_IN_QUERY', $this->errorCode($response));
        self::assertStringContainsString('query string', json_decode((string) $response->getContent(), true)['error']['message']);
    }

    public function testSingleOverrideKeepsTheFrameworkBehaviour(): void
    {
        $request = $this->challengeRequest('DELETE');
        self::assertNull($this->dispatch($this->subscriber(), $request), 'a single override is not the subscriber');
        self::assertSame('DELETE', $request->getMethod());

        // The endpoint still refuses a non-POST effective method with 405.
        $response = $this->controller()->challenge($request);
        self::assertSame(405, $response->getStatusCode());
        self::assertSame('METHOD_NOT_ALLOWED', $this->errorCode($response));
    }

    public function testNoOverrideIsUnchanged(): void
    {
        $request = $this->challengeRequest();
        self::assertNull($this->dispatch($this->subscriber(), $request));
        self::assertSame(200, $this->controller()->challenge($request)->getStatusCode());
    }

    public function testHeaderPlusFormMethodFieldIsAmbiguous(): void
    {
        $request = $this->challengeRequest(
            'POST',
            parameters: ['_method' => 'DELETE'],
        );
        $response = $this->dispatch($this->subscriber(), $request);
        self::assertNotNull($response);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($response));

        // The raw form body is inspected when no framework parse populated
        // the request bag (a Request built without form parameters).
        $raw = $this->challengeRequest(
            'POST',
            body: '_method=DELETE',
            server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
        );
        self::assertNull($raw->request->get('_method'));
        $rawResponse = $this->dispatch($this->subscriber(), $raw);
        self::assertNotNull($rawResponse);
        self::assertSame(400, $rawResponse->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($rawResponse));
    }

    public function testJsonMethodFieldIsNotAFormOverride(): void
    {
        $request = $this->challengeRequest('POST', body: '{"scope":"login","_method":"DELETE"}');
        self::assertNull($this->dispatch($this->subscriber(), $request), 'a JSON field is not the framework form override');
        self::assertSame(422, $this->controller()->challenge($request)->getStatusCode());
    }

    public function testLoneFormMethodFieldIsLeftToTheFramework(): void
    {
        $request = $this->challengeRequest(
            null,
            parameters: ['_method' => 'DELETE'],
        );
        self::assertNull($this->dispatch($this->subscriber(), $request));
    }

    public function testUnrelatedPathsAndSubRequestsAreUntouched(): void
    {
        $unrelated = $this->challengeRequest(['DELETE', 'POST'], '/app/challenge');
        self::assertNull($this->dispatch($this->subscriber(), $unrelated));

        $request = $this->challengeRequest(['DELETE', 'POST']);
        self::assertNull($this->dispatch($this->subscriber(), $request, HttpKernelInterface::SUB_REQUEST));
    }

    public function testOwnedPathsFollowThePrefix(): void
    {
        $subscriber = $this->subscriber('/captcha');
        foreach (['/captcha/challenge', '/captcha/challenge/cancel', '/captcha/siteverify', '/api/captcha/challenge'] as $path) {
            $request = $this->challengeRequest(['DELETE', 'POST'], $path, '{}');
            $response = $this->dispatch($subscriber, $request);
            self::assertNotNull($response, $path);
            self::assertSame(400, $response->getStatusCode(), $path);
            self::assertSame('DUPLICATE_HEADER', $this->errorCode($response), $path);
        }
        self::assertNull($this->dispatch($subscriber, $this->challengeRequest(['DELETE', 'POST'], '/captcha/other')));
    }

    // ── Real kernel: the subscriber must beat the router ───────────────

    private function browser(): KernelBrowser
    {
        return new KernelBrowser(new TestKernel('test', true));
    }

    public function testKernelRejectsDuplicateOverrideBeforeRouting(): void
    {
        $client = $this->browser();
        $client->request('POST', '/kiwi-captcha/challenge', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_X_HTTP_METHOD_OVERRIDE' => ['DELETE', 'POST'],
        ], '{"scope":"login"}');

        self::assertSame(400, $client->getResponse()->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($client->getResponse()));
    }

    public function testKernelSingleOverrideKeepsRoutingBehaviour(): void
    {
        $client = $this->browser();
        $client->request('POST', '/kiwi-captcha/challenge', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_X_HTTP_METHOD_OVERRIDE' => 'DELETE',
        ], '{"scope":"login"}');

        self::assertSame(405, $client->getResponse()->getStatusCode());
    }

    public function testKernelHeaderPlusFormFieldIsRejected(): void
    {
        $client = $this->browser();
        $client->request('POST', '/kiwi-captcha/challenge', ['_method' => 'DELETE'], [], [
            'HTTP_X_HTTP_METHOD_OVERRIDE' => 'POST',
        ]);

        self::assertSame(400, $client->getResponse()->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($client->getResponse()));
    }

    public function testKernelNoOverrideStillIssues(): void
    {
        $client = $this->browser();
        $client->request('POST', '/kiwi-captcha/challenge', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"scope":"login"}');

        self::assertSame(200, $client->getResponse()->getStatusCode());
    }

    public function testKernelCancelAndSiteverifyAreCovered(): void
    {
        $client = $this->browser();
        $client->request('POST', '/kiwi-captcha/challenge/cancel', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_X_HTTP_METHOD_OVERRIDE' => ['DELETE', 'POST'],
        ], '{"nonce":"abc"}');
        self::assertSame(400, $client->getResponse()->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($client->getResponse()));

        $client = $this->browser();
        $client->request('POST', '/kiwi-captcha/siteverify', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_X_HTTP_METHOD_OVERRIDE' => ['DELETE', 'POST'],
        ], '{"secret":"x","response":"y"}');
        self::assertSame(400, $client->getResponse()->getStatusCode());
        self::assertSame('DUPLICATE_HEADER', $this->errorCode($client->getResponse()));
    }

    public function testKernelUnrelatedRouteIsUnaffected(): void
    {
        $client = $this->browser();
        $client->request('POST', '/other/challenge', [], [], [
            'HTTP_X_HTTP_METHOD_OVERRIDE' => ['DELETE', 'POST'],
        ]);

        self::assertSame(404, $client->getResponse()->getStatusCode());
    }
}
