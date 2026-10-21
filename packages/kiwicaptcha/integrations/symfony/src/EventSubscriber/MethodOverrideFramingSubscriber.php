<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\EventSubscriber;

use BelConsulting\KiwiCaptchaBundle\Http\FramingChecksTrait;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Rejects an ambiguous method override before routing reads the
 * effective method.
 *
 * The router derives its method context from Request::getMethod(), which
 * consults `X-HTTP-Method-Override` and, when the framework enables it,
 * the `_method` form field. A duplicate, joined or folded header, or a
 * header combined with a form field, would otherwise turn the endpoint's
 * framing refusal into a routing 405. The gate runs above the router's
 * kernel.request priority and inspects only the bundle's own paths, so a
 * request without an override is untouched.
 */
final class MethodOverrideFramingSubscriber implements EventSubscriberInterface
{
    use FramingChecksTrait;

    /**
     * The router runs at priority 32 and builds its request context from
     * the effective method. Any priority above that answers first.
     */
    public const REQUEST_PRIORITY = 512;

    private const ROUTE_SUFFIXES = ['/challenge', '/challenge/cancel', '/siteverify'];

    public function __construct(private readonly string $routePrefix = '/kiwi-captcha')
    {
    }

    /**
     * @return array<string, list<string>|string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', self::REQUEST_PRIORITY],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        if (!$this->ownsPath($request)) {
            return;
        }
        // A query-string `_method` reaches Request::getMethod() before any
        // listener can re-examine it, so the canonical query-framing
        // refusal has to answer on the raw query bag ahead of routing.
        // The documented security invariant for every unexpected query
        // parameter — `_method` included — is 422
        // `QUERY_PARAMETERS_NOT_ALLOWED`. On Symfony 6.4 the framework's
        // HttpMethodParameterOverrideListener (priority 256) rewrites the
        // verb before the router reads it; this subscriber (priority 512)
        // therefore answers on the raw bag, preserving the 422 invariant
        // instead of letting the framework's 405 leak out.
        if ($this->hasQueryMethodOverride($request)) {
            // Also disable the framework override for this request so a
            // later listener cannot rewrite the verb after us.
            if (\method_exists($request, 'setMethodOverrideParameter')) {
                $request->setMethodOverrideParameter(false);
            }
            $event->setResponse($this->framingRefusal(
                'QUERY_PARAMETERS_NOT_ALLOWED',
                'The challenge endpoint accepts no query parameters.',
                Response::HTTP_UNPROCESSABLE_ENTITY,
            ));
            return;
        }
        $conflict = $this->methodOverrideConflict($request);
        if ($conflict === null) {
            return;
        }
        $event->setResponse($this->framingRefusal('DUPLICATE_HEADER', $conflict));
    }

    /**
     * The shared framing refusal document: a typed code, a stable
     * message and the no-store cache posture of every framing error.
     */
    private function framingRefusal(string $code, string $message, int $status = Response::HTTP_BAD_REQUEST): JsonResponse
    {
        $response = new JsonResponse(
            ['error' => ['code' => $code, 'message' => $message]],
            $status,
        );
        $response->headers->set('Cache-Control', 'no-store, private, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }

    /**
     * The bundle's route paths are the configured prefix plus one fixed
     * suffix. A suffix match also covers an application that mounts the
     * bundle routes under an additional import prefix.
     */
    private function ownsPath(Request $request): bool
    {
        $prefix = rtrim($this->routePrefix, '/');
        if ($prefix === '' || $prefix === '/') {
            return false;
        }
        $path = $request->getPathInfo();
        foreach (self::ROUTE_SUFFIXES as $suffix) {
            if (str_ends_with($path, $prefix.$suffix)) {
                return true;
            }
        }

        return false;
    }
}
