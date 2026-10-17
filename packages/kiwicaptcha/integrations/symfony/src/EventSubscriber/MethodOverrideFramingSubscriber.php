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
        $conflict = $this->methodOverrideConflict($request);
        if ($conflict === null) {
            return;
        }
        $response = new JsonResponse(
            ['error' => ['code' => 'DUPLICATE_HEADER', 'message' => $conflict]],
            Response::HTTP_BAD_REQUEST,
        );
        $response->headers->set('Cache-Control', 'no-store, private, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $event->setResponse($response);
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
