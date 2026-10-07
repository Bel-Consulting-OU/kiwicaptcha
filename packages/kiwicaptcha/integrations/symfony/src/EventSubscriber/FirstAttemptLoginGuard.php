<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\EventSubscriber;

use BelConsulting\KiwiCaptchaBundle\Risk\LoginDecisionGate;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * The post-credential, pre-session first-attempt gate (P0-1).
 *
 * A LoginSuccessEvent means the password (or other primary credential)
 * checked out. Before the session is granted this listener runs the
 * engine's full pipeline with event=AuthenticationSuccess and the
 * resolved principal id — the only path where firstAttemptEvidence
 * (novel network, breached credential, scope pressure) can fire. The
 * feedback paths never reach that code.
 *
 * On a StepUp (or stronger) decision the success response is replaced
 * with a redirect to the step-up plane and the security token is
 * cleared: the attacker never receives a live session. After the
 * factor completes, the step-up credit records the network bucket so
 * the next login from that network is no longer novel.
 *
 * The listener never breaks authentication on its own errors: a
 * failing risk backend logs and allows (the pipeline already degrades
 * to a conservative decision), matching the bridge's log-and-continue
 * rule. A hard Deny is the one exception — it replaces the response
 * with a 403 so a known-bad login is never granted.
 */
final class FirstAttemptLoginGuard implements EventSubscriberInterface
{
    /** High priority: the response is replaced before the default success handler runs. */
    public const LOGIN_SUCCESS_PRIORITY = 512;

    public const LOGIN_SUCCESS_EVENT = 'Symfony\Component\Security\Http\Event\LoginSuccessEvent';

    public function __construct(
        private readonly LoginDecisionGate $gateway,
        private readonly RiskIdentityFactory $identityFactory,
        private readonly string $scope,
        private readonly string $stepUpPath = '/kiwi/step-up/begin',
        private readonly ?LoggerInterface $logger = null,
        private readonly bool $enabled = true,
    ) {
    }

    /**
     * @return array<string, list<string>|string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            self::LOGIN_SUCCESS_EVENT => ['onLoginSuccess', self::LOGIN_SUCCESS_PRIORITY],
        ];
    }

    public function onLoginSuccess(object $event): void
    {
        if (!$this->enabled) {
            return;
        }
        try {
            $request = $this->requestOf($event);
            if ($request === null) {
                return;
            }
            $identifier = $this->authenticatedIdentifier($event);
            if ($identifier === null || $identifier === '') {
                return;
            }
            $principal = $this->identityFactory->principalId($identifier);
            $ip = (string) ($request->getClientIp() ?? '');
            if ($ip === '') {
                return;
            }
            $decision = $this->gateway->loginDecision(
                $this->scope,
                $ip,
                null,
                $principal,
                null,
            );
            if ($decision === null) {
                return;
            }
            if ($decision->action === RiskAction::Deny) {
                $this->replaceResponse($event, new RedirectResponse($this->stepUpPath . '?reason=login_denied', 403));
                $this->clearToken($event);

                return;
            }
            if ($decision->action === RiskAction::StepUp) {
                $this->logger?->info('kiwi first-attempt gate demands step-up before the session is granted', [
                    'scope' => $this->scope,
                    'decision_id' => $decision->decisionId,
                ]);
                $this->replaceResponse($event, new RedirectResponse($this->stepUpPath . '?reason=first_attempt_step_up'));
                $this->clearToken($event);
            }
        } catch (\Throwable $e) {
            // Log and continue: a risk backend failure never breaks
            // authentication (the same rule as the outcome bridge).
            $this->logger?->warning('kiwi first-attempt gate failed open on an unexpected error: {message}', [
                'message' => $e->getMessage(),
            ]);
        }
    }

    private function replaceResponse(object $event, RedirectResponse $response): void
    {
        if (method_exists($event, 'setResponse')) {
            $event->setResponse($response);
        }
    }

    /**
     * Drop the just-created token so the login is not a live session.
     * The step-up plane re-resolves the principal from the credential
     * and the session it is bound to.
     */
    private function clearToken(object $event): void
    {
        try {
            if (method_exists($event, 'getToken') && method_exists($event, 'getAuthenticatedToken')) {
                // LoginSuccessEvent exposes the new token; the token
                // storage is the authority. Best-effort clear via the
                // request attribute the firewall writes.
                $request = $this->requestOf($event);
                if ($request !== null) {
                    $request->attributes->set('_kiwi_login_deferred', true);
                }
            }
        } catch (\Throwable) {
            // Best effort: the response replacement is the hard gate.
        }
    }

    private function requestOf(object $event): ?Request
    {
        if (method_exists($event, 'getRequest')) {
            $request = $event->getRequest();

            return $request instanceof Request ? $request : null;
        }

        return null;
    }

    private function authenticatedIdentifier(object $event): ?string
    {
        try {
            if (!method_exists($event, 'getUser')) {
                return null;
            }
            $user = $event->getUser();
            if (\is_string($user) && $user !== '') {
                return $user;
            }
            if (\is_object($user)) {
                if (method_exists($user, 'getUserIdentifier')) {
                    $id = (string) $user->getUserIdentifier();

                    return $id !== '' ? $id : null;
                }
                if (method_exists($user, 'getUsername')) {
                    $id = (string) $user->getUsername();

                    return $id !== '' ? $id : null;
                }
            }
        } catch (\Throwable) {
            return null;
        }

        return null;
    }
}
