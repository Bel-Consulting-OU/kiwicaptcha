<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpLockoutGuard;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The two remaining step-up hardening contracts: a completion is
 * bound to the session that began the challenge, and the
 * cross-challenge brute-force budget escalates lockouts per principal
 * and target instead of letting the per-challenge cap be farmed.
 */
final class StepUpHardeningTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';
    private const PRINCIPAL_B = 'ffeeddccbbaa99887766554433221100';
    private const TARGET = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private CapturingStepUpCodeSender $sender;

    private StepUpTicket $ticket;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore($this->clock());
        $this->sender = new CapturingStepUpCodeSender();
        $this->ticket = new StepUpTicket(self::MASTER);
    }

    /**
     * A completion presented under a different session than the one
     * that began the challenge is refused before any code is compared:
     * a stolen ticket belongs to nobody else.
     */
    public function testCompletionIsBoundToTheSessionThatBeganIt(): void
    {
        $handler = $this->handler();
        $begin = $handler->begin($this->beginRequest(), $this->context(self::PRINCIPAL));
        $code = (string) $this->sender->lastCode();

        // The same session completes: bound to PRINCIPAL, matching.
        $ok = $handler->complete($this->completeRequest($this->ticketOf($begin), $code, self::PRINCIPAL));
        self::assertSame(StepUpResultStatus::Succeeded, $ok->status);

        // A fresh challenge stolen by another session.
        $second = $handler->begin($this->beginRequest(), $this->context(self::PRINCIPAL));
        $stolen = $handler->complete($this->completeRequest($this->ticketOf($second), (string) $this->sender->lastCode(), self::PRINCIPAL_B));
        self::assertSame(StepUpResultStatus::Failed, $stolen->status);
        self::assertSame(StepUpResult::FAIL_SESSION_MISMATCH, $stolen->failureCode);

        // And an unbound request (a handler reached without the
        // controller) fails closed, never open.
        $unbound = Request::create('https://example.com/kiwi/step-up/complete', 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => $this->ticketOf($second),
            EmailOtpStepUpHandler::CODE_FIELD => (string) $this->sender->lastCode(),
        ]);
        self::assertSame(StepUpResult::FAIL_SESSION_MISMATCH, $handler->complete($unbound)->failureCode);
    }

    /**
     * The cross-challenge budget: five failures arm the first lockout
     * on BOTH the principal and the target keys, a further campaign
     * escalates the lockout, and begin()/complete() refuse while it
     * holds. The lockout is keyed per principal and per target, so a
     * hot target cools off independently of one account.
     */
    public function testBruteForceBudgetEscalatesLockoutsPerPrincipalAndTarget(): void
    {
        $notifications = [];
        $notifier = new class ($notifications) implements \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOwnerNotifier {
            /** @param list<array{0: string, 1: string, 2: int, 3: int}> $notifications */
            public function __construct(private array &$notifications)
            {
            }

            public function notifyLockout(string $dimension, string $pseudonym, int $untilSecs, int $failures): void
            {
                $this->notifications[] = [$dimension, $pseudonym, $untilSecs, $failures];
            }
        };
        $guard = new StepUpLockoutGuard(
            $this->store,
            StepUpLockoutGuard::DEFAULT_LADDER,
            StepUpLockoutGuard::DEFAULT_WINDOW_SECS,
            $notifier,
            $this->clock(),
        );
        $handler = $this->handler(lockout: $guard);

        // Five failures arm the first rung (5 → 300 s) on both keys.
        for ($i = 0; $i < 5; ++$i) {
            $begin = $handler->begin($this->beginRequest(), $this->context(self::PRINCIPAL));
            self::assertSame(200, $begin->getStatusCode(), 'no lockout yet at failure '.($i + 1));
            $result = $handler->complete($this->completeRequest($this->ticketOf($begin), '000000', self::PRINCIPAL));
            self::assertNotSame(StepUpResultStatus::Succeeded, $result->status, 'the wrong code never completes');
        }
        self::assertNotEmpty($notifications, 'the owner is notified on lockout');
        $dimensions = array_column($notifications, 0);
        self::assertContains('principal', $dimensions);
        self::assertContains('target', $dimensions);

        $retryAfter = $guard->retryAfterSecs(self::PRINCIPAL, self::TARGET, $this->now);
        self::assertSame(300, $retryAfter, 'the first rung locks the pair for 300 s');

        // While locked: begin refuses with 429 and complete refuses.
        $refused = $handler->begin($this->beginRequest(), $this->context(self::PRINCIPAL));
        self::assertSame(429, $refused->getStatusCode());
        self::assertSame('300', (string) $refused->headers->get('Retry-After'));

        // A different principal is not held out by someone else's
        // budget — the target key is, though, so a target-scoped flow
        // for the same target must also wait.
        self::assertSame(300, $guard->retryAfterSecs(self::PRINCIPAL_B, self::TARGET, $this->now), 'the target budget holds every principal out');
        self::assertSame(0, $guard->retryAfterSecs(self::PRINCIPAL_B, null, $this->now), 'a clean principal with no target is admissible');

        // Escalation: past the second rung the lockout grows.
        $this->now += 400;
        for ($i = 0; $i < 15; ++$i) {
            $guard->registerFailure(self::PRINCIPAL, self::TARGET);
        }
        self::assertSame(1800, $guard->retryAfterSecs(self::PRINCIPAL, self::TARGET, $this->now), '15 failures escalate to the 30-minute rung');

        // A completed step-up clears the owner's budget.
        $this->now += 2000;
        $guard->registerSuccess(self::PRINCIPAL, self::TARGET);
        self::assertSame(0, $guard->retryAfterSecs(self::PRINCIPAL, self::TARGET, $this->now));
    }

    /**
     * The lockout is also enforced at complete() — a client that
     * already holds a live ticket cannot keep guessing while the
     * budget is locked.
     */
    public function testCompleteRefusesWhileTheBudgetIsLocked(): void
    {
        $guard = new StepUpLockoutGuard($this->store, now: $this->clock());
        $handler = $this->handler(lockout: $guard);
        $begin = $handler->begin($this->beginRequest(), $this->context(self::PRINCIPAL));
        $ticket = $this->ticketOf($begin);
        $code = (string) $this->sender->lastCode();

        for ($i = 0; $i < 5; ++$i) {
            $guard->registerFailure(self::PRINCIPAL, self::TARGET);
        }
        $result = $handler->complete($this->completeRequest($ticket, $code, self::PRINCIPAL));
        self::assertSame(StepUpResult::FAIL_LOCKED_OUT, $result->failureCode, 'the correct code is still refused while locked');
    }

    /** The escalating ladder must be strictly ascending in both fields. */
    public function testTheLadderRefusesANonEscalatingShape(): void
    {
        $refusals = 0;
        foreach (
            [
                [],
                [[5, 300], [5, 600]],
                [[5, 300], [10, 300]],
                [[10, 600], [5, 300]],
            ] as $bad
        ) {
            try {
                new StepUpLockoutGuard($this->store, $bad, now: $this->clock());
                self::fail('a non-escalating ladder must be refused');
            } catch (\InvalidArgumentException) {
                // refused, fail closed
                ++$refusals;
            }
        }
        self::assertSame(4, $refusals);
    }

    private function handler(?StepUpLockoutGuard $lockout = null): EmailOtpStepUpHandler
    {
        return new EmailOtpStepUpHandler(
            $this->store,
            $this->ticket,
            new StepUpCompletionCredit(new SpyOutcomeReporter(), self::MASTER),
            $this->sender,
            self::MASTER,
            maxBegins: 50,
            now: $this->clock(),
            lockout: $lockout,
        );
    }

    private function context(string $principal): StepUpContext
    {
        return new StepUpContext($principal, self::TARGET, 'login', '/back', 'post_solve_step_up_required');
    }

    private function beginRequest(): Request
    {
        return Request::create('https://example.com/kiwi/step-up/begin');
    }

    private function completeRequest(string $ticket, string $code, string $bindPrincipal): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/complete', 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => $ticket,
            EmailOtpStepUpHandler::CODE_FIELD => $code,
        ]);
        StepUpSessionBinding::bind($request, $bindPrincipal);

        return $request;
    }

    private function ticketOf(\Symfony\Component\HttpFoundation\Response $response): string
    {
        self::assertSame(1, preg_match('/name="kiwi_step_up_ticket" value="([^"]+)"/', (string) $response->getContent(), $m));

        return html_entity_decode($m[1]);
    }

    private function clock(): \Closure
    {
        return function (): int {
            return $this->now;
        };
    }
}
