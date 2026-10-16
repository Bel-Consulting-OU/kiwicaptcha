<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendLease;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendSettlement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorCompletion;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The delivery-generation lease of the email one-time-code begin.
 *
 * The replacement semantics made the store's challenge swap atomic, but
 * the handler still admitted before it sent. Two concurrent begins of one
 * demand could therefore both reach the mailbox: the second begin
 * replaced the first's challenge between that begin's admission and its
 * handoff, both messages arrived, and only the second code was valid.
 * Mail ordering is uncontrolled, so the invalid message could land last
 * and look newest. The lease is what orders that window: the begin
 * holding it is the generation whose code becomes the demand's
 * authoritative factor, and a begin that cannot claim it sends nothing.
 *
 * The fixture stages the competing request the way the ownership
 * handler's own race tests do, at the store seam the begin calls, so the
 * interleaving is a real state move rather than a mock's opinion.
 */
final class StepUpOtpDeliveryRaceTest extends TestCase
{
    private const MASTER = 'otp-delivery-race-master-secret-0123456789';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const LINEAGE = 'otp-delivery-race-lineage';

    private const TARGET = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $inner;

    private CapturingStepUpCodeSender $sender;

    private StepUpTicket $ticket;

    protected function setUp(): void
    {
        $this->inner = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->sender = new CapturingStepUpCodeSender();
        $this->ticket = new StepUpTicket(self::MASTER);
    }

    /**
     * A begin that loses the delivery window delivers nothing, replaces
     * nothing and answers a retryable conflict. The standing challenge
     * is the proof that nothing was replaced: it is still the demand's
     * active challenge and still completes on its own code.
     */
    public function testAConcurrentBeginHoldingTheDeliveryWindowRefusesAndReplacesNothing(): void
    {
        $demand = $this->mintDemand();
        $store = new DeliveryRaceStepUpChallengeStore($this->inner);
        $handler = $this->handler($store);
        $context = $this->context($demand);

        // The first begin takes the window and delivers: its code is the
        // demand's standing factor.
        self::assertSame(200, $handler->begin($this->request(), $context)->getStatusCode());
        self::assertCount(1, $this->sender->deliveries);
        $standing = $this->inner->readDemand($demand)?->activeChallengeId;
        self::assertNotNull($standing, 'the first begin admitted its challenge');

        // The competing begin cannot claim the window, so it must not
        // send and must not touch the standing challenge.
        $store->refuseNextLeaseClaim = true;
        $answer = $handler->begin($this->request(), $context);

        self::assertSame(409, $answer->getStatusCode(), 'a held delivery window is a retryable conflict: '.(string) $answer->getContent());
        self::assertSame('step_up_send_in_progress', json_decode((string) $answer->getContent(), true)['error'] ?? null);
        self::assertSame('1', $answer->headers->get('Retry-After'), 'the loser is told to retry in a moment');
        self::assertCount(1, $this->sender->deliveries, 'the refused begin delivered nothing');
        self::assertSame($standing, $this->inner->readDemand($demand)?->activeChallengeId, 'the refused begin replaced no challenge');
        self::assertSame(
            [$standing],
            $store->admittedDuringRefusal,
            'the refusal saw the standing challenge and admitted nothing of its own',
        );

        // The standing challenge is untouched in the only sense that
        // matters: it still completes on the code its own delivery got.
        $code = $this->sender->deliveries[0]['code'];
        $completion = $this->inner->completeFactor(
            $standing,
            $demand,
            $this->presentedBinding($standing),
            $this->now,
            null,
            'login',
            hash('sha256', self::LINEAGE),
        );
        self::assertNotNull($completion, 'the standing challenge still completes after the refused replacement');
    }

    /**
     * A refused begin hands its mail capacity back: the reservation it
     * made is released, so a retry is not charged for a delivery that
     * never happened.
     */
    public function testTheRefusedBeginReleasesItsMailReservation(): void
    {
        $demand = $this->mintDemand();
        $store = new DeliveryRaceStepUpChallengeStore($this->inner);
        $handler = $this->handler($store);

        $store->refuseNextLeaseClaim = true;
        $answer = $handler->begin($this->request(), $this->context($demand));

        self::assertSame(409, $answer->getStatusCode());
        self::assertCount(1, $store->releasedReservations, 'the refused begin released its reservation');
        self::assertSame([], $this->sender->deliveries);
    }

    /**
     * An unprovable claim fails closed: when the store cannot say whether
     * this begin owns the generation, the begin sends nothing rather than
     * sending a code it cannot vouch for.
     */
    public function testAClaimThatCannotBeMadeRefusesTheBegin(): void
    {
        $demand = $this->mintDemand();
        $store = new DeliveryRaceStepUpChallengeStore($this->inner);
        $store->throwOnLeaseClaim = true;
        $handler = $this->handler($store);

        $answer = $handler->begin($this->request(), $this->context($demand));

        self::assertSame(409, $answer->getStatusCode(), 'an unprovable generation is refused: '.(string) $answer->getContent());
        self::assertSame('step_up_send_in_progress', json_decode((string) $answer->getContent(), true)['error'] ?? null);
        self::assertSame([], $this->sender->deliveries, 'no code leaves on an unprovable claim');
        self::assertSame([], $this->admittedChallengeIds($demand), 'no challenge record was admitted');
    }

    /**
     * The begin that sends is the one whose generation is authoritative:
     * afterwards the window is free again (the next begin may claim it)
     * and the demand's delivery budget has been spent once.
     */
    public function testTheDeliveringBeginPromotesAndFreesTheWindow(): void
    {
        $demand = $this->mintDemand();
        $handler = $this->handler(new DeliveryRaceStepUpChallengeStore($this->inner));

        self::assertSame(200, $handler->begin($this->request(), $this->context($demand))->getStatusCode());

        $record = $this->inner->readDemand($demand);
        self::assertNotNull($record);
        self::assertNull($record->leaseUntilMs, 'the window is released once the handoff settled');
        self::assertSame(1, $record->sends, 'the delivered generation spent one delivery');
        self::assertSame($this->now, $record->lastSentAt);
        self::assertNotNull($record->activeChallengeId, 'the delivered challenge is the demand\'s active one');

        // The freed window admits the next begin, which is what makes the
        // refusal a retry rather than a permanent loss of the flow.
        self::assertSame(200, $handler->begin($this->request(), $this->context($demand))->getStatusCode());
        self::assertCount(2, $this->sender->deliveries);
    }

    /**
     * An ambiguous outcome at or after the handoff spends the delivery.
     * A code the transport may have delivered is never handed back as if
     * it had never been sent, and the challenge record does not outlive
     * a code the factor cannot vouch for.
     */
    public function testAnAmbiguousHandoffSpendsTheDeliveryAndLeavesNoChallenge(): void
    {
        $demand = $this->mintDemand();
        $handler = $this->handler(new DeliveryRaceStepUpChallengeStore($this->inner));
        $this->sender->throwOnSend = new \RuntimeException('transport failed after acceptance');

        $answer = $handler->begin($this->request(), $this->context($demand));

        self::assertSame(503, $answer->getStatusCode());
        self::assertSame('step_up_delivery_failed', json_decode((string) $answer->getContent(), true)['error'] ?? null);
        $record = $this->inner->readDemand($demand);
        self::assertNotNull($record);
        self::assertSame(1, $record->sends, 'the ambiguous handoff spent the delivery');
        self::assertNull($record->leaseUntilMs, 'the window is released');
        self::assertSame([], $this->admittedChallengeIds($demand), 'no challenge survives an unvouched-for code');
    }

    /**
     * A pre-handoff refusal restores the demand's delivery budget: the
     * window closes without spending a delivery, so a begin that never
     * reached the transport costs the demand nothing.
     */
    public function testAPreHandoffRefusalRestoresTheDeliveryBudget(): void
    {
        $demand = $this->mintDemand();
        $store = new DeliveryRaceStepUpChallengeStore($this->inner);
        $handler = $this->handler($store);
        // The refusal the store raises before any challenge is admitted.
        $store->throwOnAdmission = true;

        $answer = $handler->begin($this->request(), $this->context($demand));

        self::assertSame(503, $answer->getStatusCode(), (string) $answer->getContent());
        self::assertSame([], $this->sender->deliveries);
        $record = $this->inner->readDemand($demand);
        self::assertNotNull($record);
        self::assertSame(0, $record->sends, 'a pre-handoff refusal spent no delivery');
        self::assertNull($record->lastSentAt);
        self::assertNull($record->leaseUntilMs);
    }

    private function handler(StepUpChallengeStore $store): EmailOtpStepUpHandler
    {
        return new EmailOtpStepUpHandler(
            $store,
            $this->ticket,
            $this->sender,
            self::MASTER,
            300,
            5,
            6,
            3,
            900,
            '/kiwi/step-up/complete',
            fn (): int => $this->now,
        );
    }

    private function request(): Request
    {
        return Request::create('/kiwi/step-up/begin', 'POST', ['scope' => 'login']);
    }

    private function context(string $demandId): StepUpContext
    {
        return new StepUpContext(
            self::PRINCIPAL,
            self::TARGET,
            'login',
            '/back',
            'post_solve_step_up_required',
            StepUpContext::MODE_JSON,
            true,
            $demandId,
        );
    }

    /** The demand an authorizing challenge binds, stored and live. */
    private function mintDemand(): string
    {
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            'login',
            null,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
            '',
            null,
            null,
            false,
            null,
            null,
            null,
            hash('sha256', self::LINEAGE),
        );
        $this->inner->createDemand($demand, 600);

        return $demand->id;
    }

    private function presentedBinding(string $challengeId): string
    {
        $challenge = $this->inner->read($challengeId);
        self::assertNotNull($challenge);

        return (string) ($challenge->sessionHash ?? $challenge->clientSecretHash ?? '');
    }

    /**
     * The challenge records the demand's store still holds. The demand's
     * active-challenge pointer outlives a consumed record by design, so
     * the liveness of the record itself is what this reports.
     *
     * @return list<string>
     */
    private function admittedChallengeIds(string $demandId): array
    {
        $active = $this->inner->readDemand($demandId)?->activeChallengeId;
        if ($active === null || $this->inner->read($active) === null) {
            return [];
        }

        return [$active];
    }
}
