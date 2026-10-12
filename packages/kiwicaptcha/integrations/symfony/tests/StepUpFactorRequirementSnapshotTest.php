<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\CapturingEmailOwnershipSender;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The strictly-stronger-factor rule over one continuity session. A
 * demand snapshots the factor it requires, the atomic completion
 * records the completed factor under the session hash and scope, and
 * the next demand of the same session demands a strictly stronger
 * family than the factor already proven. The two-record state moves in
 * one transition. A completion can therefore never strand a consumed
 * challenge beside an open demand, nor the reverse.
 */
final class StepUpFactorRequirementSnapshotTest extends TestCase
{
    private const MASTER = 'kiwi-snapshot-master-0123456789ab';

    private const remoteKey = 'REMOTE_ADDR';

    private ArrayStepUpChallengeStore $store;

    private CapturingEmailOwnershipSender $sender;

    private ContinuityCookie $cookie;

    private int $now = 1700000000;

    private string $sessionValue;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->sender = new CapturingEmailOwnershipSender();
        $this->cookie = new ContinuityCookie();
        $this->sessionValue = $this->cookie->mint();
    }

    public function testTheDemandCarriesTheFactorSnapshotTheMintResolved(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);

        $demandId = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $demand = $this->store->readDemand($demandId);

        self::assertNotNull($demand);
        self::assertNotNull($demand->requiredFactor, 'the mint snapshots the resolved factor onto the demand');
        self::assertSame(FactorRequirement::EMAIL_OTP, $demand->requiredFactor->family);
        self::assertSame('email_otp', $demand->requiredFactor->factorId);
        self::assertSame(1, $demand->requiredFactor->assuranceRank);
    }

    public function testASecondOperationOfACompletedSessionDemandsTheStrictlyStrongerFactor(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);

        $first = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $this->complete($factor, $first);
        self::assertSame(FactorRequirement::EMAIL_OTP, $this->store->completedFactorOf($sessionHash, 'signup', $this->now), 'the completion records the proven factor for the session');

        // The next step-up of the same session under a fresh operation
        // mints its own demand: the completion marker escalates its
        // requirement strictly past the proven factor.
        $secondDigest = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest::formFields('signup', ['email' => 'visitor@example.com', 'nonce' => 'second']);
        $secondId = (string) $factor->mintDemand('signup', $sessionHash, null, null, \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind::FormFields, $secondDigest);
        $second = $this->store->readDemand($secondId);
        self::assertNotSame($first, $secondId, 'the second operation mints its own demand');
        self::assertNotNull($second);
        self::assertNotNull($second->requiredFactor);
        self::assertSame(FactorRequirement::TOTP, $second->requiredFactor->family, 'the demand after a completed email otp demands the totp factor');
        self::assertSame(2, $second->requiredFactor->assuranceRank, 'totp is the strictly stronger rung');
    }

    public function testAReRaisedOperationEscalatesItsFamilyChild(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);

        $first = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $firstDemand = $this->store->readDemand($first);
        self::assertNotNull($firstDemand?->requiredFactor);
        self::assertSame(FactorRequirement::EMAIL_OTP, $firstDemand->requiredFactor->family);
        self::assertNull($this->store->completedFactorOf($sessionHash, 'signup', $this->now), 'no completion marker exists');

        $secondId = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $second = $this->store->readDemand($secondId);
        self::assertNotNull($second);
        self::assertNotSame($first, $secondId, 'the re-raised step-up supersedes the family with a child');
        self::assertNotNull($second->requiredFactor);
        self::assertSame(FactorRequirement::TOTP, $second->requiredFactor->family, 'the family child demands strictly more than its parent required');
        self::assertSame(2, $second->requiredFactor->assuranceRank);
        self::assertTrue($this->store->readDemand($first)?->superseded(), 'the parent handed its authorization to the child');
    }

    public function testTheCompletionConsumesBothRecordsInOneTransition(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);
        $demandId = (string) $factor->mintDemand('signup', $sessionHash, null, null);
        $demand = $this->store->readDemand($demandId);
        self::assertNotNull($demand);

        $this->complete($factor, $demandId);

        $completed = $this->store->readDemand($demandId);
        self::assertNotNull($completed, 'the completed demand stays as the consumption proof');
        self::assertTrue($completed->state === StepUpDemandState::Completed, 'the demand reached the completed state in the same script');
        self::assertSame(0, $this->liveChallengeCount(), 'the challenge record was consumed by the same transition');
        self::assertNull($this->store->read($this->challengeIds[0] ?? ''), 'the consumed challenge is gone');
    }

    public function testAWebAuthnRequiredDemandRefusesTheWeakerEmailGrant(): void
    {
        // The bypass test: a demand whose stored requirement names
        // webauthn (rank 3) attempted with the email grant (the stored
        // challenge's kind proves the email_otp rung, rank 1). The
        // atomic completion judges the requirement against the factor
        // identity the challenge record carries, never a caller
        // argument, and refuses with both records untouched.
        $demand = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            hash('sha256', $this->sessionValue),
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
            new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3),
        );
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOwnership,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'email_ownership',
            $this->now,
            600,
            5,
            str_repeat('a', 64),
            null,
            $this->sessionValue,
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($challenge, 600);
        $this->store->createDemand($demand, 600);

        $binding = hash('sha256', $this->sessionValue);
        self::assertNull($this->store->completeFactor($challenge->id, $demand->id, $binding, $this->now, FactorRequirement::EMAIL_OTP, $challenge->sessionHash), 'the weaker factor completes nothing');
        self::assertNotNull($this->store->read($challenge->id), 'the weaker-factor refusal consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the weaker-factor refusal completed no demand');
    }

    /**
     * The end-to-end shape of the same refusal: the factor's completion
     * lane answers the typed failure, never a grant, when the demand
     * requires a strictly stronger factor than the grant proves.
     */
    public function testTheGrantCompletionRefusesAWebAuthnRequiredDemand(): void
    {
        $factor = $this->factor(new StepUpFactorResolver('email_otp'));
        $sessionHash = hash('sha256', $this->sessionValue);
        $demand = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            $sessionHash,
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
            new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3),
        );
        $this->store->createDemand($demand, 600);

        $begin = $factor->begin($this->emailRequest($demand->id));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $body = json_decode((string) $begin->getContent(), true);
        $code = (string) $this->sender->lastCode();
        $delivered = \count($this->sender->codes);
        $request = Request::create('https://example.com/kiwi/step-up/email/complete', 'POST', [
            EmailOwnershipStepUp::EMAIL_FIELD => 'visitor@example.com',
            EmailOwnershipStepUp::DEMAND_FIELD => $demand->id,
            'kiwi_step_up_ticket' => (string) $body['challenge'],
            'kiwi_step_up_code' => $code,
        ]);
        $request->cookies->set($this->cookie->cookie($request, 'seed')->getName(), $this->sessionValue);
        $response = $factor->complete($request);

        self::assertSame(422, $response->getStatusCode(), (string) $response->getContent(), 'the weaker grant completes nothing');
        self::assertSame('unknown_challenge', json_decode((string) $response->getContent(), true)['failure_code'] ?? null);
        self::assertSame($delivered, \count($this->sender->codes), 'no second code is delivered for a refused completion');
    }

    public function testTheStoreCompletesACrossedPairForNoOne(): void
    {
        // The challenge of one demand can never complete through
        // another: the script asserts the challenge names exactly the
        // demand id it is driven with, and a refusal consumes nothing.
        $demand = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            hash('sha256', $this->sessionValue),
            null,
            null,
            $this->now,
            600,
        );
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOwnership,
            '00112233445566778899aabbccddeeff',
            null,
            'signup',
            null,
            'email_ownership',
            $this->now,
            600,
            5,
            str_repeat('a', 64),
            null,
            $this->sessionValue,
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($challenge, 600);
        $this->store->createDemand($demand, 600);
        $other = StepUpDemand::mint(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            'signup',
            null,
            null,
            null,
            $this->now,
            600,
        );
        $this->store->createDemand($other, 600);

        $completion = $this->store->completeFactor($challenge->id, $other->id, hash('sha256', $this->sessionValue), $this->now, FactorRequirement::EMAIL_OTP, $challenge->sessionHash);
        self::assertNull($completion, 'a crossed pair completes nothing');
        self::assertNotNull($this->store->read($challenge->id), 'the refused transition consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the refused transition completed no demand');

        // The right pair, the wrong browser: the binding hash is
        // checked inside the script.
        $wrong = $this->store->completeFactor($challenge->id, $demand->id, str_repeat('b', 64), $this->now, FactorRequirement::EMAIL_OTP, $challenge->sessionHash);
        self::assertNull($wrong, 'a completion without the session binding is refused');
        self::assertNotNull($this->store->read($challenge->id), 'the binding refusal consumed nothing');

        // The right pair, the right browser: exactly one transition.
        $right = $this->store->completeFactor($challenge->id, $demand->id, hash('sha256', $this->sessionValue), $this->now, FactorRequirement::EMAIL_OTP, $challenge->sessionHash);
        self::assertNotNull($right);
        self::assertSame($demand->id, $right->demandId);
        self::assertSame('00112233445566778899aabbccddeeff', $right->verifiedSubjectPseudonym, 'the verified subject derives from the stored challenge');
        self::assertNull($this->store->read($challenge->id), 'the challenge is consumed');
        self::assertTrue($this->store->readDemand($demand->id)?->state === StepUpDemandState::Completed, 'the demand is completed');

        // A replay of the transition answers nothing.
        self::assertNull($this->store->completeFactor($challenge->id, $demand->id, hash('sha256', $this->sessionValue), $this->now, FactorRequirement::EMAIL_OTP, $challenge->sessionHash), 'a spent pair completes no one twice');
    }

    /** @var list<string> */
    private array $challengeIds = [];

    private function complete(EmailOwnershipStepUp $factor, string $demandId): void
    {
        $begin = $factor->begin($this->emailRequest($demandId));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $body = json_decode((string) $begin->getContent(), true);
        $this->challengeIds[] = $this->challengeIdOfTicket((string) $body['challenge']);
        $code = (string) $this->sender->lastCode();
        $request = Request::create('https://example.com/kiwi/step-up/email/complete', 'POST', [
            EmailOwnershipStepUp::EMAIL_FIELD => 'visitor@example.com',
            EmailOwnershipStepUp::DEMAND_FIELD => $demandId,
            'kiwi_step_up_ticket' => (string) $body['challenge'],
            'kiwi_step_up_code' => $code,
        ]);
        $request->cookies->set($this->cookie->cookie($request, 'seed')->getName(), $this->sessionValue);
        $response = $factor->complete($request);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
    }

    /**
     * The challenge id the signed ticket names: decoded through the
     * ticket service, the same id the store keyed the record under.
     */
    private function challengeIdOfTicket(string $ticket): string
    {
        $payload = (new StepUpTicket(self::MASTER))->look($ticket);
        self::assertIsArray($payload);

        return (string) $payload['challengeId'];
    }

    private function liveChallengeCount(): int
    {
        $live = 0;
        foreach ($this->challengeIds as $id) {
            if ($this->store->read($id) !== null) {
                $live++;
            }
        }

        return $live;
    }

    private function emailRequest(string $demandId): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/email/begin', 'POST', [
            EmailOwnershipStepUp::EMAIL_FIELD => 'visitor@example.com',
            EmailOwnershipStepUp::DEMAND_FIELD => $demandId,
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $request->cookies->set($this->cookie->cookie($request, 'seed')->getName(), $this->sessionValue);

        return $request;
    }

    private function factor(StepUpFactorResolver $resolver): EmailOwnershipStepUp
    {
        return new EmailOwnershipStepUp(
            $this->store,
            new StepUpTicket(self::MASTER),
            $this->sender,
            $this->cookie,
            null,
            'login',
            self::MASTER,
            emailCarrierScopes: ['signup' => true],
            now: fn (): int => $this->now,
            factorResolver: $resolver,
        );
    }
}
