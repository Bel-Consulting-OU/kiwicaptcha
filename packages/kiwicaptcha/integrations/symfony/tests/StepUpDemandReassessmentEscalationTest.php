<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFinalization;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use PHPUnit\Framework\TestCase;

/**
 * The finalizer's fresh reassessment of a completed factor: a Deny
 * settles the demand denied, a fresh StepUp escalates the assurance,
 * and every rung below StepUp settles the demand authorized. The
 * escalation supersedes the parent demand by its strictly stronger
 * child in one atomic store transaction, and the completion answers
 * the escalated result, never an authorization. A completed factor no
 * rung outranks fails closed: the demand settles denied.
 */
final class StepUpDemandReassessmentEscalationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const MASTER = 'kiwi-escalation-master-0123456789ab';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const SCOPE = 'login';

    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private SpyOutcomeReporter $reporter;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->reporter = new SpyOutcomeReporter();
    }

    public function testAFreshStepUpReassessmentEscalatesToTheStrongerChildDemand(): void
    {
        $finalizer = $this->finalizer('step_up');
        $demandId = $this->completedEmailOtpDemand($finalizer);

        $finalization = $finalizer->finalizeLogin($this->proof($demandId), self::SCOPE);

        self::assertFalse($finalization->authorized, 'a fresh StepUp reassessment never authorizes the completed weaker factor');
        self::assertSame(StepUpFinalization::ESCALATED, $finalization->reason);
        self::assertNotNull($finalization->demand, 'the escalated answer names the child demand');
        $child = $finalization->demand;
        self::assertNotSame($demandId, $child->id, 'the child is its own demand, never the parent');
        self::assertSame($demandId, $child->parentDemandId, 'the child names the parent it took over');
        self::assertNotNull($child->requiredFactor, 'the child demands a strictly stronger factor');
        self::assertSame('totp', $child->requiredFactor->family, 'the rung past the completed email otp is totp');
        self::assertSame(2, $child->requiredFactor->assuranceRank);
        self::assertTrue($this->store->readDemand($demandId)?->superseded(), 'the parent handed the family over');
        self::assertTrue($this->store->readDemand($demandId)->state === StepUpDemandState::Superseded, 'the parent sits in the superseded terminal');
        self::assertTrue($child->state->isOpen(), 'the child stands open for its own completion');
        self::assertSame(StepUpDemandState::Open, $child->state);
        self::assertCount(0, $this->reporter->reports, 'an escalated completion books no credit');
        self::assertFalse($this->store->recentStepUpSuccess(self::PRINCIPAL, 900, $this->now), 'an escalated completion books no enrollment marker');
        self::assertNull($this->store->readDemand($demandId)?->factor, 'the parent retains no completed factor');
    }

    public function testAFreshAllowReassessmentSettlesAuthorized(): void
    {
        $finalizer = $this->finalizer('allow');
        $demandId = $this->completedEmailOtpDemand($finalizer);

        $finalization = $finalizer->finalizeLogin($this->proof($demandId), self::SCOPE);

        self::assertTrue($finalization->authorized, 'a rung below StepUp settles the demand authorized');
        self::assertSame(StepUpDemandState::Authorized, $this->store->readDemand($demandId)?->state);
        self::assertCount(1, $this->reporter->reports, 'the authorized settlement books the completion credit');
        self::assertTrue($this->store->recentStepUpSuccess(self::PRINCIPAL, 900, $this->now), 'the authorized settlement books the enrollment marker');
    }

    public function testAFreshDenyReassessmentSettlesDenied(): void
    {
        $finalizer = $this->finalizer('deny');
        $demandId = $this->completedEmailOtpDemand($finalizer);

        $finalization = $finalizer->finalizeLogin($this->proof($demandId), self::SCOPE);

        self::assertFalse($finalization->authorized);
        self::assertSame(StepUpFinalization::REFUSED_DENIED, $finalization->reason);
        self::assertTrue($this->store->readDemand($demandId)->state === StepUpDemandState::Denied, 'the denied terminal is durable');
        self::assertCount(0, $this->reporter->reports);
    }

    public function testAnEscalationPastTheTopOfTheLadderFailsClosed(): void
    {
        // webauthn completes the ladder: a fresh StepUp reassessment
        // finds no strictly stronger rung to demand, and the escalation
        // fails closed. The demand settles denied, never authorized on
        // the proof alone.
        $finalizer = $this->finalizer('step_up');
        $demandId = (string) $finalizer->mintLoginDemand(self::SCOPE, self::PRINCIPAL, null, 600);
        self::assertNotNull($demandId);
        self::assertNotNull($this->store->completeDemand($demandId, $this->now, 600));

        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            self::PRINCIPAL,
            null,
            self::SCOPE,
            null,
            'post_solve_step_up_required',
            $this->now,
            300,
            5,
            str_repeat('a', 64),
            'assertion',
            null,
            false,
            false,
            null,
            $demandId,
        );

        $finalization = $finalizer->finalizeLogin(StepUpResult::proved($challenge, StepUpFactorAssurance::webauthn()), self::SCOPE);

        self::assertFalse($finalization->authorized, 'no stronger rung means no authorization');
        self::assertSame(StepUpFinalization::REFUSED_DENIED, $finalization->reason);
        self::assertTrue($this->store->readDemand($demandId)->state === StepUpDemandState::Denied, 'the fail-closed escalation settles the demand denied');
        self::assertCount(0, $this->reporter->reports);
    }

    public function testTheEscalatedChildCarriesTheOperationBindingAndTheWindowUnchanged(): void
    {
        $finalizer = $this->finalizer('step_up');
        $sessionHash = str_repeat('c', 64);
        $demandId = (string) $finalizer->mintLoginDemand(self::SCOPE, self::PRINCIPAL, $sessionHash, 600);
        self::assertNotNull($demandId);
        $parent = $this->store->readDemand($demandId);
        self::assertNotNull($parent);
        self::assertNotNull($this->store->completeDemand($demandId, $this->now, 600));

        $finalization = $finalizer->finalizeLogin($this->proof($demandId, $sessionHash), self::SCOPE);

        self::assertSame(StepUpFinalization::ESCALATED, $finalization->reason);
        $child = $this->store->readDemand((string) $finalization->demand?->id);
        self::assertNotNull($child);
        self::assertSame($parent->expiresAt, $child->expiresAt, 'the escalation never refreshes the authorization window');
        self::assertSame($parent->scope, $child->scope, 'the booking scope rides unchanged');
        self::assertSame($parent->sessionHash, $child->sessionHash, 'the browser binding rides unchanged');
        self::assertSame(1, $child->generation, 'the child is the first escalation generation');
    }

    // ── helpers ─────────────────────────────────────────────────────

    /** The login demand of the principal, completed as the email_otp rung proves it. */
    private function completedEmailOtpDemand(StepUpDemandFinalizer $finalizer): string
    {
        $demandId = (string) $finalizer->mintLoginDemand(self::SCOPE, self::PRINCIPAL, null, 600);
        self::assertNotNull($demandId);
        self::assertNotNull($this->store->completeDemand($demandId, $this->now, 600), 'the factor completion landed');

        return $demandId;
    }

    /** The verified proof of the completed rung: FactorVerified, credited by nothing. */
    private function proof(string $demandId, ?string $sessionHash = null): StepUpResult
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            self::SCOPE,
            null,
            'post_solve_step_up_required',
            $this->now,
            300,
            5,
            str_repeat('a', 64),
            null,
            $sessionHash,
            false,
            false,
            null,
            $demandId,
        );

        return StepUpResult::proved($challenge, StepUpFactorAssurance::emailOtp());
    }

    private function finalizer(string $minimum): StepUpDemandFinalizer
    {
        return new StepUpDemandFinalizer(
            $this->store,
            new StepUpCompletionCredit($this->reporter, self::MASTER),
            null,
            $this->gateway($minimum),
            null,
            null,
            null,
            null,
            fn (): int => $this->now,
            self::MASTER,
            new StepUpFactorResolver('email_otp'),
        );
    }

    /**
     * The risk gateway of the reassessment: the scope minimum is the
     * one knob the test moves, so the fresh decision answers exactly
     * the action under test.
     */
    private function gateway(string $minimum): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => $minimum, 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), [self::SCOPE => 1], policy: $policy);
    }
}
