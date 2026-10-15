<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandAdmissionRefused;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationMaterial;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use PHPUnit\Framework\TestCase;

/**
 * The adversarial matrix of the demand binding: a completed factor may
 * only ever answer the exact demand it was raised for.
 *
 * A challenge of another session, scope or account completes nothing,
 * even when the presented binding matches the challenge perfectly. The
 * (session, scope) factor history is monotonic: it never regresses from
 * a stronger to a weaker proof. The active-challenge admission keeps one
 * live generation per demand and replaces the prior one. The wire schema
 * refuses the v3 records. The canonical operation encoding is injective
 * against embedded delimiters. The finalization reproduces the demand
 * subject, never an anonymous presentation of a subject-bound demand.
 */
final class StepUpBindingAdversarialTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';

    private const PRINCIPAL_A = '00112233445566778899aabbccddeeff';

    private const PRINCIPAL_B = 'ffeeddccbbaa99887766554433221100';

    private const SCOPE = 'checkout';

    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private SpyOutcomeReporter $reporter;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->reporter = new SpyOutcomeReporter();
    }

    private function finalizer(): StepUpDemandFinalizer
    {
        return new StepUpDemandFinalizer(
            $this->store,
            new StepUpCompletionCredit($this->reporter, self::MASTER),
            null,
            null,
            null,
            null,
            null,
            null,
            fn (): int => $this->now,
            self::MASTER,
        );
    }

    /**
     * A challenge of another session never completes a session-bound
     * demand, even when the presented binding reproduces the challenge
     * itself: the proof earned in session B belongs to another browser
     * than the demand names.
     */
    public function testAChallengeOfAnotherSessionCompletesNothing(): void
    {
        $sessionA = hash('sha256', 'sess-a');
        $sessionB = hash('sha256', 'sess-b');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            $sessionA,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        );
        $this->store->createDemand($demand, 600);

        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_A,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code'),
            null,
            'sess-b',
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($challenge, 600);

        // The presented binding matches the challenge (session B), yet
        // the demand belongs to session A: the completion refuses.
        $completed = $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            $sessionB,
            $this->now,
            $sessionB,
            self::SCOPE,
        );

        self::assertNull($completed, 'a crossed session must complete nothing');
    }

    /**
     * A challenge of another scope never completes a demand, even in the
     * same session: the scope is part of the demand identity.
     */
    public function testAChallengeOfAnotherScopeCompletesNothing(): void
    {
        $session = hash('sha256', 'sess');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            'login',
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        );
        $this->store->createDemand($demand, 600);

        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_A,
            null,
            'checkout',
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code'),
            null,
            'sess',
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($challenge, 600);

        $completed = $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            $session,
            $this->now,
            $session,
            'checkout',
        );

        self::assertNull($completed, 'a crossed scope must complete nothing');
    }

    /**
     * An account switch inside one session never completes a login demand:
     * the demand was minted for the first principal, and a challenge of the
     * second principal in the same session answers another account.
     */
    public function testAnAccountSwitchInsideOneSessionCompletesNothing(): void
    {
        $session = hash('sha256', 'sess');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            'login',
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::Login,
            StepUpOperationDigest::login('login', self::PRINCIPAL_A),
            null,
            null,
            false,
            null,
            null,
            self::PRINCIPAL_A,
        );
        $this->store->createDemand($demand, 600);

        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_B,
            null,
            'login',
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code'),
            null,
            'sess',
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->create($challenge, 600);

        $completed = $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            $session,
            $this->now,
            $session,
            'login',
        );

        self::assertNull($completed, 'a crossed subject must complete nothing');
    }

    /**
     * The (session, scope) factor history is monotonic: a later, weaker
     * completion never overwrites a stronger one. Two legitimate demands
     * of the same pair complete webauthn first and email_otp second, and
     * the history still answers webauthn.
     */
    public function testTheFactorHistoryNeverRegressesFromStrongToWeak(): void
    {
        $session = hash('sha256', 'sess');

        $webauthnDemand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        );
        $this->store->createDemand($webauthnDemand, 600);
        $webauthn = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            self::PRINCIPAL_A,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'ceremony-challenge'),
            'assertion',
            'sess',
            false,
            false,
            null,
            $webauthnDemand->id,
        );
        $this->store->create($webauthn, 600);
        $strong = $this->store->completeFactor(
            $webauthn->id,
            $webauthnDemand->id,
            $session,
            $this->now,
            $session,
            self::SCOPE,
        );
        self::assertNotNull($strong, 'the webauthn completion must land');
        self::assertSame('webauthn', $this->store->completedFactorOf($session, self::SCOPE, $this->now));

        $emailDemand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        );
        $this->store->createDemand($emailDemand, 600);
        $email = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_A,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code'),
            null,
            'sess',
            false,
            false,
            null,
            $emailDemand->id,
        );
        $this->store->create($email, 600);
        $weak = $this->store->completeFactor(
            $email->id,
            $emailDemand->id,
            $session,
            $this->now,
            $session,
            self::SCOPE,
        );
        self::assertNotNull($weak, 'the email_otp completion must land');

        self::assertSame(
            'webauthn',
            $this->store->completedFactorOf($session, self::SCOPE, $this->now),
            'the weaker completion must never regress the history',
        );
    }

    /**
     * The active-challenge admission keeps one live generation per
     * demand and replaces the prior one. A second admission succeeds,
     * consumes the first
     * record, the demand stamp moves to the second id, an absent demand
     * refuses with the typed exception, and a challenge whose TTL would
     * outlive its demand is clamped to the demand's own expiry.
     */
    public function testActiveChallengeAdmissionReplacesAndClamps(): void
    {
        $session = hash('sha256', 'sess');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        );
        $this->store->createDemand($demand, 600);

        $first = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_A,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code-1'),
            null,
            'sess',
            false,
            false,
            null,
            $demand->id,
        );
        $firstId = $this->store->createAdmittedChallenge($first, 100000);

        $second = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_A,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code-2'),
            null,
            'sess',
            false,
            false,
            null,
            $demand->id,
        );
        $secondId = $this->store->createAdmittedChallenge($second, 100000);

        self::assertNotSame($firstId, $secondId, 'the second admission mints a fresh generation');
        self::assertNull($this->store->read($firstId), 'the replaced generation is consumed');
        $stored = $this->store->readDemand($demand->id);
        self::assertNotNull($stored);
        self::assertSame($secondId, $stored->activeChallengeId, 'the demand stamp moves to the new generation');

        // The admission TTL asked for far more than the demand funds, so
        // the stored expiry is the demand's own authorization deadline.
        $clamped = $this->store->read($secondId);
        self::assertNotNull($clamped);
        self::assertLessThanOrEqual(
            $demand->expiresAt,
            $clamped->expiresAt,
            'a challenge must never outlive its demand',
        );
        self::assertSame($demand->expiresAt, $clamped->expiresAt, 'the challenge is clamped to the demand expiry');

        // An absent demand refuses the admission with the typed exception.
        $ghost = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_A,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code-3'),
            null,
            'sess',
            false,
            false,
            null,
            StepUpChallenge::mintId(),
        );
        $this->expectException(StepUpDemandAdmissionRefused::class);
        $this->store->createAdmittedChallenge($ghost, 600);
    }

    /**
     * The wire schema refuses the v3 records: a v3 record and a v4
     * record missing the load-bearing family digest both decode as
     * absent, fail closed toward a fresh demand.
     */
    public function testThePreFixSchemaRecordsAreRefused(): void
    {
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            hash('sha256', 'sess'),
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        );

        $v3 = $demand->toArray();
        $v3['v'] = 3;
        self::assertNull(StepUpDemand::fromArray($v3), 'a v3 record must decode as absent');

        $noFamily = $demand->toArray();
        unset($noFamily['family_digest']);
        self::assertNull(StepUpDemand::fromArray($noFamily), 'a v4 record without its family digest must decode as absent');
    }

    /**
     * The canonical operation encoding is injective against the classic
     * delimiter forgeries: an embedded NUL, an embedded '=' and a value
     * that is a prefix of another key/value pair. Each pair derives
     * distinct canonical bytes and distinct digests, where a
     * delimiter-joined spelling collides.
     */
    public function testTheCanonicalEncodingIsInjectiveAgainstDelimiterForgeries(): void
    {
        $nulA = ['a' => 'x'."\0".'b=2'."\0"];
        $nulB = ['a' => 'x', 'b' => '2'];
        self::assertNotSame(
            StepUpOperationDigest::canonicalOperationContent($nulA),
            StepUpOperationDigest::canonicalOperationContent($nulB),
            'an embedded NUL must not forge a field boundary',
        );
        self::assertNotSame(
            StepUpOperationDigest::formFields(self::SCOPE, $nulA),
            StepUpOperationDigest::formFields(self::SCOPE, $nulB),
            'the NUL-forged maps must derive distinct digests',
        );

        $equalsA = ['a=b' => 'x'];
        $equalsB = ['a' => 'b=x'];
        self::assertNotSame(
            StepUpOperationDigest::canonicalOperationContent($equalsA),
            StepUpOperationDigest::canonicalOperationContent($equalsB),
            'an embedded equals sign must not forge a name/value boundary',
        );
        self::assertNotSame(
            StepUpOperationDigest::formFields(self::SCOPE, $equalsA),
            StepUpOperationDigest::formFields(self::SCOPE, $equalsB),
            'the equals-forged maps must derive distinct digests',
        );

        $prefixA = ['a' => 'x', 'b' => 'y'];
        $prefixB = ['a' => "x\0b=y"];
        self::assertNotSame(
            StepUpOperationDigest::canonicalOperationContent($prefixA),
            StepUpOperationDigest::canonicalOperationContent($prefixB),
            'a value that embeds a whole key/value pair must not collide',
        );
        self::assertNotSame(
            StepUpOperationDigest::formFields(self::SCOPE, $prefixA),
            StepUpOperationDigest::formFields(self::SCOPE, $prefixB),
            'the prefix-forged maps must derive distinct digests',
        );
    }

    /**
     * The finalization reproduces the demand subject: a financial demand
     * minted for a principal refuses an anonymous presentation and
     * authorizes only when the presenting material names the same
     * principal.
     */
    public function testTheFinalizationReproducesTheDemandSubject(): void
    {
        $finalizer = $this->finalizer();
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];
        $canonical = StepUpOperationDigest::canonicalOperationContent($content);

        $demandId = $finalizer->mintFinancialDemand(
            self::SCOPE,
            'tx-42',
            $content,
            ttlSecs: 600,
            principalPseudonym: 'user-42',
        );
        self::assertNotNull($demandId);
        $completed = $this->store->completeDemand($demandId, $this->now, 600);
        self::assertNotNull($completed, 'the factor+demand completion must land');

        // An anonymous presentation of the same operation refuses: the
        // subject-bound demand is never answered without its principal.
        $anonymous = $finalizer->finalizeGrant(
            $demandId,
            new StepUpOperationMaterial(),
            null,
            'email_otp',
            'tx-42',
            $canonical,
        );
        self::assertFalse($anonymous->authorized, 'an anonymous presentation must not reproduce a subject-bound demand');

        // The presenting principal reproduces the demand subject and the
        // completion authorizes.
        $authorized = $finalizer->finalizeGrant(
            $demandId,
            new StepUpOperationMaterial(principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-42',
            $canonical,
        );
        self::assertTrue($authorized->authorized, 'the presenting principal must reproduce the demand subject');
    }
}
