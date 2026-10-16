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
     * itself: the proof earned in one browser belongs to another
     * browser than the demand names.
     *
     * The crossed state can no longer be built by admitting a crossed
     * challenge: the admission gate now judges the newcomer's identity
     * before it replaces anything, so a session-B challenge never
     * enters a session-A demand. The honest construction runs the
     * other way round: a genuine session-A challenge is admitted while
     * the demand still names session A. The demand record is then
     * re-saved in the crossed shape through the public createDemand
     * door (its id freed by the demand consumption), with the admitted
     * challenge stamped as the active one. The completion must still
     * answer nothing.
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
            'sess-a',
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->createAdmittedChallenge($challenge, 600);

        // The demand record is re-saved naming session B. The standing
        // challenge is a genuine session-A proof, and the crossed pair
        // is exactly the shape the completion gate must refuse. The
        // active-challenge stamp rides the re-saved record, so the
        // session crossing is the only gate left that can refuse the
        // completion below.
        self::assertNotNull($this->store->consumeDemand($demand->id), 'the demand id is freed for the crossed re-save');
        $crossed = StepUpDemand::mint(
            $demand->id,
            self::SCOPE,
            $sessionB,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        )->admitFactorChallenge($challenge->id, $challenge->expiresAt, $this->now);
        self::assertNotNull($crossed, 'the crossed demand record is constructible');
        $this->store->createDemand($crossed, 600);

        // The presented binding matches the challenge (session A), yet
        // the demand names session B: the completion refuses.
        $completed = $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            $sessionA,
            $this->now,
            $sessionA,
            self::SCOPE,
            hash('sha256', 'lineage-test')
    );

        self::assertNull($completed, 'a crossed session must complete nothing');
        self::assertNotNull($this->store->read($challenge->id), 'the crossed-session refusal consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the crossed demand stays open');
    }

    /**
     * A challenge of another scope never completes a demand, even in
     * the same session: the scope is part of the demand identity.
     *
     * The crossed pair is built the same way as the crossed session
     * above: the admission gate refuses a crossed newcomer outright,
     * so a genuine challenge of the demand's own scope is admitted
     * first. The demand record is then re-saved under the other scope
     * through the public createDemand door.
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
        $this->store->createAdmittedChallenge($challenge, 600);

        // The demand record is re-saved under the checkout scope: the
        // standing challenge is a genuine login-scope proof, and the
        // active-challenge stamp rides the re-saved record.
        self::assertNotNull($this->store->consumeDemand($demand->id), 'the demand id is freed for the crossed re-save');
        $crossed = StepUpDemand::mint(
            $demand->id,
            'checkout',
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
        )->admitFactorChallenge($challenge->id, $challenge->expiresAt, $this->now);
        self::assertNotNull($crossed, 'the crossed demand record is constructible');
        $this->store->createDemand($crossed, 600);

        $completed = $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            $session,
            $this->now,
            $session,
            'login',
            hash('sha256', 'lineage-test')
    );

        self::assertNull($completed, 'a crossed scope must complete nothing');
        self::assertNotNull($this->store->read($challenge->id), 'the crossed-scope refusal consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the crossed demand stays open');
    }

    /**
     * An account switch inside one session never completes a login demand:
     * the demand was minted for the first principal, and a challenge of the
     * second principal in the same session answers another account.
     *
     * The admission gate now refuses the crossed subject outright, so
     * the crossed pair is built from the honest side: a challenge of
     * the demand's own principal is admitted first. The demand record
     * is then re-saved for the second principal through the public
     * createDemand door, and the completion must still answer nothing.
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
            self::PRINCIPAL_A,
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
        $this->store->createAdmittedChallenge($challenge, 600);

        // The demand record is re-saved naming the second principal (a
        // login record carries its principal by construction). The
        // standing challenge is a genuine first-principal proof, and
        // the active-challenge stamp rides the re-saved record, so the
        // subject crossing is the only gate left to refuse on.
        self::assertNotNull($this->store->consumeDemand($demand->id), 'the demand id is freed for the crossed re-save');
        $crossed = StepUpDemand::mint(
            $demand->id,
            'login',
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::Login,
            StepUpOperationDigest::login('login', self::PRINCIPAL_B),
            null,
            null,
            false,
            null,
            null,
            self::PRINCIPAL_B,
        )->admitFactorChallenge($challenge->id, $challenge->expiresAt, $this->now);
        self::assertNotNull($crossed, 'the crossed demand record is constructible');
        $this->store->createDemand($crossed, 600);

        $completed = $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            $session,
            $this->now,
            $session,
            'login',
            hash('sha256', 'lineage-test')
    );

        self::assertNull($completed, 'a crossed subject must complete nothing');
        self::assertNotNull($this->store->read($challenge->id), 'the crossed-subject refusal consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the crossed demand stays open');
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
        $this->store->createAdmittedChallenge($webauthn, 600);
        $strong = $this->store->completeFactor(
            $webauthn->id,
            $webauthnDemand->id,
            $session,
            $this->now,
            $session,
            self::SCOPE,
            hash('sha256', 'lineage-test')
    );
        self::assertNotNull($strong, 'the webauthn completion must land');
        self::assertSame('webauthn', $this->store->completedFactorOf(hash('sha256', 'lineage-test'), null, self::SCOPE, $this->now));

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
        $this->store->createAdmittedChallenge($email, 600);
        $weak = $this->store->completeFactor(
            $email->id,
            $emailDemand->id,
            $session,
            $this->now,
            $session,
            self::SCOPE,
            hash('sha256', 'lineage-test')
    );
        self::assertNotNull($weak, 'the email_otp completion must land');

        self::assertSame(
            'webauthn',
            $this->store->completedFactorOf(hash('sha256', 'lineage-test'), null, self::SCOPE, $this->now),
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
     * The factor class rule, stated once on the kind: email_otp, totp
     * and webauthn verify material the account holds, while
     * email_ownership verifies a visitor-supplied mailbox only. The
     * demand-side predicate reads the rule off the stored records: a
     * demand that names a principal answers only to a
     * principal-authenticating factor whose verified subject reproduces
     * it, and a demand that names none keeps its behaviour.
     */
    public function testTheFactorClassRuleIsDerivedFromTheKind(): void
    {
        self::assertTrue(StepUpChallengeKind::EmailOtp->provesPrincipal(), 'a mailbox code sent to the account proves the account');
        self::assertTrue(StepUpChallengeKind::Totp->provesPrincipal(), 'a totp code from the account secret proves the account');
        self::assertTrue(StepUpChallengeKind::WebAuthn->provesPrincipal(), 'a credential assertion proves the account');
        self::assertFalse(StepUpChallengeKind::EmailOwnership->provesPrincipal(), 'an address-ownership proof is not the account proof');

        $bound = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            hash('sha256', 'sess'),
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::FormFields,
            str_repeat('a', 64),
            str_repeat('a', 64),
            str_repeat('b', 64),
            false,
            null,
            null,
            self::PRINCIPAL_A,
            hash('sha256', 'lineage'),
        );
        self::assertTrue($bound->admitsFactor(StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A), 'the own principal factor answers the demand');
        self::assertFalse($bound->admitsFactor(StepUpChallengeKind::EmailOtp, self::PRINCIPAL_B), 'another account factor never answers it');
        self::assertFalse($bound->admitsFactor(StepUpChallengeKind::EmailOwnership, null), 'an address-ownership factor never stands for the account');
        self::assertFalse($bound->admitsFactor(StepUpChallengeKind::WebAuthn, null), 'a subject-less principal factor never answers it');

        $free = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            hash('sha256', 'sess'),
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
            hash('sha256', 'lineage'),
        );
        self::assertTrue($free->admitsFactor(StepUpChallengeKind::EmailOwnership, null), 'a demand that names no principal keeps its behaviour');
        self::assertTrue($free->admitsFactor(StepUpChallengeKind::EmailOtp, self::PRINCIPAL_B), 'a principal-free demand answers any principal, as before');
    }

    /**
     * The address-ownership factor never answers a principal-bound
     * demand: the mailbox proof is not the account's proof. The
     * admission refuses the EmailOwnership challenge before it replaces
     * the standing one, the completion refuses a pair built out of
     * band, and no principal-scoped history is ever published by it.
     * The control completes the same demand with the demand's own
     * principal factor.
     */
    public function testAnAddressOwnershipFactorNeverAnswersAPrincipalBoundDemand(): void
    {
        $session = hash('sha256', 'sess');
        $lineage = hash('sha256', 'lineage-address-ownership');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::FormFields,
            str_repeat('a', 64),
            str_repeat('a', 64),
            str_repeat('b', 64),
            false,
            null,
            null,
            self::PRINCIPAL_A,
            $lineage,
        );
        $this->store->createDemand($demand, 600);

        // The standing challenge is the demand's own principal factor.
        $standing = StepUpChallenge::begin(
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
            $demand->id,
        );
        $this->store->createAdmittedChallenge($standing, 600);

        // The address-ownership newcomer is refused at the door: the
        // standing challenge stays exactly where it was.
        $addressOwnership = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOwnership,
            str_repeat('e', 32),
            null,
            self::SCOPE,
            null,
            'email_ownership',
            $this->now,
            600,
            5,
            hash('sha256', 'mail-code'),
            null,
            'sess',
            false,
            false,
            null,
            $demand->id,
        );
        try {
            $this->store->createAdmittedChallenge($addressOwnership, 600);
            self::fail('an address-ownership challenge must never be admitted against a principal-bound demand');
        } catch (StepUpDemandAdmissionRefused) {
        }
        self::assertNull($this->store->read($addressOwnership->id), 'the refused newcomer left no record');
        self::assertNotNull($this->store->read($standing->id), 'the standing challenge is untouched');
        self::assertSame($standing->id, $this->store->readDemand($demand->id)?->activeChallengeId, 'the demand still names its own challenge');

        // The completion boundary, on a pair built out of band. The
        // address-ownership record enters through the plain create door
        // while the demand is out of the open state (the grant shape),
        // then the demand id is freed and the demand is re-created open
        // with the record stamped as its active challenge: a shape no
        // reachable caller can build any more now that admission refuses
        // the address-ownership factor outright. The completion must
        // still refuse and publish no principal history.
        self::assertNotNull($this->store->completeDemand($demand->id, $this->now, 600), 'the demand leaves the open state for the grant-shaped create');
        $this->store->create($addressOwnership, 600);
        self::assertNotNull($this->store->read($addressOwnership->id), 'the grant-shaped address-ownership record stores');
        self::assertNotNull($this->store->consumeDemand($demand->id), 'the demand id is freed for the crossed re-save');
        $crossed = StepUpDemand::mint(
            $demand->id,
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::FormFields,
            str_repeat('a', 64),
            str_repeat('a', 64),
            str_repeat('b', 64),
            false,
            null,
            null,
            self::PRINCIPAL_A,
            $lineage,
        )->admitFactorChallenge($addressOwnership->id, $addressOwnership->expiresAt, $this->now);
        self::assertNotNull($crossed, 'the crossed demand record is constructible');
        $this->store->createDemand($crossed, 600);

        $completed = $this->store->completeFactor(
            $addressOwnership->id,
            $demand->id,
            (string) $addressOwnership->sessionHash,
            $this->now,
            $addressOwnership->sessionHash,
            self::SCOPE,
            $lineage,
        );
        self::assertNull($completed, 'the address-ownership factor completes nothing');
        self::assertNotNull($this->store->read($addressOwnership->id), 'the refusal consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the demand stays open');
        self::assertNull($this->store->completedFactorOf($lineage, self::PRINCIPAL_A, self::SCOPE, $this->now), 'no principal-scoped history was published');

        // The control: the demand's own principal factor completes it
        // and files its history under the principal's bucket.
        $control = StepUpChallenge::begin(
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
        $this->store->createAdmittedChallenge($control, 600);
        $controlDone = $this->store->completeFactor(
            $control->id,
            $demand->id,
            (string) $control->sessionHash,
            $this->now,
            $control->sessionHash,
            self::SCOPE,
            $lineage,
        );
        self::assertNotNull($controlDone, 'the principal factor completes the demand');
        self::assertSame('email_otp', $this->store->completedFactorOf($lineage, self::PRINCIPAL_A, self::SCOPE, $this->now));
        self::assertNull($this->store->completedFactorOf($lineage, null, self::SCOPE, $this->now), 'the principal history never lands in the anonymous bucket');
    }

    /**
     * The principal rule holds on every binding kind, not only login: a
     * financial operation minted for one account is answered by that
     * account's factor alone. The crossed challenge is refused at the
     * door, and the crossed pair built out of band is refused at the
     * completion.
     */
    public function testANonLoginPrincipalBoundDemandRefusesAnotherPrincipalsFactor(): void
    {
        $session = hash('sha256', 'sess');
        $lineage = hash('sha256', 'lineage-subject');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::RequestBinding,
            str_repeat('c', 64),
            null,
            null,
            false,
            null,
            null,
            self::PRINCIPAL_A,
            $lineage,
        );
        $this->store->createDemand($demand, 600);

        $own = StepUpChallenge::begin(
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
            $demand->id,
        );
        $this->store->createAdmittedChallenge($own, 600);

        $foreign = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_B,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code-b'),
            null,
            'sess',
            false,
            false,
            null,
            $demand->id,
        );
        try {
            $this->store->createAdmittedChallenge($foreign, 600);
            self::fail('another account factor must never be admitted against a principal-bound demand');
        } catch (StepUpDemandAdmissionRefused) {
        }
        self::assertNull($this->store->read($foreign->id), 'the refused newcomer left no record');
        self::assertSame($own->id, $this->store->readDemand($demand->id)?->activeChallengeId, 'the demand still names its own challenge');

        // The completion boundary on the crossed pair built out of band:
        // the second account's challenge is admitted against a demand of
        // its own principal first, then this demand is re-saved with that
        // record stamped as its active challenge. The completion must
        // refuse and file no history.
        $otherDemand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::RequestBinding,
            str_repeat('c', 64),
            null,
            null,
            false,
            null,
            null,
            self::PRINCIPAL_B,
            $lineage,
        );
        $this->store->createDemand($otherDemand, 600);
        $foreignStored = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL_B,
            null,
            self::SCOPE,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code-b2'),
            null,
            'sess',
            false,
            false,
            null,
            $otherDemand->id,
        );
        $this->store->createAdmittedChallenge($foreignStored, 600);
        self::assertNotNull($this->store->read($foreignStored->id), 'the second account challenge is admitted against its own demand');

        self::assertNotNull($this->store->consumeDemand($demand->id), 'the demand id is freed for the crossed re-save');
        $crossed = StepUpDemand::mint(
            $demand->id,
            self::SCOPE,
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::RequestBinding,
            str_repeat('c', 64),
            null,
            null,
            false,
            null,
            null,
            self::PRINCIPAL_A,
            $lineage,
        )->admitFactorChallenge($foreignStored->id, $foreignStored->expiresAt, $this->now);
        self::assertNotNull($crossed, 'the crossed demand record is constructible');
        $this->store->createDemand($crossed, 600);

        $completed = $this->store->completeFactor(
            $foreignStored->id,
            $demand->id,
            $session,
            $this->now,
            $session,
            self::SCOPE,
            $lineage,
        );
        self::assertNull($completed, 'the second account factor completes nothing for the first account demand');
        self::assertNotNull($this->store->read($foreignStored->id), 'the refusal consumed no challenge');
        self::assertTrue($this->store->readDemand($demand->id)?->state->isOpen(), 'the demand stays open');
        self::assertNull($this->store->completedFactorOf($lineage, self::PRINCIPAL_A, self::SCOPE, $this->now), 'the crossed refusal filed no history');
        self::assertNull($this->store->completedFactorOf($lineage, self::PRINCIPAL_B, self::SCOPE, $this->now), 'the crossed refusal filed nothing for the other account either');
    }

    /**
     * A demand that names no principal keeps its current behaviour: an
     * address-ownership factor answers it, the anonymous grant lane.
     */
    public function testAPrincipalFreeDemandKeepsItsCurrentFactorBehaviour(): void
    {
        $session = hash('sha256', 'sess');
        $lineage = hash('sha256', 'lineage-anonymous');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            'signup',
            $session,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
            StepUpOperationDigest::none('signup'),
            null,
            null,
            false,
            null,
            null,
            null,
            $lineage,
        );
        $this->store->createDemand($demand, 600);
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOwnership,
            str_repeat('d', 32),
            null,
            'signup',
            null,
            'email_ownership',
            $this->now,
            600,
            5,
            hash('sha256', 'mail-code'),
            null,
            'sess',
            false,
            false,
            null,
            $demand->id,
        );
        $this->store->createAdmittedChallenge($challenge, 600);
        $completed = $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            (string) $challenge->sessionHash,
            $this->now,
            $challenge->sessionHash,
            'signup',
            $lineage,
        );
        self::assertNotNull($completed, 'the anonymous carrier demand admits and completes the address-ownership factor');
        self::assertSame('email_otp', $this->store->completedFactorOf($lineage, null, 'signup', $this->now), 'the anonymous bucket keeps the ladder');
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
