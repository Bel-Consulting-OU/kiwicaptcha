<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandAdmissionRefused;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The two admission and completion gates of the step-up stores are
 * driven side by side through both backends. The first is the identity
 * gate of createAdmittedChallenge(), which runs before the replace
 * touches anything. The second is the active-challenge authority of
 * completeFactor(), which lets only the demand's own active challenge
 * complete it.
 *
 * Every case runs the same scenario on the array store (the
 * single-process dev/test backend) and on the Redis store over the
 * emulated Predis client, and asserts the two lanes agreed on every
 * projected answer before the expected answers are pinned. One clock
 * serves both lanes: the array store's injected clock box and the
 * emulated server clock of the fake stand at the same instant, so no
 * time boundary can flip between the two calls.
 *
 * The property the identity gate exists for is stated by the shared
 * projection of every refused admission. That projection is: the typed
 * refusal, no record for the newcomer, and the standing active
 * challenge still readable, still the demand's own active challenge,
 * and still completing on its own binding. An invalid newcomer can
 * therefore never evict a perfectly good code and strand the browser
 * that holds it.
 */
final class StepUpAdmissionAuthorityTest extends TestCase
{
    private const BASE_NOW = 1700000000;

    /** A hash-tagged key family, the shape the Redis store requires. */
    private const PREFIX = '{kiwi:admit}:stepup:';

    private const SESSION_ID = 'admission-authority-session-00001';

    private const FOREIGN_SESSION_ID = 'admission-authority-session-00002';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const FOREIGN_PRINCIPAL = 'ffeeddccbbaa99887766554433221100';

    /** The 64-hex operation digest a bound demand must carry at mint. */
    private const OPERATION_DIGEST = '1111111111111111111111111111111111111111111111111111111111111111';

    /** The 64-hex lineage the history keys are filed under. */
    private const LINEAGE_HASH = '9f2c4b7a1d5e8036c9a4f1b2d7e6a35c8b0d9e4f2a7c6b1d8e3f5a0c9b4d2e71';

    /**
     * The projection every refused admission must produce, whichever
     * identity dimension carried the newcomer across: the typed
     * refusal, nothing stored for the newcomer, and the standing active
     * challenge untouched, still the demand's own active challenge and
     * still completing.
     *
     * @var array<string, bool>
     */
    private const REFUSED_NEWCOMER = [
        'the refusal is typed' => true,
        'the newcomer left no record' => true,
        'the standing challenge is still readable' => true,
        'the demand still names the standing challenge' => true,
        'the standing challenge still completes' => true,
    ];

    /**
     * The scope dimension. A challenge of another scope is not the
     * demand's challenge, whatever else it carries: the admission
     * refuses it before the standing challenge is touched, and the
     * standing challenge goes on to complete.
     */
    public function testTheScopeGateRefusesACrossedScopeOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatescopedemand00001'), 900);
            $standing = $this->challenge('admitgatescopechall000001', 'admitgatescopedemand00001');
            $store->createAdmittedChallenge($standing, 600);
            $newcomer = $this->challenge('admitgatescopechall000002', 'admitgatescopedemand00001', 'checkout_other');

            return $this->refusedNewcomer($store, 'admitgatescopedemand00001', $standing, $newcomer);
        });

        self::assertSame(self::REFUSED_NEWCOMER, $answer, 'a crossed scope must refuse and leave the standing challenge whole');
    }

    /**
     * The liveness dimension. A newcomer whose own window has already
     * closed is refused like any other invalid record. Admitted, it
     * would evict the standing challenge and leave the demand naming a
     * record nothing can complete, stranding the browser that holds a
     * perfectly good code. The clock is walked forward to just inside
     * the demand's own authorization window and well past the
     * newcomer's ten-second window, so the refusal is the newcomer's
     * expiry and never the demand's.
     */
    public function testTheLivenessGateRefusesANewcomerWhoseWindowClosedOnBothStores(): void
    {
        $lanes = [];
        foreach ([false, true] as $redisLane) {
            [$arrayStore, $redisStore, $fake, $clock] = $this->stores();
            $store = $redisLane ? $redisStore : $arrayStore;
            $no = $redisLane ? '02' : '01';
            $store->createDemand($this->demand('admitgatelivedemand000'.$no), 900);
            $standing = $this->challenge('admitgatelivechall0000'.$no.'1', 'admitgatelivedemand000'.$no);
            $store->createAdmittedChallenge($standing, 600);
            $newcomer = $this->challenge('admitgatelivechall0000'.$no.'2', 'admitgatelivedemand000'.$no)->withClampedExpiry(self::BASE_NOW + 10);
            $clock->now = self::BASE_NOW + 100;
            $fake->setTimeMs(($clock->now) * 1000);
            $lanes[$redisLane ? 'the Redis store' : 'the array store'] = $this->refusedNewcomer($store, 'admitgatelivedemand000'.$no, $standing, $newcomer);
        }
        self::assertSame($lanes['the array store'], $lanes['the Redis store'], 'the two stores must answer this case identically');
        self::assertSame(self::REFUSED_NEWCOMER, $lanes['the array store'], 'a newcomer whose own window closed must refuse and leave the standing challenge whole');
    }

    /**
     * The session dimension. The demand is bound to one continuity
     * session, so a challenge of another session belongs to another
     * browser: the admission refuses it and the session's own challenge
     * stays active and completes.
     */
    public function testTheSessionGateRefusesACrossedSessionOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatesessiondemand001'), 900);
            $standing = $this->challenge('admitgatesessionchall00001', 'admitgatesessiondemand001');
            $store->createAdmittedChallenge($standing, 600);
            $newcomer = $this->challenge('admitgatesessionchall00002', 'admitgatesessiondemand001', 'checkout', self::FOREIGN_SESSION_ID);

            return $this->refusedNewcomer($store, 'admitgatesessiondemand001', $standing, $newcomer);
        });

        self::assertSame(self::REFUSED_NEWCOMER, $answer, 'a crossed session must refuse and leave the standing challenge whole');
    }

    /**
     * The subject dimension. The login demand names the principal it
     * was minted for, so a challenge of another principal would prove
     * another account's factor: the admission refuses it and the
     * demand's own principal keeps its active challenge.
     */
    public function testTheSubjectGateRefusesACrossedPrincipalOnALoginDemandOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatesubjectdemand001', 'checkout', self::SESSION_ID, StepUpOperationBindingKind::Login, self::PRINCIPAL), 900);
            $standing = $this->challenge('admitgatesubjectchall00001', 'admitgatesubjectdemand001');
            $store->createAdmittedChallenge($standing, 600);
            $newcomer = $this->challenge('admitgatesubjectchall00002', 'admitgatesubjectdemand001', 'checkout', self::SESSION_ID, self::FOREIGN_PRINCIPAL);

            return $this->refusedNewcomer($store, 'admitgatesubjectdemand001', $standing, $newcomer);
        });

        self::assertSame(self::REFUSED_NEWCOMER, $answer, 'a crossed principal must refuse and leave the standing challenge whole');
    }

    /**
     * The factor-snapshot dimension, first case: a record without a
     * snapshot at all. No constructor of {@see StepUpChallenge} can
     * produce the shape (the begin derives the kind's own rung and the
     * decode does the same). The record is therefore forged at the
     * object level, exactly the degenerate shape the admission gate's
     * snapshot clause defends against. Both stores must refuse it and
     * leave the standing challenge whole.
     */
    public function testTheFactorGateRefusesANewcomerWithoutASnapshotOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatefactordemand0001', 'checkout', self::SESSION_ID, StepUpOperationBindingKind::Login, self::PRINCIPAL), 900);
            $standing = $this->challenge('admitgatefactorchall00001', 'admitgatefactordemand0001');
            $store->createAdmittedChallenge($standing, 600);
            $newcomer = $this->forgedChallenge(
                $this->challenge('admitgatefactorchall00002', 'admitgatefactordemand0001'),
                null,
            );

            return $this->refusedNewcomer($store, 'admitgatefactordemand0001', $standing, $newcomer);
        });

        self::assertSame(self::REFUSED_NEWCOMER, $answer, 'a snapshot-less newcomer must refuse and leave the standing challenge whole');
    }

    /**
     * The factor-snapshot dimension, second case: a snapshot whose
     * family is the empty string. The value class refuses such a
     * requirement at construction, so the record is forged at the
     * object level, and both stores must refuse it by the same clause
     * that refuses the snapshot-less record.
     */
    public function testTheFactorGateRefusesANewcomerWhoseSnapshotNamesNoFamilyOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatefamilydemand001', 'checkout', self::SESSION_ID, StepUpOperationBindingKind::Login, self::PRINCIPAL), 900);
            $standing = $this->challenge('admitgatefamilychall00001', 'admitgatefamilydemand001');
            $store->createAdmittedChallenge($standing, 600);
            $newcomer = $this->forgedChallenge(
                $this->challenge('admitgatefamilychall00002', 'admitgatefamilydemand001'),
                $this->forgedRequirement('', 'email_otp', 1),
            );

            return $this->refusedNewcomer($store, 'admitgatefamilydemand001', $standing, $newcomer);
        });

        self::assertSame(self::REFUSED_NEWCOMER, $answer, 'a snapshot naming no family must refuse and leave the standing challenge whole');
    }

    /**
     * The control beside the factor gate: a coherent snapshot that
     * names a custom handler identity inside its kind's own family is
     * exactly the shape a custom handler ships. Both stores must admit
     * it and complete it under the family the record proves. The gate
     * refuses incoherence, never a handler identity.
     */
    public function testACustomHandlerSnapshotWithinTheKindFamilyIsAdmittedOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatecustomdemand0001', 'checkout', self::SESSION_ID, StepUpOperationBindingKind::Login, self::PRINCIPAL), 900);
            $custom = $this->challenge(
                'admitgatecustomchall00001',
                'admitgatecustomdemand0001',
                'checkout',
                self::SESSION_ID,
                self::PRINCIPAL,
                new FactorRequirement(FactorRequirement::EMAIL_OTP, 'acme_email_otp', 1),
            );
            $store->createAdmittedChallenge($custom, 600);
            $completion = $store->completeFactor($custom->id, 'admitgatecustomdemand0001', $this->bindingOf($custom), self::BASE_NOW);

            return [
                'the custom snapshot was admitted' => $store->readDemand('admitgatecustomdemand0001')?->activeChallengeId === $custom->id,
                'the custom challenge completes' => $completion !== null,
                'the completed factor is the kind family' => $completion?->completedFactor,
            ];
        });

        self::assertSame(
            ['the custom snapshot was admitted' => true, 'the custom challenge completes' => true, 'the completed factor is the kind family' => 'email_otp'],
            $answer,
            'a handler identity inside the kind family is never over-refused',
        );
    }

    /**
     * The gates must not over-refuse. A demand bound neither to a
     * session nor to a login principal judges neither dimension. A
     * challenge of a session the demand never saw, and a stateless
     * challenge of a principal the demand never named, both belong to
     * it and both complete it on both stores.
     */
    public function testASessionlessNonLoginDemandAdmitsAnySessionAndAnyPrincipalOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            // The demand carries no session binding, so the challenge of
            // a foreign session is admitted and completes.
            $store->createDemand($this->demand('admitgatelessdemand00001', 'checkout', null), 900);
            $foreignSession = $this->challenge('admitgatelesschall000001', 'admitgatelessdemand00001', 'checkout', self::FOREIGN_SESSION_ID, self::FOREIGN_PRINCIPAL);
            $store->createAdmittedChallenge($foreignSession, 600);
            $foreignSessionCompletes = $store->completeFactor($foreignSession->id, 'admitgatelessdemand00001', $this->bindingOf($foreignSession), self::BASE_NOW) !== null;

            // The demand binds no session at all, so a stateless
            // challenge arrives through its own client secret, with a
            // subject the demand never named.
            $store->createDemand($this->demand('admitgatelessdemand00002', 'checkout', null), 900);
            $stateless = $this->challenge('admitgatelesschall000002', 'admitgatelessdemand00002', 'checkout', null, self::FOREIGN_PRINCIPAL);
            $store->createAdmittedChallenge($stateless, 600);
            $statelessCompletes = $store->completeFactor($stateless->id, 'admitgatelessdemand00002', $this->bindingOf($stateless), self::BASE_NOW) !== null;

            return [
                'a challenge of a foreign session is admitted and completes' => $foreignSessionCompletes,
                'a stateless challenge of a foreign principal is admitted and completes' => $statelessCompletes,
            ];
        });

        self::assertSame(
            ['a challenge of a foreign session is admitted and completes' => true, 'a stateless challenge of a foreign principal is admitted and completes' => true],
            $answer,
            'the session and subject clauses apply only to the demand shapes that carry those bindings',
        );
    }

    /**
     * The scope clause is the one dimension every demand shape judges:
     * a session-less non-login demand refuses a challenge of another
     * scope exactly like the bound shapes do, and its own challenge
     * stays active and completes.
     */
    public function testTheScopeGateAppliesToASessionlessNonLoginDemandOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatescopelessdemand01', 'checkout', null), 900);
            $standing = $this->challenge('admitgatescopelesschall001', 'admitgatescopelessdemand01', 'checkout', null);
            $store->createAdmittedChallenge($standing, 600);
            $newcomer = $this->challenge('admitgatescopelesschall002', 'admitgatescopelessdemand01', 'checkout_other', null);

            return $this->refusedNewcomer($store, 'admitgatescopelessdemand01', $standing, $newcomer);
        });

        self::assertSame(self::REFUSED_NEWCOMER, $answer, 'the scope clause applies to every demand shape');
    }

    /**
     * The replace semantics of a successful admission, on both stores:
     * the second admitted challenge becomes the demand's one active
     * challenge, the first record is retired in the same move, and the
     * demand's active challenge id moves with it. A late completion of
     * the retired code answers nothing, and the standing one answers
     * the factor.
     */
    public function testASuccessfulReplaceRetiresThePriorChallengeOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatereplacedemand001'), 900);
            $first = $this->challenge('admitgatereplacechall001', 'admitgatereplacedemand001');
            $second = $this->challenge('admitgatereplacechall002', 'admitgatereplacedemand001');
            $store->createAdmittedChallenge($first, 600);
            $store->createAdmittedChallenge($second, 600);

            return [
                'the retired record is gone' => $store->read($first->id) === null,
                'the retired challenge completes nothing' => $store->completeFactor($first->id, 'admitgatereplacedemand001', $this->bindingOf($first), self::BASE_NOW) === null,
                'the demand names the second challenge' => $store->readDemand('admitgatereplacedemand001')?->activeChallengeId === $second->id,
                'the second challenge completes' => $store->completeFactor($second->id, 'admitgatereplacedemand001', $this->bindingOf($second), self::BASE_NOW) !== null,
            ];
        });

        self::assertSame(
            ['the retired record is gone' => true, 'the retired challenge completes nothing' => true, 'the demand names the second challenge' => true, 'the second challenge completes' => true],
            $answer,
            'a replace must retire the prior challenge and leave exactly one completing code',
        );
    }

    /**
     * The active authority at its most ordinary: a demand-bound record
     * that entered through the plain create door, the email ownership
     * grant shape (the demand it names is already out of the open
     * state). The completion answers nothing and consumes neither
     * record on either store, so the grant can never be mistaken for
     * the demand's factor.
     */
    public function testACompletionThroughAPlainCreatedGrantCompletesNothingOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgategrantdemand00001'), 900);
            $store->completeDemand('admitgategrantdemand00001', self::BASE_NOW, 900);
            $grant = $this->challenge('admitgategrantchall00001', 'admitgategrantdemand00001');
            $store->create($grant, 600);
            $refused = $store->completeFactor($grant->id, 'admitgategrantdemand00001', $this->bindingOf($grant), self::BASE_NOW) === null;

            return [
                'the completion through the grant answers nothing' => $refused,
                'the grant record is still there' => $store->read($grant->id) !== null,
                'the demand record is still there' => $store->readDemand('admitgategrantdemand00001') !== null,
                'the demand never moved' => $store->readDemand('admitgategrantdemand00001')?->state === StepUpDemandState::Completed,
            ];
        });

        self::assertSame(
            ['the completion through the grant answers nothing' => true, 'the grant record is still there' => true, 'the demand record is still there' => true, 'the demand never moved' => true],
            $answer,
            'a plain-created grant completes nothing and consumes nothing',
        );
    }

    /**
     * The active authority as the gate itself: a live, identity-
     * matching, unexpired record that names the open demand yet is not
     * the challenge the demand acts on. The completion must answer
     * nothing, consume neither record, and leave the demand's real
     * active challenge completing.
     *
     * The construction is deliberate and is the only reachable one.
     * A demand-bound record enters through the plain create door only
     * while its demand is out of the open state. No demand transition
     * returns to the open state, so the demand id is re-minted
     * underneath the grant: the record is consumed, then a fresh
     * demand of the same scope and session stands under the same id.
     * That is the one shape in which a live record bound to an open
     * demand coexists with the demand without being its active
     * challenge, which is exactly what the authority gate is for.
     */
    public function testTheActiveChallengeAuthorityRefusesAStrayRecordOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatestraydemand00001'), 900);
            $store->completeDemand('admitgatestraydemand00001', self::BASE_NOW, 900);
            $stray = $this->challenge('admitgatestraychall000001', 'admitgatestraydemand00001');
            $store->create($stray, 600);
            $store->consumeDemand('admitgatestraydemand00001');
            $store->createDemand($this->demand('admitgatestraydemand00001'), 900);

            // No active challenge is stamped yet, and the stray record
            // is live, unexpired and answers the demand's identity.
            $refusedWithoutAnActive = $store->completeFactor($stray->id, 'admitgatestraydemand00001', $this->bindingOf($stray), self::BASE_NOW) === null;
            $survivedTheFirstRefusal = $store->read($stray->id) !== null;

            // Now the demand has a real active challenge beside it, so
            // the stray needs no excuse at all: nothing was consumed,
            // both records survive, and the demand still names its own
            // challenge.
            $active = $this->challenge('admitgatestraychall000002', 'admitgatestraydemand00001');
            $store->createAdmittedChallenge($active, 600);
            $refusedBesideTheActive = $store->completeFactor($stray->id, 'admitgatestraydemand00001', $this->bindingOf($stray), self::BASE_NOW) === null;

            // The control: the identical demand and challenge shapes,
            // the challenge admitted as its demand's active challenge,
            // complete. Every identity dimension of the stray fixture is
            // therefore complete, and the authority gate is the one gate
            // its refusal can be.
            $store->createDemand($this->demand('admitgatecontroldemand001'), 900);
            $control = $this->challenge('admitgatecontrolchall001', 'admitgatecontroldemand001');
            $store->createAdmittedChallenge($control, 600);
            $controlCompletes = $store->completeFactor($control->id, 'admitgatecontroldemand001', $this->bindingOf($control), self::BASE_NOW) !== null;

            return [
                'the stray completes nothing without an active challenge' => $refusedWithoutAnActive,
                'the stray survived that refusal' => $survivedTheFirstRefusal,
                'the stray completes nothing beside the active challenge' => $refusedBesideTheActive,
                'the stray survived the second refusal' => $store->read($stray->id) !== null,
                'the active challenge is untouched' => $store->read($active->id) !== null,
                'the demand still names the active challenge' => $store->readDemand('admitgatestraydemand00001')?->activeChallengeId === $active->id,
                'the active challenge still completes' => $store->completeFactor($active->id, 'admitgatestraydemand00001', $this->bindingOf($active), self::BASE_NOW) !== null,
                'the same shapes complete when the record is the active challenge' => $controlCompletes,
            ];
        });

        self::assertSame(
            [
                'the stray completes nothing without an active challenge' => true,
                'the stray survived that refusal' => true,
                'the stray completes nothing beside the active challenge' => true,
                'the stray survived the second refusal' => true,
                'the active challenge is untouched' => true,
                'the demand still names the active challenge' => true,
                'the active challenge still completes' => true,
                'the same shapes complete when the record is the active challenge' => true,
            ],
            $answer,
            'only the demand active challenge may complete it, and a refusal consumes nothing',
        );
    }

    /**
     * The plain create door of both stores, on the same fixture shape:
     * a challenge bound to a live open demand is refused with the
     * typed runtime error and stores nothing. A challenge bound to an
     * absent demand is refused too. The one allowed demand-bound
     * record is the grant whose demand is already out of the open
     * state; that record stores and reads back.
     */
    public function testAPlainCreateRefusesALiveDemandBoundChallengeOnBothStores(): void
    {
        $answer = $this->bothStores(function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array {
            $store->createDemand($this->demand('admitgatecreatedemand0001'), 900);
            $boundToALiveDemand = $this->challenge('admitgatecreatechall00001', 'admitgatecreatedemand0001');
            $liveRefusal = null;
            try {
                $store->create($boundToALiveDemand, 600);
            } catch (\Throwable $refusal) {
                $liveRefusal = $refusal::class;
            }
            $absentRefusal = null;
            try {
                $store->create($this->challenge('admitgatecreatechall00002', 'admitgateabsentdemand0001'), 600);
            } catch (\Throwable $refusal) {
                $absentRefusal = $refusal::class;
            }

            $store->completeDemand('admitgatecreatedemand0001', self::BASE_NOW, 900);
            $grant = $this->challenge('admitgatecreatechall00003', 'admitgatecreatedemand0001');
            $stored = null;
            try {
                $stored = $store->create($grant, 600);
            } catch (\Throwable) {
                $stored = null;
            }

            return [
                'a live-demand record is refused' => $liveRefusal,
                'an absent-demand record is refused' => $absentRefusal,
                'nothing of the refused creates landed' => $store->read($boundToALiveDemand->id) === null && $store->read('admitgatecreatechall00002') === null,
                'the settled-demand grant stores' => $stored,
                'the settled-demand grant is readable' => $store->read($grant->id) !== null,
                'the demand stayed out of the open state' => $store->readDemand('admitgatecreatedemand0001')?->state === StepUpDemandState::Completed,
            ];
        });

        self::assertSame(
            [
                'a live-demand record is refused' => \RuntimeException::class,
                'an absent-demand record is refused' => \RuntimeException::class,
                'nothing of the refused creates landed' => true,
                'the settled-demand grant stores' => 'admitgatecreatechall00003',
                'the settled-demand grant is readable' => true,
                'the demand stayed out of the open state' => true,
            ],
            $answer,
            'the plain create door admits only the settled-demand grant shape',
        );
    }

    /**
     * The history-key parity. A completion on a login demand that
     * carries a principal pseudonym is filed under one key identity on
     * both backends: the (lineage, principal, scope) triple. The array
     * store derives the key from its stored demand record, and the
     * Redis script derives it from the demand record it is about to
     * move. So the same probe must answer the completed factor on both
     * stores, and the anonymous bucket (a null principal) must answer
     * nothing on both. The raw key and value of the Redis lane are
     * pinned too, since that is the one lane whose storage is
     * observable.
     */
    public function testACompletionIsFiledUnderOneHistoryKeyOnBothStores(): void
    {
        [$arrayStore, $redisStore, $fake] = $this->stores();
        $answers = [];
        foreach (['the array store' => $arrayStore, 'the Redis store' => $redisStore] as $lane => $store) {
            $answers[$lane] = $this->historyScenario($store);
        }

        self::assertSame($answers['the array store'], $answers['the Redis store'], 'the two stores must file and read the completion history under one key identity');
        self::assertSame(
            [
                'the completion answered the factor' => true,
                'the principal-keyed probe answers the factor' => 'email_otp',
                'the anonymous-bucket probe answers nothing' => null,
                'another principal answers nothing' => null,
                'another scope answers nothing' => null,
                'an unknown lineage answers nothing' => null,
            ],
            $answers['the array store'],
            'the login completion is filed under the demand principal alone',
        );

        // The Redis key family of the escalation marker, spelled out:
        // the deploy prefix, the history family, the lineage, the
        // principal digest and the scope digest. The value carries the
        // scope, the family, the ladder rank, the demand's authorization
        // window and the completion stamp the server clock read.
        $key = self::PREFIX.'emdone:'.self::LINEAGE_HASH.':'.hash('sha256', self::PRINCIPAL).':'.hash('sha256', 'checkout');
        self::assertSame(
            'checkout|email_otp|1|'.(self::BASE_NOW + 900).'|'.self::BASE_NOW,
            $fake->strings[$key] ?? null,
            'the marker sits under the (lineage, principal, scope) key with the record-proven identity',
        );
    }

    /**
     * One history scenario, driven end to end on one store: a login
     * demand whose principal is named, its admitted challenge, the
     * completion that files the history, and the probes over the key
     * identity. It returns only scalars, so the two lanes' answers can
     * be compared whole.
     *
     * @return array<string, mixed>
     */
    private function historyScenario(ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store): array
    {
        $store->createDemand($this->demand('admitgatehistorydemand001', 'checkout', self::SESSION_ID, StepUpOperationBindingKind::Login, self::PRINCIPAL), 900);
        $challenge = $this->challenge('admitgatehistorychall001', 'admitgatehistorydemand001');
        $store->createAdmittedChallenge($challenge, 600);
        $completion = $store->completeFactor(
            $challenge->id,
            'admitgatehistorydemand001',
            $this->bindingOf($challenge),
            self::BASE_NOW,
            $challenge->sessionHash,
            'checkout',
            self::LINEAGE_HASH,
        );

        return [
            'the completion answered the factor' => $completion !== null,
            'the principal-keyed probe answers the factor' => $store->completedFactorOf(self::LINEAGE_HASH, self::PRINCIPAL, 'checkout', self::BASE_NOW),
            'the anonymous-bucket probe answers nothing' => $store->completedFactorOf(self::LINEAGE_HASH, null, 'checkout', self::BASE_NOW),
            'another principal answers nothing' => $store->completedFactorOf(self::LINEAGE_HASH, self::FOREIGN_PRINCIPAL, 'checkout', self::BASE_NOW),
            'another scope answers nothing' => $store->completedFactorOf(self::LINEAGE_HASH, self::PRINCIPAL, 'login', self::BASE_NOW),
            'an unknown lineage answers nothing' => $store->completedFactorOf(str_repeat('a', 64), self::PRINCIPAL, 'checkout', self::BASE_NOW),
        ];
    }

    /**
     * One refused admission, driven through a store and projected into
     * the five answers of {@see self::REFUSED_NEWCOMER}: the typed
     * refusal, no record for the newcomer, and the standing challenge
     * still readable, still the demand's own active challenge. It still
     * completes on its own binding. The standing challenge is completed
     * last, since a completion spends the demand.
     *
     * @return array<string, bool>
     */
    private function refusedNewcomer(
        ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store,
        string $demandId,
        StepUpChallenge $standing,
        StepUpChallenge $newcomer,
    ): array {
        $refusalType = null;
        try {
            $store->createAdmittedChallenge($newcomer, 600);
        } catch (\Throwable $refusal) {
            $refusalType = $refusal::class;
        }

        return [
            'the refusal is typed' => $refusalType === StepUpDemandAdmissionRefused::class,
            'the newcomer left no record' => $store->read($newcomer->id) === null,
            'the standing challenge is still readable' => $store->read($standing->id) !== null,
            'the demand still names the standing challenge' => $store->readDemand($demandId)?->activeChallengeId === $standing->id,
            'the standing challenge still completes' => $store->completeFactor($standing->id, $demandId, $this->bindingOf($standing), self::BASE_NOW) !== null,
        ];
    }

    /**
     * The two stores over one clock, the differential test's own
     * construction: the array store on the injected clock box and the
     * Redis store over the emulated client whose server clock stands at
     * the same instant. The two lanes therefore judge every expiry
     * against one time.
     *
     * @return array{0: ArrayStepUpChallengeStore, 1: RedisStepUpChallengeStore, 2: FakePredisClient, 3: \stdClass}
     */
    private function stores(): array
    {
        $clock = new \stdClass();
        $clock->now = self::BASE_NOW;
        $fake = new FakePredisClient();
        $fake->setTimeMs(self::BASE_NOW * 1000);
        $arrayStore = new ArrayStepUpChallengeStore(static fn (): int => $clock->now);
        $redisStore = new RedisStepUpChallengeStore($fake, self::PREFIX);

        return [$arrayStore, $redisStore, $fake, $clock];
    }

    /**
     * Drive one scenario on both stores and answer the array store's
     * projection, asserting first that the two lanes produced the same
     * answer field for field. Every scenario builds its own demand and
     * challenge ids, so the two lanes never share a record.
     *
     * @param \Closure(ArrayStepUpChallengeStore|RedisStepUpChallengeStore): array<string, mixed> $scenario
     *
     * @return array<string, mixed>
     */
    private function bothStores(\Closure $scenario): array
    {
        [$arrayStore, $redisStore] = $this->stores();
        $answers = [
            'the array store' => $scenario($arrayStore),
            'the Redis store' => $scenario($redisStore),
        ];
        self::assertSame($answers['the array store'], $answers['the Redis store'], 'the two stores must answer this case identically');

        return $answers['the array store'];
    }

    /**
     * The stored demand fixture: bound to the named session (null when
     * the shape carries no session binding), with the login binding and
     * its principal when the kind names one. A bound demand needs the
     * operation digest its recipe mints, so the fixed 64-hex digest
     * rides the non-empty binding kinds.
     */
    private function demand(
        string $id,
        string $scope = 'checkout',
        ?string $sessionId = self::SESSION_ID,
        StepUpOperationBindingKind $kind = StepUpOperationBindingKind::None,
        ?string $principal = null,
    ): StepUpDemand {
        return StepUpDemand::mint(
            $id,
            $scope,
            StepUpChallenge::sessionHash($sessionId),
            null,
            'admission-gate-decision',
            self::BASE_NOW,
            900,
            $kind,
            $kind === StepUpOperationBindingKind::None ? '' : self::OPERATION_DIGEST,
            null,
            null,
            false,
            null,
            null,
            $principal,
        );
    }

    /**
     * The challenge fixture: an email-otp record (so it carries the
     * code hash its schema demands) bound to the named demand, session
     * and principal, with the factor snapshot its kind derives unless
     * the caller names a coherent one.
     */
    private function challenge(
        string $id,
        string $demandId,
        string $scope = 'checkout',
        ?string $sessionId = self::SESSION_ID,
        string $principal = self::PRINCIPAL,
        ?FactorRequirement $factor = null,
    ): StepUpChallenge {
        return StepUpChallenge::begin(
            $id,
            StepUpChallengeKind::EmailOtp,
            $principal,
            null,
            $scope,
            null,
            'post_solve_step_up_required',
            self::BASE_NOW,
            600,
            5,
            str_repeat('a', 64),
            null,
            $sessionId,
            false,
            false,
            null,
            $demandId,
            $factor,
        );
    }

    /**
     * The binding a completion must present for this record: the
     * session hash of a session-bound challenge, the stored
     * client-secret hash of a stateless one. A record carries exactly
     * one of the two by construction.
     */
    private function bindingOf(StepUpChallenge $challenge): string
    {
        return (string) ($challenge->sessionHash ?? $challenge->clientSecretHash);
    }

    /**
     * A copy of a valid challenge record with its factor snapshot
     * replaced. Both the begin and the strict decode derive or refuse
     * every snapshot the value class can express. A record carrying no
     * snapshot, or a requirement naming no family, can therefore only
     * exist as a shape a foreign or corrupt writer produced: exactly
     * what the gate's snapshot clause defends against. The copy is
     * built by reflection because the readonly properties admit one
     * initialization each.
     */
    private function forgedChallenge(StepUpChallenge $template, ?FactorRequirement $factor): StepUpChallenge
    {
        $forged = (new \ReflectionClass(StepUpChallenge::class))->newInstanceWithoutConstructor();
        foreach ((new \ReflectionClass(StepUpChallenge::class))->getProperties() as $property) {
            // Every other field is copied verbatim from the valid
            // record; the snapshot is the one property initialized by
            // the override below, never copied, since a readonly
            // property admits one initialization.
            if ($property->getName() !== 'factor' && $property->isInitialized($template)) {
                $property->setValue($forged, $property->getValue($template));
            }
        }
        (new \ReflectionProperty(StepUpChallenge::class, 'factor'))->setValue($forged, $factor);

        return $forged;
    }

    /**
     * A requirement whose fields the constructor would refuse: the
     * family outside the ladder, or the factor id outside its alphabet.
     * Only a foreign or corrupt writer produces this shape, and the
     * stores must treat it as no coherent snapshot at all.
     */
    private function forgedRequirement(string $family, string $factorId, int $rank): FactorRequirement
    {
        $forged = (new \ReflectionClass(FactorRequirement::class))->newInstanceWithoutConstructor();
        foreach (['family' => $family, 'factorId' => $factorId, 'assuranceRank' => $rank] as $field => $value) {
            (new \ReflectionProperty(FactorRequirement::class, $field))->setValue($forged, $value);
        }

        return $forged;
    }
}
