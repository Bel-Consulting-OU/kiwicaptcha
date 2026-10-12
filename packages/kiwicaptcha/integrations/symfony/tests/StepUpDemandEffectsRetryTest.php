<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\SessionRestorer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpEffectsJournal;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionRestore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The effects journal of the durable authorized settlement: the crash
 * boundary of the completion lifecycle. The challenge is spent and the
 * demand is terminal authorized before the outcome credit, the session
 * restore and the trust marker book. A failure there is recovered by
 * the demand-bound effects retry on the same completion endpoint,
 * without a second factor. The journal rides the demand record itself;
 * landed effects skip, missing effects run once and journal on
 * success, and a restore refusal never completes the journal.
 */
final class StepUpDemandEffectsRetryTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';

    private const SCOPE = 'login';

    private const RAW_USER = 'alice@example.com';

    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private SpyOutcomeReporter $reporter;

    private RiskIdentityFactory $identity;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->reporter = new SpyOutcomeReporter();
        $this->identity = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x2a", 32)));
    }

    /** The canonical principal pseudonym of the test identity. */
    private function principal(): string
    {
        return $this->identity->principalId(self::RAW_USER);
    }

    private function finalizer(?SessionRestorer $restorer = null): StepUpDemandFinalizer
    {
        return new StepUpDemandFinalizer(
            $this->store,
            new StepUpCompletionCredit($this->reporter, self::MASTER),
            $restorer,
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
     * A login demand carried to its authorized terminal with every
     * effect landing: the journal is complete, rides the demand record
     * through the wire round trip, and a re-run of the effects (an
     * authorized replay) books nothing twice.
     */
    public function testTheCompleteJournalRidesTheDurableAuthorization(): void
    {
        $finalizer = $this->finalizer();
        $principal = $this->principal();
        $demandId = $finalizer->mintLoginDemand(self::SCOPE, $principal, null, 900);
        self::assertNotNull($demandId);
        $this->completeFactor($demandId);

        $finalization = $finalizer->finalizeLogin($this->proof($demandId, $principal), self::SCOPE);
        self::assertTrue($finalization->authorized);
        self::assertNotNull($finalization->effects);
        self::assertTrue($finalization->effects->complete(), 'every effect journals on success');
        self::assertCount(1, $this->reporter->reports, 'the outcome credit booked exactly once');
        self::assertTrue($this->store->recentStepUpSuccess($principal, 900, $this->now), 'the trust marker landed');

        $stored = $this->store->readDemand($demandId);
        self::assertNotNull($stored);
        self::assertNotNull($stored->effects);
        self::assertTrue($stored->effects->complete(), 'the journal rides the demand record');

        $encoded = (string) json_encode($stored->toArray(), JSON_UNESCAPED_SLASHES);
        $decoded = StepUpDemand::fromJson($encoded);
        self::assertNotNull($decoded);
        self::assertNotNull($decoded->effects);
        self::assertTrue($decoded->effects->complete(), 'the wire round trip preserves the journal');

        // The authorized replay books nothing twice: every journal
        // entry skips its effect.
        $replay = $finalizer->finalizeLogin($this->proof($demandId, $principal), self::SCOPE);
        self::assertTrue($replay->authorized);
        self::assertTrue($replay->effectsComplete());
        self::assertCount(1, $this->reporter->reports, 'the replay never double-books the credit');
    }

    /**
     * The crash-boundary retry: the outcome reporter fails after the
     * authorization, the demand is terminal authorized with an
     * incomplete journal, and the retry on the same demand (the same
     * endpoint, the same session) completes the missing credit without
     * another factor. The credit runs before the restore, so the
     * pending token survives the crashed attempt and the retry can
     * still restore the session.
     */
    public function testAnOutcomeFailureAfterAuthorizationRetriesWithoutAnotherFactor(): void
    {
        $session = $this->pendingSession();
        $finalizer = $this->finalizer($session->restorer);
        $principal = $this->principal();
        $demandId = $finalizer->mintLoginDemand(self::SCOPE, $principal, null, 900);
        self::assertNotNull($demandId);
        $session->bindDemand($demandId);
        $this->completeFactor($demandId);

        $this->reporter->throwOnReport = new \RuntimeException('outcome backend unavailable');
        $crashed = $finalizer->finalizeLogin($this->proof($demandId, $principal), self::SCOPE);
        self::assertTrue($crashed->authorized, 'the factor proof still settles the authorization');
        self::assertFalse($crashed->effectsComplete(), 'the failed credit leaves the journal incomplete');
        self::assertNotNull($crashed->effects);
        self::assertTrue($crashed->effects->settled());
        self::assertFalse($crashed->effects->outcomeCredited());
        self::assertFalse($crashed->effects->sessionRestored(), 'the restore never ran past the failed credit');
        self::assertCount(0, $this->reporter->reports);
        self::assertInstanceOf(StepUpPendingToken::class, $session->tokenStorage->getToken(), 'the session is still pending');
        self::assertFalse($this->store->recentStepUpSuccess($principal, 900, $this->now), 'the trust marker never landed');

        // The retry: the same endpoint, the same demand, the same
        // principal, no second factor.
        $this->reporter->throwOnReport = null;
        $this->now += 5;
        $retried = $finalizer->retryAuthorizedEffects($demandId, $principal);
        self::assertNotNull($retried, 'the authorized demand accepts the effects retry');
        self::assertTrue($retried->authorized);
        self::assertTrue($retried->effectsComplete(), 'the retry completes every missing effect');
        self::assertCount(1, $this->reporter->reports, 'the credit lands exactly once');
        self::assertTrue($this->store->recentStepUpSuccess($principal, 900, $this->now), 'the trust marker lands on the retry');
        self::assertNotInstanceOf(StepUpPendingToken::class, $session->tokenStorage->getToken(), 'the session restored on the retry');

        // A second retry is a no-op: every journal entry skips.
        $again = $finalizer->retryAuthorizedEffects($demandId, $principal);
        self::assertNotNull($again);
        self::assertTrue($again->effectsComplete());
        self::assertCount(1, $this->reporter->reports, 'the journal makes the retry idempotent');
    }

    /**
     * The retry is demand-bound and fail closed: another principal's
     * pending session reproduces nothing, an open demand retries
     * nothing, an unknown demand answers null.
     */
    public function testTheRetryRefusesAnotherPrincipalAndANonAuthorizedDemand(): void
    {
        $finalizer = $this->finalizer();
        $principal = $this->principal();
        $demandId = $finalizer->mintLoginDemand(self::SCOPE, $principal, null, 900);
        self::assertNotNull($demandId);
        $this->completeFactor($demandId);

        // Still open (finalization never ran): no authorized terminal,
        // no retry surface.
        self::assertNull($finalizer->retryAuthorizedEffects($demandId, $principal));

        $this->now += 1;
        $finalizer->finalizeLogin($this->proof($demandId, $principal), self::SCOPE);
        self::assertNotNull($finalizer->retryAuthorizedEffects($demandId, $principal), 'the demand accepts its own principal');
        self::assertNull($finalizer->retryAuthorizedEffects($demandId, str_repeat('f', 32)), 'another principal reproduces nothing');
        self::assertNull($finalizer->retryAuthorizedEffects('nonexistent-demand-000001', $principal), 'an unknown demand answers null');
    }

    /**
     * A refused restore journals nothing and leaves the journal
     * incomplete: the answer must never become user-visible success.
     * The matched session then retries and lands the restore.
     */
    public function testARestoreRefusalNeverCompletesTheJournal(): void
    {
        $session = $this->pendingSession(StepUpPendingToken::mintDemandId());
        $finalizer = $this->finalizer($session->restorer);
        $principal = $this->principal();
        $demandId = $finalizer->mintLoginDemand(self::SCOPE, $principal, null, 900);
        self::assertNotNull($demandId);
        $this->completeFactor($demandId);

        $refused = $finalizer->finalizeLogin($this->proof($demandId, $principal), self::SCOPE);
        self::assertTrue($refused->authorized);
        self::assertFalse($refused->effectsComplete(), 'a refused restore is an incomplete journal');
        self::assertNotNull($refused->effects);
        self::assertTrue($refused->effects->outcomeCredited());
        self::assertFalse($refused->effects->sessionRestored());
        self::assertInstanceOf(StepUpPendingToken::class, $session->tokenStorage->getToken(), 'the mismatched session never opened');

        // The session re-binds to the demand the proof finalized (the
        // exact same pending login) and the retry lands the restore.
        $session->bindDemand($demandId);
        $retried = $finalizer->retryAuthorizedEffects($demandId, $principal);
        self::assertNotNull($retried);
        self::assertTrue($retried->effectsComplete(), 'the matched session restores on the retry');
        self::assertNotInstanceOf(StepUpPendingToken::class, $session->tokenStorage->getToken());
    }

    /**
     * The store journal write guards: only the authorized terminal
     * journals, only the known effect vocabulary journals, and the
     * journal decode refuses a wrong shape instead of impersonating
     * completed effects.
     */
    public function testTheStoreJournalWriteGuardsTheTerminalAndTheVocabulary(): void
    {
        $finalizer = $this->finalizer();
        $principal = $this->principal();
        $demandId = $finalizer->mintLoginDemand(self::SCOPE, $principal, null, 900);
        self::assertNotNull($demandId);
        self::assertNull($this->store->recordDemandEffect($demandId, StepUpEffectsJournal::SETTLED, $this->now), 'an open demand journals nothing');
        $this->completeFactor($demandId);
        self::assertNull($this->store->recordDemandEffect($demandId, StepUpEffectsJournal::SETTLED, $this->now), 'a completed demand journals nothing');

        $this->now += 1;
        $finalization = $finalizer->finalizeLogin($this->proof($demandId, $principal), self::SCOPE);
        self::assertTrue($finalization->authorized);
        self::assertNull($this->store->recordDemandEffect($demandId, 'side_effect', $this->now), 'an unknown effect journals nothing');

        $recorded = $this->store->recordDemandEffect($demandId, StepUpEffectsJournal::TRUST_WRITTEN, $this->now);
        self::assertNotNull($recorded);
        self::assertNotNull($recorded->effects);
        self::assertTrue($recorded->effects->trustWritten());

        // A corrupt fx value refuses the whole record, fail closed.
        $decoded = json_decode((string) json_encode($recorded->toArray(), JSON_UNESCAPED_SLASHES), true);
        $decoded['fx']['mystery'] = 1;
        self::assertNull(StepUpDemand::fromJson((string) json_encode($decoded)), 'a corrupt journal decodes as no record');
    }

    /**
     * The typed restore answer: a landed restore and a refused one are
     * distinguishable, so the caller can journal the first and answer
     * no success for the second.
     */
    public function testTheRestoreAnswerIsTyped(): void
    {
        $session = $this->pendingSession();
        $restore = $session->restorer->restore($this->principal(), null, $session->pending->demandId());
        self::assertInstanceOf(StepUpSessionRestore::class, $restore);
        self::assertTrue($restore->landed());
        self::assertSame(StepUpSessionRestore::RESTORED, $restore->status);

        $mismatch = $this->pendingSession();
        $refused = $mismatch->restorer->restore(str_repeat('f', 32), null, $mismatch->pending->demandId());
        self::assertFalse($refused->landed());
        self::assertSame(StepUpSessionRestore::REFUSED_PRINCIPAL_MISMATCH, $refused->status);

        $plain = $this->authenticatedSession();
        $nothing = $plain->restore($this->principal(), null, StepUpPendingToken::mintDemandId());
        self::assertTrue($nothing->landed(), 'a session with no pending token trivially lands');
        self::assertSame(StepUpSessionRestore::NOTHING_PENDING, $nothing->status);
    }

    // ── helpers ─────────────────────────────────────────────────────

    private function proof(string $demandId, string $principal): StepUpResult
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::Totp,
            $principal,
            null,
            self::SCOPE,
            null,
            'post_solve_step_up_required',
            $this->now,
            300,
            5,
            null,
            null,
            null,
            false,
            false,
            null,
            $demandId,
        );

        return StepUpResult::proved($challenge, StepUpFactorAssurance::totp());
    }

    /** Move the demand open -> completed (the factor+demand completion). */
    private function completeFactor(string $demandId): void
    {
        $completed = $this->store->completeDemand($demandId, $this->now, 900);
        self::assertNotNull($completed);
        self::assertSame(StepUpDemandState::Completed, $completed->state);
    }

    /**
     * A pending session with a restorer wired, ready to have its exact
     * demand identity bound to the demand under test.
     */
    private function pendingSession(?string $demandId = null): PendingSession
    {
        $wrapped = new UsernamePasswordToken(new InMemoryUser(self::RAW_USER, null, ['ROLE_USER']), 'main');
        $tokenStorage = new TokenStorage();
        $pending = new StepUpPendingToken($wrapped, $demandId);
        $tokenStorage->setToken($pending);
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            identityFactory: $this->identity,
        );

        return new PendingSession($restorer, $tokenStorage, $pending);
    }

    private function authenticatedSession(): SessionRestorer
    {
        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser(self::RAW_USER, null, ['ROLE_USER']), 'main'));

        return new SessionRestorer(
            tokenStorage: $tokenStorage,
            identityFactory: $this->identity,
        );
    }
}

/**
 * The pending session fixture of the retry tests: the restorer, the
 * token storage it unwraps through and the pending token itself.
 */
final class PendingSession
{
    public function __construct(
        public readonly SessionRestorer $restorer,
        public readonly TokenStorage $tokenStorage,
        public readonly StepUpPendingToken $pending,
    ) {
    }

    /** Bind the pending session to the demand the proof finalized. */
    public function bindDemand(string $demandId): void
    {
        $this->pending->setAttribute(StepUpPendingToken::DEMAND_ID_ATTRIBUTE, $demandId);
    }
}
