<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The demand finalizer of the step-up plane: the one service the whole
 * plane authorizes a completed factor through. There is exactly one
 * implementation, and every completion lane calls it. The validator
 * calls it when a redeemed grant resubmits the protected form, and the
 * login completion path calls it before any session restore. Nothing
 * else books a step-up completion. FactorVerified is never
 * AuthorizedStepUp: only this finalizer's authorized terminal creates
 * the generic enrollment bootstrap marker, restores the login, trusts
 * the device/network, writes StepUpCompleted, or validates the
 * protected operation.
 *
 * The sequence, in order and shared by every lane:
 *
 *  1. the operation binding check: when the demand carries the split
 *     financial/action binding, both digests must reproduce:
 *     operationIdentityDigest (HMAC of the server-owned unique logical
 *     operation id) and operationContentDigest (HMAC of the canonical
 *     amount/currency/recipient contents). The same logical operation
 *     with the same contents is idempotent; a different operation
 *     (even with identical contents) or changed contents is rejected.
 *     A step-up for tx-001 never authorizes tx-002.
 *  2. the recipe rerun: the demand record carries the operation digest
 *     minted with one canonical recipe, named by its
 *     {@see StepUpOperationBindingKind}. The finalizer recomputes the
 *     digest with that same recipe over the caller's material and
 *     refuses on any mismatch.
 *  3. the acquisition: the demand lifecycle claim moves the completed
 *     demand to finalizing atomically, so exactly one owner runs the
 *     reassessment (a stale claim is retaken after its window).
 *  4. the reassessment: a fresh engine decision under the
 *     completed-step-up event, on the same inputs the demand was
 *     raised in. Only a Deny refuses the completion; an absent engine
 *     (manual construction) or an absent decision authorizes the
 *     demand on the factor proof alone.
 *  5. the terminal compare-and-set: the demand settles authorized or
 *     denied, atomically, once. The authorized terminal is durable and
 *     retains the operation digests, the decision, the quarantine
 *     flag, the factor and the timestamp.
 *  6. the completion effects, authorized settlements only: the
 *     stepUpCompleted outcome credit ({@see StepUpCompletionCredit}),
 *     the pending-login restore ({@see SessionRestorer}) and the
 *     generic enrollment bootstrap marker. An authorized replay
 *     re-runs the effects idempotently.
 *
 * The finalizer is also the mint of the login plane's demand: a pending
 * token's begin() obtains its demand record here, under the login
 * binding kind and the principal recipe. The custom handler a login
 * flow selects therefore binds to a demand through the same mechanism
 * as every built-in factor.
 */
final class StepUpDemandFinalizer
{
    /** The claim window of one finalization owner. */
    private const CLAIM_SECS = 30;

    /** The enrollment bootstrap marker lifetime (the same 900 s the handlers used). */
    public const ENROLLMENT_MARKER_TTL_SECS = 900;

    public function __construct(
        private readonly StepUpChallengeStore $store,
        private readonly StepUpCompletionCredit $credit,
        private readonly ?SessionRestorer $sessionRestorer = null,
        private readonly ?RiskGateway $risk = null,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?ContinuityCookie $continuity = null,
        private readonly ?RequestStack $requestStack = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?\Closure $now = null,
        /**
         * The HMAC master of the split operation digests (identity and
         * content). Purpose-separated HKDF derivations of this master
         * key the two digests; the master itself is never used as a key.
         * A deployment that mints financial bindings MUST pass the same
         * master here and at mint, or the reproduce check refuses.
         */
        private readonly string $operationBindingMaster = '',
        /**
         * The factor requirement source. Null keeps the login demand
         * un-snapshotted (a deployment that mints without the resolver);
         * wired, every minted demand records the factor it requires,
         * escalated strictly past the family's completed factor.
         */
        private readonly ?StepUpFactorResolver $factorResolver = null,
    ) {
    }

    /**
     * Mint the login plane's demand for one raised step-up demand: the
     * record a pending token's begin binds its factor challenge to. The
     * digest is minted under the login recipe over the principal
     * pseudonym, so only the session that resolves the same principal
     * can ever finalize it. Null when the store refused the record; the
     * begin then answers no demandId and its proof finalizes nothing,
     * fail closed.
     *
     * $demandId is the exact demand identity the pending token was
     * wrapped under. When given, the record takes it as its own id: the
     * completed proof names the demand of exactly this login, and the
     * finalization can hold the restoring session to it. A standing
     * open record of that identity is answered as-is (a re-begin inside
     * one pending login). Anything else is refused.
     */
    public function mintLoginDemand(string $scope, string $principalPseudonym, ?string $sessionHash, int $ttlSecs, ?string $demandId = null): ?string
    {
        if ($demandId !== null && preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demandId) !== 1) {
            return null;
        }
        $demand = StepUpDemand::mint(
            $demandId ?? StepUpChallenge::mintId(),
            $scope,
            $sessionHash,
            null,
            null,
            $this->now(),
            $ttlSecs,
            StepUpOperationBindingKind::Login,
            StepUpOperationDigest::login($scope, $principalPseudonym),
            null,
            null,
            false,
            null,
            $this->requiredFactorOf($scope, $sessionHash),
        );
        try {
            $this->store->createDemand($demand, $ttlSecs);
        } catch (\Throwable) {
            // The identity collides with a standing record: the same
            // pending login re-beginning is served by its live open
            // demand, anything else refuses, fail closed.
            if ($demandId === null) {
                return null;
            }
            try {
                $standing = $this->store->readDemand($demandId);
            } catch (\Throwable) {
                return null;
            }
            if ($standing === null || $standing->expired($this->now()) || !$standing->state->isOpen() || $standing->superseded()) {
                return null;
            }

            return $standing->id;
        }

        return $demand->id;
    }

    /**
     * The factor requirement the mint snapshots onto its demand: the
     * resolver's answer for the scope, escalated strictly past the
     * factor the family's live completion marker records. A demand
     * minted after a completed weaker factor can therefore never be
     * answered with that same weaker factor again. Null when no
     * resolver is wired (the demand then carries no snapshot).
     */
    private function requiredFactorOf(string $scope, ?string $sessionHash): ?FactorRequirement
    {
        if ($this->factorResolver === null) {
            return null;
        }
        $completed = null;
        if ($sessionHash !== null && $sessionHash !== '') {
            try {
                $completed = $this->store->completedFactorOf($sessionHash, $scope, $this->now());
            } catch (\Throwable) {
                $completed = null;
            }
        }
        try {
            return $this->factorResolver->requiredFactor($scope, null, new StepUpFactorContext($completed));
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Mint a financial/action-bound demand: the split operation binding
     * of the protected operation. The identity digest is the HMAC of
     * the server-owned unique logical operation id (never a raw client
     * value alone); the content digest is the HMAC of the canonical
     * amount/currency/recipient contents. Null when the store refused
     * the record.
     *
     * @param array<string, string> $canonicalContentFields the named
     *                                                      contents
     *                                                      (amount,
     *                                                      currency,
     *                                                      recipient,
     *                                                      ...)
     */
    public function mintFinancialDemand(
        string $scope,
        string $serverOwnedOperationId,
        array $canonicalContentFields,
        ?string $sessionHash = null,
        ?string $chainId = null,
        ?string $decisionId = null,
        int $ttlSecs = 600,
        bool $quarantine = false,
    ): ?string {
        $binding = StepUpOperationDigest::financialBinding(
            $this->operationBindingMaster,
            $scope,
            $serverOwnedOperationId,
            StepUpOperationDigest::canonicalOperationContent($canonicalContentFields),
        );
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            $scope,
            $sessionHash,
            $chainId,
            $decisionId,
            $this->now(),
            $ttlSecs,
            StepUpOperationBindingKind::FormFields,
            $binding['identity'],
            $binding['identity'],
            $binding['content'],
            $quarantine,
        );
        try {
            return $this->store->createRootDemand($demand, $ttlSecs);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Finalize one completed factor for the login plane: the demand
     * named by the proof is completed by the caller (the atomic
     * factor+demand transition), reassessed, settled terminally and,
     * only when authorized, credited and restored.
     *
     * @param StepUpResult $proof the handler's verified factor proof
     */
    public function finalizeLogin(StepUpResult $proof, string $scope, ?Request $request = null): StepUpFinalization
    {
        if ($proof->demandId === null || $proof->principalPseudonym === null) {
            return StepUpFinalization::refusedUnbound();
        }
        $demand = $this->liveDemand($proof->demandId);
        if ($demand === null) {
            return StepUpFinalization::refusedAbsent();
        }
        $material = StepUpOperationMaterial::login($proof->principalPseudonym);
        $reassessed = $this->finalize($demand, $material, $proof->factor ?? 'unknown', $request);

        return $this->bookEffects($reassessed, $proof, $request);
    }

    /**
     * Finalize the demand a redeemed grant answers, for the form
     * resubmission lane: the validator calls this after the factor
     * consumed the grant, with the canonical operation fields of the
     * resubmitted form and the transaction binding it resolved. The
     * demand must already sit in the completed state the factor's
     * atomic completion left it in; the authorized answer is the
     * validator's acceptance.
     *
     * When the demand carries the split financial/action binding, the
     * caller must supply the same logical operation id and contents the
     * demand was minted for: a different operation or changed contents
     * is refused, so a step-up for tx-001 never authorizes tx-002.
     */
    public function finalizeGrant(
        string $demandId,
        StepUpOperationMaterial $material,
        ?Request $request = null,
        string $factor = 'email_ownership',
        ?string $operationId = null,
        ?string $canonicalContent = null,
    ): StepUpFinalization {
        $demand = $this->liveDemand($demandId);
        if ($demand === null) {
            return StepUpFinalization::refusedAbsent();
        }
        if (!$this->operationBindingMatches($demand, $operationId, $canonicalContent)) {
            $this->logger?->info('kiwi step-up demand finalization refused: the presented operation does not reproduce the bound authorization', [
                'demand' => $demand->id,
            ]);

            return StepUpFinalization::refusedDigest();
        }
        $finalized = $this->finalize($demand, $material, $factor, $request);

        return $this->bookAuthorizedEffects($finalized, $demand, $factor, $material->principalPseudonym, $request);
    }

    /**
     * Reproduce a durable authorized settlement for the same logical
     * operation and the same contents. The same op + contents answers
     * the existing authorization idempotently; a different op or
     * changed contents is rejected. Null when the demand is not an
     * authorized terminal or the binding does not reproduce.
     */
    public function reproduce(
        string $demandId,
        ?string $operationId,
        ?string $canonicalContent,
    ): ?StepUpDemand {
        $demand = $this->liveDemand($demandId);
        if ($demand === null || $demand->state !== StepUpDemandState::Authorized) {
            return null;
        }
        if (!$this->operationBindingMatches($demand, $operationId, $canonicalContent)) {
            return null;
        }

        return $demand;
    }

    /**
     * The shared sequence over one completed demand: the recipe rerun,
     * the acquisition, the reassessment, the terminal settlement. The
     * completion effects are booked by the lane (it owns the proof
     * payload); every lane books them through
     * {@see self::bookEffects()} and nothing else.
     */
    private function finalize(StepUpDemand $demand, StepUpOperationMaterial $material, string $factor, ?Request $request): StepUpFinalization
    {
        if ($demand->state !== StepUpDemandState::Completed) {
            // An authorized terminal replays its disposition
            // idempotently; a denied or superseded demand stays closed.
            if ($demand->state === StepUpDemandState::Authorized) {
                return StepUpFinalization::authorizedReplay($demand);
            }
            if ($demand->state === StepUpDemandState::Denied) {
                return StepUpFinalization::refusedDenied();
            }

            return StepUpFinalization::refusedState($demand->state);
        }
        // The recipe rerun, before any state move: the digest the stored
        // binding kind prescribes, computed over the caller's material.
        // A mismatch (or a material that cannot feed the recipe) refuses
        // the finalization without spending the claim. The split
        // financial/action binding already ran its own dual-digest
        // check (identity AND content), so the recipe rerun applies to
        // the unsplit bindings only.
        if ($demand->operationIdentityDigest === null) {
            $computed = StepUpOperationDigest::rerun($demand->scope, $demand->operationBindingKind, $material);
            if ($computed === null || !hash_equals($demand->operationDigest, $computed)) {
                $this->logger?->info('kiwi step-up demand finalization refused: the operation digest does not match the stored recipe', [
                    'kind' => $demand->operationBindingKind->value,
                ]);

                return StepUpFinalization::refusedDigest();
            }
        }
        // The acquisition: exactly one owner reassesses. A demand that
        // is already authorized replays its disposition (the effects are
        // re-run idempotently by the caller); a denied demand stays
        // denied.
        $claimed = $this->store->claimDemandFinalization($demand->id, $this->now(), self::CLAIM_SECS);
        if ($claimed === null) {
            $fresh = $this->liveDemand($demand->id);
            if ($fresh !== null && $fresh->state === StepUpDemandState::Authorized) {
                return StepUpFinalization::authorizedReplay($fresh);
            }
            if ($fresh !== null && $fresh->state === StepUpDemandState::Denied) {
                return StepUpFinalization::refusedDenied();
            }

            return StepUpFinalization::refusedState($fresh?->state ?? StepUpDemandState::Denied);
        }
        // The reassessment: a fresh engine answer under the
        // completed-step-up event, on the context the demand carried.
        // Only a Deny refuses; an unwired engine (manual construction)
        // authorizes on the factor proof alone.
        $decision = $this->reassess($demand, $material, $request);
        if ($decision !== null && $decision->action === \KiwiCaptcha\Risk\RiskAction::Deny) {
            $this->settle($demand->id, StepUpDemandState::Denied);
            $this->logger?->info('kiwi step-up demand finalization refused: the fresh assessment denied the completed factor');

            return StepUpFinalization::refusedDenied();
        }
        $this->settleAuthorized($demand->id, $factor);

        return StepUpFinalization::authorized($demand);
    }

    /**
     * The completion effects of an authorized settlement for the grant
     * lane: the outcome credit, the pending-login restore and the
     * generic enrollment bootstrap marker. Invoked only after
     * {@see self::finalize()} answered authorized, and re-invoked
     * idempotently for an authorized replay.
     */
    private function bookAuthorizedEffects(
        StepUpFinalization $finalization,
        StepUpDemand $demand,
        string $factor,
        ?string $principalPseudonym,
        ?Request $request,
    ): StepUpFinalization {
        if (!$finalization->authorized) {
            return $finalization;
        }
        if ($principalPseudonym === null || $principalPseudonym === '') {
            return $finalization;
        }
        $this->credit->report($demand->id, $principalPseudonym, null, false);
        $this->sessionRestorer?->restore($principalPseudonym, $request ?? $this->requestStack?->getCurrentRequest(), $demand->id);
        $this->writeEnrollmentMarker($principalPseudonym, $factor, $request);

        return $finalization;
    }

    /**
     * Whether the presented operation binding reproduces the demand's
     * split financial/action binding. An unbound demand (no digests)
     * matches only an unbound presentation; a bound demand requires
     * both digests to match: the same logical operation and the same
     * contents.
     */
    private function operationBindingMatches(StepUpDemand $demand, ?string $operationId, ?string $canonicalContent): bool
    {
        if ($demand->operationIdentityDigest === null && $demand->operationContentDigest === null) {
            return $operationId === null && $canonicalContent === null;
        }
        if ($operationId === null || $canonicalContent === null) {
            return false;
        }
        $computed = StepUpOperationDigest::financialBinding(
            $this->operationBindingMaster,
            $demand->scope,
            $operationId,
            $canonicalContent,
        );

        return hash_equals((string) $demand->operationIdentityDigest, $computed['identity'])
            && hash_equals((string) $demand->operationContentDigest, $computed['content']);
    }

    /**
     * The completion effects of an authorized settlement: the outcome
     * credit, the pending-login restore and the generic enrollment
     * bootstrap marker. Invoked by the lane only after
     * {@see self::finalize()} answered authorized, and re-invoked
     * idempotently for an authorized replay. The credit's idempotency
     * keys make a re-run a no-op, the restore unwraps a pending token
     * exactly once, and the marker rewrite is a timestamp refresh.
     */
    public function bookEffects(StepUpFinalization $finalization, StepUpResult $proof, ?Request $request = null): StepUpFinalization
    {
        if (!$finalization->authorized) {
            return $finalization;
        }
        if ($proof->principalPseudonym !== null) {
            $this->credit->report(
                $proof->challengeId ?? '',
                $proof->principalPseudonym,
                $proof->targetPseudonym,
                $proof->targetOwned,
            );
            $this->sessionRestorer?->restore($proof->principalPseudonym, $request ?? $this->requestStack?->getCurrentRequest(), $proof->demandId);
            $this->writeEnrollmentMarker($proof->principalPseudonym, $proof->factor ?? 'unknown', $request);
        }

        return $finalization;
    }

    /**
     * The generic enrollment bootstrap marker: created only by the
     * authorized terminal, never by a FactorVerified proof.
     */
    private function writeEnrollmentMarker(string $principalPseudonym, string $factor, ?Request $request): void
    {
        $now = $this->now();
        $effectiveRequest = $request ?? $this->requestStack?->getCurrentRequest();
        try {
            $this->store->markStepUpSuccess($principalPseudonym, self::ENROLLMENT_MARKER_TTL_SECS, $now);
            $this->store->markSessionStepUpSuccess(
                $effectiveRequest !== null ? (string) StepUpSessionBinding::sessionId($effectiveRequest) : '',
                $principalPseudonym,
                $factor,
                self::ENROLLMENT_MARKER_TTL_SECS,
                $now,
            );
        } catch (\Throwable $e) {
            $this->logger?->warning('kiwi step-up enrollment marker failed: {message}', [
                'message' => $e->getMessage(),
            ]);
        }
    }

    /** The fresh engine decision of the completed factor, null when it cannot evaluate. */
    private function reassess(StepUpDemand $demand, StepUpOperationMaterial $material, ?Request $request): ?\KiwiCaptcha\Risk\RiskDecision
    {
        if ($this->risk === null) {
            return null;
        }
        $ip = '';
        if ($request !== null) {
            try {
                $ip = $this->clientIpResolver !== null
                    ? $this->clientIpResolver->resolve($request)
                    : (string) ($request->getClientIp() ?? '');
            } catch (AmbiguousForwardingException) {
                $ip = '';
            }
        }
        $session = $request !== null ? $this->continuity?->read($request) : null;
        try {
            return $this->risk->stepUpCompletedDecision(
                $demand->scope,
                $ip,
                $session,
                $material->principalPseudonym,
                'stepup-demand:'.$demand->id,
                $material->targetFields,
            );
        } catch (\InvalidArgumentException) {
            return $this->risk->degradedDecisionForScope($this->risk->scopeId($demand->scope));
        }
    }

    /** The terminal settlement; a store failure surfaces to the caller, fail closed. */
    private function settle(string $demandId, StepUpDemandState $state, ?string $factor = null): void
    {
        $settled = $this->store->settleDemandFinalization($demandId, $state, $this->now(), $factor);
        if ($settled === null) {
            throw new \RuntimeException('The step-up demand finalization could not settle its terminal state');
        }
    }

    /** The authorized terminal settlement, retaining the completed factor. */
    private function settleAuthorized(string $demandId, string $factor): void
    {
        $this->settle($demandId, StepUpDemandState::Authorized, $factor);
    }

    /** The live demand of an id: present and unexpired, else null. */
    private function liveDemand(string $demandId): ?StepUpDemand
    {
        try {
            $demand = $this->store->readDemand($demandId);
        } catch (\Throwable) {
            return null;
        }
        if ($demand === null || $demand->expired($this->now())) {
            return null;
        }

        return $demand;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }
}
