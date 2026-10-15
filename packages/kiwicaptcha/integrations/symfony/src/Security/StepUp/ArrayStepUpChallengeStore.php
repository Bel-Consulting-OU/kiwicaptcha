<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * In-memory step-up store for test and dev semantics: single-process
 * only. The production wiring of the step-up plane always sits on the
 * Redis store (risk.enabled requires a risk Redis client), so this
 * implementation exists for unit tests and offline kernels.
 *
 * Mirrors the Redis store exactly, with an explicit clock: expiry is
 * evaluated on read, consume is a read-and-remove, and the attempt
 * accounting answers the same contract. Every record round-trips
 * through the strict wire decode, so this store observes the identical
 * schema the Redis store persists.
 */
final class ArrayStepUpChallengeStore implements StepUpChallengeStore
{
    /** @var array<string, array{record: StepUpChallenge, expiresAt: int}> */
    private array $challenges = [];

    /** @var array<string, int> */
    private array $beginWindows = [];

    /** @var array<string, string> */
    private array $totpSecrets = [];

    /** @var array<string, int> */
    private array $totpSteps = [];

    /** @var array<string, array{at: int, expires: int}> principal -> completion marker */
    private array $stepUpSuccess = [];

    /** @var array<string, int> "<dimension>:<pseudonym>" -> failure count */
    private array $lockoutFailures = [];

    /** @var array<string, int> "<dimension>:<pseudonym>" -> lockout deadline (epoch secs) */
    private array $lockoutUntil = [];

    public function __construct(
        private readonly ?\Closure $now = null,
    ) {
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        // A demand-bound challenge may only enter the store through
        // admission, which proves it belongs to the demand and makes it
        // the demand's one active challenge. A plain create of a
        // challenge bound to an open demand would bypass that proof: it
        // could never become the active challenge, and a custom handler
        // reaching for it would strand the flow. The single legitimate
        // demand-bound record that is not admitted is the email
        // ownership grant, which names an already-settled demand; that
        // shape stays allowed.
        if ($challenge->demandId !== null) {
            $boundDemand = $this->liveDemand($challenge->demandId);
            if ($boundDemand === null || $boundDemand->state->isOpen()) {
                throw new \RuntimeException('A demand-bound challenge enters the store through createAdmittedChallenge, never a plain create');
            }
        }
        return $this->storeRecord($challenge, $ttlSecs);
    }

    /**
     * The raw record write, shared by the two doors: `create()` after
     * its gate, `createAdmittedChallenge()` after admission proved the
     * challenge belongs to its demand. Nothing else writes a challenge.
     */
    private function storeRecord(StepUpChallenge $challenge, int $ttlSecs): string
    {
        $this->challenges[$challenge->id] = [
            'record' => StepUpChallenge::fromJson((string) json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES)),
            'expiresAt' => ($this->now()) + max(1, $ttlSecs),
        ];

        return $challenge->id;
    }

    public function createAdmittedChallenge(StepUpChallenge $challenge, int $ttlSecs): string
    {
        if ($challenge->demandId === null) {
            // The demandless ceremonies (enrollment creation, the drain
            // shapes) store like any other: they authorize nothing and
            // admit through no demand.
            return $this->create($challenge, $ttlSecs);
        }
        $demand = $this->liveDemand($challenge->demandId);
        if ($demand === null || !$demand->state->isOpen() || $demand->superseded()) {
            throw new StepUpDemandAdmissionRefused('the demand is absent, not open, or superseded');
        }
        $now = $this->now();
        if ($demand->expired($now)) {
            throw new StepUpDemandAdmissionRefused('the demand has expired');
        }
        // The admission identity gate, and it runs ahead of the replace
        // below touches anything: a newcomer that does not belong to
        // this demand must leave the standing active challenge exactly
        // as it found it. Admission used to judge only the demand's
        // liveness, so a crossed or buggy challenge could evict a
        // perfectly good active challenge and be refused only at
        // completion, stranding the browser. These are the same identity
        // rules the completion enforces, applied at the door: the
        // challenge answers this demand's scope, a session-bound demand
        // admits only a challenge of that same session, a login demand
        // admits only a challenge of the principal the demand was minted
        // for, and the factor snapshot the completion judges must be
        // present and coherent. The demand id itself needs no check
        // here: the record above was read by it.
        $snapshot = $challenge->factor;
        if ($challenge->scope !== $demand->scope
            || ($demand->sessionHash !== null && $demand->sessionHash !== ''
                && $challenge->sessionHash !== $demand->sessionHash)
            || ($demand->operationBindingKind === StepUpOperationBindingKind::Login
                && $demand->principalPseudonym !== null && $demand->principalPseudonym !== ''
                && $challenge->principalSubject() !== $demand->principalPseudonym)
            || $snapshot === null || $snapshot->family === '' || $snapshot->factorId === '') {
            throw new StepUpDemandAdmissionRefused('the challenge does not belong to the demand it claims');
        }
        // A newcomer that is already dead must not take the slot either.
        // Admission that judged only the demand's liveness would admit a
        // record whose own window has closed (a skewed or replayed begin
        // mints one), evict the standing challenge for it, and hand the
        // demand an active challenge nothing can ever complete: the
        // browser would be stranded with a valid code and no door. The
        // record is refused the way the store refuses an expired demand,
        // and the standing challenge stays exactly where it was.
        if ($challenge->expiresAt <= $now) {
            throw new StepUpDemandAdmissionRefused('the challenge arrived with its own window already closed');
        }
        // The admitted challenge never outlives its demand, and the
        // clamp stays in the mint-lane clock domain (the challenge's own
        // created_at plus its TTL, against the demand's authorization
        // deadline): a resend late in the window issues a shorter-lived
        // code, never a refusal, and no store-clock value ever feeds the
        // record's own expiry. The store TTL budget is separate.
        $challengeExpiresAt = min($challenge->createdAt + max(1, $ttlSecs), $demand->expiresAt);
        $challenge = $challenge->withClampedExpiry($challengeExpiresAt);
        // The replace semantics: the new begin supersedes any prior live
        // challenge of the same demand — its record is consumed here, in
        // the same all-or-nothing move that stamps the new one, so at
        // most one live challenge per demand holds at any instant and a
        // late completion of the old code can never answer. A refused
        // admission (unreachable in the single-process store after the
        // guards above, but kept for the contract) restores the replaced
        // challenge; nothing new is stored.
        $activeId = $demand->activeChallengeId;
        $activeUntil = $demand->activeChallengeExpiresAt ?? 0;
        $replaced = $activeId !== null && $activeUntil > $now ? $this->challenges[$activeId] ?? null : null;
        if ($replaced !== null) {
            unset($this->challenges[$activeId]);
        }
        $id = $this->storeRecord($challenge, max(1, $challengeExpiresAt - $now));
        $admitted = $demand->admitFactorChallenge($id, $challengeExpiresAt, $now);
        if ($admitted === null) {
            unset($this->challenges[$id]);
            if ($replaced !== null) {
                $this->challenges[$activeId] = $replaced;
            }
            throw new StepUpDemandAdmissionRefused('the demand refused the challenge admission');
        }
        $this->demands[$demand->id] = ['record' => $admitted, 'expiresAt' => $demand->expiresAt];

        return $id;
    }

    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->live($challengeId);
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        $record = $this->live($challengeId);
        if ($record !== null) {
            unset($this->challenges[$challengeId]);
        }

        return $record;
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        $record = $this->live($challengeId);
        if ($record === null) {
            return -1;
        }
        $attempts = $record->attempts + 1;
        if ($attempts >= max(1, $maxAttempts)) {
            unset($this->challenges[$challengeId]);

            return 0;
        }
        $this->challenges[$challengeId]['record'] = $record->withAttempts($attempts);

        return $attempts;
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        $this->beginWindows[$principalPseudonym] = ($this->beginWindows[$principalPseudonym] ?? 0) + 1;

        return $this->beginWindows[$principalPseudonym];
    }

    /** @var array<string, array{record: StepUpDemand, expiresAt: int}> */
    private array $demands = [];

    public function createDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        if (isset($this->demands[$demand->id])) {
            throw new \RuntimeException('The step-up demand record could not be persisted (id collision)');
        }
        $this->demands[$demand->id] = [
            'record' => StepUpDemand::fromJson((string) json_encode($demand->toArray(), JSON_UNESCAPED_SLASHES))
                ?? throw new \RuntimeException('The step-up demand record could not be persisted (undecodable shape)'),
            'expiresAt' => ($this->now()) + max(1, $ttlSecs),
        ];

        return $demand->id;
    }

    public function readDemand(string $demandId): ?StepUpDemand
    {
        return $this->liveDemand($demandId);
    }

    public function consumeDemand(string $demandId): ?StepUpDemand
    {
        $demand = $this->liveDemand($demandId);
        if ($demand !== null) {
            unset($this->demands[$demandId]);
        }

        return $demand;
    }

    public function completeDemand(string $demandId, int $now, int $ttlSecs): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        if (!$entry['record']->state->isOpen() || $entry['record']->superseded()) {
            return null;
        }
        $completed = $entry['record']->withState(StepUpDemandState::Completed, $now);
        $this->demands[$demandId] = [
            'record' => $completed,
            'expiresAt' => $now + max(1, $ttlSecs),
        ];

        return $completed;
    }

    public function completeFactor(string $challengeId, string $demandId, string $presentedBindingHash, int $now, ?string $sessionHash = null, ?string $scope = null, ?string $lineageHash = null): ?StepUpFactorCompletion
    {
        // The same gate order the Redis script runs: presence, decode
        // (the records round-trip through the strict wire decode at
        // write time here), identity, state, liveness, binding, factor
        // requirement.
        $challenge = $this->live($challengeId);
        if ($challenge === null) {
            return null;
        }
        $demand = $this->liveDemand($demandId);
        if ($demand === null) {
            return null;
        }
        if ($challenge->demandId !== $demandId || $demand->id !== $demandId) {
            return null;
        }
        // The demand/challenge identity binding, judged on the stored
        // records alone: a challenge answers exactly its own demand's
        // scope, a session-bound demand is completed only by a challenge
        // of that same session, and a login demand is completed only by
        // a challenge of the principal the demand was minted for (the
        // identity-factory pseudonym both records carry). A crossed
        // session, scope or subject completes nothing — the presented
        // binding may match the challenge perfectly and the completion
        // still refuses, because the proof earned belongs to another
        // browser, scope or account than the demand names.
        if ($challenge->scope !== $demand->scope) {
            return null;
        }
        if ($demand->sessionHash !== null && $challenge->sessionHash !== $demand->sessionHash) {
            return null;
        }
        if ($demand->operationBindingKind === StepUpOperationBindingKind::Login
            && $demand->principalPseudonym !== null
            && $challenge->principalSubject() !== $demand->principalPseudonym) {
            return null;
        }
        // A superseded demand completes nothing, whatever its state
        // field still says: escalation replaced it with a stronger
        // child. Same gate the Redis script runs.
        if (!$demand->state->isOpen() || $demand->superseded()) {
            return null;
        }
        if ($challenge->expired($now) || $demand->expired($now)) {
            return null;
        }
        $bound = ($challenge->sessionHash !== null && $challenge->sessionHash === $presentedBindingHash)
            || ($challenge->clientSecretHash !== null && $challenge->clientSecretHash === $presentedBindingHash);
        if (!$bound) {
            return null;
        }
        // The active-challenge authority, the same gate the Redis script
        // runs: the demand's own `active_challenge_id` names the one
        // challenge that may complete it. A demand-bound challenge that
        // never became the demand's active challenge, or one the
        // replace semantics already superseded, completes nothing.
        if ($demand->activeChallengeId === null || $demand->activeChallengeId !== $challengeId) {
            return null;
        }
        // The factor requirement gate, the script's own rule: the
        // demand's stored requirement is judged against the factor
        // identity the stored challenge record carries (its server-held
        // snapshot, resolved at begin), never a caller argument. A
        // completion below the required assurance rank refuses, and so
        // does a factor neither the snapshot's family nor its exact id
        // answers at or below that rank. A strictly stronger completion
        // satisfies a weaker floor, the ladder is a floor. Nothing
        // moves on a refusal.
        $required = $demand->requiredFactor;
        $snapshot = $challenge->factor;
        if ($required !== null) {
            if ($snapshot === null || $snapshot->assuranceRank < $required->assuranceRank) {
                return null;
            }
            if ($snapshot->family !== $required->factorId
                && $snapshot->factorId !== $required->factorId
                && $snapshot->assuranceRank <= $required->assuranceRank) {
                return null;
            }
        }
        // The transition: consume the challenge, complete the demand,
        // record the escalation marker, all or nothing. The marker
        // stores the factor identity the record itself carries, never a
        // caller argument: a completion cannot poison the future
        // assurance escalation by claiming a stronger factor than its
        // challenge proves. The marker is keyed per (session, scope)
        // pair, the same derivation the Redis script uses, and the
        // write requires both hints to equal the record's own fields,
        // so one scope's history can never overwrite another's.
        unset($this->challenges[$challengeId]);
        $completed = $demand->withState(StepUpDemandState::Completed, $now);
        $this->demands[$demandId] = ['record' => $completed, 'expiresAt' => $demand->expiresAt];
        // The marker's factor identity: the stored snapshot when the
        // record carries one, the kind's own ladder rung otherwise (the
        // same fallback the Redis script's kind tables perform, so the
        // dev/test lane records the marker a production replay reads).
        $family = $snapshot?->family
            ?? match ($challenge->kind) {
                StepUpChallengeKind::EmailOtp, StepUpChallengeKind::EmailOwnership => 'email_otp',
                StepUpChallengeKind::Totp => 'totp',
                StepUpChallengeKind::WebAuthn => 'webauthn',
            };
        // The history write. Its identity is (lineage, principal, scope),
        // never the bare PHP session: the lineage survives the session-id
        // rotation a successful login performs, so the factor a browser
        // already proved is still visible to its next demand, and folding
        // the principal in stops one account's completion from becoming
        // another account's history when a session switches identity.
        // Every hint is checked against the stored record, so a caller
        // can never file a completion under another subject's key.
        if ($lineageHash !== null && preg_match('/^[0-9a-f]{64}$/D', $lineageHash) === 1
            && $scope !== null && $challenge->scope === $scope
            && \is_string($family) && $family !== '') {
            $rank = FactorRequirement::rankOf($family);
            $key = $this->completedIndexKey($lineageHash, $demand->principalPseudonym, $scope);
            $prior = $this->completedIndex[$key] ?? null;
            $priorRank = 0;
            $priorExpiry = 0;
            if ($prior !== null) {
                $priorParts = explode('|', (string) $prior['value']);
                // A legacy entry (before the rank and the completion
                // stamp rode the value) reads as rank 0 with no recorded
                // expiry: any ladder completion moves it forward.
                $priorRank = \count($priorParts) >= 4 ? (int) $priorParts[2] : 0;
                $priorExpiry = \count($priorParts) >= 4 ? (int) $priorParts[3] : 0;
            }
            // The monotonic rule, stated once: a strictly stronger
            // completion replaces the entry. An equal-rank completion
            // keeps the later authorization window, so a same-rank
            // demand completing late can never shorten the history it
            // shares. A weaker completion writes nothing at all.
            if ($rank > $priorRank) {
                $window = $demand->expiresAt;
            } elseif ($rank === $priorRank && $priorRank > 0) {
                $window = max($priorExpiry, $demand->expiresAt);
            } else {
                return StepUpFactorCompletion::fromRecords($challenge, $completed);
            }
            $this->completedIndex[$key] = [
                'value' => $challenge->scope.'|'.$family.'|'.$rank.'|'.$window.'|'.$now,
                'expiresAt' => $window,
            ];
        }

        return StepUpFactorCompletion::fromRecords($challenge, $completed);
    }

    /** @var array<string, array{value: string, expiresAt: int}> (session hash, scope) key -> escalation marker */
    private array $completedIndex = [];

    public function completedFactorOf(string $lineageHash, ?string $principalPseudonym, string $scope, int $now): ?string
    {
        if (preg_match('/^[0-9a-f]{64}$/D', $lineageHash) !== 1) {
            return null;
        }
        $key = $this->completedIndexKey($lineageHash, $principalPseudonym, $scope);
        $entry = $this->completedIndex[$key] ?? null;
        if ($entry === null || $now >= $entry['expiresAt']) {
            unset($this->completedIndex[$key]);

            return null;
        }
        $parts = explode('|', $entry['value']);
        // The rank and the completion stamp ride the value
        // (scope|family|rank|window|completed); a legacy three- or
        // four-part entry predating the stamp stays readable for its
        // own TTL.
        if (\count($parts) !== 5 && \count($parts) !== 4 && \count($parts) !== 3) {
            return null;
        }
        if ($parts[0] !== $scope || !\is_string($parts[1])) {
            return null;
        }
        if (\count($parts) >= 4 && preg_match('/^[0-9]+$/', $parts[2]) !== 1) {
            return null;
        }

        return FactorRequirement::isFamily($parts[1]) ? $parts[1] : null;
    }

    /**
     * The escalation marker key of one (lineage, principal, scope)
     * identity: the same derivation the Redis store applies to its own
     * key family. The principal and the scope ride as SHA-256 digests
     * instead of their raw spellings, so the key stays bounded whatever
     * they contain, and the lineage keeps its own 64-hex validation. An
     * absent or malformed scope or principal derives the all-zero
     * placeholder, which the write gate never produces.
     */
    private function completedIndexKey(string $lineageHash, ?string $principalPseudonym, ?string $scope): string
    {
        $validScope = $scope !== null && preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $scope) === 1;
        $validPrincipal = $principalPseudonym !== null && $principalPseudonym !== '';

        return $lineageHash.':'.($validPrincipal ? hash('sha256', $principalPseudonym) : str_repeat('0', 64))
            .':'.($validScope ? hash('sha256', $scope) : str_repeat('0', 64));
    }

    public function claimDemandFinalization(string $demandId, int $now, int $claimSecs): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        $state = $entry['record']->state;
        // A superseded demand finalizes nothing: escalation replaced
        // it, so no retake may drive it to a terminal.
        if ($entry['record']->superseded()) {
            return null;
        }
        if ($state === StepUpDemandState::Finalizing) {
            // A claim inside its window is untouchable; a stale claim
            // (an owner that died inside the window) is retaken.
            $claimedAt = $entry['record']->stateAt;
            if ($claimedAt !== null && ($now - $claimedAt) < max(1, $claimSecs)) {
                return null;
            }
        } elseif ($state !== StepUpDemandState::Completed) {
            return null;
        }
        $claimed = $entry['record']->withState(StepUpDemandState::Finalizing, $now);
        $this->demands[$demandId] = ['record' => $claimed, 'expiresAt' => $entry['expiresAt']];

        return $claimed;
    }

    public function settleDemandFinalization(string $demandId, StepUpDemandState $state, int $now, ?string $factor = null): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        if ($entry['record']->state !== StepUpDemandState::Finalizing) {
            return null;
        }
        if (!$state->isTerminal()) {
            throw new \InvalidArgumentException('A step-up demand finalization settles to a terminal state only');
        }
        // A superseded demand authorizes nothing ever again: only the
        // superseded settlement itself and the fail-closed denied
        // terminal may still land.
        if ($state === StepUpDemandState::Authorized && $entry['record']->superseded()) {
            return null;
        }
        $settled = $entry['record']->withState($state, $now, $factor);
        $this->demands[$demandId] = ['record' => $settled, 'expiresAt' => $entry['expiresAt']];

        return $settled;
    }

    public function recordDemandEffect(string $demandId, string $effect, int $now): ?StepUpDemand
    {
        // The same gate order the Redis op runs: presence, liveness,
        // terminal state, effect vocabulary.
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        if ($entry['record']->state !== StepUpDemandState::Authorized) {
            return null;
        }
        if (!StepUpEffectsJournal::isEffect($effect)) {
            return null;
        }
        $journal = ($entry['record']->effects ?? StepUpEffectsJournal::none())->withEffect($effect, $now);
        $record = $entry['record']->withEffects($journal);
        $this->demands[$demandId] = ['record' => $record, 'expiresAt' => $entry['expiresAt']];

        return $record;
    }

    private function liveDemand(string $demandId): ?StepUpDemand
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }

        return $entry['record'];
    }

    /** @var array<string, string> operation digest -> the family tip's demand id */
    private array $operationIndex = [];

    public function demandIdForFamily(string $familyDigest): ?string
    {
        $tipId = $this->operationIndex[$familyDigest] ?? null;
        if ($tipId === null) {
            return null;
        }
        // An expired tip leaves no family: the index dies with it.
        if (!$this->liveDemand($tipId) instanceof StepUpDemand) {
            unset($this->operationIndex[$familyDigest]);

            return null;
        }

        return $tipId;
    }

    public function createRootDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        // One atomic decision, single-process by construction here: a
        // live family tip stands, a dead one is replaced. A standing
        // tip is answered as-is, never refreshed.
        $live = $this->demandIdForFamily($demand->familyDigest);
        if ($live !== null) {
            return $live;
        }
        $this->createDemand($demand, $ttlSecs);
        $this->operationIndex[$demand->familyDigest] = $demand->id;

        return $demand->id;
    }

    public function supersedeDemandWithChild(string $parentDemandId, StepUpDemand $child): ?StepUpDemand
    {
        $entry = $this->demands[$parentDemandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$parentDemandId]);

            return null;
        }
        $parent = $entry['record'];
        if ($parent->superseded()) {
            return null;
        }
        // A terminal demand is history, not a family head: only an
        // open demand or a claimed finalizing one may be superseded.
        if (!$parent->state->isOpen() && $parent->state !== StepUpDemandState::Finalizing) {
            return null;
        }
        if (isset($this->demands[$child->id])) {
            return null;
        }
        // The child inherits the parent's remaining lifetime and its
        // exact authorization deadline and family: any other shape
        // refuses (a child under another family digest would orphan the
        // parent's family when the index repoints).
        if ($child->expiresAt !== $parent->expiresAt || $child->parentDemandId !== $parent->id || $child->familyDigest !== $parent->familyDigest) {
            return null;
        }
        $expiresAt = $entry['expiresAt'];
        // The single atomic move: write the child, mark the parent,
        // repoint the family index. No intermediate state can lose the
        // child while the parent is already superseded.
        $this->demands[$child->id] = [
            'record' => StepUpDemand::fromJson((string) json_encode($child->toArray(), JSON_UNESCAPED_SLASHES))
                ?? throw new \RuntimeException('The step-up demand record could not be persisted (undecodable shape)'),
            'expiresAt' => $expiresAt,
        ];
        // The same terminal shape the Redis script writes in one
        // transaction: state superseded, stamped on this store's clock.
        // The order is load-bearing: withState stamps the terminal at
        // now, and supersededBy preserves an existing stateAt, so
        // reversing them would silently stamp createdAt instead.
        $this->demands[$parentDemandId] = ['record' => $parent->withState(StepUpDemandState::Superseded, $this->now())->supersededBy($child->id), 'expiresAt' => $expiresAt];
        $this->operationIndex[$child->familyDigest] = $child->id;

        return $this->demands[$parentDemandId]['record'];
    }

    public function claimDemandSendLease(string $demandId, int $resendAfterSecs, int $leaseSecs): ?StepUpDemandSendLease
    {
        $entry = $this->demands[$demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            unset($this->demands[$demandId]);

            return null;
        }
        $now = $this->now();
        $record = $entry['record'];
        if (!$record->state->isOpen() || $record->superseded() || $record->expired($now)) {
            return null;
        }
        $nowMs = $now * 1000;
        $leaseUntil = $record->leaseUntilMs ?? 0;
        if ($leaseUntil > $nowMs) {
            // Another worker's live lease: nobody else claims now.
            return null;
        }
        $recovered = $leaseUntil > 0;
        $priorSends = $record->sends;
        $priorLastSentAt = $record->lastSentAt;
        if (!$recovered) {
            if (!$record->canSend()) {
                return null;
            }
            if ($record->nextSendIsResend() && $priorLastSentAt !== null && ($now - $priorLastSentAt) < $resendAfterSecs) {
                return null;
            }
            $record = $record->withSend($now);
        }
        $claimed = $record->withLease($nowMs + max(1, $leaseSecs) * 1000);
        $this->demands[$demandId] = ['record' => $claimed, 'expiresAt' => $entry['expiresAt']];

        return new StepUpDemandSendLease($claimed, $now, $claimed->leaseUntilMs ?? 0, $priorSends, $priorLastSentAt, $recovered);
    }

    public function settleDemandSendLease(StepUpDemandSendSettlement $settlement): bool
    {
        $entry = $this->demands[$settlement->demandId] ?? null;
        if ($entry === null || $this->now() >= $entry['expiresAt']) {
            return false;
        }
        $record = $entry['record'];
        // The compare-and-set: only the worker whose lease (and claim)
        // still stamps the record settles it. A recovered slot refuses
        // the crashed claimant's late outcome.
        if ($record->leaseUntilMs !== $settlement->leaseUntilMs) {
            return false;
        }
        $settled = $settlement->delivered
            ? $record
            : $record->withSends($settlement->priorSends, $settlement->priorLastSentAt);
        $this->demands[$settlement->demandId] = ['record' => $settled->withLease(null), 'expiresAt' => $entry['expiresAt']];

        return true;
    }

    /** @var array<string, int> budget key -> fixed-window count */
    private array $mailBudgets = [];

    /** @var array<string, array{keys: list<string>, leaseUntil: int}> reservation id -> its live reservation */
    private array $mailReservations = [];

    public function reserveMailQuota(string $reservationId, array $budgetKeys, array $limits, int $windowSecs, int $leaseSecs): bool
    {
        $budgetKeys = array_values($budgetKeys);
        $limits = array_values($limits);
        if (\count($budgetKeys) !== \count($limits) || $budgetKeys === []) {
            throw new \InvalidArgumentException('A mail quota reservation names a limit for every budget key');
        }
        $now = $this->now();
        // All or nothing: the whole reservation rolls back when any
        // budget is over its limit, so a refusal reserves nothing.
        $touched = [];
        foreach ($budgetKeys as $i => $key) {
            $entry = $this->mailBudgets[$key] ?? null;
            $count = ($entry['count'] ?? 0) + 1;
            $windowExpires = ($entry['windowExpires'] ?? 0) > $now ? $entry['windowExpires'] : $now + max(1, $windowSecs);
            $this->mailBudgets[$key] = ['count' => $count, 'windowExpires' => $windowExpires];
            $touched[] = $key;
            if ($count > $limits[$i]) {
                foreach ($touched as $touchedKey) {
                    $current = $this->mailBudgets[$touchedKey];
                    $this->mailBudgets[$touchedKey] = ['count' => max(0, $current['count'] - 1), 'windowExpires' => $current['windowExpires']];
                }

                return false;
            }
        }
        $this->mailReservations[$reservationId] = ['keys' => array_values($budgetKeys), 'leaseUntil' => $now + max(1, $leaseSecs)];

        return true;
    }

    public function commitMailQuota(string $reservationId): void
    {
        // Committed-by-default on lease expiry: an unknown reservation
        // commits trivially, the counters already carry the spend.
        unset($this->mailReservations[$reservationId]);
    }

    public function releaseMailQuota(string $reservationId): bool
    {
        $reservation = $this->mailReservations[$reservationId] ?? null;
        if ($reservation === null) {
            return false;
        }
        unset($this->mailReservations[$reservationId]);
        if ($this->now() > $reservation['leaseUntil']) {
            // Past its lease the reservation committed by default; a
            // late release never refunds a possibly-delivered message.
            return false;
        }
        foreach ($reservation['keys'] as $key) {
            $current = $this->mailBudgets[$key] ?? null;
            if ($current !== null && $current['count'] > 0) {
                $this->mailBudgets[$key] = ['count' => $current['count'] - 1, 'windowExpires' => $current['windowExpires']];
            }
        }

        return true;
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        $this->totpSecrets[$principalPseudonym] = $secretRaw;
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        return $this->totpSecrets[$principalPseudonym] ?? null;
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        if (($this->totpSteps[$principalPseudonym] ?? -1) >= $step) {
            return false;
        }
        $this->totpSteps[$principalPseudonym] = $step;

        return true;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    private function live(string $challengeId): ?StepUpChallenge
    {
        $entry = $this->challenges[$challengeId] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($this->now() >= $entry['expiresAt']) {
            unset($this->challenges[$challengeId]);

            return null;
        }

        return $entry['record'];
    }
    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
    {
        $this->stepUpSuccess[$principalPseudonym] = ['at' => $now, 'expires' => $now + $ttlSecs];
    }

    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
    {
        $marker = $this->stepUpSuccess[$principalPseudonym] ?? null;
        if ($marker === null || $marker['expires'] <= $now) {
            return false;
        }

        return ($now - $marker['at']) <= $withinSecs;
    }

    /** @var array<string, array{at: int, expires: int, factor: string}> */
    private array $sessionStepUpSuccess = [];

    public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return;
        }
        $this->sessionStepUpSuccess[$sessionId."\0".$principalPseudonym] = [
            'at' => $now,
            'expires' => $now + $ttlSecs,
            'factor' => $factor,
        ];
    }

    public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return false;
        }
        $marker = $this->sessionStepUpSuccess[$sessionId."\0".$principalPseudonym] ?? null;
        if ($marker === null || $marker['expires'] <= $now || ($now - $marker['at']) > $withinSecs) {
            return false;
        }
        if ($minFactor !== null && self::factorRank($marker['factor']) < self::factorRank($minFactor)) {
            return false;
        }

        return true;
    }

    /** webauthn > totp > email_otp > unknown. */
    private static function factorRank(string $factor): int
    {
        return match ($factor) {
            'webauthn' => 3,
            'totp' => 2,
            'email_otp' => 1,
            default => 0,
        };
    }

    public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int
    {
        $key = $dimension.':'.$pseudonym;
        $this->lockoutFailures[$key] = ($this->lockoutFailures[$key] ?? 0) + 1;

        return $this->lockoutFailures[$key];
    }

    public function lockoutUntil(string $dimension, string $pseudonym, int $now): int
    {
        $until = $this->lockoutUntil[$dimension.':'.$pseudonym] ?? 0;

        return $until > $now ? $until : 0;
    }

    public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void
    {
        $key = $dimension.':'.$pseudonym;
        $until = $now + max(1, $ttlSecs);
        if (($this->lockoutUntil[$key] ?? 0) < $until) {
            $this->lockoutUntil[$key] = $until;
        }
    }

    public function clearLockout(string $dimension, string $pseudonym): void
    {
        $key = $dimension.':'.$pseudonym;
        unset($this->lockoutFailures[$key], $this->lockoutUntil[$key]);
    }
}
