<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * In-memory stand-in for Predis\Client with exactly the command surface
 * the Redis chain state store uses: GET / SET (with the EX options-array
 * form) / TTL / time / eval. The eval interpreter runs the store's chain
 * scripts by their marker comments: obligation create-or-get with rank
 * raising and stale-mapping repair, the owner-scoped short lease from
 * time + min(lease, remaining TTL) with keepttl, and the idempotent
 * issued transition. The terminal verified transition deletes the
 * obligation atomically; the nonce-pinned rearm and the owner-gated
 * release complete the surface. The clock advances through
 * {@see self::setTimeMs()} so the lease expiry is enforceable.
 */
final class ChainRedisFake extends \Predis\Client
{
    /** @var array<string, string> plain strings (the chain/obligation records) */
    public array $strings = [];

    /** @var array<string, int> expire deadlines in ms */
    public array $expirations = [];

    /** @var list<array{0: string, 1: list<mixed>}> every command issued, WAIT included */
    public array $calls = [];

    /** The WAIT acknowledgement count to answer (violated when < waitReplicas). */
    public int $waitAck = 1;

    private float $clockMs = 1_000_000.0;

    public function clockSecs(): int
    {
        return (int) floor($this->clockMs / 1000);
    }

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    /** @internal test hook: advance the fake Redis server clock (ms). */
    public function setTimeMs(float $ms): void
    {
        $this->clockMs = $ms;
    }

    /** @return list<array{0: string, 1: list<mixed>}> the WAIT commands issued */
    public function waits(): array
    {
        return array_values(array_filter($this->calls, static fn (array $c): bool => $c[0] === 'WAIT'));
    }

    public function __call($commandID, $arguments)
    {
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'GET' => $this->strings[(string) $arguments[0]] ?? null,
            'SET' => $this->fakeSet($arguments),
            'SETEX' => $this->fakeSetex($arguments),
            'TTL' => $this->fakeTtl((string) $arguments[0]),
            'TIME' => $this->fakeTime(),
            'EVAL' => $this->fakeEval($arguments),
            default => throw new \LogicException('unexpected command '.$commandID),
        };
    }

    private function fakeSetex(array $arguments): string
    {
        $this->strings[(string) $arguments[0]] = (string) $arguments[2];

        return 'OK';
    }

    /**
     * The recovery fence is a fresh same-namespace write on the accepting
     * connection immediately before the WAIT. The fence key must be
     * {kiwi:<ns>}:replication-fence, never a non-namespaced bare key and
     * never an undefined-property access on PHP 8.2+. The write lands
     * before the WAIT on the same connection, and a shortfall fails
     * closed.
     */
    public function testEstablishReplicationFenceWritesTheNamespacedKeyAndWaits(): void
    {
        $store = $this->waitingStore();
        $this->fake->calls = [];
        $this->fake->waitAck = 1;

        $store->establishReplicationFence('the stage-2 recovery acceptance');

        $writes = array_values(array_filter($this->fake->calls, static fn (array $c): bool => $c[0] === 'SETEX'));
        self::assertCount(1, $writes, 'the fence performs exactly one fresh write');
        self::assertSame('{kiwi:kiwi-test}:replication-fence', $writes[0][1][0], 'the fence key is the same-namespace replication-fence key');
        self::assertSame(60, $writes[0][1][1], 'the fence carries the bounded TTL');
        self::assertCount(1, $this->fake->waits(), 'the fence WAITs on the same connection');
        self::assertArrayHasKey('{kiwi:kiwi-test}:replication-fence', $this->fake->strings, 'the fresh fence value is stored');

        $this->fake->waitAck = 0;
        $this->fake->calls = [];
        try {
            $store->establishReplicationFence('a shortfalling recovery acceptance');
            self::fail('a shortfalling fence must fail closed');
        } catch (ReplicaWaitException $e) {
            self::assertStringContainsString('acknowledged 0 of 1 requested replicas after a shortfalling recovery acceptance', $e->getMessage());
        }
        self::assertCount(1, $this->fake->waits(), 'the shortfalling fence still issued exactly one WAIT');
    }

    /** The raw-command escape hatch the store's verified WAIT uses. */
    public function executeRaw(array $arguments, &$error = null): mixed
    {
        $this->calls[] = [strtoupper((string) ($arguments[0] ?? '')), \array_slice($arguments, 1)];

        return $this->waitAck;
    }

    private function fakeSet(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $value = (string) $arguments[1];
        $ttl = null;
        if (isset($arguments[2]) && \is_array($arguments[2]) && isset($arguments[2]['EX'])) {
            $ttl = (int) $arguments[2]['EX'];
        }
        $this->strings[$key] = $value;
        if ($ttl !== null) {
            $this->expirations[$key] = (int) ($this->clockMs + $ttl * 1000);
        }

        return 'OK';
    }

    private function fakeTtl(string $key): int
    {
        if (!isset($this->strings[$key])) {
            return -2;
        }
        if (!isset($this->expirations[$key])) {
            return -1;
        }
        $remainingMs = $this->expirations[$key] - $this->clockMs;

        return (int) max(1, floor($remainingMs / 1000));
    }

    /** @return array{0: int, 1: int} [seconds, microseconds] */
    private function fakeTime(): array
    {
        $sec = (int) floor($this->clockMs / 1000);

        return [$sec, (int) round(($this->clockMs - $sec * 1000) * 1000)];
    }

    private function fakeEval(array $arguments): mixed
    {
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $args = \array_slice($keysAndArgs, $numKeys);

        if (str_contains($script, 'Chain obligation create-or-get')) {
            return $this->luaCreateOrGet($keys, $args);
        }
        if (str_contains($script, 'Chain reservation')) {
            return $this->luaReserve($keys[0], $args);
        }
        if (str_contains($script, 'Chain issuance')) {
            return $this->luaMarkIssued($keys[0], $args);
        }
        if (str_contains($script, 'Chain verification')) {
            return $this->luaMarkVerified($keys, $args);
        }
        if (str_contains($script, 'Chain step-up')) {
            return $this->luaMarkStepUpRequired($keys[0], $args);
        }
        if (str_contains($script, 'Chain denial')) {
            return $this->luaMarkDenied($keys[0], $args);
        }
        if (str_contains($script, 'Transaction denial')) {
            return $this->luaTransactionDenied($keys, $args);
        }
        if (str_contains($script, 'Transaction step-up')) {
            return $this->luaTransactionStepUpRequired($keys, $args);
        }
        if (str_contains($script, 'Chain rearm')) {
            return $this->luaRearm($keys[0], $args);
        }
        if (str_contains($script, 'Chain release')) {
            return $this->luaRelease($keys[0], $args);
        }
        if (str_contains($script, 'Chain completion')) {
            return $this->luaComplete($keys[0], $args);
        }
        if (str_contains($script, 'Chain live read')) {
            return $this->luaRead($keys[0]);
        }
        if (str_contains($script, 'Chain obligation compare-delete')) {
            return $this->luaDeleteObligation($keys[0], $args);
        }

        throw new \LogicException('unexpected script');
    }

    /** @var null|\Closure test hook: fires at the top of the create-or-get emulation (mapping-move races). */
    public ?\Closure $onCreateOrGet = null;

    private function luaCreateOrGet(array $keys, array $args): array
    {
        if ($this->onCreateOrGet !== null) {
            ($this->onCreateOrGet)();
        }
        $chainKey = $keys[0];
        $obligationKey = $keys[1];
        $pointedKey = $keys[2];
        $pointedChainId = (string) $args[10];
        $existing = $this->strings[$obligationKey] ?? null;
        if ($existing !== null) {
            if ($existing !== $pointedChainId) {
                return [$pointedChainId, 0, 'moved'];
            }
            $chained = $this->strings[$pointedKey] ?? null;
            if ($chained !== null) {
                $rec = json_decode($chained, true, 8, JSON_THROW_ON_ERROR);
                // The live-check mirrors the Lua: a past-expiry pointed-at
                // record is stale and the mapping heals with a fresh chain.
                if (isset($rec['requiredRank']) && \is_int($rec['requiredRank']) && (int) $rec['expiresAt'] > (int) floor($this->clockMs / 1000)) {
                    $newRank = (int) $args[5];
                    if ($newRank > $rec['requiredRank']) {
                        $rec['requiredRank'] = $newRank;
                        $rec['requiredAction'] = (string) $args[4];
                        $this->strings[$pointedKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

                        return [$pointedChainId, 1, ''];
                    }

                    return [$pointedChainId, 0, ''];
                }
            }
            if (($this->strings[$obligationKey] ?? null) === $pointedChainId) {
                unset($this->strings[$obligationKey], $this->expirations[$obligationKey]);
            }
        }
        $rec = [
            'v' => 2,
            'stage1Nonce' => (string) $args[2],
            'scope' => (string) $args[3],
            'obligationId' => (string) $args[0],
            'requiredAction' => (string) $args[4],
            'requiredRank' => (int) $args[5],
            'policyVersion' => (int) $args[6],
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => (string) $args[7] !== '' ? (string) $args[7] : null,
            'expiresAt' => (int) $args[8],
        ];
        $ttl = (int) $args[9];
        $this->strings[$chainKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        $this->expirations[$chainKey] = (int) ($this->clockMs + $ttl * 1000);
        $this->strings[$obligationKey] = (string) $args[1];
        $this->expirations[$obligationKey] = (int) ($this->clockMs + $ttl * 1000);

        return [(string) $args[1], 1, ''];
    }

    private function luaReserve(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $ttl = $this->fakeTtl($key);
        if ($ttl <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        $nowSecs = (int) floor($this->clockMs / 1000);
        if ($this->fakeRecordExpired($rec, $nowSecs)) {
            return 'missing';
        }
        if ($rec['state'] === 'issued') {
            return 'issued';
        }
        if ($rec['state'] === 'verified') {
            return 'verified';
        }
        if ($rec['state'] === 'completed') {
            return 'completed';
        }
        if ($rec['state'] === 'reserved') {
            if ($rec['owner'] === $args[0]) {
                return 'retry';
            }
            if ((int) $rec['leaseUntil'] > $nowSecs) {
                return 'busy';
            }
            $lease = min((int) $args[1], $ttl);
            $rec['state'] = 'reserved';
            $rec['owner'] = (string) $args[0];
            $rec['leaseUntil'] = $nowSecs + $lease;
            $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

            return 'taken_over';
        }
        $lease = min((int) $args[1], $ttl);
        $rec['state'] = 'reserved';
        $rec['owner'] = (string) $args[0];
        $rec['leaseUntil'] = $nowSecs + $lease;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'available';
    }

    private function luaMarkIssued(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        if ($this->fakeTtl($key) <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return 'missing';
        }
        if ($rec['state'] === 'reserved') {
            if ($rec['owner'] !== $args[0]) {
                return 'not_owner';
            }
            $rec['state'] = 'issued';
            $rec['stage2Nonce'] = (string) $args[1];
            $rec['owner'] = null;
            $rec['leaseUntil'] = null;
            $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

            return 'issued_new';
        }
        if ($rec['state'] === 'issued' || $rec['state'] === 'completed') {
            return $rec['stage2Nonce'] === $args[1] ? 'issued_same' : 'conflict';
        }
        if ($rec['state'] === 'verified') {
            return $rec['stage2Nonce'] === $args[1] ? 'verified_same' : 'conflict';
        }

        return 'not_owner';
    }

    private function luaMarkVerified(array $keys, array $args): string
    {
        $key = $keys[0];
        $obligationKey = $keys[1];
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        if ($this->fakeTtl($key) <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return 'missing';
        }
        if ($rec['state'] === 'verified') {
            return $rec['stage2Nonce'] === $args[0] ? 'verified_same' : 'conflict';
        }
        if (($rec['state'] !== 'issued' && $rec['state'] !== 'completed') || $rec['stage2Nonce'] !== $args[0]) {
            return 'conflict';
        }
        $rec['state'] = 'verified';
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        if (($this->strings[$obligationKey] ?? null) === $args[1]) {
            unset($this->strings[$obligationKey], $this->expirations[$obligationKey]);
        }

        return 'verified_new';
    }

    private function luaMarkStepUpRequired(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        if ($this->fakeTtl($key) <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return 'missing';
        }
        if ($rec['state'] === 'step_up_required') {
            return $rec['stage2Nonce'] === $args[0] ? 'step_up_required_same' : 'conflict';
        }
        if (($rec['state'] !== 'issued' && $rec['state'] !== 'completed') || $rec['stage2Nonce'] !== $args[0]) {
            return 'conflict';
        }
        $rec['state'] = 'step_up_required';
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'step_up_required_new';
    }

    private function luaMarkDenied(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        if ($this->fakeTtl($key) <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return 'missing';
        }
        if ($rec['state'] === 'denied') {
            return $rec['stage2Nonce'] === $args[0] ? 'denied_same' : 'conflict';
        }
        if (($rec['state'] !== 'issued' && $rec['state'] !== 'completed') || $rec['stage2Nonce'] !== $args[0]) {
            return 'conflict';
        }
        $rec['state'] = 'denied';
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'denied_new';
    }

    private function luaTransactionDenied(array $keys, array $args): string
    {
        $key = $keys[0];
        $obligationKey = $keys[1];
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        if ($this->fakeTtl($key) <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if (($rec['obligationId'] ?? null) !== $args[1]) {
            return 'obligation_moved';
        }
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return 'missing';
        }
        $mapped = $this->strings[$obligationKey] ?? null;
        if ($mapped === null) {
            return 'already_completed';
        }
        if ($mapped !== $args[0]) {
            return 'obligation_moved';
        }
        if ($rec['state'] === 'denied') {
            return 'denied_same';
        }
        if ($rec['state'] === 'step_up_required') {
            return 'conflict';
        }
        if ($rec['state'] === 'verified') {
            return 'already_verified';
        }
        if (!\in_array($rec['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $rec['state'] = 'denied';
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'denied_new';
    }

    private function luaTransactionStepUpRequired(array $keys, array $args): string
    {
        $key = $keys[0];
        $obligationKey = $keys[1];
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        if ($this->fakeTtl($key) <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if (($rec['obligationId'] ?? null) !== $args[1]) {
            return 'obligation_moved';
        }
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return 'missing';
        }
        $mapped = $this->strings[$obligationKey] ?? null;
        if ($mapped === null) {
            return 'already_completed';
        }
        if ($mapped !== $args[0]) {
            return 'obligation_moved';
        }
        if ($rec['state'] === 'step_up_required') {
            return 'step_up_required_same';
        }
        if ($rec['state'] === 'denied') {
            return 'conflict';
        }
        if ($rec['state'] === 'verified') {
            return 'already_verified';
        }
        if (!\in_array($rec['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $rec['state'] = 'step_up_required';
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'step_up_required_new';
    }

    private function luaRearm(string $key, array $args): bool
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        if ($this->fakeTtl($key) <= 0) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return false;
        }
        if ($rec['state'] !== 'issued' || $rec['stage2Nonce'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'available';
        $rec['stage2Nonce'] = null;
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return true;
    }

    private function luaRelease(string $key, array $args): mixed
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        if ($this->fakeTtl($key) <= 0) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return false;
        }
        if ($rec['state'] !== 'reserved' || $rec['owner'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'available';
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return true;
    }

    private function luaComplete(string $key, array $args): mixed
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        if ($this->fakeTtl($key) <= 0) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return false;
        }
        if ($rec['state'] !== 'reserved' || $rec['owner'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'completed';
        $rec['stage2Nonce'] = (string) $args[1];
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return (string) json_encode($rec, JSON_THROW_ON_ERROR);
    }

    /**
     * The live-read emulation of the read script: missing or
     * lifetime-less or past-expiry -> null (false), undecodable ->
     * 'corrupt', live -> the raw JSON (the PHP strict decode still runs
     * as the second gate).
     */
    private function luaRead(string $key): mixed
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null || $existing === '') {
            return null;
        }
        if ($this->fakeTtl($key) <= 0) {
            return null;
        }
        try {
            $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return 'corrupt';
        }
        if (!\is_array($rec)) {
            return 'corrupt';
        }
        if ($this->fakeRecordExpired($rec, (int) floor($this->clockMs / 1000))) {
            return null;
        }

        return $existing;
    }

    /** The signed-expiry guard of the Lua chainRecordExpired(). */
    private function fakeRecordExpired(array $rec, int $nowSecs): bool
    {
        return (int) ($rec['expiresAt'] ?? 0) <= $nowSecs;
    }

    private function luaDeleteObligation(string $key, array $args): mixed
    {
        if (($this->strings[$key] ?? null) === $args[0]) {
            unset($this->strings[$key], $this->expirations[$key]);

            return 1;
        }

        return 0;
    }
}
