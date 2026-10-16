<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\Storage\KeyspaceMode;
use KiwiCaptcha\Risk\Storage\OutcomeRegistration;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;
use KiwiCaptcha\Risk\TargetIdentifierResolverInterface;
use PHPUnit\Framework\TestCase;

/**
 * The outcome-credit path under real OS-process concurrency.
 *
 * Forked workers with their own Redis connections race every
 * transition of the credit path, released on one wall-clock barrier.
 * The raced transitions are the consolidated registration, the
 * exactly-once confirm, the retried target-failure report, the sharded
 * step-up trust credit and the ledger score.
 *
 * The invariants: a pending ledger entry is consumed by exactly one
 * confirmation, one report books each credited surface once, and a
 * step-up credits the same trust in every keyspace layout. The ledger
 * score always equals the score of the decision the caller received.
 *
 * Runs in the real-Redis lane (RISK_REDIS_URL) and skips cleanly
 * otherwise. Each test method works in its own fresh namespace with its
 * own key prefix. No test flushes the shared server. A product denial
 * (a degraded decision) is classified as a denial, never as a harness
 * error.
 */
final class OutcomeCreditConcurrencyTest extends TestCase
{
    private const SCOPE = 1;

    private const PRINCIPAL = '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18';

    private const SESSION = 'c7b3e1f9a5d24708b6e0c8a2f4d69123';

    /** The target pseudonym the seeded failures address (32-hex handle). */
    private const TARGET = '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813';

    private const SOURCE = '198.51.100.7';

    private string $url = '';

    private \Predis\Client $client;

    /** @var list<int> */
    private array $children = [];

    /** @var list<string> */
    private array $namespaces = [];

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6421 --save "" --appendonly no --daemonize yes');
        }
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent outcome workers');
        }
        $this->url = $url;
        $this->client = self::relaxedClient($url);
        $this->client->ping();
    }

    /**
     * A client with CI-jitter-proof timeouts: the store's contract
     * defaults (5 ms connect, 10 ms read/write) are fail-fast tuning
     * knobs, and a loaded runner must never turn a scheduling pause into
     * a harness error.
     */
    private static function relaxedClient(string $url): \Predis\Client
    {
        return new \Predis\Client($url, [
            'connection' => [
                'timeout' => 2.0,
                'read_write_timeout' => 2.0,
            ],
        ]);
    }

    protected function tearDown(): void
    {
        foreach ($this->children as $pid) {
            $status = 0;
            pcntl_waitpid($pid, $status);
        }
        $this->children = [];
        foreach ($this->namespaces as $namespace) {
            try {
                $this->sweep($namespace);
            } catch (\Throwable) {
                // a dead instance must not fail the shutdown path
            }
        }
        $this->namespaces = [];
    }

    // ------------------------------------------------------------------
    // The consolidated registration and the exactly-once confirm
    // ------------------------------------------------------------------

    public function testTheLedgerConfirmConsumesThePendingEntryExactlyOnceUnderTheRace(): void
    {
        $namespace = $this->freshNamespace();
        $store = $this->store($namespace);
        $decisionId = self::hex('confirm-race');

        // The consolidated assessment books the pending entry atomically
        // with the observation, so the confirm finds a pending ledger.
        $reply = $store->assessV2WithReply(
            $this->observation(self::hex('event-'.$decisionId)),
            null,
            null,
            $this->registration($decisionId),
        );
        self::assertTrue($reply->registrationStatus, 'the consolidated assessment registered the pending ledger entry');

        $rows = $this->fork(
            array_fill(0, 6, ['op' => 'confirm', 'namespace' => $namespace, 'decision' => $decisionId]),
        );

        $firsts = 0;
        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            if ((int) $row['status'] === 1) {
                $firsts++;
            }
        }
        self::assertSame(1, $firsts, 'six concurrent confirmations consume the pending entry exactly once');

        $ledger = json_decode((string) $this->client->get($store->ledgerKey($decisionId)), true);
        self::assertSame('A', $ledger['o'], 'the ledger ends on the first confirmation outcome');
    }

    /**
     * The registration half of the same boundary: one decision id can
     * be registered once, however many assessments race it, and the
     * pending entry carries the outcome-ledger TTL.
     */
    public function testConcurrentRegistrationsOfOneDecisionCreateOnePendingEntry(): void
    {
        $namespace = $this->freshNamespace();
        $decisionId = self::hex('registration-race');

        $rows = $this->fork(
            array_fill(0, 6, ['op' => 'register', 'namespace' => $namespace, 'decision' => $decisionId]),
        );

        $created = 0;
        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            if ($row['registered']) {
                $created++;
            }
        }
        self::assertSame(1, $created, 'the pending entry is created by exactly one writer');

        $store = $this->store($namespace);
        $ledger = json_decode((string) $this->client->get($store->ledgerKey($decisionId)), true);
        self::assertSame('P', $ledger['o'], 'the surviving entry is pending');
        $ttl = (int) $this->client->ttl($store->ledgerKey($decisionId));
        self::assertGreaterThan(0, $ttl, 'the pending entry carries its outcome-ledger TTL');
        self::assertLessThanOrEqual(
            RedisRiskStateStore::DEFAULT_OUTCOME_TTL_SECS,
            $ttl,
            'the TTL is the store outcome TTL, never a longer one',
        );
    }

    // ------------------------------------------------------------------
    // The retried report must book each credited surface once
    // ------------------------------------------------------------------

    public function testConcurrentDuplicateTargetReportsBookOneTargetFailure(): void
    {
        $namespace = $this->freshNamespace();

        $rows = $this->fork(
            array_fill(0, 8, ['op' => 'report-target-failure', 'namespace' => $namespace]),
        );

        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            self::assertTrue($row['booked'], 'the report context books the mapped channel');
        }

        $store = $this->store($namespace);
        $state = $store->readTargetState(self::TARGET);
        self::assertSame(
            1,
            $state['fails'],
            'eight concurrent deliveries of one report book one target failure, got '.$state['fails'],
        );

        // The reputation channel of the same report is deduped by the
        // derived event id: exactly one AuthenticationFailure landed.
        $principal = $this->client->hgetall(
            '{kiwi:'.$store->namespace().'}:risk:principal:'.$this->principalPseudonym(),
        );
        self::assertSame('2500', $principal['af'] ?? null, 'the reputation channel books the event once');
    }

    // ------------------------------------------------------------------
    // The consolidated first-seen tag records
    // ------------------------------------------------------------------

    /**
     * The first-seen client-context record is first-write-wins: the
     * racing assessments agree on one recorded tag, and the record
     * carries the session TTL. A reader can never observe a torn or
     * later record and call it the session's first context.
     */
    public function testTheFirstSeenContextTagIsFirstWriteWinsUnderTheRace(): void
    {
        $namespace = $this->freshNamespace();
        $rows = $this->fork([
            ['op' => 'tag-record', 'namespace' => $namespace, 'tag' => 'tag-a'],
            ['op' => 'tag-record', 'namespace' => $namespace, 'tag' => 'tag-b'],
            ['op' => 'tag-record', 'namespace' => $namespace, 'tag' => 'tag-c'],
            ['op' => 'tag-record', 'namespace' => $namespace, 'tag' => 'tag-d'],
        ]);

        $observed = [];
        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            self::assertContains($row['existing'], ['tag-a', 'tag-b', 'tag-c', 'tag-d'], 'a racing assessment sees one recorded tag');
            $observed[$row['existing']] = true;
        }
        self::assertCount(1, $observed, 'every racing assessment reports the same recorded tag');

        $store = $this->store($namespace);
        // The observation carries the session pseudonym verbatim, so the
        // record is keyed by it exactly.
        $key = '{kiwi:'.$store->namespace().'}:risk:ctx:'.self::SESSION;
        self::assertSame(array_key_first($observed), (string) $this->client->get($key), 'the reported tag is the recorded one');
        $ttl = (int) $this->client->ttl($key);
        self::assertGreaterThan(0, $ttl, 'the record carries the session TTL');
    }

    // ------------------------------------------------------------------
    // The step-up trust credit must hold in every keyspace layout
    // ------------------------------------------------------------------

    public function testAShardedStepUpCompletionCreditsTrustUnderTheRace(): void
    {
        $namespace = $this->freshNamespace();

        $rows = $this->fork([
            ['op' => 'step-up-sharded', 'namespace' => $namespace],
            ['op' => 'step-up-sharded', 'namespace' => $namespace],
            ['op' => 'step-up-sharded', 'namespace' => $namespace],
            ['op' => 'step-up-sharded', 'namespace' => $namespace],
        ]);

        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            self::assertSame(80, $row['trustCredit'], 'a sharded step-up credits the source/session trust');
            self::assertSame(200, $row['principalCredit'], 'a sharded step-up credits the principal trust');
        }

        // The layout parity the credit is judged against: the classic
        // store answers the identical signal slots for the same event.
        $legacy = $this->store($this->freshNamespace());
        $vector = $legacy->observe($this->stepUpObservation('legacy-step-up'));
        self::assertSame(80, $vector->trustCredit, 'the classic layout credits the source/session trust');
        self::assertSame(200, $vector->principalCredit, 'the classic layout credits the principal trust');

        // A sharded assessment after the raced credit is not degraded:
        // the credit write must not have poisoned the layout's state.
        $decision = $this->engine($this->shardedStore($namespace))->assessPreIssue($this->preIssueContext());
        self::assertNotContains(
            RiskReason::CapacityPressure,
            $decision->reasons,
            'a sharded assessment after the raced credit is not degraded',
        );
        self::assertGreaterThan(0, $decision->score, 'the sharded assessment after the race scores normally');
    }

    // ------------------------------------------------------------------
    // The ledger score must be the score of the returned decision
    // ------------------------------------------------------------------

    public function testTheConsolidatedLedgerScoreIsTheDecisionScoreUnderTheRace(): void
    {
        $namespace = $this->freshNamespace();
        $store = $this->store($namespace);
        $engine = $this->engine($store, $this->resolver());

        // Seed a target that already carries failures, so a live target
        // pressure and spread ride the consolidated assessment.
        $targetId = $engine->resolveTargetId(self::SCOPE, $this->targetFields());
        $store->registerTargetFailure($targetId, 'seed-source-1', 'seed-asn-1');
        $store->registerTargetFailure($targetId, 'seed-source-2', 'seed-asn-2');

        $rows = $this->fork([
            ['op' => 'ledger-score', 'namespace' => $namespace, 'event' => RiskEventKind::AuthenticationFailure->value],
            ['op' => 'ledger-score', 'namespace' => $namespace, 'event' => RiskEventKind::PreIssue->value],
            ['op' => 'ledger-score-honeypot', 'namespace' => $namespace],
            ['op' => 'ledger-score-sharded', 'namespace' => $namespace],
        ]);

        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            self::assertTrue($row['registered'], 'worker '.$row['index'].' registered its ledger entry');
            self::assertSame(
                $row['decisionScore'],
                $row['ledgerScore'],
                'worker '.$row['index'].' booked a ledger score that differs from its decision score',
            );
        }
    }

    // ------------------------------------------------------------------
    // The engine and store wiring of one assessment
    // ------------------------------------------------------------------

    private function engine(
        \KiwiCaptcha\Risk\Storage\RiskStateStoreInterface $store,
        ?TargetIdentifierResolverInterface $resolver = null,
    ): AdaptiveRiskEngine {
        $keys = $this->keys();

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [
                    self::SCOPE => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                ],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
            targetResolver: $resolver,
        );
    }

    private function keys(): RiskKeys
    {
        return RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
    }

    /** A resolver naming one target field for every scope. */
    private function resolver(): TargetIdentifierResolverInterface
    {
        return new class implements TargetIdentifierResolverInterface {
            public function resolve(int $scope, array $fields): ?string
            {
                return $fields['email'] ?? null;
            }
        };
    }

    /** @return array<string, string> */
    private function targetFields(): array
    {
        return ['email' => 'target@example.com'];
    }

    private function principalPseudonym(): string
    {
        return (new RiskIdentityFactory($this->keys()))->principalId(self::PRINCIPAL);
    }

    private function context(RiskEventKind $event, bool $withTarget = false): RiskContext
    {
        return new RiskContext(
            scope: self::SCOPE,
            sourceIp: self::SOURCE,
            sessionId: self::SESSION,
            principalId: self::PRINCIPAL,
            event: $event,
            networkFlags: (new CidrNetworkClassifier([]))->classify(self::SOURCE),
            resources: new ResourcePressure(1000, 1000),
            targetFields: $withTarget ? $this->targetFields() : [],
        );
    }

    private function preIssueContext(): RiskContext
    {
        return $this->context(RiskEventKind::PreIssue);
    }

    private function observation(string $eventId, RiskEventKind $event = RiskEventKind::PreIssue): RiskObservation
    {
        return new RiskObservation(
            event: $event,
            scope: self::SCOPE,
            sourceEpoch: 12345,
            sourceIdPrev: str_repeat('a', 32),
            sourceId: str_repeat('b', 32),
            sourceIdNext: str_repeat('c', 32),
            subnetEpoch: 12345,
            subnetIdPrev: str_repeat('d', 32),
            subnetId: str_repeat('e', 32),
            subnetIdNext: str_repeat('f', 32),
            sessionId: self::SESSION,
            principalId: self::PRINCIPAL,
            eventId: $eventId,
            networkRisk: 0,
            nowMs: 1_700_000_000_000,
        );
    }

    private function stepUpObservation(string $seed): RiskObservation
    {
        return $this->observation(self::hex($seed), RiskEventKind::StepUpCompleted);
    }

    private function registration(string $decisionId): OutcomeRegistration
    {
        return new OutcomeRegistration(
            decisionId: $decisionId,
            decisionHour: 472222,
            baseRisk: 100,
            globalPressureEnabled: true,
            honeypotHit: false,
            weights: new RiskWeights(),
            v2Weights: new RiskV2Weights(),
        );
    }

    private static function hex(string $seed): string
    {
        return substr(hash('sha256', $seed), 0, 32);
    }

    // ------------------------------------------------------------------
    // Stores and namespaces
    // ------------------------------------------------------------------

    private function freshNamespace(): string
    {
        $namespace = 'occredit'.bin2hex(random_bytes(4));
        $this->namespaces[] = $namespace;

        return $namespace;
    }

    private function store(string $namespace): RedisRiskStateStore
    {
        return new RedisRiskStateStore(self::relaxedClient($this->url), namespace: $namespace);
    }

    private function shardedStore(string $namespace): ShardedRedisRiskStateStore
    {
        return new ShardedRedisRiskStateStore(
            [$this->url],
            namespace: $namespace,
            connectTimeoutSecs: 2.0,
            commandTimeoutSecs: 2.0,
        );
    }

    /** Removes every key of one namespace without touching the shared server. */
    private function sweep(string $namespace): void
    {
        $store = $this->store($namespace);
        $encoded = $store->namespace();
        foreach (['*{kiwi:'.$encoded.'}*', '*{kiwi:'.$encoded.':*'] as $pattern) {
            $keys = $this->client->keys($pattern);
            if (\is_array($keys) && $keys !== []) {
                $this->client->del(...$keys);
            }
        }
    }

    // ------------------------------------------------------------------
    // The forked worker harness
    // ------------------------------------------------------------------

    /**
     * Fork one worker per job, release them on the shared wall-clock
     * barrier, and collect one result row per worker in job order.
     *
     * @param list<array<string, mixed>> $jobs
     *
     * @return list<array<string, mixed>>
     */
    private function fork(array $jobs): array
    {
        $startAt = microtime(true) + 1.0;
        $base = tempnam(sys_get_temp_dir(), 'kiwi-occredit-');
        self::assertNotFalse($base, 'a scratch result path is available');
        $rows = [];
        foreach ($jobs as $index => $job) {
            $out = $base.'.'.$index;
            $pid = pcntl_fork();
            self::assertNotSame(-1, $pid, 'pcntl_fork succeeds');
            if ($pid === 0) {
                $row = ['index' => $index, 'op' => $job['op']];
                try {
                    while (microtime(true) < $startAt) {
                        usleep(100);
                    }
                    $row += $this->runWorker($job);
                } catch (\Throwable $e) {
                    $row['error'] = get_class($e).': '.$e->getMessage();
                }
                file_put_contents($out, json_encode($row, JSON_THROW_ON_ERROR));
                exit(0);
            }
            $this->children[] = $pid;
        }
        foreach ($this->children as $pid) {
            $status = 0;
            pcntl_waitpid($pid, $status);
            self::assertSame(0, pcntl_wexitstatus($status), 'every outcome worker exits cleanly');
        }
        $this->children = [];
        foreach ($jobs as $index => $job) {
            $raw = is_file($base.'.'.$index) ? (string) file_get_contents($base.'.'.$index) : '';
            self::assertNotSame('', $raw, 'worker '.$index.' reports a result');
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($decoded);
            $rows[] = $decoded;
            @unlink($base.'.'.$index);
        }
        @unlink($base);

        return $rows;
    }

    /**
     * One worker action, run in the forked child on its own connection.
     *
     * @param array<string, mixed> $job
     *
     * @return array<string, mixed>
     */
    private function runWorker(array $job): array
    {
        $namespace = (string) $job['namespace'];
        // Every worker owns its socket: a forked child sharing the
        // parent's connection would interleave replies with its
        // siblings.
        $client = self::relaxedClient($this->url);

        if ($job['op'] === 'confirm') {
            $store = $this->store($namespace);
            return ['status' => $store->confirmOutcome((string) $job['decision'], false)];
        }

        if ($job['op'] === 'register') {
            $store = $this->store($namespace);
            return [
                'registered' => $store->registerOutcome((string) $job['decision'], self::SCOPE, 472222, 500),
            ];
        }

        if ($job['op'] === 'tag-record') {
            $store = $this->store($namespace);
            $reply = $store->assessV2WithReply(
                $this->observation(self::hex('tag-'.$job['tag']), RiskEventKind::PreIssue),
                (string) $job['tag'],
                null,
                null,
            );

            return ['existing' => $reply->existingContextTag];
        }

        if ($job['op'] === 'report-target-failure') {
            $store = $this->store($namespace);
            $outcomes = new KiwiOutcomes($this->engine($store), $store);
            $receipt = $outcomes->report(
                Outcome::AuthenticationFailure,
                OutcomeHandle::target(self::TARGET),
                'webhook-delivery-1',
                $this->context(RiskEventKind::AuthenticationFailure),
            );

            return ['booked' => $receipt->channelBooked];
        }

        if ($job['op'] === 'step-up-sharded') {
            $store = $this->shardedStore($namespace);
            $vector = $store->observe($this->stepUpObservation('sharded-step-up'));

            return ['trustCredit' => $vector->trustCredit, 'principalCredit' => $vector->principalCredit];
        }

        if ($job['op'] === 'ledger-score' || $job['op'] === 'ledger-score-honeypot') {
            $store = $this->store($namespace);
            $event = $job['op'] === 'ledger-score-honeypot'
                ? RiskEventKind::HoneypotTriggered
                : RiskEventKind::from((int) $job['event']);
            $engine = $this->engine($store, $this->resolver());
            $decision = $engine->assessPreIssue($this->context($event, withTarget: true));
            $ledger = json_decode((string) $client->get($store->ledgerKey($decision->decisionId)), true);

            return [
                'registered' => \is_array($ledger) && ($ledger['o'] ?? null) === 'P',
                'decisionScore' => $decision->score,
                'ledgerScore' => (int) ($ledger['score'] ?? -1),
            ];
        }

        if ($job['op'] === 'ledger-score-sharded') {
            $store = $this->shardedStore($namespace);
            $engine = $this->engine($store, $this->resolver());
            $decision = $engine->assessPreIssue($this->context(RiskEventKind::PreIssue, withTarget: true));
            $ledger = json_decode(
                (string) $client->get(KeyspaceMode::outcomeLedgerKey($store->namespace(), $decision->decisionId)),
                true,
            );

            return [
                'registered' => \is_array($ledger) && ($ledger['o'] ?? null) === 'P',
                'decisionScore' => $decision->score,
                'ledgerScore' => (int) ($ledger['score'] ?? -1),
            ];
        }

        throw new \RuntimeException('unknown op '.$job['op']);
    }
}
