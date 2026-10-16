<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedPostSolveDispositionException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveFinalizeOutcome;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

/**
 * The quarantine disposition under real process concurrency.
 *
 * The final disposition of a verified proof is claimed once per nonce and
 * persisted as one complete record. The quarantine disposition rides that
 * record as an additive flag on the pass kind, so a replay withholds the
 * same submission instead of publishing it. This suite spawns independent
 * worker processes through proc_open, each with its own Predis
 * connection, released on one wall-clock barrier, and races the claim,
 * the finalize and the transaction acceptance guard against each other.
 *
 * The invariants. One claim owner per nonce, the expired-lease takeover
 * included. One complete disposition per nonce. A completed record is
 * terminal and never redirected by a takeover. The refusals perform no
 * write and never consume the decision mapping. A quarantined pass is
 * refused once the transaction escalated. A stored hold replays only
 * while the transaction still authorizes it.
 *
 * Runs in the real-Redis lane (`KC_REDIS_URL` / `TEST_REDIS_URL`) and
 * skips cleanly otherwise, like every other real-Redis suite.
 */
final class RealRedisQuarantineDispositionConcurrencyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The independent OS worker processes per race. */
    private const WORKERS = 8;

    /** The seconds every worker busy-waits before firing. */
    private const START_DELAY = 1.5;

    /** The store-level record lifetime used by this suite. */
    private const TTL_SECS = 300;

    /** The documented claim outcome set. */
    private const CLAIM_VOCABULARY = ['claimed', 'pending', 'taken_over', 'complete'];

    private string $url = '';

    private string $namespace = '';

    /** @var list<resource> */
    private array $procs = [];

    private string $tmpDir = '';

    private string $workerPath = '';

    protected function setUp(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();
            $probe->disconnect();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured URL — start one for the quarantine disposition suite');
        }
        $this->url = $url;
        $this->namespace = 'quarantineconc'.bin2hex(random_bytes(4));

        $autoload = \dirname(__DIR__).'/vendor/autoload.php';
        self::assertFileExists($autoload, 'the bundle autoloader must exist for the spawned workers');
        $this->tmpDir = sys_get_temp_dir().'/kiwi-quarantine-conc-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the concurrency scratch directory');
        }
        $this->workerPath = $this->tmpDir.'/worker.php';
        file_put_contents($this->workerPath, $this->workerSource());
    }

    protected function tearDown(): void
    {
        foreach ($this->procs as $proc) {
            $status = proc_get_status($proc);
            if ($status !== false && $status['running']) {
                proc_terminate($proc, 9);
            }
            proc_close($proc);
        }
        $this->procs = [];
        if ($this->namespace !== '') {
            try {
                $client = new \Predis\Client($this->url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
                $keys = $client->keys('{kiwi:'.$this->namespace.'}:*');
                if (\is_array($keys) && $keys !== []) {
                    $client->del(...$keys);
                }
                $client->disconnect();
            } catch (\Throwable) {
                // a dead instance must not fail the shutdown path
            }
        }
        if ($this->tmpDir !== '' && is_dir($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
        $this->tmpDir = '';
    }

    // ------------------------------------------------------------------
    // One claim owner per nonce
    // ------------------------------------------------------------------

    public function testConcurrentClaimsHaveExactlyOneWinner(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('claim');
        $decisionKey = $this->decisionKey($nonce);
        $client->set($decisionKey, json_encode(['decision_id' => 'decision-claim'], JSON_THROW_ON_ERROR));

        $rows = $this->runRace($this->claimJobs($nonce, 'claim-owner-', $decisionKey));
        $this->assertEveryWorkerReported($rows);

        $claimed = 0;
        $pending = 0;
        $carried = null;
        foreach ($rows as $row) {
            $result = $row['results'][0];
            self::assertContains($result['status'], self::CLAIM_VOCABULARY, 'the claim outcome is from the documented set: '.$result['status']);
            self::assertSame('finalized', $result['guard'], 'a fresh claim carries the pass-through guard');
            if ($result['status'] === 'claimed') {
                $claimed++;
                $carried = $result['recordDecisionId'];
            } else {
                $pending++;
                self::assertNull($result['kind'], 'a busy claim carries no record');
            }
        }
        self::assertSame(1, $claimed, 'exactly one of the '.self::WORKERS.' concurrent claims may win');
        self::assertSame(self::WORKERS - 1, $pending, 'every other concurrent claim is the retryable busy answer');
        self::assertSame('decision-claim', $carried, 'the winner carries the consumed decision handle');
        self::assertFalse((bool) $client->exists($decisionKey), 'the decision mapping is consumed exactly once');

        $record = $store->read($nonce);
        self::assertSame('pending', $record?->state, 'the record is pending after the race');
        self::assertSame('decision-claim', $record?->decisionId, 'the pending record carries the original handle');
    }

    public function testTakeoverOfAnExpiredLeaseHasExactlyOneWinner(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('takeover');
        $client->set($this->key($nonce), json_encode([
            'v' => 1,
            'state' => 'pending',
            'owner' => 'owner-dead',
            'lease_until' => time() - 5,
            'disposition' => null,
            'decision_id' => 'decision-takeover',
        ], JSON_THROW_ON_ERROR), 'EX', self::TTL_SECS);

        $rows = $this->runRace($this->claimJobs($nonce, 'takeover-owner-'));
        $this->assertEveryWorkerReported($rows);

        $takeovers = 0;
        $winner = null;
        foreach ($rows as $i => $row) {
            $result = $row['results'][0];
            self::assertContains($result['status'], ['pending', 'taken_over'], 'the lapsed record answers the takeover pair: '.$result['status']);
            if ($result['status'] === 'taken_over') {
                $takeovers++;
                $winner = 'takeover-owner-'.$i;
                self::assertSame('decision-takeover', $result['recordDecisionId'], 'the takeover preserves the original decision handle');
            }
        }
        self::assertSame(1, $takeovers, 'exactly one concurrent claim may take over the lapsed lease');

        $record = $store->read($nonce);
        self::assertSame($winner, $record?->owner, 'the record is transferred to the one takeover winner');
        self::assertSame('decision-takeover', $record?->decisionId, 'the handle survives the owner transfer');
    }

    public function testACompletedQuarantinedHoldIsTerminalUnderConcurrentClaims(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('terminal');
        [$chainId] = $this->issuedChain($client, 'terminal', $nonce);
        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-hold', quarantined: true)));
        $before = (string) $client->get($this->key($nonce));

        $decisionKey = $this->decisionKey($nonce);
        $client->set($decisionKey, json_encode(['decision_id' => 'decision-late'], JSON_THROW_ON_ERROR));

        $rows = $this->runRace($this->claimJobs($nonce, 'late-owner-'));
        $this->assertEveryWorkerReported($rows);

        foreach ($rows as $row) {
            $result = $row['results'][0];
            self::assertSame('complete', $result['status'], 'a completed disposition is terminal for every claimant');
            self::assertSame('pass', $result['kind'], 'the completed record carries the pass kind');
            self::assertTrue($result['quarantined'], 'the completed record carries the quarantine hold');
            self::assertSame('decision-hold', $result['dispositionDecisionId'], 'the completed record carries its original handle');
        }
        self::assertSame($before, (string) $client->get($this->key($nonce)), 'the terminal record is never rewritten');
        self::assertGreaterThan(0, (int) $client->pttl($this->key($nonce)), 'the hold keeps its key lifetime through the race');
        self::assertTrue((bool) $client->exists($decisionKey), 'a complete claim never consumes the fresh decision mapping');
        // The chain state stands untouched by the disposition claims.
        self::assertSame('issued', (new RedisChainedChallengeStateStore($client, $this->namespace))->read($chainId)['state'] ?? null);
    }

    // ------------------------------------------------------------------
    // One complete disposition per nonce
    // ------------------------------------------------------------------

    public function testConcurrentFinalizesLeaveExactlyOneDisposition(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('finalize');
        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            // The guarded finalize without a wired obligation: the
            // acceptance runs the same typed record checks, and the
            // concurrent losers exercise the completed-record branch.
            $jobs[] = ['calls' => [['op' => 'finalize', 'args' => [
                'nonce' => $nonce,
                'owner' => 'owner-w',
                'kind' => $i % 2 === 0 ? 'pass' : 'deny',
                'guarded' => true,
            ]]]];
        }
        $rows = $this->runRace($jobs);
        $this->assertEveryWorkerReported($rows);

        $finalized = 0;
        $winnerKind = null;
        foreach ($rows as $i => $row) {
            $result = $row['results'][0];
            if (($result['outcome'] ?? null) === 'finalized') {
                $finalized++;
                $winnerKind = $i % 2 === 0 ? 'pass' : 'deny';
            } else {
                self::assertSame('ownership-lost', $result['outcome'] ?? null, 'a concurrent finalize loser answers the lost claim');
            }
        }
        self::assertSame(1, $finalized, 'exactly one concurrent finalize may commit the disposition');

        $record = $store->read($nonce);
        self::assertSame('complete', $record?->state, 'the record is complete after the race');
        self::assertSame($winnerKind, $record?->disposition?->kind->value, 'the persisted kind is the winner kind');
    }

    public function testAConcurrentFinalizeLoserNeverRewritesTheRecord(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('loser');
        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-first', quarantined: true)));
        $before = (string) $client->get($this->key($nonce));

        // The guarded retry of a claim that already completed: the store
        // answers the same typed refusal the in-memory store answers.
        $outcome = $store->finalizeGuarded($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Deny), null, null, null);
        self::assertSame(PostSolveFinalizeOutcome::OwnershipLost, $outcome, 'a completed record is a lost claim, never a schema corruption');

        $array = new ArrayPostSolveDispositionStore();
        self::assertSame('claimed', $array->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        self::assertTrue($array->finalize($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        self::assertSame(
            $outcome,
            $array->finalizeGuarded($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Deny), null, null, null),
            'Redis and the in-memory store answer the same typed refusal for one record state',
        );

        self::assertSame($before, (string) $client->get($this->key($nonce)), 'the refused finalize performs zero mutation');
        self::assertSame('decision-first', $store->read($nonce)?->disposition?->decisionId, 'the completed disposition is the first writer disposition');
    }

    // ------------------------------------------------------------------
    // The acceptance guard against a concurrent escalation
    // ------------------------------------------------------------------

    public function testAQuarantinedPassIsRefusedWhenTheTransactionEscalatedFirst(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('guard');
        [$chainId, $obligationId] = $this->issuedChain($client, 'guard', $nonce);
        $chain = new RedisChainedChallengeStateStore($client, $this->namespace);

        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        self::assertSame('step_up_required_new', $chain->markTransactionStepUpRequired($chainId, $obligationId));

        $outcome = $store->finalizeGuarded(
            $nonce,
            'owner-w',
            new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-guard', quarantined: true),
            $obligationId,
            $chainId,
            $nonce,
        );
        self::assertSame(PostSolveFinalizeOutcome::TransactionStepUp, $outcome, 'a terminal escalation refuses the stale quarantined pass');
        self::assertSame('pending', $store->read($nonce)?->state, 'the refused acceptance writes no disposition');
        self::assertSame($nonce, $chain->read($chainId)['stage2Nonce'] ?? null, 'the terminal chain keeps its stage-2 nonce');
    }

    public function testAStoredQuarantinedHoldIsNeverReplayedAfterATerminalEscalation(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('replay-terminal');
        [$chainId, $obligationId] = $this->issuedChain($client, 'replay-terminal', $nonce);
        $chain = new RedisChainedChallengeStateStore($client, $this->namespace);

        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-replay', quarantined: true)));
        self::assertSame('step_up_required_new', $chain->markTransactionStepUpRequired($chainId, $obligationId));

        [$status, , $guard] = $store->claim($nonce, 'replay-owner', self::TTL_SECS, null, $obligationId, $chainId, $nonce);
        self::assertSame('complete', $status, 'the record itself is still complete');
        self::assertSame(PostSolveFinalizeOutcome::TransactionStepUp, $guard, 'the terminal escalation dominates the stored hold on every replay');
        self::assertSame('pass', $store->read($nonce)?->disposition?->kind->value, 'the store never rewrites the historical record');
    }

    public function testAStoredQuarantinedHoldReplaysWhenThePassClearedTheObligation(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('replay-pass');
        $chainId = $this->issuedChain($client, 'replay-pass', $nonce)[0];
        $chain = new RedisChainedChallengeStateStore($client, $this->namespace);

        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-hold', quarantined: true)));
        self::assertSame('verified_new', $chain->markVerified($chainId, $nonce));

        // The replay snapshot of a passed transaction finds no open chain.
        [$status, $record, $guard] = $store->claim($nonce, 'replay-owner', self::TTL_SECS, null, null, null, null);
        self::assertSame('complete', $status);
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $guard, 'a cleared obligation authorizes the stored pass');
        self::assertSame('pass', $record?->disposition?->kind->value);
        self::assertTrue($record?->disposition?->quarantined, 'the replay reproduces the hold instead of publishing');
    }

    public function testAPassWhoseChainMovedAfterTheFinalizeIsReDemandedOnRetry(): void
    {
        $client = $this->client();
        $store = $this->store($client);
        $nonce = self::nonce('two-moves');
        [$chainId, $obligationId] = $this->issuedChain($client, 'two-moves', $nonce);
        $chain = new RedisChainedChallengeStateStore($client, $this->namespace);

        // Move one: the disposition is durably accepted while the chain
        // still authorizes this nonce.
        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        $accepted = $store->finalizeGuarded(
            $nonce,
            'owner-w',
            new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-two-moves', quarantined: true),
            $obligationId,
            $chainId,
            $nonce,
        );
        self::assertSame(PostSolveFinalizeOutcome::Finalized, $accepted, 'the authorized acceptance commits');

        // Move two is refused: another request rearmed the chain before
        // the stage-2 transition ran, so the exact nonce is no longer
        // issuable and the obligation must not be cleared.
        self::assertTrue($chain->rearmIssued($chainId, $nonce), 'a concurrent request rearms the issued chain');
        self::assertSame('conflict', $chain->markVerified($chainId, $nonce), 'the stage-2 transition is refused after the rearm');
        self::assertSame($chainId, $chain->obligationChainId($obligationId), 'the refused transition leaves the obligation bound');

        // The retry never replays the persisted pass over the moved
        // chain: the claim's guard re-resolves the chain and demands the
        // fresh stage.
        [$status, , $guard] = $store->claim($nonce, 'retry-owner', self::TTL_SECS, null, $obligationId, $chainId, $nonce);
        self::assertSame('complete', $status, 'the accepted record itself stands');
        self::assertSame(PostSolveFinalizeOutcome::ChainRequired, $guard, 'the moved chain defeats the stored pass on the retry');
    }

    // ------------------------------------------------------------------
    // The quarantine flag stays on the pass kind
    // ------------------------------------------------------------------

    public function testAQuarantinedFlagOutsideThePassKindIsRefusedAtEveryBoundary(): void
    {
        $client = $this->client();
        $store = $this->store($client);

        // The write path: the typed disposition refuses the combination
        // before any store call, in both stores.
        foreach ([$store, new ArrayPostSolveDispositionStore()] as $target) {
            try {
                $nonce = self::nonce('wire');
                self::assertSame('claimed', $target->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
                $target->finalize($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Deny, quarantined: true));
                self::fail('a quarantined deny disposition must be refused before any write');
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('rides the Pass kind only', $e->getMessage());
            }
        }

        // The wire path: a tampered complete record carrying the flag on a
        // denied kind is corruption, never a hold or a denied pass.
        $nonce = self::nonce('wire-tamper');
        self::assertSame('claimed', $store->claim($nonce, 'owner-w', self::TTL_SECS)[0]);
        self::assertTrue($store->finalize($nonce, 'owner-w', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-wire')));
        $raw = (string) $client->get($this->key($nonce));
        $tampered = str_replace('"kind":"pass"', '"kind":"deny","quarantined":true', $raw);
        self::assertNotSame($raw, $tampered, 'the tamper applies');
        $client->set($this->key($nonce), $tampered, 'EX', self::TTL_SECS);

        try {
            $store->read($nonce);
            self::fail('a quarantined non-pass record must fail closed');
        } catch (MalformedPostSolveDispositionException) {
            // the strict decode refuses it
        }
        try {
            $store->claim($nonce, 'owner-x', self::TTL_SECS);
            self::fail('the claim must refuse a quarantined non-pass record');
        } catch (MalformedPostSolveDispositionException) {
            // the strict validation runs inside the claim too
        }
        self::assertSame($tampered, (string) $client->get($this->key($nonce)), 'every refusal leaves the record untouched');
    }

    // ------------------------------------------------------------------
    // Fixtures and the harness
    // ------------------------------------------------------------------

    /**
     * A chain in the issued state under its obligation mapping: the exact
     * state a stage-2 verification observes.
     *
     * @return array{0: string, 1: string} the chain id and the obligation id
     */
    private function issuedChain(\Predis\Client $client, string $tag, string $stage2Nonce): array
    {
        // The chain store and the disposition store share the deployment
        // namespace, so the acceptance guard reads the same chain keys.
        $store = new RedisChainedChallengeStateStore($client, $this->namespace);
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
        $requirement = $service->requireStage2(self::nonce($tag.'-stage1'), 'login', 'txn-'.$tag, 1, RiskAction::Sha16, time() + 300);
        $obligationId = $service->obligationIdFor('login', 'txn-'.$tag, 1);
        self::assertSame('available', $store->reserve($requirement->chainId, 'mint-owner', 15));
        self::assertSame('issued_new', $store->markIssued($requirement->chainId, 'mint-owner', $stage2Nonce));

        return [$requirement->chainId, $obligationId];
    }

    /**
     * @return list<array{calls: list<array{op: string, args: array<string, mixed>}>}>
     */
    private function claimJobs(string $nonce, string $ownerPrefix, ?string $decisionKey = null): array
    {
        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $args = ['nonce' => $nonce, 'owner' => $ownerPrefix.$i];
            if ($decisionKey !== null) {
                $args['decisionKey'] = $decisionKey;
            }
            $jobs[] = ['calls' => [['op' => 'claim', 'args' => $args]]];
        }

        return $jobs;
    }

    private function store(\Predis\Client $client): RedisPostSolveDispositionStore
    {
        return new RedisPostSolveDispositionStore($client, $this->namespace, self::TTL_SECS);
    }

    private function client(): \Predis\Client
    {
        return new \Predis\Client($this->url, ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
    }

    private function key(string $nonce): string
    {
        return '{kiwi:'.$this->namespace.'}:postsolve:'.$nonce;
    }

    private function decisionKey(string $nonce): string
    {
        return '{kiwi:'.$this->namespace.'}:decision:'.$nonce;
    }

    /** A deterministic Kiwi-shaped challenge nonce for a seed. */
    private static function nonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'quarantine-disposition:'.$seed, true));
    }

    /**
     * Spawn the workers, release them on the shared barrier, and return
     * the decoded per-worker result rows in spawn order.
     *
     * @param list<array{calls: list<array{op: string, args: array<string, mixed>}>}> $jobs
     *
     * @return list<array<string, mixed>>
     */
    private function runRace(array $jobs): array
    {
        $startAt = microtime(true) + self::START_DELAY;
        $outs = [];
        foreach ($jobs as $i => $job) {
            $out = $this->tmpDir.'/out-'.$i.'-'.bin2hex(random_bytes(3)).'.json';
            $outs[$i] = $out;
            $job['out'] = $out;
            $job['startAt'] = $startAt;
            $job['url'] = $this->url;
            $job['namespace'] = $this->namespace;
            $job['autoload'] = \dirname(__DIR__).'/vendor/autoload.php';
            $jobPath = $out.'.job.json';
            file_put_contents($jobPath, json_encode($job, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

            $proc = proc_open(
                [\PHP_BINARY, $this->workerPath, $jobPath],
                [
                    0 => ['pipe', 'r'],
                    1 => ['file', $out.'.log', 'a'],
                    2 => ['file', $out.'.log', 'a'],
                ],
                $pipes,
            );
            if (!\is_resource($proc)) {
                self::fail('failed to spawn a quarantine disposition worker');
            }
            fclose($pipes[0]);
            $this->procs[] = $proc;
        }

        $exits = [];
        foreach ($this->procs as $i => $proc) {
            $exits[$i] = proc_close($proc);
        }
        $this->procs = [];

        $decoded = [];
        foreach ($outs as $i => $out) {
            $raw = is_file($out) ? (string) file_get_contents($out) : '';
            if ($raw === '') {
                $log = is_file($out.'.log') ? (string) file_get_contents($out.'.log') : '(no log)';
                self::fail('worker '.$i.' produced no result (exit '.($exits[$i] ?? '?').'); log: '.$log);
            }
            $row = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($row);
            $decoded[] = $row;
        }

        return $decoded;
    }

    /** @param list<array<string, mixed>> $rows */
    private function assertEveryWorkerReported(array $rows): void
    {
        foreach ($rows as $i => $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$i.' failed: '.json_encode($row));
            self::assertTrue($row['ok'] ?? false, 'worker '.$i.' did not finish its calls: '.json_encode($row));
            self::assertIsArray($row['results'] ?? null, 'worker '.$i.' reports its per-call results');
        }
    }

    private function removeDir(string $dir): void
    {
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir.'/'.$item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * The worker script: a self-contained PHP process that connects with
     * its own Predis client, waits at the shared barrier, runs its call
     * list against one disposition store, and writes a JSON result row.
     */
    private function workerSource(): string
    {
        return <<<'PHP'
<?php

declare(strict_types=1);

$job = json_decode((string) @file_get_contents($argv[1] ?? ''), true, 512, JSON_THROW_ON_ERROR);
require $job['autoload'];

$out = ['ok' => false];
try {
    $client = new \Predis\Client($job['url'], ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
    $client->ping();
    $store = new \BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore($client, $job['namespace'], 300);

    $startAt = (float) $job['startAt'];
    while (microtime(true) < $startAt) {
        usleep(100);
    }

    $results = [];
    foreach ($job['calls'] as $call) {
        $delay = (int) ($call['delayMs'] ?? 0);
        if ($delay > 0) {
            usleep($delay * 1000);
        }
        if (!isset($call['op']) || $call['op'] === '') {
            continue;
        }
        $args = $call['args'] ?? [];
        if ($call['op'] === 'claim') {
            [$status, $record, $guard] = $store->claim(
                $args['nonce'],
                $args['owner'],
                300,
                $args['decisionKey'] ?? null,
                $args['obligationId'] ?? null,
                $args['snapshotChainId'] ?? null,
                $args['expectedStage2Nonce'] ?? null,
            );
            $results[] = [
                'status' => $status,
                'guard' => $guard->value,
                'kind' => $record?->disposition?->kind->value,
                'quarantined' => $record?->disposition?->quarantined,
                'dispositionDecisionId' => $record?->disposition?->decisionId,
                'recordDecisionId' => $record?->decisionId,
            ];
            continue;
        }
        if ($call['op'] === 'finalize') {
            $disposition = new \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition(
                \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::from($args['kind']),
                null,
                null,
                null,
                (bool) ($args['quarantined'] ?? false),
            );
            if ($args['guarded'] ?? false) {
                $results[] = ['outcome' => $store->finalizeGuarded(
                    $args['nonce'],
                    $args['owner'],
                    $disposition,
                    $args['obligationId'] ?? null,
                    $args['snapshotChainId'] ?? null,
                    $args['expectedStage2Nonce'] ?? null,
                )->value];
            } else {
                $results[] = ['finalized' => $store->finalize($args['nonce'], $args['owner'], $disposition)];
            }
            continue;
        }
        throw new \RuntimeException('unknown op '.(string) $call['op']);
    }
    $out['results'] = $results;
    $out['ok'] = true;
} catch (\Throwable $e) {
    $out['error'] = get_class($e).': '.$e->getMessage();
}
file_put_contents($job['out'], json_encode($out, JSON_THROW_ON_ERROR));
PHP;
    }
}
