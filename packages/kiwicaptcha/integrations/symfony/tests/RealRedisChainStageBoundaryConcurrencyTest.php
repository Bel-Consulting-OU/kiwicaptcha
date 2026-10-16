<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

/**
 * The chained-challenge stage boundaries under real process concurrency.
 *
 * The chained transaction is a reservation, then an issue, then a verify,
 * with a stage obligation that clears atomically. Every one of those
 * boundaries is a single Lua transition on real Redis, and the store
 * layers owner tokens, leases and monotonic requirement generations on
 * top. A single PHP process cannot lose an update, because one
 * connection serializes its own commands. This suite therefore spawns
 * independent worker processes through proc_open, each with its own
 * Predis connection, all released on one wall-clock barrier, and judges
 * the boundaries where they actually matter.
 *
 * The invariants. One reservation wins a stage. One nonce installs per
 * issuance generation. A reservation lease that lapsed can never let its
 * former owner install over the takeover winner. The verify clears the
 * obligation exactly once with the state flip. One proof advances one
 * stage. A terminal state is absorbing under concurrent retries.
 *
 * Runs in the real-Redis lane (`KC_REDIS_URL` / `TEST_REDIS_URL`) and
 * skips cleanly otherwise, like every other real-Redis suite.
 */
final class RealRedisChainStageBoundaryConcurrencyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The independent OS worker processes per race. */
    private const WORKERS = 8;

    /**
     * The seconds every worker busy-waits before firing, so all commands
     * reach Redis as close to simultaneously as the OS allows. Covers the
     * PHP and Predis startup cost of the last spawned worker.
     */
    private const START_DELAY = 1.5;

    /** The documented reservation outcome set. */
    private const RESERVE_VOCABULARY = ['available', 'retry', 'busy', 'taken_over', 'issued', 'verified', 'completed', 'step_up_required', 'denied', 'missing'];

    /** The documented issuance outcome set. */
    private const ISSUE_VOCABULARY = ['issued_new', 'issued_same', 'verified_same', 'conflict', 'not_owner', 'missing', 'stale_requirement'];

    /** The documented verification outcome set. */
    private const VERIFY_VOCABULARY = ['verified_new', 'verified_same', 'conflict', 'missing'];

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
            self::markTestSkipped('no Redis at the configured URL — start one for the chain boundary suite');
        }
        $this->url = $url;
        $this->namespace = 'chainboundary'.bin2hex(random_bytes(4));

        $autoload = \dirname(__DIR__).'/vendor/autoload.php';
        self::assertFileExists($autoload, 'the bundle autoloader must exist for the spawned workers');
        $this->tmpDir = sys_get_temp_dir().'/kiwi-chain-boundary-'.bin2hex(random_bytes(6));
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
                $keys = $client->keys($this->namespacePattern());
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
    // One reservation wins one stage
    // ------------------------------------------------------------------

    public function testConcurrentReservationsLeaveExactlyOneStageWinner(): void
    {
        $client = $this->client();
        [$chainId] = $this->freshChain($client, 'reserve');

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $jobs[] = ['calls' => [['op' => 'reserve', 'args' => ['chainId' => $chainId, 'owner' => 'owner-'.$i, 'leaseSecs' => 15]]]];
        }
        $rows = $this->runRace($jobs);
        $this->assertEveryWorkerReported($rows);

        $winners = [];
        foreach ($rows as $i => $row) {
            $outcome = (string) $row['results'][0];
            self::assertContains($outcome, self::RESERVE_VOCABULARY, 'the reservation outcome is from the documented set: '.$outcome);
            if ($outcome === 'available') {
                $winners[] = 'owner-'.$i;
            }
        }
        self::assertCount(
            1,
            $winners,
            'exactly one of the '.self::WORKERS.' concurrent reservations may win the stage, got '.count($winners).' winners',
        );

        $record = $this->store($client)->read($chainId);
        self::assertIsArray($record, 'the chain record survives the race');
        self::assertSame('reserved', $record['state'], 'the stage is reserved after the race');
        self::assertSame($winners[0], $record['owner'], 'the record is held by the one reservation winner');
    }

    // ------------------------------------------------------------------
    // One nonce installs per issuance generation
    // ------------------------------------------------------------------

    public function testConcurrentIssuanceInstallsExactlyOneNonce(): void
    {
        $client = $this->client();
        [$chainId] = $this->freshChain($client, 'issue');
        $store = $this->store($client);
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));

        $nonces = [];
        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $nonce = self::nonce('issue-'.$i);
            $nonces[$i] = $nonce;
            $jobs[] = ['calls' => [['op' => 'issue', 'args' => ['chainId' => $chainId, 'owner' => 'owner-a', 'nonce' => $nonce]]]];
        }
        $rows = $this->runRace($jobs);
        $this->assertEveryWorkerReported($rows);

        $installed = [];
        $fresh = 0;
        foreach ($rows as $i => $row) {
            $outcome = (string) $row['results'][0];
            self::assertContains($outcome, self::ISSUE_VOCABULARY, 'the issuance outcome is from the documented set: '.$outcome);
            if ($outcome === 'issued_new') {
                $fresh++;
                $installed[] = $nonces[$i];
            }
        }
        self::assertSame(1, $fresh, 'exactly one fresh issuance may install a stage-2 nonce');
        self::assertCount(1, $installed, 'the winner is identified');

        $record = $store->read($chainId);
        self::assertIsArray($record);
        self::assertSame('issued', $record['state'], 'the chain is issued after the race');
        self::assertSame($installed[0], $record['stage2Nonce'], 'the installed nonce is exactly the winner nonce');
    }

    public function testConcurrentSameNonceRetriesAreIdempotent(): void
    {
        $client = $this->client();
        [$chainId] = $this->freshChain($client, 'retry');
        $store = $this->store($client);
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $nonce = self::nonce('retry');

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $jobs[] = ['calls' => [['op' => 'issue', 'args' => ['chainId' => $chainId, 'owner' => 'owner-a', 'nonce' => $nonce]]]];
        }
        $rows = $this->runRace($jobs);
        $this->assertEveryWorkerReported($rows);

        $fresh = 0;
        foreach ($rows as $row) {
            $outcome = (string) $row['results'][0];
            self::assertContains($outcome, ['issued_new', 'issued_same'], 'a same-nonce retry answers the idempotent pair: '.$outcome);
            if ($outcome === 'issued_new') {
                $fresh++;
            }
        }
        self::assertSame(1, $fresh, 'one transition performs the state change');

        $record = $store->read($chainId);
        self::assertSame('issued', $record['state'] ?? null);
        self::assertSame($nonce, $record['stage2Nonce'] ?? null, 'the retries converge on the same installed nonce');
    }

    // ------------------------------------------------------------------
    // An issue racing its reservation expiry
    // ------------------------------------------------------------------

    public function testAnIssuePastItsReservationLeaseNeverInstallsOverATakeover(): void
    {
        $client = $this->client();
        [$chainId] = $this->freshChain($client, 'lease');
        $store = $this->store($client);
        // The short lease lapses well before either worker fires.
        self::assertSame('available', $store->reserve($chainId, 'owner-early', 1));

        $nonceLate = self::nonce('lease-late');
        $nonceEarly = self::nonce('lease-early');
        $jobs = [
            // After the lease lapsed: the takeover owner reserves and issues.
            ['calls' => [
                ['delayMs' => 1500],
                ['op' => 'reserve', 'args' => ['chainId' => $chainId, 'owner' => 'owner-late', 'leaseSecs' => 15]],
                ['op' => 'issue', 'args' => ['chainId' => $chainId, 'owner' => 'owner-late', 'nonce' => $nonceLate]],
            ]],
            // The lapsed reservation's former owner issues after the takeover.
            ['calls' => [
                ['delayMs' => 2500],
                ['op' => 'issue', 'args' => ['chainId' => $chainId, 'owner' => 'owner-early', 'nonce' => $nonceEarly]],
            ]],
        ];
        $rows = $this->runRace($jobs, workerCount: 2);
        $this->assertEveryWorkerReported($rows);

        $takeover = $rows[0]['results'];
        $lapsed = $rows[1]['results'];
        $record = $store->read($chainId);
        $installed = $record['stage2Nonce'] ?? null;
        self::assertContains($installed, [$nonceLate, $nonceEarly], 'exactly one of the two racing nonces is installed');

        if ($installed === $nonceLate) {
            // The takeover leg won the ordering: the lapsed lease was
            // claimed before the former owner issued.
            self::assertSame('taken_over', $takeover[0], 'the lapsed lease is taken over after its expiry');
            self::assertSame('issued_new', $takeover[1], 'the takeover owner installs its nonce');
            self::assertContains($lapsed[0], ['not_owner', 'conflict', 'missing'], 'the lapsed former owner can never install over the takeover: '.$lapsed[0]);
        } else {
            // The former owner issued inside the lapsed-lease window
            // before any takeover: the takeover leg then refuses to
            // overwrite the installed nonce.
            self::assertSame('issued_new', $lapsed[0], 'the former owner issued before the takeover landed');
            self::assertContains($takeover[1], ['conflict', 'issued_same'], 'the takeover owner never replaces the installed nonce: '.$takeover[1]);
            self::assertContains($takeover[0], ['issued', 'verified', 'completed'], 'the takeover leg observes the issued chain: '.$takeover[0]);
        }

        // The lapsed owner stays locked out for the rest of the
        // generation, whatever the ordering was.
        $extra = self::nonce('lease-extra');
        self::assertContains($store->markIssued($chainId, 'owner-early', $extra), ['not_owner', 'conflict'], 'a lapsed reservation holder never installs a further nonce');
        self::assertSame($installed, $store->read($chainId)['stage2Nonce'] ?? null, 'the installed nonce is immutable under the refused issuance');
    }

    // ------------------------------------------------------------------
    // The verify clears the obligation and flips the state together
    // ------------------------------------------------------------------

    public function testConcurrentVerificationClearsTheObligationExactlyOnce(): void
    {
        $client = $this->client();
        [$chainId, $obligationId] = $this->freshChain($client, 'verify');
        $store = $this->store($client);
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $nonce = self::nonce('verify');
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $jobs[] = ['calls' => [['op' => 'verify', 'args' => ['chainId' => $chainId, 'nonce' => $nonce]]]];
        }
        $rows = $this->runRace($jobs);
        $this->assertEveryWorkerReported($rows);

        $fresh = 0;
        foreach ($rows as $row) {
            $outcome = (string) $row['results'][0];
            self::assertContains($outcome, self::VERIFY_VOCABULARY, 'the verification outcome is from the documented set: '.$outcome);
            if ($outcome === 'verified_new') {
                $fresh++;
            }
        }
        self::assertSame(1, $fresh, 'exactly one verification performs the terminal transition');

        $record = $store->read($chainId);
        self::assertSame('verified', $record['state'] ?? null, 'the terminal state is verified');
        self::assertSame($nonce, $record['stage2Nonce'] ?? null, 'the verified record keeps the exact nonce');
        self::assertNull($store->obligationChainId($obligationId), 'the obligation mapping is cleared exactly once with the state flip');
    }

    public function testVerifyRacingTransactionTerminalizationKeepsOneTerminalState(): void
    {
        $client = $this->client();
        [$chainId, $obligationId] = $this->freshChain($client, 'terminal');
        $store = $this->store($client);
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $nonce = self::nonce('terminal');
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));

        $rows = $this->runRace([
            ['calls' => [['op' => 'verify', 'args' => ['chainId' => $chainId, 'nonce' => $nonce]]]],
            ['calls' => [['op' => 'txDenied', 'args' => ['chainId' => $chainId, 'obligationId' => $obligationId]]]],
            ['calls' => [['op' => 'txStepUp', 'args' => ['chainId' => $chainId, 'obligationId' => $obligationId]]]],
        ], workerCount: 3);
        $this->assertEveryWorkerReported($rows);

        $record = $store->read($chainId);
        $state = $record['state'] ?? null;
        self::assertContains($state, ['verified', 'denied', 'step_up_required'], 'the chain ends in one terminal state');
        $mapped = $store->obligationChainId($obligationId);
        if ($state === 'verified') {
            self::assertNull($mapped, 'a verified state comes with the cleared obligation');
        } else {
            self::assertSame($chainId, $mapped, 'a disposition terminal state keeps the obligation bound');
        }

        $newOutcomes = 0;
        foreach ($rows as $row) {
            $outcome = (string) $row['results'][0];
            if (\in_array($outcome, ['verified_new', 'denied_new', 'step_up_required_new'], true)) {
                $newOutcomes++;
            }
        }
        self::assertSame(1, $newOutcomes, 'exactly one terminal transition is performed');
    }

    public function testTerminalStatesAreAbsorbingUnderConcurrentRetries(): void
    {
        $client = $this->client();
        [$chainId, $obligationId] = $this->freshChain($client, 'absorb');
        $store = $this->store($client);
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $nonce = self::nonce('absorb');
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertSame('verified_new', $store->markVerified($chainId, $nonce));

        $rows = $this->runRace([
            ['calls' => [['op' => 'verify', 'args' => ['chainId' => $chainId, 'nonce' => $nonce]]]],
            ['calls' => [['op' => 'issue', 'args' => ['chainId' => $chainId, 'owner' => 'owner-b', 'nonce' => self::nonce('absorb-b')]]]],
            ['calls' => [['op' => 'rearm', 'args' => ['chainId' => $chainId, 'nonce' => $nonce]]]],
            ['calls' => [['op' => 'reserve', 'args' => ['chainId' => $chainId, 'owner' => 'owner-c', 'leaseSecs' => 15]]]],
        ], workerCount: 4);
        $this->assertEveryWorkerReported($rows);

        self::assertContains((string) $rows[0]['results'][0], ['verified_same', 'conflict'], 'the retry confirms or refuses, never re-mints');
        self::assertContains((string) $rows[1]['results'][0], ['verified_same', 'conflict'], 'a terminal chain never issues a second nonce');
        self::assertFalse((bool) $rows[2]['results'][0], 'a terminal chain never rearms');
        self::assertContains((string) $rows[3]['results'][0], ['verified', 'issued', 'denied', 'step_up_required'], 'a terminal chain never reserves');

        $record = $store->read($chainId);
        self::assertSame('verified', $record['state'] ?? null, 'the terminal state is absorbing');
        self::assertSame($nonce, $record['stage2Nonce'] ?? null, 'the installed nonce is immutable after verification');
        self::assertNull($store->obligationChainId($obligationId), 'the cleared obligation is never resurrected');
    }

    // ------------------------------------------------------------------
    // One proof advances one stage
    // ------------------------------------------------------------------

    public function testOneProofAdvancesOneStageAndNeverOpensASecondChain(): void
    {
        $client = $this->client();
        $namespace = $this->namespaceFor('one-stage');
        $this->activeNamespace = $namespace;
        $store = $this->store($client);
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
        $stage1 = self::nonce('one-stage-1');
        $requirement = $service->requireStage2($stage1, 'login', 'txn-one-stage', 1, RiskAction::Sha16, time() + 300);
        $obligationId = $service->obligationIdFor('login', 'txn-one-stage', 1);

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $jobs[] = ['calls' => [['op' => 'createOrGet', 'args' => [
                'obligationId' => $obligationId,
                'candidateId' => self::chainId(),
                'stage1Nonce' => $stage1,
                'scope' => 'login',
                'binding' => 'txn-one-stage',
                'requiredAction' => 'sha16',
                'requiredRank' => 1,
                'policyVersion' => 1,
                'expiresAt' => time() + 300,
                'ttlSecs' => 300,
            ]]]];
        }
        $rows = $this->runRace($jobs);
        $this->assertEveryWorkerReported($rows);

        foreach ($rows as $row) {
            self::assertSame($requirement->chainId, (string) $row['results'][0], 'every stage-1 proof of one transaction resolves the same chain');
        }
        $chainKeys = array_values(array_filter(
            (array) $client->keys($this->namespacePatternFor($namespace)),
            static fn (string $key): bool => !str_contains($key, ':chain-obligation:'),
        ));
        self::assertCount(1, $chainKeys, 'one transaction owns exactly one chain record');
        self::assertSame($requirement->chainId, $client->get('{kiwi:'.$namespace.'}:chain-obligation:'.$obligationId), 'the obligation mapping points at that chain');

        $record = $store->read($requirement->chainId);
        self::assertSame('available', $record['state'] ?? null, 'the stage-1 proof leaves the chain one stage in, at available');
        $pttl = (int) $client->pttl('{kiwi:'.$namespace.'}:chain:'.$requirement->chainId);
        self::assertGreaterThan(0, $pttl, 'the chain record carries a key lifetime');
        $obligationPttl = (int) $client->pttl('{kiwi:'.$namespace.'}:chain-obligation:'.$obligationId);
        self::assertGreaterThan(0, $obligationPttl, 'the obligation mapping carries the same lifetime class');

        // The stage-1 proof can never verify: the chain carries no stage-2
        // nonce, so a verify of that proof is refused and the state stands.
        self::assertSame('conflict', $store->markVerified($requirement->chainId, $stage1), 'a stage-1 proof never verifies a stage-2 obligation');
        self::assertSame('available', $store->read($requirement->chainId)['state'] ?? null, 'the refused verify performs no transition');
    }

    // ------------------------------------------------------------------
    // The harness
    // ------------------------------------------------------------------

    /**
     * A fresh chain with its obligation mapping: one atomic create-or-get.
     *
     * @return array{0: string, 1: string} the chain id and the obligation id
     */
    private function freshChain(\Predis\Client $client, string $tag): array
    {
        $this->activeNamespace = $this->namespaceFor($tag);
        $store = $this->store($client);
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
        $requirement = $service->requireStage2(self::nonce($tag), 'login', 'txn-'.$tag, 1, RiskAction::Sha16, time() + 300);
        $obligationId = $service->obligationIdFor('login', 'txn-'.$tag, 1);
        self::assertSame('available', $requirement->state, 'the fresh chain starts available');

        return [$requirement->chainId, $obligationId];
    }

    private function namespaceFor(string $tag): string
    {
        return $this->namespace.'-'.$tag;
    }

    private function namespacePattern(): string
    {
        return $this->namespacePatternFor($this->namespace).'*';
    }

    private function namespacePatternFor(string $namespace): string
    {
        return '{kiwi:'.$namespace.'}:chain:*';
    }

    private function store(\Predis\Client $client): RedisChainedChallengeStateStore
    {
        // The namespace of the most recent freshChain() call: the race
        // tests use one tag per test method.
        return new RedisChainedChallengeStateStore($client, $this->activeNamespace);
    }

    /** The namespace of the chain the current test races. */
    private string $activeNamespace = '';

    private function client(): \Predis\Client
    {
        return new \Predis\Client($this->url, ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
    }

    /** A deterministic Kiwi-shaped challenge nonce for a seed. */
    private static function nonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'chain-boundary:'.$seed, true));
    }

    /** A random chain id in the minting alphabet. */
    private static function chainId(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
    }

    /**
     * Spawn the workers, release them on the shared barrier, and return
     * the decoded per-worker result rows in spawn order.
     *
     * @param list<array{calls: list<array{op?: string, args?: array<string, mixed>, delayMs?: int}>}> $jobs
     *
     * @return list<array<string, mixed>>
     */
    private function runRace(array $jobs, int $workerCount = self::WORKERS, ?string $namespace = null): array
    {
        $startAt = microtime(true) + self::START_DELAY;
        $outs = [];
        foreach ($jobs as $i => $job) {
            $out = $this->tmpDir.'/out-'.$i.'-'.bin2hex(random_bytes(3)).'.json';
            $outs[$i] = $out;
            $job['out'] = $out;
            $job['startAt'] = $startAt;
            $job['url'] = $this->url;
            $job['namespace'] = $namespace ?? $this->activeNamespace;
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
                self::fail('failed to spawn a chain boundary worker');
            }
            fclose($pipes[0]);
            $this->procs[] = $proc;
        }
        self::assertCount($workerCount, $this->procs, 'every requested worker is spawned');

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
     * list against one chain store, and writes a JSON result row. It never
     * boots PHPUnit.
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
    $store = new \BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore($client, $job['namespace']);

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
            // A pure barrier offset: no operation, the delay already ran.
            continue;
        }
        $args = $call['args'] ?? [];
        $results[] = match ($call['op']) {
            'reserve' => $store->reserve($args['chainId'], $args['owner'], (int) $args['leaseSecs']),
            'release' => $store->release($args['chainId'], $args['owner']),
            'issue' => $store->markIssued($args['chainId'], $args['owner'], $args['nonce']),
            'verify' => $store->markVerified($args['chainId'], $args['nonce']),
            'rearm' => $store->rearmIssued($args['chainId'], $args['nonce']),
            'txDenied' => $store->markTransactionDenied($args['chainId'], $args['obligationId']),
            'txStepUp' => $store->markTransactionStepUpRequired($args['chainId'], $args['obligationId']),
            'createOrGet' => $store->createOrGetObligation(
                $args['obligationId'],
                $args['candidateId'],
                $args['stage1Nonce'],
                $args['scope'],
                $args['binding'],
                $args['requiredAction'],
                (int) $args['requiredRank'],
                (int) $args['policyVersion'],
                (int) $args['expiresAt'],
                (int) $args['ttlSecs'],
            ),
            default => throw new \RuntimeException('unknown op '.(string) $call['op']),
        };
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
