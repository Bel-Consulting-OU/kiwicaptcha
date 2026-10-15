<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use PHPUnit\Framework\TestCase;

/**
 * The step-up store's atomicity guarantees, proven across concurrent OS
 * processes against a live redis-server.
 *
 * The in-process suites exercise the same transitions. A single PHP
 * process cannot produce a lost update, because the Lua scripts run
 * serially on one Redis connection. This suite spawns N=8 independent
 * PHP worker processes, each with a fresh Predis client from proc_open.
 * They all hammer one key family at a shared wall-clock barrier, so the
 * racing commands reach the server from distinct connections and
 * the atomicity claims are judged where they actually matter:
 *
 *  1. one completion wins: eight processes call completeFactor on the
 *     same challenge+demand; exactly one observes a non-null result.
 *  2. one active challenge: eight processes admit eight distinct
 *     challenges onto one open demand; every call succeeds or is
 *     refused, and exactly ONE live challenge record survives (the one
 *     the demand's activeChallengeId names) — the replaced records are
 *     gone.
 *  3. one finalization owner: eight processes claim the finalization
 *     of one completed demand; exactly one wins.
 *  4. monotonic under race: a webauthn completion races an email_otp
 *     completion for the same lineage and scope; the completed-factor
 *     history must never end as the weaker family once the stronger
 *     has landed.
 *
 * Runs when KC_REDIS_URL points at a reachable server (the real-Redis
 * lane); skips cleanly otherwise, like every other real-Redis suite.
 */
final class StepUpStoreConcurrencyRealRedisTest extends TestCase
{
    /** The number of concurrent OS worker processes per race. */
    private const WORKERS = 8;

    private const PREFIX = '{kiwi:concreal}:stepup:';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const SESSION = 'sess-concreal';

    private const SCOPE = 'checkout';

    /**
     * The seconds every worker waits (busy-wait) before firing, so all
     * eight commands reach Redis as close to simultaneously as the OS
     * allows. Covers the PHP+Predis startup cost of the last spawn.
     */
    private const START_DELAY = 1.5;

    private string $tmpDir = '';

    private string $workerPath = '';

    private string $autoloadPath = '';

    private string $url = '';

    /** @var list<resource> */
    private array $procs = [];

    private \Predis\Client $client;

    private RedisStepUpChallengeStore $store;

    private int $now = 0;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — the process-level step-up concurrency leg is skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->url = $url;
        $this->client = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at KC_REDIS_URL: '.$e->getMessage());
        }
        $this->now = time();
        $this->store = new RedisStepUpChallengeStore($this->client, self::PREFIX);
        $this->sweep();

        $this->autoloadPath = \dirname(__DIR__).'/vendor/autoload.php';
        self::assertFileExists($this->autoloadPath, 'the bundle autoloader must exist for the spawned workers');

        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-stepup-conc-'.bin2hex(random_bytes(6));
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
        if (isset($this->client)) {
            try {
                $this->sweep();
            } catch (\Throwable) {
                // a dead instance must not fail the shutdown path
            }
        }
        if ($this->tmpDir !== '' && is_dir($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
        $this->tmpDir = '';
    }

    /**
     * The stored session hash both a demand and a challenge carry: the
     * demand's mint takes it pre-hashed, the challenge's begin hashes
     * the raw session id itself, and the two must agree for a
     * completion to bind.
     */
    private function sessionHash(): string
    {
        return (string) StepUpChallenge::sessionHash(self::SESSION);
    }

    private function sweep(): void
    {
        $keys = $this->client->keys(self::PREFIX.'*');
        if (\is_array($keys) && $keys !== []) {
            $this->client->del(...$keys);
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

    // ------------------------------------------------------------------
    // 1. One completion wins
    // ------------------------------------------------------------------

    public function testExactlyOneOfEightConcurrentCompletionsWins(): void
    {
        $demandId = StepUpChallenge::mintId();
        $challengeId = StepUpChallenge::mintId();
        $this->store->createDemand(StepUpDemand::mint($demandId, 'login', $this->sessionHash(), null, null, $this->now, 600), 600);
        $this->store->createAdmittedChallenge(
            StepUpChallenge::begin(
                $challengeId,
                StepUpChallengeKind::EmailOtp,
                self::PRINCIPAL,
                null,
                'login',
                null,
                'post_solve_step_up_required',
                $this->now,
                300,
                5,
                hash('sha256', 'code'),
                null,
                self::SESSION,
                false,
                false,
                null,
                $demandId,
            ),
            300,
        );
        $binding = (string) StepUpChallenge::sessionHash(self::SESSION);

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $jobs[] = ['op' => 'complete', 'args' => [
                'challengeId' => $challengeId,
                'demandId' => $demandId,
                'binding' => $binding,
            ]];
        }
        $results = $this->runRace($jobs);
        $this->assertAllClean($results);

        $winners = array_filter($results, static fn (array $r): bool => ($r['won'] ?? false) === true);
        $losers = array_filter($results, static fn (array $r): bool => ($r['won'] ?? false) === false);

        self::assertCount(
            1,
            $winners,
            'exactly one of the '.self::WORKERS.' concurrent completions must observe a non-null result, '
            .'got '.count($winners).' winners (a lost update would let two callers win the same challenge)',
        );
        self::assertCount(self::WORKERS - 1, $losers, 'every other concurrent completion must answer null');
        self::assertNull($this->store->read($challengeId), 'the consumed challenge record must be gone after the race');
        self::assertSame('completed', $this->store->readDemand($demandId)?->state->value, 'the demand settled completed exactly once');
    }

    // ------------------------------------------------------------------
    // 2. One active challenge
    // ------------------------------------------------------------------

    public function testEightConcurrentAdmissionsLeaveExactlyOneLiveChallenge(): void
    {
        $demandId = StepUpChallenge::mintId();
        $this->store->createDemand(
            StepUpDemand::mint($demandId, self::SCOPE, $this->sessionHash(), null, null, $this->now, 600),
            600,
        );

        $ids = [];
        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $id = StepUpChallenge::mintId();
            $ids[] = $id;
            $challenge = StepUpChallenge::begin(
                $id,
                StepUpChallengeKind::EmailOtp,
                self::PRINCIPAL,
                null,
                self::SCOPE,
                null,
                'step_up',
                $this->now,
                300,
                5,
                hash('sha256', 'code-'.$i),
                null,
                self::SESSION,
                false,
                false,
                null,
                $demandId,
            );
            $jobs[] = ['op' => 'admit', 'args' => [
                'challenge' => $challenge->toArray(),
                'ttl' => 300,
            ]];
        }

        $results = $this->runRace($jobs);
        $this->assertAllClean($results, allowRefused: true);

        $admitted = array_filter($results, static fn (array $r): bool => ($r['admitted'] ?? false) === true);
        $refused = array_filter($results, static fn (array $r): bool => ($r['refused'] ?? false) === true);
        self::assertSame(
            self::WORKERS,
            count($admitted) + count($refused),
            'every concurrent admission must either succeed or throw StepUpDemandAdmissionRefused, never error',
        );

        $live = [];
        foreach ($ids as $id) {
            if ($this->store->read($id) !== null) {
                $live[] = $id;
            }
        }
        self::assertCount(
            1,
            $live,
            'exactly one live challenge record must survive '.self::WORKERS.' concurrent admissions '
            .'(a lost update would leave two live records for one demand); live: '.implode(',', $live),
        );

        $demand = $this->store->readDemand($demandId);
        self::assertNotNull($demand, 'the demand survives the admissions');
        self::assertContains(
            $demand->activeChallengeId,
            $ids,
            'the demand must name one of the admitted challenge ids',
        );
        self::assertSame(
            $live[0],
            $demand->activeChallengeId,
            'the demand activeChallengeId must name the one live challenge record',
        );
    }

    // ------------------------------------------------------------------
    // 3. One finalization owner
    // ------------------------------------------------------------------

    public function testExactlyOneOfEightConcurrentClaimsWinsFinalization(): void
    {
        $demandId = StepUpChallenge::mintId();
        $this->store->createDemand(StepUpDemand::mint($demandId, 'login', $this->sessionHash(), null, null, $this->now, 600), 600);
        self::assertNotNull(
            $this->store->completeDemand($demandId, $this->now, 600),
            'the demand must reach completed before the finalization race',
        );

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $jobs[] = ['op' => 'claim', 'args' => ['demandId' => $demandId, 'claimSecs' => 30]];
        }
        $results = $this->runRace($jobs);
        $this->assertAllClean($results);

        $winners = array_filter($results, static fn (array $r): bool => ($r['won'] ?? false) === true);
        self::assertCount(
            1,
            $winners,
            'exactly one of the '.self::WORKERS.' concurrent claimers must own the finalization, got '.count($winners),
        );
        self::assertSame('finalizing', $this->store->readDemand($demandId)?->state->value, 'the demand is held by exactly one owner');
    }

    // ------------------------------------------------------------------
    // 4. Monotonic under race
    // ------------------------------------------------------------------

    public function testConcurrentStrongAndWeakCompletionsNeverRegressTheHistory(): void
    {
        $sessionHash = (string) StepUpChallenge::sessionHash(self::SESSION);
        $scope = self::SCOPE;

        $strongDemandId = StepUpChallenge::mintId();
        $weakDemandId = StepUpChallenge::mintId();
        $this->store->createDemand(StepUpDemand::mint($strongDemandId, $scope, $this->sessionHash(), null, null, $this->now, 600), 600);
        $this->store->createDemand(StepUpDemand::mint($weakDemandId, $scope, $this->sessionHash(), null, null, $this->now, 600), 600);

        $strongId = StepUpChallenge::mintId();
        $weakId = StepUpChallenge::mintId();
        $this->store->createAdmittedChallenge(
            StepUpChallenge::begin(
                $strongId,
                StepUpChallengeKind::WebAuthn,
                self::PRINCIPAL,
                null,
                $scope,
                null,
                'step_up',
                $this->now,
                600,
                5,
                hash('sha256', 'ceremony-challenge'),
                'assertion',
                self::SESSION,
                false,
                false,
                null,
                $strongDemandId,
            ),
            600,
        );
        $this->store->createAdmittedChallenge(
            StepUpChallenge::begin(
                $weakId,
                StepUpChallengeKind::EmailOtp,
                self::PRINCIPAL,
                null,
                $scope,
                null,
                'step_up',
                $this->now,
                600,
                5,
                hash('sha256', 'code'),
                null,
                self::SESSION,
                false,
                false,
                null,
                $weakDemandId,
            ),
            600,
        );

        $jobs = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $strong = $i % 2 === 0;
            $jobs[] = ['op' => 'complete', 'args' => [
                'challengeId' => $strong ? $strongId : $weakId,
                'demandId' => $strong ? $strongDemandId : $weakDemandId,
                'binding' => $sessionHash,
                'sessionHash' => $sessionHash,
                'scope' => $scope,
            ]];
        }
        $results = $this->runRace($jobs);
        $this->assertAllClean($results);

        // The strong completion always lands: its challenge rides its own
        // independent open demand, so no weak completion can starve it.
        $strongWinners = array_filter(
            $results,
            static fn (array $r): bool => ($r['won'] ?? false) === true && ($r['challengeId'] ?? '') === ($jobs[0]['args']['challengeId'] ?? ''),
        );
        self::assertGreaterThanOrEqual(
            1,
            count($strongWinners),
            'the webauthn completion must land; otherwise the monotonic invariant is untested',
        );

        $family = $this->store->completedFactorOf(hash('sha256', 'lineage-test'), null, $scope, time());
        self::assertSame(
            'webauthn',
            $family,
            'the completed-factor history must never regress to the weaker family once the stronger completion landed; '
            .'observed '.var_export($family, true),
        );
    }

    // ------------------------------------------------------------------
    // The fork/exec harness
    // ------------------------------------------------------------------

    /**
     * Spawn N workers, each holding its own Redis connection, all of
     * them busy-waiting to the same wall-clock barrier before firing the
     * op. Returns the decoded per-worker result rows in spawn order.
     *
     * @param list<array{op: string, args: array<string, mixed>}> $jobs
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
            $this->spawnWorker($job, $out, $startAt);
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

    /** @param array{op: string, args: array<string, mixed>} $job */
    private function spawnWorker(array $job, string $outPath, float $startAt): void
    {
        $job['out'] = $outPath;
        $job['startAt'] = $startAt;
        $job['url'] = $this->url;
        $job['prefix'] = self::PREFIX;
        $job['autoload'] = $this->autoloadPath;
        $jobPath = $outPath.'.job.json';
        file_put_contents($jobPath, json_encode($job, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        $proc = proc_open(
            [\PHP_BINARY, $this->workerPath, $jobPath],
            [
                0 => ['pipe', 'r'],
                1 => ['file', $outPath.'.log', 'a'],
                2 => ['file', $outPath.'.log', 'a'],
            ],
            $pipes,
        );
        if (!\is_resource($proc)) {
            self::fail('failed to spawn a step-up concurrency worker');
        }
        fclose($pipes[0]);
        $this->procs[] = $proc;
    }

    /**
     * @param list<array<string, mixed>> $results
     */
    private function assertAllClean(array $results, bool $allowRefused = false): void
    {
        self::assertCount(self::WORKERS, $results, 'every worker must report exactly one result');
        foreach ($results as $i => $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$i.' failed: '.var_export($row, true));
            if (!$allowRefused) {
                self::assertArrayNotHasKey('refused', $row, 'worker '.$i.' was unexpectedly refused');
            }
            self::assertTrue($row['ok'] ?? false, 'worker '.$i.' did not complete its op: '.var_export($row, true));
        }
    }

    /**
     * The worker script: a self-contained PHP process that connects to
     * Redis with its own client, waits at the shared barrier, runs the
     * one op, and writes a JSON result row. It never boots PHPUnit.
     */
    private function workerSource(): string
    {
        return <<<'PHP'
<?php

declare(strict_types=1);

$jobPath = $argv[1] ?? '';
$job = json_decode((string) @file_get_contents($jobPath), true, 512, JSON_THROW_ON_ERROR);
require $job['autoload'];

$out = ['op' => $job['op'], 'ok' => false];
try {
    $client = new \Predis\Client($job['url'], ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
    $client->ping();
    $store = new \BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore($client, $job['prefix']);

    $startAt = (float) $job['startAt'];
    while (microtime(true) < $startAt) {
        usleep(200);
    }

    $a = $job['args'];
    if ($job['op'] === 'complete') {
        $result = $store->completeFactor(
            (string) $a['challengeId'],
            (string) $a['demandId'],
            (string) $a['binding'],
            time(),
            isset($a['sessionHash']) ? (string) $a['sessionHash'] : null,
            isset($a['scope']) ? (string) $a['scope'] : null,
            hash('sha256', 'lineage-test')
    );
        $out['won'] = $result !== null;
        $out['challengeId'] = (string) $a['challengeId'];
    } elseif ($job['op'] === 'admit') {
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::fromJson(
            json_encode($a['challenge'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        );
        $store->createAdmittedChallenge($challenge, (int) $a['ttl']);
        $out['admitted'] = true;
        $out['challengeId'] = $challenge->id;
    } elseif ($job['op'] === 'claim') {
        $result = $store->claimDemandFinalization((string) $a['demandId'], time(), (int) $a['claimSecs']);
        $out['won'] = $result !== null;
    } else {
        throw new \RuntimeException('unknown op '.$job['op']);
    }
    $out['ok'] = true;
} catch (\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandAdmissionRefused $e) {
    $out['ok'] = true;
    $out['refused'] = true;
    $out['msg'] = $e->getMessage();
} catch (\Throwable $e) {
    $out['error'] = get_class($e).': '.$e->getMessage();
}
file_put_contents($job['out'], json_encode($out, JSON_THROW_ON_ERROR));
PHP;
    }
}
