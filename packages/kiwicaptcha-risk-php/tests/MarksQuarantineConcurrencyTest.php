<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Marks\Quarantine;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The long-memory mark plane under real OS-process concurrency.
 *
 * A mark is one hash written by one marks script per report, and the
 * quarantine selection reads the live mark set of a request. This suite
 * forks independent worker processes, each with its own Redis connection,
 * and releases them on one wall-clock barrier, so the mark writes, the
 * relief erasures and the selection reads reach the server from distinct
 * connections.
 *
 * The invariants: a mark is always read whole (one hash read, one script
 * write), a duplicate report id writes the mark exactly once under the
 * race, and the selection is exactly a function of the mark set the
 * reader observed.
 *
 * Runs in the real-Redis lane (RISK_REDIS_URL) and skips cleanly
 * otherwise.
 */
final class MarksQuarantineConcurrencyTest extends TestCase
{
    private const SESSION = 'c7b3e1f9a5d24708b6e0c8a2f4d69123';

    private const ASN = 'as64500';

    /** The mark lifetime this suite configures, in seconds. */
    private const MARK_TTL_SECS = 300;

    private string $url = '';

    private string $namespace = '';

    private \Predis\Client $client;

    /** @var list<int> */
    private array $children = [];

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6421 --save "" --appendonly no --daemonize yes');
        }
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent mark workers');
        }
        $this->url = $url;
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
        $this->namespace = 'marksconc'.bin2hex(random_bytes(4));
        $this->sweep();
    }

    protected function tearDown(): void
    {
        foreach ($this->children as $pid) {
            $status = 0;
            pcntl_waitpid($pid, $status);
        }
        $this->children = [];
        if (isset($this->client)) {
            try {
                $this->sweep();
            } catch (\Throwable) {
                // a dead instance must not fail the shutdown path
            }
        }
    }

    private function sweep(): void
    {
        $keys = $this->client->keys('mark:{kiwi:'.$this->namespace.'}:*');
        if (\is_array($keys) && $keys !== []) {
            $this->client->del(...$keys);
        }
    }

    /**
     * A store on its own connection, so every forked worker owns its
     * socket.
     */
    private function store(): RedisRiskStateStore
    {
        return new RedisRiskStateStore(RedisRiskStateStore::createClient($this->url), namespace: $this->namespace, markTtlSecs: self::MARK_TTL_SECS);
    }

    // ------------------------------------------------------------------
    // A mark is never read torn while writes race the relief erasure
    // ------------------------------------------------------------------

    public function testMarkWritesRacingReliefNeverLeaveATornMark(): void
    {
        self::assertSame(1, $this->store()->writeMark('session', self::SESSION, 'spamReported', 0, 'seed-event'), 'the mark exists before the race');

        $rows = $this->fork([
            // Three concurrent reports of the spam kind.
            ['op' => 'write', 'seed' => 'w0'],
            ['op' => 'write', 'seed' => 'w1'],
            ['op' => 'write', 'seed' => 'w2'],
            // Three concurrent relief erasures of the same mark.
            ['op' => 'forget'],
            ['op' => 'forget'],
            ['op' => 'forget'],
            // Two readers sampling the mark through the whole race.
            ['op' => 'read-many'],
            ['op' => 'read-many'],
        ]);

        $totalReads = 0;
        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            foreach ((array) ($row['observations'] ?? []) as $observation) {
                if ($observation !== null) {
                    $this->assertWholeSpamMark($observation, 'worker '.$row['index'].' observed a partial or foreign mark');
                }
            }
            if (isset($row['observed'])) {
                if ($row['observed'] !== null) {
                    $this->assertWholeSpamMark($row['observed'], 'worker '.$row['index'].' observed a partial or foreign mark');
                }
            }
            $totalReads += $row['reads'] ?? 1;
        }
        self::assertGreaterThanOrEqual(120, $totalReads, 'the readers sampled the racing mark set');

        // The mark stays writable after the race: a fresh report lands
        // whole and advances the count by one, so a concurrent erasure
        // never leaves a damaged hash.
        $store = $this->store();
        $before = $store->readMark('session', self::SESSION);
        $counted = $store->writeMark('session', self::SESSION, 'spamReported', 0, 'after-race');
        self::assertSame((int) ($before['count'] ?? 0) + 1, $counted, 'a fresh report lands after the race');
        $final = $store->readMark('session', self::SESSION);
        self::assertNotNull($final, 'the fresh report survives the race');
        $this->assertWholeSpamMark($final, 'the surviving mark is whole');
        self::assertSame('spamReported', $final['kind'], 'the final state is the spam kind');
    }

    public function testConcurrentDuplicateReportsWriteTheMarkExactlyOnce(): void
    {
        $eventId = 'duplicate-event-1';
        $rows = $this->fork(array_fill(0, 8, ['op' => 'write', 'seed' => 'dup', 'eventId' => $eventId]));

        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            self::assertSame(1, $row['count'], 'a duplicate report returns the current count without a second write');
        }

        $mark = $this->store()->readMark('session', self::SESSION);
        self::assertNotNull($mark, 'the mark exists');
        self::assertSame(1, $mark['count'], 'eight concurrent duplicate reports book exactly one write');
        self::assertSame('spamReported', $mark['kind']);
    }

    // ------------------------------------------------------------------
    // The selection is exactly a function of the observed mark set
    // ------------------------------------------------------------------

    public function testTheQuarantineSelectionMatchesTheObservedViewUnderAMixedWrite(): void
    {
        $this->store()->writeMark('session', self::SESSION, 'spamReported', 0);

        $rows = $this->fork([
            // The escalation evidence: a serious mark on the request's asn
            // dimension lands while readers assess the same identity.
            ['op' => 'escalate'],
            ['op' => 'escalate'],
            ['op' => 'select'],
            ['op' => 'select'],
            ['op' => 'select'],
            ['op' => 'select'],
            ['op' => 'select'],
            ['op' => 'select'],
        ]);

        $observedSelects = 0;
        foreach ($rows as $row) {
            self::assertArrayNotHasKey('error', $row, 'worker '.$row['index'].' failed: '.json_encode($row));
            if (!\array_key_exists('selects', $row)) {
                continue;
            }
            $observedSelects++;
            self::assertSame(
                !$row['asnObserved'],
                $row['selects'],
                'the selection matches the observed view: a live escalation mark always drops the quarantine',
            );
        }
        self::assertGreaterThan(0, $observedSelects, 'the selection legs ran');

        // After the race the escalation is durable, so every later
        // selection refuses the quarantine and the stronger treatment
        // stands.
        $store = $this->store();
        self::assertNotNull($store->readMark('asn', self::ASN), 'the escalation mark is durable after the race');
        $view = MarksView::read($store, ['session' => self::SESSION, 'asn' => self::ASN], null);
        self::assertFalse(
            Quarantine::selects($view, false, (int) floor(microtime(true) * 1000), self::MARK_TTL_SECS * 1000),
            'the mixed identity is never a quarantine',
        );
    }

    /** @param array<string, mixed> $mark */
    private function assertWholeSpamMark(array $mark, string $label): void
    {
        foreach (['kind', 'last_kind', 'count', 'first_ms', 'last_ms'] as $field) {
            self::assertArrayHasKey($field, $mark, $label.': the mark carries '.$field);
        }
        self::assertSame('spamReported', $mark['kind'], $label.': the max-severity kind is the spam kind');
        self::assertGreaterThanOrEqual(1, $mark['count'], $label.': the count is positive');
        self::assertLessThanOrEqual($mark['last_ms'], $mark['first_ms'], $label.': the window is ordered');
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
        $base = tempnam(sys_get_temp_dir(), 'kiwi-marks-conc-');
        self::assertNotFalse($base, 'a scratch result path is available');
        $rows = [];
        foreach ($jobs as $index => $job) {
            $out = $base.'.'.$index;
            $pid = pcntl_fork();
            self::assertNotSame(-1, $pid, 'pcntl_fork succeeds');
            if ($pid === 0) {
                $row = ['index' => $index, 'op' => $job['op']];
                try {
                    $store = $this->store();
                    while (microtime(true) < $startAt) {
                        usleep(100);
                    }
                    if ($job['op'] === 'write') {
                        $row['count'] = $store->writeMark('session', self::SESSION, 'spamReported', 0, (string) ($job['eventId'] ?? 'event-'.$job['seed']));
                    } elseif ($job['op'] === 'forget') {
                        $row['removed'] = $store->forgetMarks('session', self::SESSION);
                    } elseif ($job['op'] === 'read-many') {
                        $observations = [];
                        for ($sample = 0; $sample < 60; $sample++) {
                            $observations[] = $store->readMark('session', self::SESSION);
                            usleep(2000);
                        }
                        $row['observations'] = $observations;
                        $row['reads'] = 60;
                    } elseif ($job['op'] === 'escalate') {
                        $row['count'] = $store->writeMark('asn', self::ASN, 'fraudConfirmed', 0, 'escalate-'.$index);
                    } elseif ($job['op'] === 'select') {
                        $nowMs = (int) floor(microtime(true) * 1000);
                        $view = MarksView::read($store, ['session' => self::SESSION, 'asn' => self::ASN], null);
                        $live = $view->ownInTtl($nowMs, self::MARK_TTL_SECS * 1000);
                        $row['asnObserved'] = isset($live['asn']);
                        $row['selects'] = Quarantine::selects($view, false, $nowMs, self::MARK_TTL_SECS * 1000);
                    } else {
                        throw new \RuntimeException('unknown op '.$job['op']);
                    }
                    if ($job['op'] === 'write' || $job['op'] === 'forget') {
                        $row['observed'] = $store->readMark('session', self::SESSION);
                    }
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
            self::assertSame(0, pcntl_wexitstatus($status), 'every mark worker exits cleanly');
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
}
