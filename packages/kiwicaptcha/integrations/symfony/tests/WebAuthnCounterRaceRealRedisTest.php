<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The WebAuthn sign-counter rollback guard under cross-process
 * concurrency, judged where the race actually happens: the Redis
 * server. The client-side GET-then-SETEX the registry used to run
 * cannot be atomic: two workers both read the stored counter, both
 * pass the comparison, and the later write rewinds the persisted
 * counter. That defeats the cloned-authenticator evidence the sign
 * counter exists to provide.
 *
 * Eight independent PHP processes (own Predis clients, spawned with
 * proc_open) share one barrier, then hammer one credential with a
 * shuffled pool of counters. With the atomic Lua CAS the persisted
 * counter is always the maximum of every write that landed; with the
 * old read-then-write pair the last writer wins and the final counter
 * is almost never the maximum.
 *
 * Runs when a Redis URL is present (the real-Redis lanes); skips
 * cleanly otherwise, like every other real-Redis suite.
 */
final class WebAuthnCounterRaceRealRedisTest extends TestCase
{
    /** The number of concurrent OS worker processes. */
    private const WORKERS = 8;

    /** The counter pool: workers draw disjoint shuffled chunks of it. */
    private const POOL_MAX = 160;

    private const PREFIX = '{kiwi:webauthn-cas}:cred-race:';

    private const CREDENTIAL_ID = 'race-credential-1';

    private const PRINCIPAL = 'race-principal-1';

    /**
     * The seconds every worker busy-waits before firing, so all eight
     * clients start writing as close together as the OS allows.
     */
    private const START_DELAY = 1.5;

    private string $tmpDir = '';

    private string $workerPath = '';

    private string $autoloadPath = '';

    private string $url = '';

    /** @var list<resource> */
    private array $procs = [];

    private \Predis\Client $client;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL') ?: (getenv('TEST_REDIS_URL') ?: getenv('RISK_REDIS_URL'));
        if ($url === false || $url === '') {
            self::markTestSkipped('no KC_REDIS_URL/TEST_REDIS_URL — the counter-race leg is skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->url = (string) $url;
        $this->client = new \Predis\Client($this->url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at '.$this->url.': '.$e->getMessage());
        }
        $this->sweep();

        $this->autoloadPath = \dirname(__DIR__).'/vendor/autoload.php';
        self::assertFileExists($this->autoloadPath, 'the bundle autoloader must exist for the spawned workers');

        $this->tmpDir = sys_get_temp_dir().'/kiwi-webauthn-cas-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the counter-race scratch directory');
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
            foreach ((array) scandir($this->tmpDir) as $item) {
                if ($item !== '.' && $item !== '..') {
                    @unlink($this->tmpDir.'/'.$item);
                }
            }
            @rmdir($this->tmpDir);
        }
        $this->tmpDir = '';
    }

    /**
     * Eight processes, one credential, one shuffled pool: the persisted
     * counter must end at the pool maximum. Any interleaving that lands
     * a lower value means a write rewound the counter under a
     * concurrent higher one — the rollback the CAS exists to prevent.
     */
    public function testConcurrentCounterWritesNeverRewindThePersistedCounter(): void
    {
        $pool = range(1, self::POOL_MAX);
        shuffle($pool);
        $chunks = array_chunk($pool, (int) ceil(self::POOL_MAX / self::WORKERS));
        self::assertCount(self::WORKERS, $chunks, 'one chunk per worker');

        $startAt = microtime(true) + self::START_DELAY;
        $outs = [];
        foreach ($chunks as $i => $chunk) {
            $out = $this->tmpDir.'/out-'.$i.'-'.bin2hex(random_bytes(3)).'.json';
            $outs[$i] = $out;
            $this->spawnWorker($chunk, $out, $startAt);
        }

        $exits = [];
        foreach ($this->procs as $i => $proc) {
            $exits[$i] = proc_close($proc);
        }
        $this->procs = [];

        foreach ($outs as $i => $out) {
            $raw = is_file($out) ? (string) file_get_contents($out) : '';
            if ($raw === '') {
                $log = is_file($out.'.log') ? (string) file_get_contents($out.'.log') : '(no log)';
                self::fail('worker '.$i.' produced no result (exit '.($exits[$i] ?? '?').'); log: '.$log);
            }
            $row = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($row);
            self::assertTrue($row['ok'] ?? false, 'worker '.$i.' failed: '.var_export($row, true));
            self::assertSame(\count($chunks[$i]), $row['saves'] ?? 0, 'worker '.$i.' saved its whole chunk');
        }

        $stored = $this->client->get(self::PREFIX.'credential:'.hash('sha256', self::CREDENTIAL_ID));
        self::assertIsString($stored, 'the raced credential record must exist');
        $record = json_decode($stored, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(
            self::POOL_MAX,
            $record['counter'],
            'the final counter is the maximum of every concurrent write — a lower value means a rollback landed',
        );
    }

    private function sweep(): void
    {
        $keys = $this->client->keys(self::PREFIX.'*');
        if (\is_array($keys) && $keys !== []) {
            $this->client->del(...$keys);
        }
    }

    /** @param list<int> $chunk */
    private function spawnWorker(array $chunk, string $outPath, float $startAt): void
    {
        $job = [
            'counters' => $chunk,
            'out' => $outPath,
            'startAt' => $startAt,
            'url' => $this->url,
            'prefix' => self::PREFIX,
            'credentialId' => self::CREDENTIAL_ID,
            'principal' => self::PRINCIPAL,
            'autoload' => $this->autoloadPath,
        ];
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
            self::fail('failed to spawn a counter-race worker');
        }
        fclose($pipes[0]);
        $this->procs[] = $proc;
    }

    /** The self-contained worker: own client, shared barrier, chunk saves. */
    private function workerSource(): string
    {
        return <<<'PHP'
<?php
declare(strict_types=1);

$jobPath = $argv[1] ?? '';
$job = json_decode((string) file_get_contents($jobPath), true, 512, JSON_THROW_ON_ERROR);
require $job['autoload'];

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnCredentialRegistry;

try {
    $client = new Predis\Client($job['url'], ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
    $client->ping();
    // Fresh connection per process: the race must come from distinct
    // clients, never a shared in-process pipe.
    $registry = new WebAuthnCredentialRegistry($client, $job['prefix'], 31536000);

    $startAt = (float) $job['startAt'];
    while (microtime(true) < $startAt) {
        // busy-wait to the shared barrier
    }

    $saves = 0;
    foreach ($job['counters'] as $counter) {
        $record = Webauthn\CredentialRecord::create(
            $job['credentialId'],
            'public-key',
            [],
            'none',
            new Webauthn\TrustPath\EmptyTrustPath(),
            Symfony\Component\Uid\Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            'key-material',
            $job['principal'],
            (int) $counter,
        );
        $registry->saveCredentialSource($record);
        ++$saves;
    }

    file_put_contents($job['out'], json_encode(['ok' => true, 'saves' => $saves]));
    exit(0);
} catch (Throwable $e) {
    file_put_contents($job['out'], json_encode(['ok' => false, 'error' => $e->getMessage()]));
    exit(1);
}
PHP;
    }
}
