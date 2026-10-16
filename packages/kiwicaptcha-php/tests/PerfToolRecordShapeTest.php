<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The --json-out provenance record of the timing tools.
 *
 * A timing line without the machine that produced it cannot be
 * audited or compared against a baseline measured elsewhere. These
 * tests run the tools at a tiny iteration count and pin the record
 * shape. They assert the schema and tool name, every measurement with
 * its n and its printed percentiles, the ratchet verdict, and the
 * environment block with explicit nulls where a value is unknown.
 * They also assert the credential redaction of the Redis target. The
 * offline lanes run everywhere; the Redis lanes run against a scratch
 * server the test starts and stops itself, and they are skipped when
 * no redis-server binary exists. The risk lane is skipped without the
 * Symfony bundle vendor, which the PHP core test job does not install.
 */
final class PerfToolRecordShapeTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/kc-perf-record-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0o700, true);
    }

    protected function tearDown(): void
    {
        if ($this->dir === '' || !is_dir($this->dir)) {
            return;
        }
        $files = scandir($this->dir);
        foreach ($files === false ? [] : $files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            @unlink($this->dir.'/'.$file);
        }
        @rmdir($this->dir);
    }

    public function testBenchRecordCarriesTheEnvelopeTheMeasurementsAndTheRatchet(): void
    {
        $tool = self::toolPath('perf-bench.php');
        // A scratch baseline with a p95 far above any machine's timing
        // keeps the shape assertions deterministic while the record
        // still names the baseline file the ratchet consulted.
        $baseline = $this->dir.'/baseline.json';
        file_put_contents($baseline, '{"bench":{"sha_array":{"issue":{"p95_ms":1000000},"verify":{"p95_ms":1000000}}}}');
        $out = $this->dir.'/bench.json';
        $result = $this->runTool($tool, ['--iterations', '6', '--warmup', '2', '--baseline-out', $baseline, '--json-out', $out]);

        self::assertSame(0, $result['code'], $result['out']);
        $record = $this->readRecord($out);
        $this->assertEnvelope($record, 'perf-bench');
        self::assertNull($record['environment']['redis'], 'a run without --redis must keep the redis block as an explicit null');
        self::assertSame(realpath($baseline), $record['baseline_file']);
        self::assertSame('ok', $record['verdict']);

        $lane = $record['measurements']['sha_array'];
        self::assertSame(2, $lane['configuration']['warmup']);
        self::assertSame(6, $lane['configuration']['iterations']);
        self::assertSame('sha256', $lane['configuration']['algorithm']);
        foreach (['issue', 'verify'] as $phase) {
            $this->assertSample($lane[$phase], 6, true);
            $this->assertRatchet($lane[$phase]['ratchet'], 'ok');
        }

        $raw = (string) file_get_contents($out);
        self::assertStringNotContainsString('redis://', $raw, 'a run without --redis must carry no Redis target');
        self::assertDoesNotMatchRegularExpression('/[a-z]+:\/\/[^"\s]*:[^"\s@]*@/', $raw, 'no scheme://user:password@ form may appear in the record');
    }

    public function testAFailingRatchetStillWritesTheRecord(): void
    {
        $tool = self::toolPath('perf-bench.php');
        $baseline = $this->dir.'/tiny-baseline.json';
        file_put_contents($baseline, '{"bench":{"sha_array":{"issue":{"p95_ms":0.0001},"verify":{"p95_ms":0.0001}}}}');
        $out = $this->dir.'/bench-failed.json';

        $result = $this->runTool($tool, ['--iterations', '6', '--warmup', '2', '--baseline-out', $baseline, '--json-out', $out]);

        self::assertSame(1, $result['code'], 'the ratchet failure must keep its failure exit status');
        $record = $this->readRecord($out);
        self::assertSame('failed', $record['verdict']);
        self::assertSame('failed', $record['measurements']['sha_array']['issue']['ratchet']['verdict']);
        self::assertSame('failed', $record['measurements']['sha_array']['verify']['ratchet']['verdict']);
        $this->assertRatchet($record['measurements']['sha_array']['issue']['ratchet'], 'failed');
        self::assertSame(0.0001, (float) $record['measurements']['sha_array']['issue']['ratchet']['baseline_p95_ms']);
        self::assertSame(realpath($baseline), $record['baseline_file'], 'the record must name the baseline file the ratchet consulted');
    }

    public function testASkippedRedisLaneIsAnExplicitNullInTheRecord(): void
    {
        $tool = self::toolPath('perf-bench.php');
        $port = $this->freePort();
        $out = $this->dir.'/bench-skipped.json';

        $result = $this->runTool(
            $tool,
            ['--redis', '--iterations', '6', '--warmup', '2', '--json-out', $out],
            ['KC_REDIS_URL' => 'redis://127.0.0.1:'.$port],
        );

        self::assertSame(0, $result['code'], $result['out']);
        $record = $this->readRecord($out);
        self::assertNull($record['measurements']['sha_redis'], 'a skipped lane must be an explicit null, never an omission');
        self::assertIsArray($record['environment']['redis']);
        self::assertSame('redis://127.0.0.1:'.$port, $record['environment']['redis']['target']);
        self::assertNull($record['environment']['redis']['version'], 'the version of a server that never answered is null');
        self::assertSame('ok', $record['verdict']);
    }

    public function testAnUnwritableRecordPathFailsTheRun(): void
    {
        $tool = self::toolPath('perf-bench.php');
        $result = $this->runTool($tool, ['--iterations', '3', '--warmup', '1', '--json-out', $this->dir]);

        self::assertSame(1, $result['code'], 'a missing record is worse than a failed run');
        self::assertStringContainsString('cannot write the --json-out record', $result['out']);
    }

    public function testTheRedisLaneRecordsTheTargetWithoutItsCredential(): void
    {
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis is not installed; the Redis lane cannot run here');
        }
        $tool = self::toolPath('perf-bench.php');
        if (trim((string) @shell_exec('command -v redis-server 2>/dev/null')) === '') {
            self::markTestSkipped('redis-server is not installed; the offline lanes assert the record shape');
        }
        $port = $this->freePort();
        $secret = 'kc-record-secret-'.bin2hex(random_bytes(6));
        $log = $this->dir.'/redis.log';
        $proc = proc_open(
            ['redis-server', '--port', (string) $port, '--save', '', '--appendonly', 'no', '--requirepass', $secret, '--logfile', $log],
            [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']],
            $pipes,
        );
        if (!is_resource($proc)) {
            self::markTestSkipped('the scratch redis-server could not be started');
        }
        fclose($pipes[0]);
        try {
            $ready = false;
            $deadline = microtime(true) + 15.0;
            while (microtime(true) < $deadline) {
                $pong = (string) @shell_exec('redis-cli --no-auth-warning -a '.escapeshellarg($secret).' -p '.$port.' ping 2>/dev/null');
                if (str_contains($pong, 'PONG')) {
                    $ready = true;
                    break;
                }
                usleep(150_000);
            }
            self::assertTrue($ready, 'the scratch redis-server must answer PONG');

            $out = $this->dir.'/bench-redis.json';
            $baseline = $this->dir.'/redis-baseline.json';
            file_put_contents($baseline, '{"bench":{"sha_redis":{"issue":{"p95_ms":1000000},"verify":{"p95_ms":1000000}}}}');
            $result = $this->runTool(
                $tool,
                ['--redis', '--iterations', '6', '--warmup', '2', '--baseline-out', $baseline, '--json-out', $out],
                ['KC_REDIS_URL' => 'redis://:'.$secret.'@127.0.0.1:'.$port],
            );

            self::assertSame(0, $result['code'], $result['out']);
            $record = $this->readRecord($out);
            $this->assertEnvelope($record, 'perf-bench');
            $redis = $record['environment']['redis'];
            self::assertIsArray($redis);
            self::assertSame('redis://<redacted>@127.0.0.1:'.$port, $redis['target'], 'the target keeps the wire address and loses the credential');
            self::assertIsString($redis['version']);
            self::assertMatchesRegularExpression('/^\d+\.\d+/', $redis['version']);
            $this->assertSample($record['measurements']['sha_redis']['issue'], 6, true);
            $this->assertRatchet($record['measurements']['sha_redis']['issue']['ratchet'], 'ok');

            $raw = (string) file_get_contents($out);
            self::assertStringNotContainsString($secret, $raw, 'the record must never carry the Redis credential');
            self::assertStringContainsString('<redacted>', $raw);
        } finally {
            @shell_exec('redis-cli --no-auth-warning -a '.escapeshellarg($secret).' -p '.$port.' shutdown nosave 2>/dev/null');
            $status = proc_get_status($proc);
            if ($status !== false && $status['running']) {
                proc_terminate($proc);
            }
            proc_close($proc);
        }
    }

    public function testTheRiskRecordShapeWhereTheBundleVendorIsInstalled(): void
    {
        $tool = self::toolPath('perf-bench-risk.php');
        $bundleVendor = \dirname(__DIR__, 3).'/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php';
        if (!is_file($bundleVendor)) {
            self::markTestSkipped('the Symfony bundle vendor is not installed; the risk records are asserted where it is present');
        }
        $out = $this->dir.'/risk.json';
        $baseline = $this->dir.'/risk-baseline.json';
        file_put_contents($baseline, '{"bench_risk":{"in_memory":{"p95_ms":1000000}}}');
        $result = $this->runTool($tool, ['--iterations', '6', '--warmup', '2', '--baseline-out', $baseline, '--json-out', $out]);

        self::assertSame(0, $result['code'], $result['out']);
        $record = $this->readRecord($out);
        $this->assertEnvelope($record, 'perf-bench-risk');
        self::assertSame('in_memory', $record['mode']);
        self::assertNull($record['environment']['redis']);
        self::assertSame(realpath($baseline), $record['baseline_file']);
        self::assertSame('ok', $record['verdict']);
        $this->assertSample($record['measurement'], 6, false);
        $this->assertRatchet($record['measurement']['ratchet'], 'ok');
    }

    private static function toolPath(string $tool): string
    {
        return \dirname(__DIR__, 3).'/packages/kiwicaptcha/tools/'.$tool;
    }

    /**
     * Run one timing tool with the test CLI arguments and the extra
     * environment, and return the exit code plus the combined output.
     *
     * @param list<string> $args
     * @param array<string, string> $env
     * @return array{code: int, out: string}
     */
    private function runTool(string $tool, array $args, array $env = []): array
    {
        if (!is_file($tool)) {
            self::markTestSkipped('the timing tools are not present in this checkout layout');
        }
        $command = escapeshellarg(PHP_BINARY).' '.escapeshellarg($tool);
        foreach ($args as $arg) {
            $command .= ' '.escapeshellarg($arg);
        }
        $prefix = '';
        foreach ($env as $name => $value) {
            $prefix .= $name.'='.escapeshellarg($value).' ';
        }
        $lines = [];
        $code = 0;
        exec($prefix.$command.' 2>&1', $lines, $code);

        return ['code' => $code, 'out' => implode("\n", $lines)];
    }

    /** @return array<string, mixed> */
    private function readRecord(string $path): array
    {
        self::assertFileExists($path);
        $raw = (string) file_get_contents($path);
        $record = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($record);

        return $record;
    }

    /** @param array<string, mixed> $record */
    private function assertEnvelope(array $record, string $tool): void
    {
        self::assertSame('kiwicaptcha.perf-run/1', $record['schema']);
        self::assertSame($tool, $record['tool']);
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $record['generated_at']);
        self::assertIsArray($record['command']);
        self::assertContains('--json-out', $record['command']);

        $env = $record['environment'];
        self::assertIsArray($env);
        self::assertSame(PHP_VERSION, $env['php_version']);
        self::assertSame(PHP_SAPI, $env['php_sapi']);
        self::assertIsString($env['os']);
        self::assertNotSame('', $env['os']);
        self::assertIsString($env['arch']);
        self::assertNotSame('', $env['arch']);
        self::assertTrue($env['cpu_count'] === null || (is_int($env['cpu_count']) && $env['cpu_count'] > 0), 'cpu_count must be an int or an explicit null');
        self::assertTrue($env['cpu_model'] === null || (is_string($env['cpu_model']) && $env['cpu_model'] !== ''), 'cpu_model must be a string or an explicit null');
        self::assertTrue($env['memory_total_bytes'] === null || (is_int($env['memory_total_bytes']) && $env['memory_total_bytes'] > 0), 'memory_total_bytes must be an int or an explicit null');
        self::assertTrue($env['runner'] === null || is_array($env['runner']), 'runner must carry the environment variables or be an explicit null');
        self::assertArrayHasKey('redis', $env);

        $source = $record['source'];
        self::assertTrue($source === null || is_array($source), 'source must be the checkout identity or an explicit null');
        if (is_array($source)) {
            self::assertTrue($source['commit'] === null || preg_match('/^[0-9a-f]{40}$/', (string) $source['commit']) === 1);
            self::assertIsBool($source['dirty']);
        }
        self::assertArrayHasKey('baseline_file', $record);
        self::assertArrayHasKey('verdict', $record);
    }

    /** @param array<string, mixed> $sample */
    private function assertSample(array $sample, int $n, bool $p90Reported, bool $throughputReported = false): void
    {
        self::assertSame($n, $sample['n']);
        self::assertIsNumeric($sample['p50_ms']);
        self::assertIsNumeric($sample['p95_ms']);
        if ($p90Reported) {
            self::assertIsNumeric($sample['p90_ms']);
        } else {
            self::assertNull($sample['p90_ms'], 'a percentile the tool does not print is an explicit null');
        }
        if ($throughputReported) {
            self::assertIsInt($sample['throughput_per_second']);
        } else {
            self::assertNull($sample['throughput_per_second']);
        }
        self::assertArrayHasKey('ratchet', $sample);
    }

    /** @param array<string, mixed>|null $ratchet */
    private function assertRatchet(?array $ratchet, string $verdict): void
    {
        self::assertIsArray($ratchet);
        self::assertSame($verdict, $ratchet['verdict']);
        self::assertSame(3.0, (float) $ratchet['multiplier']);
        if ($verdict === 'ok' || $verdict === 'failed') {
            self::assertIsNumeric($ratchet['baseline_p95_ms']);
            self::assertIsNumeric($ratchet['limit_p95_ms']);
            self::assertEqualsWithDelta(
                (float) $ratchet['baseline_p95_ms'] * 3.0,
                (float) $ratchet['limit_p95_ms'],
                0.000001,
                'the ceiling must be the baseline times the multiplier',
            );
        } else {
            self::assertNull($ratchet['baseline_p95_ms']);
            self::assertNull($ratchet['limit_p95_ms']);
        }
    }

    private function freePort(): int
    {
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $port = random_int(20_000, 45_000);
            $server = @stream_socket_server('tcp://127.0.0.1:'.$port, $errno, $errstr);
            if ($server !== false) {
                fclose($server);

                return $port;
            }
        }
        self::markTestSkipped('no free local port is available for the scratch Redis');
    }
}
