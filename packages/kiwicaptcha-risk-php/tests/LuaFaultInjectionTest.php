<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;
use Predis\Client;
use Predis\Response\ServerException;

/**
 * Fault injection at every Lua mutation boundary the risk plane owns.
 *
 * The invariant: a script error plus a retry of the same operation yields
 * exactly the terminal state of one uninterrupted execution, and a
 * partial state never observes as valid. The cases cover a wrong key
 * type, a non-numeric persisted field, a malformed ledger and a command
 * failure injected mid-script. The decoder block is also compared byte
 * for byte across every bundled script.
 */
final class LuaFaultInjectionTest extends TestCase
{
    private const EVENT = '0123456789abcdef0123456789abcdef';

    private const SESSION = 'c7b3e1f9a5d24708b6e0c8a2f4d69123';

    private const PRINCIPAL = '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18';

    private const TARGET = '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813';

    /** Values that must be refused by every strict decoder. */
    private const CORRUPT_NUMBERS = [
        'nan',
        'NaN',
        'NAN',
        'inf',
        '-inf',
        'Infinity',
        '-Infinity',
        '1e999',
        '-1e999',
        '1e309',
        '',
        'not-a-number',
        '--1',
        '1e',
    ];

    /** Values valid as a float but not as an integer field. */
    private const NON_INTEGERS = ['1.5', '-1.5', '0.1', '1e-3'];

    private ?Client $client = null;

    /** @var list<string> */
    private array $namespaces = [];

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set');
        }
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
    }

    protected function tearDown(): void
    {
        foreach ($this->namespaces as $namespace) {
            $this->sweep($namespace);
        }
    }

    private function namespace(string $prefix): string
    {
        $ns = $prefix.bin2hex(random_bytes(4));
        $this->namespaces[] = $ns;

        return $ns;
    }

    private function sweep(string $namespace): void
    {
        foreach (['{kiwi:'.$namespace.'}', 'mark:{kiwi:'.$namespace.'}'] as $pattern) {
            $cursor = '0';
            do {
                $page = $this->client->scan($cursor, ['MATCH' => $pattern.'*', 'COUNT' => 500]);
                $cursor = (string) $page[0];
                if ($page[1] !== []) {
                    $this->client->del(array_map('strval', $page[1]));
                }
            } while ($cursor !== '0');
        }
    }

    private static function script(string $file): string
    {
        $path = dirname(__DIR__).'/resources/'.$file;
        $script = file_get_contents($path);
        self::assertIsString($script, $path);

        return $script;
    }

    /** Run one script body exactly as shipped. */
    private function evalScript(string $file, array $keys, array $args): mixed
    {
        return $this->runBody(self::script($file), $keys, $args);
    }

    /** Run a modified script body (the fault-injection carrier). */
    private function runBody(string $script, array $keys, array $args): mixed
    {
        $sha = $this->client->script('LOAD', $script);
        self::assertIsString($sha);

        return $this->client->evalsha($sha, \count($keys), ...$keys, ...$args);
    }

    /** Insert one command failure immediately after an anchor. */
    private static function injectAfter(string $file, string $anchor): string
    {
        $script = self::script($file);
        $position = strpos($script, $anchor);
        self::assertNotFalse($position, 'injection anchor exists in '.$file);

        $position += strlen($anchor);

        return substr($script, 0, $position)
            ."\nerror('injected-command-failure')\n"
            .substr($script, $position);
    }

    /** The 12 signal fields of one state hash (clock and effect fields removed). */
    private function signals(string $key): array
    {
        $fields = (array) $this->client->hgetall($key);
        foreach (['ts', 'cool', 'fx'] as $ignored) {
            unset($fields[$ignored]);
        }
        ksort($fields);

        return $fields;
    }

    /** Bucket fields with transient per-decision markers removed. */
    private function bucket(string $key): array
    {
        $fields = (array) $this->client->hgetall($key);
        foreach (array_keys($fields) as $field) {
            if (str_starts_with((string) $field, 'fx:')) {
                unset($fields[$field]);
            }
        }
        ksort($fields);

        return $fields;
    }

    private function expectStorageCorruption(callable $call): void
    {
        try {
            $call();
            self::fail('the corrupt state must fail closed');
        } catch (ServerException $e) {
            self::assertStringContainsString('storage-corruption', $e->getMessage());
        }
    }

    // ── the shared decoder ─────────────────────────────────────────────

    public function testThePersistedStateDecoderIsSharedByteForByte(): void
    {
        $expected = [
            'assess_v2.lua', 'calibration.lua', 'calibration_v2.lua', 'confirm.lua',
            'confirm_v2.lua', 'correction.lua', 'correction_v2.lua', 'decoy_escalation.lua',
            'marks.lua', 'outcome_confirm.lua', 'outcome_correct.lua', 'outcome_register.lua',
            'principal_networks.lua', 'register_decision.lua', 'risk-v1.lua',
            'sampling_metrics.lua', 'sharded_hysteresis.lua', 'sharded_identity.lua',
            'sharded_scope.lua', 'target_failure.lua', 'trust.lua',
        ];
        $blocks = [];
        foreach ($expected as $file) {
            $script = self::script($file);
            $start = strpos($script, '-- BEGIN KIWI PERSISTED-STATE DECODER');
            $end = strpos($script, '-- END KIWI PERSISTED-STATE DECODER');
            self::assertNotFalse($start, $file.' carries the decoder start marker');
            self::assertNotFalse($end, $file.' carries the decoder end marker');
            $blocks[$file] = substr($script, $start, $end - $start);
        }
        $reference = $blocks['risk-v1.lua'];
        foreach ($blocks as $file => $block) {
            self::assertSame($reference, $block, $file.' must carry the identical decoder block');
        }
        self::assertStringContainsString('kiwi_decode_integer', $reference);
        self::assertStringContainsString('kiwi_effect_matches', $reference);
    }

    // ── risk-v1 / sharded identity / sharded scope ────────────────────

    /** @return array{0: list<string>, 1: list<int|string>} */
    private function riskV1Case(string $ns, string $eventId): array
    {
        $tag = '{kiwi:'.$ns.'}';
        $keys = [
            $tag.':risk:src:1:b', $tag.':risk:src:0:a', $tag.':risk:src:2:c',
            $tag.':risk:net:1:e', $tag.':risk:net:0:d', $tag.':risk:net:2:f',
            $tag.':risk:sess:'.self::SESSION, $tag.':risk:prin:'.self::PRINCIPAL,
            $tag.':risk:global', $tag.':risk:dd:'.$eventId,
        ];
        $args = [
            1, 1, 0, $eventId, 60, 1800, 60000,
            8000, 100000, 6000, 4000, 3000, 2000, 6000, 10000, 70000, 10000, 10000,
            1, 1, 1800, 1800,
        ];

        return [$keys, $args];
    }

    public function testRiskV1WrongTypeFailsBeforeAnyWrite(): void
    {
        $ns = $this->namespace('fiwt');
        [$keys, $args] = $this->riskV1Case($ns, self::EVENT);
        $this->client->set($keys[3], 'not-a-hash');

        $this->expectStorageCorruption(fn () => $this->evalScript('risk-v1.lua', $keys, $args));
        self::assertSame(0, (int) $this->client->exists($keys[0]), 'no source write before the refusal');
        self::assertSame(0, (int) $this->client->exists($keys[9]), 'no dedupe claim before the refusal');
    }

    public function testRiskV1CorruptFieldFailsBeforeAnyWrite(): void
    {
        $values = array_merge(self::CORRUPT_NUMBERS, self::NON_INTEGERS);
        foreach ($values as $value) {
            $ns = $this->namespace('ficf');
            [$keys, $args] = $this->riskV1Case($ns, self::EVENT);
            $this->client->hset($keys[3], 'rf', $value);

            $this->expectStorageCorruption(fn () => $this->evalScript('risk-v1.lua', $keys, $args));
            self::assertSame(0, (int) $this->client->exists($keys[0]), 'no source write for '.json_encode($value));
            self::assertSame(0, (int) $this->client->exists($keys[9]), 'no claim for '.json_encode($value));
        }
    }

    public function testRiskV1InjectedMidwayRetryEqualsOneExecution(): void
    {
        $clean = $this->namespace('ficlean');
        $faulty = $this->namespace('fifault');
        [$cleanKeys, $cleanArgs] = $this->riskV1Case($clean, 'aaaa');
        [$faultyKeys, $faultyArgs] = $this->riskV1Case($faulty, 'bbbb');

        $this->evalScript('risk-v1.lua', $cleanKeys, $cleanArgs);
        $injected = self::injectAfter('risk-v1.lua', "save(KEYS[1], src, state_ttl, effect_marker)");
        try {
            $this->runBody($injected, $faultyKeys, $faultyArgs);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame(0, (int) $this->client->exists($faultyKeys[9]), 'an aborted invocation must leave no claim');

        $this->evalScript('risk-v1.lua', $faultyKeys, $faultyArgs);

        foreach ([0, 3, 6, 7, 8] as $index) {
            self::assertSame(
                $this->signals($cleanKeys[$index]),
                $this->signals($faultyKeys[$index]),
                'key '.$index.' must carry exactly one event after the retry',
            );
        }
        self::assertSame('1', (string) $this->client->get($faultyKeys[9]), 'the completed retry claims the event');
    }

    /** @return array{0: list<string>, 1: list<int|string>} */
    private function shardedIdentityCase(string $ns, string $eventId): array
    {
        $tag = '{kiwi:'.$ns.'}';

        return [
            [$tag.':risk:src:100:'.str_repeat('b', 32), $tag.':risk:dd:'.$eventId],
            [1, 1, 1, 1, 60, $eventId, 1800],
        ];
    }

    public function testShardedIdentityInjectedMidwayRetryEqualsOneExecution(): void
    {
        $clean = $this->namespace('ficlean');
        $faulty = $this->namespace('fifault');
        [$cleanKeys, $cleanArgs] = $this->shardedIdentityCase($clean, 'aaaa');
        [$faultyKeys, $faultyArgs] = $this->shardedIdentityCase($faulty, 'bbbb');

        $this->evalScript('sharded_identity.lua', $cleanKeys, $cleanArgs);
        $injected = self::injectAfter('sharded_identity.lua', 'save(KEYS[1], s, state_ttl, effect_marker)');
        try {
            $this->runBody($injected, $faultyKeys, $faultyArgs);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame(0, (int) $this->client->exists($faultyKeys[1]), 'no claim after the abort');
        $this->evalScript('sharded_identity.lua', $faultyKeys, $faultyArgs);
        self::assertSame($this->signals($cleanKeys[0]), $this->signals($faultyKeys[0]));
        self::assertSame('1', (string) $this->client->get($faultyKeys[1]));
    }

    public function testShardedScopeInjectedMidwayRetryEqualsOneExecution(): void
    {
        $clean = $this->namespace('ficlean');
        $faulty = $this->namespace('fifault');
        $cleanKeys = ['{kiwi:'.$clean.'}:scope:global:0', '{kiwi:'.$clean.'}:dd:aa'];
        $faultyKeys = ['{kiwi:'.$faulty.'}:scope:global:0', '{kiwi:'.$faulty.'}:dd:bb'];
        $cleanArgs = [1, 1, 1, 60, 'aa'];
        $faultyArgs = [1, 1, 1, 60, 'bb'];

        $this->evalScript('sharded_scope.lua', $cleanKeys, $cleanArgs);
        $injected = self::injectAfter('sharded_scope.lua', 'save(KEYS[1], s, effect_marker)');
        try {
            $this->runBody($injected, $faultyKeys, $faultyArgs);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame(0, (int) $this->client->exists($faultyKeys[1]));
        $this->evalScript('sharded_scope.lua', $faultyKeys, $faultyArgs);
        self::assertSame($this->signals($cleanKeys[0]), $this->signals($faultyKeys[0]));
        self::assertSame('1', (string) $this->client->get($faultyKeys[1]));
    }

    // ── assess_v2 ──────────────────────────────────────────────────────

    /** @return array{0: list<string>, 1: list<int|string>} */
    private function assessCase(string $ns, string $eventId, string $decisionId, bool $target): array
    {
        $tag = '{kiwi:'.$ns.'}';
        $keys = [
            $tag.':risk:src:1:b', $tag.':risk:src:0:a', $tag.':risk:src:2:c',
            $tag.':risk:net:1:e', $tag.':risk:net:0:d', $tag.':risk:net:2:f',
            $tag.':risk:sess:'.self::SESSION, $tag.':risk:prin:'.self::PRINCIPAL,
            $tag.':risk:global', $tag.':risk:dd:'.$eventId,
            $tag.':risk:ctx:'.self::SESSION, $tag.':risk:tls:'.self::SESSION,
            $tag.':outcome:'.$decisionId,
            $target ? $tag.':risk:tgt:'.self::TARGET : $tag.':risk:tgt:unused',
            $target ? $tag.':risk:tgt:src:'.self::TARGET : $tag.':risk:tgt:src:unused',
            $target ? $tag.':risk:tgt:asn:'.self::TARGET : $tag.':risk:tgt:asn:unused',
            $tag.':risk:tgt:dd:'.($target ? $eventId : 'unused'),
        ];
        $args = [
            11, 1, 0, $eventId, 60, 1800, 60000,
            8000, 100000, 6000, 4000, 3000, 2000, 6000, 10000, 70000, 10000, 10000,
            1, 1, 1800, 1800, '', '', $decisionId, 0, 9000, 0, 1, 0, 0,
            100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
            $target ? 1 : 0, 'src-x', 'as64500', 86400, 0, 0,
        ];

        return [$keys, $args];
    }

    public function testAssessV2InjectedBeforeRegistrationRetryEqualsOneExecution(): void
    {
        $clean = $this->namespace('ficlean');
        $faulty = $this->namespace('fifault');
        [$cleanKeys, $cleanArgs] = $this->assessCase($clean, 'aaaa', 'decision-clean', true);
        [$faultyKeys, $faultyArgs] = $this->assessCase($faulty, 'bbbb', 'decision-faulty', true);

        $this->evalScript('assess_v2.lua', $cleanKeys, $cleanArgs);
        $injected = self::injectAfter(
            'assess_v2.lua',
            "if redis.call('SET', KEYS[13], ledger, 'NX', 'EX', tonumber(ARGV[27])) then",
        );
        // Insert the failure before the registration branch, not inside it.
        $injected = str_replace(
            "if redis.call('SET', KEYS[13], ledger, 'NX', 'EX', tonumber(ARGV[27])) then\n",
            "error('injected-command-failure')\nif redis.call('SET', KEYS[13], ledger, 'NX', 'EX', tonumber(ARGV[27])) then\n",
            self::script('assess_v2.lua'),
        );
        try {
            $this->runBody($injected, $faultyKeys, $faultyArgs);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame(0, (int) $this->client->exists($faultyKeys[9]), 'no global claim before the retry');
        self::assertNull($this->client->get($faultyKeys[12]), 'no ledger before the retry');

        $this->evalScript('assess_v2.lua', $faultyKeys, $faultyArgs);

        foreach ([0, 3, 6, 7, 8] as $index) {
            self::assertSame($this->signals($cleanKeys[$index]), $this->signals($faultyKeys[$index]));
        }
        self::assertSame(
            (int) $this->client->hget($cleanKeys[13], 'fails'),
            (int) $this->client->hget($faultyKeys[13], 'fails'),
            'the target failure is booked once',
        );
        self::assertSame(
            (int) $this->client->pfcount($cleanKeys[14]),
            (int) $this->client->pfcount($faultyKeys[14]),
            'the spread is recorded once',
        );
        self::assertSame('1', (string) $this->client->get($faultyKeys[9]));
        $cleanLedger = json_decode((string) $this->client->get($cleanKeys[12]), true);
        $faultyLedger = json_decode((string) $this->client->get($faultyKeys[12]), true);
        self::assertSame($cleanLedger, $faultyLedger, 'the retry books the same ledger entry');
    }

    public function testAssessV2CorruptTargetFailsBeforeAnyWrite(): void
    {
        foreach (array_merge(self::CORRUPT_NUMBERS, self::NON_INTEGERS) as $value) {
            $ns = $this->namespace('fiat');
            [$keys, $args] = $this->assessCase($ns, self::EVENT, 'decision-corrupt', true);
            $this->client->hset($keys[13], 'fails', $value);

            $this->expectStorageCorruption(fn () => $this->evalScript('assess_v2.lua', $keys, $args));
            self::assertSame(0, (int) $this->client->exists($keys[0]), 'no state write for '.json_encode($value));
            self::assertSame(0, (int) $this->client->exists($keys[9]), 'no claim for '.json_encode($value));
        }
    }

    // ── register_decision ─────────────────────────────────────────────

    /** @return array{0: list<string>, 1: list<int|string>} */
    private function registerCase(string $ns, string $decision, bool $sampled = true): array
    {
        $tag = '{kiwi:'.$ns.'}';
        $receipt = json_encode([
            'scope' => 1, 'band' => 2, 'action' => 'sha18',
            'decision_hour' => 0, 'score' => 300, 'sampled' => $sampled ? 1 : 0,
        ], JSON_THROW_ON_ERROR);

        return [
            [$tag.':cal:receipt:'.$decision, $tag.':cal:1:0', $tag.':outcome:'.$decision],
            [$receipt, '300', $sampled ? '1' : '0', '86400', '9000', '1', '0', '300', '1'],
        ];
    }

    public function testRegisterDecisionInjectedMidwayRetryBooksOneSample(): void
    {
        $ns = $this->namespace('fird');
        [$keys, $args] = $this->registerCase($ns, 'decision-reg');
        $injected = self::injectAfter(
            'register_decision.lua',
            "local ledger_ok = redis.call('SET', KEYS[3], cjson.encode(ledger), 'NX', 'EX', ledger_ttl)",
        );
        try {
            $this->runBody($injected, $keys, $args);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertNull($this->client->hget($keys[1], 'sample_total'), 'the aborted attempt leaves the denominator pending');
        self::assertSame(1, (int) $this->evalScript('register_decision.lua', $keys, $args), 'the retry completes the registration');
        self::assertSame('1', (string) $this->client->hget($keys[1], 'sample_total'));
        self::assertSame(0, (int) $this->evalScript('register_decision.lua', $keys, $args), 'the completed registration stays a duplicate');
        self::assertSame('1', (string) $this->client->hget($keys[1], 'sample_total'));
        self::assertNull($this->client->hget($keys[1], 'fx:decision-reg'), 'the transient marker is removed');
    }

    public function testRegisterDecisionCorruptSampleTotalFailsBeforeClaim(): void
    {
        foreach (array_merge(self::CORRUPT_NUMBERS, self::NON_INTEGERS) as $value) {
            $ns = $this->namespace('firc');
            [$keys, $args] = $this->registerCase($ns, 'decision-corrupt');
            $this->client->hset($keys[1], 'sample_total', $value);

            $this->expectStorageCorruption(fn () => $this->evalScript('register_decision.lua', $keys, $args));
            self::assertSame(0, (int) $this->client->exists($keys[0]), 'no receipt for '.json_encode($value));
            self::assertSame(0, (int) $this->client->exists($keys[2]), 'no ledger for '.json_encode($value));
        }
    }

    public function testRegisterDecisionWrongTypeBucketFailsBeforeClaim(): void
    {
        $ns = $this->namespace('firt');
        [$keys, $args] = $this->registerCase($ns, 'decision-wrongtype');
        $this->client->set($keys[1], 'not-a-hash');

        $this->expectStorageCorruption(fn () => $this->evalScript('register_decision.lua', $keys, $args));
        self::assertSame(0, (int) $this->client->exists($keys[0]));
        self::assertSame(0, (int) $this->client->exists($keys[2]));
    }

    // ── confirm ────────────────────────────────────────────────────────

    /** @return array{0: list<string>, 1: list<int|string>} */
    private function confirmCase(string $ns, string $decision, bool $sampled = true): array
    {
        $tag = '{kiwi:'.$ns.'}';
        $this->evalScript('register_decision.lua', ...$this->registerCase($ns, $decision, $sampled));

        return [
            [$tag.':cal:receipt:'.$decision, $tag.':cal:1:0', $tag.':outcome:'.$decision],
            [2, '1', '1', '86400', '9000', '1', '0'],
        ];
    }

    public function testConfirmInjectedBeforeBucketRetryEqualsOneExecution(): void
    {
        $clean = $this->namespace('ficlean');
        $faulty = $this->namespace('fifault');
        [$cleanKeys, $cleanArgs] = $this->confirmCase($clean, 'decision-clean');
        [$faultyKeys, $faultyArgs] = $this->confirmCase($faulty, 'decision-faulty');

        self::assertSame(1, (int) $this->evalScript('confirm.lua', $cleanKeys, $cleanArgs));
        $injected = self::injectAfter(
            'confirm.lua',
            "ledger.w = weight\nredis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')",
        );
        try {
            $this->runBody($injected, $faultyKeys, $faultyArgs);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertNotSame(0, (int) $this->client->exists($faultyKeys[0]), 'the receipt survives for the retry');
        $ledger = json_decode((string) $this->client->get($faultyKeys[2]), true);
        self::assertSame('P', $ledger['o'], 'an interrupted confirmation never presents a terminal outcome');
        self::assertSame(1, $ledger['fx'], 'the ledger records the pending effect set');

        self::assertSame(1, (int) $this->evalScript('confirm.lua', $faultyKeys, $faultyArgs));
        self::assertSame($this->bucket($cleanKeys[1]), $this->bucket($faultyKeys[1]));
        self::assertSame(
            $this->normalizedLedger($cleanKeys[2]),
            $this->normalizedLedger($faultyKeys[2]),
        );
        self::assertSame(0, (int) $this->client->exists($faultyKeys[0]), 'the completed confirmation consumes the receipt');
    }

    public function testConfirmInjectedAfterBucketRetryEqualsOneExecution(): void
    {
        $ns = $this->namespace('fiab');
        [$keys, $args] = $this->confirmCase($ns, 'decision-after-bucket');
        $injected = self::injectAfter('confirm.lua', "redis.call('HSET', KEYS[2], unpack(fields))");
        try {
            $this->runBody($injected, $keys, $args);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame('1', (string) $this->client->hget($keys[1], 'fx:decision-after-bucket'), 'the bucket effect is recorded');
        self::assertSame(1, (int) $this->evalScript('confirm.lua', $keys, $args));
        self::assertSame('1', (string) $this->client->hget($keys[1], 'legit_count'), 'the retry does not double the sample');
        self::assertSame('300', (string) $this->client->hget($keys[1], 'legit_score_sum'));
        self::assertNull($this->client->hget($keys[1], 'fx:decision-after-bucket'));
    }

    public function testConfirmCorruptBucketFailsBeforeConsume(): void
    {
        foreach (self::CORRUPT_NUMBERS as $value) {
            $ns = $this->namespace('ficb');
            [$keys, $args] = $this->confirmCase($ns, 'decision-corrupt');
            $this->client->hset($keys[1], 'legit_count', $value);

            $this->expectStorageCorruption(fn () => $this->evalScript('confirm.lua', $keys, $args));
            self::assertNotSame(0, (int) $this->client->exists($keys[0]), 'a refused confirm keeps the receipt');
            $ledger = json_decode((string) $this->client->get($keys[2]), true);
            self::assertSame('P', $ledger['o'], 'a refused confirm leaves the ledger PENDING');
        }
    }

    public function testConfirmMalformedLedgerFailsClosed(): void
    {
        $ns = $this->namespace('fiml');
        [$keys, $args] = $this->confirmCase($ns, 'decision-malformed');
        $this->client->set($keys[2], '{not-json');

        $this->expectStorageCorruption(fn () => $this->evalScript('confirm.lua', $keys, $args));
        self::assertSame('{not-json', (string) $this->client->get($keys[2]), 'the malformed ledger is not rewritten');
        self::assertNotSame(0, (int) $this->client->exists($keys[0]));
    }

    private function normalizedLedger(string $key): array
    {
        $ledger = json_decode((string) $this->client->get($key), true);
        self::assertIsArray($ledger);
        unset($ledger['fx']);
        ksort($ledger);

        return $ledger;
    }

    // ── confirm_v2 / corrections ──────────────────────────────────────

    /** @return array{0: list<string>, 1: list<int|string>} */
    private function confirmV2Case(string $ns, string $decision): array
    {
        $tag = '{kiwi:'.$ns.'}';
        $receipt = json_encode([
            'scope' => 1, 'band' => 2, 'action' => 'sha18',
            'decision_hour' => 0, 'score' => 300, 'sampled' => 1, 'cv' => 2,
        ], JSON_THROW_ON_ERROR);
        $this->evalScript('register_decision.lua', [
            $tag.':cal:receipt:'.$decision, $tag.':cal:1:0', $tag.':outcome:'.$decision,
        ], [$receipt, '300', '1', '86400', '9000', '1', '0', '300', '1']);

        return [
            [
                $tag.':cal:receipt:'.$decision, $tag.':cal:1:0', $tag.':outcome:'.$decision,
                $tag.':trust:identity',
            ],
            [2, '1', '1', '86400', '9000', '1', '0', '1', '2', '10'],
        ];
    }

    public function testConfirmV2InjectedAfterBucketRetryEqualsOneExecution(): void
    {
        $ns = $this->namespace('fiv2');
        [$keys, $args] = $this->confirmV2Case($ns, 'decision-v2');
        $injected = self::injectAfter('confirm_v2.lua', "redis.call('HSET', KEYS[2], unpack(fields))");
        try {
            $this->runBody($injected, $keys, $args);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame('1', (string) $this->client->hget($keys[1], 'fx:decision-v2'));
        self::assertSame(1, (int) $this->evalScript('confirm_v2.lua', $keys, $args));
        self::assertSame('1', (string) $this->client->hget($keys[1], 'n2'), 'the admitted counter is booked once');
        self::assertSame('1', (string) $this->client->hget($keys[3], 'n'), 'the identity cap counter is booked once');
        self::assertNull($this->client->hget($keys[1], 'fx:decision-v2'));
        self::assertNull($this->client->hget($keys[3], 'fx:decision-v2'));
    }

    public function testCorrectionInjectedAfterPendingRetryEqualsOneExecution(): void
    {
        $clean = $this->namespace('ficlean');
        $faulty = $this->namespace('fifault');
        [$cleanKeys] = $this->confirmCase($clean, 'decision-clean');
        [$faultyKeys] = $this->confirmCase($faulty, 'decision-faulty');
        $this->evalScript('confirm.lua', $cleanKeys, [2, '1', '1', '86400', '9000', '1', '0']);
        $this->evalScript('confirm.lua', $faultyKeys, [2, '1', '1', '86400', '9000', '1', '0']);

        $correctArgs = ['A', '1', '86400', '9000', '1', '0'];
        $injected = self::injectAfter(
            'correction.lua',
            "ledger.nw = weight\nredis.call('SET', KEYS[1], cjson.encode(ledger), 'KEEPTTL')",
        );
        try {
            $this->runBody($injected, [$faultyKeys[2], $faultyKeys[1]], $correctArgs);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame(1, (int) $this->evalScript('correction.lua', [$faultyKeys[2], $faultyKeys[1]], $correctArgs));
        self::assertSame(1, (int) $this->evalScript('correction.lua', [$cleanKeys[2], $cleanKeys[1]], $correctArgs));
        self::assertSame($this->bucket($cleanKeys[1]), $this->bucket($faultyKeys[1]));
        self::assertSame(
            $this->normalizedLedger($cleanKeys[2]),
            $this->normalizedLedger($faultyKeys[2]),
        );
    }

    // ── target_failure / marks ────────────────────────────────────────

    public function testTargetFailureInjectedMidwayRetryBooksOnce(): void
    {
        $ns = $this->namespace('fitf');
        $tag = '{kiwi:'.$ns.'}';
        $keys = [
            $tag.':risk:tgt:'.self::TARGET,
            $tag.':risk:tgt:src:'.self::TARGET,
            $tag.':risk:tgt:asn:'.self::TARGET,
            $tag.':risk:tgt:dd:report-1',
        ];
        $args = ['fail', 'src-x', 'as64500', '3600', 'report-1', '60'];
        $injected = self::injectAfter('target_failure.lua', "redis.call('PEXPIRE', KEYS[1], ttl * 1000)");
        try {
            $this->runBody($injected, $keys, $args);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame(0, (int) $this->client->exists($keys[3]), 'an aborted report leaves no claim');
        $reply = $this->evalScript('target_failure.lua', $keys, $args);
        self::assertSame(1, (int) $reply[0], 'the retry books exactly one failure');
        self::assertSame(1, (int) $this->client->pfcount($keys[1]), 'the retry records one spread element');
        self::assertSame('1', (string) $this->client->get($keys[3]));
    }

    public function testMarksInjectedMidwayRetryCountsOnce(): void
    {
        $ns = $this->namespace('fimk');
        $mark = 'mark:{kiwi:'.$ns.'}:session:'.self::SESSION;
        $keys = [$mark, $mark.':dd:mark-1'];
        $args = ['spamReported', '0', '60000', 'mark-1'];
        $injected = self::injectAfter('marks.lua', "redis.call('PEXPIRE', KEYS[1], ttl_ms)");
        try {
            $this->runBody($injected, $keys, $args);
            self::fail('the injected failure must abort');
        } catch (ServerException $e) {
            self::assertStringContainsString('injected-command-failure', $e->getMessage());
        }
        self::assertSame(0, (int) $this->client->exists($keys[1]));
        self::assertSame(1, (int) $this->evalScript('marks.lua', $keys, $args));
        self::assertSame('1', (string) $this->client->hget($keys[0], 'count'), 'the retry does not double the mark');
        self::assertSame('1', (string) $this->client->get($keys[1]));
    }

    // ── reader-only and single-key decoders ───────────────────────────

    public function testHysteresisCorruptLevelFailsClosed(): void
    {
        foreach (array_merge(self::CORRUPT_NUMBERS, self::NON_INTEGERS) as $value) {
            $ns = $this->namespace('fihy');
            $key = '{kiwi:'.$ns.'}:risk:hyst';
            $this->client->hset($key, 'scope', $value);
            $this->expectStorageCorruption(
                fn () => $this->evalScript('sharded_hysteresis.lua', [$key], [0, 70000, 60000]),
            );
            self::assertSame($value, (string) $this->client->hget($key, 'scope'), 'the corrupt level is not rewritten');
        }
    }

    public function testTrustCorruptFailsClosed(): void
    {
        foreach (array_merge(self::CORRUPT_NUMBERS, self::NON_INTEGERS) as $value) {
            $ns = $this->namespace('fitr');
            $key = '{kiwi:'.$ns.'}:trust:'.self::SESSION.':a64500';
            $this->client->hset($key, 'trust', $value);
            $this->expectStorageCorruption(
                fn () => $this->evalScript('trust.lua', [$key], ['credit', '100', '60000']),
            );
            self::assertSame($value, (string) $this->client->hget($key, 'trust'));
        }
    }

    public function testCalibrationCorruptFieldFailsClosed(): void
    {
        foreach (self::CORRUPT_NUMBERS as $value) {
            $ns = $this->namespace('fica');
            $keys = [];
            for ($i = 1; $i <= 24; $i++) {
                $keys[] = '{kiwi:'.$ns.'}:cal:1:'.($i - 1);
            }
            $keys[] = '{kiwi:'.$ns.'}:cal:state:1';
            $this->client->hset($keys[0], 'legit_count', $value);
            $this->expectStorageCorruption(fn () => $this->evalScript('calibration.lua', $keys, [
                '0', '3', '150', '100000', '0', '0', '1', '2',
            ]));
            self::assertSame(0, (int) $this->client->exists($keys[24]), 'no rate-limit state write');
        }
    }

    public function testSamplingMetricsCorruptCounterFailsClosed(): void
    {
        foreach (array_merge(self::CORRUPT_NUMBERS, self::NON_INTEGERS) as $value) {
            $ns = $this->namespace('fism');
            $keys = [];
            for ($i = 1; $i <= 24; $i++) {
                $keys[] = '{kiwi:'.$ns.'}:cal:1:'.($i - 1);
            }
            $this->client->hset($keys[0], 'sample_total', $value);
            $this->expectStorageCorruption(fn () => $this->evalScript('sampling_metrics.lua', $keys, ['0']));
        }
    }

    public function testPrincipalNetworkCorruptLastUseFailsClosed(): void
    {
        foreach (array_merge(self::CORRUPT_NUMBERS, self::NON_INTEGERS) as $value) {
            $ns = $this->namespace('fipn');
            $key = 'pnet:{kiwi:'.$ns.':'.str_repeat('ab', 16).'}';
            $this->client->hset($key, 'net:11223344', $value);
            $this->expectStorageCorruption(
                fn () => $this->evalScript('principal_networks.lua', [$key], ['record', 'net:55667788', '86400000', '64', '0']),
            );
            self::assertSame($value, (string) $this->client->hget($key, 'net:11223344'));
        }
    }
}
