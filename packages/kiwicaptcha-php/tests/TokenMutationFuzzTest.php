<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Token-mutation fuzz (NEW probe): every single-field mutation of a
 * freshly verified token must be rejected. A tampered counter, duration,
 * telemetry flag or execution field that still verifies is a forgery
 * accept — the strongest class of bug the fixed corpora cannot see,
 * because they only cover mutations somebody already thought of.
 *
 * Invariants under test:
 *   1. the baseline token verifies exactly once (one-shot);
 *   2. every counter/duration/telemetry mutation is refused;
 *   3. a refused attempt never consumes the original (the caller can
 *      still present the untampered token afterwards).
 */
final class TokenMutationFuzzTest extends TestCase
{
    private const SECRET = 'mutation-fuzz-secret-0123456789abcdef';

    /**
     * The test's own proof oracle: a SECOND, independent implementation
     * of the target check, never the production {@see Verifier} path
     * under test. It hashes the challenge bytes itself and counts the
     * leading zero bits of the digest with its own bit loop, so a
     * defective production helper can never bless its own answer. Every
     * counter this test calls "valid" or "invalid" is decided here.
     */
    private static function oracleValid(string $prefix, int $counter, string $salt, int $targetBits): bool
    {
        $digest = hash('sha256', $prefix.$counter.$salt, true);
        $bits = 0;
        foreach (str_split($digest) as $byte) {
            $value = ord($byte);
            if ($value === 0) {
                $bits += 8;
                continue;
            }
            for ($mask = 0x80; $mask > 0 && ($value & $mask) === 0; $mask >>= 1) {
                ++$bits;
            }
            break;
        }
        return $bits >= $targetBits;
    }

    /** The first counter at/above $from the oracle rates valid, or null. */
    private static function findOracleValid(string $prefix, int $from, string $salt, int $targetBits): ?int
    {
        for ($d = 0; $d < 10000; ++$d) {
            $c = $from + $d;
            if (self::oracleValid($prefix, $c, $salt, $targetBits)) {
                return $c;
            }
        }
        return null;
    }

    /** The first counter at/above $from the oracle rates INVALID, or null. */
    private static function findOracleInvalid(string $prefix, int $from, string $salt, int $targetBits): ?int
    {
        for ($d = 0; $d < 10000; ++$d) {
            $c = $from + $d;
            if (!self::oracleValid($prefix, $c, $salt, $targetBits)) {
                return $c;
            }
        }
        return null;
    }

    /**
     * @return array{0: Verifier, 1: string, 2: \KiwiCaptcha\ChallengeRecord, 3: ArrayStorage}
     *         [verifier, token, record, storage] — the storage rides along so
     *         every test can assert the EXACT consume/replay state instead
     *         of only the returned verdict.
     */
    private function verifier(): array
    {
        // The record must live in the verifier's storage; rebuild the
        // stack per assertion so each mutation runs against a live record.
        $config = new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 4, minDurationMs: 0);
        $now = (int) (microtime(true) * 1000);
        $storage = new ArrayStorage();
        $issuer = new Issuer($config, $storage, now: static fn (): int => $now);
        $ch = $issuer->issue('login', '203.0.113.50');
        $record = $storage->find($ch->nonce);
        \assert($record !== null);
        $salt = base64_decode($ch->salt, true);
        \assert($salt !== false);
        $c = 0;
        while (!self::oracleValid($ch->prefix, $c, $salt, $ch->targetBits)) {
            ++$c;
        }
        $token = SolutionToken::create($ch->nonce, $c, 5000, [])->encode();
        $verifier = new Verifier($storage, now: static fn (): int => $now, acceptLegacyV1: true);

        return [$verifier, $token, $record, $storage];
    }

    public function testBaselineVerifiesOnceThenIsAlreadyConsumed(): void
    {
        [$verifier, $token] = $this->verifier();
        $first = $verifier->verify($token, self::SECRET, 'login', '203.0.113.50');
        self::assertTrue($first->isOk(), 'the untampered token verifies: '.$first->code());
        $second = $verifier->verify($token, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($second->isOk(), 'the one-shot token must not verify twice');
        self::assertSame('already_consumed', $second->code());
    }

    public function testCounterMutationsAreNeverAccepted(): void
    {
        // Sound oracle (not "counter+1 must fail"): every counter has an
        // independent 2^-d chance of satisfying the target, so two
        // adjacent counters can both be valid. The oracle below is the
        // test's OWN implementation — never the production Verifier —
        // and the property under test is that the verifier's verdict
        // matches it exactly: a counter the oracle rates invalid must be
        // refused with the deterministic code, and a counter the oracle
        // rates valid above the issued solve is a legitimate alternate
        // solve (not a bypass). Both directions are asserted with their
        // exact consume/replay state.
        [$verifier, $token, $record, $storage] = $this->verifier();
        $decoded = SolutionToken::decode($token);
        $salt = base64_decode($record->salt, true);
        self::assertNotFalse($salt);
        $first = $decoded->counter;
        self::assertTrue(
            self::oracleValid($record->prefix, $first, $salt, $record->targetBits),
            'the oracle must rate the issued counter valid (oracle/production soundness on the baseline solve)',
        );

        // 1. An oracle-INVALID counter above the solve must be refused
        //    with the exact deterministic verdict, and the refusal burns
        //    the one-shot record (consume-on-presentation): the exact
        //    stored state and the exact replay verdict are asserted, not
        //    just "some error happened".
        $failCounter = self::findOracleInvalid($record->prefix, $first + 1, $salt, $record->targetBits);
        self::assertNotNull($failCounter, 'searched 10000 counters above the solve without finding an invalid one (implausible at a 4-bit target)');
        $tampered = SolutionToken::create(
            $decoded->nonce,
            $failCounter,
            $decoded->durationMs,
            $decoded->telemetry,
        )->encode();
        $out = $verifier->verify($tampered, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($out->isOk(), 'a counter whose digest fails the target must be refused');
        self::assertSame(
            'insufficient_work',
            $out->code(),
            'an oracle-invalid counter must be refused as insufficient_work, got: '.$out->code(),
        );
        $consumed = $storage->consumedState($decoded->nonce);
        self::assertNotNull($consumed, 'a refused proof still consumes the one-shot record (consume-on-presentation)');
        self::assertNotNull($consumed->consumedResult, 'the deterministic invalid outcome is committed with the consume');
        self::assertFalse($consumed->consumedResult->valid, 'the committed outcome is the invalid proof verdict');
        $replay = $verifier->verify($token, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($replay->isOk(), 'the burned record must never accept on replay');
        self::assertSame(
            'insufficient_work',
            $replay->code(),
            'the committed invalid outcome replays deterministically to any caller: '.$replay->code(),
        );

        // 2. An oracle-VALID counter above the issued solve is a
        //    legitimate alternate solution: the verifier must ACCEPT it
        //    (proving the verifier checks the target, not "the counter
        //    never changes" — rejecting every change would mask a
        //    different bug), on a fresh stack because step 1 burned its
        //    record. The issued counter is the FIRST valid one, so the
        //    search runs ABOVE it: no counter below the first valid solve
        //    can ever be valid.
        [$verifier2, $token2, $record2, $storage2] = $this->verifier();
        $decoded2 = SolutionToken::decode($token2);
        $salt2 = base64_decode($record2->salt, true);
        self::assertNotFalse($salt2);
        $passCounter = self::findOracleValid($record2->prefix, $decoded2->counter + 1, $salt2, $record2->targetBits);
        self::assertNotNull($passCounter, 'searched 10000 counters above the first valid solve without finding an alternate valid one (implausible at a 4-bit target)');
        $tokenPass = SolutionToken::create($decoded2->nonce, $passCounter, $decoded2->durationMs, $decoded2->telemetry)->encode();
        $outPass = $verifier2->verify($tokenPass, self::SECRET, 'login', '203.0.113.50');
        self::assertTrue($outPass->isOk(), 'a counter whose digest independently passes the target must verify: '.$outPass->code());
        $consumed2 = $storage2->consumedState($decoded2->nonce);
        self::assertNotNull($consumed2, 'the accepted alternate solve consumes the one-shot record');
        self::assertNotNull($consumed2->consumedResult, 'the valid outcome is committed with the consume');
        self::assertTrue($consumed2->consumedResult->valid, 'the committed outcome is the valid proof verdict');
        $replayPass = $verifier2->verify($token2, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($replayPass->isOk(), 'the record is one-shot: the original token must not fund a second acceptance');
        self::assertSame(
            'already_consumed',
            $replayPass->code(),
            'a committed success replays only for its operation identity; a bare retry is already_consumed: '.$replayPass->code(),
        );
    }

    public function testDurationMutationsAreNeverAccepted(): void
    {
        // Client-reported durationMs never drives the gate by design
        // (it is forgeable); the server-measured floor does. Build a
        // stack with a 200 ms floor and prove an immediate verify is
        // refused as too_fast whatever durationMs claims.
        $config = new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 4, minDurationMs: 200);
        $now = (int) (microtime(true) * 1000);
        foreach ([0, 999999] as $duration) {
            $storage = new ArrayStorage();
            $issuer = new Issuer($config, $storage, now: static fn (): int => $now);
            $ch = $issuer->issue('login', '203.0.113.50');
            $salt = base64_decode($ch->salt, true);
            $c = 0;
            do {
                $h = hash('sha256', $ch->prefix.$c.$salt, true);
                ++$c;
            } while (Verifier::leadingZeroBits($h) < $ch->targetBits);
            --$c;
            $token = SolutionToken::create($ch->nonce, $c, $duration, [])->encode();
            $verifier = new Verifier($storage, now: static fn (): int => $now, acceptLegacyV1: true);
            $out = $verifier->verify($token, self::SECRET, 'login', '203.0.113.50');
            self::assertFalse($out->isOk(), sprintf('a 200ms floor must refuse an immediate verify (claimed duration=%d), got %s', $duration, $out->code()));
            self::assertSame('too_fast', $out->code());
        }
    }

    /**
     * Regression: a caller-supplied receipt clock in true nanoseconds
     * (the literal reading of the `nowNs` parameter) must not disable
     * the minimum-duration floor. Before the unit reconciliation a
     * nanosecond receipt made elapsed = ~1e18us, the floor never
     * tripped, and an immediate verify passed a 200ms floor.
     */
    public function testNanosecondReceiptClockCannotDisableTheMinimumDurationFloor(): void
    {
        $config = new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 4, minDurationMs: 200);
        $now = (int) (microtime(true) * 1000);
        $storage = new ArrayStorage();
        $issuer = new Issuer($config, $storage, now: static fn (): int => $now);
        $ch = $issuer->issue('login', '203.0.113.50');
        $salt = base64_decode($ch->salt, true);
        $c = 0;
        do {
            $h = hash('sha256', $ch->prefix.$c.$salt, true);
            ++$c;
        } while (Verifier::leadingZeroBits($h) < $ch->targetBits);
        --$c;
        $token = SolutionToken::create($ch->nonce, $c, 5000, [])->encode();
        $verifier = new Verifier($storage, now: static fn (): int => $now, acceptLegacyV1: true);
        $out = $verifier->verify($token, self::SECRET, 'login', '203.0.113.50', nowNs: (int) (microtime(true) * 1e9));
        self::assertFalse($out->isOk(), 'a nanosecond receipt clock must not bypass the floor');
        self::assertSame('too_fast', $out->code(), 'the 200ms floor must fire under a nanosecond receipt clock');
    }

    public function testTelemetryInjectionDoesNotBypassConsume(): void
    {
        // The counter is chosen by this test's OWN oracle, never by an
        // offset assumption ("counter + 3"): at a four-bit target a fixed
        // offset is valid with probability 2^-4, so the old assumption
        // made this test flaky — and a valid injected counter would have
        // made the assertion pass for the wrong reason. Telemetry and
        // proof validity are tested separately below, each with the
        // exact consume/replay state.
        [$verifier, $token, $record, $storage] = $this->verifier();
        $decoded = SolutionToken::decode($token);
        $salt = base64_decode($record->salt, true);
        self::assertNotFalse($salt);
        $badCounter = self::findOracleInvalid($record->prefix, $decoded->counter + 1, $salt, $record->targetBits);
        self::assertNotNull($badCounter, 'searched 10000 counters above the solve without finding an invalid one (implausible at a 4-bit target)');

        // A telemetry payload that claims a perfect solve must never turn
        // a rejected proof into an acceptance: the proof verdict alone
        // decides, and the exact verdict is asserted.
        $tampered = SolutionToken::create(
            $decoded->nonce,
            $badCounter,
            $decoded->durationMs,
            ['wd' => false, 'perfect' => true, 'n' => 0],
        )->encode();
        $out = $verifier->verify($tampered, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($out->isOk(), 'injected telemetry must not carry a bad proof');
        self::assertSame(
            'insufficient_work',
            $out->code(),
            'the proof verdict decides, not the telemetry: '.$out->code(),
        );

        // Exact consume state: the refused presentation still burns the
        // one-shot record (consume-on-presentation, matching Rust) and
        // commits the deterministic invalid outcome.
        $consumed = $storage->consumedState($decoded->nonce);
        self::assertNotNull($consumed, 'a refused presentation consumes the one-shot record');
        self::assertNotNull($consumed->consumedResult, 'the deterministic invalid outcome is committed');
        self::assertFalse($consumed->consumedResult->valid, 'the committed outcome is the invalid proof verdict');

        // Exact replay state: the untampered original replays the
        // committed invalid outcome — never a second acceptance.
        $replay = $verifier->verify($token, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($replay->isOk(), 'the burned record must not accept on replay');
        self::assertSame(
            'insufficient_work',
            $replay->code(),
            'the committed invalid outcome replays deterministically: '.$replay->code(),
        );

        // Telemetry tested SEPARATELY from proof validity: the same
        // telemetry payload on the oracle-valid issued proof must verify
        // (telemetry never decides the proof verdict in either
        // direction), and the exact one-shot replay state follows.
        [$verifier2, $token2, $record2, $storage2] = $this->verifier();
        $decoded2 = SolutionToken::decode($token2);
        self::assertTrue(
            self::oracleValid(
                $record2->prefix,
                $decoded2->counter,
                base64_decode($record2->salt, true) ?: '',
                $record2->targetBits,
            ),
            'the oracle must rate the issued counter valid',
        );
        $withTelemetry = SolutionToken::create(
            $decoded2->nonce,
            $decoded2->counter,
            $decoded2->durationMs,
            ['wd' => false, 'perfect' => true, 'n' => 0],
        )->encode();
        $ok = $verifier2->verify($withTelemetry, self::SECRET, 'login', '203.0.113.50');
        self::assertTrue($ok->isOk(), 'telemetry does not invalidate an oracle-valid proof: '.$ok->code());
        $consumed2 = $storage2->consumedState($decoded2->nonce);
        self::assertNotNull($consumed2, 'the accepted proof consumes the one-shot record');
        self::assertNotNull($consumed2->consumedResult, 'the valid outcome is committed');
        self::assertTrue($consumed2->consumedResult->valid, 'the committed outcome is the valid proof verdict');
        $replay2 = $verifier2->verify($token2, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($replay2->isOk(), 'one solved token never funds a second acceptance');
        self::assertSame(
            'already_consumed',
            $replay2->code(),
            'a committed success without an operation identity replays as already_consumed: '.$replay2->code(),
        );
    }

    public function testCrossScopePresentationIsRefused(): void
    {
        [$verifier, $token] = $this->verifier();
        $out = $verifier->verify($token, self::SECRET, 'admin_login', '203.0.113.50');
        self::assertFalse($out->isOk(), 'a login token must not verify as a different scope');
    }
}
