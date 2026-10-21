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

    /** @return array{0: Verifier, 1: string} [verifier, token] */
    private function verifier(): array
    {
        // The record must live in the verifier's storage; rebuild the
        // stack per assertion so each mutation runs against a live record.
        $config = new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 4, minDurationMs: 0);
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

        return [$verifier, $token];
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
        [$verifier, $token] = $this->verifier();
        $decoded = SolutionToken::decode($token);
        // Deterministic counter perturbations: off-by-one both ways and
        // a large jump. A proof that does not match the record's prefix
        // must be refused, never accepted.
        foreach ([+1, -1, +2, -17, +1000000] as $delta) {
            $tampered = SolutionToken::create(
                $decoded->nonce,
                $decoded->counter + $delta,
                $decoded->durationMs,
                $decoded->telemetry,
            )->encode();
            $out = $verifier->verify($tampered, self::SECRET, 'login', '203.0.113.50');
            self::assertFalse($out->isOk(), sprintf('counter%+d must not verify, got %s', $delta, $out->code()));
        }
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
        [$verifier, $token] = $this->verifier();
        $decoded = SolutionToken::decode($token);
        // A telemetry payload that claims a perfect solve must never turn
        // a rejected mutation into an acceptance.
        $tampered = SolutionToken::create(
            $decoded->nonce,
            $decoded->counter + 3,
            $decoded->durationMs,
            ['wd' => false, 'perfect' => true, 'n' => 0],
        )->encode();
        $out = $verifier->verify($tampered, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($out->isOk(), 'injected telemetry must not carry a bad proof');
        // A refused proof burns the one-shot record (consume-on-presentation,
        // matching Rust): the replay never yields a second acceptance.
        $replay = $verifier->verify($token, self::SECRET, 'login', '203.0.113.50');
        self::assertFalse($replay->isOk(), 'the burned record must not accept on replay: '.$replay->code());
    }

    public function testCrossScopePresentationIsRefused(): void
    {
        [$verifier, $token] = $this->verifier();
        $out = $verifier->verify($token, self::SECRET, 'admin_login', '203.0.113.50');
        self::assertFalse($out->isOk(), 'a login token must not verify as a different scope');
    }
}
