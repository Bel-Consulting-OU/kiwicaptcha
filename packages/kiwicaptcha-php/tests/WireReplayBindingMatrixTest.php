<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The replay and binding matrix: one solved token, every scope,
 * transaction-binding, tenant and expiry pairing.
 *
 * The matrix is generated, not hand written: each issue/verify pair is
 * a row, so a binding regression fails on the exact pair that moved.
 */
final class WireReplayBindingMatrixTest extends TestCase
{
    private const SECRET = 'binding-matrix-secret-0123456789abcdef';

    private const TENANT_A = 'tenant-a';

    private const T0 = 1_800_000_000;

    private const IP = '198.51.100.9';

    private function issuer(ArrayStorage $storage, array $config = []): Issuer
    {
        return new Issuer(
            new Config(...array_merge([
                'secretKey' => self::SECRET,
                'targetBits' => 8,
                'ttlSecs' => 120,
                'minDurationMs' => 0,
            ], $config)),
            $storage,
            now: static fn (): int => self::T0,
        );
    }

    private function verifier(ArrayStorage $storage, int $offset = 0, mixed ...$named): Verifier
    {
        return new Verifier(...array_merge([
            'storage' => $storage,
            'now' => static fn (): int => self::T0 + $offset,
        ], $named));
    }

    private static function solve(Challenge $challenge): int
    {
        $salt = base64_decode($challenge->salt, true);
        for ($counter = 0; ; ++$counter) {
            if (Verifier::leadingZeroBits(hash('sha256', $challenge->prefix.$counter.$salt, true)) >= $challenge->targetBits) {
                return $counter;
            }
        }
    }

    private function issueAndSolve(Issuer $issuer, string $scope = 'login', ?string $binding = null): array
    {
        $challenge = $issuer->issue($scope, self::IP, $binding);

        return [$challenge, SolutionToken::create($challenge->nonce, self::solve($challenge), 4000, [])->encode()];
    }

    public function testAReplayOfTheSameTokenYieldsAtMostOneGrant(): void
    {
        $storage = new ArrayStorage(static fn (): int => self::T0);
        [, $token] = $this->issueAndSolve($this->issuer($storage));
        $first = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::IP, operationIdentity: 'op-first');
        self::assertTrue($first->isOk(), 'the genuine first redemption must pass: '.$first->code());
        $second = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::IP, operationIdentity: 'op-second');
        self::assertFalse($second->isOk(), 'a second redeemer received a fresh grant');
    }

    /** @return iterable<string, array{0: string, 1: ?string, 2: bool}> */
    public static function scopePairs(): iterable
    {
        foreach (['login', 'signup', 'admin'] as $issued) {
            foreach (['login', 'signup', null, 'LOGIN', 'login:admin'] as $expected) {
                $label = 'issued '.$issued.' verified as '.($expected ?? 'null');
                yield $label => [$issued, $expected, $expected === null || $expected === $issued];
            }
        }
    }

    #[DataProvider('scopePairs')]
    public function testScopePairing(string $issued, ?string $expected, bool $shouldPass): void
    {
        $storage = new ArrayStorage(static fn (): int => self::T0);
        [, $token] = $this->issueAndSolve($this->issuer($storage), $issued);
        $outcome = $this->verifier($storage)->verify($token, self::SECRET, $expected, self::IP);
        self::assertSame($shouldPass, $outcome->isOk(), $outcome->code() ?? '');
        if (!$shouldPass) {
            self::assertSame(VerifyError::WrongScope, $outcome->error);
        }
    }

    /** @return iterable<string, array{0: ?string, 1: ?string, 2: bool}> */
    public static function bindingPairs(): iterable
    {
        foreach ([null, 'tx-1', 'tx-2'] as $issued) {
            foreach ([null, 'tx-1', 'tx-2'] as $expected) {
                $label = 'issued '.($issued ?? 'null').' expected '.($expected ?? 'null');
                yield $label => [$issued, $expected, $issued === $expected];
            }
        }
    }

    #[DataProvider('bindingPairs')]
    public function testRequestBindingPairing(?string $issued, ?string $expected, bool $shouldPass): void
    {
        $storage = new ArrayStorage(static fn (): int => self::T0);
        [, $token] = $this->issueAndSolve($this->issuer($storage), 'login', $issued);
        $outcome = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::IP, expectedRequestBinding: $expected);
        self::assertSame($shouldPass, $outcome->isOk(), $outcome->code() ?? '');
        if (!$shouldPass) {
            self::assertSame(VerifyError::RequestBindingMismatch, $outcome->error);
        }
    }

    /** @return iterable<string, array{0: int, 1: bool}> */
    public static function expiryOffsets(): iterable
    {
        foreach ([-61 => false, -60 => true, -1 => true, 0 => true, 119 => true, 120 => false, 121 => false] as $offset => $shouldPass) {
            yield ($offset >= 0 ? '+' : '').$offset.'s' => [$offset, $shouldPass];
        }
    }

    #[DataProvider('expiryOffsets')]
    public function testExpiryAndSkewWindow(int $offset, bool $shouldPass): void
    {
        $storage = new ArrayStorage(static fn (): int => self::T0);
        [, $token] = $this->issueAndSolve($this->issuer($storage));
        $outcome = $this->verifier($storage, $offset)->verify($token, self::SECRET, 'login', self::IP);
        self::assertSame($shouldPass, $outcome->isOk(), $outcome->code() ?? '');
        if (!$shouldPass) {
            self::assertSame(VerifyError::Expired, $outcome->error);
        }
    }

    /** @return iterable<string, array{0: string, 1: string, 2: bool}> */
    public static function tenantPairs(): iterable
    {
        foreach ([null, self::TENANT_A] as $issued) {
            foreach ([null, self::TENANT_A, 'tenant-b'] as $verified) {
                $label = 'issued '.($issued ?? 'global').' verified '.($verified ?? 'global');
                yield $label => [$issued, $verified, $issued === $verified];
            }
        }
    }

    #[DataProvider('tenantPairs')]
    public function testTenantPairing(?string $issued, ?string $verified, bool $shouldPass): void
    {
        $storage = new ArrayStorage(static fn (): int => self::T0);
        $config = $issued === null ? [] : ['tenantId' => $issued];
        [, $token] = $this->issueAndSolve($this->issuer($storage, $config));
        $outcome = $this->verifier($storage, 0, tenantId: $verified)->verify($token, self::SECRET, 'login', self::IP);
        self::assertSame($shouldPass, $outcome->isOk(), $outcome->code() ?? '');
    }

    public function testAStoredRequestBindingCannotBeChangedAfterIssuance(): void
    {
        $storage = new ArrayStorage(static fn (): int => self::T0);
        [$challenge, $token] = $this->issueAndSolve($this->issuer($storage), 'login', 'tx-1');
        $record = $storage->find($challenge->nonce);
        self::assertInstanceOf(ChallengeRecord::class, $record);
        $tampered = new ChallengeRecord(...array_merge(get_object_vars($record), ['requestBinding' => 'tx-2']));
        $storage->store($tampered);
        $outcome = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::IP, expectedRequestBinding: 'tx-2');
        self::assertSame(VerifyError::BadSignature, $outcome->error, 'the signed canonical must reject a rewritten binding');
    }

    public function testATokenNonceSwappedOntoAnotherChallengeIsRefused(): void
    {
        $storage = new ArrayStorage(static fn (): int => self::T0);
        $issuer = $this->issuer($storage, ['targetBits' => 12]);
        [$a, $tokenA] = $this->issueAndSolve($issuer);
        [$b] = $this->issueAndSolve($issuer);
        // Find a counter that proves work for A and provably does not
        // for B, so the swap cannot pass by chance at equal difficulty.
        $saltA = base64_decode($a->salt, true);
        $saltB = base64_decode($b->salt, true);
        for ($counterA = 0; ; ++$counterA) {
            $bitsA = Verifier::leadingZeroBits(hash('sha256', $a->prefix.$counterA.$saltA, true));
            $bitsB = Verifier::leadingZeroBits(hash('sha256', $b->prefix.$counterA.$saltB, true));
            if ($bitsA >= $a->targetBits && $bitsB < $b->targetBits) {
                break;
            }
        }
        $swapped = SolutionToken::create($b->nonce, $counterA, 4000, [])->encode();
        $outcome = $this->verifier($storage)->verify($swapped, self::SECRET, 'login', self::IP);
        if ($outcome->isOk()) {
            self::fail('a counter solved for one challenge was accepted for another');
        }
        self::assertNotSame($tokenA, $swapped);
    }
}
