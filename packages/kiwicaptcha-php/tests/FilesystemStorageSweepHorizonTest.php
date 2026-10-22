<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\FilesystemStorage;
use PHPUnit\Framework\TestCase;

/**
 * The FilesystemStorage sweep horizon, probed fresh: the per-issuance
 * full scan is gated on the earliest retention, the gate never hides an
 * expired record from a read, and a soon-expiring insert always
 * reopens the gate at its own expiry — the three obligations the
 * horizon must keep for the O(n²)-to-O(1) issuance path to be safe.
 */
final class FilesystemStorageSweepHorizonTest extends TestCase
{
    private const SALT = 'c2FsdHNhbHRzYWx0c2FsdA==';
    private const CLOCK = 1_800_000_000;

    private ?string $dir = null;

    protected function tearDown(): void
    {
        if ($this->dir !== null) {
            $rm = function (string $p) use (&$rm): void {
                if (is_dir($p) && !is_link($p)) {
                    foreach (scandir($p) ?: [] as $e) {
                        if ($e !== '.' && $e !== '..') {
                            $rm($p.'/'.$e);
                        }
                    }

                    return;
                }
                @unlink($p);
            };
            $rm($this->dir);
            $this->dir = null;
        }
    }

    private function nonce(int $i): string
    {
        return base64_encode(hash('sha256', 'sweep-horizon/'.$i, true));
    }

    private function record(int $i, int $expiresAt): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $this->nonce($i),
            scope: 'login',
            bindingTag: 'tag',
            issuedAt: self::CLOCK,
            expiresAt: $expiresAt,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0, t: 1, p: 1, targetBits: 8,
            salt: self::SALT,
            prefix: 'challenge|'.self::SALT.'|',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: self::CLOCK * 1_000_000,
        );
    }

    public function testAnExpiredRecordIsReapedOnTheNextIssuanceEvenWhileTheGateWasClosed(): void
    {
        $clock = self::CLOCK;
        $this->dir = sys_get_temp_dir().'/kiwi-sweep-horizon-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
        $store = new FilesystemStorage(
            $this->dir,
            localDiskAcknowledged: true,
            now: static function () use (&$clock): int {
                return $clock;
            },
        );

        // A record retained until CLOCK+160 (ttl 100 + margin 60).
        $store->store($this->record(1, self::CLOCK + 100));
        $path = (new \ReflectionMethod(FilesystemStorage::class, 'pathsFor'))
            ->invoke($store, $this->nonce(1))['record'];
        self::assertFileExists($path, 'the record is written');

        // While the horizon is ahead of the clock the sweep is gated
        // shut: an issuance cannot reclaim anything yet.
        $horizon = new \ReflectionProperty(FilesystemStorage::class, 'nextSweepAt');
        self::assertGreaterThan($clock, $horizon->getValue($store), 'the gate is closed');

        // The clock passes the retention: the NEXT issuance observes
        // the expired horizon and reaps the file in the same locked
        // transition as before the gate existed.
        $clock = self::CLOCK + 200;
        $store->store($this->record(2, $clock + 100));
        self::assertFileDoesNotExist($path, 'the expired record is swept at its own retention');
        self::assertNotNull($store->find($this->nonce(2)), 'the fresh record lands');
    }

    public function testAReadNeverDependsOnTheSweepEvenWithTheGateForcedShut(): void
    {
        $clock = self::CLOCK;
        $this->dir = sys_get_temp_dir().'/kiwi-sweep-horizon-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
        $store = new FilesystemStorage(
            $this->dir,
            localDiskAcknowledged: true,
            now: static function () use (&$clock): int {
                return $clock;
            },
        );
        $store->store($this->record(1, self::CLOCK + 100));

        // The retention passes, and the gate is FORCED shut: no sweep
        // may run, yet the read must already answer "absent" — the
        // sweep is reclamation, never the expiry authority.
        $clock = self::CLOCK + 200;
        $horizon = new \ReflectionProperty(FilesystemStorage::class, 'nextSweepAt');
        $horizon->setValue($store, \PHP_INT_MAX);
        self::assertNull(
            $store->find($this->nonce(1)),
            'an expired record answers null even while the sweep is gated off'
        );
        self::assertNull(
            $store->consume($this->nonce(1)),
            'an expired nonce never consumes, even while the sweep is gated off'
        );
    }

    public function testASoonExpiringInsertReopensTheGateAtItsOwnRetention(): void
    {
        $clock = self::CLOCK;
        $this->dir = sys_get_temp_dir().'/kiwi-sweep-horizon-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
        $store = new FilesystemStorage(
            $this->dir,
            localDiskAcknowledged: true,
            now: static function () use (&$clock): int {
                return $clock;
            },
        );

        // A long-lived record fixes the horizon far out.
        $store->store($this->record(1, self::CLOCK + 250));
        $horizon = new \ReflectionProperty(FilesystemStorage::class, 'nextSweepAt');
        self::assertSame(self::CLOCK + 310, $horizon->getValue($store), 'retention = expiry + margin');

        // A short-lived insert must LOWER the horizon to its own
        // retention, so it — not the long-lived record — reaps first.
        $store->store($this->record(2, self::CLOCK + 50));
        self::assertSame(self::CLOCK + 110, $horizon->getValue($store), 'the insert lowers the horizon');

        // At its retention the short-lived file is swept while the
        // long-lived one survives.
        $clock = self::CLOCK + 120;
        $store->store($this->record(3, $clock + 100));
        $paths = (new \ReflectionMethod(FilesystemStorage::class, 'pathsFor'));
        self::assertFileDoesNotExist($paths->invoke($store, $this->nonce(2))['record']);
        self::assertFileExists($paths->invoke($store, $this->nonce(1))['record']);
        self::assertNotNull($store->find($this->nonce(1)));
    }
}
