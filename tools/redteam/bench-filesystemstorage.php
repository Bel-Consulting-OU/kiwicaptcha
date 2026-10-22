<?php
// A/B: FilesystemStorage::store() cost — the horizon-gated sweep (as
// shipped) vs the pre-gate behavior (a full scan+decode on every
// issuance). Same process, same directory, interleaved rounds: each
// round measures one gated store (the horizon says nothing can be
// dropped) and then one ungated store (nextSweepAt forced to 0, which
// is exactly the old per-store scan and which self-heals the horizon
// for the next round's gated arm).
$REPO = dirname(__DIR__, 2);
require $REPO . '/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\FilesystemStorage;

const LIVE = 1500;
const ROUNDS = 300;

function benchNonce(int $i): string
{
    // 32 bytes → the 44-char standard-base64 nonce shape the decoder pins.
    return base64_encode(hash('sha256', 'fs-bench-'.$i, true));
}

function makeRecord(int $i, int $expiresAt): ChallengeRecord
{
    // The strict decode boundary the file adapter reads back through:
    // a 24-char/16-byte salt and prefix == challenge|salt|.
    $salt = 'c2FsdHNhbHRzYWx0c2FsdA==';

    return new ChallengeRecord(
        nonce: benchNonce($i),
        scope: 'login',
        bindingTag: 'tag',
        issuedAt: 1_800_000_000,
        expiresAt: $expiresAt,
        algorithm: PoWAlgorithm::Sha256,
        mKib: 0, t: 1, p: 1, targetBits: 8,
        salt: $salt, prefix: 'challenge|'.$salt.'|', challenge: 'challenge',
        minDurationMs: 0, issuedAtNs: 1_800_000_000_000_000,
    );
}

$dir = sys_get_temp_dir().'/kiwi-fs-bench-'.getmypid().'-'.bin2hex(random_bytes(4));
mkdir($dir, 0700, true);

$clock = 1_800_000_000;
$store = new FilesystemStorage(
    $dir,
    localDiskAcknowledged: true,
    now: static function () use (&$clock): int {
        return $clock;
    },
);

// Prefill: LIVE live records (expires 1h past the clock).
for ($i = 0; $i < LIVE; ++$i) {
    $store->store(makeRecord($i, $clock + 300));
}

$ref = new ReflectionClass($store);
$horizon = $ref->getProperty('nextSweepAt');

$gated = [];
$ungated = [];
for ($round = 0, $n = 0; $round < ROUNDS; ++$round, ++$n) {
    // Gated arm: the horizon is intact (the previous round's ungated
    // sweep recomputed it), so this store pays one integer compare.
    $t = hrtime(true);
    $store->store(makeRecord(LIVE + $n, $clock + 300));
    $gated[] = hrtime(true) - $t;

    // Ungated arm: the pre-gate behavior, horizon forced open. The
    // index keeps both cohorts contiguous in [0, LIVE + 2*ROUNDS) for
    // the integrity sweep below.
    $horizon->setValue($store, 0);
    $t = hrtime(true);
    $store->store(makeRecord(LIVE + ROUNDS + $n, $clock + 300));
    $ungated[] = hrtime(true) - $t;
}

$median = static function (array $xs): float {
    sort($xs);
    $c = count($xs);

    return $c % 2 === 1 ? (float) $xs[(int) floor($c / 2)] : ($xs[$c / 2 - 1] + $xs[$c / 2]) / 2.0;
};
$gMed = $median($gated) / 1e3;
$uMed = $median($ungated) / 1e3;
printf(
    "fs-sweep A/B: %d rounds over %d live records — gated p50 %.1f us/op vs ungated p50 %.1f us/op — %.0fx\n",
    ROUNDS,
    LIVE,
    $gMed,
    $uMed,
    $uMed / max($gMed, 0.001),
);
printf(
    "fs-sweep means: gated %.1f us/op, ungated %.1f us/op\n",
    array_sum($gated) / count($gated) / 1e3,
    array_sum($ungated) / count($ungated) / 1e3,
);

// The store must still hold every record: the gate never skips a write.
$kept = 0;
for ($i = 0; $i < LIVE + 2 * ROUNDS; ++$i) {
    if ($store->find(benchNonce($i)) !== null) {
        ++$kept;
    }
}
$expected = LIVE + 2 * ROUNDS;
printf("fs-sweep integrity: %d/%d records readable after the bench\n", $kept, $expected);
if ($kept !== $expected) {
    fwrite(STDERR, "FAIL: records went missing under the gated sweep\n");
    exit(1);
}

// Cleanup.
$rm = static function (string $p) use (&$rm): void {
    if (is_dir($p) && !is_link($p)) {
        foreach (scandir($p) ?: [] as $e) {
            if ($e !== '.' && $e !== '..') {
                $rm($p.'/'.$e);
            }
        }
        @rmdir($p);

        return;
    }
    @unlink($p);
};
$rm($dir);
echo "fs-sweep A/B: OK\n";
