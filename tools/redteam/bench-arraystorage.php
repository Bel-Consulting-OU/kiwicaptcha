<?php
// A/B: ArrayStorage::store() cost, new earliest-expiry gate vs the old
// per-store full prune. Same process, same records, interleaved rounds.
$REPO = dirname(__DIR__, 2);
require $REPO . '/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Storage\ArrayStorage;

function makeRecord(string $nonce, int $expiresAt): ChallengeRecord {
    return new ChallengeRecord(
        nonce: $nonce,
        scope: 'login',
        bindingTag: 'tag',
        issuedAt: 1792544000,
        expiresAt: $expiresAt,
        algorithm: \KiwiCaptcha\PoWAlgorithm::Sha256,
        mKib: 0, t: 1, p: 1, targetBits: 8,
        salt: 'c2FsdA==', prefix: 'prefix', challenge: 'challenge',
        minDurationMs: 0, issuedAtNs: 1,
    );
}

// The OLD behavior, inlined for the control arm: full scan on every store.
function oldStore(ArrayStorage $s, ChallengeRecord $r, int $maxEntries, int $margin, callable $now): void {
    $ref = new ReflectionClass($s);
    $prop = $ref->getProperty('records');
    $records = $prop->getValue($s);
    $nowS = (int) $now();
    // pruneExpired equivalent (unconditional full scan)
    foreach ($records as $nonce => $entry) {
        if ($nowS >= $entry['record']->expiresAt + $margin) unset($records[$nonce]);
    }
    $needed = (isset($records[$r->nonce]) ? 0 : 1) + count($records) - $maxEntries;
    if ($needed > 0) {
        $by = [];
        foreach ($records as $nonce => $entry) $by[$nonce] = $entry['record']->expiresAt;
        asort($by); $keys = array_keys($by);
        for ($i = 0; $i < $needed; $i++) unset($records[$keys[$i]]);
    }
    $records[$r->nonce] = ['record' => $r, 'consumed' => false, 'cancelled' => false,
        'result' => null, 'operationIdentity' => null, 'claim' => null, 'claimUntil' => null];
    $prop->setValue($s, $records);
}

$N = 4000;       // inserts per arm
$WARM = 400;
$ROUNDS = 5;
$clock = time() + 3600; // nothing expires during the bench
$now = static fn (): int => $GLOBALS['clock'];

function fill(ArrayStorage $s, int $n, int $base): void {
    for ($i = 0; $i < $n; $i++) $s->store(makeRecord(sprintf('fill-%d-%d', $base, $i), $GLOBALS['clock'] + 600));
}

$results = ['old' => [], 'new' => []];
for ($round = 0; $round < $ROUNDS; $round++) {
    // interleave order so thermal/scheduler drift hits both arms
    $order = ($round % 2 === 0) ? ['old', 'new'] : ['new', 'old'];
    foreach ($order as $arm) {
        $s = new ArrayStorage(now: $now, maxEntries: 10_000, retentionMarginSecs: 0);
        fill($s, 1000, 0); // warm heap + fill cache lines
        $t0 = hrtime(true);
        for ($i = 0; $i < $WARM; $i++) {
            $r = makeRecord(sprintf('w-%d-%d', $round, $i), $clock + 600);
            $arm === 'old' ? oldStore($s, $r, 10_000, 0, $now) : $s->store($r);
        }
        $t0 = hrtime(true);
        for ($i = 0; $i < $N; $i++) {
            $r = makeRecord(sprintf('%s-%d-%d', $arm, $round, $i), $clock + 600);
            $arm === 'old' ? oldStore($s, $r, 10_000, 0, $now) : $s->store($r);
        }
        $results[$arm][] = (hrtime(true) - $t0) / 1000 / $N; // us per store
    }
}
function med(array $a): float { sort($a); $c = count($a); return $c % 2 ? $a[intdiv($c,2)] : ($a[$c/2-1]+$a[$c/2])/2; }
$oldUs = med($results['old']);
$newUs = med($results['new']);
printf("A/B ArrayStorage::store over %d inserts x %d rounds (filled to 1000 entries first)\n", $N, $ROUNDS);
printf("  old (per-store full prune): %8.2f us/store\n", $oldUs);
printf("  new (earliest-expiry gate): %8.2f us/store\n", $newUs);
printf("  speedup: %.2fx  (%.1f%% less time per store)\n", $oldUs / $newUs, (1 - $newUs/$oldUs) * 100);
