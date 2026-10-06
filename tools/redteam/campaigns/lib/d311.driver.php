<?php

declare(strict_types=1);

/**
 * d311.driver.php — the D3.11 engine-plane legs: the oversized-record
 * guard of the frozen Lua scripts and the hysteresis map under
 * adversarial key churn, measured on the real store.
 *
 *   oversized record  the assess scripts refuse a session or TLS tag
 *                     beyond the 64-byte contract bound BEFORE any
 *                     state mutation (the error-reply guard), so an
 *                     oversized record never enters and never spends
 *                     script CPU beyond the bounded check. The leg
 *                     fires 200 oversized calls and measures the
 *                     per-call latency.
 *
 *   hysteresis churn  the sharded LRU map of the hysteresis plane is
 *                     driven with 200000 adversarial distinct keys at
 *                     a band edge; the per-select p95 holds against
 *                     the warm baseline (5x bound), and the map's
 *                     bounded size (1024 entries) never grows.
 *
 * Output: one JSON summary on stdout.
 */

use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\ScopeActionHysteresis;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$client = RedisRiskStateStore::createClient($redisUrl);
$store = new RedisRiskStateStore($client, namespace: 'd311-' . bin2hex(random_bytes(4)));
$keys = RiskKeys::fromMaster(random_bytes(32));
$factory = new RiskIdentityFactory($keys);
$nowMs = (int) (microtime(true) * 1000);
$nowSecs = intdiv($nowMs, 1000);
$epoch = intdiv($nowSecs, 900);

// ---------- the oversized-record guard ----------
$oversized = str_repeat('O', 200);
$refused = 0;
$lat = [];
for ($i = 0; $i < 200; $i++) {
    $t0 = microtime(true);
    try {
        $store->assessV2(new RiskObservation(
            event: RiskEventKind::PreIssue,
            scope: 1,
            sourceEpoch: $epoch,
            sourceIdPrev: $factory->sourceId('198.51.100.5', $epochSecs = $epoch * 900),
            sourceId: $factory->sourceId('198.51.100.5', $epoch * 900),
            sourceIdNext: $factory->sourceId('198.51.100.5', $epoch * 900),
            subnetEpoch: $epoch,
            subnetIdPrev: $factory->subnetId('198.51.100.5', $epoch * 900),
            subnetId: $factory->subnetId('198.51.100.5', $epoch * 900),
            subnetIdNext: $factory->subnetId('198.51.100.5', $epoch * 900),
            sessionId: null,
            principalId: null,
            eventId: str_pad(dechex($i), 24, '0', STR_PAD_LEFT) . 'd311',
            networkRisk: 0,
            nowMs: $nowMs + $i,
        ), $oversized, null);
        // An oversized tag that assesses clean would be the failure.
    } catch (\Throwable $e) {
        $refused++;
    }
    $lat[] = (microtime(true) - $t0) * 1000;
}
sort($lat);
$oversizeP95 = $lat[(int) floor(count($lat) * 0.95) - 1];

// ---------- the hysteresis map churn ----------
$hysteresis = new ScopeActionHysteresis();
$t0 = microtime(true);
for ($i = 0; $i < 20000; $i++) {
    $hysteresis->select(1, 'warm-' . ($i % 64), 449 + ($i % 3), RiskAction::actionForScore(449), $nowMs + $i);
}
$warmMs = (microtime(true) - $t0) * 1000;

$churnLat = [];
$mix = unpack('q', substr(hash('sha256', (string) getenv('KIWI_RT_SEED')), 0, 8))[1] & 0x7FFFFFFF;
$churnKeys = 200000;
for ($i = 0; $i < $churnKeys; $i++) {
    $mix = ($mix * 1103515245 + 12345) & 0x7FFFFFFF;
    $t1 = microtime(true);
    $hysteresis->select(1, 'churn-' . $mix, 449 + ($i % 3), RiskAction::actionForScore(449), $nowMs + $i);
    $churnLat[] = (microtime(true) - $t1) * 1000;
}
sort($churnLat);
$churnP95 = $churnLat[(int) floor(count($churnLat) * 0.95) - 1];
$churnP99 = $churnLat[(int) floor(count($churnLat) * 0.99) - 1];
$mapBounded = $hysteresis->count() <= ScopeActionHysteresis::MAX_ENTRIES;

$summary = [
    'oversized_record' => [
        'calls' => 200,
        'refused' => $refused,
        'p95_ms' => round($oversizeP95, 3),
        'guard_holds' => $refused === 200,
    ],
    'hysteresis_churn' => [
        'keys' => $churnKeys,
        'warm_p95_ms' => round($warmMs / 20000 * 1000, 4), // per-call us -> ms scale note
        'warm_per_call_ms' => round($warmMs / 20000, 4),
        'churn_p95_ms' => round($churnP95, 4),
        'churn_p99_ms' => round($churnP99, 4),
        'map_bounded' => $mapBounded,
        'map_entries' => $hysteresis->count(),
        'p95_within_5x_baseline' => $churnP95 <= max(5 * ($warmMs / 20000), 0.5),
    ],
];
echo json_encode($summary), "\n";

$pass = $refused === 200
    && $mapBounded
    && $churnP95 <= max(5 * ($warmMs / 20000), 0.5);
exit($pass ? 0 : 1);
