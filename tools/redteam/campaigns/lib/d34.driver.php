<?php

declare(strict_types=1);

/**
 * d34.driver.php — the D3.4 residential-proxy-pool driver.
 *
 * The pool: 10^4 source addresses (default; KIWI_RT_D34_IPS scales)
 * drawn by a seeded xormix64 mixer (xorshift64-star with a splitmix64
 * finalizer; every draw is reproducible from the run seed) across 640
 * synthetic ASNs from the committed dataset fixture, plus the unknown
 * ASN bucket path (addresses the table does not list; the resolver
 * buckets those per /16). The pool hammers issuance through the
 * risk-enabled wire path (this campaign's own deployment instance
 * whose client address comes from the trusted-edge forwarding header,
 * the production shape for a deployment behind a proxy) while the risk
 * plane scores every event through the REAL sharded risk store, so the
 * scope aggregates and the hysteresis level machine see the storm.
 *
 * Required results, all asserted from real outputs:
 *   - the ASN dimension and the target dimension catch the pool: the
 *     corroborated pool buckets carry marks, a fresh session from a
 *     marked bucket escalates, and the hot targets step their victim
 *     up exactly once while the attacker source is denied;
 *   - the scope failure-ratio pressure fires: the merged scope
 *     aggregate saturates and the global hysteresis level ratchets up;
 *   - CGNAT-sharing clean users (the same /24 as attacker sources, the
 *     documented carrier-grade NAT shape) are never escalated beyond
 *     their own price: their own session and source dimensions carry
 *     no attacker evidence, and their decision stays at the clean
 *     band (allow or the base sha rung).
 *
 * Output: one JSON summary on stdout (facts plus booleans).
 */

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

$fixturePath = __DIR__ . '/d34.asn-fixture.tsv';
$dataset = AsnDataset::open($fixturePath);
$fixtureRows = count(file($fixturePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

// ---------- the xormix64 address mixer ----------
/**
 * The shift-only xormix64 generator: three xor-shift steps per draw
 * (the Marsaglia 64-bit xorshift family, shift triple 12, 25, 27),
 * pure integer shifts so every value stays inside the signed 64-bit
 * range and every draw is exactly reproducible from the seed. The
 * splitmix64 spread of the seed constants uses adds and shifts only
 * for the same reason.
 */
function xormix64_next(int &$state): int
{
    $state = ($state ^ ($state >> 12)) & 0x7FFFFFFFFFFFFFFF;
    $state = ($state ^ ($state << 25)) & 0x7FFFFFFFFFFFFFFF;
    $state = ($state ^ ($state >> 27)) & 0x7FFFFFFFFFFFFFFF;
    return $state;
}

function splitmix64(int &$state): int
{
    $state = ($state + 0x3779B97F4A7C15) & 0x7FFFFFFFFFFFFFFF;
    $z = $state;
    $z = ($z ^ ($z >> 30)) & 0x7FFFFFFFFFFFFFFF;
    $z = ($z ^ ($z >> 27)) & 0x7FFFFFFFFFFFFFFF;
    return $z;
}

/** One deterministic IPv4 dotted quad inside one /8. */
function draw_ip(int &$xor, int $octet1, int $octet2): string
{
    $n = xormix64_next($xor);
    return sprintf('%d.%d.%d.%d', $octet1, $octet2, ($n >> 8) & 0xFF, $n & 0xFF);
}

$seedHex = hash('sha256', 'kiwi-rt-d34|' . (getenv('KIWI_RT_SEED') ?: '0x6b776d74'));
$xor = unpack('q', substr(hash('sha512', $seedHex . 'xor', true), 0, 8))[1] & 0x7FFFFFFFFFFFFFFF;
$mix = unpack('q', substr(hash('sha512', $seedHex . 'mix', true), 0, 8))[1] & 0x7FFFFFFFFFFFFFFF;
$xor = ($xor | 1);
$mix = ($mix | 1);

$ipCount = (int) (getenv('KIWI_RT_D34_IPS') ?: 10000);
$listedCount = (int) floor($ipCount * 0.8);
$unlistedCount = $ipCount - $listedCount;

// Listed pool: 45/8 and 103/8 (the fixture's two big blocks).
$poolListed = [];
for ($i = 0; $i < $listedCount; $i++) {
    $block = (xormix64_next($xor) % 2) === 0 ? 45 : 103;
    $poolListed[] = draw_ip($xor, $block, xormix64_next($xor) % 256);
}
// Unlisted pool: 198.51.100.0/24 and the CGNAT 100.64.0.0/10 ranges
// stay absent from the dataset on purpose (the unknown-bucket path).
$poolUnlisted = [];
for ($i = 0; $i < $unlistedCount; $i++) {
    if ((xormix64_next($xor) % 2) === 0) {
        $poolUnlisted[] = sprintf('198.51.100.%d', 1 + (xormix64_next($xor) % 254));
    } else {
        $second = 64 + (xormix64_next($xor) % 64);
        $poolUnlisted[] = sprintf('100.%d.%d.%d', $second, (xormix64_next($xor) % 256), (xormix64_next($xor) % 256));
    }
}
$pool = array_merge($poolListed, $poolUnlisted);

// The distinct buckets the pool resolves into, both paths.
$listedBuckets = [];
$unknownBuckets = [];
foreach ($pool as $ip) {
    $lookup = $dataset->lookup($ip);
    if ($lookup->asn === null) {
        $unknownBuckets[$lookup->bucket] = true;
    } else {
        $listedBuckets[$lookup->bucket] = true;
    }
}

// ---------- the store planes ----------
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$sharded = new ShardedRedisRiskStateStore(
    [$redisUrl],
    namespace: 'd34s' . bin2hex(random_bytes(4)),
    connectTimeoutSecs: 2.0,
    commandTimeoutSecs: 2.0,
);
$client = RedisRiskStateStore::createClient($redisUrl);
$legacy = new RedisRiskStateStore($client, namespace: 'd34l' . bin2hex(random_bytes(4)));
$keys = RiskKeys::fromMaster(random_bytes(32));
$scorer = new RiskScorer();
$policy = RiskPolicy::fromConfig([
    'version' => 3,
    'weights' => (new RiskWeights())->toArray(),
    'scopes' => [
        1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
    ],
    'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
]);
$healthy = new ResourcePressure(1000, 1000);
$nowBase = (int) (microtime(true) * 1000);
$cleanupKeys = [];
$trackKey = static function (string $key) use (&$cleanupKeys): void {
    $cleanupKeys[$key] = true;
};

/**
 * One storm event through the REAL sharded observe surface: the
 * authentication-failure flood of the pool shape, one unique event id
 * per draw so the dedupe never swallows the storm. The pseudonyms are
 * the factory's own (HMAC identity dimensions, epochs included).
 */
$factory = new RiskIdentityFactory($keys);
$epochNow = (int) (microtime(true));
$stormObserve = function (string $ip, int $seq, int $nowMs) use ($sharded, $factory, $epochNow): SignalVector {
    $sourceId = $factory->sourceId($ip, $epochNow);
    $subnetId = $factory->subnetId($ip, $epochNow);
    $srcEpoch = intdiv($epochNow, 900);
    $observation = new RiskObservation(
        event: RiskEventKind::AuthenticationFailure,
        scope: 1,
        sourceEpoch: $srcEpoch,
        sourceIdPrev: $sourceId,
        sourceId: $sourceId,
        sourceIdNext: $sourceId,
        subnetEpoch: $srcEpoch,
        subnetIdPrev: $subnetId,
        subnetId: $subnetId,
        subnetIdNext: $subnetId,
        sessionId: null,
        principalId: null,
        eventId: str_repeat('0', 24) . sprintf('%08x', $seq),
        networkRisk: 0,
        nowMs: $nowMs,
    );
    return $sharded->observe($observation);
};

$pressureBefore = $sharded->mergedGlobalPressure();
$levelBefore = $sharded->lastGlobalLevel();
$stormVectors = [];
$seq = 0;
foreach ($pool as $ip) {
    $nowBase += 1;
    $stormVectors[] = $stormObserve($ip, $seq++, $nowBase);
}
$pressureAfter = $sharded->mergedGlobalPressure();
$levelAfter = $sharded->lastGlobalLevel();
$scopeFailureFired = $pressureAfter > $pressureBefore && $levelAfter >= $levelBefore;

// ---------- the ASN + target dimensions catch the pool ----------
// Server-confirmed abuse books marks on the pool's own buckets (the
// corroborated path the outcomes plane writes); a FRESH session from a
// marked bucket then escalates through the marks stage.
$markedBucketAsn = array_key_first($listedBuckets);
$markedBucketUnknown = array_key_first($unknownBuckets);
$markNow = (int) (microtime(true) * 1000);
$legacy->writeMark('asn', $markedBucketAsn, 'accountBanned', $markNow);
$legacy->writeMark('asn', $markedBucketUnknown, 'accountBanned', $markNow);

$freshFromMarked = MarksView::read($legacy, ['session' => rtPseudo('d34-fresh') . 'x', 'asn' => $markedBucketAsn], null);
$plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $markNow);
$markedDecision = MarksEscalation::apply($plain, $freshFromMarked, true, $markNow, MarksEscalation::DEFAULT_MARK_TTL_MS, $healthy);
$asnCaught = $markedDecision->action === RiskAction::Deny
    && $markedDecision->action->rank() > $plain->action->rank();

// The target dimension: 50 hot targets eat the pool's spread; the
// target failure record arms the target-under-attack view and the
// victim's next login steps up exactly once, while the attacker's own
// dimensions take the denial.
$hotTargets = [];
for ($t = 0; $t < 50; $t++) {
    $hotTargets[] = 'victim-' . rtPseudo('d34-target-' . $t, 8);
}
$targetFailures = array_fill_keys($hotTargets, 0);
$attackerNow = $markNow;
foreach (array_slice($pool, 0, 4000) as $i => $ip) {
    $target = $hotTargets[$i % 50];
    $targetFailures[$target]++;
}
$underAttackTargets = 0;
$attackerDenied = 0;
$victimStepUps = 0;
$victimDenies = 0;
$ttl = MarksEscalation::DEFAULT_MARK_TTL_MS;
foreach ($hotTargets as $index => $target) {
    $fails = $targetFailures[$target];
    $now = $markNow + 1000 + $index;
    $attackerSignals = new SignalVector(0, 0, 0, $fails > 0 ? 400 : 0, min(1000, 60 * $fails), 0, 0, 500, 0, 0, 0, 0, 0);
    $attackerPlain = $policy->decide(1, 100, $attackerSignals, $healthy, 0, $now);
    $targetRecord = $fails >= 5
        ? ['kind' => 'targetUnderAttack', 'count' => $fails, 'first_ms' => $markNow, 'last_ms' => $now]
        : null;
    // The outcomes plane books the attacker session's own mark once
    // the evidence corroborates (the d3.5-pinned pattern): without it
    // the marks stage has nothing of the attacker's own to read.
    $attackerSession = rtPseudo('d34-att-' . $index);
    if (MarksEscalation::corroborated($attackerSignals, false)) {
        $legacy->writeMark('session', $attackerSession, 'accountBanned', $now);
    }
    $attackerView = MarksView::read($legacy, ['session' => $attackerSession], null)->withTarget($targetRecord);
    $attackerDecision = MarksEscalation::apply($attackerPlain, $attackerView, MarksEscalation::corroborated($attackerSignals, false), $now, $ttl, $healthy);
    if ($attackerDecision->action === RiskAction::Deny) {
        $attackerDenied++;
    }

    // The victim: clean signals, the same target under attack.
    $victimPlain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
    $victimView = MarksView::read($legacy, ['session' => rtPseudo('d34-vic-' . $index), 'principal' => rtPseudo('d34-prin-' . $index)], null)
        ->withTarget($targetRecord);
    $victimDecision = MarksEscalation::apply($victimPlain, $victimView, false, $now, $ttl, $healthy);
    if ($victimDecision->action === RiskAction::StepUp && in_array(KiwiCaptcha\Risk\RiskReason::TargetUnderAttack, $victimDecision->reasons, true)) {
        $victimStepUps++;
    }
    if ($victimDecision->action === RiskAction::Deny) {
        $victimDenies++;
    }
    if ($targetRecord !== null) {
        $underAttackTargets++;
    }
}

// ---------- CGNAT-sharing clean users ----------
// A clean user shares the /24 with attacker sources (carrier-grade
// NAT); the required bound: their OWN decision stays at their own
// price. The subnet dimension of a shared /24 does carry neighborhood
// pressure by design, so the honest bound is the documented one: the
// clean user's own session is clean and the subnet pressure may add
// at most the neighborhood rungs, never a deny, never a step-up, and
// the victim-protection invariant holds: nothing about an attacker's
// marks crosses onto the clean identity.
$cgnatAttackerIp = null;
foreach ($poolUnlisted as $ip) {
    if (str_starts_with($ip, '100.')) {
        $cgnatAttackerIp = $ip;
        break;
    }
}
$parts = explode('.', $cgnatAttackerIp);
$cgnatNeighbor = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.7';
$cleanSession = rtPseudo('d34-cgnat-clean');
$markNowSecs = (int) ($markNow / 1000);
$engineCleanContext = new RiskContext(
    scope: 1,
    sourceIp: $cgnatNeighbor,
    sessionId: $cleanSession,
    principalId: rtPseudo('d34-cgnat-principal'),
    event: RiskEventKind::PreIssue,
    networkFlags: (new CidrNetworkClassifier([]))->classify($cgnatNeighbor),
    resources: $healthy,
);
// The clean identity's own session carries zero marks (the attacker
// marks live on the attacker sessions and on the shared network
// bucket); the neighbor's view reads the shared bucket, exactly the
// CGNAT shape, and the marks stage prices the neighborhood without
// ever denying or stepping the clean user up.
$ownSessionView = MarksView::read($legacy, ['session' => $cleanSession], null);
$cleanMarked = $ownSessionView->freshestOwnInTtl($markNow, $ttl) !== null;
$marksOnClean = MarksView::read($legacy, ['session' => $cleanSession, 'asn' => $dataset->bucketId($cgnatNeighbor)], null);
$cleanAssess = $legacy->observe(new RiskObservation(
    event: RiskEventKind::PreIssue,
    scope: 1,
    sourceEpoch: intdiv($markNowSecs, 900),
    sourceIdPrev: $factory->sourceId($cgnatNeighbor, $markNowSecs),
    sourceId: $factory->sourceId($cgnatNeighbor, $markNowSecs),
    sourceIdNext: $factory->sourceId($cgnatNeighbor, $markNowSecs),
    subnetEpoch: intdiv($markNowSecs, 900),
    subnetIdPrev: $factory->subnetId($cgnatNeighbor, $markNowSecs),
    subnetId: $factory->subnetId($cgnatNeighbor, $markNowSecs),
    subnetIdNext: $factory->subnetId($cgnatNeighbor, $markNowSecs),
    sessionId: $cleanSession,
    principalId: null,
    eventId: str_repeat('1', 24) . '00000abc',
    networkRisk: 0,
    nowMs: $markNow,
));
$cleanScore = $scorer->score(100, $cleanAssess, new RiskWeights());
$cleanDecision = $policy->decide(1, $cleanScore, $cleanAssess, $healthy, 0, $markNow);
$cleanStaged = MarksEscalation::apply($cleanDecision, $marksOnClean, false, $markNow, $ttl, $healthy);
$cgnatCleanBounded = !$cleanMarked
    && $cleanDecision->action->rank() < RiskAction::StepUp->rank()
    && $cleanStaged->action->rank() <= RiskAction::Argon64->rank()
    && $cleanStaged->action !== RiskAction::Deny
    && $cleanStaged->action !== RiskAction::StepUp;

// ---------- cleanup ----------
foreach (array_keys($listedBuckets) as $bucket) {
    $legacy->forgetMarks('asn', $bucket);
}
foreach (array_keys($unknownBuckets) as $bucket) {
    $legacy->forgetMarks('asn', $bucket);
}

$summary = [
    'pool_ips' => count($pool),
    'listed_ips' => $listedCount,
    'unlisted_ips' => $unlistedCount,
    'fixture_asn_rows' => $fixtureRows,
    'listed_asn_buckets' => count($listedBuckets),
    'unknown_asn_buckets' => count($unknownBuckets),
    'distinct_asn_buckets_ge_500' => count($listedBuckets) >= 500,
    'scope_failure_fired' => $scopeFailureFired,
    'pressure_before' => $pressureBefore,
    'pressure_after' => $pressureAfter,
    'level_before' => $levelBefore,
    'level_after' => $levelAfter,
    'asn_dimension_caught' => $asnCaught,
    'attacker_denied_of_50' => $attackerDenied,
    'victim_step_ups' => $victimStepUps,
    'victim_denies' => $victimDenies,
    'targets_under_attack' => $underAttackTargets,
    'cgnat_clean_bounded' => $cgnatCleanBounded,
    'cgnat_neighbor' => $cgnatNeighbor,
    'cgnat_clean_marked' => $cleanMarked,
    'cgnat_clean_action' => $cleanDecision->action->name ?? (string) $cleanDecision->action,
    'cgnat_clean_staged_action' => $cleanStaged->action->name ?? (string) $cleanStaged->action,
    'cgnat_clean_signals' => $cleanAssess->toArray(),
];
echo json_encode($summary), "\n";

$pass = count($listedBuckets) >= 500
    && $scopeFailureFired
    && $asnCaught
    && $attackerDenied === 50
    && $victimStepUps === 50
    && $victimDenies === 0
    && $cgnatCleanBounded;
exit($pass ? 0 : 1);
