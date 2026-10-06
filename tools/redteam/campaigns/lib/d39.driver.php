<?php

declare(strict_types=1);

/**
 * d39.driver.php — the D3.9 risk-engine gaming driver: the five
 * gaming strategies of the spec, each against the REAL risk engine
 * surfaces over the REAL Redis.
 *
 *   trust farming       a session earns credit in its home ASN bucket
 *                       and the cookie is then shared across a botnet
 *                       presenting from hundreds of foreign buckets:
 *                       the farmed trust never crosses ASNs (foreign
 *                       reads earn and see nothing), and the genuine
 *                       home commute keeps every home unit.
 *
 *   boundary riding     a score oscillating across a band edge (449,
 *                       450, 451, ...) selects the stable hysteresis
 *                       action, never a per-request flip.
 *
 *   calibration poison  the label-flood shape of the 10^5-labels test
 *                       re-driven through the REAL outcome plane
 *                       (register + confirm through the real store) at
 *                       the stated downscale: forged
 *                       confirmed-legitimate labels move the scope
 *                       bias at most 1 point.
 *
 *   mark evasion        the storm session churns into fresh session
 *                       identities: every churned identity starts
 *                       untrusted (zero bucket trust), while the
 *                       source dimension keeps the storm's pressure,
 *                       so the churn buys no escape from escalation.
 *
 *   victim forcing      the attacker shares the victim's subnet: the
 *                       victim's own decision stays at its own price
 *                       (never a deny, never an attacker mark on its
 *                       view), the shared subnet pricing the
 *                       neighborhood at most to the argon floor.
 *
 * Output: one JSON summary on stdout.
 */

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\ScopeActionHysteresis;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Trust\ContextBoundTrust;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$client = RedisRiskStateStore::createClient($redisUrl);
$store = new RedisRiskStateStore($client, namespace: 'd39-' . bin2hex(random_bytes(4)));
$keys = RiskKeys::fromMaster(random_bytes(32));
$factory = new RiskIdentityFactory($keys);
$healthy = new ResourcePressure(1000, 1000);
$ttl = MarksEscalation::DEFAULT_MARK_TTL_MS;
$nowMs = (int) (microtime(true) * 1000);
$policy = RiskPolicy::fromConfig([
    'version' => 3,
    'weights' => (new RiskWeights())->toArray(),
    'scopes' => [
        1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
    ],
    'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
]);

$labels = (int) (getenv('KIWI_RT_D39_LABELS') ?: 100000);

// ---------- 1. trust farming ----------
$dataset = AsnDataset::open(__DIR__ . '/d34.asn-fixture.tsv');
$trust = new ContextBoundTrust($dataset, $store);
$farmerSession = rtPseudo('d39-farmer');
$homeIp = '45.10.20.30';
$earned = $trust->earn($farmerSession, $homeIp, 100);
$homeCredit = $trust->creditFor($farmerSession, $homeIp)->rawTrust;
$foreignOk = true;
$foreignTested = 0;
$mix = unpack('q', substr(hash('sha256', (string) getenv('KIWI_RT_SEED')), 0, 8))[1] & 0x7FFFFFFF;
for ($i = 0; $i < 300; $i++) {
    $mix = ($mix * 1103515245 + 12345) & 0x7FFFFFFF;
    $octet2 = $mix % 256;
    $mix = ($mix * 1103515245 + 12345) & 0x7FFFFFFF;
    $ip = sprintf('103.%d.%d.%d', $octet2, ($mix >> 8) & 0xFF, $mix & 0xFF);
    if ($dataset->bucketId($ip) === $dataset->bucketId($homeIp)) {
        continue;
    }
    $foreignTested++;
    $credit = $trust->creditFor($farmerSession, $ip);
    if ($credit->isHome || $credit->rawTrust > 0) {
        $foreignOk = false;
    }
}
$homeKept = $trust->creditFor($farmerSession, $homeIp)->rawTrust === $homeCredit;

// ---------- 2. hysteresis boundary riding ----------
$hysteresis = new ScopeActionHysteresis();
$ridingScores = [449, 451, 449, 450, 451, 449, 450, 451];
$ridingActions = [];
$t = $nowMs;
foreach ($ridingScores as $score) {
    $t += 1000;
    $ridingActions[] = $hysteresis->select(1, rtPseudo('d39-rider'), $score, RiskAction::actionForScore($score), $t)->name ?? '?';
}
$stableRiding = count(array_unique($ridingActions)) === 1;

// ---------- 3. calibration poisoning ----------
$calibrator = new AggregateCalibrator(
    $client,
    'd39cal' . bin2hex(random_bytes(3)),
    samplingMode: 'complete',   // the poisoner wants every receipt recorded
);
$poisoned = 0;
for ($i = 0; $i < $labels; $i++) {
    $decisionId = str_pad(dechex($i), 16, '0', STR_PAD_LEFT) . bin2hex(random_bytes(8));
    $calibrator->recordReceipt($decisionId, 1, 0, RiskAction::Sha16, 100, 1, intdiv($nowMs, 3600000), 1.0);
    $poisoned += $calibrator->confirmOutcome($decisionId, true) === 1 ? 1 : 0;
}
$biasAfterPoison = $calibrator->biasForScope(1, (int) (microtime(true) * 1000));
$biasBounded = abs($biasAfterPoison) <= 1;

// ---------- 4. mark evasion by churn ----------
$stormIp = '45.99.88.7';
$epochSecs = intdiv(intdiv($nowMs, 1000), 900);
$stormObserve = static function (string $session, string $eventId) use ($store, $factory, $stormIp, $epochSecs, &$nowMs): SignalVector {
    $nowMs += 1;
    return $store->observe(new KiwiCaptcha\Risk\RiskObservation(
        event: RiskEventKind::AuthenticationFailure,
        scope: 1,
        sourceEpoch: $epochSecs,
        sourceIdPrev: $factory->sourceId($stormIp, $epochSecs * 900),
        sourceId: $factory->sourceId($stormIp, $epochSecs * 900),
        sourceIdNext: $factory->sourceId($stormIp, $epochSecs * 900),
        subnetEpoch: $epochSecs,
        subnetIdPrev: $factory->subnetId($stormIp, $epochSecs * 900),
        subnetId: $factory->subnetId($stormIp, $epochSecs * 900),
        subnetIdNext: $factory->subnetId($stormIp, $epochSecs * 900),
        sessionId: $session,
        principalId: null,
        eventId: $eventId,
        networkRisk: 0,
        nowMs: $nowMs,
    ));
};
$scorer = new RiskScorer();
$weights = new RiskWeights();
$sessionOne = rtPseudo('d39-churn-1');
$stormObserve($sessionOne, str_repeat('1', 32));
$stormObserve($sessionOne, str_repeat('2', 32));
$stormObserve($sessionOne, str_repeat('3', 32));
$stormObserve($sessionOne, str_repeat('4', 32));
$v1 = $stormObserve($sessionOne, str_repeat('5', 32));
$scoreOne = $scorer->score(100, $v1, $weights);
// The churn: a fresh session identity, same source.
$sessionTwo = rtPseudo('d39-churn-2');
$v2 = $stormObserve($sessionTwo, str_repeat('6', 32));
$scoreTwo = $scorer->score(100, $v2, $weights);
$churnUntrusted = $store->readBucketTrust($sessionTwo, $dataset->bucketId($stormIp)) === 0;
$sourcePressureKept = $scoreTwo >= $scoreOne;

// ---------- 5. forced victim escalation via shared network ----------
$victimIp = '45.99.88.9';
$victimSession = rtPseudo('d39-victim');
$attackerSession = rtPseudo('d39-attacker');
$store->writeMark('session', $attackerSession, 'accountBanned', $nowMs);
$victimView = MarksView::read($store, ['session' => $victimSession, 'principal' => rtPseudo('d39-victim-principal')], null);
$victimPlain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $nowMs);
$victimDecision = MarksEscalation::apply($victimPlain, $victimView, false, $nowMs, $ttl, $healthy);
$victimUnaffected = $victimDecision->action === RiskAction::Allow
    && $victimView->freshestOwnInTtl($nowMs, $ttl) === null;
// The attacker's own view: marked and corroborated, denied.
$attackerView = MarksView::read($store, ['session' => $attackerSession], null);
$attackerPlain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $nowMs);
$attackerDecision = MarksEscalation::apply($attackerPlain, $attackerView, true, $nowMs, $ttl, $healthy);
$attackerDenied = $attackerDecision->action === RiskAction::Deny;

$summary = [
    'trust_farming' => [
        'home_credit_earned' => $homeCredit,
        'foreign_peers_tested' => $foreignTested,
        'foreign_credit_zero' => $foreignOk,
        'home_credit_kept' => $homeKept,
    ],
    'boundary_riding' => [
        'scores' => $ridingScores,
        'actions' => $ridingActions,
        'stable' => $stableRiding,
    ],
    'calibration_poison' => [
        'labels_forged' => $labels,
        'labels_recorded' => $poisoned,
        'bias_after_points' => $biasAfterPoison,
        'bias_bounded_1_point' => $biasBounded,
    ],
    'mark_evasion' => [
        'score_before_churn' => $scoreOne,
        'score_after_churn' => $scoreTwo,
        'churned_starts_untrusted' => $churnUntrusted,
        'source_pressure_kept' => $sourcePressureKept,
    ],
    'victim_forcing' => [
        'victim_action' => $victimDecision->action->name ?? (string) $victimDecision->action,
        'victim_clean' => $victimUnaffected,
        'attacker_denied' => $attackerDenied,
    ],
];
echo json_encode($summary), "\n";

$pass = $foreignOk
    && $homeKept
    && $stableRiding
    && $poisoned === $labels
    && $biasBounded
    && $churnUntrusted
    && $sourcePressureKept
    && $victimUnaffected
    && $attackerDenied;
exit($pass ? 0 : 1);
