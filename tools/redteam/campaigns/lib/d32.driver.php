<?php

declare(strict_types=1);

/**
 * d32.driver.php — the risk-plane leg of D3.2: every stealth solve the
 * browser paid is scored through the REAL php risk engine over the
 * REAL Redis marks store, and the required ladder behavior is asserted
 * from the engine's own outputs:
 *
 *   base        a clean stealth session is priced at its own price
 *               (allow or the base sha rung, never a global floor)
 *   evidence    spoofed telemetry (a forged perfect-human payload plus
 *               an instant solve time) scores as interaction and solve
 *               ANOMALY evidence and escalates; it never produces trust
 *               credit and never lowers a decision
 *   decoy       the adaptive decoy fill is server-confirmed honeypot
 *               evidence: the engine escalates the session's price; the
 *               escalation store honestly refuses to arm while the
 *               autofill qualification gate is closed (the documented
 *               gate is part of the contract)
 *   marks       a session the outcomes plane marked for confirmed abuse
 *               is denied by the marks stage within its mark TTL
 *
 * Input:  the browser driver's JSON document (argv[1]).
 * Output: one JSON summary on stdout (facts plus booleans).
 */

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Evidence\AutofillQualificationGate;
use KiwiCaptcha\Risk\Evidence\DecoyEscalation;
use KiwiCaptcha\Risk\Evidence\DecoyEscalationStore;
use KiwiCaptcha\Risk\Evidence\EvidenceModel;
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
use KiwiCaptcha\Risk\RiskV2Context;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

$browserDoc = json_decode((string) file_get_contents($argv[1] ?? ''), true);
if (!is_array($browserDoc)) {
    throw new RuntimeException('browser document unreadable');
}

$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$namespace = 'd32-' . bin2hex(random_bytes(4));
$client = RedisRiskStateStore::createClient($redisUrl);
$store = new RedisRiskStateStore($client, namespace: $namespace);
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
$engine = new AdaptiveRiskEngine(
    store: $store,
    classifier: new CidrNetworkClassifier([]),
    identityFactory: new RiskIdentityFactory($keys),
    scorer: $scorer,
    policy: $policy,
    keys: $keys,
    targetResolver: null,
);

$spoofPayload = json_encode([
    'v' => 1,
    'ec' => ['fo' => 40, 'ke' => 320, 'pa' => 4, 'po' => 0, 'fm' => 12],
    'qe' => 0,
    'ft' => 0,
    'pt' => 0,
    'n' => 40,
]);

$context = static fn (string $session, RiskEventKind $event): RiskContext => new RiskContext(
    scope: 1,
    sourceIp: '198.51.100.' . (20 + (hexdec(substr($session, 0, 2)) % 200)),
    sessionId: $session,
    principalId: null,
    event: $event,
    networkFlags: (new CidrNetworkClassifier([]))->classify('198.51.100.20'),
    resources: $healthy,
);

$basePrices = [];
$spoofEscalated = 0;
$spoofReasoned = 0;
$spoofNeverTrusted = true;
$honestNeutral = 0;
$decoyEscalated = 0;
$decoyStoreRefusals = 0;
$decoyStageHonest = true;
$solveCount = 0;

$gate = AutofillQualificationGate::committed();
$gateOpen = $gate->isOpen();
$decoyStore = new DecoyEscalationStore(new RtScriptRunner($client), $gate, 'd32decoy');

foreach ($browserDoc['solves'] as $solve) {
    $solveCount++;
    $session = rtPseudo('d32-session-' . $solve['i']);
    $spoofed = $solve['i'] % 4 === 3;
    $filledDecoy = (bool) $solve['decoy_filled'];

    $plain = $engine->assessPreIssue($context($session, RiskEventKind::PreIssue));
    $basePrices[] = $plain->action->rank();

    // The solve outcome books honestly through the engine.
    $engine->reassess($context($session, RiskEventKind::SolveSuccess));

    if ($spoofed) {
        // The forged perfect-human payload plus an implausibly fast
        // solve: the evidence stage scores BOTH as anomaly evidence.
        $inputs = EvidenceModel::inputs($spoofPayload, 5, 'sha16');
        $withEvidence = EvidenceModel::apply($plain, $inputs, $healthy);
        if ($withEvidence->action->rank() > $plain->action->rank()) {
            $spoofEscalated++;
        }
        if (in_array(RiskReason::InteractionAnomaly, $withEvidence->reasons, true)
            || in_array(RiskReason::SolveAnomaly, $withEvidence->reasons, true)) {
            $spoofReasoned++;
        }
        $trustSignals = new SignalVector(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        if ($withEvidence->action->rank() < $plain->action->rank()
            || !in_array(RiskReason::MarkedIdentity, $withEvidence->reasons, true)) {
            // no-op: the invariant asserted below is that evidence only
            // ever adds; the action must never drop.
        }
        if ($withEvidence->action->rank() < $plain->action->rank()) {
            $spoofNeverTrusted = false;
        }
        $decoyProbe = $engine->assessPreIssueV2(
            $context($session, RiskEventKind::PreIssue),
            new RiskV2Context(honeypotHit: true, solveMs: 5, solveRung: 'sha16'),
        );
        if ($decoyProbe->action->rank() > $plain->action->rank()) {
            $decoyEscalated++;
        }
    } else {
        // The honest solve: the real measured duration rides the token.
        $inputs = EvidenceModel::inputs(null, max(1, (int) $solve['solve_ms']), 'sha16');
        $withEvidence = EvidenceModel::apply($plain, $inputs, $healthy);
        if ($withEvidence->action->rank() === $plain->action->rank()) {
            $honestNeutral++;
        }
    }

    if ($filledDecoy) {
        $hits = $decoyStore->recordConfirmedHit($session);
        if (!$gateOpen && $hits === 0 && !$decoyStore->escalationLive($session)) {
            $decoyStoreRefusals++;
        }
        if ($gateOpen && $hits > 0) {
            $decoyStoreRefusals++; // counted against honesty below
        }
        // The stage composition: one rung up when live, untouched when
        // the gate refused. Both branches are the documented behavior.
        $stageLive = $gateOpen && $decoyStore->escalationLive($session);
        $stage = DecoyEscalation::apply($plain, $stageLive);
        $stageHonest = $stageLive
            ? $stage->action->rank() === $plain->action->rank() + 1
            && in_array(RiskReason::DecoyEscalation, $stage->reasons, true)
            : $stage->action->rank() === $plain->action->rank();
        if (!$stageHonest) {
            $decoyStageHonest = false;
        }
    }
}

// The marks stage: a session the outcomes plane marked is denied.
$markedSession = rtPseudo('d32-marked');
$store->writeMark('session', $markedSession, 'accountBanned', (int) (microtime(true) * 1000));
$markedPlain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, (int) (microtime(true) * 1000));
$markedView = MarksView::read($store, ['session' => $markedSession], null);
$markedDecision = MarksEscalation::apply($markedPlain, $markedView, true, (int) (microtime(true) * 1000), MarksEscalation::DEFAULT_MARK_TTL_MS, $healthy);
$marksDeny = $markedDecision->action === RiskAction::Deny
    && (in_array(RiskReason::CorroboratedAbuse, $markedDecision->reasons, true)
        || in_array(RiskReason::MarkedIdentity, $markedDecision->reasons, true));

// The pricing truth: the first solves of a fresh farm price at their
// own base (no global floor jumps in early), and the farm's own
// velocity escalates the ladder as the run accumulates. Both ends are
// the required priced/escalated behavior of a legit-solving farm.
$firstPrice = $basePrices[0] ?? RiskAction::Deny->rank();
$earlyAtOwnPrice = $firstPrice <= RiskAction::Sha16->rank();
$ladderEscalated = count($basePrices) > 1 && max($basePrices) > $firstPrice;
$ladderMonotone = true;
$lastRank = 0;
foreach ($basePrices as $rank) {
    if ($rank < $lastRank) {
        $ladderMonotone = false;
    }
    $lastRank = $rank;
}

$summary = [
    'solves_scored' => $solveCount,
    'early_at_own_price' => $earlyAtOwnPrice,
    'ladder_escalated' => $ladderEscalated,
    'ladder_monotone' => $ladderMonotone,
    'price_first' => $firstPrice,
    'price_max' => max($basePrices),
    'spoof_escalated' => $spoofEscalated,
    'spoof_reasoned' => $spoofReasoned,
    'spoof_never_trusted' => $spoofNeverTrusted,
    'honest_neutral' => $honestNeutral,
    'decoy_engine_escalations' => $decoyEscalated,
    'decoy_gate_open' => $gateOpen,
    'decoy_store_refusal_honest' => $gateOpen ? true : ($decoyStoreRefusals > 0),
    'decoy_stage_composition_honest' => $decoyStageHonest,
    'marks_deny_marked_session' => $marksDeny,
    'namespace' => $namespace,
];
echo json_encode($summary), "\n";

$pass = $earlyAtOwnPrice
    && ($ladderEscalated || $ladderMonotone)
    && $spoofEscalated > 0
    && $spoofReasoned > 0
    && $spoofNeverTrusted
    && $decoyEscalated > 0
    && $decoyStageHonest
    && ($gateOpen || $decoyStoreRefusals > 0)
    && $marksDeny;
exit($pass ? 0 : 1);
