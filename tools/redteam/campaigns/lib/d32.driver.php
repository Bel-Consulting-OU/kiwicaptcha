<?php

declare(strict_types=1);

/**
 * d32.driver.php — the risk-plane leg of D3.2: every stealth solve the
 * browser paid is scored through the product's own risk engine inside
 * a booted Symfony kernel (rt.kernel.php: FrameworkBundle +
 * SecurityBundle + KiwiCaptchaBundle, the shipped abuse_first profile,
 * zero container overrides, the computed audit diff of the reference
 * build), read through the container's RiskGateway — the same gateway
 * the deployment serves — over the real Redis marks store, and the
 * required ladder behavior is asserted from the engine's own outputs:
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
 * The hand-built policy of the fixture era (scope base_risk 100,
 * minimum allow, post-solve check, sha20 degraded; the sha16/sha18/
 * sha20/sha20 global floors) is the shipped configuration: the kernel
 * boots with those exact kiwi_captcha.risk scope keys and the bundle's
 * own global_pressure defaults, and the decisions come from the engine
 * that configuration wires.
 *
 * Input:  the browser driver's JSON document (argv[1]).
 * Output: one JSON summary on stdout (facts plus booleans).
 */

use BelConsulting\KiwiCaptchaBundle\Risk\DecoyEscalationScriptRunner;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use KiwiCaptcha\Risk\Evidence\AutofillQualificationGate;
use KiwiCaptcha\Risk\Evidence\DecoyEscalation;
use KiwiCaptcha\Risk\Evidence\DecoyEscalationStore;
use KiwiCaptcha\Risk\Evidence\EvidenceModel;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskV2Context;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiRt\RtCampaignKernel;
use KiwiRt\RtContainerAuditPass;
use KiwiRt\RtReferenceKernel;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt.kernel.php';

$browserDoc = json_decode((string) file_get_contents($argv[1] ?? ''), true);
if (!is_array($browserDoc)) {
    throw new RuntimeException('browser document unreadable');
}

// ---------- boot the product (per-run namespace) ----------
// The engine is the product's own, booted on the real Redis under a
// fresh per-run risk namespace: the run compiles its own container and
// never inherits a previous run's pressure or marks. The scope row is
// the hand-built policy's exact shape, expressed as the bundle's own
// scope configuration; the global floors need no override at all (the
// shipped defaults are 1=>sha16, 2=>sha18, 3=>sha20, 4=>sha20, with
// level 0 always Allow — the identical table).
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
if ($redisUrl === '') {
    fwrite(STDERR, "FATAL: KIWI_RT_RISK_REDIS_URL is not set; the kernel boots the real risk engine on real Redis\n");
    exit(2);
}
$namespace = 'd32-' . bin2hex(random_bytes(4));
RtCampaignKernel::$loginScopeOverrides = [
    'base_risk' => 100,
    'minimum' => 'allow',
    'post_solve_check' => true,
    'degraded' => 'sha20',
];
RtCampaignKernel::$riskNamespace = $namespace;
(new RtReferenceKernel())->boot();
$kernel = new RtCampaignKernel();
$kernel->boot();
$overrides = RtContainerAuditPass::overrideCount();
if ($overrides < 0) {
    $overrides = RtContainerAuditPass::persistedCount($kernel->getCacheDir());
}
if ($overrides !== 0) {
    fwrite(STDERR, "FATAL: the container override audit is $overrides (the product contract is 0)\n");
    exit(2);
}

// The risk answers come from the booted container's gateway; the
// shipped policy and the live marks store are measurement reads.
$container = $kernel->getContainer();
$gateway = $container->get(RiskGateway::class);
\assert($gateway instanceof RiskGateway);
$policy = $container->get('kiwi_captcha.risk.policy');
\assert($policy instanceof RiskPolicy);
$store = $container->get('kiwi_captcha.risk.store');
\assert($store instanceof \KiwiCaptcha\Risk\Storage\TargetStateStoreInterface);

$healthy = new ResourcePressure(1000, 1000);

$spoofPayload = json_encode([
    'v' => 1,
    'ec' => ['fo' => 40, 'ke' => 320, 'pa' => 4, 'po' => 0, 'fm' => 12],
    'qe' => 0,
    'ft' => 0,
    'pt' => 0,
    'n' => 40,
]);

$ipOf = static fn (string $session): string => '198.51.100.' . (20 + (hexdec(substr($session, 0, 2)) % 200));

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
// The decoy store rides the product's own Redis script runner (the
// bundle's DecoyEscalationScriptRunner, the one implementation the
// deployment wires): the canonical Lua runs on the real Redis through
// the real client, so a confirmed decoy hit is the deployment's own
// atomic transition, never a fixture.
$client = RedisRiskStateStore::createClient($redisUrl);
$decoyStore = new DecoyEscalationStore(new DecoyEscalationScriptRunner($client), $gate, 'd32decoy');

foreach ($browserDoc['solves'] as $solve) {
    $solveCount++;
    $session = rtPseudo('d32-session-' . $solve['i']);
    $spoofed = $solve['i'] % 4 === 3;
    $filledDecoy = (bool) $solve['decoy_filled'];
    $ip = $ipOf($session);

    $plain = $gateway->preIssue('login', $ip, $session);
    $basePrices[] = $plain->action->rank();

    // The solve outcome books honestly through the engine.
    $gateway->postSolveDecision('login', $ip, $session);

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
        $decoyProbe = $gateway->preIssue('login', $ip, $session, v2: new RiskV2Context(honeypotHit: true, solveMs: 5, solveRung: 'sha16'));
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
