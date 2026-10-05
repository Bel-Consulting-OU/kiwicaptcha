<?php

declare(strict_types=1);

/**
 * The D3.5 credential-stuffing driver (change.md D3.5, done-when of
 * change.md 3.3.3), re-driven at the deployment level.
 *
 * The attacker_stuffing pattern of both risk cores, replayed through
 * REAL surfaces: every attempt of every attacker identity walks the
 * deployment's own HTTP flow (POST /challenge, an honestly paid proof
 * of work, POST /verify), so the wire, the issuance budget and the
 * one-shot consume semantics are exercised for real; the risk plane
 * then scores the attempt through the REAL php risk engine (scorer,
 * policy, marks escalation) over the REAL Redis marks store, exactly
 * the shape packages/kiwicaptcha-risk-php/tests/
 * AttackerDenialSimulatorTest.php pins.
 *
 * The model of one attempt: the PoW never prices the attacker out
 * (commodity bots rent solves), so a verify acceptance hands the
 * credential to the login; the risk plane decides whether the login
 * proceeds. A denied attempt never reaches authentication and adds no
 * target failure. Attempt j of an attacker carries the accumulated
 * invalid-proof evidence bad_proof = min(1000, 250 * j); the outcome
 * plane writes the attacker's abuse marks (session plus shared ASN
 * bucket) once the evidence corroborates; the victim logs in mid
 * storm against the target-under-attack view and must see exactly one
 * interactive step-up and zero lockouts.
 *
 * Required result: every attacker identity denied within N of its own
 * attempts, the victim step-up exactly once and never a deny, the
 * step-up outcome credit booked with zero marks written, and every
 * HTTP leg honest (the denials come from the risk plane, never from a
 * broken flow).
 *
 * Output: one JSON summary on stdout.
 */

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
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
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;

require getenv('KIWI_RT_RISK_AUTOLOAD')
    ?: throw new RuntimeException('KIWI_RT_RISK_AUTOLOAD is required');

const K = 12;
const M = 6;
/** Documented bound: every attacker identity is denied by attempt N. */
const N = 3;
const GROUPS = 3;
const T0 = 1_700_000_000_000;
const TARGET_ATTACK_THRESHOLD = 5;

$base = rtrim((string) getenv('KIWI_RT_BASE'), '/');
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$solver = (string) getenv('KIWI_RT_SOLVER');
$namespace = 'stuffing-' . bin2hex(random_bytes(4));

$httpPosts = 0;
$httpVerifiesOk = 0;
$hashesSpent = 0;

/**
 * One honest pass through the deployment's own wire flow: issue, pay
 * the proof of work at the browser's price, carry the token.
 */
function httpAttempt(string $base, string $solver, int &$posts, int &$hashes): ?string
{
    $challenge = httpPost($base . '/challenge', ['scope' => 'login']);
    $posts++;
    $doc = json_decode($challenge, true);
    if (!is_array($doc) || !isset($doc['nonce'], $doc['prefix'], $doc['salt'], $doc['targetBits'])) {
        return null;
    }
    $counter = powSolve((string) $doc['prefix'], (string) $doc['salt'], (int) $doc['targetBits'], $hashes);
    $token = base64_encode($doc['nonce'] . '.' . $counter . '.5.{}');

    return httpPost($base . '/verify', ['token' => $token, 'scope' => 'login']);
}

function httpPost(string $url, array $payload): string
{
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "content-type: application/json\r\n",
        'content' => json_encode($payload, JSON_UNESCAPED_SLASHES),
        'timeout' => 30,
        'ignore_errors' => true,
    ]]);
    $body = (string) file_get_contents($url, false, $context);

    return $body === '' ? '{}' : $body;
}

/** The shared preimage contract: sha256(prefix || counter || salt). */
function powSolve(string $prefix, string $salt, int $targetBits, int &$hashes): int
{
    $saltRaw = base64_decode($salt, true);
    if ($saltRaw === false) {
        throw new RuntimeException('salt did not decode');
    }
    $fullBytes = intdiv($targetBits, 8);
    $remBits = $targetBits % 8;
    for ($counter = 0; ; $counter++) {
        $digest = hash('sha256', $prefix . (string) $counter . $saltRaw, true);
        $hashes++;
        $pass = true;
        for ($i = 0; $i < $fullBytes; $i++) {
            if (ord($digest[$i]) !== 0) {
                $pass = false;
                break;
            }
        }
        if ($pass && $remBits > 0 && (ord($digest[$fullBytes]) >> (8 - $remBits)) !== 0) {
            $pass = false;
        }
        if ($pass) {
            return $counter;
        }
    }
}

$client = RedisRiskStateStore::createClient($redisUrl);
$client->ping();
$store = new RedisRiskStateStore($client, namespace: $namespace);
$cleanupKeys = static function () use ($client, $store): void {
    foreach (range(0, K - 1) as $i) {
        $client->del([$store->markKey('session', sprintf('%032x', $i + 1))]);
    }
    foreach (range(0, GROUPS - 1) as $group) {
        $client->del([$store->markKey('asn', sprintf('a%d', 64496 + $group))]);
    }
};

$weights = new RiskWeights();
$scorer = new RiskScorer();
$policy = RiskPolicy::fromConfig([
    'version' => 3,
    'weights' => $weights->toArray(),
    'scopes' => [
        1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
    ],
    'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
]);
$healthy = new ResourcePressure(1000, 1000);
$ttl = MarksEscalation::DEFAULT_MARK_TTL_MS;

$victimSession = str_repeat('e5', 16);
$victimPrincipal = str_repeat('f6', 16);
$sessions = array_map(static fn (int $i): string => sprintf('%032x', $i + 1), range(0, K - 1));
$buckets = array_map(static fn (int $g): string => sprintf('a%d', 64496 + $g), range(0, GROUPS - 1));

$targetFailures = 0;
$lastFailureAt = 0;
$attackStartedAt = 0;
$stepUpCompleted = false;
$marked = array_fill(0, K, false);
$deniedAt = [];
$victimActions = [];
$wireFailures = 0;

$targetRecord = null;
$refreshTargetRecord = static function () use (&$targetRecord, &$targetFailures, &$attackStartedAt, &$lastFailureAt): void {
    $targetRecord = $targetFailures >= TARGET_ATTACK_THRESHOLD
        ? ['kind' => 'targetUnderAttack', 'count' => $targetFailures, 'first_ms' => $attackStartedAt, 'last_ms' => $lastFailureAt]
        : null;
};

try {
    // Round-robin: round j runs every attacker once, mirroring the
    // core simulator's ordering so the shared bucket marks land the
    // same way.
    for ($j = 1; $j <= M; $j++) {
        for ($i = 0; $i < K; $i++) {
            $now = T0 + ((($j - 1) * K) + $i) * 1000;
            $badProof = min(1000, 250 * $j);
            $signals = new SignalVector(0, 0, 0, 0, $badProof, 0, 0, 0, 0, 0, 0, 0, 0);
            $score = $scorer->score(100, $signals, $weights);
            $plain = $policy->decide(1, $score, $signals, $healthy, 0, $now);

            // The wire leg: the attempt walks the deployment's own
            // challenge and verify surfaces with an honestly paid
            // proof, exactly a rented-solve bot would.
            $verifyBody = httpAttempt($base, $solver, $httpPosts, $hashesSpent);
            $wireDoc = json_decode((string) $verifyBody, true);
            if (!is_array($wireDoc) || ($wireDoc['ok'] ?? false) !== true) {
                $wireFailures++;
            } else {
                $httpVerifiesOk++;
            }

            $bucket = $buckets[intdiv($i * GROUPS, K)];
            $refreshTargetRecord();
            $view = MarksView::read($store, ['session' => $sessions[$i], 'asn' => $bucket], null)
                ->withTarget($targetRecord);
            $decision = MarksEscalation::apply($plain, $view, MarksEscalation::corroborated($signals, false), $now, $ttl, $healthy);
            if ($decision->action === RiskAction::Deny) {
                $deniedAt[$i] ??= $j;
            } else {
                // The attempt reaches the login and fails: one more
                // target failure.
                $targetFailures++;
                if ($targetFailures === TARGET_ATTACK_THRESHOLD) {
                    $attackStartedAt = $now;
                }
                $lastFailureAt = $now;
            }
            if (!$marked[$i] && $badProof >= MarksEscalation::CORROBORATION_FLOOR) {
                $store->writeMark('session', $sessions[$i], 'accountBanned', $now);
                $store->writeMark('asn', $bucket, 'accountBanned', $now);
                $marked[$i] = true;
            }
        }

        if ($j === 2) {
            // The victim logs in while the target is under attack.
            $now = T0 + (K * 2) * 1000;
            $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
            $refreshTargetRecord();
            $view = MarksView::read($store, ['session' => $victimSession, 'principal' => $victimPrincipal], null)
                ->withTarget($targetRecord);
            $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
            $victimActions[] = $decision->action;
            $victimStepUpReason = $decision->hasReason(RiskReason::TargetUnderAttack);

            // The step-up completes: the outcome credit through the
            // typed outcomes facade over the same real marks store.
            $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
            $engine = new AdaptiveRiskEngine(
                store: $store,
                classifier: new CidrNetworkClassifier([]),
                identityFactory: new RiskIdentityFactory($keys),
                scorer: $scorer,
                policy: $policy,
                keys: $keys,
            );
            $outcomes = new KiwiOutcomes($engine, $store);
            $receipt = $outcomes->report(
                Outcome::StepUpCompleted,
                OutcomeHandle::principal($victimPrincipal),
                'victim-step-up-credit',
                new RiskContext(
                    scope: 1,
                    sourceIp: '203.0.113.7',
                    sessionId: $victimSession,
                    principalId: $victimPrincipal,
                    event: RiskEventKind::ProtectedActionSuccess,
                    networkFlags: (new CidrNetworkClassifier([]))->classify('203.0.113.7'),
                    resources: new ResourcePressure(1000, 1000),
                ),
            );
            $stepUpCompleted = $receipt->channelBooked && $receipt->marksWritten === 0;
        }
    }

    // The relief round: a quiet window decays the rolling failure
    // count and the victim's credit restores the plain allow.
    $quietAt = $lastFailureAt + 900_000;
    $targetFailures = 0;
    $refreshTargetRecord();
    $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $quietAt);
    $view = MarksView::read($store, ['session' => $victimSession, 'principal' => $victimPrincipal], null)
        ->withTarget($targetRecord);
    $relief = MarksEscalation::apply($plain, $view, false, $quietAt, $ttl, $healthy);
    $victimActions[] = $relief->action;
} finally {
    $cleanupKeys();
}

$deniedWithinN = count($deniedAt) === K;
foreach ($deniedAt as $attempt) {
    if ($attempt < 2 || $attempt > N) {
        $deniedWithinN = false;
    }
}
$exactlyOneStepUp = count($victimActions) === 2
    && $victimActions[0] === RiskAction::StepUp
    && $victimActions[1] === RiskAction::Allow
    && ($victimStepUpReason ?? false);
$noLockout = !in_array(RiskAction::Deny, $victimActions, true);

$summary = json_encode([
    'attackers' => K,
    'rounds' => M,
    'bound_n' => N,
    'denied_within_n' => $deniedWithinN,
    'denial_rounds' => array_values($deniedAt),
    'victim_actions' => array_map(static fn ($a) => $a->name ?? (string) $a, $victimActions),
    'exactly_one_step_up' => $exactlyOneStepUp,
    'zero_lockouts' => $noLockout,
    'step_up_credit_booked' => $stepUpCompleted,
    'wire_verifies_ok' => $httpVerifiesOk,
    'wire_failures' => $wireFailures,
    'http_posts' => $httpPosts,
    'pow_hashes_spent' => $hashesSpent,
    'marks_store' => 'redis',
    'namespace' => $namespace,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

// The summary goes straight to the file the campaign wrapper parses,
// so the shell never races this process's stdout flush.
$summaryPath = getenv('KIWI_RT_SUMMARY_PATH');
if (is_string($summaryPath) && $summaryPath !== '') {
    file_put_contents($summaryPath, $summary . "\n");
}
echo $summary, "\n";

$pass = $deniedWithinN && $exactlyOneStepUp && $noLockout && $stepUpCompleted && $wireFailures === 0;
exit($pass ? 0 : 1);
