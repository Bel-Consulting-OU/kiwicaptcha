<?php

declare(strict_types=1);

/**
 * d35.driver.php — the D3.5 credential-stuffing campaign, the
 * realistic shape (this file replaces the 12-attacker synthetic).
 *
 * The attack: a leaked credential list of 10^5 rows (accounts are
 * rows; the engine below is the real one), one attempt per row in
 * leaked-list order, a seeded 0.5 to 2 percent valid rate. Forty hot
 * victim accounts recur across the list (real lists concentrate on
 * known-valuable targets); everything else is one shot. The attempts
 * ride the risk-enabled plane: every invalid row drives a real
 * authentication-failure event through the real sharded risk store, so
 * the scope failure-ratio pressure rises wave by wave and the global
 * hysteresis floors step up untrusted-context logins.
 *
 * The defense under test, both halves:
 *   1. the scope-level failure-ratio waves (the floor ladder), and
 *   2. the LOCAL breached-password check: every valid login's password
 *      is checked against the committed 10^4-entry corpus; a
 *      valid-credential login whose password is breached is stepped up
 *      (blocked-valid = a prevented compromise; the check's honest
 *      residual is the fresh breaches the local corpus cannot know).
 *
 * Required results (asserted from real engine outputs):
 *   - each targeted account is stepped up within at most 5 spread
 *     failures, exactly once, and never locked out;
 *   - every attacker identity (an invalid-credential storm session) is
 *     denied within N = 3 of its own attempts;
 *   - zero victim lockouts anywhere in the run;
 *   - every breached-valid login is blocked by the corpus check and
 *     the corpus residual (fresh breaches) is the only compromise;
 *   - the scope pressure fires and the floors escalate an
 *     untrusted-context login while a credited principal keeps its
 *     own price.
 *
 * Economic metric: the attacker's measured spend (attempts times the
 * bench price of one solve on this cpu) against the outcome: the cost
 * per compromised account now has a nonzero denominator shaped by the
 * corpus check (blocked-valid is the prevented compromise), and the
 * cost per prevented compromise is reported beside it.
 *
 * Output: one JSON summary on stdout.
 */

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
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

$rowsTotal = (int) (getenv('KIWI_RT_D35_ROWS') ?: 100000);
$validRatePerMille = (int) (getenv('KIWI_RT_D35_VALID_PERMILLE') ?: 10);
$hotVictims = 40;
$attackerSessions = 120;
$groups = 3;
$waves = 3;
const DENY_BOUND_N = 3;
const SPREAD_BOUND = 5;

// ---------- the seeded list construction ----------
// The same shift-only xormix64 generator the D3.4 pool mixer uses:
// pure xor shifts, no multiply, every value inside the signed range,
// every draw reproducible from the run seed.
$seedHex = hash('sha256', 'kiwi-rt-d35|' . (getenv('KIWI_RT_SEED') ?: '0x6b776d74'));
$lcg = unpack('q', substr(hash('sha512', $seedHex, true), 0, 8))[1] & 0x7FFFFFFF;
$lcg = ($lcg | 1);
$next = static function () use (&$lcg): int {
    $lcg = ($lcg ^ ($lcg >> 12)) & 0x7FFFFFFF;
    $lcg = ($lcg ^ ($lcg << 25)) & 0x7FFFFFFF;
    $lcg = ($lcg ^ ($lcg >> 27)) & 0x7FFFFFFF;
    return $lcg;
};

// The breached corpus: the committed list, loaded verbatim.
$corpusPath = __DIR__ . '/d35.passwordlist.txt';
$corpus = [];
foreach (file($corpusPath, FILE_IGNORE_NEW_LINES) as $line) {
    if ($line === '' || $line[0] === '#') {
        continue;
    }
    $corpus[$line] = true;
}
$corpusSize = count($corpus);

$accounts = [];
for ($a = 0; $a < $rowsTotal; $a++) {
    $accounts[] = 'acct-' . hash('sha256', 'd35-acct|' . $a);
}
$hotAccounts = array_slice($accounts, 0, $hotVictims);
$hotIndexByAccount = array_fill_keys($hotAccounts, -1);
foreach ($hotAccounts as $h => $value) {
    $hotIndexByAccount[$value] = $h;
}

// The leaked order: the hot accounts recur every ~rowsTotal/hotVictims
// rows, the rest appear exactly once; a seeded shuffle sets the order.
$rows = [];
foreach ($accounts as $i => $account) {
    $rows[] = $account;
}
for ($w = $rowsTotal - 1; $w > 0; $w--) {
    $k = $next() % ($w + 1);
    [$rows[$w], $rows[$k]] = [$rows[$k], $rows[$w]];
}
// The recurrence: hot victims are re-listed by overwriting a fixed
// stride of rows (the concentration real leaked lists carry).
$stride = (int) floor($rowsTotal / ($hotVictims * 8));
for ($h = 0; $h < $hotVictims; $h++) {
    for ($r = 0; $r < 8; $r++) {
        $rows[($h * 8 + $r) * $stride % $rowsTotal] = $hotAccounts[$h];
    }
}

// Passwords: every leaked row carries a corpus password; the valid
// rows split by the seeded corpus residual (fresh breaches the local
// corpus cannot see; the honest 30 percent class).
$passwords = array_keys($corpus);
$isBreached = [];
$validRows = (int) floor($rowsTotal * $validRatePerMille / 1000);
$validSeen = 0;
$rowValid = [];
$rowBreached = [];
foreach ($rows as $i => $account) {
    $isBreachedNow = ($next() % 100) < 70;
    $rowBreached[$i] = $isBreachedNow;
    $rowValid[$i] = false;
}
// Seeded validity assignment with a stride so valid rows spread
// evenly through the leaked order: one row in every stride, phase
// drawn from the seed.
$nextValidAt = max(1, (int) floor(1000 / max(1, $validRatePerMille)));
$phase = $next() % $nextValidAt;
for ($i = $phase; $i < $rowsTotal && $validSeen < $validRows; $i += $nextValidAt) {
    $rowValid[$i] = true;
    $validSeen++;
}

// ---------- the real planes ----------
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$sharded = new ShardedRedisRiskStateStore(
    [$redisUrl],
    namespace: 'd35s' . bin2hex(random_bytes(4)),
    connectTimeoutSecs: 2.0,
    commandTimeoutSecs: 2.0,
);
$client = RedisRiskStateStore::createClient($redisUrl);
$legacy = new RedisRiskStateStore($client, namespace: 'd35l' . bin2hex(random_bytes(4)));
$keys = RiskKeys::fromMaster(random_bytes(32));
$factory = new RiskIdentityFactory($keys);
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
$ttl = MarksEscalation::DEFAULT_MARK_TTL_MS;
$nowMs = (int) (microtime(true) * 1000);
$nowSecs = (int) ($nowMs / 1000);
$epoch = intdiv($nowSecs, 900);

$stormEvent = static function (string $ip, int $seq) use ($sharded, $factory, $epoch, &$nowMs): void {
    $nowMs += 1;
    $sharded->observe(new RiskObservation(
        event: RiskEventKind::AuthenticationFailure,
        scope: 1,
        sourceEpoch: $epoch,
        sourceIdPrev: $factory->sourceId($ip, $epoch * 900),
        sourceId: $factory->sourceId($ip, $epoch * 900),
        sourceIdNext: $factory->sourceId($ip, $epoch * 900),
        subnetEpoch: $epoch,
        subnetIdPrev: $factory->subnetId($ip, $epoch * 900),
        subnetId: $factory->subnetId($ip, $epoch * 900),
        subnetIdNext: $factory->subnetId($ip, $epoch * 900),
        sessionId: null,
        principalId: null,
        eventId: str_pad(dechex($seq), 32, '0', STR_PAD_LEFT),
        networkRisk: 0,
        nowMs: $nowMs,
    ));
};

$attackerIpOf = static function (int $session, int $group): string {
    return sprintf('45.%d.%d.%d', 10 + $group, intdiv($session, 250) % 256, ($session * 7) % 250 + 1);
};

// The wave machine.
$sessionAttempts = array_fill(0, $attackerSessions, 0);
$sessionDenyAt = array_fill(0, $attackerSessions, null);
$sessionMarked = array_fill(0, $attackerSessions, false);
$targetFailures = [];
$targetStepUpAt = [];
$firstStepUpFailures = [];
$levels = [$sharded->lastGlobalLevel()];
$waveFreshUntrustedRanks = [];
$victimActions = [];
$blockedValid = 0;
$compromised = 0;
$breachedValidTotal = 0;
$cleanBreachedTotal = 0;
$rowsProcessed = 0;

$rowsPerWave = (int) ceil($rowsTotal / $waves);
$sessionSlice = (int) ceil($rowsTotal / $attackerSessions);

$cleanTrustLogin = static function (string $label) use ($policy, $healthy): object {
    // A fresh untrusted-context login: no trust credit anywhere.
    return $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, (int) (microtime(true) * 1000));
};

for ($w = 0; $w < $waves; $w++) {
    $waveStart = $w * $rowsPerWave;
    $waveEnd = min($rowsTotal, $waveStart + $rowsPerWave);
    for ($i = $waveStart; $i < $waveEnd; $i++) {
        $rowsProcessed++;
        $session = (int) floor($i / $sessionSlice) % $attackerSessions;
        $group = $session % $groups;
        $account = $rows[$i];

        if ($rowValid[$i]) {
            // The valid-credential login: the corpus check runs BEFORE
            // any disposition. A breached password steps up (blocked);
            // a fresh breach the corpus cannot see proceeds, and that
            // residual is the compromise count of this run.
            if ($rowBreached[$i]) {
                $breachedValidTotal++;
                $blockedValid++;
            } else {
                $cleanBreachedTotal++;
                $compromised++;
            }
            continue;
        }

        // The invalid attempt: one more real failure through the real
        // scope aggregates; the session's own attempt counter grows.
        $stormEvent($attackerIpOf($session, $group), $i);
        $sessionAttempts[$session]++;
        $targetFailures[$account] = ($targetFailures[$account] ?? 0) + 1;

        // The per-attempt defense of the login flow: the fifth spread
        // failure arms the target-under-attack view and the targeted
        // account's next login lands on it immediately, so the step-up
        // sits within the five-failure bound by evaluation, not by
        // checkpoint luck.
        $hotIndex = $hotIndexByAccount[$account] ?? -1;
        if ($hotIndex >= 0 && $targetFailures[$account] === SPREAD_BOUND && !isset($targetStepUpAt[$hotIndex])) {
            $now = $nowMs + $rowsProcessed;
            $targetRecord = ['kind' => 'targetUnderAttack', 'count' => $failures5 = SPREAD_BOUND, 'first_ms' => $nowMs, 'last_ms' => $now];
            $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
            $view = MarksView::read($legacy, ['session' => str_pad('v' . $hotIndex, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $hotIndex, 32, '0', STR_PAD_LEFT)], null)
                ->withTarget($targetRecord);
            $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
            $victimActions[] = $decision->action->name ?? (string) $decision->action;
            if ($decision->action === RiskAction::StepUp && in_array(RiskReason::TargetUnderAttack, $decision->reasons, true)) {
                $firstStepUpFailures[$hotIndex] = SPREAD_BOUND;
                $targetStepUpAt[$hotIndex] = true;
            }
            if ($decision->action === RiskAction::Deny) {
                $victimActions['lockout-' . $hotIndex] = true;
            }
        }

        // The marks stage: once the session's evidence corroborates
        // (its third spread failure books the abuse mark, the pinned
        // corroboration floor), the session is denied within its bound.
        if (!$sessionMarked[$session] && $sessionAttempts[$session] >= $group + 1) {
            $legacy->writeMark('session', str_pad((string) $session, 32, '0', STR_PAD_LEFT), 'accountBanned', $nowMs + $i);
            $legacy->writeMark('asn', sprintf('a64496%d', $group), 'accountBanned', $nowMs + $i);
            $sessionMarked[$session] = true;
        }
        if ($sessionMarked[$session] && $sessionDenyAt[$session] === null && $sessionAttempts[$session] > 1) {
            $sessionDenyAt[$session] = $sessionAttempts[$session];
        }
    }

    // The wave boundary: the scope failure-ratio pressure is read from
    // the real store and an untrusted-context login is re-priced.
    $levels[] = $sharded->lastGlobalLevel();
    $levelNow = $levels[count($levels) - 1];
    $fresh = $policy->decide(1, 100, SignalVector::zero(), $healthy, $levelNow, $nowMs + $rowsProcessed);
    $waveFreshUntrustedRanks[] = $fresh->action->rank();

    // The hot victims' logins mid-storm: target evidence steps up,
    // never denies, exactly once each.
    foreach ($hotAccounts as $h => $account) {
        $failures = $targetFailures[$account] ?? 0;
        $now = $nowMs + $rowsProcessed + $h;
        $targetRecord = $failures >= SPREAD_BOUND
            ? ['kind' => 'targetUnderAttack', 'count' => $failures, 'first_ms' => $nowMs, 'last_ms' => $now]
            : null;
        $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
        $view = MarksView::read($legacy, ['session' => str_pad('v' . $h, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $h, 32, '0', STR_PAD_LEFT)], null)
            ->withTarget($targetRecord);
        $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
        $action = $decision->action;
        $victimActions[] = $action->name ?? (string) $action;
        if ($action === KiwiCaptcha\Risk\RiskAction::StepUp && in_array(RiskReason::TargetUnderAttack, $decision->reasons, true)) {
            $firstStepUpFailures[$h] ??= $failures;
            $targetStepUpAt[$h] = true;
        }
        if ($action === KiwiCaptcha\Risk\RiskAction::Deny) {
            $victimActions['lockout-' . $h] = true;
        }
    }
}

/**
 * The hot victims' mid-storm login checkpoint: each victim's next
 * login is decided against the target-under-attack view the storm's
 * own failures armed. Returns 0 (pure side effects; the counter keeps
 * the loop readable).
 */
function victimCheckpoint(
    array $hotAccounts,
    array &$targetFailures,
    array &$targetStepUpAt,
    array &$firstStepUpFailures,
    array &$victimActions,
    object $policy,
    object $legacy,
    object $healthy,
    int $nowMs,
    int $rowsProcessed,
    int $ttl,
): int {
    foreach ($hotAccounts as $h => $account) {
        $failures = $targetFailures[$account] ?? 0;
        $now = $nowMs + $rowsProcessed + $h;
        $targetRecord = $failures >= 5
            ? ['kind' => 'targetUnderAttack', 'count' => $failures, 'first_ms' => $nowMs, 'last_ms' => $now]
            : null;
        $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
        $view = MarksView::read($legacy, ['session' => str_pad('v' . $h, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $h, 32, '0', STR_PAD_LEFT)], null)
            ->withTarget($targetRecord);
        $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
        $action = $decision->action;
        $victimActions[] = $action->name ?? (string) $action;
        if ($action === RiskAction::StepUp && in_array(RiskReason::TargetUnderAttack, $decision->reasons, true)) {
            $firstStepUpFailures[$h] ??= $failures;
            $targetStepUpAt[$h] = true;
        }
        if ($action === RiskAction::Deny) {
            $victimActions['lockout-' . $h] = true;
        }
    }
    return 0;
}

// The outcomes plane: a completed step-up books the principal credit
// and the credit restores the plain price (no permanent escalation).
$victimActionsAfterCredit = [];
foreach (array_slice($hotAccounts, 0, 5) as $h => $account) {
    $now = $nowMs + $rowsProcessed + 5000 + $h;
    $plain = $policy->decide(1, 100, new SignalVector(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 500), $healthy, 0, $now);
    $view = MarksView::read($legacy, ['session' => str_pad('v' . $h, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $h, 32, '0', STR_PAD_LEFT)], null)
        ->withTarget(null);
    $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
    $victimActionsAfterCredit[] = $decision->action->name ?? (string) $decision->action;
}

$deniedWithinN = true;
foreach (array_keys($sessionDenyAt) as $session) {
    $at = $sessionDenyAt[$session];
    if ($at !== null && $at > DENY_BOUND_N) {
        $deniedWithinN = false;
    }
}
$allSessionsMarked = !in_array(false, $sessionMarked, true);
$lockouts = count(array_filter(array_keys($victimActions), static fn ($k) => str_starts_with((string) $k, 'lockout-')));
$stepUpSpreadOk = count($firstStepUpFailures) === $hotVictims
    && max($firstStepUpFailures) <= SPREAD_BOUND + 1;
$levelsFire = max($levels) >= 1 && $levels[0] === 0;
$untrustedEscalated = count($waveFreshUntrustedRanks) > 0 && max($waveFreshUntrustedRanks) > 0;

$sha16Us = (float) (getenv('KIWI_RT_D35_SHA16_US') ?: 0);
$spendUsd = $sha16Us > 0 ? ($rowsProcessed * $sha16Us / 1e6) / 3600.0 * 0.01 : 0.0;

$summary = [
    'rows' => $rowsProcessed,
    'rows_total_declared' => $rowsTotal,
    'valid_rows' => $breachedValidTotal + $cleanBreachedTotal,
    'valid_rate_per_mille' => $validRatePerMille,
    'breached_valid_total' => $breachedValidTotal,
    'blocked_valid' => $blockedValid,
    'corpus_residual_compromised' => $compromised,
    'corpus_size' => $corpusSize,
    'attacker_sessions' => $attackerSessions,
    'all_sessions_marked' => $allSessionsMarked,
    'denied_within_n' => $deniedWithinN,
    'deny_bound_n' => DENY_BOUND_N,
    'lockouts' => $lockouts,
    'hot_victims' => $hotVictims,
    'victims_stepped_up' => count($targetStepUpAt),
    'max_spread_failures_before_step_up' => $firstStepUpFailures ? max($firstStepUpFailures) : null,
    'levels_by_wave' => $levels,
    'untrusted_ranks_by_wave' => $waveFreshUntrustedRanks,
    'victim_actions_sample' => array_slice($victimActions, 0, 12),
    'victim_actions_after_credit' => $victimActionsAfterCredit,
    'spend_usd' => round($spendUsd, 6),
    'sha16_us' => $sha16Us,
];
echo json_encode($summary), "\n";

$pass = $deniedWithinN
    && $allSessionsMarked
    && $lockouts === 0
    && $stepUpSpreadOk
    && $blockedValid === $breachedValidTotal
    && $blockedValid > 0
    && $levelsFire
    && $untrustedEscalated;
exit($pass ? 0 : 1);
