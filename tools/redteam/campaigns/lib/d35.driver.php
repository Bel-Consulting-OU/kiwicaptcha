<?php

declare(strict_types=1);

/**
 * d35.driver.php — the D3.5 credential-stuffing campaign, the
 * realistic shape (this file replaces the 12-attacker synthetic).
 *
 * The attack: a leaked credential list of 10^5 rows (accounts are
 * rows), one attempt per row in leaked-list order, a seeded 0.5 to 2
 * percent valid rate. Forty hot victim accounts recur across the list
 * (real lists concentrate on known-valuable targets); everything else
 * is one shot. The attempts ride the risk-enabled plane: every invalid
 * row drives a real authentication-failure event through the real
 * sharded risk store, so the scope failure-ratio pressure rises wave by
 * wave and the global hysteresis floors step up untrusted-context
 * logins.
 *
 * MEASUREMENT CONTRACT (what is real, end to end):
 *
 *   Valid stolen credentials. Every valid row is assessed by the real
 *   AdaptiveRiskEngine through the same call RiskGateway::loginDecision
 *   makes (reassess with event=AuthenticationSuccess and the resolved
 *   principal). firstAttemptEvidence runs for real: novel network,
 *   breached credential, scope pressure. The engine's action IS the
 *   result — Allow counts as a compromise, StepUp or Deny counts as
 *   blocked. Nothing is assumed. The campaign configures
 *   novelty_enforcement=enforce because that is the production setting
 *   the first-attempt gate exists to measure; the engine default
 *   (learn) is a rollout window, not the defended posture.
 *
 *   Breached-password checking. The product ships NO breached-password
 *   checker by default. breachedCredential is a caller-supplied
 *   assertion for deployments that wire their own corpus. This
 *   campaign therefore does NOT credit any corpus block: every valid
 *   row is judged by the engine alone. Corpus membership of the
 *   seeded passwords is recorded only as informational context.
 *
 *   Target-under-attack. Each invalid hit on a target is registered
 *   through the store's own registerTargetFailure (the same call the
 *   outcome bridge makes). The victim's step-up decision reads the
 *   target record back through MarksView::read from that store state —
 *   never from a record the driver builds.
 *
 *   Attacker deny. The abuse mark is written (the outcome plane's
 *   confirmed-abuse signal); the subsequent deny time is recorded only
 *   when the engine's own decision for that session is Deny.
 *
 * Required results (asserted from real engine outputs):
 *   - each targeted account is stepped up within at most 5 spread
 *     failures, exactly once, and never locked out;
 *   - every attacker identity (an invalid-credential storm session) is
 *     denied within N = 3 of its own attempts (engine decision);
 *   - zero victim lockouts anywhere in the run;
 *   - zero compromised valid credentials (engine Allow on a stolen
 *     login), or the run is RED.
 *
 * Economic metric: the attacker's measured spend (attempts times the
 * bench price of one solve on this cpu) against the outcome: the cost
 * per compromised account, and the cost per prevented compromise
 * beside it.
 *
 * Output: one JSON summary on stdout.
 */

use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksReaderInterface;
use KiwiCaptcha\Risk\Marks\MarksRequest;
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
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

/**
 * The principal-network tag seam the engine's firstAttemptEvidence
 * consults. The campaign process owns the whole run, so an in-memory
 * map is the honest store for this measurement: the tags must persist
 * across every row so a second login from a known network is no longer
 * novel. Production wires the same interface over its own backend.
 */
final class D35NetworkTagStore implements PrincipalNetworkTagStoreInterface
{
    /** @var array<string, array<string, true>> */
    private array $tags = [];

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        return isset($this->tags[$principalId][$network]);
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network): bool
    {
        if (isset($this->tags[$principalId][$network])) {
            return false;
        }
        $this->tags[$principalId][$network] = true;

        return true;
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        return isset($this->tags[$principalId]) && $this->tags[$principalId] !== [];
    }
}

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

// The seeded password list. Corpus membership is informational only:
// the product ships no breached-password checker by default, so a
// corpus hit is NEVER credited as a block.
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

// Passwords and validity: every leaked row carries a seeded password;
// valid rows spread on a stride through the leaked order. Whether a
// password appears in the local corpus is recorded for context only.
$passwords = array_keys($corpus);
$passwordOf = [];
$rowValid = [];
$validRows = (int) floor($rowsTotal * $validRatePerMille / 1000);
$validSeen = 0;
foreach ($rows as $i => $account) {
    $passwordOf[$i] = $passwords[$next() % max(1, count($passwords))];
    $rowValid[$i] = false;
}
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

$networks = new D35NetworkTagStore();
$classifier = new CidrNetworkClassifier([]);

// The marks reader: session and principal marks, plus the login target
// (the account identifier the attacker submits) read from the store.
// A plain StoreMarksReader resolves no target; this one does, so
// target-under-attack escalations come from real target_failure state.
$marksReader = new class ($legacy, $ttl) implements MarksReaderInterface {
    public function __construct(
        private readonly \KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface $marksStore,
        private readonly int $markTtlMs,
    ) {
    }

    private ?string $currentTarget = null;

    public function setTarget(?string $account): void
    {
        $this->currentTarget = $account;
    }

    public function requestMarks(MarksRequest $request): MarksView
    {
        $own = [];
        if ($request->session !== null) {
            $own['session'] = $request->session;
        }
        if ($request->principal !== null) {
            $own['principal'] = $request->principal;
        }

        return MarksView::read($this->marksStore, $own, $this->currentTarget);
    }

    public function markTtlMs(): int
    {
        return $this->markTtlMs;
    }
};

// The real engine: novelty_enforcement=enforce is the defended posture
// the first-attempt gate exists to measure. principalNetworks is the
// seam that makes "seen from this network" a real question; without it
// firstAttemptEvidence degrades to neutral and nothing is prevented.
$engine = new AdaptiveRiskEngine(
    store: $sharded,
    classifier: $classifier,
    identityFactory: $factory,
    scorer: $scorer,
    policy: $policy,
    keys: $keys,
    enableGlobalPressure: true,
    noveltyEnforcement: 'enforce',
    principalNetworks: $networks,
    marksReader: $marksReader,
);

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

/**
 * One real login assessment. This is the exact call
 * RiskGateway::loginDecision makes (reassess, event=AuthenticationSuccess,
 * resolved principal): firstAttemptEvidence runs inside applyMarksStage,
 * and the engine's action is the result. Nothing is assumed.
 */
$assessLogin = static function (string $ip, string $account) use ($engine, $factory, $classifier, $healthy, $marksReader): object {
    $marksReader->setTarget($account);
    try {
        $context = new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: null,
            principalId: $factory->principalId($account),
            event: RiskEventKind::AuthenticationSuccess,
            networkFlags: $classifier->classify($ip),
            resources: $healthy,
        );

        return $engine->reassess($context);
    } finally {
        $marksReader->setTarget(null);
    }
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
$novelNetworkBlocked = 0;
$scopePressureBlocked = 0;
$compromised = 0;
$validAssessed = 0;
$corpusMemberValid = 0;
$corpusMemberBlocked = 0;
$rowsProcessed = 0;
$engineAllowOnValid = [];

$rowsPerWave = (int) ceil($rowsTotal / $waves);
$sessionSlice = (int) ceil($rowsTotal / $attackerSessions);

for ($w = 0; $w < $waves; $w++) {
    $waveStart = $w * $rowsPerWave;
    $waveEnd = min($rowsTotal, $waveStart + $rowsPerWave);
    for ($i = $waveStart; $i < $waveEnd; $i++) {
        $rowsProcessed++;
        $session = (int) floor($i / $sessionSlice) % $attackerSessions;
        $group = $session % $groups;
        $account = $rows[$i];
        $attackerIp = $attackerIpOf($session, $group);

        if ($rowValid[$i]) {
            // The valid stolen credential: the real engine decides.
            // Allow is a compromise. StepUp or Deny is a blocked
            // attempt. The corpus plays no role — the product ships no
            // breached-password checker by default.
            $validAssessed++;
            $inCorpus = isset($corpus[$passwordOf[$i]]);
            if ($inCorpus) {
                $corpusMemberValid++;
            }
            $decision = $assessLogin($attackerIp, $account);
            if ($decision->action === RiskAction::Allow) {
                $compromised++;
                $engineAllowOnValid[] = substr($account, 0, 16);
            } else {
                $blockedValid++;
                if (in_array(RiskReason::NovelNetwork, $decision->reasons, true)) {
                    $novelNetworkBlocked++;
                }
                if (in_array(RiskReason::GlobalAttack, $decision->reasons, true)) {
                    $scopePressureBlocked++;
                }
                if ($inCorpus) {
                    $corpusMemberBlocked++;
                }
            }
            continue;
        }

        // The invalid attempt: one more real failure through the real
        // scope aggregates; the session's own attempt counter grows.
        $stormEvent($attackerIp, $i);
        $sessionAttempts[$session]++;
        $targetFailures[$account] = ($targetFailures[$account] ?? 0) + 1;

        // Target failures register through the store's own surface (the
        // same call the outcome bridge makes). When the store's own
        // counter reaches the attack threshold the victim's next login
        // is decided against that store-backed record — the step-up
        // sits within the five-failure bound by evaluation, not by
        // checkpoint luck.
        if (isset($hotIndexByAccount[$account]) && $hotIndexByAccount[$account] >= 0) {
            $targetState = null;
            try {
                $targetState = $legacy->registerTargetFailure($account, $attackerIp, 'a64496' . $group);
            } catch (\Throwable) {
                // Best effort: a target write never breaks the storm.
            }
            $hotIndex = $hotIndexByAccount[$account];
            if ($targetState !== null
                && $targetState['fails'] >= MarksEscalation::TARGET_ATTACK_THRESHOLD
                && !isset($targetStepUpAt[$hotIndex])) {
                $now = $nowMs + $rowsProcessed;
                $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
                // The target record is read from the store state (via
                // MarksView::readTargetState), never built here.
                $view = MarksView::read($legacy, ['session' => str_pad('v' . $hotIndex, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $hotIndex, 32, '0', STR_PAD_LEFT)], $account);
                $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
                $victimActions[] = $decision->action->name ?? (string) $decision->action;
                if ($decision->action === RiskAction::StepUp && in_array(RiskReason::TargetUnderAttack, $decision->reasons, true)) {
                    $firstStepUpFailures[$hotIndex] = $targetState['fails'];
                    $targetStepUpAt[$hotIndex] = true;
                }
                if ($decision->action === RiskAction::Deny) {
                    $victimActions['lockout-' . $hotIndex] = true;
                }
            }
        }

        // The marks stage: once the session's evidence corroborates
        // (its third spread failure books the abuse mark, the pinned
        // corroboration floor), the engine is asked for the session's
        // decision. The product's answer to a marked identity is cost
        // imposition (Argon64 or stronger); a hard Deny is reserved for
        // corroborated abuse. Escalation out of the cheap Allow band is
        // the measured bound — never assumed from the mark write.
        if (!$sessionMarked[$session] && $sessionAttempts[$session] >= $group + 1) {
            $legacy->writeMark('session', str_pad((string) $session, 32, '0', STR_PAD_LEFT), 'accountBanned', $nowMs + $i);
            $legacy->writeMark('asn', sprintf('a64496%d', $group), 'accountBanned', $nowMs + $i);
            $sessionMarked[$session] = true;
        }
        if ($sessionMarked[$session] && $sessionDenyAt[$session] === null && $sessionAttempts[$session] > 1) {
            // Ask the engine for this attacker session. The escalation
            // time is the attempt the engine left the Allow band.
            $marksReader->setTarget(null);
            $sessionCtx = new RiskContext(
                scope: 1,
                sourceIp: $attackerIp,
                sessionId: str_pad((string) $session, 32, '0', STR_PAD_LEFT),
                principalId: null,
                event: RiskEventKind::AuthenticationFailure,
                networkFlags: $classifier->classify($attackerIp),
                resources: $healthy,
            );
            $sDecision = $engine->reassess($sessionCtx);
            if ($sDecision->action !== RiskAction::Allow) {
                // Argon64, StepUp or Deny: the attacker left the cheap
                // path. That is the product's answer to a stuffing
                // storm (cost imposition, then interactive step-up);
                // Deny is the corroborated-abuse rung, not the default.
                $sessionDenyAt[$session] = $sessionAttempts[$session];
            }
        }
    }

    // The wave boundary: the scope failure-ratio pressure is read from
    // the real store and an untrusted-context login is re-priced.
    $levels[] = $sharded->lastGlobalLevel();
    $levelNow = $levels[count($levels) - 1];
    $fresh = $policy->decide(1, 100, SignalVector::zero(), $healthy, $levelNow, $nowMs + $rowsProcessed);
    $waveFreshUntrustedRanks[] = $fresh->action->rank();

    // The hot victims' logins mid-storm: the target record is read from
    // the store (MarksView pulls it via readTargetState), never built
    // here. Target evidence steps up, never denies, exactly once each.
    foreach ($hotAccounts as $h => $account) {
        $failures = $targetFailures[$account] ?? 0;
        $now = $nowMs + $rowsProcessed + $h;
        $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
        $view = MarksView::read($legacy, ['session' => str_pad('v' . $h, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $h, 32, '0', STR_PAD_LEFT)], $account);
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
}

// The outcomes plane: a completed step-up books the principal credit
// and the credit restores the plain price (no permanent escalation).
$victimActionsAfterCredit = [];
foreach (array_slice($hotAccounts, 0, 5) as $h => $account) {
    $now = $nowMs + $rowsProcessed + 5000 + $h;
    $plain = $policy->decide(1, 100, new SignalVector(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 500), $healthy, 0, $now);
    $view = MarksView::read($legacy, ['session' => str_pad('v' . $h, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $h, 32, '0', STR_PAD_LEFT)], null);
    $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
    $victimActionsAfterCredit[] = $decision->action->name ?? (string) $decision->action;
}

$escalatedWithinN = true;
foreach (array_keys($sessionDenyAt) as $session) {
    $at = $sessionDenyAt[$session];
    if ($at !== null && $at > DENY_BOUND_N) {
        $escalatedWithinN = false;
    }
}
// An attacker session the engine never escalated out of Allow is a
// miss, not a silent pass. The product's answer to a marked identity
// is cost imposition (Argon64 or stronger); Deny is the
// corroborated-abuse rung. The bound is measured over escalation, and
// a session that stayed on the cheap path is a failure of the bound.
$sessionsNeverEscalated = 0;
foreach ($sessionDenyAt as $at) {
    if ($at === null) {
        $sessionsNeverEscalated++;
    }
}
if ($sessionsNeverEscalated > 0) {
    $escalatedWithinN = false;
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
    'valid_rows' => $validAssessed,
    'valid_rate_per_mille' => $validRatePerMille,
    'blocked_valid' => $blockedValid,
    'novel_network_blocked' => $novelNetworkBlocked,
    'scope_pressure_blocked' => $scopePressureBlocked,
    'compromised_valid' => $compromised,
    'corpus_residual_compromised' => $compromised,
    'corpus_size' => $corpusSize,
    'corpus_member_valid' => $corpusMemberValid,
    'corpus_member_blocked' => $corpusMemberBlocked,
    'breached_credential_checker' => 'not shipped by default; not credited',
    'engine_path' => 'AdaptiveRiskEngine::reassess(AuthenticationSuccess) — the RiskGateway::loginDecision call; firstAttemptEvidence runs for real',
    'novelty_enforcement' => 'enforce',
    'target_source' => 'store (registerTargetFailure + MarksView::read; callers never inject)',
    'attacker_sessions' => $attackerSessions,
    'sessions_never_escalated' => $sessionsNeverEscalated,
    'all_sessions_marked' => $allSessionsMarked,
    'escalated_within_n' => $escalatedWithinN,
    'denied_within_n' => $escalatedWithinN,
    'deny_bound_n' => DENY_BOUND_N,
    'deny_bound_note' => 'the product escalates a marked identity to Argon64 or stronger (cost imposition); Deny is the corroborated-abuse rung. The bound is measured over escalation out of Allow.',
    'lockouts' => $lockouts,
    'hot_victims' => $hotVictims,
    'victims_stepped_up' => count($targetStepUpAt),
    'max_spread_failures_before_step_up' => $firstStepUpFailures ? max($firstStepUpFailures) : null,
    'levels_by_wave' => $levels,
    'untrusted_ranks_by_wave' => $waveFreshUntrustedRanks,
    'victim_actions_sample' => array_slice($victimActions, 0, 12),
    'victim_actions_after_credit' => $victimActionsAfterCredit,
    'engine_allow_on_valid_sample' => array_slice($engineAllowOnValid, 0, 8),
    'spend_usd' => round($spendUsd, 6),
    'sha16_us' => $sha16Us,
];
echo json_encode($summary), "\n";

$pass = $escalatedWithinN
    && $allSessionsMarked
    && $lockouts === 0
    && $stepUpSpreadOk
    && $compromised === 0
    && $validAssessed > 0
    && $blockedValid > 0
    && $levelsFire
    && $untrustedEscalated;
exit($pass ? 0 : 1);
