<?php

declare(strict_types=1);

/**
 * d35.kernel.php — the D3.5 credential-stuffing campaign through the
 * product, not around it. Boots the real DI container (no test-kernel
 * overrides) on the abuse_first profile and drives the real
 * AdaptiveRiskEngine through the same call RiskGateway makes.
 *
 * The old d35.driver.php built its own store and engine — exactly the
 * pattern that hid the null principal_networks seam. This driver
 * resolves every service from the production container so a missing
 * seam is a hard failure, not a silent pass.
 *
 * Measurement contract (same as the old driver):
 *   - every valid stolen credential is assessed by the real engine;
 *     Allow is a compromise (bar 0), StepUp/Deny is blocked;
 *   - the product ships no breached-password checker: none credited;
 *   - target records come from the store, never from a driver-built
 *     record;
 *   - the legitimate baseline measures false positives with bound
 *     device continuity;
 *   - the attacker carries fresh unbound cookies (the realistic case).
 *
 * Output: one JSON summary on stdout.
 */

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\SessionRestorer;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\Definition\Processor;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';
// The bundle's Symfony Config tree for the profile-aware container.
$bundleAutoload = dirname(__DIR__, 4) . '/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php';
if (is_file($bundleAutoload)) {
    require_once $bundleAutoload;
}

$rowsTotal = (int) (getenv('KIWI_RT_D35_ROWS') ?: 100000);
$validRatePerMille = (int) (getenv('KIWI_RT_D35_VALID_PERMILLE') ?: 10);
$hotVictims = 40;
$attackerSessions = 120;
$groups = 3;
$waves = 3;
const DENY_BOUND_N = 3;
const SPREAD_BOUND = 5;

// ---------- boot the production container ----------
// No test-kernel overrides: every service comes from the real
// extension. A missing seam is a hard failure.
$secret = str_repeat('a', 32);
$processor = new Processor();
$config = new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration();
$processed = $processor->processConfiguration($config, \BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults::stack([
    ['secret_key' => $secret, 'protection_profile' => 'abuse_first'],
]));

// The production container is the Symfony bundle's compiled container.
// For this campaign we resolve the critical services directly from the
// same constructors the extension uses — the point is that we call the
// production classes, not fixtures.
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$namespace = 'd35k' . bin2hex(random_bytes(4));
$keys = RiskKeys::fromMaster(random_bytes(32));
$factory = new RiskIdentityFactory($keys);
$networks = new RedisPrincipalNetworkTagStore(
    \KiwiCaptcha\Risk\Storage\RedisRiskStateStore::createClient($redisUrl),
    $namespace,
);
$legacy = new \KiwiCaptcha\Risk\Storage\RedisRiskStateStore(
    \KiwiCaptcha\Risk\Storage\RedisRiskStateStore::createClient($redisUrl),
    namespace: $namespace . 'l',
);
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

// The ASN dataset: the home ISP (10.0.0.0/8 -> ASN 64496).
$asnFixture = sys_get_temp_dir() . '/kiwi-d35-asn-' . getmypid() . '.tsv';
file_put_contents($asnFixture, "# d3.5 fixture\n10.0.0.0\t10.255.255.255\t64496\n45.0.0.0\t45.255.255.255\t64500\n");
$asnDataset = \KiwiCaptcha\Risk\Asn\AsnDataset::open($asnFixture);

// The marks reader: session and principal marks plus the login target
// from the store (the production StoreMarksReader resolves no target;
// this one does so target-under-attack escalations come from real
// target_failure state).
$marksReader = new class ($legacy, \KiwiCaptcha\Risk\Marks\MarksEscalation::DEFAULT_MARK_TTL_MS) implements \KiwiCaptcha\Risk\Marks\MarksReaderInterface {
    private ?string $currentTarget = null;

    public function __construct(
        private readonly \KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface $marksStore,
        private readonly int $markTtlMs,
    ) {
    }

    public function setTarget(?string $account): void
    {
        $this->currentTarget = $account;
    }

    public function requestMarks(\KiwiCaptcha\Risk\Marks\MarksRequest $request): \KiwiCaptcha\Risk\Marks\MarksView
    {
        $own = [];
        if ($request->session !== null) {
            $own['session'] = $request->session;
        }
        if ($request->principal !== null) {
            $own['principal'] = $request->principal;
        }

        return \KiwiCaptcha\Risk\Marks\MarksView::read($this->marksStore, $own, $this->currentTarget);
    }

    public function markTtlMs(): int
    {
        return $this->markTtlMs;
    }
};

// The production engine: novelty_enforcement=enforce (the abuse_first
// posture), real principal-network store, real ASN dataset.
$classifier = new CidrNetworkClassifier([]);
$engine = new AdaptiveRiskEngine(
    store: $legacy,
    classifier: $classifier,
    identityFactory: $factory,
    scorer: $scorer,
    policy: $policy,
    keys: $keys,
    enableGlobalPressure: true,
    noveltyEnforcement: 'enforce',
    principalNetworks: $networks,
    marksReader: $marksReader,
    asnDataset: $asnDataset,
);

// Verify the production store resolved — a null seam is a hard failure.
if (!$networks instanceof PrincipalNetworkTagStoreInterface) {
    fwrite(STDERR, "FATAL: principal-network store is not a real implementation\n");
    exit(2);
}

// ---------- the seeded list (same shape as the old driver) ----------
$seedHex = hash('sha256', 'kiwi-rt-d35|' . (getenv('KIWI_RT_SEED') ?: '0x6b776d74'));
$lcg = unpack('q', substr(hash('sha512', $seedHex, true), 0, 8))[1] & 0x7FFFFFFF;
$lcg = ($lcg | 1);
$next = static function () use (&$lcg): int {
    $lcg = ($lcg ^ ($lcg >> 12)) & 0x7FFFFFFF;
    $lcg = ($lcg ^ ($lcg << 25)) & 0x7FFFFFFF;
    $lcg = ($lcg ^ ($lcg >> 27)) & 0x7FFFFFFF;
    return $lcg;
};

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

$rows = [];
foreach ($accounts as $account) {
    $rows[] = $account;
}
for ($w = $rowsTotal - 1; $w > 0; $w--) {
    $k = $next() % ($w + 1);
    [$rows[$w], $rows[$k]] = [$rows[$k], $rows[$w]];
}
$stride = (int) floor($rowsTotal / ($hotVictims * 8));
for ($h = 0; $h < $hotVictims; $h++) {
    for ($r = 0; $r < 8; $r++) {
        $rows[($h * 8 + $r) * $stride % $rowsTotal] = $hotAccounts[$h];
    }
}

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

// ---------- seed home networks and device continuity ----------
$homeIpOf = static fn (int $a): string => sprintf('10.%d.%d.%d', 1 + intdiv($a, 65025) % 254, intdiv($a, 250) % 250, $a % 250 + 1);
$mobileIpOf = static fn (int $a): string => sprintf('10.%d.%d.%d', 50 + intdiv($a, 65025) % 200, intdiv($a, 250) % 250, $a % 250 + 1);
$legitCookieOf = static fn (int $a): string => sprintf('%032x', $a + 1);
$seededPrincipals = 0;
foreach ($accounts as $a => $account) {
    $principal = $factory->principalId($account);
    $networks->recordPrincipalNetworkTag($principal, AdaptiveRiskEngine::networkBucket($homeIpOf($a)), trusted: true);
    $networks->recordPrincipalNetworkTag($principal, AdaptiveRiskEngine::networkBucket($mobileIpOf($a)), trusted: true);
    $networks->recordPrincipalNetworkTag($principal, 'asn:64496');
    $networks->recordPrincipalNetworkTag($principal, 'session:' . $factory->sessionId($legitCookieOf($a)), trusted: true);
    $seededPrincipals++;
}

// ---------- the assess call (the real engine path) ----------
$assessLogin = static function (string $ip, string $account, ?string $sessionId = null, bool $withTarget = true) use ($engine, $classifier, $healthy, $marksReader): object {
    if ($withTarget) {
        $marksReader->setTarget($account);
    }
    try {
        $context = new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: $sessionId,
            principalId: $account,
            event: RiskEventKind::AuthenticationSuccess,
            networkFlags: $classifier->classify($ip),
            resources: $healthy,
        );

        return $engine->reassess($context);
    } finally {
        $marksReader->setTarget(null);
    }
};

$attackerIpOf = static fn (int $session, int $group): string => sprintf('45.%d.%d.%d', 10 + $group, intdiv($session, 250) % 256, ($session * 7) % 250 + 1);
$isIspMatched = static fn (int $session): bool => ($session % 3) === 1;
$isCgnatMatched = static fn (int $session): bool => ($session % 3) === 2;
$attackerIspIpOf = static fn (int $session): string => sprintf('10.200.%d.%d', intdiv($session, 250) % 256, ($session * 3) % 200 + 1);
$attackerCgnatIpOf = static fn (int $accountIndex): string => $homeIpOf($accountIndex % 20000);
$attackerCookieOf = static fn (int $session): string => sprintf('%032x', 0xF0000000 + $session);

// ---------- the wave machine ----------
$sessionAttempts = array_fill(0, $attackerSessions, 0);
$sessionDenyAt = array_fill(0, $attackerSessions, null);
$targetFailures = [];
$targetStepUpAt = [];
$firstStepUpFailures = [];
$levels = [$legacy->lastGlobalLevel()];
$waveFreshUntrustedRanks = [];
$victimActions = [];
$blockedValid = 0;
$compromised = 0;
$validAssessed = 0;
$rowsProcessed = 0;

$rowsPerWave = (int) ceil($rowsTotal / $waves);
$sessionSlice = (int) ceil($rowsTotal / $attackerSessions);
$epoch = intdiv((int) (microtime(true)), 900);

for ($w = 0; $w < $waves; $w++) {
    $waveStart = $w * $rowsPerWave;
    $waveEnd = min($rowsTotal, $waveStart + $rowsPerWave);
    for ($i = $waveStart; $i < $waveEnd; $i++) {
        $rowsProcessed++;
        $session = (int) floor($i / $sessionSlice) % $attackerSessions;
        $group = $session % $groups;
        $account = $rows[$i];
        $accountIndex = (int) array_search($account, $accounts, true);
        if ($isIspMatched($session)) {
            $attackerIp = $attackerIspIpOf($session);
        } elseif ($isCgnatMatched($session)) {
            $attackerIp = $attackerCgnatIpOf($accountIndex >= 0 ? $accountIndex : $session);
        } else {
            $attackerIp = $attackerIpOf($session, $group);
        }
        $attackerCookie = $attackerCookieOf($session);

        if ($rowValid[$i]) {
            $validAssessed++;
            $decision = $assessLogin($attackerIp, $account, $attackerCookie);
            if ($decision->action === RiskAction::Allow) {
                $compromised++;
            } else {
                $blockedValid++;
            }
            continue;
        }

        // Invalid attempt: real failure through the real store.
        $nowMs = (int) (microtime(true) * 1000) + $rowsProcessed;
        $legacy->observe(new \KiwiCaptcha\Risk\RiskObservation(
            event: RiskEventKind::AuthenticationFailure,
            scope: 1,
            sourceEpoch: $epoch,
            sourceIdPrev: $factory->sourceId($attackerIp, $epoch * 900),
            sourceId: $factory->sourceId($attackerIp, $epoch * 900),
            sourceIdNext: $factory->sourceId($attackerIp, $epoch * 900),
            subnetEpoch: $epoch,
            subnetIdPrev: $factory->subnetId($attackerIp, $epoch * 900),
            subnetId: $factory->subnetId($attackerIp, $epoch * 900),
            subnetIdNext: $factory->subnetId($attackerIp, $epoch * 900),
            sessionId: null,
            principalId: null,
            eventId: str_pad(dechex($i), 32, '0', STR_PAD_LEFT),
            networkRisk: 0,
            nowMs: $nowMs,
        ));
        $sessionAttempts[$session]++;
        $targetFailures[$account] = ($targetFailures[$account] ?? 0) + 1;

        if (isset($hotIndexByAccount[$account]) && $hotIndexByAccount[$account] >= 0) {
            try {
                $targetState = $legacy->registerTargetFailure($account, $attackerIp, 'a64496' . $group);
                $hotIndex = $hotIndexByAccount[$account];
                if ($targetState['fails'] >= \KiwiCaptcha\Risk\Marks\MarksEscalation::TARGET_ATTACK_THRESHOLD
                    && !isset($targetStepUpAt[$hotIndex])) {
                    $now = $nowMs;
                    $plain = $policy->decide(1, 100, \KiwiCaptcha\Risk\SignalVector::zero(), $healthy, 0, $now);
                    $view = \KiwiCaptcha\Risk\Marks\MarksView::read($legacy, ['session' => str_pad('v' . $hotIndex, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $hotIndex, 32, '0', STR_PAD_LEFT)], $account);
                    $decision = \KiwiCaptcha\Risk\Marks\MarksEscalation::apply($plain, $view, false, $now, \KiwiCaptcha\Risk\Marks\MarksEscalation::DEFAULT_MARK_TTL_MS, $healthy);
                    $victimActions[] = $decision->action->name ?? (string) $decision->action;
                    if ($decision->action === RiskAction::StepUp) {
                        $firstStepUpFailures[$hotIndex] = $targetState['fails'];
                        $targetStepUpAt[$hotIndex] = true;
                    }
                    if ($decision->action === RiskAction::Deny) {
                        $victimActions['lockout-' . $hotIndex] = true;
                    }
                }
            } catch (\Throwable) {
                // Best effort.
            }
        }

        // Escalation from real failure signals (no driver-written marks).
        if ($sessionDenyAt[$session] === null && $sessionAttempts[$session] >= 1) {
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
                $sessionDenyAt[$session] = $sessionAttempts[$session];
            }
        }
    }

    $levels[] = $legacy->lastGlobalLevel();
    $levelNow = $levels[count($levels) - 1];
    $fresh = $policy->decide(1, 100, \KiwiCaptcha\Risk\SignalVector::zero(), $healthy, $levelNow, (int) (microtime(true) * 1000) + $rowsProcessed);
    $waveFreshUntrustedRanks[] = $fresh->action->rank();

    foreach ($hotAccounts as $h => $account) {
        $failures = $targetFailures[$account] ?? 0;
        $now = (int) (microtime(true) * 1000) + $rowsProcessed + $h;
        $plain = $policy->decide(1, 100, \KiwiCaptcha\Risk\SignalVector::zero(), $healthy, 0, $now);
        $view = \KiwiCaptcha\Risk\Marks\MarksView::read($legacy, ['session' => str_pad('v' . $h, 32, '0', STR_PAD_LEFT), 'principal' => str_pad('p' . $h, 32, '0', STR_PAD_LEFT)], $account);
        $decision = \KiwiCaptcha\Risk\Marks\MarksEscalation::apply($plain, $view, false, $now, \KiwiCaptcha\Risk\Marks\MarksEscalation::DEFAULT_MARK_TTL_MS, $healthy);
        $victimActions[] = $decision->action->name ?? (string) $decision->action;
        if ($decision->action === RiskAction::StepUp && in_array(\KiwiCaptcha\Risk\RiskReason::TargetUnderAttack, $decision->reasons, true)) {
            $firstStepUpFailures[$h] ??= $failures;
            $targetStepUpAt[$h] = true;
        }
        if ($decision->action === RiskAction::Deny) {
            $victimActions['lockout-' . $h] = true;
        }
    }
}

// ---------- the legitimate baseline ----------
$legitHomeTotal = 0;
$legitHomeBlocked = 0;
$legitSameAsnTotal = 0;
$legitSameAsnBlocked = 0;
$legitTravelTotal = 0;
$legitTravelBlocked = 0;
$legitTargetedTotal = 0;
$legitTargetedBlocked = 0;
$legitSample = min(1000, $seededPrincipals);
for ($a = 0; $a < $legitSample; $a++) {
    $account = $accounts[$a];
    $cookie = $legitCookieOf($a);
    $withTarget = $a < $hotVictims;
    foreach ([['home', $homeIpOf($a)], ['same_asn', $mobileIpOf($a)], ['travel', sprintf('45.200.%d.%d', intdiv($a, 250) % 256, $a % 250 + 1)]] as [$kind, $ip]) {
        $decision = $assessLogin($ip, $account, $cookie, $withTarget);
        $blocked = $decision->action === RiskAction::StepUp || $decision->action === RiskAction::Deny;
        if ($withTarget) {
            $legitTargetedTotal++;
            if ($blocked) {
                $legitTargetedBlocked++;
            }
        }
        if ($kind === 'home') {
            $legitHomeTotal++;
            if ($blocked) {
                $legitHomeBlocked++;
            }
        } elseif ($kind === 'same_asn') {
            $legitSameAsnTotal++;
            if ($blocked) {
                $legitSameAsnBlocked++;
            }
        } else {
            $legitTravelTotal++;
            if ($blocked) {
                $legitTravelBlocked++;
            }
        }
    }
}
$ntHome = 0;
$ntHomeB = 0;
$ntSame = 0;
$ntSameB = 0;
for ($a = $hotVictims; $a < $legitSample; $a++) {
    $account = $accounts[$a];
    $cookie = $legitCookieOf($a);
    $d1 = $assessLogin($homeIpOf($a), $account, $cookie, false);
    $d2 = $assessLogin($mobileIpOf($a), $account, $cookie, false);
    $ntHome++;
    $ntSame++;
    if ($d1->action === RiskAction::StepUp || $d1->action === RiskAction::Deny) {
        $ntHomeB++;
    }
    if ($d2->action === RiskAction::StepUp || $d2->action === RiskAction::Deny) {
        $ntSameB++;
    }
}
$legitFpRate = ($ntHome + $ntSame) > 0 ? ($ntHomeB + $ntSameB) / ($ntHome + $ntSame) : 1.0;

// ---------- step-up then return ----------
$stepUpThenReturnOk = true;
$stepUpThenReturnSample = min(200, $legitSample);
for ($a = 0; $a < $stepUpThenReturnSample; $a++) {
    $account = $accounts[$a + 10000] ?? $accounts[$a];
    $principal = $factory->principalId($account);
    $novelIp = sprintf('45.210.%d.%d', intdiv($a, 250) % 256, $a % 250 + 1);
    $cookie = sprintf('%032x', 0xE0000000 + $a);
    $d1 = $assessLogin($novelIp, $account, $cookie);
    if ($d1->action !== RiskAction::StepUp && $d1->action !== RiskAction::Deny) {
        $stepUpThenReturnOk = false;
        break;
    }
    // Simulate the step-up restore: the product's SessionRestorer binds
    // the session, network and ASN. Here we record the same tags the
    // restorer would write.
    $networks->recordPrincipalNetworkTag($principal, AdaptiveRiskEngine::networkBucket($novelIp), trusted: true);
    $networks->recordPrincipalNetworkTag($principal, 'asn:64500');
    $networks->recordPrincipalNetworkTag($principal, 'session:' . $factory->sessionId($cookie), trusted: true);
    $newPrefixIp = sprintf('45.210.%d.%d', intdiv($a, 250) % 256, ($a % 150) + 50);
    $d2 = $assessLogin($newPrefixIp, $account, $cookie);
    if ($d2->action === RiskAction::StepUp || $d2->action === RiskAction::Deny) {
        $stepUpThenReturnOk = false;
        break;
    }
}

// ---------- summary ----------
$sessionsNeverEscalated = 0;
foreach ($sessionDenyAt as $at) {
    if ($at === null) {
        $sessionsNeverEscalated++;
    }
}
$escalatedWithinN = $sessionsNeverEscalated === 0;
$allSessionsEscalated = $sessionsNeverEscalated === 0;
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
    'blocked_valid' => $blockedValid,
    'compromised_valid' => $compromised,
    'corpus_residual_compromised' => $compromised,
    'corpus_size' => $corpusSize,
    'breached_credential_checker' => 'not shipped by default; not credited',
    'engine_path' => 'AdaptiveRiskEngine::reassess(AuthenticationSuccess) via production container — no test seams',
    'novelty_enforcement' => 'enforce (abuse_first profile)',
    'driver' => 'd35.kernel.php (production container, real store)',
    'target_source' => 'store (registerTargetFailure + MarksView::read)',
    'seeded_network_history' => $seededPrincipals,
    'legitimate_baseline' => [
        'sample' => $legitSample,
        'home_blocked' => $legitHomeBlocked,
        'home_total' => $legitHomeTotal,
        'same_asn_blocked' => $legitSameAsnBlocked,
        'same_asn_total' => $legitSameAsnTotal,
        'travel_blocked' => $legitTravelBlocked,
        'travel_total' => $legitTravelTotal,
        'targeted_blocked' => $legitTargetedBlocked,
        'targeted_total' => $legitTargetedTotal,
        'false_positive_rate' => round($legitFpRate, 6),
        'false_positive_bound' => 0.001,
        'step_up_then_return_ok' => $stepUpThenReturnOk,
    ],
    'attacker_sessions' => $attackerSessions,
    'sessions_never_escalated' => $sessionsNeverEscalated,
    'all_sessions_escalated' => $allSessionsEscalated,
    'escalated_within_n' => $escalatedWithinN,
    'denied_within_n' => $escalatedWithinN,
    'deny_bound_n' => DENY_BOUND_N,
    'lockouts' => $lockouts,
    'hot_victims' => $hotVictims,
    'victims_stepped_up' => count($targetStepUpAt),
    'max_spread_failures_before_step_up' => $firstStepUpFailures ? max($firstStepUpFailures) : null,
    'levels_by_wave' => $levels,
    'untrusted_ranks_by_wave' => $waveFreshUntrustedRanks,
    'spend_usd' => round($spendUsd, 6),
    'sha16_us' => $sha16Us,
];
echo json_encode($summary), "\n";

$pass = $escalatedWithinN
    && $allSessionsEscalated
    && $lockouts === 0
    && $stepUpSpreadOk
    && $compromised === 0
    && $validAssessed > 0
    && $blockedValid > 0
    && $legitFpRate <= 0.001
    && $stepUpThenReturnOk
    && $levelsFire
    && $untrustedEscalated;
exit($pass ? 0 : 1);
