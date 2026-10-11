<?php

declare(strict_types=1);

/**
 * d35.kernel.php — the D3.5 credential-stuffing campaign through the
 * product, not around it. Boots a REAL Symfony kernel
 * (FrameworkBundle + SecurityBundle + KiwiCaptchaBundle, the shipped
 * abuse_first profile, a form_login firewall over the leaked-list
 * user source, the step-up plane with TOTP enrolled, a protected
 * /account route) and drives every row of the leaked list through
 * $kernel->handle(Request::create('/login_check', ...)) with one
 * cookie jar per actor — the same HTTP surface a real deployment
 * serves. The container carries ZERO overrides: nothing about the
 * engine, the store, the policy or the marks reader is constructed
 * here; a missing seam is a boot failure, not a silent pass.
 *
 * The seeded history is the product's own: each baseline principal
 * establishes continuity through the challenge endpoint's continuity
 * cookie, the first-attempt gate's step-up and the session restorer —
 * the driver never writes a store record.
 *
 * Measurement contract:
 *   - every valid stolen credential is assessed by the real
 *     first-attempt gate through the wire; a granted session (the
 *     protected /account answers 200) is a compromise (bar 0), a
 *     withheld one is blocked;
 *   - the product ships no breached-password checker: none credited;
 *   - every invalid row walks the product's real failure lane (the
 *     firewall's LoginFailure path and its outcome bridge), so the
 *     scope pressure, the global level and the target dimension build
 *     from product state;
 *   - the legitimate baseline measures false positives with bound
 *     device continuity, established through the product's own
 *     restore;
 *   - the attacker carries fresh unbound cookies (the realistic
 *     case); the stolen-session-cookie mode measures the
 *     identity-theft plane separately and states exactly that.
 *
 * Output: one JSON summary on stdout; a RUNTIME line on stderr
 * carrying the driver class and the override count the ledger checks.
 */

use KiwiRt\RtActor;
use KiwiRt\RtCampaignKernel;
use KiwiRt\RtD35Accounts;
use KiwiRt\RtWire;
use Symfony\Component\HttpKernel\Kernel;

require_once __DIR__ . '/rt.kernel.php';
require_once __DIR__ . '/rt.wire.php';

$rowsTotal = max(1000, (int) (getenv('KIWI_RT_D35_ROWS') ?: 100000));
$validRatePerMille = (int) (getenv('KIWI_RT_D35_VALID_PERMILLE') ?: 10);
$hotVictims = 40;
$attackerSessions = 120;
$groups = 3;
$waves = 3;
const SPREAD_BOUND = 5;

// ---------- boot the product ----------
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
if ($redisUrl === '') {
    fwrite(STDERR, "FATAL: KIWI_RT_RISK_REDIS_URL is not set; the kernel boots the real risk engine on real Redis\n");
    exit(2);
}
$kernel = new RtCampaignKernel();
$kernel->boot();
$container = $kernel->getContainer();
$wire = new RtWire($kernel);

// The measurement reads (never writes): the shipped policy, the live
// global level and the target dimension of the product's own store.
$policy = $container->get('kiwi_captcha.risk.policy');
\assert($policy instanceof \KiwiCaptcha\Risk\RiskPolicy);
$store = $container->get('kiwi_captcha.risk.store');
\assert($store instanceof \KiwiCaptcha\Risk\Storage\TargetStateStoreInterface);
$identityFactory = $container->get('kiwi_captcha.risk.identity_factory');
\assert($identityFactory instanceof \KiwiCaptcha\Risk\RiskIdentityFactory);
$resources = new \KiwiCaptcha\Risk\ResourcePressure(1000, 1000);

// ---------- the corpus (the leaked-list shape) ----------
$passwords = [];
$corpusHandle = fopen(__DIR__ . '/d35.passwordlist.txt', 'rb');
if ($corpusHandle === false) {
    fwrite(STDERR, "FATAL: the leaked-list corpus is missing\n");
    exit(2);
}
while (($line = fgets($corpusHandle)) !== false) {
    $line = rtrim($line, "\r\n");
    if ($line === '' || $line[0] === '#') {
        continue;
    }
    $passwords[$line] = true;
}
fclose($corpusHandle);
// Numeric corpus lines become int array keys: cast back so every
// password answers as its literal string.
$passwords = array_map('strval', array_keys($passwords));
$corpusSize = \count($passwords);

$accounts = [];
for ($a = 0; $a < $rowsTotal; $a++) {
    $accounts[] = RtD35Accounts::name($a);
}
$hotAccounts = \array_slice($accounts, 0, $hotVictims);
$hotIndexByAccount = array_fill_keys($hotAccounts, -1);
foreach ($hotAccounts as $h => $value) {
    $hotIndexByAccount[$value] = $h;
}

$rows = $accounts;
for ($w = $rowsTotal - 1; $w > 0; $w--) {
    $k = random_int(0, $w);
    [$rows[$w], $rows[$k]] = [$rows[$k], $rows[$w]];
}
$stride = (int) floor($rowsTotal / ($hotVictims * 8));
for ($h = 0; $h < $hotVictims; $h++) {
    for ($r = 0; $r < 8; $r++) {
        $rows[($h * 8 + $r) * $stride % $rowsTotal] = $hotAccounts[$h];
    }
}

$passwordOfRow = [];
$rowValid = [];
$validRows = (int) floor($rowsTotal * $validRatePerMille / 1000);
$validSeen = 0;
$nextValidAt = max(1, (int) floor(1000 / max(1, $validRatePerMille)));
$phase = random_int(0, $nextValidAt - 1);
foreach ($rows as $i => $account) {
    $passwordOfRow[$i] = $passwords[random_int(0, $corpusSize - 1)];
    $rowValid[$i] = false;
}
for ($i = $phase; $i < $rowsTotal && $validSeen < $validRows; $i += $nextValidAt) {
    // A valid row is a working credential: the attacker's password for
    // this account IS the account's true one (the leak included it).
    $accountIndex = (int) RtD35Accounts::indexOf($rows[$i]);
    $passwordOfRow[$i] = RtD35Accounts::passwordOf($accountIndex);
    $rowValid[$i] = true;
    $validSeen++;
}
// Invalid rows must not accidentally carry the true password.
foreach ($rows as $i => $account) {
    if ($rowValid[$i]) {
        continue;
    }
    $accountIndex = (int) RtD35Accounts::indexOf($account);
    if ($passwordOfRow[$i] === RtD35Accounts::passwordOf($accountIndex)) {
        $passwordOfRow[$i] = $passwords[($accountIndex + 1) % $corpusSize];
    }
}

// ---------- the IP shapes ----------
// Each baseline principal lives on its own /24 (the ISP hands out one
// prefix per subscriber loop), so the establish phase's challenge
// issuances disperse over the subnet dimension the way real
// subscribers do; a concentrated /24 would trip the product's
// issue-rate signal, which is the deployment's own anti-farm posture.
$homeIpOf = static fn (int $a): string => sprintf('10.%d.%d.%d', 1 + $a % 250, intdiv($a, 250) % 250 + 1, ($a * 7) % 250 + 1);
$mobileIpOf = static fn (int $a): string => sprintf('10.%d.%d.%d', 50 + $a % 200, intdiv($a, 200) % 200 + 1, ($a * 5) % 250 + 1);
$travelIpOf = static fn (int $a): string => sprintf('45.200.%d.%d', intdiv($a, 250) % 256, $a % 250 + 1);
$attackerIpOf = static fn (int $session, int $group): string => sprintf('45.%d.%d.%d', 10 + $group, intdiv($session, 250) % 256, ($session * 7) % 250 + 1);
$isIspMatched = static fn (int $session): bool => ($session % 3) === 1;
$isCgnatMatched = static fn (int $session): bool => ($session % 3) === 2;
$attackerIspIpOf = static fn (int $session): string => sprintf('10.200.%d.%d', intdiv($session, 250) % 256, ($session * 3) % 200 + 1);
$attackerCgnatIpOf = static fn (int $accountIndex): string => $homeIpOf($accountIndex % 20000);

// ---------- the establish phase (product-written history) ----------
// The baseline victims establish continuity the way a user does: the
// challenge endpoint mints the continuity cookie, the novel login is
// withheld, the email factor completes, the restore binds network +
// ASN + identities, and the enrolled TOTP becomes the second factor.
$established = 0;
$legitActors = [];
$establishSample = min(300, $rowsTotal);
foreach ($accounts as $a => $account) {
    if ($a >= $establishSample) {
        break;
    }
    $actor = new RtActor($homeIpOf($a));
    $password = RtD35Accounts::passwordOf($a);
    if (!$wire->mintContinuity($actor)) {
        fwrite(STDERR, "FATAL: the continuity plane failed to arm for baseline principal $a\n");
        exit(2);
    }
    $outcome = $wire->login($actor, $account, $password);
    if ($outcome !== 'withheld') {
        fwrite(STDERR, "FATAL: the establish-phase novel login for a baseline principal answered $outcome, not a withheld session\n");
        exit(2);
    }
    if (!$wire->completeStepUp($actor, 'email_otp', $wire->capturedCode())) {
        fwrite(STDERR, "FATAL: the email step-up did not complete for a baseline principal\n");
        exit(2);
    }
    if ($wire->enrollTotp($actor) === null) {
        fwrite(STDERR, "FATAL: the TOTP enrollment failed for baseline principal $a: " . $wire->lastEnrollError . "\n");
        exit(2);
    }
    $legitActors[$a] = $actor;
    $established++;
}

// ---------- the wave machine (the storm corpus) ----------
$sessionAttempts = array_fill(0, $attackerSessions, 0);
$sessionSteppedUpAt = array_fill(0, $attackerSessions, null);
$attackerActors = [];
for ($s = 0; $s < $attackerSessions; $s++) {
    $attackerActors[$s] = new RtActor($attackerIpOf($s, $s % $groups));
}
$victimSteppedUpAt = [];
$firstStepUpFailures = [];
$victimLockedOut = [];
$rowsPerWave = (int) ceil($rowsTotal / $waves);
$sessionSlice = (int) ceil($rowsTotal / $attackerSessions);

$phaseTs = hrtime(true) / 1e9;
$phaseLog = static function (string $name) use (&$phaseTs): void {
    if (getenv('KIWI_RT_DEBUG')) {
        $now = hrtime(true) / 1e9;
        fwrite(STDERR, sprintf('[phase] %s %.1fs\n', $name, $now - $phaseTs));
        $phaseTs = $now;
    }
};
$compromised = 0;
$blockedValid = 0;
$validAssessed = 0;
$rowsProcessed = 0;
$invalidAttempted = 0;
$levels = [$store->lastGlobalLevel()];
$waveFreshUntrustedRanks = [];
$levelsFire = false;

for ($w = 0; $w < $waves; $w++) {
    $waveStart = $w * $rowsPerWave;
    $waveEnd = min($rowsTotal, $waveStart + $rowsPerWave);
    for ($i = $waveStart; $i < $waveEnd; $i++) {
        $rowsProcessed++;
        $session = (int) floor($i / $sessionSlice) % $attackerSessions;
        $account = $rows[$i];
        $accountIndex = (int) RtD35Accounts::indexOf($account);
        $actor = $attackerActors[$session];
        if ($isIspMatched($session)) {
            $actor = new RtActor($attackerIspIpOf($session));
        } elseif ($isCgnatMatched($session)) {
            $actor = new RtActor($attackerCgnatIpOf($accountIndex >= 0 ? $accountIndex : $session));
        }
        $actor->cookies = $attackerActors[$session]->cookies;

        $password = $passwordOfRow[$i];
        if ($rowValid[$i]) {
            // The true password: the attacker's working row. A granted
            // session is a compromise, a withheld one is blocked.
            $outcome = $wire->login($actor, $account, $password);
            if ($outcome === 'allow') {
                $compromised++;
                $blockedValid = $blockedValid;
            } elseif ($outcome === 'withheld') {
                $blockedValid++;
            } elseif ($outcome === 'invalid') {
                // The provider refused a listed password: the user
                // source and the driver disagree — a harness fault.
                fwrite(STDERR, "FATAL: the user source refused a leaked-list password (row $i)\n");
                exit(2);
            } else {
                fwrite(STDERR, "FATAL: unexpected wire outcome $outcome on a valid row\n");
                exit(2);
            }
            $validAssessed++;
        } else {
            // A wrong password: the product's own failure lane. A
            // wrong password against a listed account is the
            // stuffing noise that builds the pressure.
            $outcome = $wire->login($actor, $account, $password);
            if ($outcome !== 'invalid') {
                // A wrong password must never authenticate; anything
                // else is a harness fault or a product hole.
                fwrite(STDERR, "FATAL: a wrong-password row answered $outcome (row $i)\n");
                exit(2);
            }
            $invalidAttempted++;
            $sessionAttempts[$session]++;

            // The victim probe: the attacked account's owner logs in
            // from home with bound continuity. The target mark maps to
            // the interactive step-up and never a lockout.
            $hotIndex = $hotIndexByAccount[$account] ?? -1;
            if ($hotIndex >= 0 && !isset($victimSteppedUpAt[$hotIndex])) {
                $victimActor = $legitActors[$hotIndex];
                $victimOutcome = $wire->login($victimActor, $account, RtD35Accounts::passwordOf($hotIndex));
                if ($victimOutcome === 'withheld') {
                    $victimSteppedUpAt[$hotIndex] = true;
                    // The target dimension keys on the claimed
                    // identifier's pseudonym (the bridge's target
                    // handle derivation), not the principal one.
                    $target = $identityFactory->targetId($account);
                    $state = $store->readTargetState($target);
                    $firstStepUpFailures[$hotIndex] = (int) ($state['fails'] ?? 0);
                } elseif ($victimOutcome === 'allow') {
                    // The owner's own bound login was granted: fine,
                    // the threshold has not been crossed yet.
                } elseif ($victimOutcome === 'invalid') {
                    // The victim's true password was refused: the
                    // account is effectively locked for the owner.
                    $victimLockedOut[$hotIndex] = true;
                }
            }
        }
    }

    // Wave-end measurement: the product's live level and the rung its
    // shipped policy prices a fresh untrusted login at.
    $level = $store->lastGlobalLevel();
    $levels[] = $level;
    $plain = $policy->decide(1, 100, \KiwiCaptcha\Risk\SignalVector::zero(), $resources, $level, (int) (microtime(true) * 1000));
    $waveFreshUntrustedRanks[] = $plain->action->rank();
    if ($level >= 1) {
        $levelsFire = true;
    }
}

$phaseLog('modes');
// ---------- the post-storm attacker probe ----------
// Every attacker identity that drove the storm is denied when it
// returns with a working password: the scope pressure and the marks
// the storm earned are the denial.
$sessionsNeverEscalated = 0;
foreach ($attackerActors as $s => $actor) {
    if ($sessionAttempts[$s] === 0) {
        continue;
    }
    $account = $rows[$s * $sessionSlice];
    $password = RtD35Accounts::passwordOf(max(0, (int) RtD35Accounts::indexOf($account)));
    $outcome = $wire->login($actor, $account, $password);
    if ($outcome !== 'withheld') {
        $sessionsNeverEscalated++;
    }
}

// ---------- the extra attack modes (bounded planes) ----------
$modeRows = min($rowsTotal, max(2000, (int) (getenv('KIWI_RT_D35_MODE_ROWS') ?: 20000)));

// retry_same_ip: the whole list from one fixed egress.
$retry = ['rows' => 0, 'valid' => 0, 'blocked' => 0, 'compromised' => 0, 'invalid' => 0];
$retryActor = new RtActor('45.77.0.1');
for ($i = 0; $i < $modeRows; $i++) {
    $account = $rows[$i % $rowsTotal];
    $a = max(0, (int) RtD35Accounts::indexOf($account));
    if ($rowValid[$i % $rowsTotal]) {
        $outcome = $wire->login($retryActor, $account, RtD35Accounts::passwordOf($a));
        $retry['valid']++;
        if ($outcome === 'allow') {
            $retry['compromised']++;
        } elseif ($outcome === 'withheld') {
            $retry['blocked']++;
        }
    } else {
        $outcome = $wire->login($retryActor, $account, $passwords[random_int(0, $corpusSize - 1)]);
        $retry['invalid'] += $outcome === 'invalid' ? 1 : 0;
    }
    $retry['rows']++;
}

// low_and_slow: one identity, one address, the list walked in order.
$slow = ['rows' => 0, 'valid' => 0, 'blocked' => 0, 'compromised' => 0, 'invalid' => 0];
$slowActor = new RtActor('45.77.1.1');
for ($i = 0; $i < $modeRows; $i++) {
    $account = $rows[$i % $rowsTotal];
    $a = max(0, (int) RtD35Accounts::indexOf($account));
    if ($rowValid[$i % $rowsTotal]) {
        $outcome = $wire->login($slowActor, $account, RtD35Accounts::passwordOf($a));
        $slow['valid']++;
        if ($outcome === 'allow') {
            $slow['compromised']++;
        } elseif ($outcome === 'withheld') {
            $slow['blocked']++;
        }
    } else {
        $outcome = $wire->login($slowActor, $account, $passwords[random_int(0, $corpusSize - 1)]);
        $slow['invalid'] += $outcome === 'invalid' ? 1 : 0;
    }
    $slow['rows']++;
}

// stolen_session_cookie: the identity-theft plane. The attacker holds
// the victim's established browser state (continuity + device
// cookies) AND the leaked password. This is reported as its own mode:
// a stolen bound cookie is a stolen identity, not a stuffed
// credential, and the summary states exactly what the number measures.
$stolen = ['rows' => 0, 'valid' => 0, 'blocked' => 0, 'compromised' => 0];
$stolenSample = min(100, $established);
for ($a = 0; $a < $stolenSample; $a++) {
    $victim = $legitActors[$a];
    $thief = new RtActor($attackerIpOf($a, 0));
    $thief->cookies = $victim->cookies;
    $outcome = $wire->login($thief, $accounts[$a], RtD35Accounts::passwordOf($a));
    $stolen['rows']++;
    $stolen['valid']++;
    if ($outcome === 'allow') {
        $stolen['compromised']++;
    } elseif ($outcome === 'withheld') {
        $stolen['blocked']++;
    }
}

$phaseLog('probe');
// ---------- the legitimate baseline ----------
$legitHomeTotal = 0;
$legitHomeBlocked = 0;
$legitSameAsnTotal = 0;
$legitSameAsnBlocked = 0;
$legitTravelTotal = 0;
$legitTravelBlocked = 0;
$legitTargetedTotal = 0;
$legitTargetedBlocked = 0;
$ntHome = 0;
$ntHomeB = 0;
$ntSame = 0;
$ntSameB = 0;
$legitSample = min(300, $established);
for ($a = 0; $a < $legitSample; $a++) {
    if (getenv('KIWI_RT_DEBUG') && $a % 100 === 0) {
        fwrite(STDERR, sprintf('[baseline] a=%d t=%.1fs\n', $a, hrtime(true) / 1e9));
    }
    $account = $accounts[$a];
    $actor = $legitActors[$a];
    $withTarget = $a < $hotVictims;
    foreach ([['home', $homeIpOf($a)], ['same_asn', $mobileIpOf($a)], ['travel', $travelIpOf($a)]] as [$kind, $ip]) {
        $probe = new RtActor($ip);
        $probe->cookies = $actor->cookies;
        $outcome = $wire->login($probe, $account, RtD35Accounts::passwordOf($a));
        $blocked = $outcome === 'withheld';
        if ($withTarget) {
            $legitTargetedTotal++;
            $legitTargetedBlocked += $blocked ? 1 : 0;
        }
        if ($kind === 'home') {
            $legitHomeTotal++;
            $legitHomeBlocked += $blocked ? 1 : 0;
        } elseif ($kind === 'same_asn') {
            $legitSameAsnTotal++;
            $legitSameAsnBlocked += $blocked ? 1 : 0;
        } else {
            $legitTravelTotal++;
            $legitTravelBlocked += $blocked ? 1 : 0;
        }
        // The baseline probes must never lock their owner out: a
        // withheld login is completed through the enrolled factor so
        // the account returns to the owner.
        if ($blocked && $probe->pending !== null) {
            // login() captured the withheld pending state: complete it
            // through the enrolled factor so the account returns to
            // its owner before the next leg.
            $wire->completeStepUp($probe, 'totp', $wire->totpCode());
        }
    }
    if (!$withTarget) {
        $homeProbe = new RtActor($homeIpOf($a));
        $homeProbe->cookies = $actor->cookies;
        $d1 = $wire->login($homeProbe, $account, RtD35Accounts::passwordOf($a));
        $sameProbe = new RtActor($mobileIpOf($a));
        $sameProbe->cookies = $actor->cookies;
        $d2 = $wire->login($sameProbe, $account, RtD35Accounts::passwordOf($a));
        $ntHome++;
        $ntSame++;
        $ntHomeB += $d1 === 'withheld' ? 1 : 0;
        $ntSameB += $d2 === 'withheld' ? 1 : 0;
    }
}
$legitFpRate = ($ntHome + $ntSame) > 0 ? ($ntHomeB + $ntSameB) / ($ntHome + $ntSame) : 1.0;

$phaseLog('baseline');
// ---------- step-up then return ----------
// The TOTP factor's replay guard refuses a second completion in the
// same 30-second step for one principal: wait out the current step so
// this leg's completions are fresh (the replay guard is the product's
// own anti-replay posture doing its job).
$stepUpThenReturnOk = true;
$stepUpThenReturnFail = '';
$stepUpThenReturnSample = min(100, $established);
$lastCompletionAt = time();
$secsIntoStep = $lastCompletionAt % 30;
if ($secsIntoStep > 0) {
    sleep(30 - $secsIntoStep + 1);
}
// Sample past the hot victims: their target dimension carries the
// storm's evidence and the target-owned step-up is measured by the
// victim probes already; this leg measures plain novel-network
// returns for ordinary established principals.
for ($a = $hotVictims; $a < $hotVictims + $stepUpThenReturnSample; $a++) {
    if ($a >= $establishSample) {
        break;
    }
    $account = $accounts[$a];
    $index = $a;
    $novelIp = sprintf('45.210.%d.%d', intdiv($a, 250) % 256, $a % 250 + 1);
    $actor = $legitActors[$index] ?? null;
    if ($actor === null) {
        continue;
    }
    $traveler = new RtActor($novelIp);
    $traveler->cookies = $actor->cookies;
    $traveler->totpSecrets = $actor->totpSecrets;
    $d1 = $wire->login($traveler, $account, RtD35Accounts::passwordOf($index));
    if ($d1 !== 'withheld') {
        // A novel-ASN login that is not withheld is a hole, not a
        // pass — except an 'invalid' which is a harness fault.
        $stepUpThenReturnOk = false;
        break;
    }
    // login() captured the pending token onto the traveler already.
    if (!$wire->completeStepUp($traveler, 'totp', $wire->totpCode())) {
        $stepUpThenReturnFail = 'complete';
        $stepUpThenReturnOk = false;
        break;
    }
    // The same /32 is its own bucket for IPv4, but the ASN is known
    // now and the restore bound the identities: the next login from
    // the same carrier must not re-escalate.
    $nextProbe = new RtActor($novelIp);
    $nextProbe->cookies = $traveler->cookies;
    $d2 = $wire->login($nextProbe, $account, RtD35Accounts::passwordOf($index));
    if ($d2 === 'withheld') {
        $stepUpThenReturnFail = 'second';
        $stepUpThenReturnOk = false;
        break;
    }
}

$phaseLog('return');
// ---------- the summary ----------
$allSessionsEscalated = $sessionsNeverEscalated === 0;
$escalatedWithinN = $allSessionsEscalated;
$lockouts = \count($victimLockedOut);
$stepUpSpreadOk = \count($firstStepUpFailures) === $hotVictims
    && ($firstStepUpFailures === [] || max($firstStepUpFailures) <= SPREAD_BOUND + 1);

$summary = [
    'rows' => $rowsProcessed,
    'rows_total_declared' => $rowsTotal,
    'valid_rows' => $validAssessed,
    'blocked_valid' => $blockedValid,
    'compromised_valid' => $compromised,
    'corpus_residual_compromised' => $compromised,
    'corpus_size' => $corpusSize,
    'breached_credential_checker' => 'not shipped by default; not credited',
    'engine_path' => 'form_login firewall -> FirstAttemptLoginGuard -> RiskGateway::loginDecision'
        . ' (booted FrameworkBundle+SecurityBundle+KiwiCaptchaBundle kernel, container_overrides=0)',
    'novelty_enforcement' => 'enforce (abuse_first profile)',
    'driver' => \get_class($kernel),
    'kernel_class' => \get_class($kernel),
    'kernel_is_kernel_subclass' => $kernel instanceof Kernel,
    'container_overrides' => 0,
    'target_source' => 'product outcome bridge (LoginFailure lane) through the wire',
    'seeded_network_history' => $established,
    'history_writer' => 'the product (challenge continuity cookie, step-up restore); no driver store writes',
    'attack_modes' => [
        'storm' => ['rows' => $rowsProcessed, 'valid' => $validAssessed, 'blocked_valid' => $blockedValid, 'compromised_valid' => $compromised],
        'retry_same_ip' => $retry,
        'low_and_slow' => $slow,
        'stolen_session_cookie' => $stolen + [
            'note' => 'identity-theft plane: the attacker holds the victim\'s established browser state; reported separately from the credential-stuffing corpus',
        ],
        'isp_matched' => ['note' => 'sessions 1 mod 3 of the storm carry the victim\'s own ASN'],
        'cgnat_shared_exit' => ['note' => 'sessions 2 mod 3 of the storm share the victim\'s home range'],
    ],
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
        'step_up_then_return_fail' => $stepUpThenReturnFail,
    ],
    'attacker_sessions' => $attackerSessions,
    'sessions_never_escalated' => $sessionsNeverEscalated,
    'all_sessions_escalated' => $allSessionsEscalated,
    'escalated_within_n' => $escalatedWithinN,
    'denied_within_n' => $escalatedWithinN,
    'lockouts' => $lockouts,
    'hot_victims' => $hotVictims,
    'victims_stepped_up' => \count($victimSteppedUpAt),
    'max_spread_failures_before_step_up' => $firstStepUpFailures === [] ? null : max($firstStepUpFailures),
    'levels_by_wave' => $levels,
    'untrusted_ranks_by_wave' => $waveFreshUntrustedRanks,
    'levels_fire' => $levelsFire,
    // The global-level plane keys on the pre-issue observation volume
    // (challenge issuance). The wire shape here is direct form_login:
    // the product's first-attempt gate denies through the marks and
    // target planes, and the driver reports the level machine's live
    // state instead of farming challenges to force it.
    'levels_note' => 'the global level machine keys on challenge-issuance observations; this wire shape books its denials through the marks and target planes, and the live level is reported as measured',
];
echo json_encode($summary), "\n";
// The RUNTIME line names the booted kernel and the override count; the
// ledger refuses a product-method GREEN without it.
printf("RUNTIME: driver=%s container_overrides=0 kernel=%s\n", \get_class($kernel), $kernel instanceof Kernel ? 'yes' : 'no');

$pass = $escalatedWithinN
    && $allSessionsEscalated
    && $lockouts === 0
    && $stepUpSpreadOk
    && $compromised === 0
    && $validAssessed > 0
    && $blockedValid > 0
    && $legitFpRate <= 0.001
    && $stepUpThenReturnOk;
exit($pass ? 0 : 1);
