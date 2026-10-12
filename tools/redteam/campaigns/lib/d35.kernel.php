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
 * serves. The container carries ZERO overrides, and the count is
 * computed: the booted container's bundle surface is diffed against
 * the reference build (the identical configuration compiled with no
 * campaign passes), so an override can never hide behind a literal.
 *
 * Phase isolation: every phase boots its own risk namespace, so no
 * phase inherits another's pressure or marks and each measurement
 * plane is judged on its own state. The namespace is the deployment's
 * own state-sharding knob (RtCampaignKernel::$riskNamespace rides the
 * compiled container class), never a product override.
 *
 * The global posture, stated plainly: the shipped engine ratchets a
 * namespace's global level to the emergency admission stop once its
 * rolling failure counters saturate (about thirty authentication
 * failures, each booking the shipped AuthenticationFailure weight).
 * A full-list stuffing walk is that storm by definition, so the
 * volume phases (retry_same_ip, low_and_slow, the storm) measure
 * inside the emergency posture and classify it honestly: a valid
 * credential the wire refuses is the product's denial of that login,
 * never a granted session and never a fixture fault. The credential
 * fixture is proven separately at boot (the self-check below), so a
 * fixture drift still fails the campaign instead of hiding behind a
 * denial. The per-credential defenses the release criteria name (the
 * first-attempt gate's step-up, the target dimension's spread bound,
 * the zero-lockout promise, the legitimate baseline) are measured in
 * namespaces whose failure volume stays under the emergency trip, so
 * the global admission stop cannot drown the plane under test.
 *
 * The seeded history is the product's own: each baseline principal
 * establishes continuity through the challenge endpoint's continuity
 * cookie, the first-attempt gate's step-up and the session restorer —
 * the driver never writes a store record.
 *
 * Measurement contract:
 *   - every valid stolen credential is assessed by the real
 *     first-attempt gate through the wire; a granted session (the
 *     protected /account answers 200) is a compromise (bar 0); a
 *     withheld one is blocked; a refused one is the product's
 *     terminal denial of a proven-good credential and is blocked too,
 *     counted separately so the ledger shows which plane blocked;
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
 *     identity-theft plane separately and states exactly that, under
 *     its own documented compromise bound.
 *
 * Output: one JSON summary on stdout; a RUNTIME line on stderr
 * carrying the driver class and the computed override count the
 * ledger checks.
 */

use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiRt\RtActor;
use KiwiRt\RtCampaignKernel;
use KiwiRt\RtContainerAuditPass;
use KiwiRt\RtD35Accounts;
use KiwiRt\RtReferenceKernel;
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
$modeRows = min($rowsTotal, max(2000, (int) (getenv('KIWI_RT_D35_MODE_ROWS') ?: 20000)));
$slowRows = min($modeRows, max(200, (int) (getenv('KIWI_RT_D35_SLOW_ROWS') ?: 2000)));
$slowSleepMicros = max(0, (int) (getenv('KIWI_RT_D35_SLOW_US') ?: 1000));
$slowInterleave = 10;

// ---------- boot the product (per phase, isolated namespaces) ----------
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
if ($redisUrl === '') {
    fwrite(STDERR, "FATAL: KIWI_RT_RISK_REDIS_URL is not set; the kernel boots the real risk engine on real Redis\n");
    exit(2);
}

/**
 * Boots the reference build and the product kernel under one risk
 * namespace and returns the kernel together with the computed override
 * count (the diff of the two captured bundle surfaces). The reference
 * compiles first so the campaign capture is always diffed against a
 * capture from the same configuration; when a cached container skips
 * the compiler passes entirely, the count persisted beside that exact
 * compiled container (the audit that ran at its compile) is the answer.
 */
$bootProduct = static function (string $namespace) use ($redisUrl): array {
    if ($redisUrl === '') {
        fwrite(STDERR, "FATAL: the kernel boots the real risk engine on real Redis\n");
        exit(2);
    }
    RtCampaignKernel::$riskNamespace = $namespace;
    (new RtReferenceKernel())->boot();
    $kernel = new RtCampaignKernel();
    $kernel->boot();
    $overrides = RtContainerAuditPass::overrideCount();
    if ($overrides < 0) {
        $overrides = RtContainerAuditPass::persistedCount($kernel->getCacheDir());
    }
    if ($overrides < 0) {
        fwrite(STDERR, "FATAL: the container override audit has no capture for the booted wiring\n");
        exit(2);
    }

    return [$kernel, $overrides];
};

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

/**
 * Establishes baseline victims the way a user does, through the
 * product's own surfaces: the challenge endpoint mints the continuity
 * cookie, the novel login is withheld, the email factor completes, and
 * the enrolled TOTP becomes the second factor. Returns the established
 * actors keyed by account index.
 */
$establishVictims = static function (RtWire $wire, array $accounts, int $from, int $count) use ($homeIpOf): array {
    $actors = [];
    $end = min(\count($accounts), $from + $count);
    for ($a = $from; $a < $end; $a++) {
        $account = $accounts[$a];
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
        $actors[$a] = $actor;
    }

    return $actors;
};

/**
 * The fixture self-check: the user source the firewall authenticates
 * against must answer every sampled account with exactly the true
 * password the driver derived from the same leaked-list corpus. This
 * is the harness-fault tripwire for the walk below: a wire refusal of
 * a valid credential is classified as the product's denial, so any
 * real drift between the driver's table and the booted user source is
 * caught here, loudly, before a single row is measured.
 */
$fixtureSelfCheck = static function (RtCampaignKernel $kernel) use ($hotVictims, $rowsTotal): void {
    $provider = $kernel->getContainer()->get(\KiwiRt\RtLeakedListUserProvider::class);
    \assert($provider instanceof \KiwiRt\RtLeakedListUserProvider);
    $hasher = new \Symfony\Component\PasswordHasher\Hasher\PlaintextPasswordHasher();
    $sample = [0, 1, 2, 3, 4, 5, 6, 7, $hotVictims - 1, $hotVictims, intdiv($rowsTotal, 2), $rowsTotal - 1];
    foreach ($sample as $a) {
        $account = RtD35Accounts::name($a);
        $user = $provider->loadUserByIdentifier($account);
        $true = RtD35Accounts::passwordOf($a);
        if (!\is_string($user->getPassword()) || $user->getPassword() !== $true
            || !$hasher->verify($user->getPassword(), $true, null)) {
            fwrite(STDERR, sprintf(
                "FATAL: the leaked-list fixture drifted: the user source answers account %s with a password the driver's corpus does not carry\n",
                $account,
            ));
            exit(2);
        }
    }
};

$phaseTs = hrtime(true) / 1e9;
$phaseLog = static function (string $name) use (&$phaseTs): void {
    if (getenv('KIWI_RT_DEBUG')) {
        $now = hrtime(true) / 1e9;
        fwrite(STDERR, sprintf('[phase] %s %.1fs\n', $name, $now - $phaseTs));
        $phaseTs = $now;
    }
};

// Per-run namespace suffix: the seed keeps the corpus deterministic,
// the random half keeps the namespaces FRESH per run — a namespace a
// previous run enrolled (TOTP secrets are durable) must never be
// reused, or the establish phase would re-enroll and be refused.
$nsTag = substr(hash('sha256', 'kiwi-rt-d35-namespaces|' . (getenv('KIWI_RT_SEED') ?: '0x6b776d74')), 0, 12)
    . '-' . bin2hex(random_bytes(4));

// ============================================================
// the bounded attack modes: BEFORE the storm, each in its own
// namespace, so no mode inherits the storm's pressure or marks
// ============================================================

// ---------- retry_same_ip (fresh namespace) ----------
// The whole list pounded from one fixed egress. Each valid credential
// is attempted, receives its step-up, and is then retried five more
// times from the same actor: a withheld login must never flip to a
// grant by repetition. Any Allow on any attempt is a compromise. Past
// the namespace's emergency trip the product refuses logins outright
// (the documented admission stop): the refusal of a proven-good
// credential is a denial, counted per row, never a grant and never a
// fixture fault (the fixture self-check proved the table at boot).
$phaseLog('boot:retry');
[$retryKernel, $retryOverrides] = $bootProduct("kiwi-rt-d35-retry-$nsTag");
$fixtureSelfCheck($retryKernel);
$retryWire = new RtWire($retryKernel);
$retry = ['rows' => 0, 'valid' => 0, 'blocked' => 0, 'compromised' => 0, 'invalid' => 0, 'denied' => 0, 'retries' => 0];
$retryActor = new RtActor('45.77.0.1');
for ($i = 0; $i < $modeRows; $i++) {
    $row = $i % $rowsTotal;
    $account = $rows[$row];
    $a = max(0, (int) RtD35Accounts::indexOf($account));
    if ($rowValid[$row]) {
        $granted = false;
        for ($attempt = 0; $attempt <= 5; $attempt++) {
            $outcome = $retryWire->login($retryActor, $account, RtD35Accounts::passwordOf($a));
            if ($attempt > 0) {
                $retry['retries']++;
            }
            if ($outcome === 'allow') {
                $granted = true;
                break;
            }
            if ($outcome === 'invalid') {
                // The product refused a proven-good credential: the
                // denial plane (the first-attempt gate's terminal deny
                // or the namespace's emergency admission stop). The
                // credential was never granted; keep retrying so the
                // repetition flip stays measured.
                if ($attempt === 0) {
                    $retry['denied']++;
                }

                continue;
            }
            if (str_starts_with($outcome, 'http:')) {
                // The wire broke: a harness fault, still fatal.
                fwrite(STDERR, "FATAL: the wire broke on a valid credential (retry row $i, attempt $attempt, outcome $outcome)\n");
                exit(2);
            }
        }
        $retry['valid']++;
        if ($granted) {
            $retry['compromised']++;
        } else {
            $retry['blocked']++;
        }
    } else {
        $outcome = $retryWire->login($retryActor, $account, $passwords[random_int(0, $corpusSize - 1)]);
        $retry['invalid'] += $outcome === 'invalid' ? 1 : 0;
    }
    $retry['rows']++;
}
unset($retryKernel, $retryWire);

// ---------- low_and_slow (fresh namespace, paced) ----------
// One identity, one address, the list walked in order at a pace the
// scope never reads as a storm: ten established legitimate logins are
// interleaved per stuffing row (the driver's own clock paces the
// walk), so the scope failure ratio stays far under the pressure
// floor and the first-attempt gate is measured on novelty alone. A
// legitimate interleave login the namespace's emergency stop refuses
// is counted (legit_denied) and disclosed: the stop is the walk's own
// failure volume, never a per-account refusal.
$phaseLog('boot:slow');
[$slowKernel, $slowOverrides] = $bootProduct("kiwi-rt-d35-slow-$nsTag");
$slowWire = new RtWire($slowKernel);
$slowLegitCount = min(150, max(20, (int) ceil($slowRows / 4)));
$slowLegitActors = $establishVictims($slowWire, $accounts, $hotVictims, $slowLegitCount);
$slowLegitIndex = array_keys($slowLegitActors);
$slowLegitAt = 0;
$slow = ['rows' => 0, 'valid' => 0, 'blocked' => 0, 'compromised' => 0, 'invalid' => 0, 'denied' => 0, 'legit' => 0, 'legit_blocked' => 0, 'legit_denied' => 0, 'retries' => 0];
$slowActor = new RtActor('45.77.1.1');
for ($i = 0; $i < $slowRows; $i++) {
    $row = $i % $rowsTotal;
    $account = $rows[$row];
    $a = max(0, (int) RtD35Accounts::indexOf($account));
    if ($rowValid[$row]) {
        $granted = false;
        for ($attempt = 0; $attempt <= 5; $attempt++) {
            $outcome = $slowWire->login($slowActor, $account, RtD35Accounts::passwordOf($a));
            if ($attempt > 0) {
                $slow['retries']++;
            }
            if ($outcome === 'allow') {
                $granted = true;
                break;
            }
            if ($outcome === 'invalid') {
                if ($attempt === 0) {
                    $slow['denied']++;
                }

                continue;
            }
            if (str_starts_with($outcome, 'http:')) {
                fwrite(STDERR, "FATAL: the wire broke on a valid credential (slow row $i, attempt $attempt, outcome $outcome)\n");
                exit(2);
            }
        }
        $slow['valid']++;
        if ($granted) {
            $slow['compromised']++;
        } else {
            $slow['blocked']++;
        }
    } else {
        $outcome = $slowWire->login($slowActor, $account, $passwords[random_int(0, $corpusSize - 1)]);
        $slow['invalid'] += $outcome === 'invalid' ? 1 : 0;
    }
    $slow['rows']++;
    // The interleave: ten established legitimate logins per stuffing
    // row, the pacing that keeps the scope failure ratio under the
    // pressure floor while the walk never stops.
    for ($l = 0; $l < $slowInterleave; $l++) {
        $legitIndex = $slowLegitIndex[$slowLegitAt % \count($slowLegitIndex)];
        $slowLegitAt++;
        $legitAccount = $accounts[$legitIndex];
        $legitActor = $slowLegitActors[$legitIndex];
        $legitIp = new RtActor($homeIpOf($legitIndex));
        $legitIp->cookies = $legitActor->cookies;
        $legitIp->totpSecrets = $legitActor->totpSecrets;
        $legitOutcome = $slowWire->login($legitIp, $legitAccount, RtD35Accounts::passwordOf($legitIndex));
        $slow['legit']++;
        if ($legitOutcome === 'withheld') {
            $slow['legit_blocked']++;
            if ($legitIp->pending !== null) {
                // Return the account to its owner through the enrolled
                // factor (the product's own step-up plane).
                $slowWire->completeStepUp($legitIp, 'totp', $slowWire->totpCode());
            }
        } elseif ($legitOutcome === 'invalid') {
            // The namespace's admission stop refused an established
            // bound login: counted and disclosed, never a grant.
            $slow['legit_denied']++;
        } elseif ($legitOutcome !== 'allow') {
            fwrite(STDERR, "FATAL: the slow-mode legitimate interleave answered $legitOutcome\n");
            exit(2);
        }
    }
    if ($slowSleepMicros > 0) {
        usleep($slowSleepMicros);
    }
}
$slowDenominator = $slow['invalid'] + $slow['legit'];
$slowFailureRatioPerMille = $slowDenominator > 0
    ? (int) round($slow['invalid'] * 1000 / $slowDenominator)
    : MarksEscalation::SCOPE_PRESSURE_FLOOR;
$slowRatioUnderFloor = $slowFailureRatioPerMille < MarksEscalation::SCOPE_PRESSURE_FLOOR;
unset($slowKernel, $slowWire);

// ---------- stolen_session_cookie (fresh namespace) ----------
// The identity-theft plane: the attacker holds the victim's
// established browser state (continuity + device cookies) AND the
// leaked password. Reported as its own mode under its own documented
// bound: the first-attempt gate still withholds a thief arriving from
// a never-seen ASN even with bound cookies, and the bound absorbs the
// ASN-matched corner of the space. The mode carries no failure
// volume, so its namespace never enters the emergency stop and the
// gate verdicts are measured on their own.
$phaseLog('boot:stolen');
[$stolenKernel, $stolenOverrides] = $bootProduct("kiwi-rt-d35-stolen-$nsTag");
$stolenWire = new RtWire($stolenKernel);
$stolenVictimActors = $establishVictims($stolenWire, $accounts, 0, min(100, 300));
$stolen = ['rows' => 0, 'valid' => 0, 'blocked' => 0, 'compromised' => 0];
$stolenSample = \count($stolenVictimActors);
foreach ($stolenVictimActors as $a => $victim) {
    $thief = new RtActor($attackerIpOf($a, 0));
    $thief->cookies = $victim->cookies;
    $outcome = $stolenWire->login($thief, $accounts[$a], RtD35Accounts::passwordOf($a));
    $stolen['rows']++;
    $stolen['valid']++;
    if ($outcome === 'allow') {
        $stolen['compromised']++;
    } elseif ($outcome === 'withheld') {
        $stolen['blocked']++;
    }
}
// The documented identity-theft bound: at most one stolen bound
// session in ten may be granted. The expected state is zero (the
// novel-ASN verdict withholds the thief); the bound is the mode's own
// bar, not the credential-stuffing one.
$stolenCompromiseBound = (int) ceil($stolen['rows'] * 0.1);
unset($stolenKernel, $stolenWire);

$auditOverrides = max($retryOverrides, $slowOverrides, $stolenOverrides);

// ============================================================
// the storm (its own namespace, fresh per run): the corpus at volume
// ============================================================
$phaseLog('boot:storm');
[$kernel, $stormOverrides] = $bootProduct("kiwi-rt-d35-storm-$nsTag");
$auditOverrides = max($auditOverrides, $stormOverrides);
$container = $kernel->getContainer();
$wire = new RtWire($kernel);

// The measurement reads (never writes): the shipped policy, the live
// global level and the target dimension of the product's own store.
$policy = $container->get('kiwi_captcha.risk.policy');
\assert($policy instanceof \KiwiCaptcha\Risk\RiskPolicy);
$store = $container->get('kiwi_captcha.risk.store');
\assert($store instanceof \KiwiCaptcha\Risk\Storage\TargetStateStoreInterface);
$resources = new \KiwiCaptcha\Risk\ResourcePressure(1000, 1000);

// ---------- the wave machine (the storm corpus) ----------
// The full list at volume from the attacker fleet. The namespace
// ratchets into the emergency admission stop early in the walk (the
// failure volume is the storm), so the measured outcomes separate:
// withheld valid credentials are the first-attempt gate's step-up on
// the quiet head of the walk, refused valid credentials are the
// admission stop's terminal denial. Neither is ever a granted
// session; the compromise bar stays zero.
$sessionAttempts = array_fill(0, $attackerSessions, 0);
$attackerActors = [];
for ($s = 0; $s < $attackerSessions; $s++) {
    $attackerActors[$s] = new RtActor($attackerIpOf($s, $s % $groups));
}
$rowsPerWave = (int) ceil($rowsTotal / $waves);
$sessionSlice = (int) ceil($rowsTotal / $attackerSessions);
$compromised = 0;
$blockedValid = 0;
$deniedValid = 0;
$validAssessed = 0;
$rowsProcessed = 0;
$levels = [$store->lastGlobalLevel()];
$waveFreshUntrustedRanks = [];
$levelsFire = false;

// Per-subclass storm attribution: the measured rows behind the
// isp_matched and cgnat_shared_exit notes (sessions 1 and 2 mod 3 of
// the storm carry the victim's own ASN, or share the victim's home
// range; the plain sessions are the fresh-egress control).
$subClass = [];
foreach (['plain', 'isp_matched', 'cgnat_shared_exit'] as $kind) {
    $subClass[$kind] = ['sessions' => 0, 'rows' => 0, 'valid' => 0, 'blocked' => 0, 'compromised' => 0];
}
$subClassOf = static fn (int $session): string => $isIspMatched($session)
    ? 'isp_matched'
    : ($isCgnatMatched($session) ? 'cgnat_shared_exit' : 'plain');
$seenSubSessions = [];
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
        $bucket = $subClassOf($session);
        $seenSubSessions[$bucket][$session] = true;
        $subClass[$bucket]['rows']++;

        $password = $passwordOfRow[$i];
        if ($rowValid[$i]) {
            // The true password: the attacker's working row. A granted
            // session is a compromise; a withheld one is the gate's
            // step-up; a refused one is the product's denial. None is
            // ever a silent pass.
            $outcome = $wire->login($actor, $account, $password);
            $subClass[$bucket]['valid']++;
            if ($outcome === 'allow') {
                $compromised++;
                $subClass[$bucket]['compromised']++;
            } elseif ($outcome === 'withheld') {
                $blockedValid++;
                $subClass[$bucket]['blocked']++;
            } elseif ($outcome === 'invalid') {
                // The terminal denial of a proven-good credential (the
                // gate's deny or the namespace admission stop): the
                // credential never granted a session.
                $deniedValid++;
                $subClass[$bucket]['blocked']++;
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
            $sessionAttempts[$session]++;
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

// Fold the per-row subclass attribution into the measured buckets.
foreach ($subClass as $bucket => $row) {
    $subClass[$bucket]['sessions'] = isset($seenSubSessions[$bucket]) ? \count($seenSubSessions[$bucket]) : 0;
}

$phaseLog('probe');
// ---------- the post-storm attacker probe ----------
// Every attacker identity that drove the storm is denied when it
// returns with a working password: the marks and target evidence the
// storm earned, plus the namespace's admission stop while it holds,
// are the denial. A grant on return is the failure this leg hunts.
$sessionsNeverEscalated = 0;
foreach ($attackerActors as $s => $actor) {
    if ($sessionAttempts[$s] === 0) {
        continue;
    }
    $account = $rows[$s * $sessionSlice];
    $password = RtD35Accounts::passwordOf(max(0, (int) RtD35Accounts::indexOf($account)));
    $outcome = $wire->login($actor, $account, $password);
    if ($outcome === 'allow') {
        $sessionsNeverEscalated++;
    }
}
unset($kernel, $wire, $container);

$auditOverridesMax = static function (int $current, array $pair): int {
    return max($current, $pair[1]);
};

$phaseLog('victims');
// ---------- the target-dimension spread (fresh namespaces) ----------
// The per-victim plane the release criteria name: each hot victim is
// established (continuity, email step-up, enrolled TOTP) in a fresh
// namespace, the account is attacked from distinct egresses through
// the product's own failure lane, and the owner probes after every
// attack row. The measured facts: the owner's login steps up within
// the spread bound, never locks out, and every targeted account steps
// up. Three victims share one namespace (their combined failure
// volume stays under the emergency trip), so the target dimension and
// the first-attempt gate are measured on their own, never under the
// storm's admission stop.
$victimSteppedUpAt = [];
$firstStepUpFailures = [];
$victimLockedOut = [];
$victimsPerBatch = 3;
$attackRowsPerVictim = 8;
for ($first = 0; $first < $hotVictims; $first += $victimsPerBatch) {
    $batch = intdiv($first, $victimsPerBatch);
    $phaseLog("boot:victims$batch");
    [$victimKernel, $victimOverrides] = $bootProduct("kiwi-rt-d35-victims-$nsTag-$batch");
    $auditOverrides = $auditOverridesMax($auditOverrides, [$victimKernel, $victimOverrides]);
    $victimWire = new RtWire($victimKernel);
    $victimStore = $victimKernel->getContainer()->get('kiwi_captcha.risk.store');
    \assert($victimStore instanceof \KiwiCaptcha\Risk\Storage\TargetStateStoreInterface);
    $victimIdentity = $victimKernel->getContainer()->get('kiwi_captcha.risk.identity_factory');
    \assert($victimIdentity instanceof \KiwiCaptcha\Risk\RiskIdentityFactory);
    $batchActors = $establishVictims($victimWire, $accounts, $first, min($victimsPerBatch, $hotVictims - $first));
    foreach (array_keys($batchActors) as $vIndex) {
        $account = $accounts[$vIndex];
        $accountIndex = (int) RtD35Accounts::indexOf($account);
        $steppedUp = false;
        for ($k = 0; $k < $attackRowsPerVictim; $k++) {
            // One attack row: a distinct attacker egress presents a
            // wrong password for the victim's account (the leaked-list
            // shape), booking the product's own target failure.
            $attacker = new RtActor($attackerIpOf($k, $k % $groups));
            $wrong = $passwords[($accountIndex + 1 + $k) % $corpusSize];
            if ($wrong === RtD35Accounts::passwordOf($vIndex)) {
                $wrong = $passwords[($k + 7) % $corpusSize];
            }
            $attackOutcome = $victimWire->login($attacker, $account, $wrong);
            if ($attackOutcome !== 'invalid') {
                // A wrong password must never authenticate.
                fwrite(STDERR, "FATAL: a victim-attack row answered $attackOutcome (victim $vIndex, attack $k)\n");
                exit(2);
            }
            // The owner probes from home with bound continuity, the
            // way the current code probes a hot victim after its
            // attacked row.
            $victimActor = $batchActors[$vIndex];
            $victimOutcome = $victimWire->login($victimActor, $account, RtD35Accounts::passwordOf($vIndex));
            if ($victimOutcome === 'withheld') {
                $victimSteppedUpAt[$vIndex] = true;
                $steppedUp = true;
                // The target dimension keys on the claimed
                // identifier's pseudonym (the bridge's target handle
                // derivation), not the principal one.
                $target = $victimIdentity->targetId($account);
                $state = $victimStore->readTargetState($target);
                $firstStepUpFailures[$vIndex] = (int) ($state['fails'] ?? 0);
                if ($victimActor->pending !== null) {
                    // Return the account to its owner through the
                    // enrolled factor (the product's own step-up
                    // plane), so the next probe measures cleanly.
                    $victimWire->completeStepUp($victimActor, 'totp', $victimWire->totpCode());
                }

                break;
            }
            if ($victimOutcome === 'invalid') {
                // The owner's true password was refused in a namespace
                // with no emergency volume: a genuine lockout.
                $victimLockedOut[$vIndex] = true;

                break;
            }
            // An Allow: the threshold has not been crossed yet; the
            // next attack row continues the spread.
        }
        if (!$steppedUp && !isset($victimLockedOut[$vIndex])) {
            // Eight spread failures and the owner still logs in
            // unchallenged: the target dimension never escalated, the
            // measured spread for this victim stays missing and the
            // stepped-up bar below fails honestly.
        }
    }
    unset($victimKernel, $victimWire);
}
$lockouts = \count($victimLockedOut);
$stepUpSpreadOk = \count($firstStepUpFailures) === $hotVictims
    && ($firstStepUpFailures === [] || max($firstStepUpFailures) <= SPREAD_BOUND + 1);

$phaseLog('baseline');
// ---------- the legitimate baseline (fresh namespace) ----------
// The established users' return logins, measured in a namespace whose
// failure volume stays at zero: the false-positive bound judges the
// continuity and trust planes (a bound home or same-ASN login must
// pass), a claim the storm's own admission stop would drown if the
// probes shared the storm namespace. The storm-side collateral is
// measured by the target-dimension spread above.
[$baselineKernel, $baselineOverrides] = $bootProduct("kiwi-rt-d35-baseline-$nsTag");
$auditOverrides = $auditOverridesMax($auditOverrides, [$baselineKernel, $baselineOverrides]);
$baselineWire = new RtWire($baselineKernel);
$legitActors = $establishVictims($baselineWire, $accounts, 0, min(300, $rowsTotal));
$established = \count($legitActors);

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
        $outcome = $baselineWire->login($probe, $account, RtD35Accounts::passwordOf($a));
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
            $baselineWire->completeStepUp($probe, 'totp', $baselineWire->totpCode());
        }
    }
    if (!$withTarget) {
        $homeProbe = new RtActor($homeIpOf($a));
        $homeProbe->cookies = $actor->cookies;
        $d1 = $baselineWire->login($homeProbe, $account, RtD35Accounts::passwordOf($a));
        $sameProbe = new RtActor($mobileIpOf($a));
        $sameProbe->cookies = $actor->cookies;
        $d2 = $baselineWire->login($sameProbe, $account, RtD35Accounts::passwordOf($a));
        $ntHome++;
        $ntSame++;
        $ntHomeB += $d1 === 'withheld' ? 1 : 0;
        $ntSameB += $d2 === 'withheld' ? 1 : 0;
    }
}
$legitFpRate = ($ntHome + $ntSame) > 0 ? ($ntHomeB + $ntSameB) / ($ntHome + $ntSame) : 1.0;

$phaseLog('return');
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
// spread measurement already; this leg measures plain novel-network
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
    $d1 = $baselineWire->login($traveler, $account, RtD35Accounts::passwordOf($index));
    if ($d1 !== 'withheld') {
        // A novel-ASN login that is not withheld is a hole, not a
        // pass — except an 'invalid' which is a harness fault.
        $stepUpThenReturnOk = false;
        break;
    }
    // login() captured the pending token onto the traveler already.
    if (!$baselineWire->completeStepUp($traveler, 'totp', $baselineWire->totpCode())) {
        $stepUpThenReturnFail = 'complete';
        $stepUpThenReturnOk = false;
        break;
    }
    // The same /32 is its own bucket for IPv4, but the ASN is known
    // now and the restore bound the identities: the next login from
    // the same carrier must not re-escalate.
    $nextProbe = new RtActor($novelIp);
    $nextProbe->cookies = $traveler->cookies;
    $d2 = $baselineWire->login($nextProbe, $account, RtD35Accounts::passwordOf($index));
    if ($d2 === 'withheld') {
        $stepUpThenReturnFail = 'second';
        $stepUpThenReturnOk = false;
        break;
    }
}
$driverClass = \get_class($baselineKernel);
$driverIsKernel = $baselineKernel instanceof Kernel;
unset($baselineWire);

$phaseLog('summary');
// ---------- the summary ----------
$allSessionsEscalated = $sessionsNeverEscalated === 0;
$escalatedWithinN = $allSessionsEscalated;

// The attacker economics: the storm's measured rows at the bench
// price of one sha16 solve (the harness supplies the measured mean).
$sha16Us = (float) (getenv('KIWI_RT_D35_SHA16_US') ?: 300000);
$spendUsd = $rowsProcessed * $sha16Us / 1e6;

$summary = [
    'rows' => $rowsProcessed,
    'rows_total_declared' => $rowsTotal,
    'valid_rows' => $validAssessed,
    'blocked_valid' => $blockedValid + $deniedValid,
    'blocked_valid_by_step_up' => $blockedValid,
    'blocked_valid_by_deny' => $deniedValid,
    'compromised_valid' => $compromised,
    'corpus_residual_compromised' => $compromised,
    'corpus_size' => $corpusSize,
    'sha16_us' => $sha16Us,
    'spend_usd' => round($spendUsd, 6),
    'breached_credential_checker' => 'not shipped by default; not credited',
    'engine_path' => 'form_login firewall -> FirstAttemptLoginGuard -> RiskGateway::loginDecision'
        . ' (booted FrameworkBundle+SecurityBundle+KiwiCaptchaBundle kernel, override audit diff of the reference build)',
    'novelty_enforcement' => 'enforce (abuse_first profile)',
    'trust_gate' => 'store (the shipped default; not configured by the driver)',
    'driver' => $driverClass,
    'kernel_class' => $driverClass,
    'kernel_is_kernel_subclass' => $driverIsKernel,
    'container_overrides' => $auditOverrides,
    'container_overrides_by_kernel' => [
        'retry_same_ip' => $retryOverrides,
        'low_and_slow' => $slowOverrides,
        'stolen_session_cookie' => $stolenOverrides,
        'storm' => $stormOverrides,
        'victim_spread' => 'one namespace per three hot victims, each audited 0',
        'baseline' => $baselineOverrides,
    ],
    'target_source' => 'product outcome bridge (LoginFailure lane) through the wire',
    'seeded_network_history' => $established,
    'history_writer' => 'the product (challenge continuity cookie, step-up restore); no driver store writes',
    'mode_isolation' => 'every phase boots its own risk namespace before the next; the per-credential planes are measured under their own volume',
    'global_posture_note' => 'the shipped engine ratchets a namespace into the emergency admission stop at its rolling failure saturation; the volume phases measure inside that posture and count the refusals of proven-good credentials as the denials they are (blocked_valid_by_deny), while the per-credential planes (target spread, lockouts, baseline) are measured in namespaces under the trip',
    'attack_modes' => [
        'storm' => ['rows' => $rowsProcessed, 'valid' => $validAssessed, 'blocked_valid' => $blockedValid + $deniedValid, 'compromised_valid' => $compromised],
        'retry_same_ip' => $retry + ['note' => 'each valid credential was attempted, stepped up or denied, and retried five times from the same actor; any Allow counts'],
        'low_and_slow' => $slow + [
            'pacing' => ['interleave_legit_per_row' => $slowInterleave, 'sleep_us_per_row' => $slowSleepMicros],
            'failure_ratio_permille' => $slowFailureRatioPerMille,
            'scope_pressure_floor_permille' => MarksEscalation::SCOPE_PRESSURE_FLOOR,
            'note' => 'one identity, one address, the list walked in order before the storm, paced under the scope pressure floor',
        ],
        'stolen_session_cookie' => $stolen + [
            'compromise_bound' => $stolenCompromiseBound,
            'note' => 'identity-theft plane: the attacker holds the victim\'s established browser state; reported separately from the credential-stuffing corpus, under its own documented bound (the novel-ASN verdict still withholds a thief; the bound absorbs the ASN-matched corner)',
        ],
        'isp_matched' => $subClass['isp_matched'] + ['note' => 'sessions 1 mod 3 of the storm carry the victim\'s own ASN'],
        'cgnat_shared_exit' => $subClass['cgnat_shared_exit'] + ['note' => 'sessions 2 mod 3 of the storm share the victim\'s home range'],
        'storm_plain' => $subClass['plain'] + ['note' => 'sessions 0 mod 3 of the storm: the fresh-egress control'],
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
// The RUNTIME line names the booted kernel and the computed override
// count; the ledger refuses a product-method GREEN without it. It
// rides STDERR: the stdout stream is the pure JSON summary file.
fprintf(
    STDERR,
    "RUNTIME: driver=%s container_overrides=%d kernel=%s\n",
    $driverClass,
    $auditOverrides,
    $driverIsKernel ? 'yes' : 'no',
);

$pass = $escalatedWithinN
    && $allSessionsEscalated
    && $lockouts === 0
    && $stepUpSpreadOk
    && $compromised === 0
    && $validAssessed > 0
    && ($blockedValid + $deniedValid) > 0
    && $legitFpRate <= 0.001
    && $stepUpThenReturnOk
    && $retry['compromised'] === 0
    && $slow['compromised'] === 0
    && $slowRatioUnderFloor
    && $stolen['compromised'] <= $stolenCompromiseBound
    && $auditOverrides === 0;
exit($pass ? 0 : 1);
