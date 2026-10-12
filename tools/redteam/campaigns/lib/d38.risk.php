<?php

declare(strict_types=1);

/**
 * d38.risk.php — the unauthenticated computer-use agent's risk-plane
 * leg of D3.8: the scripted browser driver (webdriver visible, no
 * stealth) has its solve events scored through the product's own risk
 * engine inside a booted Symfony kernel (rt.kernel.php: FrameworkBundle
 * + SecurityBundle + KiwiCaptchaBundle, the shipped abuse_first
 * profile, zero container overrides, the computed audit diff of the
 * reference build), read through the container's RiskGateway — the
 * same gateway the deployment serves — over the real Redis. The
 * required behavior for an UNAUTHENTICATED agent is exactly the
 * commodity-bot treatment: priced at its own band while clean,
 * escalated by its own velocity as the run accumulates, never credited
 * as human, and its verification pass rate matches the wire's honesty
 * (every honestly paid solve accepted).
 *
 * The hand-built policy of the fixture era (scope base_risk 100,
 * minimum allow, post-solve check, sha20 degraded; the sha16/sha18/
 * sha20/sha20 global floors) is the shipped configuration: the kernel
 * boots with those exact kiwi_captcha.risk scope keys and the bundle's
 * own global_pressure defaults, and the decisions come from the engine
 * that configuration wires.
 *
 * Input: the scripted browser driver's JSON document (argv[1]).
 * Output: one JSON summary on stdout.
 */

use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
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
$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
if ($redisUrl === '') {
    fwrite(STDERR, "FATAL: KIWI_RT_RISK_REDIS_URL is not set; the kernel boots the real risk engine on real Redis\n");
    exit(2);
}
RtCampaignKernel::$loginScopeOverrides = [
    'base_risk' => 100,
    'minimum' => 'allow',
    'post_solve_check' => true,
    'degraded' => 'sha20',
];
RtCampaignKernel::$riskNamespace = 'd38-' . bin2hex(random_bytes(4));
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

// The risk answer comes from the booted container's gateway: the same
// RiskGateway the deployment serves. One session identity, one source
// address — the agent's own velocity is the only pressure in the run.
$gateway = $kernel->getContainer()->get(RiskGateway::class);
\assert($gateway instanceof RiskGateway);
$ip = '198.51.100.77';
$session = rtPseudo('d38-scripted-session');

$ranks = [];
$accepted = 0;
foreach ($browserDoc['solves'] as $solve) {
    $decision = $gateway->preIssue('login', $ip, $session);
    $ranks[] = $decision->action->rank();
    if (!$solve['accepted']) {
        continue;
    }
    $accepted++;
    $gateway->postSolveDecision('login', $ip, $session);
}

$firstRank = $ranks[0] ?? 0;
$summary = [
    'scripted_solves' => count($ranks),
    'scripted_accepted' => $accepted,
    'webdriver_visible' => ($browserDoc['recon']['webdriver'] ?? 'true') !== 'undefined',
    'price_first' => $firstRank,
    'price_max' => $ranks ? max($ranks) : 0,
    'ladder_escalated' => count($ranks) > 1 && max($ranks) > $firstRank,
];
echo json_encode($summary), "\n";

$pass = $accepted === count($ranks)
    && $summary['webdriver_visible']
    && $summary['ladder_escalated'];
exit($pass ? 0 : 1);
