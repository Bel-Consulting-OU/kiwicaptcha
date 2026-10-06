<?php

declare(strict_types=1);

/**
 * d38.risk.php — the unauthenticated computer-use agent's risk-plane
 * leg of D3.8: the scripted browser driver (webdriver visible, no
 * stealth) has its solve events scored through the REAL php risk
 * engine over the REAL Redis. The required behavior for an
 * UNAUTHENTICATED agent is exactly the commodity-bot treatment: priced
 * at its own band while clean, escalated by its own velocity as the
 * run accumulates, never credited as human, and its verification pass
 * rate matches the wire's honesty (every honestly paid solve
 * accepted).
 *
 * Input: the scripted browser driver's JSON document (argv[1]).
 * Output: one JSON summary on stdout.
 */

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
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

$browserDoc = json_decode((string) file_get_contents($argv[1] ?? ''), true);
if (!is_array($browserDoc)) {
    throw new RuntimeException('browser document unreadable');
}

$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$client = RedisRiskStateStore::createClient($redisUrl);
$store = new RedisRiskStateStore($client, namespace: 'd38-' . bin2hex(random_bytes(4)));
$keys = RiskKeys::fromMaster(random_bytes(32));
$engine = new AdaptiveRiskEngine(
    store: $store,
    classifier: new CidrNetworkClassifier([]),
    identityFactory: new RiskIdentityFactory($keys),
    scorer: new RiskScorer(),
    policy: RiskPolicy::fromConfig([
        'version' => 3,
        'weights' => (new RiskWeights())->toArray(),
        'scopes' => [
            1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
        ],
        'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
    ]),
    keys: $keys,
);
$healthy = new ResourcePressure(1000, 1000);
$session = rtPseudo('d38-scripted-session');

$context = new RiskContext(
    scope: 1,
    sourceIp: '198.51.100.77',
    sessionId: $session,
    principalId: null,
    event: RiskEventKind::PreIssue,
    networkFlags: (new CidrNetworkClassifier([]))->classify('198.51.100.77'),
    resources: $healthy,
);

$ranks = [];
$accepted = 0;
foreach ($browserDoc['solves'] as $solve) {
    $decision = $engine->assessPreIssue($context);
    $ranks[] = $decision->action->rank();
    if (!$solve['accepted']) {
        continue;
    }
    $accepted++;
    $engine->reassess(new RiskContext(
        scope: 1,
        sourceIp: '198.51.100.77',
        sessionId: $session,
        principalId: null,
        event: RiskEventKind::SolveSuccess,
        networkFlags: (new CidrNetworkClassifier([]))->classify('198.51.100.77'),
        resources: $healthy,
    ));
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
