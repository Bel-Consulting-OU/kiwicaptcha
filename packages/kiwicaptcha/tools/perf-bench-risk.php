<?php

declare(strict_types=1);

/**
 * Risk-enabled controller throughput benchmark.
 *
 * The bundle-level issuance path with the adaptive risk engine wired:
 * each request runs the real ChallengeController, resolves the scope,
 * runs the risk pre-issue assessment (identity keying, signal vector,
 * score, decision), issues the challenge and builds the JSON response. The workload is 400 controller invocations at
 * 40 warmup iterations against an in-memory risk state store. The
 * storage is ArrayStorage and the risk engine sees a zero signal
 * vector, so the measurement is the pure bundle-path cost of a
 * risk-enabled issuance (the engine, the gateway, the controller
 * mapping), not Redis or solver time.
 *
 * The state store is an in-memory implementation inside this harness
 * (the RiskStateStoreInterface contract: observe returns a zero
 * vector, outcome registration is a no-op). The benchmark must not
 * depend on the bundle's test fixtures, and a real Redis would turn
 * this into a network benchmark. The policy is permissive
 * (base_risk 100, minimum allow), so every request ends in a 200
 * challenge response; a denied or escalated response fails the run.
 *
 * The percentiles gate on the same generous relative ratchet as the
 * other benchmarks: the run fails only when p95 exceeds 3x its
 * recorded baseline. Noisy-runner-tolerant on purpose; the byte and
 * count budgets in perf-budget.sh remain the gating gate and this
 * timing signal is loud but never a hard merge gate by itself.
 *
 * Baseline recorded 2026-08-30 on PHP 8.5 (local Mac): risk-enabled
 * controller issuance p50 0.047 ms p95 0.065 ms. Run with
 * --update-baseline to print fresh values after a deliberate change.
 */

$autoload = __DIR__.'/../../kiwicaptcha/integrations/symfony/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "perf-bench-risk: the Symfony bundle vendor is missing at $autoload (run composer install in packages/kiwicaptcha/integrations/symfony)\n");
    exit(1);
}
require $autoload;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Storage\ArrayStorage;
use Symfony\Component\HttpFoundation\Request;

const WARMUP = 40;
const ITERATIONS = 400;
const RATCHET = 3.0;
const BASELINE_P50 = 0.047;
const BASELINE_P95 = 0.065;

/** In-memory risk state store: zero signal vectors, outcome no-ops. */
final class BenchRiskStateStore implements RiskStateStoreInterface
{
    public function observe(RiskObservation $observation): SignalVector
    {
        return SignalVector::zero();
    }

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        return true;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        return 0;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        return true;
    }
}

function percentile(array $samples, float $q): float
{
    sort($samples, SORT_NUMERIC);
    $index = (int) ceil($q / 100.0 * count($samples)) - 1;

    return $samples[max(0, $index)];
}

$secret = '0123456789abcdef0123456789abcdef';
$storage = new ArrayStorage();
$issuer = new Issuer(new Config(
    secretKey: $secret,
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 8,
    ttlSecs: 120,
), $storage);
$keys = RiskKeys::fromMaster($secret);
$classifier = new CidrNetworkClassifier([]);
$policy = RiskPolicy::fromConfig([
    'version' => RiskPolicy::CONTRACT_VERSION,
    'weights' => [],
    'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
]);
$engine = new AdaptiveRiskEngine(new BenchRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
$gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], emergencyCap: new ProcessEmergencyCap(10000));
$controller = new ChallengeController($issuer, risk: $gateway, sameOriginOnly: false, storage: $storage);

$samples = [];
for ($i = 0; $i < WARMUP + ITERATIONS; $i++) {
    $request = Request::create(
        '/challenge',
        'POST',
        [],
        [],
        [],
        ['CONTENT_TYPE' => 'application/json', 'REMOTE_ADDR' => '198.51.100.7'],
        '{"scope":"login"}',
    );
    $t0 = hrtime(true);
    $response = $controller->challenge($request);
    $t1 = hrtime(true);
    if ($response->getStatusCode() !== 200) {
        fwrite(STDERR, 'perf-bench-risk: a risk-enabled issuance did not answer 200 (status '.$response->getStatusCode().")\n");
        exit(1);
    }
    if ($i >= WARMUP) {
        $samples[] = ($t1 - $t0) / 1e6;
    }
}

$p50 = percentile($samples, 50);
$p95 = percentile($samples, 95);
printf("perf-bench-risk: risk-enabled controller issuance p50 %.3f ms p95 %.3f ms (n=%d)\n", $p50, $p95, count($samples));

if (in_array('--update-baseline', $argv, true)) {
    printf("perf-bench-risk: update the constants: p50 %.3f p95 %.3f\n", $p50, $p95);
    exit(0);
}

if ($p95 > BASELINE_P95 * RATCHET) {
    fwrite(STDERR, sprintf("perf-bench-risk FAILED: risk-enabled issuance p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $p95, BASELINE_P95 * RATCHET, BASELINE_P95));
    exit(1);
}
echo "perf-bench-risk: OK (p95 within the 3x noisy-runner-tolerant ratchet)\n";
