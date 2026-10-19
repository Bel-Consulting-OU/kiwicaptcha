<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\RswTrapdoor;
use BelConsulting\KiwiCaptchaBundle\Risk\RswTrapdoorUnavailable;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RiskRswTrapdoorTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RiskTestKernel;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use BelConsulting\KiwiCaptchaBundle\Risk\ChallengeStrength;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Pricing\PriceContextSourceInterface;
use KiwiCaptcha\Risk\Pricing\PriceInputs;
use KiwiCaptcha\Risk\Pricing\PriceRequest;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Support\RswFixture;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The adaptive rsw rung end to end (change.md 1.4: RSW is a first-class
 * rung whenever a trapdoor is configured). A kernel booted with the rsw
 * trapdoor resolves the Rsw action onto the time-lock profile; a score
 * that prices into the rsw band issues an rsw challenge. The same score
 * on a kernel without a trapdoor resolves to the interactive step-up —
 * typed, never a silent weaker challenge.
 */
final class RswAdaptiveRungKernelTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * The kernel boots with the trapdoor pair over a sha256 baseline:
     * the wired gateway arms the adaptive rsw rung and maps Rsw onto
     * the time-lock profile at the configured sequential cost.
     */
    public function testKernelWithTrapdoorArmsTheAdaptiveRswRung(): void
    {
        $kernel = new RiskRswTrapdoorTestKernel('test', true);
        $kernel->boot();
        $gateway = $kernel->getContainer()->get(RiskGateway::class);
        self::assertInstanceOf(RiskGateway::class, $gateway);

        self::assertTrue($gateway->resolvesRsw(), 'the configured pair arms the rung');
        self::assertSame(RiskAction::Rsw, $gateway->effectiveAction(RiskAction::Rsw), 'a trapdoor keeps the ladder action');
        $profile = $gateway->profileForAction(RiskAction::Rsw);
        self::assertNotNull($profile);
        self::assertSame(PoWAlgorithm::Rsw, $profile->algorithm, 'the trapdoor issues the time-lock profile');
        self::assertSame(10_000, $profile->t, 'the profile carries the configured sequential cost');
        self::assertSame(1, $profile->targetBits);
        self::assertSame(0, $profile->mKib);
        self::assertSame(1, $profile->p);

        // A minted rsw profile satisfies the action; a weaker argon one
        // never does (different families never dominate).
        self::assertTrue($gateway->challengeSatisfies(new ChallengeStrength(PoWAlgorithm::Rsw, 0, 10_000, 1, 1), RiskAction::Rsw));
        self::assertFalse($gateway->challengeSatisfies(new ChallengeStrength(PoWAlgorithm::Argon2id, 16384, 3, 1, 4), RiskAction::Rsw));
        $kernel->shutdown();
    }

    /**
     * Without a configured trapdoor the same kernel resolves Rsw to the
     * interactive step-up: the direct mapping throws the typed error —
     * never a silent weaker challenge.
     */
    public function testKernelWithoutTrapdoorResolvesRswToStepUp(): void
    {
        $kernel = new RiskTestKernel('test', true);
        $kernel->boot();
        $gateway = $kernel->getContainer()->get(RiskGateway::class);
        self::assertInstanceOf(RiskGateway::class, $gateway);

        self::assertFalse($gateway->resolvesRsw(), 'no pair, no rung');
        self::assertSame(RiskAction::StepUp, $gateway->effectiveAction(RiskAction::Rsw), 'Rsw resolves to the interactive step-up');
        self::assertSame(RiskAction::Allow, $gateway->effectiveAction(RiskAction::Allow), 'the resolution leaves every other action untouched');
        try {
            $gateway->profileForAction(RiskAction::Rsw);
            self::fail('the direct rsw mapping must fail typed without a trapdoor');
        } catch (RswTrapdoorUnavailable) {
            self::assertTrue(true);
        }
        // No record satisfies an action that resolved to the step-up.
        self::assertFalse($gateway->challengeSatisfies(new ChallengeStrength(PoWAlgorithm::Argon2id, 65536, 3, 1, 4), RiskAction::Rsw));
        $kernel->shutdown();
    }

    /**
     * A score that prices into the rsw band (work score 620 + the full
     * 300-point unproven pressure ramp = 920, inside 850..925) issues an
     * rsw challenge when the trapdoor is configured.
     */
    public function testScorePricedIntoTheRswBandIssuesAnRswChallenge(): void
    {
        $stack = self::stack(withTrapdoor: true);
        $response = $stack['controller']->challenge(self::challengeRequest());

        self::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('rsw', $data['algorithm'], 'the priced rsw rung issues the time-lock challenge');
        self::assertSame(10000, $data['t'], 'the challenge carries the configured sequential cost');
    }

    /**
     * The identical score on a deployment without a trapdoor resolves
     * the priced rsw rung to the interactive step-up (403), never a
     * weaker silent challenge.
     */
    public function testTheSameScoreWithoutATrapdoorYieldsStepUp(): void
    {
        $stack = self::stack(withTrapdoor: false);
        $response = $stack['controller']->challenge(self::challengeRequest());

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('STEP_UP_REQUIRED', $data['error']['code'] ?? null);
    }

    /**
     * The bundle risk stack over a fake store. The observed vector and
     * the fail-closed price context drive the score into the rsw band
     * deterministically: base 100 + weighted source_fast 350 + weighted
     * global_pressure 170 = 620 risk, and the unproven full ramp adds
     * 300.
     *
     * @return array{controller: ChallengeController, gateway: RiskGateway, store: FakeRiskStateStore, resolver: RiskProfileResolver}
     */
    private static function stack(bool $withTrapdoor): array
    {
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            targetBits: 8,
            ttlSecs: 120,
            rswModulusN: $withTrapdoor ? RswFixture::MODULUS_N_B64 : null,
            rswLambda: $withTrapdoor ? RswFixture::LAMBDA_B64 : null,
            rswT: 10_000,
        ), new ArrayStorage());
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $scorer = new RiskScorer();
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => ['source_fast' => 500, 'global_pressure' => 170],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        // The unproven identity: zero bucket credit, the full pressure
        // ramp applies (the same fail-closed shape an unreadable pricing
        // surface prices with).
        $priceContext = new class implements PriceContextSourceInterface {
            public function priceInputs(PriceRequest $request): PriceInputs
            {
                return PriceInputs::failClosed();
            }
        };
        $store = new FakeRiskStateStore(new SignalVector(700, 0, 0, 0, 0, 0, 0, 0, 0, 1000, 0, 0, 0));
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, $scorer, $policy, $keys, priceContext: $priceContext);
        $resolver = new RiskProfileResolver(
            PoWAlgorithm::Sha256,
            8,
            rswTrapdoor: $withTrapdoor ? new RswTrapdoor(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64, 10_000) : null,
        );
        $gateway = new RiskGateway($engine, $classifier, $resolver, ['login' => 1], policy: $policy);
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        return ['controller' => $controller, 'gateway' => $gateway, 'store' => $store, 'resolver' => $resolver];
    }

    private static function challengeRequest(): Request
    {
        return JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
    }
}
