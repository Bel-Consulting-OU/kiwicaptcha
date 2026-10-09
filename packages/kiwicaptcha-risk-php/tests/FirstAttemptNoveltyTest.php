<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Marks\MarksReaderInterface;
use KiwiCaptcha\Risk\Marks\MarksRequest;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use PHPUnit\Framework\TestCase;

/**
 * The first-attempt novelty gate against ISP-matched residential
 * proxies (D3.5 P0-2). A known ASN is NOT an automatic pass: a stuffer
 * who buys proxies on the victim's own ISP rides the same ASN on a
 * fresh /64. The same-ASN new-prefix shape is a weaker novelty signal
 * that fires unless device continuity (the first-party session
 * pseudonym) vouches for the browser.
 */
final class FirstAttemptNoveltyTest extends TestCase
{
    private const RAW_USER = 'alice@example.com';
    private const SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const HOME_IP = '10.1.2.3';
    private const ATTACKER_SAME_ASN = '10.9.9.9';
    private const ATTACKER_OTHER_ASN = '45.1.2.3';
    private const HOME_ASN_TAG = 'asn:64496';

    private RiskIdentityFactory $identity;
    private string $principalHex;
    private string $asnFixture;

    protected function setUp(): void
    {
        $keys = RiskKeys::fromMaster(str_repeat("\x11", 32));
        $this->identity = new RiskIdentityFactory($keys);
        $this->principalHex = $this->identity->principalId(self::RAW_USER);
        $this->asnFixture = sys_get_temp_dir().'/kiwi-novelty-asn-'.getmypid().'.tsv';
        file_put_contents(
            $this->asnFixture,
            "# test dataset\n10.0.0.0\t10.255.255.255\t64496\n45.0.0.0\t45.255.255.255\t64500\n",
        );
    }

    protected function tearDown(): void
    {
        @unlink($this->asnFixture);
    }

    /** @param array<string, true> $tags */
    private function buildEngine(array $tags, string $noveltyEnforcement = 'enforce'): AdaptiveRiskEngine
    {
        // The SAME identity factory as setUp: the tag store is keyed by
        // the hashed principal, so the engine and the seed must agree.
        $keys = RiskKeys::fromMaster(str_repeat("\x11", 32));
        $identity = new RiskIdentityFactory($keys);
        $store = new class extends RiskStateStoreStub {
            public function observe(\KiwiCaptcha\Risk\RiskObservation $observation): \KiwiCaptcha\Risk\SignalVector
            {
                return \KiwiCaptcha\Risk\SignalVector::fromArray([]);
            }
        };
        $networks = new class ($tags) implements PrincipalNetworkTagStoreInterface {
            /** @param array<string, array<string, true>> $tags */
            public function __construct(private array $tags)
            {
            }

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
        };
        $marksReader = new class implements MarksReaderInterface {
            public function requestMarks(MarksRequest $request): MarksView
            {
                return MarksView::read(new EmptyMarksStore(), [], null);
            }

            public function markTtlMs(): int
            {
                return 600000;
            }
        };

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: $identity,
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
            enableGlobalPressure: true,
            noveltyEnforcement: $noveltyEnforcement,
            principalNetworks: $networks,
            marksReader: $marksReader,
            asnDataset: AsnDataset::open($this->asnFixture),
        );
    }

    private function loginContext(string $ip, ?string $sessionId): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: $sessionId,
            principalId: self::RAW_USER,
            event: RiskEventKind::AuthenticationSuccess,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    /** The learned history: the home /32 and the home ASN, under the hashed principal. */
    private function homeTags(): array
    {
        return [
            $this->principalHex => [
                self::HOME_ASN_TAG => true,
                AdaptiveRiskEngine::networkBucket(self::HOME_IP) => true,
            ],
        ];
    }

    public function testAnUnknownAsnIsNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_OTHER_ASN, self::SESSION));
        self::assertNotSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'an unknown ASN is novel and must not land on the Allow path',
        );
    }

    public function testAKnownAsnAndKnownPrefixIsNotNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::HOME_IP, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'the home network on the home ASN is not novel',
        );
    }

    /**
     * The residential-proxy bypass: a stuffer on the victim's own ISP
     * ASN, fresh /64, no device continuity. Before this fix the known
     * ASN was an automatic pass. It must now escalate.
     */
    public function testAKnownAsnWithANewPrefixAndNoDeviceContinuityIsNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_SAME_ASN, null));
        self::assertNotSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'same-ASN new-prefix without device continuity is the residential-proxy shape and must escalate',
        );
    }

    /** A returning browser on a new /64 of its home ISP is normal. */
    public function testAKnownAsnWithANewPrefixAndDeviceContinuityIsNotNovel(): void
    {
        $engine = $this->buildEngine($this->homeTags());
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_SAME_ASN, self::SESSION));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'a returning browser on a new /64 of its home ISP passes on device continuity',
        );
    }

    public function testLearnModeRecordsButDoesNotEscalate(): void
    {
        $engine = $this->buildEngine($this->homeTags(), 'learn');
        $decision = $engine->reassess($this->loginContext(self::ATTACKER_SAME_ASN, null));
        self::assertSame(
            \KiwiCaptcha\Risk\RiskAction::Allow,
            $decision->action,
            'learn mode is the rollout window: novel networks are recorded, never escalated',
        );
    }
}

/** Empty marks store: the novelty tests exercise first-attempt evidence, not marks. */
final class EmptyMarksStore implements \KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface
{
    public function markKey(string $dimension, string $id): string
    {
        return 'mark:'.$dimension.':'.$id;
    }

    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int
    {
        return 1;
    }

    public function readMark(string $dimension, string $id): ?array
    {
        return null;
    }

    public function forgetMarks(string $dimension, string $id): int
    {
        return 0;
    }
}
